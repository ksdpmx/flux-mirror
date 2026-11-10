// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package helmrepo

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sync"
	"time"

	repo "helm.sh/helm/v4/pkg/repo/v1"
)

const (
	httpTimeout = 60 * time.Second

	// maxIndexSize bounds how much of an index.yaml we'll read. Mirrors
	// source-controller's helm.MaxIndexSize. A misconfigured or malicious
	// server returning a giant body shouldn't OOM the process.
	maxIndexSize = 50 << 20
	// maxChartSize bounds how much of a chart .tgz we'll read.
	maxChartSize = 100 << 20
	// maxProvenanceSize bounds how much of an optional PGP provenance file we'll read.
	maxProvenanceSize = 10 << 20
)

// HTTPSource is a Helm chart source backed by an HTTP/S Helm repository
// (the classic kind: an index.yaml plus chart .tgz files served at
// resolved URLs).
//
// We don't use helm.sh/helm/v4/pkg/getter for downloads: its Get signature
// has no context and so swallows cancellation. Per-job timeouts from the
// runner would still apply (the http.Client has its own Timeout), but a
// graceful shutdown wouldn't propagate. A plain net/http call is shorter
// and gives proper context propagation.
type HTTPSource struct {
	repoURL string
	client  *http.Client
	auth    *repo.Entry

	once  sync.Once
	index *repo.IndexFile
	err   error
}

// NewHTTPSource constructs an HTTPSource. The index is fetched lazily on
// first ListVersions or Download — failures surface there, not at construction.
// A single http.Client is reused for all requests so connection keep-alive
// kicks in across the index fetch and per-version chart downloads.
func NewHTTPSource(repoURL string) *HTTPSource {
	return &HTTPSource{
		repoURL: repoURL,
		client:  &http.Client{Timeout: httpTimeout},
	}
}

// NewHTTPSourceWithEntry constructs an HTTPSource authenticated with the
// matching Helm repositories.yaml entry, when one exists.
func NewHTTPSourceWithEntry(repoURL string, entry *repo.Entry) (*HTTPSource, error) {
	src := NewHTTPSource(repoURL)
	if entry == nil {
		return src, nil
	}
	client, err := httpClientForEntry(entry)
	if err != nil {
		return nil, err
	}
	entryCopy := *entry
	src.client = client
	src.auth = &entryCopy
	return src, nil
}

// ListVersions returns every version of chartName present in the repo's index.
func (s *HTTPSource) ListVersions(ctx context.Context, chartName string) ([]string, error) {
	idx, err := s.loadIndex(ctx)
	if err != nil {
		return nil, err
	}
	entries, ok := idx.Entries[chartName]
	if !ok || len(entries) == 0 {
		return nil, fmt.Errorf("chart %q not found in index %s", chartName, s.repoURL)
	}
	out := make([]string, 0, len(entries))
	for _, cv := range entries {
		out = append(out, cv.Version)
	}
	return out, nil
}

// Download fetches the chart .tgz for the given chartName/version. The
// download URL is whatever the index entry points at, resolved against the
// repo base — most repos use relative URLs (e.g. `nginx-1.2.3.tgz`).
func (s *HTTPSource) Download(ctx context.Context, chartName, version string) ([]byte, error) {
	chartURL, _, err := s.chartURL(ctx, chartName, version)
	if err != nil {
		return nil, err
	}
	return s.fetch(ctx, chartURL, maxChartSize)
}

// DownloadProvenance fetches the .prov sidecar beside the chart package.
// The returned filename is the chart URL basename recorded in the provenance
// file's signed checksum map.
func (s *HTTPSource) DownloadProvenance(ctx context.Context, chartName, version string) ([]byte, string, error) {
	chartURL, filename, err := s.chartURL(ctx, chartName, version)
	if err != nil {
		return nil, "", err
	}
	provURL, err := url.Parse(chartURL)
	if err != nil {
		return nil, "", fmt.Errorf("parse chart URL %q: %w", chartURL, err)
	}
	provURL.Path += ".prov"
	provURL.RawPath = ""
	data, err := s.fetch(ctx, provURL.String(), maxProvenanceSize)
	if err != nil {
		var statusErr *httpStatusError
		if errors.As(err, &statusErr) && statusErr.status == http.StatusNotFound {
			return nil, filename, ErrProvenanceNotFound
		}
		return nil, filename, fmt.Errorf("download chart provenance: %w", err)
	}
	return data, filename, nil
}

func (s *HTTPSource) chartURL(ctx context.Context, chartName, version string) (string, string, error) {
	idx, err := s.loadIndex(ctx)
	if err != nil {
		return "", "", err
	}
	cv, err := idx.Get(chartName, version)
	if err != nil {
		return "", "", fmt.Errorf("lookup chart %q@%q in index: %w", chartName, version, err)
	}
	if len(cv.URLs) == 0 {
		return "", "", fmt.Errorf("chart %q@%q has no URLs in index", chartName, version)
	}
	chartURL, err := repo.ResolveReferenceURL(s.repoURL, cv.URLs[0])
	if err != nil {
		return "", "", fmt.Errorf("resolve chart URL %q against %q: %w", cv.URLs[0], s.repoURL, err)
	}
	parsed, err := url.Parse(chartURL)
	if err != nil {
		return "", "", fmt.Errorf("parse chart URL %q: %w", chartURL, err)
	}
	filename := path.Base(parsed.Path)
	if filename == "." || filename == "/" || filename == "" {
		return "", "", fmt.Errorf("chart URL %q has no file name", chartURL)
	}
	return chartURL, filename, nil
}

// loadIndex fetches and parses index.yaml exactly once across all calls.
// The result is cached for the lifetime of the HTTPSource — this is fine
// for a single sync run because the same source is consumed by at most one
// ChartEntry, but multiple charts on the same source URL would fetch twice
// (acceptable for v1).
func (s *HTTPSource) loadIndex(ctx context.Context) (*repo.IndexFile, error) {
	s.once.Do(func() {
		idxURL, err := repo.ResolveReferenceURL(s.repoURL, "index.yaml")
		if err != nil {
			s.err = fmt.Errorf("resolve index URL: %w", err)
			return
		}
		data, err := s.fetch(ctx, idxURL, maxIndexSize)
		if err != nil {
			s.err = err
			return
		}
		// Helm v4's repo package only exposes LoadIndexFile (file path).
		// Write to a temp file and delegate so we keep the JSON-or-YAML
		// auto-detection and the SortEntries() invocation it does.
		f, err := os.CreateTemp("", "flux-mirror-index-*.yaml")
		if err != nil {
			s.err = fmt.Errorf("temp file for index: %w", err)
			return
		}
		defer os.Remove(f.Name())
		if _, err := f.Write(data); err != nil {
			_ = f.Close()
			s.err = fmt.Errorf("write index temp: %w", err)
			return
		}
		if err := f.Close(); err != nil {
			s.err = fmt.Errorf("close index temp: %w", err)
			return
		}
		idx, err := repo.LoadIndexFile(f.Name())
		if err != nil {
			s.err = fmt.Errorf("parse index from %s: %w", idxURL, err)
			return
		}
		s.index = idx
	})
	return s.index, s.err
}

func (s *HTTPSource) fetch(ctx context.Context, target string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", target, err)
	}
	req.Header.Set("User-Agent", "flux-mirror")
	if err := s.setAuth(req); err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", target, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &httpStatusError{target: target, status: resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read body from %s: %w", target, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("response from %s exceeds %d bytes", target, maxBytes)
	}
	return data, nil
}

type httpStatusError struct {
	target string
	status int
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("GET %s: status %d", e.target, e.status)
}

func (s *HTTPSource) setAuth(req *http.Request) error {
	if s.auth == nil || s.auth.Username == "" || s.auth.Password == "" {
		return nil
	}
	repoURL, err := url.Parse(s.repoURL)
	if err != nil {
		return fmt.Errorf("parse repository URL %q for auth: %w", s.repoURL, err)
	}
	if s.auth.PassCredentialsAll || (repoURL.Scheme == req.URL.Scheme && repoURL.Host == req.URL.Host) {
		req.SetBasicAuth(s.auth.Username, s.auth.Password)
	}
	return nil
}

func httpClientForEntry(entry *repo.Entry) (*http.Client, error) {
	if entry == nil || (entry.CertFile == "" && entry.KeyFile == "" && entry.CAFile == "" && !entry.InsecureSkipTLSVerify) {
		return &http.Client{Timeout: httpTimeout}, nil
	}
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("default HTTP transport is %T, want *http.Transport", http.DefaultTransport)
	}
	transport := defaultTransport.Clone()
	tlsConfig, err := tlsConfigForEntry(entry)
	if err != nil {
		return nil, err
	}
	transport.TLSClientConfig = tlsConfig
	return &http.Client{Timeout: httpTimeout, Transport: transport}, nil
}

func tlsConfigForEntry(entry *repo.Entry) (*tls.Config, error) {
	cfg := &tls.Config{}
	if entry.CertFile != "" || entry.KeyFile != "" {
		if entry.CertFile == "" || entry.KeyFile == "" {
			return nil, fmt.Errorf("helm repository %q must set both certFile and keyFile for client TLS", entry.Name)
		}
		cert, err := tls.LoadX509KeyPair(entry.CertFile, entry.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client TLS cert/key for Helm repository %q: %w", entry.Name, err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	if entry.CAFile != "" {
		pem, err := os.ReadFile(entry.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file for Helm repository %q: %w", entry.Name, err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system cert pool for Helm repository %q: %w", entry.Name, err)
		}
		if roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca file for helm repository %q contains no PEM certificates", entry.Name)
		}
		cfg.RootCAs = roots
	}
	if entry.InsecureSkipTLSVerify {
		cfg.InsecureSkipVerify = true //nolint:gosec // Mirrors Helm's explicit repository setting.
	}
	return cfg, nil
}

// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package helmrepo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// checksumHeader is the header JFrog Artifactory uses to report and verify the
// SHA-256 of a stored file.
const checksumHeader = "X-Checksum-Sha256"

// BasicAuthFunc returns the Basic credentials to send. It is called per
// request so short-lived credentials can be re-minted.
type BasicAuthFunc func(ctx context.Context) (username, password string, err error)

// Pusher publishes chart .tgz files to a JFrog Artifactory Helm repository
// directory. It holds no mutable state, so it is safe for concurrent use.
type Pusher struct {
	base   *url.URL
	client *http.Client
	basic  BasicAuthFunc
}

// PusherOption customizes a Pusher.
type PusherOption func(*Pusher)

// WithTransport sets the HTTP transport (for example the shared transport that
// stamps per-host bearer credentials). Defaults to http.DefaultTransport.
func WithTransport(rt http.RoundTripper) PusherOption {
	return func(p *Pusher) {
		if rt != nil {
			p.client = &http.Client{Transport: rt}
		}
	}
}

// WithBasicAuth sends Basic credentials with every request.
func WithBasicAuth(f BasicAuthFunc) PusherOption {
	return func(p *Pusher) { p.basic = f }
}

// NormalizeDestination parses an Artifactory Helm repository directory URL.
// The scheme is optional and defaults to https; only http and https are
// accepted. Trailing slashes are dropped.
func NormalizeDestination(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("destination is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("scheme must be https:// (or http:// with --insecure), got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("URL %q is missing a host", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("URL %q must not contain a query or fragment", raw)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

// NewPusher builds a Pusher for the repository directory dest. A plaintext
// http:// destination is rejected unless insecure is set.
func NewPusher(dest string, insecure bool, opts ...PusherOption) (*Pusher, error) {
	u, err := NormalizeDestination(dest)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "http" && !insecure {
		return nil, fmt.Errorf("destination %q uses plaintext http; pass --insecure to allow it", dest)
	}
	p := &Pusher{base: u, client: &http.Client{}}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// Host returns the host (and optional port) of the repository.
func (p *Pusher) Host() string { return p.base.Host }

// Dir returns the repository directory URL charts are stored under.
func (p *Pusher) Dir() string { return p.base.String() }

// ChartURL returns the URL the chart name at version is stored at.
func (p *Pusher) ChartURL(chartName, version string) (string, error) {
	if err := validateFilePart("chart name", chartName); err != nil {
		return "", err
	}
	if err := validateFilePart("chart version", version); err != nil {
		return "", err
	}
	u := *p.base
	u.Path = path.Join(u.Path, chartName+"-"+version+".tgz")
	return u.String(), nil
}

func validateFilePart(what, v string) error {
	if v == "" || strings.ContainsAny(v, `/\`) || strings.Contains(v, "..") {
		return fmt.Errorf("invalid %s %q", what, v)
	}
	return nil
}

// Stat returns the SHA-256 ("sha256:<hex>") of the stored chart, or "" when it
// does not exist. It trusts the server-reported checksum and falls back to
// downloading and hashing the file when the server does not report one.
func (p *Pusher) Stat(ctx context.Context, chartName, version string) (string, error) {
	target, err := p.ChartURL(chartName, version)
	if err != nil {
		return "", err
	}
	resp, err := p.do(ctx, http.MethodHead, target, nil, 0, nil)
	if err != nil {
		return "", err
	}
	_ = resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return "", nil
	case resp.StatusCode != http.StatusOK:
		return "", statusError(http.MethodHead, target, resp.StatusCode)
	}
	if sum := strings.ToLower(strings.TrimSpace(resp.Header.Get(checksumHeader))); sum != "" {
		return "sha256:" + sum, nil
	}
	return p.hashRemote(ctx, target)
}

func (p *Pusher) hashRemote(ctx context.Context, target string) (string, error) {
	resp, err := p.do(ctx, http.MethodGet, target, nil, 0, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", statusError(http.MethodGet, target, resp.StatusCode)
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(resp.Body, maxChartSize+1))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", target, err)
	}
	if n > maxChartSize {
		return "", fmt.Errorf("response from %s exceeds %d bytes", target, maxChartSize)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// Put uploads body (size bytes, whose SHA-256 is digest as "sha256:<hex>") as
// the chart at version. The checksum header makes Artifactory reject a
// corrupted upload.
func (p *Pusher) Put(ctx context.Context, chartName, version string, body io.Reader, size int64, digest string) error {
	target, err := p.ChartURL(chartName, version)
	if err != nil {
		return err
	}
	sum, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || sum == "" {
		return fmt.Errorf("digest %q is not a sha256 digest", digest)
	}
	hdr := http.Header{
		"Content-Type": {"application/gzip"},
		checksumHeader: {sum},
	}
	resp, err := p.do(ctx, http.MethodPut, target, body, size, hdr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return statusError(http.MethodPut, target, resp.StatusCode)
	}
	return nil
}

func (p *Pusher) do(ctx context.Context, method, target string, body io.Reader, size int64, hdr http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, fmt.Errorf("build %s request for %s: %w", method, target, err)
	}
	if body != nil {
		req.ContentLength = size
	}
	req.Header.Set("User-Agent", "flux-mirror")
	for k, v := range hdr {
		req.Header[k] = v
	}
	if p.basic != nil {
		user, pass, err := p.basic(ctx)
		if err != nil {
			return nil, fmt.Errorf("resolve credentials for %s: %w", p.base.Host, err)
		}
		req.SetBasicAuth(user, pass)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, target, err)
	}
	return resp, nil
}

func statusError(method, target string, code int) error {
	switch code {
	case http.StatusUnauthorized:
		return fmt.Errorf("%s %s: status %d (check the credential configured for this host under hosts)", method, target, code)
	case http.StatusForbidden:
		return fmt.Errorf("%s %s: status %d (the credential may lack deploy permission, or the repository forbids overwriting existing files)", method, target, code)
	case http.StatusNotFound:
		// Only reachable from PUT (HEAD/GET treat 404 as "file absent"): the
		// repository path does not resolve, typically a missing /artifactory
		// context path or a wrong repository key.
		return fmt.Errorf("%s %s: status %d (repository not found; JFrog URLs usually need the /artifactory context path, e.g. https://<host>/artifactory/<repo-key>/<dir>)", method, target, code)
	default:
		return fmt.Errorf("%s %s: status %d", method, target, code)
	}
}

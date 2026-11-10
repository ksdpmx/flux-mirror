// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

// Package helmrepo adapts an HTTP/S index.yaml Helm chart repository to a
// Source interface for use by the charts mirror. Destination push is handled
// directly by internal/oci. Mirroring a Helm chart that already lives in an OCI
// registry is an OCI-to-OCI copy and goes through the artifacts mirror, not
// here — the charts mirror exists only for the HTTP/S → OCI conversion.
package helmrepo

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"helm.sh/helm/v4/pkg/cli"
	repo "helm.sh/helm/v4/pkg/repo/v1"
)

// Source is a Helm chart catalog backed by an HTTP/S index.yaml repository.
type Source interface {
	// ListVersions returns all available versions of chartName, in arbitrary
	// order. Sort and limit are applied downstream by the selector.
	ListVersions(ctx context.Context, chartName string) ([]string, error)

	// Download fetches the chart .tgz bytes for chartName at version.
	Download(ctx context.Context, chartName, version string) ([]byte, error)

	// DownloadProvenance fetches the optional .prov sidecar and returns the
	// chart archive's filename from the repository index.
	DownloadProvenance(ctx context.Context, chartName, version string) ([]byte, string, error)
}

// ErrProvenanceNotFound means the chart repository does not publish a .prov
// sidecar for the requested chart version.
var ErrProvenanceNotFound = errors.New("chart provenance file not found")

// NormalizeSource parses the URL of an HTTP/S Helm chart repository. The scheme
// is optional and defaults to https; only http and https are accepted (an OCI
// Helm chart is mirrored OCI-to-OCI through the artifacts mirror, never here).
// The path is left as given.
func NormalizeSource(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("source is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("scheme %q must be one of: http, https "+
			"(use 'artifacts' to mirror an OCI Helm chart to another OCI repository)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("URL %q is missing a host", raw)
	}
	return u, nil
}

// New builds the HTTP/S Source for sourceURL (auth via Helm repositories.yaml
// when present). The scheme is optional and defaults to https; a plaintext
// http:// source is rejected unless insecure is set.
func New(sourceURL string, insecure bool) (Source, error) {
	u, err := NormalizeSource(sourceURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "http" && !insecure {
		return nil, fmt.Errorf("source %q uses plaintext http; pass --insecure to allow it", sourceURL)
	}
	normalized := u.String()
	entry, err := httpRepositoryEntry(normalized)
	if err != nil {
		return nil, err
	}
	return NewHTTPSourceWithEntry(normalized, entry)
}

func httpRepositoryEntry(sourceURL string) (*repo.Entry, error) {
	settings := cli.New()
	repos, err := repo.LoadFile(settings.RepositoryConfig)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("load Helm repository config %s: %w", settings.RepositoryConfig, err)
	}
	sourceKey, err := normalizeRepositoryURL(sourceURL)
	if err != nil {
		return nil, fmt.Errorf("normalize source URL %q: %w", sourceURL, err)
	}
	for _, entry := range repos.Repositories {
		if entry == nil || strings.TrimSpace(entry.URL) == "" {
			continue
		}
		entryKey, err := normalizeRepositoryURL(entry.URL)
		if err != nil {
			return nil, fmt.Errorf("normalize Helm repository %q URL %q: %w", entry.Name, entry.URL, err)
		}
		if entryKey == sourceKey {
			entryCopy := *entry
			return &entryCopy, nil
		}
	}
	return nil, nil
}

// VersionToTag implements the `+` → `_` substitution Helm OCI uses to encode
// semver build metadata in OCI tags (since `+` isn't a valid OCI tag
// character). The charts mirror needs it to construct destination tags.
func VersionToTag(version string) string { return strings.ReplaceAll(version, "+", "_") }

func normalizeRepositoryURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("missing scheme or host")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

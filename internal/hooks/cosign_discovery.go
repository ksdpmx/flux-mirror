// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/bundle"

	"github.com/fluxcd/flux-mirror/internal/oci"
)

const (
	referrerSigstoreBundleMediaTypePrefix = "application/vnd.dev.sigstore.bundle"
	referrerSigstoreBundleMinVersion      = "v0.3"
)

var errNoReferrerBundle = errors.New("no sigstore bundle found in OCI referrers")

func discoverCosignBundle(repo name.Repository, digest v1.Hash, opts ...remote.Option) (*bundle.Bundle, []byte, error) {
	discovered, err := findReferrerBundle(repo, digest, opts...)
	if err == nil {
		return discovered, nil, nil
	}
	var rejected *oci.SignatureRejectedError
	if errors.As(err, &rejected) || !errors.Is(err, errNoReferrerBundle) {
		return nil, nil, err
	}

	tagBundle, payload, err := findCosignTagBundle(repo, digest, opts...)
	if errors.Is(err, errNoCosignTagSignature) {
		return nil, nil, oci.NewSignatureRejectedError(fmt.Errorf(
			"no sigstore bundle found via OCI referrers or cosign tag-based discovery for %s", digest,
		))
	}
	if err != nil {
		return nil, nil, err
	}
	return tagBundle, payload, nil
}

func findReferrerBundle(repo name.Repository, digest v1.Hash, opts ...remote.Option) (*bundle.Bundle, error) {
	digestRef := repo.Digest(digest.String())
	index, err := remote.Referrers(digestRef, opts...)
	if err != nil {
		return nil, fmt.Errorf("list OCI referrers for %s: %w", digestRef, err)
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("read referrers index for %s: %w", digestRef, err)
	}
	bundleBytes, err := findReferrerSigstoreBundle(repo, manifest, opts...)
	if errors.Is(err, errNoReferrerSigstoreBundle) {
		return nil, errNoReferrerBundle
	}
	if err != nil {
		return nil, err
	}
	var sigstoreBundle bundle.Bundle
	if err := sigstoreBundle.UnmarshalJSON(bundleBytes); err != nil {
		return nil, oci.NewSignatureRejectedError(fmt.Errorf("parse sigstore bundle: %w", err))
	}
	if !sigstoreBundle.MinVersion(referrerSigstoreBundleMinVersion) {
		return nil, oci.NewSignatureRejectedError(fmt.Errorf(
			"unsupported sigstore bundle version: minimum %s required", referrerSigstoreBundleMinVersion,
		))
	}
	return &sigstoreBundle, nil
}

var errNoReferrerSigstoreBundle = errors.New("no sigstore bundle found in OCI referrers")

func findReferrerSigstoreBundle(repo name.Repository, manifest *v1.IndexManifest, opts ...remote.Option) ([]byte, error) {
	for _, descriptor := range manifest.Manifests {
		ref := repo.Digest(descriptor.Digest.String())
		image, err := remote.Image(ref, opts...)
		if err != nil {
			return nil, fmt.Errorf("fetch referrer %s: %w", ref, err)
		}
		layers, err := image.Layers()
		if err != nil {
			return nil, fmt.Errorf("list layers for referrer %s: %w", ref, err)
		}
		if len(layers) != 1 {
			continue
		}
		mediaType, err := layers[0].MediaType()
		if err != nil {
			return nil, fmt.Errorf("read layer media type for referrer %s: %w", ref, err)
		}
		if !strings.HasPrefix(string(mediaType), referrerSigstoreBundleMediaTypePrefix) {
			continue
		}
		reader, err := layers[0].Uncompressed()
		if err != nil {
			return nil, fmt.Errorf("read sigstore bundle layer for referrer %s: %w", ref, err)
		}
		data, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if closeErr != nil {
			return nil, fmt.Errorf("close sigstore bundle layer for referrer %s: %w", ref, closeErr)
		}
		if readErr != nil {
			return nil, fmt.Errorf("read sigstore bundle layer for referrer %s: %w", ref, readErr)
		}
		return data, nil
	}
	return nil, errNoReferrerSigstoreBundle
}

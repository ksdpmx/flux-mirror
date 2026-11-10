// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"encoding/json"
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
	cosignSignaturePredicateType          = "https://sigstore.dev/cosign/sign/v1"
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
	bundles, err := findReferrerBundles(repo, digest, opts...)
	if err != nil {
		return nil, err
	}
	for _, candidate := range bundles {
		isSignature, err := isCosignSignatureBundle(candidate)
		if err != nil || !isSignature {
			continue
		}
		if !candidate.MinVersion(referrerSigstoreBundleMinVersion) {
			return nil, oci.NewSignatureRejectedError(fmt.Errorf(
				"unsupported sigstore bundle version: minimum %s required", referrerSigstoreBundleMinVersion,
			))
		}
		return candidate, nil
	}
	return nil, errNoReferrerBundle
}

func findReferrerBundles(repo name.Repository, digest v1.Hash, opts ...remote.Option) ([]*bundle.Bundle, error) {
	digestRef := repo.Digest(digest.String())
	index, err := remote.Referrers(digestRef, opts...)
	if err != nil {
		return nil, fmt.Errorf("list OCI referrers for %s: %w", digestRef, err)
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("read referrers index for %s: %w", digestRef, err)
	}
	var bundles []*bundle.Bundle
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
		var sigstoreBundle bundle.Bundle
		if err := sigstoreBundle.UnmarshalJSON(data); err != nil {
			return nil, oci.NewSignatureRejectedError(fmt.Errorf("parse sigstore bundle %s: %w", ref, err))
		}
		bundles = append(bundles, &sigstoreBundle)
	}
	if len(bundles) == 0 {
		return nil, errNoReferrerBundle
	}
	return bundles, nil
}

// isCosignSignatureBundle distinguishes a cosign signature from a DSSE
// attestation. The predicate type comes from the signed DSSE payload; this
// classification is only used to select candidates before cryptographic
// verification.
func isCosignSignatureBundle(b *bundle.Bundle) (bool, error) {
	if b.GetMessageSignature() != nil {
		return true, nil
	}
	envelope := b.GetDsseEnvelope()
	if envelope == nil {
		return false, nil
	}
	var statement struct {
		PredicateType string `json:"predicateType"`
	}
	if err := json.Unmarshal(envelope.Payload, &statement); err != nil {
		return false, fmt.Errorf("read referrer DSSE predicate type: %w", err)
	}
	return statement.PredicateType == cosignSignaturePredicateType, nil
}

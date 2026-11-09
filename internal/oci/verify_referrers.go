// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
)

// SignatureRejectedError reports that a signature was absent or did not
// satisfy the configured identity policy.
type SignatureRejectedError struct {
	err error
}

func (e *SignatureRejectedError) Error() string { return e.err.Error() }
func (e *SignatureRejectedError) Unwrap() error { return e.err }

// NewSignatureRejectedError marks an absent or policy-rejected signature.
func NewSignatureRejectedError(err error) *SignatureRejectedError {
	if err == nil {
		err = fmt.Errorf("signature rejected")
	}
	return &SignatureRejectedError{err: err}
}

// VerifyReferrers verifies a cosign keyless signature found only through the
// OCI 1.1 referrers API. It deliberately does not use the legacy cosign tag
// discovery path.
func (v *Verifier) VerifyReferrers(ctx context.Context, ref string, cfg apiv1.ArtifactVerification) (*VerificationInfo, error) {
	if strings.TrimSpace(cfg.Provider) != apiv1.VerifyProviderCosign {
		return nil, fmt.Errorf("unsupported verification provider %q", cfg.Provider)
	}
	if len(cfg.MatchOIDCIdentity) == 0 {
		return nil, fmt.Errorf("at least one OIDC identity matcher is required")
	}

	ref = strings.TrimPrefix(ref, "oci://")
	parsed, err := name.ParseReference(ref, v.client.staticNameOpts...)
	if err != nil {
		return nil, fmt.Errorf("parse reference %q: %w", ref, err)
	}
	opts := v.remoteOptions(ctx)
	desc, err := remote.Get(parsed, opts...)
	if err != nil {
		return nil, fmt.Errorf("fetch descriptor for %q: %w", ref, err)
	}
	digestRef := parsed.Context().Digest(desc.Digest.String())
	index, err := remote.Referrers(digestRef, opts...)
	if err != nil {
		return nil, fmt.Errorf("list OCI referrers for %s: %w", digestRef, err)
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("read referrers index for %s: %w", digestRef, err)
	}
	bundleBytes, err := findHookSigstoreBundle(parsed.Context(), manifest, opts...)
	if err != nil {
		if errors.Is(err, errNoHookSigstoreBundle) {
			return nil, NewSignatureRejectedError(fmt.Errorf("no usable sigstore bundle found in OCI referrers"))
		}
		return nil, err
	}
	var sigstoreBundle bundle.Bundle
	if err := sigstoreBundle.UnmarshalJSON(bundleBytes); err != nil {
		return nil, NewSignatureRejectedError(fmt.Errorf("parse sigstore bundle: %w", err))
	}
	if !sigstoreBundle.MinVersion(minBundleVersion) {
		return nil, NewSignatureRejectedError(fmt.Errorf("unsupported sigstore bundle version: minimum %s required", minBundleVersion))
	}
	digestBytes, err := hex.DecodeString(desc.Digest.Hex)
	if err != nil {
		return nil, fmt.Errorf("decode digest %s: %w", desc.Digest, err)
	}

	trustedRoot, err := v.getTrustedRoot()
	if err != nil {
		return nil, err
	}
	sigVerifier, err := verify.NewVerifier(
		trustedRoot,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithIntegratedTimestamps(1),
		verify.WithTransparencyLog(1),
	)
	if err != nil {
		return nil, fmt.Errorf("create signature verifier: %w", err)
	}
	identityOptions, err := certificateIdentityOptions(cfg.MatchOIDCIdentity)
	if err != nil {
		return nil, err
	}
	policy := verify.NewPolicy(
		verify.WithArtifactDigest(desc.Digest.Algorithm, digestBytes),
		identityOptions...,
	)
	result, err := sigVerifier.Verify(&sigstoreBundle, policy)
	if err != nil {
		return nil, NewSignatureRejectedError(fmt.Errorf("signature verification failed: %w", err))
	}

	info := &VerificationInfo{
		Provider: apiv1.VerifyProviderCosign,
		Digest:   desc.Digest.String(),
	}
	if result.Signature != nil && result.Signature.Certificate != nil {
		info.Identity = result.Signature.Certificate.SubjectAlternativeName
		info.Issuer = result.Signature.Certificate.Extensions.Issuer
	}
	if integratedTime, ok := signatureIntegratedTime(result); ok {
		info.IntegratedTime = integratedTime
	}
	return info, nil
}

var errNoHookSigstoreBundle = errors.New("no sigstore bundle found")

func findHookSigstoreBundle(repo name.Repository, manifest *v1.IndexManifest, opts ...remote.Option) ([]byte, error) {
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
		if !strings.HasPrefix(string(mediaType), sigstoreBundleMediaTypePrefix) {
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
	return nil, errNoHookSigstoreBundle
}

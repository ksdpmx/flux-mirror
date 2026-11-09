// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

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

// SignatureDiscoverer finds a cosign bundle for the resolved source digest.
// A non-nil payload means the signature covers that payload rather than the
// raw artifact digest.
type SignatureDiscoverer func(name.Repository, v1.Hash, ...remote.Option) (*bundle.Bundle, []byte, error)

// VerifyWithDiscovery verifies a cosign keyless signature found by discover.
// It returns a *SignatureTooNewError with verification metadata when a valid
// signature has not aged past cfg.MinAge.
func (v *Verifier) VerifyWithDiscovery(
	ctx context.Context,
	ref string,
	cfg apiv1.ArtifactVerification,
	discover SignatureDiscoverer,
) (*VerificationInfo, error) {
	if strings.TrimSpace(cfg.Provider) != apiv1.VerifyProviderCosign {
		return nil, fmt.Errorf("unsupported verification provider %q", cfg.Provider)
	}
	if len(cfg.MatchOIDCIdentity) == 0 {
		return nil, fmt.Errorf("at least one OIDC identity matcher is required")
	}
	if discover == nil {
		return nil, fmt.Errorf("signature discoverer is required")
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
	sigstoreBundle, payload, err := discover(parsed.Context(), desc.Digest, opts...)
	if err != nil {
		return nil, err
	}
	if sigstoreBundle == nil {
		return nil, fmt.Errorf("signature discoverer returned no bundle")
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
	var artifact verify.ArtifactPolicyOption
	if payload != nil {
		artifact = verify.WithArtifact(bytes.NewReader(payload))
	} else {
		digestBytes, err := hex.DecodeString(desc.Digest.Hex)
		if err != nil {
			return nil, fmt.Errorf("decode digest %s: %w", desc.Digest, err)
		}
		artifact = verify.WithArtifactDigest(desc.Digest.Algorithm, digestBytes)
	}
	policy := verify.NewPolicy(artifact, identityOptions...)
	result, err := sigVerifier.Verify(sigstoreBundle, policy)
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
	if cfg.MinAge != nil && cfg.MinAge.Duration > 0 {
		if err := enforceMinAge(result, cfg.MinAge.Duration, time.Now()); err != nil {
			var tooNew *SignatureTooNewError
			if errors.As(err, &tooNew) {
				return info, err
			}
			return nil, err
		}
	}
	return info, nil
}

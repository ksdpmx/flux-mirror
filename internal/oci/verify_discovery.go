// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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

// AttestationDiscoverer finds the sigstore entities of the attestations
// attached to a digest. Their predicate types are only known after they have
// been verified, so the discoverer returns every candidate it can build and
// leaves out what it cannot read. No attestation at all is an empty result.
type AttestationDiscoverer func(name.Repository, v1.Hash, ...remote.Option) ([]verify.SignedEntity, error)

// VerifyAttestations verifies that an attestation of every required predicate
// type is attached to the digest of ref and signed by one of identities. The
// predicate type is read from the verified in-toto statement, never from the
// registry's annotations, and the statement must be about the digest. It
// returns the required predicate types as full URIs, in the order given. A
// missing attestation returns a *SignatureRejectedError.
func (v *Verifier) VerifyAttestations(
	ctx context.Context,
	ref string,
	identities []apiv1.OIDCIdentity,
	required []string,
	discover AttestationDiscoverer,
) ([]string, error) {
	if len(identities) == 0 {
		return nil, fmt.Errorf("at least one OIDC identity matcher is required")
	}
	if len(required) == 0 {
		return nil, fmt.Errorf("at least one attestation predicate type is required")
	}
	if discover == nil {
		return nil, fmt.Errorf("attestation discoverer is required")
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
	entities, err := discover(parsed.Context(), desc.Digest, opts...)
	if err != nil {
		return nil, err
	}
	trustedRoot, err := v.getTrustedRoot()
	if err != nil {
		return nil, err
	}
	return verifyAttestationEntities(trustedRoot, desc.Digest, entities, identities, required, attestationVerifierOptions())
}

// ResolvePlatforms reads the image index of ref and returns the manifest digest
// of each requested platform (os/arch or os/arch/variant). A platform that the
// index does not have is left out of the result, and so is every platform when
// ref is not an index.
func (v *Verifier) ResolvePlatforms(ctx context.Context, ref string, platforms []string) (map[string]string, error) {
	ref = strings.TrimPrefix(ref, "oci://")
	parsed, err := name.ParseReference(ref, v.client.staticNameOpts...)
	if err != nil {
		return nil, fmt.Errorf("parse reference %q: %w", ref, err)
	}
	desc, err := remote.Get(parsed, v.remoteOptions(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("fetch descriptor for %q: %w", ref, err)
	}
	digests := make(map[string]string, len(platforms))
	if !desc.MediaType.IsIndex() {
		return digests, nil
	}
	index, err := desc.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("read image index %q: %w", ref, err)
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("read image index manifest %q: %w", ref, err)
	}
	for _, platform := range platforms {
		// An empty or partial spec would match every manifest.
		if parts := strings.Split(platform, "/"); len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("platform %q must be os/arch or os/arch/variant", platform)
		}
		want, err := v1.ParsePlatform(platform)
		if err != nil {
			return nil, fmt.Errorf("parse platform %q: %w", platform, err)
		}
		for _, m := range manifest.Manifests {
			if m.Platform != nil && m.Platform.Satisfies(*want) {
				digests[platform] = m.Digest.String()
				break
			}
		}
	}
	return digests, nil
}

// attestationVerifierOptions are the checks every attestation must pass: a
// signed certificate timestamp, and a transparency log entry with its
// integrated timestamp.
func attestationVerifierOptions() []verify.VerifierOption {
	return []verify.VerifierOption{
		verify.WithSignedCertificateTimestamps(1),
		verify.WithIntegratedTimestamps(1),
		verify.WithTransparencyLog(1),
	}
}

func verifyAttestationEntities(
	material root.TrustedMaterial,
	digest v1.Hash,
	entities []verify.SignedEntity,
	identities []apiv1.OIDCIdentity,
	required []string,
	verifierOptions []verify.VerifierOption,
) ([]string, error) {
	sigVerifier, err := verify.NewVerifier(material, verifierOptions...)
	if err != nil {
		return nil, fmt.Errorf("create attestation verifier: %w", err)
	}
	identityOptions, err := certificateIdentityOptions(identities)
	if err != nil {
		return nil, err
	}
	digestBytes, err := hex.DecodeString(digest.Hex)
	if err != nil {
		return nil, fmt.Errorf("decode digest %s: %w", digest, err)
	}
	policy := verify.NewPolicy(verify.WithArtifactDigest(digest.Algorithm, digestBytes), identityOptions...)

	verified := make(map[string]struct{}, len(entities))
	var failures []string
	for _, entity := range entities {
		result, err := sigVerifier.Verify(entity, policy)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		if result.Statement == nil {
			continue
		}
		verified[result.Statement.PredicateType] = struct{}{}
	}

	types := make([]string, 0, len(required))
	var missing []string
	for _, entry := range required {
		predicateType, ok := apiv1.EffectivePredicateType(entry)
		if !ok {
			return nil, fmt.Errorf("attestation %q is not a predicate type", entry)
		}
		types = append(types, predicateType)
		if _, ok := verified[predicateType]; !ok {
			missing = append(missing, predicateType)
		}
	}
	if len(missing) > 0 {
		msg := fmt.Sprintf("no verified attestation of type %s for %s", strings.Join(missing, ", "), digest)
		if len(entities) == 0 {
			msg += ": no attestations are attached"
		} else if len(failures) > 0 {
			msg += fmt.Sprintf(": %d of %d attached attestations failed verification, first: %s",
				len(failures), len(entities), failures[0])
		}
		return nil, NewSignatureRejectedError(errors.New(msg))
	}
	return types, nil
}

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
	identityOptions, err := certificateIdentityOptions(cfg.MatchOIDCIdentity)
	if err != nil {
		return nil, err
	}
	return v.verifyDiscovered(ctx, ref, cfg.MinAge, discover, func(root.TrustedMaterial) (root.TrustedMaterial, []verify.VerifierOption, []verify.PolicyOption, error) {
		return nil, []verify.VerifierOption{
			verify.WithSignedCertificateTimestamps(1),
			verify.WithIntegratedTimestamps(1),
			verify.WithTransparencyLog(1),
		}, identityOptions, nil
	})
}

// VerifyWithKey verifies a key-based cosign signature found by discover: it
// must have been made by publicKeyPEM and be in a transparency log. It
// returns a *SignatureTooNewError with verification metadata when a valid
// signature has not aged past minAge.
func (v *Verifier) VerifyWithKey(
	ctx context.Context,
	ref string,
	publicKeyPEM string,
	minAge *metav1.Duration,
	discover SignatureDiscoverer,
) (*VerificationInfo, error) {
	key, err := ParsePublicKeyPEM(publicKeyPEM)
	if err != nil {
		return nil, err
	}
	keyVerifier, err := signature.LoadVerifier(key, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("load public key verifier: %w", err)
	}
	// The bundle's key hint is not trusted: the signature has to verify under
	// the configured key whatever the hint says.
	keys := root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		return root.NewExpiringKey(keyVerifier, time.Time{}, time.Time{}), nil
	})
	return v.verifyDiscovered(ctx, ref, minAge, discover, func(trusted root.TrustedMaterial) (root.TrustedMaterial, []verify.VerifierOption, []verify.PolicyOption, error) {
		return root.TrustedMaterialCollection{keys, trusted}, []verify.VerifierOption{
			verify.WithIntegratedTimestamps(1),
			verify.WithTransparencyLog(1),
		}, []verify.PolicyOption{verify.WithKey()}, nil
	})
}

// verifyDiscovered is the flow shared by the keyless and key-based checks:
// resolve ref, discover the bundle, verify it with the trusted material, the
// verifier options and the policy options that trust returns for the Sigstore
// trusted root, and enforce minAge. A nil material from trust means the trusted
// root alone.
func (v *Verifier) verifyDiscovered(
	ctx context.Context,
	ref string,
	minAge *metav1.Duration,
	discover SignatureDiscoverer,
	trust func(root.TrustedMaterial) (root.TrustedMaterial, []verify.VerifierOption, []verify.PolicyOption, error),
) (*VerificationInfo, error) {
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
	material, verifierOptions, policyOptions, err := trust(trustedRoot)
	if err != nil {
		return nil, err
	}
	if material == nil {
		material = trustedRoot
	}
	sigVerifier, err := verify.NewVerifier(material, verifierOptions...)
	if err != nil {
		return nil, fmt.Errorf("create signature verifier: %w", err)
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
	policy := verify.NewPolicy(artifact, policyOptions...)
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
	if minAge != nil && minAge.Duration > 0 {
		if err := enforceMinAge(result, minAge.Duration, time.Now()); err != nil {
			var tooNew *SignatureTooNewError
			if errors.As(err, &tooNew) {
				return info, err
			}
			return nil, err
		}
	}
	return info, nil
}

// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/verify"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
	"github.com/fluxcd/flux-mirror/internal/oci"
)

type cosignVerifier interface {
	VerifyWithDiscovery(context.Context, string, apiv1.ArtifactVerification, oci.SignatureDiscoverer) (*oci.VerificationInfo, error)
	VerifyWithKey(context.Context, string, string, *metav1.Duration, oci.SignatureDiscoverer) (*oci.VerificationInfo, error)
	VerifyAttestation(context.Context, string, string, oci.AttestationTrust, oci.AttestationDiscoverer) (string, error)
	ResolvePlatforms(context.Context, string, []string) (map[string]string, error)
}

// CosignBuilder creates the cosign signature verification provider. A step
// always verifies the digest the tag points at, and optionally verifies the
// platform manifests listed in platform; each digest has its own policy.
func CosignBuilder(verifier cosignVerifier) Builder {
	return func(config apiv1.HookStep) (Step, error) {
		if verifier == nil {
			return nil, fmt.Errorf("cosign verifier is required")
		}
		if config.Cosign == nil {
			return nil, fmt.Errorf("cosign configuration is required")
		}
		policy, err := newCosignPolicy(config.Cosign.CosignPolicy)
		if err != nil {
			return nil, err
		}
		step := cosignStep{verifier: verifier, artifact: policy}
		if config.Cosign.Platform != nil {
			policy, err := newCosignPolicy(config.Cosign.Platform.CosignPolicy)
			if err != nil {
				return nil, err
			}
			step.platform = &policy
			step.platforms = config.Cosign.Platform.Platforms
		}
		return step, nil
	}
}

// cosignTrust is whom to trust for a signature or an attestation. With a
// publicKey it is key-based and keyFingerprint names the key in the report;
// otherwise it is keyless and identities holds the identities.
type cosignTrust struct {
	identities     []apiv1.OIDCIdentity
	publicKey      string
	keyFingerprint string
}

func newCosignTrust(v apiv1.CosignVerifier) (cosignTrust, error) {
	switch {
	case v.PublicKey != "" && len(v.MatchOIDCIdentity) > 0:
		return cosignTrust{}, fmt.Errorf("publicKey and matchOIDCIdentity are mutually exclusive")
	case v.PublicKey == "" && len(v.MatchOIDCIdentity) == 0:
		return cosignTrust{}, fmt.Errorf("one of matchOIDCIdentity and publicKey is required")
	}
	trust := cosignTrust{identities: v.MatchOIDCIdentity, publicKey: v.PublicKey}
	if v.PublicKey != "" {
		key, err := oci.ParsePublicKeyPEM(v.PublicKey)
		if err != nil {
			return cosignTrust{}, err
		}
		if trust.keyFingerprint, err = oci.PublicKeyFingerprint(key); err != nil {
			return cosignTrust{}, err
		}
	}
	return trust, nil
}

// cosignPolicy is what must hold for one digest: a signature and attestations,
// each with its own trust.
type cosignPolicy struct {
	signature    cosignTrust
	minAge       *metav1.Duration
	attestations []cosignAttestationPolicy
}

type cosignAttestationPolicy struct {
	predicateType string
	trust         cosignTrust
}

func newCosignPolicy(p apiv1.CosignPolicy) (cosignPolicy, error) {
	signature, err := newCosignTrust(p.Signature.CosignVerifier)
	if err != nil {
		return cosignPolicy{}, fmt.Errorf("signature: %w", err)
	}
	policy := cosignPolicy{signature: signature, minAge: p.Signature.MinAge}
	for i, a := range p.Attestations {
		predicateType, ok := apiv1.EffectivePredicateType(a.Type)
		if !ok {
			return cosignPolicy{}, fmt.Errorf("attestations[%d]: %q is not a predicate type", i, a.Type)
		}
		trust, err := newCosignTrust(a.CosignVerifier)
		if err != nil {
			return cosignPolicy{}, fmt.Errorf("attestations[%d]: %w", i, err)
		}
		policy.attestations = append(policy.attestations, cosignAttestationPolicy{predicateType: predicateType, trust: trust})
	}
	return policy, nil
}

type cosignStep struct {
	verifier  cosignVerifier
	artifact  cosignPolicy
	platform  *cosignPolicy
	platforms []string
}

// Units implements Step. Without platform verification, the artifact digest
// is one unnamed unit. With platform verification, the artifact digest is a
// named unit followed by one unit per selected platform.
func (s cosignStep) Units(_ context.Context, input Input) ([]Unit, error) {
	artifactRef := input.Source + "@" + input.Digest
	if s.platform == nil {
		return []Unit{{Run: func(ctx context.Context) (Outcome, error) {
			return s.verify(ctx, artifactRef, input.Digest, s.artifact)
		}}}, nil
	}

	units := []Unit{{Name: "artifact", Run: func(ctx context.Context) (Outcome, error) {
		return s.verify(ctx, artifactRef, input.Digest, s.artifact)
	}}}
	resolver := &platformResolver{verifier: s.verifier, ref: artifactRef, platforms: s.platforms}
	for _, platform := range s.platforms {
		units = append(units, Unit{Name: platform, Run: func(ctx context.Context) (Outcome, error) {
			digest, err := resolver.digest(ctx, platform)
			if err != nil {
				return Outcome{}, err
			}
			return s.verify(ctx, input.Source+"@"+digest, digest, *s.platform)
		}})
	}
	return units, nil
}

// platformResolver reads the index once for all the units of a tag. A failure
// is not kept, so a unit that is retried asks again.
type platformResolver struct {
	verifier  cosignVerifier
	ref       string
	platforms []string

	mu      sync.Mutex
	digests map[string]string
}

func (r *platformResolver) digest(ctx context.Context, platform string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.digests == nil {
		digests, err := r.verifier.ResolvePlatforms(ctx, r.ref, r.platforms)
		if err != nil {
			return "", err
		}
		r.digests = digests
		if r.digests == nil {
			r.digests = map[string]string{}
		}
	}
	digest, ok := r.digests[platform]
	if !ok {
		return "", Permanent(fmt.Errorf("platform %s is not in %s", platform, r.ref))
	}
	return digest, nil
}

// verify checks the signature of ref and then its attestations. The digest is
// the one ref pins; the verifier must report the same one.
func (s cosignStep) verify(ctx context.Context, ref, digest string, policy cosignPolicy) (Outcome, error) {
	var info *oci.VerificationInfo
	var err error
	sig := policy.signature
	if sig.publicKey != "" {
		info, err = s.verifier.VerifyWithKey(ctx, ref, sig.publicKey, policy.minAge, discoverCosignBundle)
	} else {
		info, err = s.verifier.VerifyWithDiscovery(ctx, ref, apiv1.ArtifactVerification{
			Provider:          apiv1.VerifyProviderCosign,
			MatchOIDCIdentity: sig.identities,
			MinAge:            policy.minAge,
		}, discoverCosignBundle)
	}
	if err != nil {
		var tooNew *oci.SignatureTooNewError
		if errors.As(err, &tooNew) {
			if info == nil {
				return Outcome{}, fmt.Errorf("cosign verifier returned no metadata for a too-new signature")
			}
			return Outcome{
				Verdict: apiv1.StepVerdictSkip,
				Reason:  apiv1.ReasonSignatureTooNew,
				Cosign:  cosignVerification(info, tooNew, sig),
			}, nil
		}
		var rejected *oci.SignatureRejectedError
		if errors.As(err, &rejected) {
			return Outcome{
				Verdict: apiv1.StepVerdictDeny,
				Reason:  rejected.Error(),
			}, nil
		}
		return Outcome{}, err
	}
	if info == nil {
		return Outcome{}, fmt.Errorf("cosign verifier returned no verification result")
	}
	if info.Digest != "" && info.Digest != digest {
		return Outcome{}, fmt.Errorf("cosign verifier returned digest %q, want %q", info.Digest, digest)
	}

	verification := cosignVerification(info, nil, sig)
	// The .att tag is read once for all the attestations of this digest.
	discover := memoizeAttestations(discoverCosignAttestations)
	for _, att := range policy.attestations {
		predicateType, err := s.verifier.VerifyAttestation(ctx, ref, att.predicateType, oci.AttestationTrust{
			Identities:   att.trust.identities,
			PublicKeyPEM: att.trust.publicKey,
		}, discover)
		if err != nil {
			var rejected *oci.SignatureRejectedError
			if errors.As(err, &rejected) {
				return Outcome{Verdict: apiv1.StepVerdictDeny, Reason: rejected.Error()}, nil
			}
			return Outcome{}, err
		}
		verification.Attestations = append(verification.Attestations, predicateType)
	}

	return Outcome{
		Verdict: apiv1.StepVerdictAllow,
		Cosign:  verification,
	}, nil
}

// memoizeAttestations wraps discover so that the attestations of a digest are
// read once, however many attestation policies are checked against them. A
// failure is not kept.
func memoizeAttestations(discover oci.AttestationDiscoverer) oci.AttestationDiscoverer {
	type key struct {
		repo   string
		digest string
	}
	var (
		mu    sync.Mutex
		cache = map[key][]verify.SignedEntity{}
	)
	return func(repo name.Repository, digest v1.Hash, opts ...remote.Option) ([]verify.SignedEntity, error) {
		k := key{repo: repo.String(), digest: digest.String()}
		mu.Lock()
		defer mu.Unlock()
		if entities, ok := cache[k]; ok {
			return entities, nil
		}
		entities, err := discover(repo, digest, opts...)
		if err != nil {
			return nil, err
		}
		cache[k] = entities
		return entities, nil
	}
}

func cosignVerification(info *oci.VerificationInfo, tooNew *oci.SignatureTooNewError, trust cosignTrust) *apiv1.Verification {
	verification := &apiv1.Verification{
		Provider: apiv1.VerifyProviderCosign,
		Issuer:   info.Issuer,
		Identity: info.Identity,
		Key:      trust.keyFingerprint,
	}
	if !info.IntegratedTime.IsZero() {
		verification.IntegratedTime = info.IntegratedTime.UTC().Format(time.RFC3339)
	}
	if tooNew != nil {
		verification.Age = tooNew.Age.Round(time.Second).String()
		verification.MinAge = tooNew.MinAge.String()
	}
	return verification
}

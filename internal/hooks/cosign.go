// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
	"github.com/fluxcd/flux-mirror/internal/oci"
)

type cosignVerifier interface {
	VerifyWithDiscovery(context.Context, string, apiv1.ArtifactVerification, oci.SignatureDiscoverer) (*oci.VerificationInfo, error)
	VerifyAttestations(context.Context, string, []apiv1.OIDCIdentity, []string, oci.AttestationDiscoverer) ([]string, error)
	ResolvePlatforms(context.Context, string, []string) (map[string]string, error)
}

// CosignBuilder creates the cosign signature verification provider. A step
// verifies the digest the tag points at (index), the platform manifests listed
// in platform, or both; each is a work unit with its own policy.
func CosignBuilder(verifier cosignVerifier) Builder {
	return func(config apiv1.HookStep) (Step, error) {
		if verifier == nil {
			return nil, fmt.Errorf("cosign verifier is required")
		}
		if config.Cosign == nil {
			return nil, fmt.Errorf("cosign configuration is required")
		}
		step := cosignStep{verifier: verifier}
		if config.Cosign.Index != nil {
			policy := newCosignPolicy(*config.Cosign.Index)
			step.index = &policy
		}
		if config.Cosign.Platform != nil {
			policy := newCosignPolicy(config.Cosign.Platform.CosignPolicy)
			step.platform = &policy
			step.platforms = config.Cosign.Platform.Platforms
		}
		if step.index == nil && step.platform == nil {
			return nil, fmt.Errorf("cosign configuration needs index, platform or both")
		}
		return step, nil
	}
}

// cosignPolicy is what must hold for one digest.
type cosignPolicy struct {
	config       apiv1.ArtifactVerification
	attestations []string
}

func newCosignPolicy(p apiv1.CosignPolicy) cosignPolicy {
	return cosignPolicy{
		config: apiv1.ArtifactVerification{
			Provider:          apiv1.VerifyProviderCosign,
			MatchOIDCIdentity: p.MatchOIDCIdentity,
			MinAge:            p.MinAge,
		},
		attestations: p.Attestations,
	}
}

type cosignStep struct {
	verifier  cosignVerifier
	index     *cosignPolicy
	platform  *cosignPolicy
	platforms []string
}

// Units implements Step. A step with only an index policy is one unnamed unit,
// so its result keeps the shape it had before platforms existed. With a
// platform policy there is a unit named index (when configured) and one per
// platform, so each digest is reported and retried on its own.
func (s cosignStep) Units(_ context.Context, input Input) ([]Unit, error) {
	indexRef := input.Source + "@" + input.Digest
	if s.platform == nil {
		return []Unit{{Run: func(ctx context.Context) (Outcome, error) {
			return s.verify(ctx, indexRef, input.Digest, *s.index)
		}}}, nil
	}

	var units []Unit
	if s.index != nil {
		units = append(units, Unit{Name: "index", Run: func(ctx context.Context) (Outcome, error) {
			return s.verify(ctx, indexRef, input.Digest, *s.index)
		}})
	}
	resolver := &platformResolver{verifier: s.verifier, ref: indexRef, platforms: s.platforms}
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
	info, err := s.verifier.VerifyWithDiscovery(ctx, ref, policy.config, discoverCosignBundle)
	if err != nil {
		var tooNew *oci.SignatureTooNewError
		if errors.As(err, &tooNew) {
			if info == nil {
				return Outcome{}, fmt.Errorf("cosign verifier returned no metadata for a too-new signature")
			}
			return Outcome{
				Verdict: apiv1.StepVerdictSkip,
				Reason:  apiv1.ReasonSignatureTooNew,
				Cosign:  cosignVerification(info, tooNew),
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

	verification := cosignVerification(info, nil)
	if len(policy.attestations) > 0 {
		types, err := s.verifier.VerifyAttestations(ctx, ref, policy.config.MatchOIDCIdentity, policy.attestations, discoverCosignAttestations)
		if err != nil {
			var rejected *oci.SignatureRejectedError
			if errors.As(err, &rejected) {
				return Outcome{Verdict: apiv1.StepVerdictDeny, Reason: rejected.Error()}, nil
			}
			return Outcome{}, err
		}
		verification.Attestations = types
	}

	return Outcome{
		Verdict: apiv1.StepVerdictAllow,
		Cosign:  verification,
	}, nil
}

func cosignVerification(info *oci.VerificationInfo, tooNew *oci.SignatureTooNewError) *apiv1.Verification {
	verification := &apiv1.Verification{
		Provider: apiv1.VerifyProviderCosign,
		Issuer:   info.Issuer,
		Identity: info.Identity,
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

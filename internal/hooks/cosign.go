// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"context"
	"errors"
	"fmt"
	"time"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
	"github.com/fluxcd/flux-mirror/internal/oci"
)

type cosignVerifier interface {
	VerifyWithDiscovery(context.Context, string, apiv1.ArtifactVerification, oci.SignatureDiscoverer) (*oci.VerificationInfo, error)
}

// CosignBuilder creates the cosign signature verification provider.
func CosignBuilder(verifier cosignVerifier) Builder {
	return func(config apiv1.HookStep) (Step, error) {
		if verifier == nil {
			return nil, fmt.Errorf("cosign verifier is required")
		}
		if config.Cosign == nil {
			return nil, fmt.Errorf("cosign configuration is required")
		}
		return cosignStep{
			verifier: verifier,
			config: apiv1.ArtifactVerification{
				Provider:          apiv1.VerifyProviderCosign,
				MatchOIDCIdentity: config.Cosign.MatchOIDCIdentity,
				MinAge:            config.Cosign.MinAge,
			},
		}, nil
	}
}

type cosignStep struct {
	verifier cosignVerifier
	config   apiv1.ArtifactVerification
}

func (s cosignStep) Run(ctx context.Context, input Input) (Outcome, error) {
	ref := input.Source + "@" + input.Digest
	info, err := s.verifier.VerifyWithDiscovery(ctx, ref, s.config, discoverCosignBundle)
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
	if info.Digest != "" && info.Digest != input.Digest {
		return Outcome{}, fmt.Errorf("cosign verifier returned digest %q, want %q", info.Digest, input.Digest)
	}

	return Outcome{
		Verdict: apiv1.StepVerdictAllow,
		Cosign:  cosignVerification(info, nil),
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

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
	VerifyReferrers(context.Context, string, apiv1.ArtifactVerification) (*oci.VerificationInfo, error)
}

// CosignBuilder creates the referrer-only cosign provider.
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
	info, err := s.verifier.VerifyReferrers(ctx, ref, s.config)
	if err != nil {
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

	verification := &apiv1.Verification{
		Provider: apiv1.VerifyProviderCosign,
		Issuer:   info.Issuer,
		Identity: info.Identity,
	}
	if !info.IntegratedTime.IsZero() {
		verification.IntegratedTime = info.IntegratedTime.UTC().Format(time.RFC3339)
	}
	return Outcome{
		Verdict: apiv1.StepVerdictAllow,
		Cosign:  verification,
	}, nil
}

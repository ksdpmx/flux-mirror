// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"context"
	"errors"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
	"github.com/fluxcd/flux-mirror/internal/oci"
)

type fakeCosignVerifier struct {
	ref  string
	cfg  apiv1.ArtifactVerification
	info *oci.VerificationInfo
	err  error
}

func (v *fakeCosignVerifier) VerifyReferrers(_ context.Context, ref string, cfg apiv1.ArtifactVerification) (*oci.VerificationInfo, error) {
	v.ref = ref
	v.cfg = cfg
	return v.info, v.err
}

func TestCosignStep_VerifiesPinnedDigest(t *testing.T) {
	g := NewWithT(t)
	integratedTime := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	verifier := &fakeCosignVerifier{info: &oci.VerificationInfo{
		Provider:       apiv1.VerifyProviderCosign,
		Digest:         "sha256:abc",
		Issuer:         "https://token.actions.githubusercontent.com",
		Identity:       "https://github.com/example/repo/workflow",
		IntegratedTime: integratedTime,
	}}
	stepConfig := apiv1.HookStep{
		Name:     "signature",
		Provider: apiv1.HookProviderCosign,
		Cosign: &apiv1.CosignHookConfig{MatchOIDCIdentity: []apiv1.OIDCIdentity{{
			Issuer:  "https://token.actions.githubusercontent.com",
			Subject: `^https://github\.com/example/.*$`,
		}}},
	}
	builder := CosignBuilder(verifier)
	step, err := builder(stepConfig)
	g.Expect(err).ToNot(HaveOccurred())

	outcome, err := step.Run(context.Background(), Input{
		Source: "ghcr.io/example/image", Tag: "v1", Digest: "sha256:abc",
	})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(verifier.ref).To(Equal("ghcr.io/example/image@sha256:abc"))
	g.Expect(verifier.cfg.Provider).To(Equal(apiv1.VerifyProviderCosign))
	g.Expect(verifier.cfg.MatchOIDCIdentity).To(Equal(stepConfig.Cosign.MatchOIDCIdentity))
	g.Expect(outcome.Verdict).To(Equal(apiv1.StepVerdictAllow))
	g.Expect(outcome.Cosign).To(Equal(&apiv1.Verification{
		Provider:       apiv1.VerifyProviderCosign,
		Issuer:         verifier.info.Issuer,
		Identity:       verifier.info.Identity,
		IntegratedTime: integratedTime.Format(time.RFC3339),
	}))
}

func TestCosignStep_MapsSignatureRejectionToDeny(t *testing.T) {
	g := NewWithT(t)
	verifier := &fakeCosignVerifier{
		err: oci.NewSignatureRejectedError(errors.New("no matching signature")),
	}
	step, err := CosignBuilder(verifier)(apiv1.HookStep{
		Name:     "signature",
		Provider: apiv1.HookProviderCosign,
		Cosign: &apiv1.CosignHookConfig{MatchOIDCIdentity: []apiv1.OIDCIdentity{{
			Issuer: "issuer", Subject: "subject",
		}}},
	})
	g.Expect(err).ToNot(HaveOccurred())

	outcome, err := step.Run(context.Background(), Input{
		Source: "ghcr.io/example/image", Digest: "sha256:abc",
	})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(outcome.Verdict).To(Equal(apiv1.StepVerdictDeny))
	g.Expect(outcome.Reason).To(Equal("no matching signature"))
}

func TestCosignStep_PropagatesInfrastructureError(t *testing.T) {
	g := NewWithT(t)
	verifier := &fakeCosignVerifier{err: errors.New("registry unavailable")}
	step, err := CosignBuilder(verifier)(apiv1.HookStep{
		Name:     "signature",
		Provider: apiv1.HookProviderCosign,
		Cosign: &apiv1.CosignHookConfig{MatchOIDCIdentity: []apiv1.OIDCIdentity{{
			Issuer: "issuer", Subject: "subject",
		}}},
	})
	g.Expect(err).ToNot(HaveOccurred())

	_, err = step.Run(context.Background(), Input{
		Source: "ghcr.io/example/image", Digest: "sha256:abc",
	})
	g.Expect(err).To(MatchError("registry unavailable"))
}

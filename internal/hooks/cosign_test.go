// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
	"github.com/fluxcd/flux-mirror/internal/oci"
)

type fakeCosignVerifier struct {
	ref      string
	cfg      apiv1.ArtifactVerification
	info     *oci.VerificationInfo
	err      error
	discover oci.SignatureDiscoverer
}

func (v *fakeCosignVerifier) VerifyWithDiscovery(
	_ context.Context,
	ref string,
	cfg apiv1.ArtifactVerification,
	discover oci.SignatureDiscoverer,
) (*oci.VerificationInfo, error) {
	v.ref = ref
	v.cfg = cfg
	v.discover = discover
	return v.info, v.err
}

// runSingleUnit runs the only unit of step for input.
func runSingleUnit(step Step, input Input) (Outcome, error) {
	units, err := step.Units(context.Background(), input)
	if err != nil {
		return Outcome{}, err
	}
	if len(units) != 1 {
		return Outcome{}, fmt.Errorf("got %d units, want 1", len(units))
	}
	return units[0].Run(context.Background())
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

	outcome, err := runSingleUnit(step, Input{
		Source: "ghcr.io/example/image", Tag: "v1", Digest: "sha256:abc",
	})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(verifier.ref).To(Equal("ghcr.io/example/image@sha256:abc"))
	g.Expect(verifier.discover).ToNot(BeNil())
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

func TestCosignStep_SkipsTooNewSignature(t *testing.T) {
	g := NewWithT(t)
	integratedTime := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	minAge := time.Hour
	verifier := &fakeCosignVerifier{
		info: &oci.VerificationInfo{
			Provider:       apiv1.VerifyProviderCosign,
			Digest:         "sha256:abc",
			Issuer:         "issuer",
			Identity:       "identity",
			IntegratedTime: integratedTime,
		},
		err: &oci.SignatureTooNewError{
			IntegratedTime: integratedTime,
			Age:            30 * time.Minute,
			MinAge:         minAge,
		},
	}
	stepConfig := apiv1.HookStep{
		Name:     "signature",
		Provider: apiv1.HookProviderCosign,
		Cosign: &apiv1.CosignHookConfig{
			MatchOIDCIdentity: []apiv1.OIDCIdentity{{Issuer: "issuer", Subject: "subject"}},
			MinAge:            &metav1.Duration{Duration: minAge},
		},
	}
	step, err := CosignBuilder(verifier)(stepConfig)
	g.Expect(err).ToNot(HaveOccurred())

	outcome, err := runSingleUnit(step, Input{
		Source: "ghcr.io/example/image", Digest: "sha256:abc",
	})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(verifier.cfg.MinAge.Duration).To(Equal(minAge))
	g.Expect(outcome.Verdict).To(Equal(apiv1.StepVerdictSkip))
	g.Expect(outcome.Reason).To(Equal(apiv1.ReasonSignatureTooNew))
	g.Expect(outcome.Cosign.Age).To(Equal("30m0s"))
	g.Expect(outcome.Cosign.MinAge).To(Equal("1h0m0s"))
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

	outcome, err := runSingleUnit(step, Input{
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

	_, err = runSingleUnit(step, Input{
		Source: "ghcr.io/example/image", Digest: "sha256:abc",
	})
	g.Expect(err).To(MatchError("registry unavailable"))
}

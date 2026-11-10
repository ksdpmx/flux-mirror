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

const (
	platformIndexDigest = "sha256:index"
	platformAMD64       = "sha256:amd64"
	platformARM64       = "sha256:arm64"
	platformSource      = "ghcr.io/example/image"
)

var platformIdentities = []apiv1.OIDCIdentity{{Issuer: "issuer", Subject: "subject"}}

func platformSignature() apiv1.CosignSignature {
	return signatureBy(apiv1.CosignVerifier{MatchOIDCIdentity: platformIdentities})
}

func platformAttestation(attestationType string) apiv1.CosignAttestation {
	return apiv1.CosignAttestation{Type: attestationType, CosignVerifier: apiv1.CosignVerifier{MatchOIDCIdentity: platformIdentities}}
}

func platformVerifier() *fakeCosignVerifier {
	info := func(digest string) *oci.VerificationInfo {
		return &oci.VerificationInfo{Provider: apiv1.VerifyProviderCosign, Digest: digest, Issuer: "issuer", Identity: "subject"}
	}
	return &fakeCosignVerifier{
		infoByRef: map[string]*oci.VerificationInfo{
			platformSource + "@" + platformIndexDigest: info(platformIndexDigest),
			platformSource + "@" + platformAMD64:       info(platformAMD64),
			platformSource + "@" + platformARM64:       info(platformARM64),
		},
		platformDigest: map[string]string{"linux/amd64": platformAMD64, "linux/arm64": platformARM64},
	}
}

func platformStep(t *testing.T, verifier *fakeCosignVerifier, config apiv1.CosignHookConfig) Step {
	t.Helper()
	step, err := CosignBuilder(verifier)(apiv1.HookStep{Name: "signature", Provider: apiv1.HookProviderCosign, Cosign: &config})
	NewWithT(t).Expect(err).ToNot(HaveOccurred())
	return step
}

func platformInput() Input {
	return Input{Source: platformSource, Digest: platformIndexDigest}
}

func platformPolicy(platforms ...string) *apiv1.CosignPlatformPolicy {
	return &apiv1.CosignPlatformPolicy{
		CosignPolicy: apiv1.CosignPolicy{Signature: platformSignature()},
		Platforms:    platforms,
	}
}

func unitNames(units []Unit) []string {
	names := make([]string, len(units))
	for i, u := range units {
		names[i] = u.Name
	}
	return names
}

func TestCosignStep_ArtifactOnlyIsOneUnnamedUnit(t *testing.T) {
	g := NewWithT(t)
	verifier := platformVerifier()
	step := platformStep(t, verifier, apiv1.CosignHookConfig{CosignPolicy: apiv1.CosignPolicy{Signature: platformSignature()}})

	units, err := step.Units(context.Background(), platformInput())

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(unitNames(units)).To(Equal([]string{""}))
	_, err = units[0].Run(context.Background())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(verifier.refs).To(Equal([]string{platformSource + "@" + platformIndexDigest}))
	g.Expect(verifier.platformCalls).To(BeZero())
}

func TestCosignStep_ArtifactAndPlatformsAreSeparateUnits(t *testing.T) {
	g := NewWithT(t)
	verifier := platformVerifier()
	step := platformStep(t, verifier, apiv1.CosignHookConfig{
		CosignPolicy: apiv1.CosignPolicy{Signature: platformSignature()},
		Platform:     platformPolicy("linux/amd64", "linux/arm64"),
	})

	units, err := step.Units(context.Background(), platformInput())

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(unitNames(units)).To(Equal([]string{"artifact", "linux/amd64", "linux/arm64"}))
	for _, unit := range units {
		outcome, err := unit.Run(context.Background())
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(outcome.Verdict).To(Equal(apiv1.StepVerdictAllow))
	}
	g.Expect(verifier.refs).To(Equal([]string{
		platformSource + "@" + platformIndexDigest,
		platformSource + "@" + platformAMD64,
		platformSource + "@" + platformARM64,
	}))
	g.Expect(verifier.platformCalls).To(Equal(1), "the index is read once for all platforms")
	g.Expect(verifier.platformRef).To(Equal(platformSource + "@" + platformIndexDigest))
	g.Expect(verifier.platformNames).To(Equal([]string{"linux/amd64", "linux/arm64"}))
}

func TestCosignStep_MissingPlatformIsAPermanentError(t *testing.T) {
	g := NewWithT(t)
	verifier := platformVerifier()
	step := platformStep(t, verifier, apiv1.CosignHookConfig{
		CosignPolicy: apiv1.CosignPolicy{Signature: platformSignature()},
		Platform:     platformPolicy("linux/s390x"),
	})
	units, err := step.Units(context.Background(), platformInput())
	g.Expect(err).ToNot(HaveOccurred())

	_, err = units[1].Run(context.Background())

	g.Expect(err).To(MatchError(ContainSubstring("platform linux/s390x is not in ghcr.io/example/image@sha256:index")))
	g.Expect(isPermanent(err)).To(BeTrue())
	g.Expect(verifier.refs).To(BeEmpty())
}

func TestCosignStep_ResolveFailureIsNotCachedSoARetryAsksAgain(t *testing.T) {
	g := NewWithT(t)
	verifier := platformVerifier()
	verifier.platformErr = errors.New("registry unavailable")
	step := platformStep(t, verifier, apiv1.CosignHookConfig{
		CosignPolicy: apiv1.CosignPolicy{Signature: platformSignature()},
		Platform:     platformPolicy("linux/amd64"),
	})
	units, err := step.Units(context.Background(), platformInput())
	g.Expect(err).ToNot(HaveOccurred())

	_, err = units[1].Run(context.Background())
	g.Expect(err).To(MatchError("registry unavailable"))

	verifier.platformErr = nil
	outcome, err := units[1].Run(context.Background())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(outcome.Verdict).To(Equal(apiv1.StepVerdictAllow))
	g.Expect(verifier.platformCalls).To(Equal(2))
}

func TestCosignStep_EachPolicyHasItsOwnAttestations(t *testing.T) {
	g := NewWithT(t)
	verifier := platformVerifier()
	platform := platformPolicy("linux/amd64")
	platform.Attestations = []apiv1.CosignAttestation{platformAttestation("spdx")}
	step := platformStep(t, verifier, apiv1.CosignHookConfig{
		CosignPolicy: apiv1.CosignPolicy{Signature: platformSignature(), Attestations: []apiv1.CosignAttestation{platformAttestation("slsa-provenance")}},
		Platform:     platform,
	})
	units, err := step.Units(context.Background(), platformInput())
	g.Expect(err).ToNot(HaveOccurred())

	for _, unit := range units {
		_, err := unit.Run(context.Background())
		g.Expect(err).ToNot(HaveOccurred())
	}

	g.Expect(verifier.attestationLog).To(Equal([]attestationCall{
		{ref: platformSource + "@" + platformIndexDigest, predicateType: "https://slsa.dev/provenance/v1", trust: oci.AttestationTrust{Identities: platformIdentities}},
		{ref: platformSource + "@" + platformAMD64, predicateType: "https://spdx.dev/Document", trust: oci.AttestationTrust{Identities: platformIdentities}},
	}))
}

func TestCosignStep_ArtifactWithoutAttestationsDoesNotCheckThemOnPlatforms(t *testing.T) {
	g := NewWithT(t)
	verifier := platformVerifier()
	platform := platformPolicy("linux/amd64")
	platform.Attestations = []apiv1.CosignAttestation{platformAttestation("spdx")}
	step := platformStep(t, verifier, apiv1.CosignHookConfig{
		CosignPolicy: apiv1.CosignPolicy{Signature: platformSignature()},
		Platform:     platform,
	})
	units, err := step.Units(context.Background(), platformInput())
	g.Expect(err).ToNot(HaveOccurred())

	_, err = units[0].Run(context.Background())

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(verifier.attestationLog).To(BeEmpty())
}

func TestCosignStep_RunnerReportsEveryUnitAndADeniedPlatformDeniesTheTag(t *testing.T) {
	g := NewWithT(t)
	verifier := platformVerifier()
	verifier.errByRef = map[string]error{
		platformSource + "@" + platformARM64: oci.NewSignatureRejectedError(errors.New("no matching signature")),
	}
	config := apiv1.ArtifactHooks{Pre: []apiv1.HookStep{{
		Name:     "signature",
		Provider: apiv1.HookProviderCosign,
		Cosign: &apiv1.CosignHookConfig{
			CosignPolicy: apiv1.CosignPolicy{Signature: platformSignature()},
			Platform:     platformPolicy("linux/amd64", "linux/arm64"),
		},
	}}}
	builders := map[string]Builder{apiv1.HookProviderCosign: CosignBuilder(verifier)}
	runner, err := NewRunner(config, time.Minute, builders)
	g.Expect(err).ToNot(HaveOccurred())

	result, err := runner.Run(context.Background(), platformInput())

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(result.Terminal).To(Equal(&Terminal{Status: apiv1.StatusBlocked, Reason: "signature", Digest: platformIndexDigest}))
	step := result.Steps[0]
	g.Expect(step.Verdict).To(Equal(apiv1.StepVerdictDeny))
	g.Expect(step.Reason).To(Equal("linux/arm64: no matching signature"))
	g.Expect(step.Units).To(HaveLen(3))
	g.Expect(step.Units[0].Name).To(Equal("artifact"))
	g.Expect(step.Units[0].Cosign).ToNot(BeNil())
	g.Expect(step.Units[1].Verdict).To(Equal(apiv1.StepVerdictAllow))
	g.Expect(step.Units[1].Cosign.Identity).To(Equal("subject"))
	g.Expect(step.Units[2].Verdict).To(Equal(apiv1.StepVerdictDeny))
	g.Expect(step.Units[2].Cosign).To(BeNil())
}

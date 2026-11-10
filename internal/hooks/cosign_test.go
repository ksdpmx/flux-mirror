// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore-go/pkg/verify"
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

	// refs records every reference verified, in order. infoByRef and errByRef
	// give a result per reference and take the place of info and err for it.
	refs      []string
	infoByRef map[string]*oci.VerificationInfo
	errByRef  map[string]error

	attestationLog   []attestationCall
	attestationCalls int
	attestationRef   string
	attestationErr   error

	keyCalls  int
	keyRef    string
	keyPEM    string
	keyMinAge *metav1.Duration

	platformCalls  int
	platformRef    string
	platformNames  []string
	platformDigest map[string]string
	platformErr    error
}

func (v *fakeCosignVerifier) ResolvePlatforms(_ context.Context, ref string, platforms []string) (map[string]string, error) {
	v.platformCalls++
	v.platformRef = ref
	v.platformNames = platforms
	return v.platformDigest, v.platformErr
}

func (v *fakeCosignVerifier) VerifyAttestation(
	_ context.Context,
	ref string,
	predicateType string,
	trust oci.AttestationTrust,
	_ oci.AttestationDiscoverer,
) (string, error) {
	v.attestationCalls++
	v.attestationRef = ref
	v.attestationLog = append(v.attestationLog, attestationCall{ref: ref, predicateType: predicateType, trust: trust})
	if v.attestationErr != nil {
		return "", v.attestationErr
	}
	return predicateType, nil
}

type attestationCall struct {
	ref           string
	predicateType string
	trust         oci.AttestationTrust
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
	v.refs = append(v.refs, ref)
	if info, ok := v.infoByRef[ref]; ok {
		return info, v.errByRef[ref]
	}
	if err, ok := v.errByRef[ref]; ok {
		return nil, err
	}
	return v.info, v.err
}

func (v *fakeCosignVerifier) VerifyWithKey(
	_ context.Context,
	ref string,
	publicKeyPEM string,
	minAge *metav1.Duration,
	_ oci.SignatureDiscoverer,
) (*oci.VerificationInfo, error) {
	v.keyCalls++
	v.keyRef = ref
	v.keyPEM = publicKeyPEM
	v.keyMinAge = minAge
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
		Cosign: &apiv1.CosignHookConfig{CosignPolicy: apiv1.CosignPolicy{Signature: signatureBy(apiv1.CosignVerifier{MatchOIDCIdentity: []apiv1.OIDCIdentity{{
			Issuer:  "https://token.actions.githubusercontent.com",
			Subject: `^https://github\.com/example/.*$`,
		}}})}},
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
	g.Expect(verifier.cfg.MatchOIDCIdentity).To(Equal(stepConfig.Cosign.Signature.MatchOIDCIdentity))
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
		Cosign: &apiv1.CosignHookConfig{CosignPolicy: apiv1.CosignPolicy{Signature: apiv1.CosignSignature{
			CosignVerifier: apiv1.CosignVerifier{MatchOIDCIdentity: []apiv1.OIDCIdentity{{Issuer: "issuer", Subject: "subject"}}},
			MinAge:         &metav1.Duration{Duration: minAge},
		}}},
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
		Cosign: &apiv1.CosignHookConfig{CosignPolicy: apiv1.CosignPolicy{Signature: signatureBy(apiv1.CosignVerifier{
			MatchOIDCIdentity: []apiv1.OIDCIdentity{{Issuer: "issuer", Subject: "subject"}},
		})}},
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
		Cosign: &apiv1.CosignHookConfig{CosignPolicy: apiv1.CosignPolicy{Signature: signatureBy(apiv1.CosignVerifier{
			MatchOIDCIdentity: []apiv1.OIDCIdentity{{Issuer: "issuer", Subject: "subject"}},
		})}},
	})
	g.Expect(err).ToNot(HaveOccurred())

	_, err = runSingleUnit(step, Input{
		Source: "ghcr.io/example/image", Digest: "sha256:abc",
	})
	g.Expect(err).To(MatchError("registry unavailable"))
}

func attestationStep(t *testing.T, verifier *fakeCosignVerifier, attestations ...apiv1.CosignAttestation) Step {
	t.Helper()
	step, err := CosignBuilder(verifier)(apiv1.HookStep{
		Name:     "signature",
		Provider: apiv1.HookProviderCosign,
		Cosign: &apiv1.CosignHookConfig{CosignPolicy: apiv1.CosignPolicy{
			Signature:    signatureBy(apiv1.CosignVerifier{MatchOIDCIdentity: []apiv1.OIDCIdentity{{Issuer: "issuer", Subject: "subject"}}}),
			Attestations: attestations,
		}},
	})
	NewWithT(t).Expect(err).ToNot(HaveOccurred())
	return step
}

func signatureBy(v apiv1.CosignVerifier) apiv1.CosignSignature {
	return apiv1.CosignSignature{CosignVerifier: v}
}

var attestationIdentities = []apiv1.OIDCIdentity{{Issuer: "att-issuer", Subject: "att-subject"}}

func spdxAttestation() apiv1.CosignAttestation {
	return apiv1.CosignAttestation{Type: "spdx", CosignVerifier: apiv1.CosignVerifier{MatchOIDCIdentity: attestationIdentities}}
}

func TestCosignStep_VerifiesAttestationsAfterTheSignature(t *testing.T) {
	g := NewWithT(t)
	verifier := &fakeCosignVerifier{
		info: &oci.VerificationInfo{Provider: apiv1.VerifyProviderCosign, Digest: "sha256:abc"},
	}
	step := attestationStep(t, verifier, spdxAttestation())

	outcome, err := runSingleUnit(step, Input{Source: "ghcr.io/example/image", Digest: "sha256:abc"})

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(verifier.attestationCalls).To(Equal(1))
	g.Expect(verifier.attestationRef).To(Equal("ghcr.io/example/image@sha256:abc"))
	g.Expect(verifier.attestationLog).To(Equal([]attestationCall{{
		ref:           "ghcr.io/example/image@sha256:abc",
		predicateType: "https://spdx.dev/Document",
		trust:         oci.AttestationTrust{Identities: attestationIdentities},
	}}), "an attestation is verified with its own identities, not the signature's")
	g.Expect(outcome.Verdict).To(Equal(apiv1.StepVerdictAllow))
	g.Expect(outcome.Cosign.Attestations).To(Equal([]string{"https://spdx.dev/Document"}))
}

func TestCosignStep_DoesNotCheckAttestationsWhenNoneAreConfigured(t *testing.T) {
	g := NewWithT(t)
	verifier := &fakeCosignVerifier{info: &oci.VerificationInfo{Provider: apiv1.VerifyProviderCosign, Digest: "sha256:abc"}}
	step := attestationStep(t, verifier)

	outcome, err := runSingleUnit(step, Input{Source: "ghcr.io/example/image", Digest: "sha256:abc"})

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(verifier.attestationCalls).To(BeZero())
	g.Expect(outcome.Cosign.Attestations).To(BeEmpty())
}

func TestCosignStep_MissingAttestationDenies(t *testing.T) {
	g := NewWithT(t)
	verifier := &fakeCosignVerifier{
		info:           &oci.VerificationInfo{Provider: apiv1.VerifyProviderCosign, Digest: "sha256:abc"},
		attestationErr: oci.NewSignatureRejectedError(errors.New("no verified attestation of type https://spdx.dev/Document")),
	}
	step := attestationStep(t, verifier, spdxAttestation())

	outcome, err := runSingleUnit(step, Input{Source: "ghcr.io/example/image", Digest: "sha256:abc"})

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(outcome.Verdict).To(Equal(apiv1.StepVerdictDeny))
	g.Expect(outcome.Reason).To(ContainSubstring("no verified attestation of type https://spdx.dev/Document"))
}

func TestCosignStep_AttestationInfrastructureErrorIsAnError(t *testing.T) {
	g := NewWithT(t)
	verifier := &fakeCosignVerifier{
		info:           &oci.VerificationInfo{Provider: apiv1.VerifyProviderCosign, Digest: "sha256:abc"},
		attestationErr: errors.New("registry unavailable"),
	}
	step := attestationStep(t, verifier, spdxAttestation())

	_, err := runSingleUnit(step, Input{Source: "ghcr.io/example/image", Digest: "sha256:abc"})

	g.Expect(err).To(MatchError("registry unavailable"))
}

func TestCosignStep_RejectedSignatureSkipsTheAttestationCheck(t *testing.T) {
	g := NewWithT(t)
	verifier := &fakeCosignVerifier{err: oci.NewSignatureRejectedError(errors.New("no matching signature"))}
	step := attestationStep(t, verifier, spdxAttestation())

	outcome, err := runSingleUnit(step, Input{Source: "ghcr.io/example/image", Digest: "sha256:abc"})

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(outcome.Verdict).To(Equal(apiv1.StepVerdictDeny))
	g.Expect(verifier.attestationCalls).To(BeZero())
}

const testPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENQlf6X0DsdsOYZGCbV83JVKne7Kp
3XwxwGj+rHJLUPTBAbXA+vL+eZcDiFkoGbrXMsHkYR5PW7xmClX3557D5A==
-----END PUBLIC KEY-----
`

func TestCosignStep_VerifiesWithPublicKey(t *testing.T) {
	g := NewWithT(t)
	verifier := &fakeCosignVerifier{info: &oci.VerificationInfo{
		Provider: apiv1.VerifyProviderCosign,
		Digest:   "sha256:abc",
	}}
	minAge := &metav1.Duration{Duration: time.Hour}
	step, err := CosignBuilder(verifier)(apiv1.HookStep{
		Name:     "signature",
		Provider: apiv1.HookProviderCosign,
		Cosign: &apiv1.CosignHookConfig{CosignPolicy: apiv1.CosignPolicy{
			Signature: apiv1.CosignSignature{CosignVerifier: apiv1.CosignVerifier{PublicKey: testPublicKeyPEM}, MinAge: minAge},
		}},
	})
	g.Expect(err).ToNot(HaveOccurred())

	outcome, err := runSingleUnit(step, Input{Source: "public-registry.wiz.io/charts/wiz-sensor", Tag: "1.0.13003", Digest: "sha256:abc"})

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(outcome.Verdict).To(Equal(apiv1.StepVerdictAllow))
	g.Expect(verifier.keyCalls).To(Equal(1))
	g.Expect(verifier.keyRef).To(Equal("public-registry.wiz.io/charts/wiz-sensor@sha256:abc"))
	g.Expect(verifier.keyPEM).To(Equal(testPublicKeyPEM))
	g.Expect(verifier.keyMinAge).To(Equal(minAge))
	g.Expect(verifier.ref).To(BeEmpty(), "the keyless path must not run")
	g.Expect(outcome.Cosign.Key).To(Equal("sha256:080cd7b20a0ec16356024a6ba09fec5a4556997579afd225b3604d0e6b119356"))
	g.Expect(outcome.Cosign.Identity).To(BeEmpty())
}

func TestCosignStep_RejectsAnInvalidPublicKey(t *testing.T) {
	g := NewWithT(t)
	_, err := CosignBuilder(&fakeCosignVerifier{})(apiv1.HookStep{
		Name:     "signature",
		Provider: apiv1.HookProviderCosign,
		Cosign:   &apiv1.CosignHookConfig{CosignPolicy: apiv1.CosignPolicy{Signature: signatureBy(apiv1.CosignVerifier{PublicKey: "not a key"})}},
	})
	g.Expect(err).To(HaveOccurred())
}

func TestCosignStep_RequiresArtifactSignatureVerifier(t *testing.T) {
	g := NewWithT(t)
	_, err := CosignBuilder(&fakeCosignVerifier{})(apiv1.HookStep{
		Name:     "signature",
		Provider: apiv1.HookProviderCosign,
		Cosign:   &apiv1.CosignHookConfig{},
	})
	g.Expect(err).To(MatchError(ContainSubstring("one of matchOIDCIdentity and publicKey is required")))
}

func TestCosignStep_VerifiesAKeyBasedAttestationWithItsKey(t *testing.T) {
	g := NewWithT(t)
	verifier := &fakeCosignVerifier{info: &oci.VerificationInfo{Provider: apiv1.VerifyProviderCosign, Digest: "sha256:abc"}}
	step := attestationStep(t, verifier,
		apiv1.CosignAttestation{Type: "spdx", CosignVerifier: apiv1.CosignVerifier{PublicKey: testPublicKeyPEM}})

	outcome, err := runSingleUnit(step, Input{Source: "ghcr.io/example/image", Digest: "sha256:abc"})

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(outcome.Verdict).To(Equal(apiv1.StepVerdictAllow))
	g.Expect(verifier.attestationLog).To(Equal([]attestationCall{{
		ref:           "ghcr.io/example/image@sha256:abc",
		predicateType: "https://spdx.dev/Document",
		trust:         oci.AttestationTrust{PublicKeyPEM: testPublicKeyPEM},
	}}))
}

func TestCosignStep_EveryAttestationIsVerifiedAndOneMissingDenies(t *testing.T) {
	g := NewWithT(t)
	verifier := &fakeCosignVerifier{info: &oci.VerificationInfo{Provider: apiv1.VerifyProviderCosign, Digest: "sha256:abc"}}
	step := attestationStep(t, verifier, spdxAttestation(), apiv1.CosignAttestation{
		Type: "slsa-provenance", CosignVerifier: apiv1.CosignVerifier{MatchOIDCIdentity: attestationIdentities},
	})

	outcome, err := runSingleUnit(step, Input{Source: "ghcr.io/example/image", Digest: "sha256:abc"})

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(outcome.Cosign.Attestations).To(Equal([]string{"https://spdx.dev/Document", "https://slsa.dev/provenance/v1"}))
	g.Expect(verifier.attestationCalls).To(Equal(2))
}

func TestMemoizeAttestationsReadsOnceAndDoesNotKeepAFailure(t *testing.T) {
	g := NewWithT(t)
	repo, err := name.NewRepository("ghcr.io/example/image")
	g.Expect(err).ToNot(HaveOccurred())
	digest, err := v1.NewHash("sha256:" + strings.Repeat("a", 64))
	g.Expect(err).ToNot(HaveOccurred())
	calls := 0
	failFirst := true
	discover := memoizeAttestations(func(name.Repository, v1.Hash, ...remote.Option) ([]verify.SignedEntity, error) {
		calls++
		if failFirst {
			failFirst = false
			return nil, errors.New("registry unavailable")
		}
		return nil, nil
	})

	_, err = discover(repo, digest)
	g.Expect(err).To(HaveOccurred())
	_, err = discover(repo, digest)
	g.Expect(err).ToNot(HaveOccurred())
	_, err = discover(repo, digest)
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(calls).To(Equal(2))
}

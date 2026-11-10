// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
)

const testPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENQlf6X0DsdsOYZGCbV83JVKne7Kp
3XwxwGj+rHJLUPTBAbXA+vL+eZcDiFkoGbrXMsHkYR5PW7xmClX3557D5A==
-----END PUBLIC KEY-----
`

func TestValidateArtifactHooks(t *testing.T) {
	positive := 1
	zero := 0
	tests := []struct {
		name string
		step apiv1.HookStep
		err  string
	}{
		{
			name: "valid cosign step",
			step: apiv1.HookStep{
				Name:     "signature",
				Provider: apiv1.HookProviderCosign,
				Cosign:   &apiv1.CosignHookConfig{Index: idPolicy("https://token.actions.githubusercontent.com", `^https://github\.com/example/.*$`)},
			},
		},
		{
			name: "invalid step name",
			step: apiv1.HookStep{
				Name:     "Bad_Name",
				Provider: apiv1.HookProviderCosign,
				Cosign:   &apiv1.CosignHookConfig{Index: idPolicy("issuer", "subject")},
			},
			err: "lowercase identifier",
		},
		{
			name: "unknown provider",
			step: apiv1.HookStep{
				Name: "signature", Provider: "exec",
			},
			err: "provider",
		},
		{
			name: "missing cosign config",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
			},
			err: "cosign is required",
		},
		{
			name: "invalid timeout",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Timeout: &metav1.Duration{Duration: 0},
				Cosign:  &apiv1.CosignHookConfig{Index: idPolicy("issuer", "subject")},
			},
			err: "timeout must be greater than 0",
		},
		{
			name: "invalid concurrency",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Concurrency: &zero,
				Cosign:      &apiv1.CosignHookConfig{Index: idPolicy("issuer", "subject")},
			},
			err: "concurrency must be at least 1",
		},
		{
			name: "invalid retries",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Retries: func() *int { n := -1; return &n }(),
				Cosign:  &apiv1.CosignHookConfig{Index: idPolicy("issuer", "subject")},
			},
			err: "retries must be at least 0",
		},
		{
			name: "invalid onError",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				OnError: "ignore",
				Cosign:  &apiv1.CosignHookConfig{Index: idPolicy("issuer", "subject")},
			},
			err: "onError",
		},
		{
			name: "invalid onDeny",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				OnDeny: "ignore",
				Cosign: &apiv1.CosignHookConfig{Index: idPolicy("issuer", "subject")},
			},
			err: "onDeny",
		},
		{
			name: "attestation entry is neither an alias nor a URI",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Cosign: &apiv1.CosignHookConfig{Index: withAttestations(idPolicy("issuer", "subject"), idAttestation("sbom"))},
			},
			err: `attestations[0].type "sbom" must be one of cyclonedx, slsa-provenance, spdx or a predicate type URI`,
		},
		{
			name: "attestation given as an alias and as its URI",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Cosign: &apiv1.CosignHookConfig{Index: withAttestations(idPolicy("issuer", "subject"), idAttestation("spdx"), idAttestation("https://spdx.dev/Document"))},
			},
			err: `attestations[1].type "https://spdx.dev/Document" is duplicated by "spdx"`,
		},
		{
			name: "cosign without index or platform",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Cosign: &apiv1.CosignHookConfig{},
			},
			err: "at least one of index and platform is required",
		},
		{
			name: "index without identities",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Cosign: &apiv1.CosignHookConfig{Index: &apiv1.CosignPolicy{}},
			},
			err: "index: signature: one of matchOIDCIdentity and publicKey is required",
		},
		{
			name: "valid key-based cosign step",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Cosign: &apiv1.CosignHookConfig{Index: keyPolicy()},
			},
		},
		{
			name: "key-based signature with a key-based and a keyless attestation",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Cosign: &apiv1.CosignHookConfig{Index: withAttestations(keyPolicy(),
					apiv1.CosignAttestation{Type: "spdx", CosignVerifier: apiv1.CosignVerifier{PublicKey: testPublicKey}},
					idAttestation("slsa-provenance"))},
			},
		},
		{
			name: "signature with a key and identities",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Cosign: &apiv1.CosignHookConfig{Index: &apiv1.CosignPolicy{Signature: signatureBy(apiv1.CosignVerifier{
					PublicKey:         testPublicKey,
					MatchOIDCIdentity: []apiv1.OIDCIdentity{{Issuer: "issuer", Subject: "subject"}},
				})}},
			},
			err: "index: signature: publicKey and matchOIDCIdentity are mutually exclusive",
		},
		{
			name: "signature with an invalid public key",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Cosign: &apiv1.CosignHookConfig{Index: &apiv1.CosignPolicy{Signature: signatureBy(apiv1.CosignVerifier{PublicKey: "not a key"})}},
			},
			err: "index: signature: publicKey: ",
		},
		{
			name: "attestation without a verifier does not inherit the signature's",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Cosign: &apiv1.CosignHookConfig{Index: withAttestations(idPolicy("issuer", "subject"), apiv1.CosignAttestation{Type: "spdx"})},
			},
			err: "index: attestations[0]: one of matchOIDCIdentity and publicKey is required",
		},
		{
			name: "attestation with a key and identities",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Cosign: &apiv1.CosignHookConfig{Index: withAttestations(idPolicy("issuer", "subject"), apiv1.CosignAttestation{
					Type: "spdx",
					CosignVerifier: apiv1.CosignVerifier{
						PublicKey:         testPublicKey,
						MatchOIDCIdentity: []apiv1.OIDCIdentity{{Issuer: "issuer", Subject: "subject"}},
					},
				})},
			},
			err: "index: attestations[0]: publicKey and matchOIDCIdentity are mutually exclusive",
		},
		{
			name: "platform without platforms",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Cosign: &apiv1.CosignHookConfig{Platform: &apiv1.CosignPlatformPolicy{
					CosignPolicy: *idPolicy("issuer", "subject"),
				}},
			},
			err: "platform: platforms must contain at least one platform",
		},
		{
			name: "platform with an invalid platform",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Cosign: &apiv1.CosignHookConfig{Platform: &apiv1.CosignPlatformPolicy{
					CosignPolicy: *idPolicy("issuer", "subject"),
					Platforms:    []string{"linux"},
				}},
			},
			err: `platforms[0] "linux" must be os/arch or os/arch/variant`,
		},
		{
			name: "platform with a duplicated platform",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Cosign: &apiv1.CosignHookConfig{Platform: &apiv1.CosignPlatformPolicy{
					CosignPolicy: *idPolicy("issuer", "subject"),
					Platforms:    []string{"linux/amd64", "linux/amd64"},
				}},
			},
			err: `platforms[1] "linux/amd64" is duplicated`,
		},
		{
			name: "platform policy is validated on its own",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Cosign: &apiv1.CosignHookConfig{
					Index: idPolicy("issuer", "subject"),
					Platform: &apiv1.CosignPlatformPolicy{
						CosignPolicy: *withAttestations(idPolicy("issuer", "subject"), idAttestation("sbom")),
						Platforms:    []string{"linux/amd64"},
					},
				},
			},
			err: "platform: attestations[0]",
		},
		{
			name: "index and platform with their own policies",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Cosign: &apiv1.CosignHookConfig{
					Index: withAttestations(idPolicy("issuer", "subject"), idAttestation("slsa-provenance")),
					Platform: &apiv1.CosignPlatformPolicy{
						CosignPolicy: *withAttestations(idPolicy("other", "other"), idAttestation("spdx")),
						Platforms:    []string{"linux/amd64", "linux/arm64/v8"},
					},
				},
			},
		},
		{
			name: "invalid identity regex",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Cosign: &apiv1.CosignHookConfig{Index: idPolicy("issuer", "(")},
			},
			err: "does not compile",
		},
		{
			name: "negative minAge",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Cosign: &apiv1.CosignHookConfig{Index: func() *apiv1.CosignPolicy {
					p := idPolicy("issuer", "subject")
					p.Signature.MinAge = &metav1.Duration{Duration: -time.Second}
					return p
				}()},
			},
			err: "signature: minAge must be >= 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			err := validateArtifactHooks(apiv1.ArtifactHooks{Pre: []apiv1.HookStep{tt.step}})
			if tt.err == "" {
				g.Expect(err).ToNot(HaveOccurred())
			} else {
				g.Expect(err).To(MatchError(ContainSubstring(tt.err)))
			}
		})
	}

	t.Run("duplicate names", func(t *testing.T) {
		g := NewWithT(t)
		step := validHookStep()
		err := validateArtifactHooks(apiv1.ArtifactHooks{Pre: []apiv1.HookStep{step, step}})
		g.Expect(err).To(MatchError(ContainSubstring("is duplicated")))
	})

	t.Run("verify conflicts with hooks", func(t *testing.T) {
		g := NewWithT(t)
		entry := validArtifactEntry()
		entry.Verify = &apiv1.ArtifactVerification{
			Provider:          apiv1.VerifyProviderCosign,
			MatchOIDCIdentity: validHookStep().Cosign.Index.Signature.MatchOIDCIdentity,
		}
		entry.Hooks = &apiv1.ArtifactHooks{Pre: []apiv1.HookStep{validHookStep()}}
		g.Expect(validateArtifactEntry(entry)).To(MatchError(ContainSubstring("verify and hooks.pre")))
	})

	t.Run("warn and optional controls", func(t *testing.T) {
		g := NewWithT(t)
		step := validHookStep()
		step.Timeout = &metav1.Duration{Duration: time.Minute}
		step.Concurrency = &positive
		step.Retries = &zero
		step.OnDeny = apiv1.HookActionWarn
		step.OnError = apiv1.HookActionWarn
		step.Cosign.Index.Signature.MinAge = &metav1.Duration{Duration: time.Hour}
		step.Cosign.Index.Attestations = []apiv1.CosignAttestation{idAttestation("spdx"), idAttestation("slsa-provenance"), idAttestation("https://apko.dev/image-configuration")}
		g.Expect(validateArtifactHooks(apiv1.ArtifactHooks{Pre: []apiv1.HookStep{step}})).To(Succeed())
	})
}

func TestValidateWizcliHook(t *testing.T) {
	wizcliStep := func(mutate func(*apiv1.HookStep)) apiv1.HookStep {
		step := apiv1.HookStep{
			Name:     "vuln-scan",
			Provider: apiv1.HookProviderWizcli,
			Wizcli: &apiv1.WizcliHookConfig{
				Platforms: []string{"linux/amd64", "linux/arm64/v8"},
				Policies:  []string{"prod-vuln"},
			},
		}
		if mutate != nil {
			mutate(&step)
		}
		return step
	}
	tests := []struct {
		name   string
		mutate func(*apiv1.HookStep)
		err    string
	}{
		{name: "valid"},
		{name: "valid without policies", mutate: func(s *apiv1.HookStep) { s.Wizcli.Policies = nil }},
		{name: "missing wizcli block", mutate: func(s *apiv1.HookStep) { s.Wizcli = nil }, err: "wizcli is required"},
		{
			name: "cosign block on wizcli provider",
			mutate: func(s *apiv1.HookStep) {
				s.Cosign = validHookStep().Cosign
			},
			err: "cosign cannot be set",
		},
		{name: "no platforms", mutate: func(s *apiv1.HookStep) { s.Wizcli.Platforms = nil }, err: "at least one platform"},
		{name: "platform without os", mutate: func(s *apiv1.HookStep) { s.Wizcli.Platforms = []string{"amd64"} }, err: "os/arch"},
		{name: "empty platform", mutate: func(s *apiv1.HookStep) { s.Wizcli.Platforms = []string{""} }, err: "os/arch"},
		{
			name:   "duplicate platform",
			mutate: func(s *apiv1.HookStep) { s.Wizcli.Platforms = []string{"linux/amd64", "linux/amd64"} },
			err:    "is duplicated",
		},
		{name: "empty policy", mutate: func(s *apiv1.HookStep) { s.Wizcli.Policies = []string{" "} }, err: "must not be empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			err := validateArtifactHooks(apiv1.ArtifactHooks{Pre: []apiv1.HookStep{wizcliStep(tt.mutate)}})
			if tt.err == "" {
				g.Expect(err).ToNot(HaveOccurred())
			} else {
				g.Expect(err).To(MatchError(ContainSubstring(tt.err)))
			}
		})
	}

	t.Run("wizcli block on cosign provider", func(t *testing.T) {
		g := NewWithT(t)
		step := validHookStep()
		step.Wizcli = wizcliStep(nil).Wizcli
		err := validateArtifactHooks(apiv1.ArtifactHooks{Pre: []apiv1.HookStep{step}})
		g.Expect(err).To(MatchError(ContainSubstring("wizcli cannot be set")))
	})

	t.Run("decodes from YAML", func(t *testing.T) {
		g := NewWithT(t)
		raw := `apiVersion: mirror.plugin.fluxcd.io/v1beta2
kind: Config
artifacts:
  - source: ghcr.io/example/image
    destination: quay.io/mirror/image
    selector:
      semver: ">=1.0.0"
    hooks:
      pre:
        - name: vuln-scan
          provider: wizcli
          concurrency: 2
          retries: 1
          wizcli:
            platforms: [linux/amd64, linux/arm64]
            policies: [prod-vuln]
`
		cfg, _, err := Decode(strings.NewReader(raw))
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(Validate(cfg)).To(Succeed())
		g.Expect(cfg.Artifacts[0].Hooks.Pre[0].Wizcli.Platforms).To(Equal([]string{"linux/amd64", "linux/arm64"}))

		_, _, err = Decode(strings.NewReader(strings.Replace(raw, "policies: [prod-vuln]", "projects: [p1]", 1)))
		g.Expect(err).To(MatchError(ContainSubstring("unknown field")))
	})
}

func TestDecodeAndValidateHooks(t *testing.T) {
	g := NewWithT(t)
	raw := `apiVersion: mirror.plugin.fluxcd.io/v1beta2
kind: Config
artifacts:
  - source: ghcr.io/example/image
    destination: quay.io/mirror/image
    selector:
      semver: ">=1.0.0"
    hooks:
      pre:
        - name: signature
          provider: cosign
          cosign:
            index:
              signature:
                minAge: 12h
                matchOIDCIdentity:
                  - issuer: https://token.actions.githubusercontent.com
                    subject: ^https://github\.com/example/image/.*$
              attestations:
                - type: slsa-provenance
                  matchOIDCIdentity:
                    - issuer: https://token.actions.githubusercontent.com
                      subject: ^https://github\.com/slsa-framework/slsa-github-generator/.*$
`
	cfg, _, err := Decode(strings.NewReader(raw))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(Validate(cfg)).To(Succeed())
	g.Expect(cfg.Artifacts[0].Hooks.Pre).To(HaveLen(1))
	g.Expect(cfg.Artifacts[0].Hooks.Pre[0].Cosign.Index.Signature.MinAge.Duration).To(Equal(12 * time.Hour))
	g.Expect(cfg.Artifacts[0].Hooks.Pre[0].Cosign.Index.Attestations).To(HaveLen(1))
	g.Expect(cfg.Artifacts[0].Hooks.Pre[0].Cosign.Index.Attestations[0].MatchOIDCIdentity[0].Subject).To(ContainSubstring("slsa-github-generator"))

	t.Run("unknown provider config field is rejected", func(t *testing.T) {
		g := NewWithT(t)
		invalid := strings.Replace(raw, "                matchOIDCIdentity:", "                unexpected: true\n                matchOIDCIdentity:", 1)
		_, _, err := Decode(strings.NewReader(invalid))
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("unknown field"))
	})

	t.Run("charts hooks are rejected by strict decoding", func(t *testing.T) {
		g := NewWithT(t)
		invalid := `apiVersion: mirror.plugin.fluxcd.io/v1beta2
kind: Config
charts:
  - name: example
    source: https://charts.example.com
    destination: oci://ghcr.io/example/charts
    selector: {}
    hooks:
      pre: []
`
		_, _, err := Decode(strings.NewReader(invalid))
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("unknown field"))
	})
}

func validHookStep() apiv1.HookStep {
	return apiv1.HookStep{
		Name:     "signature",
		Provider: apiv1.HookProviderCosign,
		Cosign:   &apiv1.CosignHookConfig{Index: idPolicy("https://token.actions.githubusercontent.com", `^https://github\.com/example/.*$`)},
	}
}

func validArtifactEntry() apiv1.ArtifactEntry {
	return apiv1.ArtifactEntry{
		Source:      "ghcr.io/example/source",
		Destination: "ghcr.io/example/destination",
		Selector:    apiv1.Selector{},
	}
}

func idPolicy(issuer, subject string) *apiv1.CosignPolicy {
	return &apiv1.CosignPolicy{Signature: signatureBy(apiv1.CosignVerifier{
		MatchOIDCIdentity: []apiv1.OIDCIdentity{{Issuer: issuer, Subject: subject}},
	})}
}

func keyPolicy() *apiv1.CosignPolicy {
	return &apiv1.CosignPolicy{Signature: signatureBy(apiv1.CosignVerifier{PublicKey: testPublicKey})}
}

func signatureBy(v apiv1.CosignVerifier) apiv1.CosignSignature {
	return apiv1.CosignSignature{CosignVerifier: v}
}

func idAttestation(attestationType string) apiv1.CosignAttestation {
	return apiv1.CosignAttestation{Type: attestationType, CosignVerifier: apiv1.CosignVerifier{
		MatchOIDCIdentity: []apiv1.OIDCIdentity{{Issuer: "issuer", Subject: "subject"}},
	}}
}

func withAttestations(p *apiv1.CosignPolicy, attestations ...apiv1.CosignAttestation) *apiv1.CosignPolicy {
	p.Attestations = attestations
	return p
}

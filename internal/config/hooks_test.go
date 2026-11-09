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
				Cosign: &apiv1.CosignHookConfig{MatchOIDCIdentity: []apiv1.OIDCIdentity{{
					Issuer:  "https://token.actions.githubusercontent.com",
					Subject: `^https://github\.com/example/.*$`,
				}}},
			},
		},
		{
			name: "invalid step name",
			step: apiv1.HookStep{
				Name:     "Bad_Name",
				Provider: apiv1.HookProviderCosign,
				Cosign: &apiv1.CosignHookConfig{MatchOIDCIdentity: []apiv1.OIDCIdentity{{
					Issuer: "issuer", Subject: "subject",
				}}},
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
				Cosign: &apiv1.CosignHookConfig{MatchOIDCIdentity: []apiv1.OIDCIdentity{{
					Issuer: "issuer", Subject: "subject",
				}}},
			},
			err: "timeout must be greater than 0",
		},
		{
			name: "invalid concurrency",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Concurrency: &zero,
				Cosign: &apiv1.CosignHookConfig{MatchOIDCIdentity: []apiv1.OIDCIdentity{{
					Issuer: "issuer", Subject: "subject",
				}}},
			},
			err: "concurrency must be at least 1",
		},
		{
			name: "invalid retries",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Retries: func() *int { n := -1; return &n }(),
				Cosign: &apiv1.CosignHookConfig{MatchOIDCIdentity: []apiv1.OIDCIdentity{{
					Issuer: "issuer", Subject: "subject",
				}}},
			},
			err: "retries must be at least 0",
		},
		{
			name: "invalid onFailure",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				OnFailure: "ignore",
				Cosign: &apiv1.CosignHookConfig{MatchOIDCIdentity: []apiv1.OIDCIdentity{{
					Issuer: "issuer", Subject: "subject",
				}}},
			},
			err: "onFailure",
		},
		{
			name: "invalid identity regex",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Cosign: &apiv1.CosignHookConfig{MatchOIDCIdentity: []apiv1.OIDCIdentity{{
					Issuer: "issuer", Subject: "(",
				}}},
			},
			err: "does not compile",
		},
		{
			name: "negative minAge",
			step: apiv1.HookStep{
				Name: "signature", Provider: apiv1.HookProviderCosign,
				Cosign: &apiv1.CosignHookConfig{
					MatchOIDCIdentity: []apiv1.OIDCIdentity{{Issuer: "issuer", Subject: "subject"}},
					MinAge:            &metav1.Duration{Duration: -time.Second},
				},
			},
			err: "minAge must be >= 0",
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
			MatchOIDCIdentity: validHookStep().Cosign.MatchOIDCIdentity,
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
		step.OnFailure = apiv1.HookFailureWarn
		step.Cosign.MinAge = &metav1.Duration{Duration: time.Hour}
		g.Expect(validateArtifactHooks(apiv1.ArtifactHooks{Pre: []apiv1.HookStep{step}})).To(Succeed())
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
            minAge: 12h
            matchOIDCIdentity:
              - issuer: https://token.actions.githubusercontent.com
                subject: ^https://github\.com/example/image/.*$
`
	cfg, _, err := Decode(strings.NewReader(raw))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(Validate(cfg)).To(Succeed())
	g.Expect(cfg.Artifacts[0].Hooks.Pre).To(HaveLen(1))
	g.Expect(cfg.Artifacts[0].Hooks.Pre[0].Cosign.MinAge.Duration).To(Equal(12 * time.Hour))

	t.Run("unknown provider config field is rejected", func(t *testing.T) {
		g := NewWithT(t)
		invalid := strings.Replace(raw, "            matchOIDCIdentity:", "            unexpected: true\n            matchOIDCIdentity:", 1)
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
		Cosign: &apiv1.CosignHookConfig{MatchOIDCIdentity: []apiv1.OIDCIdentity{{
			Issuer:  "https://token.actions.githubusercontent.com",
			Subject: `^https://github\.com/example/.*$`,
		}}},
	}
}

func validArtifactEntry() apiv1.ArtifactEntry {
	return apiv1.ArtifactEntry{
		Source:      "ghcr.io/example/source",
		Destination: "ghcr.io/example/destination",
		Selector:    apiv1.Selector{},
	}
}

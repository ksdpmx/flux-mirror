// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	. "github.com/onsi/gomega"
	"helm.sh/helm/v4/pkg/provenance"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
	"github.com/fluxcd/flux-mirror/internal/helmrepo"
)

func TestHelmProvenanceBuilderAcceptsStandardArmor(t *testing.T) {
	g := NewWithT(t)
	publicKey, _ := newHelmTestKey(t)

	g.Expect(publicKey).To(ContainSubstring("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"))
	_, err := HelmProvenanceBuilder()(apiv1.HookStep{
		Name:     "verify-provenance",
		Provider: apiv1.HookProviderHelm,
		Helm:     &apiv1.HelmHookConfig{PublicKey: publicKey},
	})
	g.Expect(err).ToNot(HaveOccurred())
}

func TestHelmProvenanceBuilderRejectsCompactArmor(t *testing.T) {
	g := NewWithT(t)
	publicKey, _ := newHelmTestKey(t)
	compactKey := strings.Replace(
		publicKey,
		"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n",
		"-----BEGIN PGP PUBLIC KEY BLOCK-----\n",
		1,
	)

	_, err := HelmProvenanceBuilder()(apiv1.HookStep{
		Name:     "verify-provenance",
		Provider: apiv1.HookProviderHelm,
		Helm:     &apiv1.HelmHookConfig{PublicKey: compactKey},
	})
	g.Expect(err).To(MatchError(ContainSubstring("parse Helm provenance public key")))
}

func TestHelmProvenanceStepVerifiesChartArchive(t *testing.T) {
	g := NewWithT(t)
	publicKey, signer := newHelmTestKey(t)
	filename := "podinfo-1.0.0.tgz"
	archive := []byte("chart archive")
	prov, err := signer.ClearSign(archive, filename, []byte("chart metadata"))
	g.Expect(err).ToNot(HaveOccurred())

	step, err := HelmProvenanceBuilder()(apiv1.HookStep{
		Name:     "verify-provenance",
		Provider: apiv1.HookProviderHelm,
		Helm:     &apiv1.HelmHookConfig{PublicKey: publicKey},
	})
	g.Expect(err).ToNot(HaveOccurred())

	outcome, err := runSingleUnit(step, Input{
		HelmChart: &HelmChartInput{
			Archive: archive,
			FetchProvenance: func(context.Context) ([]byte, string, error) {
				return []byte(prov), filename, nil
			},
		},
	})

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(outcome.Verdict).To(Equal(apiv1.StepVerdictAllow))
}

func TestHelmProvenanceStepDeniesMissingOrInvalidProvenance(t *testing.T) {
	g := NewWithT(t)
	publicKey, signer := newHelmTestKey(t)
	filename := "podinfo-1.0.0.tgz"
	archive := []byte("chart archive")
	prov, err := signer.ClearSign(archive, filename, []byte("chart metadata"))
	g.Expect(err).ToNot(HaveOccurred())
	step, err := HelmProvenanceBuilder()(apiv1.HookStep{
		Name:     "verify-provenance",
		Provider: apiv1.HookProviderHelm,
		Helm:     &apiv1.HelmHookConfig{PublicKey: publicKey},
	})
	g.Expect(err).ToNot(HaveOccurred())

	for _, tt := range []struct {
		name       string
		archive    []byte
		provenance []byte
		provErr    error
		wantReason string
	}{
		{
			name:       "missing provenance",
			archive:    archive,
			provErr:    helmrepo.ErrProvenanceNotFound,
			wantReason: "helm provenance file is missing",
		},
		{
			name:       "archive digest mismatch",
			archive:    []byte("different chart archive"),
			provenance: []byte(prov),
			wantReason: "helm provenance verification failed",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			outcome, err := runSingleUnit(step, Input{
				HelmChart: &HelmChartInput{
					Archive: tt.archive,
					FetchProvenance: func(context.Context) ([]byte, string, error) {
						return tt.provenance, filename, tt.provErr
					},
				},
			})

			NewWithT(t).Expect(err).ToNot(HaveOccurred())
			NewWithT(t).Expect(outcome.Verdict).To(Equal(apiv1.StepVerdictDeny))
			NewWithT(t).Expect(outcome.Reason).To(ContainSubstring(tt.wantReason))
		})
	}
}

func newHelmTestKey(t *testing.T) (string, *provenance.Signatory) {
	t.Helper()
	entity, err := openpgp.NewEntity("Flux Mirror Test", "", "helm@example.com", nil)
	if err != nil {
		t.Fatalf("generate PGP key: %s", err)
	}
	var publicKey bytes.Buffer
	writer, err := armor.Encode(&publicKey, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("armor PGP public key: %s", err)
	}
	if err := entity.Serialize(writer); err != nil {
		t.Fatalf("serialize PGP public key: %s", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close armored PGP public key: %s", err)
	}
	return publicKey.String(), &provenance.Signatory{
		Entity:  entity,
		KeyRing: openpgp.EntityList{entity},
	}
}

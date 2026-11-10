// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"encoding/json"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	. "github.com/onsi/gomega"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
)

const (
	testIssuer   = "https://issuer.example.com"
	testIdentity = "https://issuer.example.com/group/identity"
	spdxType     = "https://spdx.dev/Document"
	slsaType     = "https://slsa.dev/provenance/v1"
)

var testIdentities = []apiv1.OIDCIdentity{{
	Issuer:  testIssuer,
	Subject: `^https://issuer\.example\.com/group/.*$`,
}}

func testDigest(t *testing.T, hexChar string) v1.Hash {
	t.Helper()
	h, err := v1.NewHash("sha256:" + string(repeat(hexChar, 64)))
	NewWithT(t).Expect(err).ToNot(HaveOccurred())
	return h
}

func repeat(s string, n int) []byte {
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, s...)
	}
	return out[:n]
}

// attest signs an in-toto statement of predicateType about digest with the
// virtual sigstore, the way cosign attest does.
func attest(t *testing.T, sigstore *ca.VirtualSigstore, identity, predicateType string, digest v1.Hash) verify.SignedEntity {
	t.Helper()
	statement, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": predicateType,
		"subject":       []map[string]any{{"name": "example", "digest": map[string]string{digest.Algorithm: digest.Hex}}},
		"predicate":     map[string]any{},
	})
	NewWithT(t).Expect(err).ToNot(HaveOccurred())
	entity, err := sigstore.Attest(identity, testIssuer, statement)
	NewWithT(t).Expect(err).ToNot(HaveOccurred())
	return entity
}

// identityPolicy is the keyless policy for testIdentities.
func identityPolicy(t *testing.T) []verify.PolicyOption {
	t.Helper()
	options, err := certificateIdentityOptions(testIdentities)
	NewWithT(t).Expect(err).ToNot(HaveOccurred())
	return options
}

// virtualSigstoreOptions are the production checks minus the signed certificate
// timestamp, which the virtual sigstore's certificates do not carry.
var virtualSigstoreOptions = []verify.VerifierOption{
	verify.WithIntegratedTimestamps(1),
	verify.WithTransparencyLog(1),
}

func TestAttestationVerifierOptions(t *testing.T) {
	g := NewWithT(t)
	sigstore, err := ca.NewVirtualSigstore()
	g.Expect(err).ToNot(HaveOccurred())
	digest := testDigest(t, "a")

	// The production options require a signed certificate timestamp, so a
	// certificate without one is rejected.
	_, err = verifyAttestationEntities(sigstore, digest,
		[]verify.SignedEntity{attest(t, sigstore, testIdentity, spdxType, digest)},
		[]string{"spdx"}, identityPolicy(t), attestationVerifierOptions())

	g.Expect(err).To(MatchError(ContainSubstring("signed certificate timestamp")))
}

func TestVerifyAttestationEntities(t *testing.T) {
	sigstore, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("create virtual sigstore: %s", err)
	}
	digest := testDigest(t, "a")
	other := testDigest(t, "b")

	tests := []struct {
		name     string
		entities []verify.SignedEntity
		required []string
		want     []string
		wantErr  string
	}{
		{
			name: "every required type is attached and verified",
			entities: []verify.SignedEntity{
				attest(t, sigstore, testIdentity, slsaType, digest),
				attest(t, sigstore, testIdentity, spdxType, digest),
			},
			required: []string{"spdx", "slsa-provenance"},
			want:     []string{spdxType, slsaType},
		},
		{
			name:     "an unrequired type is not needed and a full URI works",
			entities: []verify.SignedEntity{attest(t, sigstore, testIdentity, spdxType, digest)},
			required: []string{spdxType},
			want:     []string{spdxType},
		},
		{
			name:     "a missing type is rejected",
			entities: []verify.SignedEntity{attest(t, sigstore, testIdentity, spdxType, digest)},
			required: []string{"spdx", "cyclonedx"},
			wantErr:  "no verified attestation of type https://cyclonedx.org/bom",
		},
		{
			name:     "no attestations at all is rejected",
			required: []string{"spdx"},
			wantErr:  "no attestations are attached",
		},
		{
			name:     "an attestation about another digest does not count",
			entities: []verify.SignedEntity{attest(t, sigstore, testIdentity, spdxType, other)},
			required: []string{"spdx"},
			wantErr:  "no verified attestation of type https://spdx.dev/Document",
		},
		{
			name:     "an attestation signed by another identity does not count",
			entities: []verify.SignedEntity{attest(t, sigstore, "https://evil.example.com/x", spdxType, digest)},
			required: []string{"spdx"},
			wantErr:  "1 of 1 attached attestations failed verification",
		},
		{
			name: "a bad attestation does not hide a good one",
			entities: []verify.SignedEntity{
				attest(t, sigstore, "https://evil.example.com/x", spdxType, digest),
				attest(t, sigstore, testIdentity, spdxType, digest),
			},
			required: []string{"spdx"},
			want:     []string{spdxType},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := verifyAttestationEntities(sigstore, digest, tt.entities, tt.required, identityPolicy(t), virtualSigstoreOptions)

			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				var rejected *SignatureRejectedError
				g.Expect(err).To(BeAssignableToTypeOf(rejected))
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func TestVerifyAttestationEntitiesRejectsAnInvalidEntry(t *testing.T) {
	g := NewWithT(t)
	sigstore, err := ca.NewVirtualSigstore()
	g.Expect(err).ToNot(HaveOccurred())

	_, err = verifyAttestationEntities(sigstore, testDigest(t, "a"), nil, []string{"not-a-type"}, identityPolicy(t), virtualSigstoreOptions)

	g.Expect(err).To(MatchError(ContainSubstring(`attestation "not-a-type" is not a predicate type`)))
}

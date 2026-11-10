// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/fluxcd/flux-mirror/internal/testregistry"
)

func TestCosignAttestationTag(t *testing.T) {
	g := NewWithT(t)
	digest, err := v1.NewHash("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(cosignAttestationTag(digest)).To(Equal("sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.att"))
}

// attestationLayer is one layer of a pushed .att manifest.
type attestationLayer struct {
	mediaType   types.MediaType
	content     []byte
	annotations map[string]string
}

// newAttestationLayer builds a layer the way cosign attest publishes one: a
// DSSE envelope of an in-toto statement, with the signature material in the
// annotations. The signature is not valid for any trust root; discovery only
// rebuilds the bundle, and the verifier decides whether it is trusted.
func newAttestationLayer(t testing.TB, predicateType string) attestationLayer {
	t.Helper()
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"` + predicateType + `","subject":[],"predicate":{}}`)
	envelope, err := json.Marshal(map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(statement),
		"signatures":  []map[string]string{{"keyid": "", "sig": base64.StdEncoding.EncodeToString([]byte("signature"))}},
	})
	if err != nil {
		t.Fatalf("marshal envelope: %s", err)
	}

	key, certPEM := newSelfSignedKeyAndCertPEM(t)
	sum := sha256.Sum256(envelope)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatalf("sign envelope: %s", err)
	}
	rekorBundle := cosignTagRekorBundle{SignedEntryTimestamp: base64.StdEncoding.EncodeToString([]byte("test-set"))}
	rekorBundle.Payload.Body = base64.StdEncoding.EncodeToString(newHashedRekordBody(t, envelope, sig, certPEM))
	rekorBundle.Payload.IntegratedTime = 1727368221
	rekorBundle.Payload.LogIndex = 134365715
	rekorBundle.Payload.LogID = "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
	rekorBundleJSON, err := json.Marshal(rekorBundle)
	if err != nil {
		t.Fatalf("marshal rekor bundle: %s", err)
	}

	return attestationLayer{
		mediaType: types.MediaType(cosignAttestationMediaType),
		content:   envelope,
		annotations: map[string]string{
			cosignTagAnnotationSignature:   base64.StdEncoding.EncodeToString(sig),
			cosignTagAnnotationCertificate: certPEM,
			cosignTagAnnotationBundle:      string(rekorBundleJSON),
			"predicateType":                predicateType,
		},
	}
}

func pushCosignAttestations(t testing.TB, repoAddr string, digest v1.Hash, layers ...attestationLayer) {
	t.Helper()
	testregistry.UseEmptyDockerConfig(t)

	img := empty.Image
	for _, l := range layers {
		var err error
		img, err = mutate.Append(img, mutate.Addendum{
			Layer:       static.NewLayer(l.content, l.mediaType),
			Annotations: l.annotations,
		})
		if err != nil {
			t.Fatalf("build attestation image: %s", err)
		}
	}
	img = mutate.MediaType(img, types.OCIManifestSchema1)

	tagRef := repoAddr + ":" + cosignAttestationTag(digest)
	parsed, err := name.ParseReference(tagRef, name.Insecure)
	if err != nil {
		t.Fatalf("parse %s: %s", tagRef, err)
	}
	if err := remote.Push(parsed, img); err != nil {
		t.Fatalf("push %s: %s", tagRef, err)
	}
}

func discoverAttestations(t *testing.T, stem string, push func(t testing.TB, repoAddr string, digest v1.Hash)) int {
	t.Helper()
	g := NewWithT(t)
	repoAddr := repo(stem)
	digest, err := v1.NewHash(testregistry.PushImage(t, repoAddr+":v1"))
	g.Expect(err).ToNot(HaveOccurred())
	push(t, repoAddr, digest)

	repoName, err := name.NewRepository(repoAddr, name.Insecure)
	g.Expect(err).ToNot(HaveOccurred())
	entities, err := discoverCosignAttestations(repoName, digest)
	g.Expect(err).ToNot(HaveOccurred())
	return len(entities)
}

func TestDiscoverCosignAttestations(t *testing.T) {
	t.Run("every DSSE layer becomes a bundle", func(t *testing.T) {
		g := NewWithT(t)
		count := discoverAttestations(t, "cosign-att-ok", func(t testing.TB, repoAddr string, digest v1.Hash) {
			pushCosignAttestations(t, repoAddr, digest,
				newAttestationLayer(t, "https://slsa.dev/provenance/v1"),
				newAttestationLayer(t, "https://spdx.dev/Document"),
			)
		})
		g.Expect(count).To(Equal(2))
	})

	t.Run("no attestation tag is an empty result", func(t *testing.T) {
		g := NewWithT(t)
		count := discoverAttestations(t, "cosign-att-missing", func(testing.TB, string, v1.Hash) {})
		g.Expect(count).To(BeZero())
	})

	t.Run("a layer of another media type is left out", func(t *testing.T) {
		g := NewWithT(t)
		count := discoverAttestations(t, "cosign-att-other", func(t testing.TB, repoAddr string, digest v1.Hash) {
			other := newAttestationLayer(t, "https://spdx.dev/Document")
			other.mediaType = "application/vnd.example.other"
			pushCosignAttestations(t, repoAddr, digest, newAttestationLayer(t, "https://spdx.dev/Document"), other)
		})
		g.Expect(count).To(Equal(1))
	})

	t.Run("a layer without a certificate is a key-based attestation", func(t *testing.T) {
		g := NewWithT(t)
		count := discoverAttestations(t, "cosign-att-nocert", func(t testing.TB, repoAddr string, digest v1.Hash) {
			keyBased := newAttestationLayer(t, "https://spdx.dev/Document")
			delete(keyBased.annotations, cosignTagAnnotationCertificate)
			pushCosignAttestations(t, repoAddr, digest, keyBased, newAttestationLayer(t, "https://slsa.dev/provenance/v1"))
		})
		g.Expect(count).To(Equal(2))
	})

	t.Run("a layer that is not a DSSE envelope is left out", func(t *testing.T) {
		g := NewWithT(t)
		count := discoverAttestations(t, "cosign-att-garbage", func(t testing.TB, repoAddr string, digest v1.Hash) {
			broken := newAttestationLayer(t, "https://spdx.dev/Document")
			broken.content = []byte("not json")
			pushCosignAttestations(t, repoAddr, digest, broken)
		})
		g.Expect(count).To(BeZero())
	})
}

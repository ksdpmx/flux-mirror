// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"errors"
	"testing"

	. "github.com/onsi/gomega"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/sigstore-go/pkg/bundle"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/fluxcd/flux-mirror/internal/oci"
	"github.com/fluxcd/flux-mirror/internal/testregistry"
)

func mustBundleMediaType(t testing.TB, version string) string {
	t.Helper()
	mediaType, err := bundle.MediaTypeString(version)
	if err != nil {
		t.Fatalf("build bundle media type: %s", err)
	}
	return mediaType
}

func pushReferrer(t testing.TB, repoAddr string, subject v1.Hash, version string) {
	t.Helper()
	testregistry.UseEmptyDockerConfig(t)
	data, mediaType := testReferrerBundleWithType(t, version)
	layer := static.NewLayer(data, types.MediaType(mediaType))
	img, err := mutate.Append(empty.Image, mutate.Addendum{Layer: layer})
	if err != nil {
		t.Fatalf("build referrer image: %s", err)
	}
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	img = mutate.Subject(img, v1.Descriptor{
		MediaType: types.OCIManifestSchema1,
		Digest:    subject,
	}).(v1.Image)
	digest, err := img.Digest()
	if err != nil {
		t.Fatalf("digest referrer image: %s", err)
	}
	ref, err := name.NewDigest(repoAddr+"@"+digest.String(), name.Insecure)
	if err != nil {
		t.Fatalf("parse referrer digest: %s", err)
	}
	if err := remote.Push(ref, img); err != nil {
		t.Fatalf("push referrer: %s", err)
	}
}

func testReferrerBundleWithType(t testing.TB, version string) ([]byte, string) {
	t.Helper()
	mediaType, err := bundle.MediaTypeString(version)
	if err != nil {
		t.Fatalf("build bundle media type: %s", err)
	}
	_, certPEM := newSelfSignedKeyAndCertPEM(t)
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("decode test certificate PEM")
	}
	pb := &protobundle.Bundle{
		MediaType: mediaType,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{RawBytes: block.Bytes},
			},
		},
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: protocommon.HashAlgorithm_SHA2_256,
					Digest:    make([]byte, sha256.Size),
				},
				Signature: []byte("test-signature"),
			},
		},
	}
	result, err := bundle.NewBundle(pb)
	if err != nil {
		t.Fatalf("build sigstore bundle: %s", err)
	}
	data, err := result.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal sigstore bundle: %s", err)
	}
	return data, mediaType
}

func testReferrerAttestationBundle(t testing.TB, subject v1.Hash, predicateType string) ([]byte, string) {
	t.Helper()
	mediaType := mustBundleMediaType(t, "0.3")
	statement, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": predicateType,
		"subject":       []map[string]any{{"name": "example", "digest": map[string]string{subject.Algorithm: subject.Hex}}},
		"predicate":     map[string]any{"fixture": true},
	})
	if err != nil {
		t.Fatalf("marshal attestation statement: %s", err)
	}
	pb := &protobundle.Bundle{
		MediaType: mediaType,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{Hint: "fixture"},
			},
		},
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &protodsse.Envelope{
				Payload:     statement,
				PayloadType: "application/vnd.in-toto+json",
				Signatures:  []*protodsse.Signature{{Sig: []byte("fixture-signature")}},
			},
		},
	}
	result, err := bundle.NewBundle(pb)
	if err != nil {
		t.Fatalf("build attestation bundle: %s", err)
	}
	data, err := result.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal attestation bundle: %s", err)
	}
	return data, mediaType
}

func pushReferrerBundle(t testing.TB, repoAddr string, subject v1.Hash, data []byte, mediaType string) {
	t.Helper()
	testregistry.UseEmptyDockerConfig(t)
	layer := static.NewLayer(data, types.MediaType(mediaType))
	img, err := mutate.Append(empty.Image, mutate.Addendum{Layer: layer})
	if err != nil {
		t.Fatalf("build referrer image: %s", err)
	}
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.MediaType(mediaType))
	img = mutate.Subject(img, v1.Descriptor{
		MediaType: types.OCIManifestSchema1,
		Digest:    subject,
	}).(v1.Image)
	digest, err := img.Digest()
	if err != nil {
		t.Fatalf("digest referrer image: %s", err)
	}
	ref, err := name.NewDigest(repoAddr+"@"+digest.String(), name.Insecure)
	if err != nil {
		t.Fatalf("parse referrer digest: %s", err)
	}
	if err := remote.Push(ref, img); err != nil {
		t.Fatalf("push referrer: %s", err)
	}
}

func TestDiscoverCosignBundlePrefersReferrers(t *testing.T) {
	g := NewWithT(t)
	repoAddr := repo("hook-discovery-referrer")
	digestStr := testregistry.PushImage(t, repoAddr+":v1")
	digest, err := v1.NewHash(digestStr)
	g.Expect(err).ToNot(HaveOccurred())
	pushReferrer(t, repoAddr, digest, "0.3")
	pushCosignTagSignature(t, repoAddr, digest, nil)

	repoName, err := name.NewRepository(repoAddr, name.Insecure)
	g.Expect(err).ToNot(HaveOccurred())
	discovered, payload, err := discoverCosignBundle(repoName, digest)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(discovered).ToNot(BeNil())
	g.Expect(payload).To(BeNil())
	g.Expect(discovered.MinVersion("v0.3")).To(BeTrue())
}

func TestCosignSignatureBundleClassification(t *testing.T) {
	g := NewWithT(t)
	digest, err := v1.NewHash("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	g.Expect(err).ToNot(HaveOccurred())
	attestationBytes, _ := testReferrerAttestationBundle(t, digest, "https://spdx.dev/Document")
	var attestation bundle.Bundle
	g.Expect(attestation.UnmarshalJSON(attestationBytes)).To(Succeed())
	isSignature, err := isCosignSignatureBundle(&attestation)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(isSignature).To(BeFalse())

	cosignSignatureBytes, _ := testReferrerAttestationBundle(t, digest, cosignSignaturePredicateType)
	var cosignSignature bundle.Bundle
	g.Expect(cosignSignature.UnmarshalJSON(cosignSignatureBytes)).To(Succeed())
	isSignature, err = isCosignSignatureBundle(&cosignSignature)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(isSignature).To(BeTrue())

	signatureBytes, _ := testReferrerBundleWithType(t, "0.3")
	var signature bundle.Bundle
	g.Expect(signature.UnmarshalJSON(signatureBytes)).To(Succeed())
	isSignature, err = isCosignSignatureBundle(&signature)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(isSignature).To(BeTrue())
}

func TestDiscoverCosignBundleSkipsAttestationReferrers(t *testing.T) {
	g := NewWithT(t)
	repoAddr := repo("hook-discovery-att-before-signature")
	digestStr := testregistry.PushImage(t, repoAddr+":v1")
	digest, err := v1.NewHash(digestStr)
	g.Expect(err).ToNot(HaveOccurred())
	attestationBytes, mediaType := testReferrerAttestationBundle(t, digest, "https://spdx.dev/Document")
	pushReferrerBundle(t, repoAddr, digest, attestationBytes, mediaType)
	signatureBytes, mediaType := testReferrerAttestationBundle(t, digest, cosignSignaturePredicateType)
	pushReferrerBundle(t, repoAddr, digest, signatureBytes, mediaType)

	repoName, err := name.NewRepository(repoAddr, name.Insecure)
	g.Expect(err).ToNot(HaveOccurred())
	discovered, payload, err := discoverCosignBundle(repoName, digest)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(payload).To(BeNil())
	g.Expect(discovered.GetDsseEnvelope()).ToNot(BeNil())
}

func TestDiscoverCosignBundleFallsBackToLegacyTag(t *testing.T) {
	g := NewWithT(t)
	repoAddr := repo("hook-discovery-tag")
	digestStr := testregistry.PushImage(t, repoAddr+":v1")
	digest, err := v1.NewHash(digestStr)
	g.Expect(err).ToNot(HaveOccurred())
	wantPayload := pushCosignTagSignature(t, repoAddr, digest, nil)

	repoName, err := name.NewRepository(repoAddr, name.Insecure)
	g.Expect(err).ToNot(HaveOccurred())
	discovered, payload, err := discoverCosignBundle(repoName, digest)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(discovered).ToNot(BeNil())
	g.Expect(payload).To(Equal(wantPayload))
	g.Expect(discovered.MinVersion("v0.1")).To(BeTrue())
}

func TestDiscoverCosignBundleWithoutSignatureRejects(t *testing.T) {
	g := NewWithT(t)
	repoAddr := repo("hook-discovery-no-signature")
	digestStr := testregistry.PushImage(t, repoAddr+":v1")
	digest, err := v1.NewHash(digestStr)
	g.Expect(err).ToNot(HaveOccurred())

	repoName, err := name.NewRepository(repoAddr, name.Insecure)
	g.Expect(err).ToNot(HaveOccurred())
	_, _, err = discoverCosignBundle(repoName, digest)
	g.Expect(err).To(HaveOccurred())
	var rejected *oci.SignatureRejectedError
	g.Expect(errors.As(err, &rejected)).To(BeTrue())
	g.Expect(err.Error()).To(ContainSubstring("no sigstore bundle found via OCI referrers or cosign tag-based discovery"))
}

func TestDiscoverCosignBundleRejectsUnsupportedReferrerWithoutFallback(t *testing.T) {
	g := NewWithT(t)
	repoAddr := repo("hook-discovery-hard-error")
	digestStr := testregistry.PushImage(t, repoAddr+":v1")
	digest, err := v1.NewHash(digestStr)
	g.Expect(err).ToNot(HaveOccurred())
	pushReferrer(t, repoAddr, digest, "0.1")
	pushCosignTagSignature(t, repoAddr, digest, nil)

	repoName, err := name.NewRepository(repoAddr, name.Insecure)
	g.Expect(err).ToNot(HaveOccurred())
	_, _, err = discoverCosignBundle(repoName, digest)
	g.Expect(err).To(HaveOccurred())
	var rejected *oci.SignatureRejectedError
	g.Expect(errors.As(err, &rejected)).To(BeTrue())
	g.Expect(err.Error()).To(ContainSubstring("unsupported sigstore bundle version"))
}

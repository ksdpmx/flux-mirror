// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/fluxcd/flux-mirror/internal/oci"
)

// cosignAttestationMediaType is the media type of a layer of an .att manifest:
// one DSSE envelope holding an in-toto statement, signed with the same
// annotations as a tag-based signature (cosign attest).
const cosignAttestationMediaType = "application/vnd.dsse.envelope.v1+json"

// cosignAttestationTag computes the tag cosign's tag-based discovery scheme
// uses for the attestations of digest, e.g. sha256:abcd... becomes
// sha256-abcd....att.
func cosignAttestationTag(digest v1.Hash) string {
	return fmt.Sprintf("%s-%s.att", digest.Algorithm, digest.Hex)
}

// cosignDSSEEnvelope is the JSON stored in an attestation layer.
type cosignDSSEEnvelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	} `json:"signatures"`
}

// discoverCosignAttestations first looks for a referrer DSSE bundle with the
// requested predicate type, then falls back to the legacy .att tag only when no
// matching referrer candidate exists. A candidate that fails verification is
// not hidden by a tag-based fallback.
func discoverCosignAttestations(repo name.Repository, digest v1.Hash, predicateType string, opts ...remote.Option) ([]verify.SignedEntity, error) {
	entities, found, err := findReferrerAttestations(repo, digest, predicateType, opts...)
	if err != nil {
		return nil, err
	}
	if found {
		return entities, nil
	}
	return discoverCosignTagAttestations(repo, digest, opts...)
}

func findReferrerAttestations(
	repo name.Repository,
	digest v1.Hash,
	predicateType string,
	opts ...remote.Option,
) ([]verify.SignedEntity, bool, error) {
	bundles, err := findReferrerBundles(repo, digest, opts...)
	if errors.Is(err, errNoReferrerBundle) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var entities []verify.SignedEntity
	for _, sigstoreBundle := range bundles {
		envelope := sigstoreBundle.GetDsseEnvelope()
		if envelope == nil {
			continue
		}
		var statement struct {
			PredicateType string `json:"predicateType"`
		}
		if err := json.Unmarshal(envelope.Payload, &statement); err != nil {
			return nil, false, fmt.Errorf("read referrer DSSE predicate type: %w", err)
		}
		if statement.PredicateType != predicateType || statement.PredicateType == cosignSignaturePredicateType {
			continue
		}
		if !sigstoreBundle.MinVersion(referrerSigstoreBundleMinVersion) {
			return nil, false, oci.NewSignatureRejectedError(fmt.Errorf(
				"unsupported sigstore attestation bundle version: minimum %s required",
				referrerSigstoreBundleMinVersion,
			))
		}
		entities = append(entities, sigstoreBundle)
	}
	return entities, len(entities) > 0, nil
}

// discoverCosignTagAttestations reads the .att manifest of digest and rebuilds
// each DSSE layer as a sigstore bundle, so they verify like any other bundle.
// An .att manifest has one layer per attestation, and nothing in a layer other
// than its signature is trusted: the annotation that names the predicate type
// is not signed, so the predicate type is read after verification. A layer
// that cannot be read is left out; whether the attestations that remain are
// enough is for the verifier to decide. A missing .att tag is an empty result.
func discoverCosignTagAttestations(repo name.Repository, digest v1.Hash, opts ...remote.Option) ([]verify.SignedEntity, error) {
	tagRef := repo.Tag(cosignAttestationTag(digest))
	desc, err := remote.Get(tagRef, opts...)
	if err != nil {
		var terr *transport.Error
		if errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("fetch cosign attestation tag %s: %w", tagRef, err)
	}
	manifest, err := v1.ParseManifest(bytes.NewReader(desc.Manifest))
	if err != nil {
		return nil, nil
	}

	var entities []verify.SignedEntity
	for _, layer := range manifest.Layers {
		if string(layer.MediaType) != cosignAttestationMediaType {
			continue
		}
		b, err := buildCosignAttestationBundle(repo, layer, opts...)
		if err != nil {
			continue
		}
		entities = append(entities, b)
	}
	return entities, nil
}

// buildCosignAttestationBundle assembles a sigstore bundle from one
// attestation layer: the DSSE envelope is its content, and the certificate
// chain and Rekor entry come from the layer annotations, as for a signature.
func buildCosignAttestationBundle(repo name.Repository, layer v1.Descriptor, opts ...remote.Option) (*bundle.Bundle, error) {
	raw, err := fetchLayerBlob(repo, layer.Digest, opts...)
	if err != nil {
		return nil, fmt.Errorf("fetch cosign attestation envelope: %w", err)
	}
	var envelope cosignDSSEEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("parse cosign attestation envelope: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode cosign attestation payload: %w", err)
	}
	signatures := make([]*protodsse.Signature, 0, len(envelope.Signatures))
	for _, s := range envelope.Signatures {
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			return nil, fmt.Errorf("decode cosign attestation signature: %w", err)
		}
		signatures = append(signatures, &protodsse.Signature{Sig: sig, Keyid: s.KeyID})
	}

	// An attestation made with cosign attest --key has no certificate. Its
	// bundle carries no key either: the verifier supplies the configured key.
	var material *protobundle.VerificationMaterial
	if certPEM, ok := layer.Annotations[cosignTagAnnotationCertificate]; ok {
		certs, err := decodeCosignTagCertificateChain(certPEM, layer.Annotations[cosignTagAnnotationChain])
		if err != nil {
			return nil, err
		}
		material = &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_X509CertificateChain{
				X509CertificateChain: &protocommon.X509CertificateChain{Certificates: certs},
			},
		}
	} else {
		material = &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{PublicKey: &protocommon.PublicKeyIdentifier{}},
		}
	}
	tlogEntries, err := decodeCosignTagTlogEntries(layer.Annotations[cosignTagAnnotationBundle])
	if err != nil {
		return nil, err
	}
	material.TlogEntries = tlogEntries
	mediaType, err := bundle.MediaTypeString(cosignTagBundleVersion)
	if err != nil {
		return nil, fmt.Errorf("build sigstore bundle media type: %w", err)
	}

	return bundle.NewBundle(&protobundle.Bundle{
		MediaType:            mediaType,
		VerificationMaterial: material,
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &protodsse.Envelope{
				Payload:     payload,
				PayloadType: envelope.PayloadType,
				Signatures:  signatures,
			},
		},
	})
}

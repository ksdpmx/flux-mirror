// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// ParsePublicKeyPEM parses a PEM-encoded ECDSA, RSA or Ed25519 public key.
func ParsePublicKeyPEM(pemKey string) (crypto.PublicKey, error) {
	if strings.TrimSpace(pemKey) == "" {
		return nil, fmt.Errorf("public key is empty")
	}
	key, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(pemKey))
	if err != nil {
		return nil, fmt.Errorf("parse PEM public key: %w", err)
	}
	return key, nil
}

// PublicKeyFingerprint returns sha256:<hex> of the DER (PKIX) encoding of key.
func PublicKeyFingerprint(key crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

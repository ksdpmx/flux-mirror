// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"context"
	"errors"
	"testing"

	. "github.com/onsi/gomega"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
	"github.com/fluxcd/flux-mirror/internal/testregistry"
)

func TestVerifyReferrersRequiresBundleFromReferrers(t *testing.T) {
	g := NewWithT(t)
	repoAddr := repo("verify-referrers-only")
	testregistry.PushImage(t, repoAddr+":v1")

	verifier := NewVerifier(NewClient(Insecure()))
	_, err := verifier.VerifyReferrers(context.Background(), repoAddr+":v1", apiv1.ArtifactVerification{
		Provider: apiv1.VerifyProviderCosign,
		MatchOIDCIdentity: []apiv1.OIDCIdentity{{
			Issuer:  "https://token.actions.githubusercontent.com",
			Subject: `^https://github\.com/example/.*$`,
		}},
	})
	var rejected *SignatureRejectedError
	g.Expect(errors.As(err, &rejected)).To(BeTrue())
	g.Expect(err.Error()).To(ContainSubstring("no usable sigstore bundle found in OCI referrers"))
}

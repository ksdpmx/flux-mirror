// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"context"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/gomega"

	"github.com/fluxcd/flux-mirror/internal/testregistry"
)

func TestResolvePlatforms(t *testing.T) {
	g := NewWithT(t)
	testregistry.UseEmptyDockerConfig(t)
	repoAddr := repo("resolve-platforms")

	amd64, err := random.Image(128, 1)
	g.Expect(err).ToNot(HaveOccurred())
	arm64v8, err := random.Image(128, 1)
	g.Expect(err).ToNot(HaveOccurred())
	index := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: amd64, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
		mutate.IndexAddendum{Add: arm64v8, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}}},
		mutate.IndexAddendum{Add: random1(t), Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "unknown", Architecture: "unknown"}}},
	)
	indexRef, err := name.ParseReference(repoAddr+":index", name.Insecure)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(remote.WriteIndex(indexRef, index)).To(Succeed())
	indexDigest, err := crane.Digest(repoAddr+":index", crane.Insecure)
	g.Expect(err).ToNot(HaveOccurred())
	amd64Digest, err := amd64.Digest()
	g.Expect(err).ToNot(HaveOccurred())
	arm64Digest, err := arm64v8.Digest()
	g.Expect(err).ToNot(HaveOccurred())

	v := NewVerifier(NewClient(Insecure()))
	ctx := context.Background()

	t.Run("returns the digest of each platform that is in the index", func(t *testing.T) {
		g := NewWithT(t)
		got, err := v.ResolvePlatforms(ctx, repoAddr+"@"+indexDigest, []string{"linux/amd64", "linux/arm64", "linux/s390x"})
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(got).To(Equal(map[string]string{
			"linux/amd64": amd64Digest.String(),
			"linux/arm64": arm64Digest.String(),
		}), "a platform without a variant matches any variant, and a missing one is left out")
	})

	t.Run("a variant in the request must match", func(t *testing.T) {
		g := NewWithT(t)
		got, err := v.ResolvePlatforms(ctx, repoAddr+"@"+indexDigest, []string{"linux/arm64/v8", "linux/arm64/v7"})
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(got).To(Equal(map[string]string{"linux/arm64/v8": arm64Digest.String()}))
	})

	t.Run("a single image has no platforms", func(t *testing.T) {
		g := NewWithT(t)
		imageRef, err := name.ParseReference(repoAddr+":single", name.Insecure)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(remote.Write(imageRef, amd64)).To(Succeed())
		got, err := v.ResolvePlatforms(ctx, repoAddr+":single", []string{"linux/amd64"})
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(got).To(BeEmpty())
	})

	t.Run("an invalid platform is an error", func(t *testing.T) {
		g := NewWithT(t)
		for _, platform := range []string{"", "linux", "/arm64", "linux/"} {
			_, err := v.ResolvePlatforms(ctx, repoAddr+"@"+indexDigest, []string{platform})
			g.Expect(err).To(MatchError(ContainSubstring("must be os/arch or os/arch/variant")), platform)
		}
	})
}

func random1(t *testing.T) v1.Image {
	t.Helper()
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatalf("random.Image: %s", err)
	}
	return img
}

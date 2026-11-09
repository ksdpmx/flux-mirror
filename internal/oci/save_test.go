// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	. "github.com/onsi/gomega"

	"github.com/fluxcd/flux-mirror/internal/testregistry"
)

func TestSaveImage(t *testing.T) {
	g := NewWithT(t)
	testregistry.UseEmptyDockerConfig(t)
	repoAddr := repo("save-image")

	amd64, err := random.Image(128, 1)
	g.Expect(err).ToNot(HaveOccurred())
	arm64, err := random.Image(128, 1)
	g.Expect(err).ToNot(HaveOccurred())
	index := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: amd64, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
		mutate.IndexAddendum{Add: arm64, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}}},
	)
	ref, err := name.ParseReference(repoAddr+":v1", name.Insecure)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(remote.WriteIndex(ref, index)).To(Succeed())
	indexDigest, err := crane.Digest(repoAddr+":v1", crane.Insecure)
	g.Expect(err).ToNot(HaveOccurred())

	c := NewClient(Insecure())
	ctx := context.Background()

	t.Run("saves the requested platform", func(t *testing.T) {
		g := NewWithT(t)
		path := filepath.Join(t.TempDir(), "arm64.tar")
		digest, err := c.SaveImage(ctx, repoAddr+"@"+indexDigest, "linux/arm64", path)
		g.Expect(err).ToNot(HaveOccurred())

		want, err := arm64.Digest()
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(digest).To(Equal(want.String()))

		saved, err := tarball.ImageFromPath(path, nil)
		g.Expect(err).ToNot(HaveOccurred())
		savedConfig, err := saved.ConfigName()
		g.Expect(err).ToNot(HaveOccurred())
		wantConfig, err := arm64.ConfigName()
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(savedConfig).To(Equal(wantConfig))
	})

	t.Run("platform missing from the index", func(t *testing.T) {
		g := NewWithT(t)
		_, err := c.SaveImage(ctx, repoAddr+"@"+indexDigest, "linux/s390x", filepath.Join(t.TempDir(), "x.tar"))
		g.Expect(err).To(MatchError(ContainSubstring("no child with platform")))
	})

	t.Run("invalid platform", func(t *testing.T) {
		g := NewWithT(t)
		_, err := c.SaveImage(ctx, repoAddr+"@"+indexDigest, "", filepath.Join(t.TempDir(), "x.tar"))
		g.Expect(err).To(HaveOccurred())
	})
}

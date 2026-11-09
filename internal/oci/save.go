// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// SaveImage pulls the image at ref from the source registry for one platform
// (os/arch or os/arch/variant) and writes it to path as a tarball. It returns
// the manifest digest of the saved platform image. When ref resolves to an
// index, the child for platform is saved; a platform missing from the index is
// an error. The tarball needs no container runtime to be read.
func (c *Client) SaveImage(ctx context.Context, ref, platform, path string) (string, error) {
	p, err := v1.ParsePlatform(platform)
	if err != nil {
		return "", fmt.Errorf("parse platform %q: %w", platform, err)
	}
	opts := append(c.sourceCraneOptions(ctx), crane.WithPlatform(p))
	img, err := crane.Pull(ref, opts...)
	if err != nil {
		return "", fmt.Errorf("pull %s for %s: %w", ref, platform, err)
	}
	digest, err := img.Digest()
	if err != nil {
		return "", fmt.Errorf("digest of %s for %s: %w", ref, platform, err)
	}
	if err := crane.Save(img, ref, path); err != nil {
		return "", fmt.Errorf("save %s for %s: %w", ref, platform, err)
	}
	return digest.String(), nil
}

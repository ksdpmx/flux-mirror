// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package helmrepo

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
	"github.com/fluxcd/flux-mirror/internal/registryauth"
)

// NewPusherForHosts builds a Pusher for the Artifactory Helm repository
// directory dest, authenticating with the entry of hosts that matches its host.
// hosts are the destination-side hosts. A credential without a username is a
// bearer token stamped by rt, so only username credentials need Basic auth
// here. Cloud provider hosts are rejected: they only apply to OCI registries.
func NewPusherForHosts(dest string, insecure bool, rt http.RoundTripper, hosts []apiv1.RegistryHost) (*Pusher, error) {
	u, err := NormalizeDestination(dest)
	if err != nil {
		return nil, fmt.Errorf("destination: %w", err)
	}
	opts := []PusherOption{WithTransport(rt)}
	for _, h := range hosts {
		if !strings.EqualFold(h.Host, u.Host) {
			continue
		}
		if h.IsCloudProvider() {
			return nil, fmt.Errorf("host %q uses cloud provider %q, which is not supported for destinationType %q",
				h.Host, h.Provider, apiv1.DestinationTypeArtifactory)
		}
		if h.Credential != nil && h.Credential.Username != "" {
			opts = append(opts, WithBasicAuth(func(ctx context.Context) (string, string, error) {
				a, err := registryauth.ResolveHostAuth(ctx, h)
				return a.Username, a.Password, err
			}))
		}
		break
	}
	return NewPusher(dest, insecure, opts...)
}

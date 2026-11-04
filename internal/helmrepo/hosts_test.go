// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package helmrepo

import (
	"context"
	"net/http"
	"strings"
	"testing"

	. "github.com/onsi/gomega"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
	"github.com/fluxcd/flux-mirror/internal/testregistry"
)

func TestNewPusherForHosts(t *testing.T) {
	basic := func(user, pass string) string {
		req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
		req.SetBasicAuth(user, pass)
		return req.Header.Get("Authorization")
	}

	tests := []struct {
		name     string
		host     func(addr string) []apiv1.RegistryHost
		wantAuth string
		wantErr  string
	}{
		{
			name: "username credential uses Basic auth",
			host: func(addr string) []apiv1.RegistryHost {
				return []apiv1.RegistryHost{{Host: strings.ToUpper(addr),
					Credential: &apiv1.RegistryCredential{Username: "bob", Value: "secret"}}}
			},
			wantAuth: basic("bob", "secret"),
		},
		{
			// A bearer token is stamped by the shared transport, not by the Pusher.
			name: "credential without username is left to the transport",
			host: func(addr string) []apiv1.RegistryHost {
				return []apiv1.RegistryHost{{Host: addr, Credential: &apiv1.RegistryCredential{Value: "token"}}}
			},
		},
		{
			name: "other host is anonymous",
			host: func(string) []apiv1.RegistryHost {
				return []apiv1.RegistryHost{{Host: "other.example.com",
					Credential: &apiv1.RegistryCredential{Username: "bob", Value: "secret"}}}
			},
		},
		{
			name: "cloud provider host is rejected",
			host: func(addr string) []apiv1.RegistryHost {
				return []apiv1.RegistryHost{{Host: addr, Provider: apiv1.RegistryProviderECR}}
			},
			wantErr: "not supported for destinationType",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			f, url := testregistry.StartFakeArtifactory(t)
			addr := strings.TrimPrefix(url, "http://")

			p, err := NewPusherForHosts(url+"/helm", true, nil, tt.host(addr))
			if tt.wantErr != "" {
				g.Expect(err).To(MatchError(ContainSubstring(tt.wantErr)))
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
			_, err = p.Stat(context.Background(), "podinfo", "1.0.0")
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(f.LastAuth()).To(Equal(tt.wantAuth))
		})
	}
}

func TestNewPusherForHosts_RejectsBadDestination(t *testing.T) {
	g := NewWithT(t)
	_, err := NewPusherForHosts("oci://x.jfrog.io/helm", false, nil, nil)
	g.Expect(err).To(MatchError(ContainSubstring("destination:")))
	_, err = NewPusherForHosts("http://x.jfrog.io/helm", false, nil, nil)
	g.Expect(err).To(MatchError(ContainSubstring("--insecure")))
}

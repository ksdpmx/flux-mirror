// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package helmrepo

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestNormalizeSource(t *testing.T) {
	tests := []struct {
		in, want, errMsg string
	}{
		{in: "aws.github.io/eks-charts", want: "https://aws.github.io/eks-charts"},
		{in: "https://charts.example.com", want: "https://charts.example.com"},
		{in: "http://localhost:8080/charts/", want: "http://localhost:8080/charts/"},
		{in: "localhost:8080", want: "https://localhost:8080"},
		{in: "  charts.example.com  ", want: "https://charts.example.com"},
		{in: "", errMsg: "source is required"},
		{in: "oci://ghcr.io/example/charts", errMsg: "use 'artifacts' to mirror an OCI Helm chart"},
		{in: "ftp://example.com", errMsg: `scheme "ftp"`},
		{in: "https://", errMsg: "missing a host"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			g := NewWithT(t)
			u, err := NormalizeSource(tt.in)
			if tt.errMsg != "" {
				g.Expect(err).To(MatchError(ContainSubstring(tt.errMsg)))
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(u.String()).To(Equal(tt.want))
		})
	}
}

func TestNew_PlaintextHTTPRequiresInsecure(t *testing.T) {
	g := NewWithT(t)

	_, err := New("http://charts.example.com", false)
	g.Expect(err).To(MatchError(ContainSubstring("--insecure")))

	_, err = New("http://charts.example.com", true)
	g.Expect(err).ToNot(HaveOccurred())

	// https, with or without a scheme, never needs --insecure.
	_, err = New("charts.example.com", false)
	g.Expect(err).ToNot(HaveOccurred())
	_, err = New("https://charts.example.com", false)
	g.Expect(err).ToNot(HaveOccurred())
}

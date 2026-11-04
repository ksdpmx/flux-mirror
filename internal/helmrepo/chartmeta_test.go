// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package helmrepo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/fluxcd/flux-mirror/internal/testregistry"
)

// tgzOf builds a .tgz holding the given files (name -> content), in order.
func tgzOf(t *testing.T, files map[string]string, order ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, name := range order {
		body := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestChartIdentity(t *testing.T) {
	t.Run("packaged chart", func(t *testing.T) {
		g := NewWithT(t)
		name, version, err := ChartIdentity(testregistry.PackageChart(t, fixtureChart, "1.2.3"))
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(name).To(Equal("podinfo"))
		g.Expect(version).To(Equal("1.2.3"))
	})

	t.Run("reads the top-level Chart.yaml, not a dependency's", func(t *testing.T) {
		g := NewWithT(t)
		tgz := tgzOf(t, map[string]string{
			"podinfo/charts/dep/Chart.yaml": "name: dep\nversion: 9.9.9\n",
			"podinfo/Chart.yaml":            "apiVersion: v2\nname: podinfo\nversion: 1.2.3+build.5\n",
		}, "podinfo/charts/dep/Chart.yaml", "podinfo/Chart.yaml")
		name, version, err := ChartIdentity(tgz)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(name).To(Equal("podinfo"))
		g.Expect(version).To(Equal("1.2.3+build.5"))
	})

	tests := []struct {
		name, want string
		tgz        []byte
	}{
		{"not gzip", "open chart archive", []byte("nope")},
		{"no Chart.yaml", "no top-level Chart.yaml",
			tgzOf(t, map[string]string{"podinfo/values.yaml": "a: b\n"}, "podinfo/values.yaml")},
		{"missing version", "no name or version",
			tgzOf(t, map[string]string{"podinfo/Chart.yaml": "name: podinfo\n"}, "podinfo/Chart.yaml")},
		{"bad yaml", "parse Chart.yaml",
			tgzOf(t, map[string]string{"podinfo/Chart.yaml": "name: [\n"}, "podinfo/Chart.yaml")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			_, _, err := ChartIdentity(tt.tgz)
			g.Expect(err).To(MatchError(ContainSubstring(tt.want)))
		})
	}
}

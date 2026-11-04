// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package charts

import (
	"context"
	"testing"

	. "github.com/onsi/gomega"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
	"github.com/fluxcd/flux-mirror/internal/oci"
	"github.com/fluxcd/flux-mirror/internal/testregistry"
)

// planVersions returns the chart versions a Plan selects for the selector.
func planVersions(t *testing.T, srcURL string, sel apiv1.Selector) []string {
	t.Helper()
	g := NewWithT(t)
	entry := apiv1.ChartEntry{
		Source:      srcURL,
		Destination: "oci://" + testregistry.Repo(dockerReg, "charts-selector"),
		Name:        "podinfo",
		Selector:    sel,
	}
	m, err := New(oci.NewClient(oci.Insecure()), entry, Options{Logger: discardLogger(), Insecure: true})
	g.Expect(err).ToNot(HaveOccurred())
	plan, err := m.Plan(context.Background())
	g.Expect(err).ToNot(HaveOccurred())
	ids := make([]string, 0, len(plan.Jobs))
	for _, j := range plan.Jobs {
		ids = append(ids, j.ID)
	}
	return ids
}

// charts select versions exactly like artifacts select tags: the same selector,
// so without semver nothing is filtered and prereleases are included.
func TestChartsMirror_Selector(t *testing.T) {
	srcURL := newHTTPHelmRepo(t, "1.0.0", "1.1.0", "1.2.0-beta.1", "1.2.0-rc.1")
	all := []string{"1.0.0", "1.1.0", "1.2.0-beta.1", "1.2.0-rc.1"}
	unlimited := new(0)

	tests := []struct {
		name string
		sel  apiv1.Selector
		want []string
	}{
		{
			name: "no semver includes prereleases",
			sel:  apiv1.Selector{Limit: unlimited},
			want: all,
		},
		{
			name: "default limit picks the highest, a release candidate",
			sel:  apiv1.Selector{},
			want: []string{"1.2.0-rc.1"},
		},
		{
			name: "semver star excludes prereleases",
			sel:  apiv1.Selector{Semver: "*", Limit: unlimited},
			want: []string{"1.0.0", "1.1.0"},
		},
		{
			name: "semver range excludes prereleases",
			sel:  apiv1.Selector{Semver: ">=1.0.0", Limit: unlimited},
			want: []string{"1.0.0", "1.1.0"},
		},
		{
			name: "a prerelease suffix in the constraint includes prereleases",
			sel:  apiv1.Selector{Semver: ">=1.0.0-0", Limit: unlimited},
			want: all,
		},
		{
			name: "regex filters versions",
			sel: apiv1.Selector{
				Regex: &apiv1.RegexFilter{Pattern: `^[0-9]+\.[0-9]+\.[0-9]+$`},
				Limit: unlimited,
			},
			want: []string{"1.0.0", "1.1.0"},
		},
		{
			// The extracted key is compared; the original version is mirrored.
			name: "regex extract feeds the semver filter",
			sel: apiv1.Selector{
				Regex:  &apiv1.RegexFilter{Pattern: `^(?P<v>[0-9]+\.[0-9]+\.[0-9]+)(-.*)?$`, Extract: "$v"},
				Semver: ">=1.1.0",
				Limit:  unlimited,
			},
			want: []string{"1.1.0", "1.2.0-beta.1", "1.2.0-rc.1"},
		},
		{
			name: "limit caps the highest versions",
			sel:  apiv1.Selector{Semver: "*", Limit: new(1)},
			want: []string{"1.1.0"},
		},
		{
			name: "sortBy alphabetical",
			sel:  apiv1.Selector{SortBy: apiv1.SortByAlphabetical, Limit: new(1)},
			want: []string{"1.2.0-rc.1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(planVersions(t, srcURL, tt.sel)).To(ConsistOf(tt.want))
		})
	}
}

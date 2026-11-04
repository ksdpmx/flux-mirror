// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package charts

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/gomega"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
	"github.com/fluxcd/flux-mirror/internal/helmrepo"
	"github.com/fluxcd/flux-mirror/internal/oci"
	"github.com/fluxcd/flux-mirror/internal/sync"
	"github.com/fluxcd/flux-mirror/internal/testregistry"
)

const artifactoryDir = "/helm-local/team"

func artifactoryEntry(srcURL, dstURL string) apiv1.ChartEntry {
	return apiv1.ChartEntry{
		Source:          srcURL,
		Destination:     dstURL + artifactoryDir,
		DestinationType: apiv1.DestinationTypeArtifactory,
		Name:            "podinfo",
		Selector:        apiv1.Selector{Limit: new(0)},
	}
}

func artifactoryOpts() Options {
	return Options{Logger: discardLogger(), Insecure: true}
}

func storedChart(f *testregistry.FakeArtifactory, path string) []byte {
	data, _ := f.Get(path)
	return data
}

func TestChartsMirror_ToArtifactory(t *testing.T) {
	g := NewWithT(t)
	srcURL := newHTTPHelmRepo(t, "1.0.0", "1.1.0")
	fake, dstURL := testregistry.StartFakeArtifactory(t)
	c := oci.NewClient(oci.Insecure())

	run := func(entry apiv1.ChartEntry, opts Options) apiv1.EntryResult {
		m, err := New(c, entry, opts)
		g.Expect(err).ToNot(HaveOccurred())
		res, err := newRunner().Run(context.Background(), []sync.EntryMirror{m})
		g.Expect(err).ToNot(HaveOccurred())
		return res.Entries[0]
	}
	entry := artifactoryEntry(srcURL, dstURL)

	// The report shows the directory; each job shows the full .tgz URL and no
	// chart name directory is appended.
	m, err := New(c, entry, artifactoryOpts())
	g.Expect(err).ToNot(HaveOccurred())
	plan, err := m.Plan(context.Background())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(plan.Destination).To(Equal(dstURL + artifactoryDir))
	g.Expect(plan.Jobs).To(HaveLen(2))
	dsts := []string{plan.Jobs[0].Dst, plan.Jobs[1].Dst}
	g.Expect(dsts).To(ConsistOf(
		dstURL+artifactoryDir+"/podinfo-1.0.0.tgz",
		dstURL+artifactoryDir+"/podinfo-1.1.0.tgz"))

	// Dry run reports would-copy and uploads nothing.
	dry := artifactoryOpts()
	dry.DryRun = true
	e := run(entry, dry)
	g.Expect(versionsWithStatus(e, apiv1.StatusWouldCopy)).To(ConsistOf("1.0.0", "1.1.0"))
	g.Expect(fake.Paths()).To(BeEmpty())

	// First real run uploads both versions.
	e = run(entry, artifactoryOpts())
	g.Expect(versionsWithStatus(e, apiv1.StatusCopied)).To(ConsistOf("1.0.0", "1.1.0"))
	g.Expect(fake.Paths()).To(ConsistOf(
		artifactoryDir+"/podinfo-1.0.0.tgz", artifactoryDir+"/podinfo-1.1.0.tgz"))
	name, version, err := helmrepo.ChartIdentity(storedChart(fake, artifactoryDir+"/podinfo-1.1.0.tgz"))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(name + "@" + version).To(Equal("podinfo@1.1.0"))

	// A second run changes nothing.
	puts := fake.Puts()
	e = run(entry, artifactoryOpts())
	g.Expect(versionsWithStatus(e, apiv1.StatusSkipped)).To(ConsistOf("1.0.0", "1.1.0"))
	row, _ := rowByTag(e, "1.0.0")
	g.Expect(row.Reason).To(Equal(apiv1.ReasonUpToDate))
	g.Expect(fake.Puts()).To(Equal(puts))

	// A drifted file is left alone without overwrite...
	fake.Set(artifactoryDir+"/podinfo-1.0.0.tgz", []byte("tampered"))
	e = run(entry, artifactoryOpts())
	g.Expect(versionsWithStatus(e, apiv1.StatusDrifted)).To(ConsistOf("1.0.0"))
	g.Expect(storedChart(fake, artifactoryDir+"/podinfo-1.0.0.tgz")).To(Equal([]byte("tampered")))

	// ...is previewed as would-overwrite on a dry run...
	entry.Overwrite = true
	e = run(entry, dry)
	g.Expect(versionsWithStatus(e, apiv1.StatusWouldOverwrite)).To(ConsistOf("1.0.0"))
	g.Expect(storedChart(fake, artifactoryDir+"/podinfo-1.0.0.tgz")).To(Equal([]byte("tampered")))

	// ...and replaced with overwrite.
	e = run(entry, artifactoryOpts())
	g.Expect(versionsWithStatus(e, apiv1.StatusOverwritten)).To(ConsistOf("1.0.0"))
	name, version, err = helmrepo.ChartIdentity(storedChart(fake, artifactoryDir+"/podinfo-1.0.0.tgz"))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(name + "@" + version).To(Equal("podinfo@1.0.0"))
}

func TestChartsMirror_PlaintextHTTPSourceRequiresInsecure(t *testing.T) {
	g := NewWithT(t)
	srcURL := newHTTPHelmRepo(t, "1.0.0") // http://127.0.0.1:port
	c := oci.NewClient(oci.Insecure())
	entry := apiv1.ChartEntry{Source: srcURL, Destination: "oci://localhost:5050/charts", Name: "podinfo"}

	// New succeeds: the failure is reported on this entry, not as a build error
	// that would abort the whole sync.
	m, err := New(c, entry, Options{Logger: discardLogger()})
	g.Expect(err).ToNot(HaveOccurred())
	res, err := newRunner().Run(context.Background(), []sync.EntryMirror{m})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.Entries[0].Status).To(Equal(apiv1.EntryFailed))
	g.Expect(res.Entries[0].Error).To(ContainSubstring("--insecure"))
}

func TestChartsMirror_PlanShowsExplicitSourceScheme(t *testing.T) {
	g := NewWithT(t)
	c := oci.NewClient(oci.Insecure())
	// The host does not resolve, so planning fails; the plan still names the
	// source with the https default made explicit.
	entry := apiv1.ChartEntry{Source: "charts.invalid/eks", Destination: "oci://localhost:5050/charts", Name: "podinfo"}
	m, err := New(c, entry, Options{Logger: discardLogger()})
	g.Expect(err).ToNot(HaveOccurred())
	plan, err := m.Plan(context.Background())
	g.Expect(err).To(HaveOccurred())
	g.Expect(plan.Source).To(Equal("https://charts.invalid/eks/podinfo"))
}

func TestChartsMirror_ToArtifactoryRejectsProviderHost(t *testing.T) {
	g := NewWithT(t)
	srcURL := newHTTPHelmRepo(t, "1.0.0")
	c := oci.NewClient(oci.Insecure())

	entry := artifactoryEntry(srcURL, "https://x.dkr.ecr.us-east-1.amazonaws.com")
	opts := artifactoryOpts()
	opts.Hosts = []apiv1.RegistryHost{{Host: "x.dkr.ecr.us-east-1.amazonaws.com", Provider: apiv1.RegistryProviderECR}}

	// New succeeds: the failure is reported on this entry, not as a build error
	// that would abort the whole sync.
	m, err := New(c, entry, opts)
	g.Expect(err).ToNot(HaveOccurred())
	res, err := newRunner().Run(context.Background(), []sync.EntryMirror{m})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.Entries[0].Status).To(Equal(apiv1.EntryFailed))
	g.Expect(res.Entries[0].Error).To(ContainSubstring("not supported for destinationType"))
}

func TestChartsMirror_ToArtifactoryRejectsPlainHTTPWithoutInsecure(t *testing.T) {
	g := NewWithT(t)
	srcURL := newHTTPHelmRepo(t, "1.0.0")
	_, dstURL := testregistry.StartFakeArtifactory(t) // http://127.0.0.1:port
	c := oci.NewClient(oci.Insecure())

	m, err := New(c, artifactoryEntry(srcURL, dstURL), Options{Logger: discardLogger()})
	g.Expect(err).ToNot(HaveOccurred())
	res, err := newRunner().Run(context.Background(), []sync.EntryMirror{m})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.Entries[0].Status).To(Equal(apiv1.EntryFailed))
	g.Expect(res.Entries[0].Error).To(ContainSubstring("--insecure"))
}

// newMislabeledHelmRepo serves a Helm repository whose index lists podinfo
// 1.0.0 and 2.0.0 but whose 2.0.0 tarball declares version 9.9.9 in Chart.yaml.
func newMislabeledHelmRepo(t *testing.T) string {
	t.Helper()
	good := testregistry.PackageChart(t, fixtureChart, "1.0.0")
	bad := testregistry.PackageChart(t, fixtureChart, "9.9.9")
	mux := http.NewServeMux()
	mux.HandleFunc("/index.yaml", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `apiVersion: v1
entries:
  podinfo:
  - apiVersion: v2
    name: podinfo
    version: 1.0.0
    urls: [podinfo-1.0.0.tgz]
    created: "2024-01-01T00:00:00Z"
  - apiVersion: v2
    name: podinfo
    version: 2.0.0
    urls: [podinfo-2.0.0.tgz]
    created: "2024-01-02T00:00:00Z"
`)
	})
	mux.HandleFunc("/podinfo-1.0.0.tgz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(good) })
	mux.HandleFunc("/podinfo-2.0.0.tgz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(bad) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestChartsMirror_ToArtifactoryChartYAMLMismatchFailsOnlyThatVersion(t *testing.T) {
	g := NewWithT(t)
	testregistry.UseEmptyDockerConfig(t)
	srcURL := newMislabeledHelmRepo(t)
	fake, dstURL := testregistry.StartFakeArtifactory(t)
	c := oci.NewClient(oci.Insecure())

	m, err := New(c, artifactoryEntry(srcURL, dstURL), artifactoryOpts())
	g.Expect(err).ToNot(HaveOccurred())
	res, err := newRunner().Run(context.Background(), []sync.EntryMirror{m})
	g.Expect(err).ToNot(HaveOccurred())

	e := res.Entries[0]
	g.Expect(e.Status).To(Equal(apiv1.EntryCompleted))
	g.Expect(versionsWithStatus(e, apiv1.StatusCopied)).To(ConsistOf("1.0.0"))
	g.Expect(versionsWithStatus(e, apiv1.StatusFailed)).To(ConsistOf("2.0.0"))
	row, _ := rowByTag(e, "2.0.0")
	g.Expect(row.Error).To(ContainSubstring("declares podinfo@9.9.9, expected podinfo@2.0.0"))
	g.Expect(fake.Paths()).To(ConsistOf(artifactoryDir + "/podinfo-1.0.0.tgz"))
}

func TestChartsMirror_ToArtifactoryDoesNotParseChartWhenUpToDate(t *testing.T) {
	g := NewWithT(t)
	testregistry.UseEmptyDockerConfig(t)
	srcURL := newMislabeledHelmRepo(t)
	fake, dstURL := testregistry.StartFakeArtifactory(t)
	c := oci.NewClient(oci.Insecure())

	// Whatever is already stored for 2.0.0 with the same bytes counts as up to
	// date: the Chart.yaml check only guards uploads.
	bad := testregistry.PackageChart(t, fixtureChart, "9.9.9")
	fake.Set(artifactoryDir+"/podinfo-2.0.0.tgz", bad)

	entry := artifactoryEntry(srcURL, dstURL)
	entry.Selector.Semver = "2.0.0"
	m, err := New(c, entry, artifactoryOpts())
	g.Expect(err).ToNot(HaveOccurred())
	res, err := newRunner().Run(context.Background(), []sync.EntryMirror{m})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(versionsWithStatus(res.Entries[0], apiv1.StatusSkipped)).To(ConsistOf("2.0.0"))
	g.Expect(fake.Puts()).To(BeZero())
}

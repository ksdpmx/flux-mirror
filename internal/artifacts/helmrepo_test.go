// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package artifacts

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	. "github.com/onsi/gomega"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
	"github.com/fluxcd/flux-mirror/internal/hooks"
	"github.com/fluxcd/flux-mirror/internal/oci"
	"github.com/fluxcd/flux-mirror/internal/sync"
	"github.com/fluxcd/flux-mirror/internal/testregistry"
)

const fixtureChart = "../helmrepo/testdata/podinfo"

func newFakeHelmRepo(t *testing.T) (*testregistry.FakeArtifactory, string) {
	t.Helper()
	return testregistry.StartFakeArtifactory(t)
}

// stored returns the bytes the fake repository holds at path, or nil.
func stored(f *testregistry.FakeArtifactory, path string) []byte {
	data, _ := f.Get(path)
	return data
}

func pushChartFixture(t *testing.T, c *oci.Client, ref, version string) []byte {
	t.Helper()
	testregistry.UseEmptyDockerConfig(t)
	tgz := testregistry.PackageChart(t, fixtureChart, version)
	if _, err := c.PushHelmChart(context.Background(), ref, testregistry.ChartConfigJSON(t, tgz), tgz); err != nil {
		t.Fatalf("push %s: %s", ref, err)
	}
	return tgz
}

func chartEntry(src, dstURL string) apiv1.ArtifactEntry {
	return apiv1.ArtifactEntry{
		Source:          src,
		Destination:     dstURL + "/helm-local/team",
		DestinationType: apiv1.DestinationTypeArtifactory,
		Selector:        apiv1.Selector{Limit: new(0)},
	}
}

func helmOpts() Options {
	return Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Insecure: true}
}

func TestMirror_ChartToHelmRepo(t *testing.T) {
	g := NewWithT(t)
	src := repo("helm-src")
	c := oci.NewClient(oci.Insecure())
	tgz1 := pushChartFixture(t, c, src+":1.0.0", "1.0.0")
	pushChartFixture(t, c, src+":1.1.0", "1.1.0")
	fake, url := newFakeHelmRepo(t)

	run := func(entry apiv1.ArtifactEntry, opts Options) apiv1.EntryResult {
		res, err := newRunner().Run(context.Background(), []sync.EntryMirror{New(c, entry, opts)})
		g.Expect(err).ToNot(HaveOccurred())
		return res.Entries[0]
	}
	entry := chartEntry(src, url)

	// Dry run reports would-copy and uploads nothing.
	dry := helmOpts()
	dry.DryRun = true
	e := run(entry, dry)
	g.Expect(tagsWithStatus(e, apiv1.StatusWouldCopy)).To(HaveLen(2))
	g.Expect(fake.Paths()).To(BeEmpty())

	// First real run copies both versions.
	e = run(entry, helmOpts())
	g.Expect(tagsWithStatus(e, apiv1.StatusCopied)).To(HaveLen(2))
	g.Expect(stored(fake, "/helm-local/team/podinfo-1.0.0.tgz")).To(Equal(tgz1))
	g.Expect(fake.Paths()).To(ContainElement("/helm-local/team/podinfo-1.1.0.tgz"))

	// Second run is a no-op.
	puts := fake.Puts()
	e = run(entry, helmOpts())
	g.Expect(tagsWithStatus(e, apiv1.StatusSkipped)).To(HaveLen(2))
	g.Expect(fake.Puts()).To(Equal(puts))

	// A drifted destination is left alone without overwrite...
	fake.Set("/helm-local/team/podinfo-1.0.0.tgz", []byte("tampered"))
	e = run(entry, helmOpts())
	g.Expect(tagsWithStatus(e, apiv1.StatusDrifted)).To(HaveLen(1))
	g.Expect(stored(fake, "/helm-local/team/podinfo-1.0.0.tgz")).To(Equal([]byte("tampered")))

	// ...and replaced with overwrite.
	entry.Overwrite = true
	e = run(entry, helmOpts())
	g.Expect(tagsWithStatus(e, apiv1.StatusOverwritten)).To(HaveLen(1))
	g.Expect(stored(fake, "/helm-local/team/podinfo-1.0.0.tgz")).To(Equal(tgz1))
}

func TestMirror_ChartToHelmRepoHookDenyBlocksUpload(t *testing.T) {
	g := NewWithT(t)
	src := repo("helm-hook-src")
	c := oci.NewClient(oci.Insecure())
	pushChartFixture(t, c, src+":1.0.0", "1.0.0")
	manifestDigest, err := c.Digest(context.Background(), src+":1.0.0")
	g.Expect(err).ToNot(HaveOccurred())
	fake, url := newFakeHelmRepo(t)
	entry := chartEntry(src, url)
	entry.Hooks = testHookEntry(src, "quay.io/mirror/chart").Hooks
	var input hooks.Input

	opts := helmOpts()
	opts.HookBuilders = map[string]hooks.Builder{
		apiv1.HookProviderCosign: func(apiv1.HookStep) (hooks.Step, error) {
			return testHookStep(func(_ context.Context, got hooks.Input) (hooks.Outcome, error) {
				input = got
				return hooks.Outcome{Verdict: apiv1.StepVerdictDeny, Reason: "untrusted"}, nil
			}), nil
		},
	}
	res, err := newRunner().Run(context.Background(), []sync.EntryMirror{New(c, entry, opts)})
	g.Expect(err).ToNot(HaveOccurred())
	row := res.Entries[0].Tags[0]
	g.Expect(row.Status).To(Equal(apiv1.StatusBlocked))
	g.Expect(row.Digest).To(HavePrefix("sha256:"))
	g.Expect(input.Digest).To(Equal(manifestDigest))
	g.Expect(input.Source).To(Equal(src))
	g.Expect(input.Destination).To(ContainSubstring("podinfo-1.0.0.tgz"))
	g.Expect(fake.Paths()).To(BeEmpty())
}

func TestMirror_ChartToHelmRepoRejectsImage(t *testing.T) {
	g := NewWithT(t)
	src := repo("helm-image-src")
	testregistry.PushImage(t, src+":1.0.0")
	_, url := newFakeHelmRepo(t)

	c := oci.NewClient(oci.Insecure())
	res, err := newRunner().Run(context.Background(), []sync.EntryMirror{New(c, chartEntry(src, url), helmOpts())})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.Entries[0].Status).To(Equal(apiv1.EntryFailed))
	g.Expect(res.Entries[0].Error).To(ContainSubstring("not an OCI Helm chart"))
}

func TestMirror_ChartToHelmRepoVersionMismatchFailsOnlyThatTag(t *testing.T) {
	g := NewWithT(t)
	src := repo("helm-mismatch-src")
	c := oci.NewClient(oci.Insecure())
	pushChartFixture(t, c, src+":1.0.0", "1.0.0")
	pushChartFixture(t, c, src+":2.0.0", "1.5.0") // tag does not match chart version
	fake, url := newFakeHelmRepo(t)

	res, err := newRunner().Run(context.Background(), []sync.EntryMirror{New(c, chartEntry(src, url), helmOpts())})
	g.Expect(err).ToNot(HaveOccurred())
	e := res.Entries[0]
	g.Expect(e.Status).To(Equal(apiv1.EntryCompleted))
	g.Expect(tagsWithStatus(e, apiv1.StatusCopied)).To(HaveLen(1))
	failed := tagsWithStatus(e, apiv1.StatusFailed)
	g.Expect(failed).To(HaveLen(1))
	g.Expect(failed[0].Tag).To(Equal("2.0.0"))
	g.Expect(failed[0].Error).To(ContainSubstring("does not match tag"))
	g.Expect(fake.Paths()).To(HaveLen(1))
}

func TestMirror_ChartToHelmRepoRejectsProviderHost(t *testing.T) {
	g := NewWithT(t)
	src := repo("helm-provider-src")
	c := oci.NewClient(oci.Insecure())
	pushChartFixture(t, c, src+":1.0.0", "1.0.0")

	entry := chartEntry(src, "https://x.dkr.ecr.us-east-1.amazonaws.com")
	opts := helmOpts()
	opts.Hosts = []apiv1.RegistryHost{{Host: "x.dkr.ecr.us-east-1.amazonaws.com", Provider: apiv1.RegistryProviderECR}}
	res, err := newRunner().Run(context.Background(), []sync.EntryMirror{New(c, entry, opts)})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.Entries[0].Status).To(Equal(apiv1.EntryFailed))
	g.Expect(res.Entries[0].Error).To(ContainSubstring("not supported for destinationType"))
}

func TestMirror_ChartToHelmRepoVerify(t *testing.T) {
	g := NewWithT(t)
	src := repo("helm-verify-src")
	c := oci.NewClient(oci.Insecure())
	pushChartFixture(t, c, src+":1.0.0", "1.0.0")
	fake, url := newFakeHelmRepo(t)
	srcDigest, err := c.Digest(context.Background(), src+":1.0.0")
	g.Expect(err).ToNot(HaveOccurred())

	entry := chartEntry(src, url)
	entry.Verify = &apiv1.ArtifactVerification{Provider: apiv1.VerifyProviderCosign}
	opts := func(v Verifier) Options {
		o := helmOpts()
		o.Verifier = v
		return o
	}

	// A verified chart is uploaded and the job reports the Helm repo directory.
	ok := &recordingVerifier{info: &oci.VerificationInfo{Provider: apiv1.VerifyProviderCosign, Digest: srcDigest}}
	plan, err := New(c, entry, opts(ok)).Plan(context.Background())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(plan.Jobs).To(HaveLen(1))
	g.Expect(plan.Jobs[0].Dst).To(Equal(url + "/helm-local/team"))
	res, err := newRunner().Run(context.Background(), []sync.EntryMirror{New(c, entry, opts(ok))})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(tagsWithStatus(res.Entries[0], apiv1.StatusCopied)).To(HaveLen(1))
	g.Expect(fake.Paths()).To(ContainElement("/helm-local/team/podinfo-1.0.0.tgz"))

	// A verify failure becomes a failed tag row and nothing more is uploaded.
	fake.Reset()
	denied := &recordingVerifier{err: errors.New("denied")}
	plan, err = New(c, entry, opts(denied)).Plan(context.Background())
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(plan.Jobs).To(HaveLen(1))
	g.Expect(plan.Jobs[0].Dst).To(Equal(url + "/helm-local/team"))
	res, err = newRunner().Run(context.Background(), []sync.EntryMirror{New(c, entry, opts(denied))})
	g.Expect(err).ToNot(HaveOccurred())
	failed := tagsWithStatus(res.Entries[0], apiv1.StatusFailed)
	g.Expect(failed).To(HaveLen(1))
	g.Expect(failed[0].Error).To(ContainSubstring("denied"))
	g.Expect(fake.Paths()).To(BeEmpty())
}

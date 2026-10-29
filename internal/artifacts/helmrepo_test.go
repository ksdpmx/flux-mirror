// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package artifacts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	gosync "sync"
	"testing"

	. "github.com/onsi/gomega"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta1"
	"github.com/fluxcd/flux-mirror/internal/oci"
	"github.com/fluxcd/flux-mirror/internal/sync"
	"github.com/fluxcd/flux-mirror/internal/testregistry"
)

const fixtureChart = "../helmrepo/testdata/podinfo"

// fakeHelmRepo mimics the Artifactory behaviors the Helm repo pusher relies on.
type fakeHelmRepo struct {
	mu    gosync.Mutex
	files map[string][]byte
	puts  int
}

func newFakeHelmRepo(t *testing.T) (*fakeHelmRepo, string) {
	t.Helper()
	f := &fakeHelmRepo{files: map[string][]byte{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv.URL
}

func (f *fakeHelmRepo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.files[r.URL.Path]
	switch r.Method {
	case http.MethodHead:
		if !ok {
			http.NotFound(w, r)
			return
		}
		s := sha256.Sum256(data)
		w.Header().Set("X-Checksum-Sha256", hex.EncodeToString(s[:]))
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		s := sha256.Sum256(body)
		if r.Header.Get("X-Checksum-Sha256") != hex.EncodeToString(s[:]) {
			http.Error(w, "checksum mismatch", http.StatusConflict)
			return
		}
		f.files[r.URL.Path] = body
		f.puts++
		w.WriteHeader(http.StatusCreated)
	}
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
	g.Expect(fake.files).To(BeEmpty())

	// First real run copies both versions.
	e = run(entry, helmOpts())
	g.Expect(tagsWithStatus(e, apiv1.StatusCopied)).To(HaveLen(2))
	g.Expect(fake.files).To(HaveKeyWithValue("/helm-local/team/podinfo-1.0.0.tgz", tgz1))
	g.Expect(fake.files).To(HaveKey("/helm-local/team/podinfo-1.1.0.tgz"))

	// Second run is a no-op.
	puts := fake.puts
	e = run(entry, helmOpts())
	g.Expect(tagsWithStatus(e, apiv1.StatusSkipped)).To(HaveLen(2))
	g.Expect(fake.puts).To(Equal(puts))

	// A drifted destination is left alone without overwrite...
	fake.files["/helm-local/team/podinfo-1.0.0.tgz"] = []byte("tampered")
	e = run(entry, helmOpts())
	g.Expect(tagsWithStatus(e, apiv1.StatusDrifted)).To(HaveLen(1))
	g.Expect(fake.files["/helm-local/team/podinfo-1.0.0.tgz"]).To(Equal([]byte("tampered")))

	// ...and replaced with overwrite.
	entry.Overwrite = true
	e = run(entry, helmOpts())
	g.Expect(tagsWithStatus(e, apiv1.StatusOverwritten)).To(HaveLen(1))
	g.Expect(fake.files["/helm-local/team/podinfo-1.0.0.tgz"]).To(Equal(tgz1))
}

func TestMirror_ChartToHelmRepoLogsEveryOutcome(t *testing.T) {
	g := NewWithT(t)
	src := repo("helm-log-src")
	c := oci.NewClient(oci.Insecure())
	pushChartFixture(t, c, src+":1.0.0", "1.0.0")
	_, url := newFakeHelmRepo(t)
	entry := chartEntry(src, url)

	// run returns the log records of one sync, keyed by event.
	run := func(entry apiv1.ArtifactEntry) map[string]map[string]any {
		var buf bytes.Buffer
		opts := helmOpts()
		opts.Logger = slog.New(slog.NewJSONHandler(&buf, nil))
		_, err := newRunner().Run(context.Background(), []sync.EntryMirror{New(c, entry, opts)})
		g.Expect(err).ToNot(HaveOccurred())
		events := map[string]map[string]any{}
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			var rec map[string]any
			g.Expect(json.Unmarshal([]byte(line), &rec)).To(Succeed())
			if ev, ok := rec["event"].(string); ok {
				events[ev] = rec
			}
		}
		return events
	}

	ev := run(entry)
	g.Expect(ev).To(HaveKey("chart.start"))
	done := ev["chart.done"]
	g.Expect(done).To(HaveKeyWithValue("status", "copied"))
	g.Expect(done).To(HaveKeyWithValue("source", src))
	g.Expect(done).To(HaveKeyWithValue("tag", "1.0.0"))
	g.Expect(done["destination"]).To(HaveSuffix("/helm-local/team/podinfo-1.0.0.tgz"))
	g.Expect(done["digest"]).To(HavePrefix("sha256:"))
	g.Expect(done).To(HaveKey("elapsed"))

	// An up-to-date chart is still reported per tag, not only in the summary.
	ev = run(entry)
	g.Expect(ev["chart.skip"]).To(HaveKeyWithValue("reason", "destination chart is up to date"))
	g.Expect(ev["chart.done"]).To(HaveKeyWithValue("status", "skipped"))
}

func TestMirror_ChartToHelmRepoLogsDriftAndFailure(t *testing.T) {
	g := NewWithT(t)
	src := repo("helm-log2-src")
	c := oci.NewClient(oci.Insecure())
	pushChartFixture(t, c, src+":1.0.0", "1.0.0")
	pushChartFixture(t, c, src+":2.0.0", "1.5.0") // tag does not match chart version
	fake, url := newFakeHelmRepo(t)
	fake.files["/helm-local/team/podinfo-1.0.0.tgz"] = []byte("tampered")

	var buf bytes.Buffer
	opts := helmOpts()
	opts.Logger = slog.New(slog.NewJSONHandler(&buf, nil))
	_, err := newRunner().Run(context.Background(), []sync.EntryMirror{New(c, chartEntry(src, url), opts)})
	g.Expect(err).ToNot(HaveOccurred())

	events := map[string]map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		g.Expect(json.Unmarshal([]byte(line), &rec)).To(Succeed())
		if ev, ok := rec["event"].(string); ok {
			events[ev] = rec
		}
	}
	drift := events["chart.drift"]
	g.Expect(drift).To(HaveKeyWithValue("level", "WARN"))
	g.Expect(drift["digest"]).To(HavePrefix("sha256:"))
	g.Expect(drift["dst_digest"]).To(HavePrefix("sha256:"))
	g.Expect(drift).To(HaveKey("reason"))

	failed := events["chart.failed"]
	g.Expect(failed).To(HaveKeyWithValue("level", "ERROR"))
	g.Expect(failed).To(HaveKeyWithValue("tag", "2.0.0"))
	g.Expect(failed["error"]).To(ContainSubstring("does not match tag"))
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
	g.Expect(fake.files).To(HaveLen(1))
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

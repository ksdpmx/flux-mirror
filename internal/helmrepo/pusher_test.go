// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package helmrepo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	gosync "sync"
	"testing"

	. "github.com/onsi/gomega"
)

// fakeArtifactory is a minimal in-memory Helm repo directory that mimics the
// Artifactory behaviors the Pusher relies on.
type fakeArtifactory struct {
	mu             gosync.Mutex
	files          map[string][]byte
	reportChecksum bool
	forbidPut      bool
	lastAuth       string
}

func newFakeArtifactory(t *testing.T) (*fakeArtifactory, *httptest.Server) {
	t.Helper()
	f := &fakeArtifactory{files: map[string][]byte{}, reportChecksum: true}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func (f *fakeArtifactory) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastAuth = r.Header.Get("Authorization")
	data, ok := f.files[r.URL.Path]
	switch r.Method {
	case http.MethodHead, http.MethodGet:
		if !ok {
			http.NotFound(w, r)
			return
		}
		if f.reportChecksum {
			w.Header().Set("X-Checksum-Sha256", sum(data))
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write(data)
		}
	case http.MethodPut:
		if f.forbidPut {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if want := r.Header.Get("X-Checksum-Sha256"); want != sum(body) {
			http.Error(w, "checksum mismatch", http.StatusConflict)
			return
		}
		if int64(len(body)) != r.ContentLength {
			http.Error(w, "bad length", http.StatusBadRequest)
			return
		}
		f.files[r.URL.Path] = body
		w.WriteHeader(http.StatusCreated)
	}
}

func TestNormalizeDestination(t *testing.T) {
	tests := []struct {
		in, want, errMsg string
	}{
		{in: "x.jfrog.io/artifactory/helm-local/", want: "https://x.jfrog.io/artifactory/helm-local"},
		{in: "https://x.jfrog.io/helm", want: "https://x.jfrog.io/helm"},
		{in: "http://localhost:8081/helm", want: "http://localhost:8081/helm"},
		{in: "", errMsg: "required"},
		{in: "oci://x.jfrog.io/helm", errMsg: "scheme must be https"},
		{in: "https://", errMsg: "missing a host"},
		{in: "https://x.io/helm?a=b", errMsg: "query or fragment"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			g := NewWithT(t)
			u, err := NormalizeDestination(tt.in)
			if tt.errMsg != "" {
				g.Expect(err).To(MatchError(ContainSubstring(tt.errMsg)))
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(u.String()).To(Equal(tt.want))
		})
	}
}

func TestNewPusher_RejectsPlainHTTPWithoutInsecure(t *testing.T) {
	g := NewWithT(t)
	_, err := NewPusher("http://localhost:8081/helm", false)
	g.Expect(err).To(MatchError(ContainSubstring("--insecure")))
	_, err = NewPusher("http://localhost:8081/helm", true)
	g.Expect(err).ToNot(HaveOccurred())
}

func TestPusher_ChartURLRejectsUnsafeNames(t *testing.T) {
	g := NewWithT(t)
	p, err := NewPusher("https://x.jfrog.io/helm/team", false)
	g.Expect(err).ToNot(HaveOccurred())
	u, err := p.ChartURL("podinfo", "1.2.3+build")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(u).To(Equal("https://x.jfrog.io/helm/team/podinfo-1.2.3+build.tgz"))
	_, err = p.ChartURL("../evil", "1.0.0")
	g.Expect(err).To(HaveOccurred())
	_, err = p.ChartURL("podinfo", "")
	g.Expect(err).To(HaveOccurred())
}

func TestPusher_PutAndStat(t *testing.T) {
	g := NewWithT(t)
	f, srv := newFakeArtifactory(t)
	p, err := NewPusher(srv.URL+"/helm-local/team", true)
	g.Expect(err).ToNot(HaveOccurred())
	ctx := context.Background()

	got, err := p.Stat(ctx, "podinfo", "1.0.0")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(got).To(BeEmpty())

	body := []byte("chart-bytes")
	g.Expect(p.Put(ctx, "podinfo", "1.0.0", strings.NewReader(string(body)), int64(len(body)), "sha256:"+sum(body))).To(Succeed())
	g.Expect(f.files).To(HaveKeyWithValue("/helm-local/team/podinfo-1.0.0.tgz", body))

	got, err = p.Stat(ctx, "podinfo", "1.0.0")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(got).To(Equal("sha256:" + sum(body)))
}

func TestPusher_StatFallsBackToHashingWithoutChecksumHeader(t *testing.T) {
	g := NewWithT(t)
	f, srv := newFakeArtifactory(t)
	f.reportChecksum = false
	f.files["/helm/podinfo-1.0.0.tgz"] = []byte("abc")
	p, err := NewPusher(srv.URL+"/helm", true)
	g.Expect(err).ToNot(HaveOccurred())

	got, err := p.Stat(context.Background(), "podinfo", "1.0.0")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(got).To(Equal("sha256:" + sum([]byte("abc"))))
}

func TestPusher_PutForbiddenHintsAtOverwrite(t *testing.T) {
	g := NewWithT(t)
	f, srv := newFakeArtifactory(t)
	f.forbidPut = true
	p, err := NewPusher(srv.URL+"/helm", true)
	g.Expect(err).ToNot(HaveOccurred())

	body := []byte("x")
	err = p.Put(context.Background(), "podinfo", "1.0.0", strings.NewReader("x"), 1, "sha256:"+sum(body))
	g.Expect(err).To(MatchError(ContainSubstring("forbids overwriting")))
}

func TestPusher_PutNotFoundHintsAtContextPath(t *testing.T) {
	g := NewWithT(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	p, err := NewPusher(srv.URL+"/helm", true)
	g.Expect(err).ToNot(HaveOccurred())

	err = p.Put(context.Background(), "podinfo", "1.0.0", strings.NewReader("x"), 1, "sha256:"+sum([]byte("x")))
	g.Expect(err).To(MatchError(ContainSubstring("/artifactory context path")))

	// A missing file on HEAD is not an error.
	got, err := p.Stat(context.Background(), "podinfo", "1.0.0")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(got).To(BeEmpty())
}

func TestPusher_PutRejectsBadChecksumServerSide(t *testing.T) {
	g := NewWithT(t)
	_, srv := newFakeArtifactory(t)
	p, err := NewPusher(srv.URL+"/helm", true)
	g.Expect(err).ToNot(HaveOccurred())

	err = p.Put(context.Background(), "podinfo", "1.0.0", strings.NewReader("x"), 1, "sha256:"+sum([]byte("other")))
	g.Expect(err).To(MatchError(ContainSubstring("status 409")))
}

func TestPusher_BasicAuth(t *testing.T) {
	g := NewWithT(t)
	f, srv := newFakeArtifactory(t)
	p, err := NewPusher(srv.URL+"/helm", true, WithBasicAuth(func(context.Context) (string, string, error) {
		return "bob", "secret", nil
	}))
	g.Expect(err).ToNot(HaveOccurred())

	_, err = p.Stat(context.Background(), "podinfo", "1.0.0")
	g.Expect(err).ToNot(HaveOccurred())
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	req.SetBasicAuth("bob", "secret")
	g.Expect(f.lastAuth).To(Equal(req.Header.Get("Authorization")))
}

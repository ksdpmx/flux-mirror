// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package testregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// FakeArtifactory is an in-memory stand-in for a JFrog Artifactory Helm
// repository. It implements the behaviors flux-mirror relies on: HEAD and GET
// return the stored file (HEAD with an X-Checksum-Sha256 header), and PUT stores
// a file after verifying its checksum header and length.
type FakeArtifactory struct {
	// NoChecksumHeader makes HEAD/GET omit X-Checksum-Sha256.
	NoChecksumHeader bool
	// ForbidPut makes every PUT fail with 403.
	ForbidPut bool

	mu       sync.Mutex
	files    map[string][]byte
	puts     int
	lastAuth string
}

// StartFakeArtifactory starts a FakeArtifactory and returns it with its base
// URL (for example http://127.0.0.1:1234). The server stops with the test.
func StartFakeArtifactory(t testing.TB) (*FakeArtifactory, string) {
	t.Helper()
	f := &FakeArtifactory{files: map[string][]byte{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv.URL
}

// Set stores data at the URL path, for example "/helm-local/podinfo-1.0.0.tgz".
func (f *FakeArtifactory) Set(path string, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[path] = data
}

// Get returns the file stored at the URL path.
func (f *FakeArtifactory) Get(path string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.files[path]
	return data, ok
}

// Reset removes every stored file.
func (f *FakeArtifactory) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files = map[string][]byte{}
}

// Paths returns the URL paths of all stored files.
func (f *FakeArtifactory) Paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.files))
	for p := range f.files {
		out = append(out, p)
	}
	return out
}

// Puts returns the number of accepted PUT requests.
func (f *FakeArtifactory) Puts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.puts
}

// LastAuth returns the Authorization header of the most recent request.
func (f *FakeArtifactory) LastAuth() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastAuth
}

func checksum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// ServeHTTP implements http.Handler.
func (f *FakeArtifactory) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
		if !f.NoChecksumHeader {
			w.Header().Set("X-Checksum-Sha256", checksum(data))
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write(data)
		}
	case http.MethodPut:
		if f.ForbidPut {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("X-Checksum-Sha256") != checksum(body) {
			http.Error(w, "checksum mismatch", http.StatusConflict)
			return
		}
		if int64(len(body)) != r.ContentLength {
			http.Error(w, "bad length", http.StatusBadRequest)
			return
		}
		f.files[r.URL.Path] = body
		f.puts++
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

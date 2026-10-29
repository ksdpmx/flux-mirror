// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"github.com/fluxcd/flux-mirror/internal/testregistry"
)

func TestJSONReplaceAttr_DurationsAsSeconds(t *testing.T) {
	g := NewWithT(t)

	var buf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: jsonReplaceAttr}))
	l.Info("done", "elapsed", 4227*time.Millisecond, "wall", 90*time.Second, "count", 3)

	var rec map[string]any
	g.Expect(json.Unmarshal(buf.Bytes(), &rec)).To(Succeed())
	g.Expect(rec["elapsed"]).To(BeNumerically("==", 4.227))
	g.Expect(rec["wall"]).To(BeNumerically("==", 90))
	g.Expect(rec["count"]).To(BeNumerically("==", 3))
}

func TestSync_VerboseJSONLogFormat(t *testing.T) {
	g := NewWithT(t)
	ensureRegistry(t)

	src := dockerReg + "/logjson-src-" + testregistry.RandSuffix()
	dst := dockerReg + "/logjson-dst-" + testregistry.RandSuffix()
	testregistry.PushImage(t, src+":1.0.0")
	cfgPath := writeConfig(t, src, dst)
	t.Setenv("FLUX_MIRROR_CONFIG", "")

	// executeCommand merges stdout and stderr; capture stderr on its own so
	// every line can be checked to be a JSON object.
	defer resetCmdArgs()
	var stdout, stderr bytes.Buffer
	rootCmd.SetArgs([]string{"sync", cfgPath, "--insecure", "--verbose", "--log-format", "json"})
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	g.Expect(rootCmd.Execute()).To(Succeed())

	var started map[string]any
	lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
	g.Expect(lines).ToNot(BeEmpty())
	for _, line := range lines {
		var rec map[string]any
		g.Expect(json.Unmarshal([]byte(line), &rec)).To(Succeed(), "not JSON: %s", line)
		g.Expect(rec).To(HaveKey("time"))
		g.Expect(rec).To(HaveKey("level"))
		if rec["msg"] == "sync started" {
			started = rec
		}
	}
	g.Expect(started).ToNot(BeNil())
	// The default 5m timeout is rendered in seconds.
	g.Expect(started["timeout"]).To(BeNumerically("==", 300))
}

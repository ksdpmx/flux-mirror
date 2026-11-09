// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package artifacts

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
	"github.com/fluxcd/flux-mirror/internal/oci"
	"github.com/fluxcd/flux-mirror/internal/sync"
	"github.com/fluxcd/flux-mirror/internal/testregistry"
)

// writeFakeWizcli writes a wizcli stand-in that writes a report with verdict
// to the --json-output-file path and exits with exitCode.
func writeFakeWizcli(t *testing.T, exitCode int, verdict, failedPolicy string) string {
	t.Helper()
	failed := "null"
	if failedPolicy != "" {
		failed = fmt.Sprintf(`[{"policy":{"name":%q}}]`, failedPolicy)
	}
	script := fmt.Sprintf(`#!/bin/sh
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--json-output-file" ]; then out="$arg"; fi
  prev="$arg"
done
cat > "$out" <<EOF
{"id":"scan-1","status":{"state":"SUCCESS","verdict":%q},"result":{"failedPolicyMatches":%s}}
EOF
exit %d
`, verdict, failed, exitCode)
	path := filepath.Join(t.TempDir(), "wizcli")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake wizcli: %s", err)
	}
	t.Setenv("WIZ_CLIENT_ID", "client-id")
	t.Setenv("WIZ_CLIENT_SECRET", "client-secret")
	return path
}

func wizcliEntry(src, dst, binary string) apiv1.ArtifactEntry {
	return apiv1.ArtifactEntry{
		Source:      src,
		Destination: dst,
		Selector:    apiv1.Selector{Limit: new(1)},
		Hooks: &apiv1.ArtifactHooks{Pre: []apiv1.HookStep{{
			Name:     "vuln-scan",
			Provider: apiv1.HookProviderWizcli,
			Wizcli: &apiv1.WizcliHookConfig{
				Platforms: []string{"linux/amd64"},
				Binary:    binary,
			},
		}}},
	}
}

func TestMirror_WizcliBlocksBeforeCopy(t *testing.T) {
	g := NewWithT(t)
	src := repo("wizcli-block-src")
	dst := repo("wizcli-block-dst")
	testregistry.PushImage(t, src+":1.0.0")
	binary := writeFakeWizcli(t, 4, "FAILED_BY_POLICY", "Block End of Life")
	c := oci.NewClient(oci.Insecure())

	res, err := newRunner().Run(context.Background(), []sync.EntryMirror{
		New(c, wizcliEntry(src, dst, binary), Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}),
	})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.ExitCode()).To(Equal(3))

	row := res.Entries[0].Tags[0]
	g.Expect(row.Status).To(Equal(apiv1.StatusBlocked))
	g.Expect(row.Reason).To(Equal("vuln-scan"))
	g.Expect(row.Steps).To(HaveLen(1))
	g.Expect(row.Steps[0].Units).To(HaveLen(1))
	unit := row.Steps[0].Units[0]
	g.Expect(unit.Name).To(Equal("linux/amd64"))
	g.Expect(unit.Verdict).To(Equal(apiv1.StepVerdictDeny))
	g.Expect(unit.Wizcli.FailedPolicies).To(Equal([]string{"Block End of Life"}))
	g.Expect(unit.Wizcli.Digest).To(HavePrefix("sha256:"))

	cmp, err := c.Compare(context.Background(), src+":1.0.0", dst+":1.0.0")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(cmp.State).To(Equal(oci.StateMissing))
}

func TestMirror_WizcliPassCopies(t *testing.T) {
	g := NewWithT(t)
	src := repo("wizcli-pass-src")
	dst := repo("wizcli-pass-dst")
	testregistry.PushImage(t, src+":1.0.0")
	binary := writeFakeWizcli(t, 0, "PASSED_BY_POLICY", "")
	c := oci.NewClient(oci.Insecure())

	res, err := newRunner().Run(context.Background(), []sync.EntryMirror{
		New(c, wizcliEntry(src, dst, binary), Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}),
	})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.ExitCode()).To(Equal(0))

	row := res.Entries[0].Tags[0]
	g.Expect(row.Status).To(Equal(apiv1.StatusCopied))
	g.Expect(row.Steps[0].Units[0].Wizcli.Verdict).To(Equal("PASSED_BY_POLICY"))

	cmp, err := c.Compare(context.Background(), src+":1.0.0", dst+":1.0.0")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(cmp.State).To(Equal(oci.StateEqual))
}

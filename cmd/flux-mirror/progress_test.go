// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	. "github.com/onsi/gomega"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
	syncpkg "github.com/fluxcd/flux-mirror/internal/sync"
)

func TestProgressJobFinished(t *testing.T) {
	wizcliDeny := func(policies ...[]string) []apiv1.UnitResult {
		units := make([]apiv1.UnitResult, len(policies))
		for i, p := range policies {
			units[i] = apiv1.UnitResult{
				Name:    "linux/amd64",
				Verdict: apiv1.StepVerdictDeny,
				Wizcli:  &apiv1.WizcliResult{FailedPolicies: p},
			}
		}
		return units
	}

	tests := []struct {
		name string
		res  syncpkg.JobResult
		err  error
		want string
	}{
		{
			name: "copied tag shows the destination",
			res:  syncpkg.JobResult{Status: apiv1.StatusCopied},
			want: "✓ alpine:3.20 (copied)\n→ localhost:5050/alpine:3.20\n",
		},
		{
			name: "blocked tag names the step and the failed policies once",
			res: syncpkg.JobResult{
				Status: apiv1.StatusBlocked,
				Reason: "vuln-scan",
				Steps: []apiv1.StepResult{{
					Name:     "vuln-scan",
					Verdict:  apiv1.StepVerdictDeny,
					Duration: "41.234567s",
					Units: wizcliDeny(
						[]string{"EOL", "CVE"},
						[]string{"EOL"},
					),
				}},
			},
			want: "✗ alpine:3.20 (blocked by vuln-scan: EOL, CVE)\n" +
				"  └─ pre hook vuln-scan: deny (41.23s)\n",
		},
		{
			name: "blocked tag falls back to the step reason",
			res: syncpkg.JobResult{
				Status: apiv1.StatusBlocked,
				Reason: "signature",
				Steps: []apiv1.StepResult{{
					Name:     "signature",
					Verdict:  apiv1.StepVerdictDeny,
					Reason:   "no matching signature",
					Duration: "800ms",
				}},
			},
			want: "✗ alpine:3.20 (blocked by signature: no matching signature)\n" +
				"  └─ pre hook signature: deny (800ms)\n",
		},
		{
			name: "blocked tag without step details names only the step",
			res:  syncpkg.JobResult{Status: apiv1.StatusBlocked, Reason: "signature"},
			want: "✗ alpine:3.20 (blocked by signature)\n",
		},
		{
			name: "copied tag lists every hook that ran under the result",
			res: syncpkg.JobResult{
				Status: apiv1.StatusCopied,
				Steps: []apiv1.StepResult{
					{Name: "signature", Verdict: apiv1.StepVerdictAllow, Duration: "812ms"},
					{Name: "vuln-scan", Verdict: apiv1.StepVerdictAllow, Duration: "41.2s"},
				},
			},
			want: "✓ alpine:3.20 (copied)\n" +
				"→ localhost:5050/alpine:3.20\n" +
				"  ├─ pre hook signature: allow (810ms)\n" +
				"  └─ pre hook vuln-scan: allow (41.2s)\n",
		},
		{
			name: "skipped tag shows the skip reason of the hook",
			res: syncpkg.JobResult{
				Status: apiv1.StatusSkipped,
				Reason: "signature-too-new",
				Steps: []apiv1.StepResult{{
					Name:     "signature",
					Verdict:  apiv1.StepVerdictSkip,
					Reason:   "signature-too-new",
					Duration: "1s",
				}},
			},
			want: "✓ alpine:3.20 (skipped)\n" +
				"→ localhost:5050/alpine:3.20\n" +
				"  └─ pre hook signature: skip (1s): signature-too-new\n",
		},
		{
			name: "failed hook is listed under the error",
			res: syncpkg.JobResult{
				Steps: []apiv1.StepResult{{Name: "vuln-scan", Verdict: apiv1.StepVerdictError, Duration: "5s"}},
			},
			err: errTest("hook vuln-scan: timeout"),
			want: "✗ alpine:3.20 — hook vuln-scan: timeout\n" +
				"→ localhost:5050/alpine:3.20\n" +
				"  └─ pre hook vuln-scan: error (5s)\n",
		},
		{
			name: "hook error that did not fail the tag is shown as a warning with its error",
			res: syncpkg.JobResult{
				Status: apiv1.StatusCopied,
				Steps: []apiv1.StepResult{
					{Name: "signature", Verdict: apiv1.StepVerdictAllow, Duration: "812ms"},
					{Name: "vuln-scan", Verdict: apiv1.StepVerdictError, Duration: "5s", Error: "context deadline exceeded", Continued: true},
				},
			},
			want: "✓ alpine:3.20 (copied)\n" +
				"→ localhost:5050/alpine:3.20\n" +
				"  ├─ pre hook signature: allow (810ms)\n" +
				"  └─ pre hook vuln-scan: warn (5s): context deadline exceeded\n",
		},
		{
			name: "warning keeps only the first line of a long error",
			res: syncpkg.JobResult{
				Status: apiv1.StatusCopied,
				Steps: []apiv1.StepResult{{
					Name:      "vuln-scan",
					Verdict:   apiv1.StepVerdictError,
					Duration:  "5s",
					Continued: true,
					Error:     strings.Repeat("x", maxHookReason+10) + "\nsecond line",
				}},
			},
			want: "✓ alpine:3.20 (copied)\n" +
				"→ localhost:5050/alpine:3.20\n" +
				"  └─ pre hook vuln-scan: warn (5s): " + strings.Repeat("x", maxHookReason) + "…\n",
		},
		{
			name: "tag without hooks prints no hook lines",
			res:  syncpkg.JobResult{Status: apiv1.StatusSkipped},
			want: "✓ alpine:3.20 (skipped)\n→ localhost:5050/alpine:3.20\n",
		},
		{
			name: "error keeps the failure format",
			err:  errTest("boom"),
			want: "✗ alpine:3.20 — boom\n→ localhost:5050/alpine:3.20\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			var out bytes.Buffer
			p := newProgress(&out, nil, 1)

			p.JobFinished("alpine", "3.20", "localhost:5050/alpine:3.20", tt.res, tt.err)

			g.Expect(out.String()).To(Equal(tt.want))
		})
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }

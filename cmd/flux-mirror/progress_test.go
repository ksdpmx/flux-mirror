// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
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
					Name: "vuln-scan",
					Units: wizcliDeny(
						[]string{"EOL", "CVE"},
						[]string{"EOL"},
					),
				}},
			},
			want: "✗ alpine:3.20 (blocked by vuln-scan: EOL, CVE)\n",
		},
		{
			name: "blocked tag falls back to the step reason",
			res: syncpkg.JobResult{
				Status: apiv1.StatusBlocked,
				Reason: "signature",
				Steps:  []apiv1.StepResult{{Name: "signature", Reason: "no matching signature"}},
			},
			want: "✗ alpine:3.20 (blocked by signature: no matching signature)\n",
		},
		{
			name: "blocked tag without step details names only the step",
			res:  syncpkg.JobResult{Status: apiv1.StatusBlocked, Reason: "signature"},
			want: "✗ alpine:3.20 (blocked by signature)\n",
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

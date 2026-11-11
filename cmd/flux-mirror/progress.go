// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/briandowns/spinner"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
	mirrorsync "github.com/fluxcd/flux-mirror/internal/sync"
)

// progress drives a single global spinner (on stderr) plus per-job
// completion lines (on stdout) for the human-friendly text mode. It is
// intentionally only wired in non-verbose runs — the verbose log stream
// already conveys per-tag progress and a spinner would just compete with it.
//
// When ttyOut is nil (the --no-progress path) the spinner is omitted but
// per-job lines and PlanFailed lines still print. That mode is for CI logs
// where ANSI cursor escapes from the spinner are noise.
//
// The "N/M done" counter ticks on entry completion, not on individual
// jobs, so the denominator is fixed at construction (= number of entries
// in the config) and the user sees stable, predictable progression.
type progress struct {
	mu           sync.Mutex
	spinner      *spinner.Spinner // nil when --no-progress is set
	out          io.Writer
	totalEntries int
	entriesDone  int
}

func newProgress(out, ttyOut io.Writer, totalEntries int) *progress {
	p := &progress{out: out, totalEntries: totalEntries}
	if ttyOut != nil {
		p.spinner = spinner.New(spinner.CharSets[14], 100*time.Millisecond, spinner.WithWriter(ttyOut))
		p.refreshSuffixLocked()
		p.spinner.Start()
	}
	return p
}

// JobFinished is the OnJobFinished hook for sync.Runner. Safe for
// concurrent invocation.
func (p *progress) JobFinished(entry, id, dst string, res mirrorsync.JobResult, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// One write per job keeps the result line and its hook lines together.
	var b strings.Builder
	switch {
	case err != nil:
		fmt.Fprintf(&b, "✗ %s:%s — %v\n", entry, id, err)
		if dst != "" {
			fmt.Fprintf(&b, "→ %s\n", dst)
		}
	case res.Status == apiv1.StatusBlocked:
		// A blocked tag was not copied, so no destination line.
		fmt.Fprintf(&b, "✗ %s:%s (blocked by %s)\n", entry, id, blockedDetail(res))
	default:
		fmt.Fprintf(&b, "✓ %s:%s (%s)\n", entry, id, res.Status)
		if dst != "" {
			fmt.Fprintf(&b, "→ %s\n", dst)
		}
	}
	writeHookLines(&b, res.Steps)
	p.emitLocked("%s", b.String())
}

// writeHookLines lists the pre-copy hook steps that ran for a tag as a tree
// under its result line, in order: the verdict, how long the step took, and a
// reason for a skip or a warning. An up-to-date tag lists its steps as "skipped"
// without a duration or reason, since none ran. A tag that no hook ran for (drifted, no
// hooks configured) has none. Only the pre phase exists today;
// label the phase here once a post phase is added.
//
// A step that denied the tag or errored but let it continue (onDeny or onError
// is warn) is shown as "warn" with the failed policies or the error. When the
// step stopped the tag, the result line already says why.
func writeHookLines(b *strings.Builder, steps []apiv1.StepResult) {
	for i, step := range steps {
		branch := "├─"
		if i == len(steps)-1 {
			branch = "└─"
		}
		verdict, reason := string(step.Verdict), ""
		switch {
		case step.Verdict == apiv1.StepVerdictSkip && step.Reason == apiv1.ReasonUpToDate:
			verdict = "skipped"
		case step.Verdict == apiv1.StepVerdictSkip:
			reason = step.Reason
		case step.Continued:
			verdict = "warn"
			if step.Verdict == apiv1.StepVerdictError {
				reason = firstLine(step.Error, maxHookReason)
			} else {
				reason = firstLine(denyReason(step), maxHookReason)
			}
		}
		detail := verdict
		if d, err := time.ParseDuration(step.Duration); err == nil && d > 0 {
			detail += " (" + d.Round(10*time.Millisecond).String() + ")"
		}
		if reason != "" {
			detail += ": " + reason
		}
		fmt.Fprintf(b, "  %s pre hook %s: %s\n", branch, step.Name, detail)
		for _, unit := range step.Units {
			if unit.Wizcli != nil && unit.Wizcli.ReportURL != "" {
				fmt.Fprintf(b, "     %s report: %s\n", unit.Name, unit.Wizcli.ReportURL)
			}
		}
	}
}

// maxHookReason bounds the text shown for a warned hook, so a long provider
// message does not flood the output.
const maxHookReason = 120

// firstLine returns the first line of s, cut to max runes with an ellipsis.
func firstLine(s string, max int) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	line = strings.TrimSpace(line)
	if runes := []rune(line); len(runes) > max {
		return string(runes[:max]) + "…"
	}
	return line
}

// denyReason explains why a step denied a tag: the failed Wiz policies when a
// wizcli unit reported them, otherwise the step's own reason.
func denyReason(step apiv1.StepResult) string {
	var policies []string
	seen := map[string]bool{}
	for _, unit := range step.Units {
		if unit.Wizcli == nil {
			continue
		}
		for _, policy := range unit.Wizcli.FailedPolicies {
			if !seen[policy] {
				seen[policy] = true
				policies = append(policies, policy)
			}
		}
	}
	if len(policies) > 0 {
		return strings.Join(policies, ", ")
	}
	return step.Reason
}

// blockedDetail names the hook step that blocked a tag and why. Reason holds
// the step name for a blocked tag.
func blockedDetail(res mirrorsync.JobResult) string {
	for _, step := range res.Steps {
		if step.Name != res.Reason {
			continue
		}
		if reason := denyReason(step); reason != "" {
			return res.Reason + ": " + reason
		}
		break
	}
	return res.Reason
}

// EntryFinished is the OnEntryFinished hook for sync.Runner. Called once
// per entry from the main goroutine; advances the spinner counter.
func (p *progress) EntryFinished(_ string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.entriesDone++
	p.refreshSuffixLocked()
}

// PlanFailed is the OnPlanError hook for sync.Runner. Without this,
// plan-time failures (ListTags rejected, auth errors, etc.) would only
// surface in the final Summary count — never as actionable per-entry
// detail.
func (p *progress) PlanFailed(entry string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.emitLocked("✗ %s — plan failed: %v\n", entry, err)
}

func (p *progress) refreshSuffixLocked() {
	if p.spinner == nil {
		return
	}
	p.spinner.Suffix = fmt.Sprintf(" syncing... (%d/%d done)", p.entriesDone, p.totalEntries)
}

// emitLocked stops the spinner (if any), writes one line, then restarts
// it so the per-tag line lands cleanly above the spinner. Write errors on
// a TTY printer are not actionable here, so they're swallowed.
func (p *progress) emitLocked(format string, args ...any) {
	if p.spinner != nil {
		p.spinner.Stop()
	}
	_, _ = fmt.Fprintf(p.out, format, args...)
	if p.spinner != nil {
		p.spinner.Start()
	}
}

// Close stops the spinner. Idempotent — spinner.Stop is a no-op once
// stopped, and a no-op altogether when the spinner was never created.
func (p *progress) Close() {
	if p.spinner != nil {
		p.spinner.Stop()
	}
}

// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
)

type unitsStep []Unit

func (s unitsStep) Units(context.Context, Input) ([]Unit, error) { return s, nil }

func verdictUnit(name string, outcome Outcome, err error) Unit {
	return Unit{Name: name, Run: func(context.Context) (Outcome, error) { return outcome, err }}
}

func allowOutcome() Outcome { return Outcome{Verdict: apiv1.StepVerdictAllow} }

func unitVerdicts(result Result) []apiv1.StepVerdict {
	verdicts := make([]apiv1.StepVerdict, len(result.Steps[0].Units))
	for i, unit := range result.Steps[0].Units {
		verdicts[i] = unit.Verdict
	}
	return verdicts
}

func TestRunner_UnitsAllAllow(t *testing.T) {
	g := NewWithT(t)
	step := unitsStep{
		verdictUnit("linux/amd64", allowOutcome(), nil),
		verdictUnit("linux/arm64", allowOutcome(), nil),
	}
	runner, err := NewRunner(hookConfigs(1), time.Minute, buildSteps(step))
	g.Expect(err).ToNot(HaveOccurred())

	result, err := runner.Run(context.Background(), Input{Digest: "sha256:abc"})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(result.Terminal).To(BeNil())
	g.Expect(result.Steps[0].Verdict).To(Equal(apiv1.StepVerdictAllow))
	g.Expect(result.Steps[0].Attempts).To(Equal(2))
	g.Expect(unitVerdicts(result)).To(Equal([]apiv1.StepVerdict{apiv1.StepVerdictAllow, apiv1.StepVerdictAllow}))
	g.Expect(result.Steps[0].Units[0].Name).To(Equal("linux/amd64"))
}

func TestRunner_UnitDenyWinsOverError(t *testing.T) {
	g := NewWithT(t)
	step := unitsStep{
		verdictUnit("linux/amd64", allowOutcome(), nil),
		verdictUnit("linux/arm64", Outcome{Verdict: apiv1.StepVerdictDeny, Reason: "cve"}, nil),
		verdictUnit("linux/s390x", Outcome{}, Permanent(errors.New("boom"))),
	}
	runner, err := NewRunner(hookConfigs(1), time.Minute, buildSteps(step))
	g.Expect(err).ToNot(HaveOccurred())

	result, err := runner.Run(context.Background(), Input{Digest: "sha256:abc"})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(result.Terminal).To(Equal(&Terminal{Status: apiv1.StatusBlocked, Reason: "step-0", Digest: "sha256:abc"}))
	g.Expect(result.Steps[0].Verdict).To(Equal(apiv1.StepVerdictDeny))
	g.Expect(result.Steps[0].Reason).To(Equal("linux/arm64: cve"))
	g.Expect(unitVerdicts(result)).To(Equal([]apiv1.StepVerdict{
		apiv1.StepVerdictAllow, apiv1.StepVerdictDeny, apiv1.StepVerdictError,
	}))
	g.Expect(result.Steps[0].Units[2].Error).To(Equal("boom"))
}

func TestRunner_UnitErrorWithoutDenyFailsTheStep(t *testing.T) {
	g := NewWithT(t)
	step := unitsStep{
		verdictUnit("linux/amd64", allowOutcome(), nil),
		verdictUnit("linux/arm64", Outcome{}, Permanent(errors.New("boom"))),
	}
	runner, err := NewRunner(hookConfigs(1), time.Minute, buildSteps(step))
	g.Expect(err).ToNot(HaveOccurred())

	result, err := runner.Run(context.Background(), Input{})
	g.Expect(err).To(MatchError("hook step-0: linux/arm64: boom"))
	g.Expect(result.Steps[0].Verdict).To(Equal(apiv1.StepVerdictError))
	g.Expect(unitVerdicts(result)).To(Equal([]apiv1.StepVerdict{apiv1.StepVerdictAllow, apiv1.StepVerdictError}))
}

func TestRunner_UnitSkipWithoutDenyOrError(t *testing.T) {
	g := NewWithT(t)
	step := unitsStep{
		verdictUnit("linux/amd64", allowOutcome(), nil),
		verdictUnit("linux/arm64", Outcome{Verdict: apiv1.StepVerdictSkip, Reason: apiv1.ReasonSignatureTooNew}, nil),
	}
	runner, err := NewRunner(hookConfigs(1), time.Minute, buildSteps(step))
	g.Expect(err).ToNot(HaveOccurred())

	result, err := runner.Run(context.Background(), Input{Digest: "sha256:abc"})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(result.Terminal).To(Equal(&Terminal{
		Status: apiv1.StatusSkipped, Reason: apiv1.ReasonSignatureTooNew, Digest: "sha256:abc",
	}))
}

func TestRunner_UnitsAreLimitedByStepConcurrency(t *testing.T) {
	g := NewWithT(t)
	config := hookConfigs(1)
	config.Pre[0].Concurrency = new(2)
	var active, maxActive atomic.Int32
	slow := func(name string) Unit {
		return Unit{Name: name, Run: func(context.Context) (Outcome, error) {
			current := active.Add(1)
			for {
				seen := maxActive.Load()
				if current <= seen || maxActive.CompareAndSwap(seen, current) {
					break
				}
			}
			time.Sleep(30 * time.Millisecond)
			active.Add(-1)
			return allowOutcome(), nil
		}}
	}
	step := unitsStep{slow("a"), slow("b"), slow("c"), slow("d")}
	runner, err := NewRunner(config, time.Minute, buildSteps(step))
	g.Expect(err).ToNot(HaveOccurred())

	_, err = runner.Run(context.Background(), Input{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(maxActive.Load()).To(Equal(int32(2)))
}

func TestRunner_UnitRetriesAreIndependent(t *testing.T) {
	g := NewWithT(t)
	config := hookConfigs(1)
	config.Pre[0].Retries = new(1)
	var flaky atomic.Int32
	step := unitsStep{
		{Name: "linux/amd64", Run: func(context.Context) (Outcome, error) {
			if flaky.Add(1) == 1 {
				return Outcome{}, errors.New("temporary")
			}
			return allowOutcome(), nil
		}},
		verdictUnit("linux/arm64", allowOutcome(), nil),
	}
	runner, err := NewRunner(config, time.Minute, buildSteps(step))
	g.Expect(err).ToNot(HaveOccurred())

	result, err := runner.Run(context.Background(), Input{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(result.Steps[0].Units[0].Attempts).To(Equal(2))
	g.Expect(result.Steps[0].Units[1].Attempts).To(Equal(1))
	g.Expect(result.Steps[0].Attempts).To(Equal(3))
}

func TestRunner_SingleUnnamedUnitReportsNoUnits(t *testing.T) {
	g := NewWithT(t)
	runner, err := NewRunner(hookConfigs(1), time.Minute, buildSteps(StepFunc(
		func(context.Context, Input) (Outcome, error) { return allowOutcome(), nil },
	)))
	g.Expect(err).ToNot(HaveOccurred())

	result, err := runner.Run(context.Background(), Input{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(result.Steps[0].Units).To(BeEmpty())
}

func TestRunner_StepWithoutUnitsIsAnError(t *testing.T) {
	g := NewWithT(t)
	runner, err := NewRunner(hookConfigs(1), time.Minute, buildSteps(unitsStep{}))
	g.Expect(err).ToNot(HaveOccurred())

	_, err = runner.Run(context.Background(), Input{})
	g.Expect(err).To(MatchError(ContainSubstring("no work units")))
}

func logOutput(t *testing.T, config apiv1.ArtifactHooks, step Step, input Input) string {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	runner, err := NewRunner(config, time.Minute, buildSteps(step), WithLogger(logger))
	NewWithT(t).Expect(err).ToNot(HaveOccurred())
	_, _ = runner.Run(context.Background(), input)
	return buf.String()
}

func TestRunner_LogsNamedUnitsAndDeny(t *testing.T) {
	g := NewWithT(t)
	step := unitsStep{
		verdictUnit("linux/amd64", allowOutcome(), nil),
		verdictUnit("linux/arm64", Outcome{
			Verdict: apiv1.StepVerdictDeny,
			Reason:  "policy",
			Wizcli:  &apiv1.WizcliResult{ScanID: "scan-1", FailedPolicies: []string{"EOL", "CVE"}},
		}, nil),
	}

	out := logOutput(t, hookConfigs(1), step, Input{Source: "docker.io/library/alpine", Tag: "3.20"})

	g.Expect(out).To(ContainSubstring(`msg="hooks started"`))
	g.Expect(out).To(ContainSubstring("source=docker.io/library/alpine tag=3.20"))
	g.Expect(out).To(ContainSubstring(`msg="hook step started"`))
	g.Expect(out).To(ContainSubstring("step=step-0 provider=provider-0"))
	g.Expect(strings.Count(out, `msg="hook unit started"`)).To(Equal(2))
	g.Expect(out).To(ContainSubstring("unit=linux/arm64"))
	g.Expect(out).To(ContainSubstring("scanId=scan-1"))
	g.Expect(out).To(ContainSubstring("failedPolicies=EOL,CVE"))
	g.Expect(out).To(ContainSubstring(`msg="hook step finished"`))
	g.Expect(out).To(ContainSubstring(`msg="hook denied tag"`))
}

func TestRunner_LogsSingleUnitStepWithoutUnitLines(t *testing.T) {
	g := NewWithT(t)
	step := stepFunc(func(context.Context, Input) (Outcome, error) {
		return Outcome{Verdict: apiv1.StepVerdictAllow}, nil
	})

	out := logOutput(t, hookConfigs(1), step, Input{Tag: "1.0"})

	g.Expect(out).To(ContainSubstring(`msg="hook step finished"`))
	g.Expect(out).ToNot(ContainSubstring("hook unit"))
}

func TestRunner_LogsRetriesAndFailures(t *testing.T) {
	g := NewWithT(t)
	retries := 1
	config := hookConfigs(1)
	config.Pre[0].Retries = &retries
	step := unitsStep{verdictUnit("linux/amd64", Outcome{}, errors.New("transient"))}

	out := logOutput(t, config, step, Input{Tag: "1.0"})

	g.Expect(out).To(ContainSubstring(`msg="hook attempt failed; retrying"`))
	g.Expect(out).To(ContainSubstring(`msg="hook unit failed"`))
	g.Expect(out).To(ContainSubstring(`msg="hook step failed"`))
}

func TestRunner_LogsNothingWithoutLogger(t *testing.T) {
	g := NewWithT(t)
	runner, err := NewRunner(hookConfigs(1), time.Minute, buildSteps(unitsStep{verdictUnit("a", allowOutcome(), nil)}))
	g.Expect(err).ToNot(HaveOccurred())

	_, err = runner.Run(context.Background(), Input{})
	g.Expect(err).ToNot(HaveOccurred())
}

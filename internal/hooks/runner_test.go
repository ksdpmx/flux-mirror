// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
)

type stepFunc = StepFunc

func buildSteps(steps ...Step) map[string]Builder {
	builders := make(map[string]Builder, len(steps))
	for i, step := range steps {
		provider := fmt.Sprintf("provider-%d", i)
		captured := step
		builders[provider] = func(apiv1.HookStep) (Step, error) {
			return captured, nil
		}
	}
	return builders
}

func hookConfigs(n int) apiv1.ArtifactHooks {
	config := apiv1.ArtifactHooks{}
	for i := 0; i < n; i++ {
		config.Pre = append(config.Pre, apiv1.HookStep{
			Name:     fmt.Sprintf("step-%d", i),
			Provider: fmt.Sprintf("provider-%d", i),
		})
	}
	return config
}

func TestRunner_OrderedAllowAndDeny(t *testing.T) {
	g := NewWithT(t)
	var ran atomic.Int32
	steps := []Step{
		stepFunc(func(context.Context, Input) (Outcome, error) {
			ran.Add(1)
			return Outcome{Verdict: apiv1.StepVerdictAllow}, nil
		}),
		stepFunc(func(context.Context, Input) (Outcome, error) {
			ran.Add(1)
			return Outcome{Verdict: apiv1.StepVerdictDeny, Reason: "policy"}, nil
		}),
		stepFunc(func(context.Context, Input) (Outcome, error) {
			ran.Add(1)
			return Outcome{Verdict: apiv1.StepVerdictAllow}, nil
		}),
	}
	runner, err := NewRunner(hookConfigs(len(steps)), time.Minute, buildSteps(steps...))
	g.Expect(err).ToNot(HaveOccurred())

	result, err := runner.Run(context.Background(), Input{Digest: "sha256:abc"})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(ran.Load()).To(Equal(int32(2)))
	g.Expect(result.Terminal).To(Equal(&Terminal{
		Status: apiv1.StatusBlocked,
		Reason: "step-1",
		Digest: "sha256:abc",
	}))
	g.Expect(result.Steps).To(HaveLen(2))
	g.Expect(result.Steps[0].Verdict).To(Equal(apiv1.StepVerdictAllow))
	g.Expect(result.Steps[1].Reason).To(Equal("policy"))
}

func TestRunner_SkipsOnSkipVerdict(t *testing.T) {
	g := NewWithT(t)
	runner, err := NewRunner(hookConfigs(1), time.Minute, buildSteps(stepFunc(
		func(context.Context, Input) (Outcome, error) {
			return Outcome{Verdict: apiv1.StepVerdictSkip, Reason: "deferred"}, nil
		},
	)))
	g.Expect(err).ToNot(HaveOccurred())

	result, err := runner.Run(context.Background(), Input{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(result.Terminal).To(Equal(&Terminal{Status: apiv1.StatusSkipped, Reason: "deferred"}))
}

func TestRunner_RetriesErrorsAndWarns(t *testing.T) {
	g := NewWithT(t)
	config := hookConfigs(2)
	config.Pre[0].Retries = new(1)
	config.Pre[0].OnFailure = apiv1.HookFailureWarn
	var attempts atomic.Int32
	first := stepFunc(func(context.Context, Input) (Outcome, error) {
		attempts.Add(1)
		return Outcome{}, errors.New("temporary")
	})
	second := stepFunc(func(context.Context, Input) (Outcome, error) {
		return Outcome{Verdict: apiv1.StepVerdictAllow}, nil
	})
	runner, err := NewRunner(config, time.Second, buildSteps(first, second))
	g.Expect(err).ToNot(HaveOccurred())

	result, err := runner.Run(context.Background(), Input{})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(attempts.Load()).To(Equal(int32(2)))
	g.Expect(result.Steps).To(HaveLen(2))
	g.Expect(result.Steps[0].Verdict).To(Equal(apiv1.StepVerdictError))
	g.Expect(result.Steps[0].Error).To(ContainSubstring("temporary"))
	g.Expect(result.Steps[0].Attempts).To(Equal(2))
	g.Expect(result.Steps[1].Verdict).To(Equal(apiv1.StepVerdictAllow))
}

func TestRunner_BlocksOnExhaustedErrorByDefault(t *testing.T) {
	g := NewWithT(t)
	runner, err := NewRunner(hookConfigs(1), time.Second, buildSteps(stepFunc(
		func(context.Context, Input) (Outcome, error) {
			return Outcome{}, Permanent(errors.New("invalid policy"))
		},
	)))
	g.Expect(err).ToNot(HaveOccurred())

	result, err := runner.Run(context.Background(), Input{})
	g.Expect(err).To(MatchError(ContainSubstring("hook step-0: invalid policy")))
	g.Expect(result.Steps).To(HaveLen(1))
	g.Expect(result.Steps[0].Verdict).To(Equal(apiv1.StepVerdictError))
	g.Expect(result.Steps[0].Attempts).To(Equal(1))
}

func TestRunner_EnforcesConcurrency(t *testing.T) {
	g := NewWithT(t)
	concurrency := 1
	config := hookConfigs(1)
	config.Pre[0].Concurrency = &concurrency
	var active, maxActive atomic.Int32
	step := stepFunc(func(context.Context, Input) (Outcome, error) {
		current := active.Add(1)
		for {
			max := maxActive.Load()
			if current <= max || maxActive.CompareAndSwap(max, current) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		active.Add(-1)
		return Outcome{Verdict: apiv1.StepVerdictAllow}, nil
	})
	runner, err := NewRunner(config, time.Second, buildSteps(step))
	g.Expect(err).ToNot(HaveOccurred())

	var done atomic.Int32
	for i := 0; i < 4; i++ {
		go func() {
			_, _ = runner.Run(context.Background(), Input{})
			done.Add(1)
		}()
	}
	deadline := time.After(time.Second)
	for done.Load() < 4 {
		select {
		case <-deadline:
			t.Fatal("hook runs did not complete")
		case <-time.After(time.Millisecond):
		}
	}
	g.Expect(maxActive.Load()).To(Equal(int32(1)))
}

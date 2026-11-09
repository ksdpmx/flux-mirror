// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
)

// Input identifies one tag and the digest resolved before the hook chain runs.
type Input struct {
	Source      string
	Tag         string
	Destination string
	Digest      string
}

// Outcome is the policy decision and typed provider result from one step.
type Outcome struct {
	Verdict apiv1.StepVerdict
	Reason  string
	Cosign  *apiv1.Verification
}

// Step evaluates one tag.
type Step interface {
	Run(context.Context, Input) (Outcome, error)
}

// Builder constructs a step from its validated configuration.
type Builder func(apiv1.HookStep) (Step, error)

// Terminal is an outcome that stops the mirror pipeline before the copy.
type Terminal struct {
	Status apiv1.Status
	Reason string
	Digest string
}

// Result contains the hook results and an optional terminal tag outcome.
type Result struct {
	Terminal *Terminal
	Steps    []apiv1.StepResult
}

type stepRunner struct {
	config    apiv1.HookStep
	step      Step
	timeout   time.Duration
	retries   int
	onFailure string
	semaphore chan struct{}
}

// Runner runs an ordered chain of hook steps.
type Runner struct {
	steps []stepRunner
}

// NewRunner builds the configured providers once and creates per-step
// concurrency limits shared by all tags in the entry.
func NewRunner(config apiv1.ArtifactHooks, defaultTimeout time.Duration, builders map[string]Builder) (*Runner, error) {
	if defaultTimeout <= 0 {
		return nil, fmt.Errorf("default hook timeout must be greater than 0")
	}
	r := &Runner{steps: make([]stepRunner, 0, len(config.Pre))}
	for i, cfg := range config.Pre {
		builder, ok := builders[cfg.Provider]
		if !ok {
			return nil, fmt.Errorf("hooks.pre[%d]: no builder registered for provider %q", i, cfg.Provider)
		}
		step, err := builder(cfg)
		if err != nil {
			return nil, fmt.Errorf("build hook %q: %w", cfg.Name, err)
		}
		if step == nil {
			return nil, fmt.Errorf("build hook %q: provider returned no step", cfg.Name)
		}
		timeout := defaultTimeout
		if cfg.Timeout != nil {
			timeout = cfg.Timeout.Duration
		}
		concurrency := 1
		if cfg.Concurrency != nil {
			concurrency = *cfg.Concurrency
		}
		retries := 0
		if cfg.Retries != nil {
			retries = *cfg.Retries
		}
		onFailure := cfg.OnFailure
		if onFailure == "" {
			onFailure = apiv1.HookFailureBlock
		}
		r.steps = append(r.steps, stepRunner{
			config:    cfg,
			step:      step,
			timeout:   timeout,
			retries:   retries,
			onFailure: onFailure,
			semaphore: make(chan struct{}, concurrency),
		})
	}
	return r, nil
}

// Run executes each step in order and stops on a deny or skip verdict.
// Infrastructure errors are retried; onFailure decides whether an exhausted
// error blocks the tag or allows later steps to run.
func (r *Runner) Run(ctx context.Context, input Input) (Result, error) {
	result := Result{Steps: make([]apiv1.StepResult, 0, len(r.steps))}
	for i := range r.steps {
		step := &r.steps[i]
		outcome, stepResult, err := step.run(ctx, input)
		if err != nil {
			stepResult.Verdict = apiv1.StepVerdictError
			stepResult.Error = err.Error()
			result.Steps = append(result.Steps, stepResult)
			if step.onFailure == apiv1.HookFailureBlock {
				return result, fmt.Errorf("hook %s: %w", step.config.Name, err)
			}
			continue
		}

		stepResult.Verdict = outcome.Verdict
		stepResult.Reason = outcome.Reason
		stepResult.Cosign = outcome.Cosign
		result.Steps = append(result.Steps, stepResult)

		switch outcome.Verdict {
		case apiv1.StepVerdictAllow:
			continue
		case apiv1.StepVerdictDeny:
			result.Terminal = &Terminal{
				Status: apiv1.StatusBlocked,
				Reason: step.config.Name,
				Digest: input.Digest,
			}
			return result, nil
		case apiv1.StepVerdictSkip:
			result.Terminal = &Terminal{
				Status: apiv1.StatusSkipped,
				Reason: outcome.Reason,
				Digest: input.Digest,
			}
			return result, nil
		default:
			err := fmt.Errorf("hook %s returned invalid verdict %q", step.config.Name, outcome.Verdict)
			if step.onFailure == apiv1.HookFailureBlock {
				return result, err
			}
			last := &result.Steps[len(result.Steps)-1]
			last.Verdict = apiv1.StepVerdictError
			last.Error = err.Error()
		}
	}
	return result, nil
}

func (s *stepRunner) run(parent context.Context, input Input) (Outcome, apiv1.StepResult, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(parent, s.timeout)
	defer cancel()

	stepResult := apiv1.StepResult{
		Name:     s.config.Name,
		Provider: s.config.Provider,
	}
	var lastErr error
	for attempt := 0; attempt <= s.retries; attempt++ {
		select {
		case s.semaphore <- struct{}{}:
		case <-ctx.Done():
			stepResult.Duration = time.Since(start).String()
			return Outcome{}, stepResult, ctx.Err()
		}
		stepResult.Attempts++
		outcome, err := s.step.Run(ctx, input)
		<-s.semaphore
		if err == nil {
			if !validVerdict(outcome.Verdict) {
				err = Permanent(fmt.Errorf("invalid verdict %q", outcome.Verdict))
			} else if outcome.Verdict == apiv1.StepVerdictSkip && strings.TrimSpace(outcome.Reason) == "" {
				err = Permanent(fmt.Errorf("skip verdict requires a reason"))
			} else {
				stepResult.Duration = time.Since(start).String()
				return outcome, stepResult, nil
			}
		}
		lastErr = err
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || isPermanent(err) {
			break
		}
		if attempt == s.retries {
			break
		}
		backoff := retryBackoff(attempt)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			lastErr = ctx.Err()
			attempt = s.retries
		}
	}
	stepResult.Duration = time.Since(start).String()
	if lastErr == nil {
		lastErr = ctx.Err()
	}
	return Outcome{}, stepResult, lastErr
}

func validVerdict(v apiv1.StepVerdict) bool {
	switch v {
	case apiv1.StepVerdictAllow, apiv1.StepVerdictDeny, apiv1.StepVerdictSkip:
		return true
	default:
		return false
	}
}

func retryBackoff(attempt int) time.Duration {
	backoff := 200 * time.Millisecond
	for i := 0; i < attempt && backoff < 5*time.Second; i++ {
		backoff *= 2
	}
	if backoff > 5*time.Second {
		return 5 * time.Second
	}
	return backoff
}

type permanentError struct {
	err error
}

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }

// Permanent marks an error that should not be retried.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return permanentError{err: err}
}

func isPermanent(err error) bool {
	var target permanentError
	return errors.As(err, &target)
}

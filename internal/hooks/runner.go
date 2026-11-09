// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
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

// Outcome is the policy decision and typed provider result from one unit.
type Outcome struct {
	Verdict apiv1.StepVerdict
	Reason  string
	Cosign  *apiv1.Verification
	Wizcli  *apiv1.WizcliResult
}

// Unit is one independently scheduled and retried piece of a step's work for
// a tag, such as the scan of one platform. The step concurrency limit counts
// units, and retries apply to each unit separately. A unit must not wait for
// another unit while holding its slot.
type Unit struct {
	// Name identifies the unit in the report, for example the platform. A
	// step with a single unnamed unit reports no per-unit results.
	Name string
	Run  func(context.Context) (Outcome, error)
}

// Step splits its work for one tag into units. Units runs before any unit is
// scheduled, so it should not do slow work.
type Step interface {
	Units(context.Context, Input) ([]Unit, error)
}

// StepFunc adapts a function that evaluates a tag as a single unit.
type StepFunc func(context.Context, Input) (Outcome, error)

// Units implements Step.
func (f StepFunc) Units(_ context.Context, input Input) ([]Unit, error) {
	return []Unit{{Run: func(ctx context.Context) (Outcome, error) { return f(ctx, input) }}}, nil
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

type unitRun struct {
	outcome  Outcome
	err      error
	attempts int
	duration time.Duration
}

func (s *stepRunner) run(parent context.Context, input Input) (Outcome, apiv1.StepResult, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(parent, s.timeout)
	defer cancel()

	stepResult := apiv1.StepResult{
		Name:     s.config.Name,
		Provider: s.config.Provider,
	}
	units, err := s.step.Units(ctx, input)
	if err == nil && len(units) == 0 {
		err = Permanent(errors.New("step returned no work units"))
	}
	if err != nil {
		stepResult.Duration = time.Since(start).String()
		return Outcome{}, stepResult, err
	}

	runs := make([]unitRun, len(units))
	var wg sync.WaitGroup
	for i := range units {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runs[i] = s.runUnit(ctx, units[i])
		}()
	}
	wg.Wait()

	for _, run := range runs {
		stepResult.Attempts += run.attempts
	}
	if hasNamedUnits(units) {
		stepResult.Units = unitResults(units, runs)
	}
	stepResult.Duration = time.Since(start).String()
	outcome, err := aggregate(units, runs)
	return outcome, stepResult, err
}

// runUnit runs one unit with the step's retries. Every attempt takes a
// concurrency slot again, so a unit waiting to retry does not hold one.
func (s *stepRunner) runUnit(ctx context.Context, unit Unit) unitRun {
	start := time.Now()
	var run unitRun
	var lastErr error
attempts:
	for attempt := 0; attempt <= s.retries; attempt++ {
		outcome, ran, err := s.attempt(ctx, unit)
		if ran {
			run.attempts++
		}
		if err == nil {
			run.outcome = outcome
			run.duration = time.Since(start)
			return run
		}
		lastErr = err
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || isPermanent(err) {
			break
		}
		if attempt == s.retries {
			break
		}
		select {
		case <-time.After(retryBackoff(attempt)):
		case <-ctx.Done():
			lastErr = ctx.Err()
			break attempts
		}
	}
	run.err = lastErr
	run.duration = time.Since(start)
	return run
}

func (s *stepRunner) attempt(ctx context.Context, unit Unit) (Outcome, bool, error) {
	select {
	case s.semaphore <- struct{}{}:
	case <-ctx.Done():
		return Outcome{}, false, ctx.Err()
	}
	defer func() { <-s.semaphore }()

	outcome, err := unit.Run(ctx)
	if err != nil {
		return Outcome{}, true, err
	}
	if !validVerdict(outcome.Verdict) {
		return Outcome{}, true, Permanent(fmt.Errorf("invalid verdict %q", outcome.Verdict))
	}
	if outcome.Verdict == apiv1.StepVerdictSkip && strings.TrimSpace(outcome.Reason) == "" {
		return Outcome{}, true, Permanent(errors.New("skip verdict requires a reason"))
	}
	return outcome, true, nil
}

func hasNamedUnits(units []Unit) bool {
	for _, unit := range units {
		if unit.Name != "" {
			return true
		}
	}
	return false
}

func unitLabel(units []Unit, i int) string {
	if units[i].Name != "" {
		return units[i].Name
	}
	return fmt.Sprintf("unit %d", i+1)
}

func unitResults(units []Unit, runs []unitRun) []apiv1.UnitResult {
	results := make([]apiv1.UnitResult, len(units))
	for i, run := range runs {
		results[i] = apiv1.UnitResult{
			Name:     unitLabel(units, i),
			Attempts: run.attempts,
			Duration: run.duration.String(),
		}
		if run.err != nil {
			results[i].Verdict = apiv1.StepVerdictError
			results[i].Error = run.err.Error()
			continue
		}
		results[i].Verdict = run.outcome.Verdict
		results[i].Reason = run.outcome.Reason
		results[i].Wizcli = run.outcome.Wizcli
	}
	return results
}

// aggregate combines the units of one step: a deny wins, then an error, then a
// skip; the step allows only when every unit allows.
func aggregate(units []Unit, runs []unitRun) (Outcome, error) {
	if len(units) == 1 && units[0].Name == "" {
		if runs[0].err != nil {
			return Outcome{}, runs[0].err
		}
		return runs[0].outcome, nil
	}

	var denied []string
	var errs []error
	skipReason := ""
	for i, run := range runs {
		switch {
		case run.err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", unitLabel(units, i), run.err))
		case run.outcome.Verdict == apiv1.StepVerdictDeny:
			denied = append(denied, unitLabel(units, i)+": "+run.outcome.Reason)
		case run.outcome.Verdict == apiv1.StepVerdictSkip && skipReason == "":
			skipReason = run.outcome.Reason
		}
	}
	switch {
	case len(denied) > 0:
		return Outcome{Verdict: apiv1.StepVerdictDeny, Reason: strings.Join(denied, "; ")}, nil
	case len(errs) > 0:
		return Outcome{}, joinErrors(errs)
	case skipReason != "":
		return Outcome{Verdict: apiv1.StepVerdictSkip, Reason: skipReason}, nil
	default:
		return Outcome{Verdict: apiv1.StepVerdictAllow}, nil
	}
}

// joinedError reports several unit errors on one line while keeping them
// available to errors.Is and errors.As.
type joinedError []error

func (e joinedError) Error() string {
	messages := make([]string, len(e))
	for i, err := range e {
		messages[i] = err.Error()
	}
	return strings.Join(messages, "; ")
}

func (e joinedError) Unwrap() []error { return e }

func joinErrors(errs []error) error {
	if len(errs) == 1 {
		return errs[0]
	}
	return joinedError(errs)
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

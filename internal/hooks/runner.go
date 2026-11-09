// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
	onDeny    string
	onError   string
	semaphore chan struct{}
}

// Runner runs an ordered chain of hook steps.
type Runner struct {
	steps  []stepRunner
	logger *slog.Logger
}

// Option configures a Runner.
type Option func(*Runner)

// WithLogger sets the logger for step and unit progress. Without it the
// runner logs nothing.
func WithLogger(logger *slog.Logger) Option {
	return func(r *Runner) {
		if logger != nil {
			r.logger = logger
		}
	}
}

// NewRunner builds the configured providers once and creates per-step
// concurrency limits shared by all tags in the entry.
func NewRunner(config apiv1.ArtifactHooks, defaultTimeout time.Duration, builders map[string]Builder, opts ...Option) (*Runner, error) {
	if defaultTimeout <= 0 {
		return nil, fmt.Errorf("default hook timeout must be greater than 0")
	}
	r := &Runner{
		steps:  make([]stepRunner, 0, len(config.Pre)),
		logger: slog.New(slog.DiscardHandler),
	}
	for _, opt := range opts {
		opt(r)
	}
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
		onDeny := cfg.OnDeny
		if onDeny == "" {
			onDeny = apiv1.HookActionBlock
		}
		onError := cfg.OnError
		if onError == "" {
			onError = apiv1.HookActionBlock
		}
		r.steps = append(r.steps, stepRunner{
			config:    cfg,
			step:      step,
			timeout:   timeout,
			retries:   retries,
			onDeny:    onDeny,
			onError:   onError,
			semaphore: make(chan struct{}, concurrency),
		})
	}
	return r, nil
}

// Run executes each step in order and stops on a deny or skip verdict.
// Infrastructure errors are retried; onError decides whether an exhausted
// error blocks the tag or allows later steps to run, and onDeny does the same
// for a policy denial.
func (r *Runner) Run(ctx context.Context, input Input) (Result, error) {
	log := r.logger.With("source", input.Source, "tag", input.Tag)
	log.Info("hooks started", "steps", len(r.steps))
	result := Result{Steps: make([]apiv1.StepResult, 0, len(r.steps))}
	for i := range r.steps {
		step := &r.steps[i]
		outcome, stepResult, err := step.run(ctx, input, log)
		if err != nil {
			stepResult.Verdict = apiv1.StepVerdictError
			stepResult.Error = err.Error()
			if step.onError == apiv1.HookActionBlock {
				result.Steps = append(result.Steps, stepResult)
				return result, fmt.Errorf("hook %s: %w", step.config.Name, err)
			}
			stepResult.Continued = true
			result.Steps = append(result.Steps, stepResult)
			log.Warn("hook failed; continuing because onError is warn", "step", step.config.Name)
			continue
		}

		stepResult.Verdict = outcome.Verdict
		stepResult.Reason = outcome.Reason
		stepResult.Cosign = outcome.Cosign
		result.Steps = append(result.Steps, stepResult)
		last := &result.Steps[len(result.Steps)-1]

		switch outcome.Verdict {
		case apiv1.StepVerdictAllow:
			continue
		case apiv1.StepVerdictDeny:
			if step.onDeny == apiv1.HookActionWarn {
				last.Continued = true
				log.Warn("hook denied tag; continuing because onDeny is warn",
					"step", step.config.Name, "reason", outcome.Reason)
				continue
			}
			log.Info("hook denied tag", "step", step.config.Name, "reason", outcome.Reason)
			result.Terminal = &Terminal{
				Status: apiv1.StatusBlocked,
				Reason: step.config.Name,
				Digest: input.Digest,
			}
			return result, nil
		case apiv1.StepVerdictSkip:
			log.Info("hook skipped tag", "step", step.config.Name, "reason", outcome.Reason)
			result.Terminal = &Terminal{
				Status: apiv1.StatusSkipped,
				Reason: outcome.Reason,
				Digest: input.Digest,
			}
			return result, nil
		default:
			err := fmt.Errorf("hook %s returned invalid verdict %q", step.config.Name, outcome.Verdict)
			if step.onError == apiv1.HookActionBlock {
				return result, err
			}
			last.Verdict = apiv1.StepVerdictError
			last.Error = err.Error()
			last.Continued = true
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

func (s *stepRunner) run(parent context.Context, input Input, log *slog.Logger) (Outcome, apiv1.StepResult, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(parent, s.timeout)
	defer cancel()
	log = log.With("step", s.config.Name, "provider", s.config.Provider)

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
		log.Warn("hook step failed", "error", err, "elapsed", time.Since(start).Round(time.Millisecond))
		return Outcome{}, stepResult, err
	}
	named := hasNamedUnits(units)
	log.Info("hook step started", "units", len(units), "concurrency", cap(s.semaphore), "timeout", s.timeout)

	runs := make([]unitRun, len(units))
	var wg sync.WaitGroup
	for i := range units {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unitLog := log
			if named {
				unitLog = log.With("unit", unitLabel(units, i))
			}
			runs[i] = s.runUnit(ctx, units[i], unitLog, named)
		}()
	}
	wg.Wait()

	for _, run := range runs {
		stepResult.Attempts += run.attempts
	}
	if named {
		stepResult.Units = unitResults(units, runs)
	}
	stepResult.Duration = time.Since(start).String()
	outcome, err := aggregate(units, runs)
	elapsed := time.Since(start).Round(time.Millisecond)
	if err != nil {
		log.Warn("hook step failed", "error", err, "elapsed", elapsed)
	} else {
		log.Info("hook step finished", "verdict", outcome.Verdict, "elapsed", elapsed)
	}
	return outcome, stepResult, err
}

// runUnit runs one unit with the step's retries. Every attempt takes a
// concurrency slot again, so a unit waiting to retry does not hold one. The
// logger already carries the unit name; named units get their own start and
// finish lines because their work is slow and independent.
func (s *stepRunner) runUnit(ctx context.Context, unit Unit, log *slog.Logger, named bool) unitRun {
	start := time.Now()
	var run unitRun
	var lastErr error
attempts:
	for attempt := 0; attempt <= s.retries; attempt++ {
		outcome, ran, err := s.attempt(ctx, unit, log, named, attempt+1)
		if ran {
			run.attempts++
		}
		if err == nil {
			run.outcome = outcome
			run.duration = time.Since(start)
			logUnitFinished(log, named, run)
			return run
		}
		lastErr = err
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || isPermanent(err) {
			break
		}
		if attempt == s.retries {
			break
		}
		backoff := retryBackoff(attempt)
		log.Warn("hook attempt failed; retrying", "attempt", attempt+1, "error", err, "backoff", backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			lastErr = ctx.Err()
			break attempts
		}
	}
	run.err = lastErr
	run.duration = time.Since(start)
	logUnitFinished(log, named, run)
	return run
}

func (s *stepRunner) attempt(ctx context.Context, unit Unit, log *slog.Logger, named bool, number int) (Outcome, bool, error) {
	select {
	case s.semaphore <- struct{}{}:
	case <-ctx.Done():
		return Outcome{}, false, ctx.Err()
	}
	defer func() { <-s.semaphore }()

	if named {
		log.Info("hook unit started", "attempt", number)
	}
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

// logUnitFinished logs the result of a named unit. Only fields that identify
// the decision are logged: the verdict, the policy names behind a deny, and
// the scan identifier; never the provider's raw report.
func logUnitFinished(log *slog.Logger, named bool, run unitRun) {
	if !named {
		return
	}
	attrs := []any{"attempts", run.attempts, "elapsed", run.duration.Round(time.Millisecond)}
	if run.err != nil {
		log.Warn("hook unit failed", append(attrs, "error", run.err)...)
		return
	}
	attrs = append(attrs, "verdict", run.outcome.Verdict)
	if w := run.outcome.Wizcli; w != nil {
		if w.ScanID != "" {
			attrs = append(attrs, "scanId", w.ScanID)
		}
		if len(w.FailedPolicies) > 0 {
			attrs = append(attrs, "failedPolicies", strings.Join(w.FailedPolicies, ","))
		}
	} else if run.outcome.Reason != "" {
		attrs = append(attrs, "reason", run.outcome.Reason)
	}
	log.Info("hook unit finished", attrs...)
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
		results[i].Cosign = run.outcome.Cosign
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

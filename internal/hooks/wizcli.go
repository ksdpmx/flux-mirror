// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
)

const (
	wizcliDefaultBinary = "wizcli"

	// wizcliExitPolicyFailure is the exit code wizcli uses when a blocking
	// policy rejects the scan. Every other non-zero code is a scan error.
	wizcliExitPolicyFailure = 4

	// wizcliExitNotAuthenticated is the exit code wizcli returned, in a local
	// check, when it has no credentials. Retrying cannot help.
	wizcliExitNotAuthenticated = 3

	// wizcliTimeoutMargin is left between the wizcli --timeout and the step
	// deadline, so wizcli can end and report before flux-mirror kills it.
	wizcliTimeoutMargin = 10 * time.Second

	// wizcliOutputTail is how much of the wizcli output an error keeps.
	wizcliOutputTail = 512
)

// ImageSaver writes one platform of an image to a tarball and returns the
// manifest digest of the saved platform image.
type ImageSaver interface {
	SaveImage(ctx context.Context, ref, platform, path string) (string, error)
}

// WizcliBuilder creates the Wiz CLI scan provider. Each configured platform is
// one work unit: its image is saved as a tarball (wizcli cannot read a registry
// without a Docker daemon) and scanned with wizcli. Credentials are never part
// of the config: wizcli authenticates itself, from WIZ_CLIENT_ID and
// WIZ_CLIENT_SECRET or from an existing wizcli login, and fails right away
// when it has neither. No Wiz project is passed, so wizcli applies the scan to
// all projects of the service account.
func WizcliBuilder(saver ImageSaver) Builder {
	return func(config apiv1.HookStep) (Step, error) {
		if saver == nil {
			return nil, errors.New("wizcli image saver is required")
		}
		if config.Wizcli == nil {
			return nil, errors.New("wizcli configuration is required")
		}
		binary := config.Wizcli.Binary
		if binary == "" {
			binary = wizcliDefaultBinary
		}
		path, err := exec.LookPath(binary)
		if err != nil {
			return nil, fmt.Errorf("find wizcli binary: %w", err)
		}
		return wizcliStep{
			saver:     saver,
			binary:    path,
			platforms: config.Wizcli.Platforms,
			policies:  config.Wizcli.Policies,
			publish:   config.Wizcli.Publish,
		}, nil
	}
}

type wizcliStep struct {
	saver     ImageSaver
	binary    string
	platforms []string
	policies  []string
	publish   bool
}

// Units implements Step with one unit per platform.
func (s wizcliStep) Units(_ context.Context, input Input) ([]Unit, error) {
	units := make([]Unit, len(s.platforms))
	for i, platform := range s.platforms {
		units[i] = Unit{
			Name: platform,
			Run: func(ctx context.Context) (Outcome, error) {
				return s.scan(ctx, input, platform)
			},
		}
	}
	return units, nil
}

func (s wizcliStep) scan(ctx context.Context, input Input, platform string) (Outcome, error) {
	dir, err := os.MkdirTemp("", "flux-mirror-wizcli-")
	if err != nil {
		return Outcome{}, Permanent(fmt.Errorf("create scan directory: %w", err))
	}
	defer os.RemoveAll(dir)
	imagePath := filepath.Join(dir, "image.tar")
	reportPath := filepath.Join(dir, "scan.json")

	digest, err := s.saver.SaveImage(ctx, input.Source+"@"+input.Digest, platform, imagePath)
	if err != nil {
		if strings.Contains(err.Error(), "no child with platform") {
			return Outcome{}, Permanent(fmt.Errorf("platform %s is not in %s@%s: %w", platform, input.Source, input.Digest, err))
		}
		return Outcome{}, err
	}

	cmd := exec.CommandContext(ctx, s.binary, s.arguments(ctx, imagePath, reportPath)...)
	var output tailBuffer
	output.limit = wizcliOutputTail
	cmd.Stdout = &output
	cmd.Stderr = &output
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return Outcome{}, ctx.Err()
	}
	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return Outcome{}, fmt.Errorf("run wizcli: %w", runErr)
		}
		exitCode = exitErr.ExitCode()
	}
	return interpretWizcli(exitCode, reportPath, digest, output.String(), s.publish)
}

func (s wizcliStep) arguments(ctx context.Context, imagePath, reportPath string) []string {
	args := []string{
		"scan", "container-image", imagePath,
		"--no-color", "--no-style", "--no-telemetry",
		"--json-output-file", reportPath,
	}
	if !s.publish {
		args = append(args, "--no-publish")
	}
	if len(s.policies) > 0 {
		args = append(args, "--policies", strings.Join(s.policies, ","))
	}
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline) - wizcliTimeoutMargin; remaining > wizcliTimeoutMargin {
			args = append(args, "--timeout", remaining.Round(time.Second).String())
		}
	}
	return args
}

// wizcliScan is the part of the wizcli JSON report the provider reads. The
// document also names the user who ran the scan, so nothing else is kept.
type wizcliScan struct {
	ID        string `json:"id"`
	ReportURL string `json:"reportUrl"`
	Status    struct {
		State   string `json:"state"`
		Verdict string `json:"verdict"`
	} `json:"status"`
	Result struct {
		FailedPolicyMatches []struct {
			Policy struct {
				Name string `json:"name"`
			} `json:"policy"`
		} `json:"failedPolicyMatches"`
	} `json:"result"`
}

func readWizcliScan(path string) (*wizcliScan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var scan wizcliScan
	if err := json.Unmarshal(data, &scan); err != nil {
		return nil, fmt.Errorf("parse wizcli report: %w", err)
	}
	return &scan, nil
}

// interpretWizcli maps a finished scan to an outcome. It fails closed: a
// policy failure by exit code or by report verdict denies the image, and a
// clean exit without a usable successful report is an error, not an allow.
func interpretWizcli(exitCode int, reportPath, digest, output string, publish bool) (Outcome, error) {
	scan, scanErr := readWizcliScan(reportPath)
	result := &apiv1.WizcliResult{Digest: digest}
	if scan != nil {
		result.ScanID = scan.ID
		result.Verdict = scan.Status.Verdict
		if publish {
			u, err := url.Parse(scan.ReportURL)
			if err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil &&
				!strings.ContainsAny(scan.ReportURL, "\r\n\t") {
				result.ReportURL = scan.ReportURL
			}
		}
		seen := map[string]struct{}{}
		for _, match := range scan.Result.FailedPolicyMatches {
			name := match.Policy.Name
			if _, ok := seen[name]; name == "" || ok {
				continue
			}
			seen[name] = struct{}{}
			result.FailedPolicies = append(result.FailedPolicies, name)
		}
	}

	failed := exitCode == wizcliExitPolicyFailure || (scan != nil && strings.HasPrefix(scan.Status.Verdict, "FAILED"))
	switch {
	case failed:
		reason := "policy failure"
		if len(result.FailedPolicies) > 0 {
			reason = "failed policies: " + strings.Join(result.FailedPolicies, ", ")
		}
		return Outcome{Verdict: apiv1.StepVerdictDeny, Reason: reason, Wizcli: result}, nil
	case exitCode == wizcliExitNotAuthenticated:
		return Outcome{}, Permanent(fmt.Errorf("wizcli is not authenticated (exit code %d): %s",
			exitCode, strings.TrimSpace(output)))
	case exitCode != 0:
		return Outcome{}, fmt.Errorf("wizcli exited with code %d: %s", exitCode, strings.TrimSpace(output))
	case scan == nil:
		return Outcome{}, fmt.Errorf("wizcli returned no usable report: %w", scanErr)
	case scan.Status.State != "SUCCESS":
		return Outcome{}, fmt.Errorf("wizcli report state is %q, want SUCCESS", scan.Status.State)
	}
	return Outcome{Verdict: apiv1.StepVerdictAllow, Wizcli: result}, nil
}

// tailBuffer keeps the last limit bytes written to it, with line breaks
// flattened so the text fits in a one-line error.
type tailBuffer struct {
	limit int
	data  []byte
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	if len(b.data) > b.limit {
		b.data = b.data[len(b.data)-b.limit:]
	}
	return len(p), nil
}

func (b *tailBuffer) String() string {
	return string(bytes.Join(bytes.Fields(b.data), []byte(" ")))
}

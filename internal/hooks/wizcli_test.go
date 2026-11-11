// Copyright 2026 The Flux Authors
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	apiv1 "github.com/fluxcd/flux-mirror/api/v1beta2"
)

// fakeWizcliScript stands in for wizcli. It records its arguments, checks that
// the image tarball exists when it runs, and decides the outcome from the
// tarball content, which the fake saver sets per platform.
const fakeWizcliScript = `#!/bin/sh
echo "$@" >> "$FAKE_WIZCLI_LOG"
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--json-output-file" ]; then out="$arg"; fi
  prev="$arg"
done
image="$3"
if [ ! -f "$image" ]; then echo "image tarball is missing" >&2; exit 1; fi
case "$(cat "$image")" in
  *fail-policy*)
    cat > "$out" <<EOF
{"id":"scan-fail","reportUrl":"https://app.wiz.io/reports/scan-fail","status":{"state":"SUCCESS","verdict":"FAILED_BY_POLICY"},"createdBy":{"name":"someone"},"result":{"failedPolicyMatches":[{"policy":{"name":"Block End of Life"}},{"policy":{"name":"Block End of Life"}}]}}
EOF
    exit 4 ;;
  *scan-error*)
    echo "boom: something broke" >&2
    exit 1 ;;
  *)
    cat > "$out" <<EOF
{"id":"scan-pass","reportUrl":"https://app.wiz.io/reports/scan-pass","status":{"state":"SUCCESS","verdict":"PASSED_BY_POLICY"},"createdBy":{"name":"someone"},"result":{"failedPolicyMatches":null}}
EOF
    exit 0 ;;
esac
`

type fakeSaver struct {
	content map[string]string
	err     error
	refs    []string
}

func (s *fakeSaver) SaveImage(_ context.Context, ref, platform, path string) (string, error) {
	s.refs = append(s.refs, ref)
	if s.err != nil {
		return "", s.err
	}
	content, ok := s.content[platform]
	if !ok {
		content = "pass"
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", err
	}
	return "sha256:" + strings.ReplaceAll(platform, "/", "-"), nil
}

type fakeWizcli struct {
	binary string
	log    string
}

func newFakeWizcli(t *testing.T) fakeWizcli {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "wizcli")
	if err := os.WriteFile(binary, []byte(fakeWizcliScript), 0o700); err != nil {
		t.Fatalf("write fake wizcli: %s", err)
	}
	log := filepath.Join(dir, "calls.log")
	t.Setenv("FAKE_WIZCLI_LOG", log)
	t.Setenv("WIZ_CLIENT_ID", "client-id")
	t.Setenv("WIZ_CLIENT_SECRET", "client-secret")
	return fakeWizcli{binary: binary, log: log}
}

func (f fakeWizcli) calls(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatalf("read fake wizcli log: %s", err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func wizcliRunner(t *testing.T, fake fakeWizcli, saver ImageSaver, mutate func(*apiv1.HookStep)) *Runner {
	t.Helper()
	step := apiv1.HookStep{
		Name:     "vuln-scan",
		Provider: apiv1.HookProviderWizcli,
		Wizcli: &apiv1.WizcliHookConfig{
			Platforms: []string{"linux/amd64", "linux/arm64"},
			Binary:    fake.binary,
		},
	}
	if mutate != nil {
		mutate(&step)
	}
	runner, err := NewRunner(apiv1.ArtifactHooks{Pre: []apiv1.HookStep{step}}, time.Minute, map[string]Builder{
		apiv1.HookProviderWizcli: WizcliBuilder(saver),
	})
	if err != nil {
		t.Fatalf("build runner: %s", err)
	}
	return runner
}

func TestWizcliBuilder_RejectsMissingSetup(t *testing.T) {
	fake := newFakeWizcli(t)
	step := apiv1.HookStep{
		Name:     "vuln-scan",
		Provider: apiv1.HookProviderWizcli,
		Wizcli:   &apiv1.WizcliHookConfig{Platforms: []string{"linux/amd64"}, Binary: fake.binary},
	}

	t.Run("binary", func(t *testing.T) {
		g := NewWithT(t)
		missing := step
		missing.Wizcli = &apiv1.WizcliHookConfig{Platforms: []string{"linux/amd64"}, Binary: "/nonexistent/wizcli"}
		_, err := WizcliBuilder(&fakeSaver{})(missing)
		g.Expect(err).To(MatchError(ContainSubstring("find wizcli binary")))
	})
	t.Run("saver", func(t *testing.T) {
		g := NewWithT(t)
		_, err := WizcliBuilder(nil)(step)
		g.Expect(err).To(HaveOccurred())
	})
}

func TestWizcliStep_AllPlatformsPass(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeWizcli(t)
	saver := &fakeSaver{}
	runner := wizcliRunner(t, fake, saver, func(step *apiv1.HookStep) {
		step.Wizcli.Policies = []string{"prod-vuln", "prod-secrets"}
	})

	result, err := runner.Run(context.Background(), Input{Source: "ghcr.io:5000/example/image", Tag: "v1.2.3", Digest: "sha256:index"})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(result.Terminal).To(BeNil())

	step := result.Steps[0]
	g.Expect(step.Verdict).To(Equal(apiv1.StepVerdictAllow))
	g.Expect(step.Units).To(HaveLen(2))
	g.Expect(step.Units[0].Name).To(Equal("linux/amd64"))
	g.Expect(step.Units[0].Wizcli).To(Equal(&apiv1.WizcliResult{
		Digest: "sha256:linux-amd64", ScanID: "scan-pass", Verdict: "PASSED_BY_POLICY",
	}))
	g.Expect(step.Units[1].Wizcli.Digest).To(Equal("sha256:linux-arm64"))

	g.Expect(saver.refs).To(ConsistOf("ghcr.io:5000/example/image@sha256:index", "ghcr.io:5000/example/image@sha256:index"))
	calls := fake.calls(t)
	g.Expect(calls).To(HaveLen(2))
	for _, call := range calls {
		g.Expect(call).To(ContainSubstring("scan container-image"))
		g.Expect(call).To(ContainSubstring("--name ghcr.io:5000/example/image:v1.2.3"))
		g.Expect(call).To(ContainSubstring("--no-publish"))
		g.Expect(call).To(ContainSubstring("--policies prod-vuln,prod-secrets"))
		g.Expect(call).ToNot(ContainSubstring("--projects"))
		g.Expect(call).ToNot(ContainSubstring("client-secret"))
	}
}

func TestWizcliStep_OneFailingPlatformBlocksTheTag(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeWizcli(t)
	saver := &fakeSaver{content: map[string]string{"linux/arm64": "fail-policy"}}
	runner := wizcliRunner(t, fake, saver, nil)

	result, err := runner.Run(context.Background(), Input{Source: "ghcr.io/example/image", Digest: "sha256:index"})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(result.Terminal).To(Equal(&Terminal{Status: apiv1.StatusBlocked, Reason: "vuln-scan", Digest: "sha256:index"}))

	step := result.Steps[0]
	g.Expect(step.Verdict).To(Equal(apiv1.StepVerdictDeny))
	g.Expect(step.Reason).To(Equal("linux/arm64: failed policies: Block End of Life"))
	g.Expect(step.Units[0].Verdict).To(Equal(apiv1.StepVerdictAllow))
	g.Expect(step.Units[1].Verdict).To(Equal(apiv1.StepVerdictDeny))
	g.Expect(step.Units[1].Wizcli.FailedPolicies).To(Equal([]string{"Block End of Life"}))
	g.Expect(step.Units[1].Wizcli.Verdict).To(Equal("FAILED_BY_POLICY"))
}

func TestWizcliStep_PublishReports(t *testing.T) {
	g := NewWithT(t)
	fake := newFakeWizcli(t)
	saver := &fakeSaver{content: map[string]string{"linux/arm64": "fail-policy"}}
	runner := wizcliRunner(t, fake, saver, func(step *apiv1.HookStep) {
		step.Wizcli.Publish = true
	})

	result, err := runner.Run(context.Background(), Input{Source: "ghcr.io/example/image", Digest: "sha256:index"})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(result.Terminal.Status).To(Equal(apiv1.StatusBlocked))
	g.Expect(result.Steps[0].Units[0].Wizcli.ReportURL).To(Equal("https://app.wiz.io/reports/scan-pass"))
	g.Expect(result.Steps[0].Units[1].Wizcli.ReportURL).To(Equal("https://app.wiz.io/reports/scan-fail"))
	for _, call := range fake.calls(t) {
		g.Expect(call).ToNot(ContainSubstring("--no-publish"))
	}
}

func TestWizcliStep_PolicyFailureFollowsOnDeny(t *testing.T) {
	saver := func() *fakeSaver {
		return &fakeSaver{content: map[string]string{"linux/arm64": "fail-policy"}}
	}

	t.Run("warn continues and keeps the failed policies", func(t *testing.T) {
		g := NewWithT(t)
		runner := wizcliRunner(t, newFakeWizcli(t), saver(), func(step *apiv1.HookStep) {
			step.OnDeny = apiv1.HookActionWarn
		})
		result, err := runner.Run(context.Background(), Input{Source: "ghcr.io/example/image", Digest: "sha256:index"})
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(result.Terminal).To(BeNil())
		g.Expect(result.Steps[0].Verdict).To(Equal(apiv1.StepVerdictDeny))
		g.Expect(result.Steps[0].Continued).To(BeTrue())
		g.Expect(result.Steps[0].Units[1].Wizcli.FailedPolicies).To(Equal([]string{"Block End of Life"}))
	})

	t.Run("onError warn does not let a policy failure through", func(t *testing.T) {
		g := NewWithT(t)
		runner := wizcliRunner(t, newFakeWizcli(t), saver(), func(step *apiv1.HookStep) {
			step.OnError = apiv1.HookActionWarn
		})
		result, err := runner.Run(context.Background(), Input{Source: "ghcr.io/example/image", Digest: "sha256:index"})
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(result.Terminal).ToNot(BeNil())
		g.Expect(result.Terminal.Status).To(Equal(apiv1.StatusBlocked))
	})
}

func TestWizcliStep_ScanErrorFollowsOnError(t *testing.T) {
	saver := func() *fakeSaver {
		return &fakeSaver{content: map[string]string{"linux/arm64": "scan-error"}}
	}

	t.Run("block", func(t *testing.T) {
		g := NewWithT(t)
		runner := wizcliRunner(t, newFakeWizcli(t), saver(), nil)
		result, err := runner.Run(context.Background(), Input{Source: "ghcr.io/example/image", Digest: "sha256:index"})
		g.Expect(err).To(MatchError(ContainSubstring("hook vuln-scan: linux/arm64: wizcli exited with code 1: boom: something broke")))
		g.Expect(result.Steps[0].Verdict).To(Equal(apiv1.StepVerdictError))
		g.Expect(result.Steps[0].Units[0].Verdict).To(Equal(apiv1.StepVerdictAllow))
		g.Expect(result.Steps[0].Units[1].Verdict).To(Equal(apiv1.StepVerdictError))
	})

	t.Run("warn", func(t *testing.T) {
		g := NewWithT(t)
		runner := wizcliRunner(t, newFakeWizcli(t), saver(), func(step *apiv1.HookStep) {
			step.OnError = apiv1.HookActionWarn
		})
		result, err := runner.Run(context.Background(), Input{Source: "ghcr.io/example/image", Digest: "sha256:index"})
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(result.Terminal).To(BeNil())
		g.Expect(result.Steps[0].Verdict).To(Equal(apiv1.StepVerdictError))
		g.Expect(result.Steps[0].Continued).To(BeTrue())
	})
}

func TestWizcliStep_MissingPlatformIsNotRetried(t *testing.T) {
	g := NewWithT(t)
	saver := &fakeSaver{err: errors.New("pull: no child with platform {linux s390x} in index x")}
	runner := wizcliRunner(t, newFakeWizcli(t), saver, func(step *apiv1.HookStep) {
		step.Retries = new(2)
		step.Wizcli.Platforms = []string{"linux/s390x"}
	})

	result, err := runner.Run(context.Background(), Input{Source: "ghcr.io/example/image", Digest: "sha256:index"})
	g.Expect(err).To(MatchError(ContainSubstring("platform linux/s390x is not in ghcr.io/example/image@sha256:index")))
	g.Expect(result.Steps[0].Units[0].Attempts).To(Equal(1))
}

func TestWizcliStep_RemovesTemporaryFiles(t *testing.T) {
	g := NewWithT(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	runner := wizcliRunner(t, newFakeWizcli(t), &fakeSaver{}, nil)

	_, err := runner.Run(context.Background(), Input{Source: "ghcr.io/example/image", Digest: "sha256:index"})
	g.Expect(err).ToNot(HaveOccurred())
	entries, err := os.ReadDir(tmp)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(entries).To(BeEmpty())
}

func TestWizcliArguments_Timeout(t *testing.T) {
	g := NewWithT(t)
	step := wizcliStep{}

	g.Expect(step.arguments(context.Background(), "image.tar", "scan.json", "example/image:v1")).ToNot(ContainElement("--timeout"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	args := step.arguments(ctx, "image.tar", "scan.json", "example/image:v1")
	g.Expect(args).To(ContainElement("--timeout"))

	short, cancelShort := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShort()
	g.Expect(step.arguments(short, "image.tar", "scan.json", "example/image:v1")).ToNot(ContainElement("--timeout"))
}

func TestInterpretWizcli(t *testing.T) {
	report := func(t *testing.T, content string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "scan.json")
		if content != "" {
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatalf("write report: %s", err)
			}
		}
		return path
	}
	passed := `{"id":"s1","status":{"state":"SUCCESS","verdict":"PASSED_BY_POLICY"}}`
	failed := `{"id":"s2","status":{"state":"SUCCESS","verdict":"FAILED_BY_POLICY"},"result":{"failedPolicyMatches":[{"policy":{"name":"A"}},{"policy":{"name":"B"}}]}}`

	tests := []struct {
		name        string
		exitCode    int
		report      string
		wantVerdict apiv1.StepVerdict
		wantReason  string
		wantErr     string
	}{
		{name: "pass", report: passed, wantVerdict: apiv1.StepVerdictAllow},
		{name: "policy failure", exitCode: 4, report: failed, wantVerdict: apiv1.StepVerdictDeny, wantReason: "failed policies: A, B"},
		{name: "policy failure without report", exitCode: 4, wantVerdict: apiv1.StepVerdictDeny, wantReason: "policy failure"},
		{name: "failed verdict with exit zero fails closed", report: failed, wantVerdict: apiv1.StepVerdictDeny, wantReason: "failed policies: A, B"},
		{name: "scan error", exitCode: 1, wantErr: "wizcli exited with code 1: output"},
		{name: "not authenticated", exitCode: 3, wantErr: "wizcli is not authenticated (exit code 3): output"},
		{name: "clean exit without report", wantErr: "no usable report"},
		{name: "unreadable report", report: "not json", wantErr: "no usable report"},
		{name: "state not success", report: `{"status":{"state":"FAILED","verdict":"PASSED_BY_POLICY"}}`, wantErr: `state is "FAILED"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			outcome, err := interpretWizcli(tt.exitCode, report(t, tt.report), "sha256:child", "output", false)
			if tt.wantErr != "" {
				g.Expect(err).To(MatchError(ContainSubstring(tt.wantErr)))
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(outcome.Verdict).To(Equal(tt.wantVerdict))
			g.Expect(outcome.Reason).To(Equal(tt.wantReason))
			g.Expect(outcome.Wizcli.Digest).To(Equal("sha256:child"))
		})
	}
}

func TestInterpretWizcliReportURL(t *testing.T) {
	for _, tc := range []struct {
		name, url, want string
		publish         bool
	}{
		{name: "published", url: "https://app.wiz.io/report/1", want: "https://app.wiz.io/report/1", publish: true},
		{name: "not published", url: "https://app.wiz.io/report/1"},
		{name: "message", url: "No report was generated", publish: true},
		{name: "non-https", url: "http://example.com/report", publish: true},
		{name: "credentials", url: "https://user:password@example.com/report", publish: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			path := filepath.Join(t.TempDir(), "scan.json")
			content := `{"reportUrl":"` + tc.url + `","status":{"state":"SUCCESS","verdict":"PASSED_BY_POLICY"}}`
			g.Expect(os.WriteFile(path, []byte(content), 0o600)).To(Succeed())
			outcome, err := interpretWizcli(0, path, "sha256:child", "", tc.publish)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(outcome.Wizcli.ReportURL).To(Equal(tc.want))
		})
	}
}

func TestTailBuffer(t *testing.T) {
	g := NewWithT(t)
	buffer := tailBuffer{limit: 10}
	_, err := buffer.Write([]byte("line one\nline  two\nline three"))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(buffer.String()).To(Equal("line three"))
}

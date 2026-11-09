# Fork TODO: Helm repo publishing and verify

Status: `destinationType: artifactory` is implemented for `artifacts` and for
`charts` (OCI Helm chart or HTTP/S Helm repo source to a JFrog Artifactory Helm
repository); see
[Publishing to a Helm repository](config.md#publishing-to-a-helm-repository) and
[Publishing charts to a Helm repository](config.md#publishing-charts-to-a-helm-repository).
`artifacts` and `charts` were both checked against a real JFrog instance.
`charts` selects versions with the same `selector` as `artifacts`
(`charts[].version` and `charts[].limit` were removed, a breaking change for
v1beta2 configs; v1beta1 configs are converted automatically).
This file tracks what is still open.

## Open: charts follow-ups

- **C4.** `artifacts` with `destinationType: artifactory` takes the file name
  from the OCI config blob and only compares `version` with the tag. It does not
  check `name`, nor compare the blob with the tarball (the tarball is streamed).
  `charts` now checks both against `Chart.yaml` before an upload; consider a
  `name` check for `artifacts` too.
- **C5.** Migrate the internal `sk8s-flux-mirror` Helm chart (`4054-sk8s-modules`)
  to `charts[].selector`: it renders `charts[].version` / `limit`, which the
  v1beta2 config now rejects (`unknown field`). Update its templates,
  `tests/configmap_charts_test.yaml`, and snapshots together with the image bump.
  Its current override only uses `artifacts`, so nothing is broken until `charts`
  entries are added.
- Out of scope for the above: B1 (source auth via `hosts`), B2, B3, T5's
  `artifacts` default, V8.

## Follow-ups from real-world testing

- **T1.** A wrong repository path is not caught by `--dry-run`, for `artifacts`
  and `charts` with `destinationType: artifactory`: a `HEAD` 404
  means "file absent", so dry-run reports `would-copy` and the failure only
  shows at `PUT` (for example a missing `/artifactory` context path). The `PUT`
  404 now carries a hint; probing the repository in `Plan` would surface it
  earlier.
- **T3.** Verbose logs have no stable schema and no JSON format: lines use ad
  hoc fields (`src`/`dst`, `chart`/`dst`) and no `event`. Define one schema (for
  example `event`, `source`, `tag`, `destination`, `status`, `digest`, `reason`,
  `error`, `elapsed`), then add `--log-format text|json` for the `--verbose`
  stream on top of it:
  - `artifacts` to OCI (`internal/artifacts/mirror.go`): `mirroring tag`,
    `tag done`, drift and referrer warnings, `signature too new` use `src`/`dst`
    and no `event`.
  - `artifacts` to a Helm repo (`internal/artifacts/helmrepo.go`):
    `mirroring chart`, `chart done`, and the drift warning use `src`/`dst` and
    no `event`.
  - `charts` (`internal/charts/mirror.go`): `mirroring chart` / `chart done` use
    `chart`/`dst` and no `status` on drift.
  - runner (`internal/sync/runner.go`): `sync started`, `entry started/finished`,
    `plan failed`, `job failed, retrying` have no `event`.
  - Selector exclusions (`tag excluded by selector`, `version excluded by
    selector`) and the crane progress lines (a JSON handler would only wrap
    them, not structure them).
  - Durations: the text format prints Go notation such as `850ms` / `4.227s`,
    while slog's JSON handler emits integer nanoseconds. A JSON format needs a
    `ReplaceAttr` that renders `time.Duration` as seconds.
  - Decide whether the text format should include `msg=` and `level=` like a
    JSON stream. `plainHandler` (`cmd/flux-mirror/logging.go`) is shared by every
    slog line in verbose mode, so changing it (for example to the standard
    `slog.TextHandler` logfmt) is a global change: all lines would become
    `time=… level=INFO msg="…" k=v` with RFC3339 times, and `docs/sync.md`
    examples and tests would need updating. crane's own progress lines would
    still be plain `log` lines in text mode.
- **T4.** With `destinationType: artifactory` (`artifacts` and `charts`, which
  share `helmrepo.NewPusherForHosts`), a host `credential` that sets
  `username` is resolved through `registryauth.ResolveHostAuth` on every HTTP
  request. A `credential.provider` token source (for example `github`) therefore
  mints a new token per `HEAD`/`PUT`, bypassing the sync token cache, which only
  covers cloud `provider` hosts. Static `value`/`fromPath` and the bearer path
  (no `username`) are unaffected. Resolve once per entry or route it through the
  token cache.
- **T5.** `artifacts` selects tags with no semver filter by default, so
  prereleases are kept: with no `semver` and no `regex` every tag that parses as
  semver is eligible, and sorted by semver `1.2.0-rc.1` ranks above `1.1.0`, so
  the default `limit: 1` picks the release candidate. Adding `semver: "*"` or a
  `regex` excludes it. `charts` now uses the same selector and therefore behaves
  the same way (see the charts section in `docs/config.md`).
  - Still open: whether the shared default should change (for example exclude
    prereleases unless asked), which would alter which tags and versions
    existing configs mirror, for `artifacts` and `charts` alike.
- **T6.** `artifacts` does not accept an `oci://` prefix consistently, unlike
  `charts` (where the OCI destination takes `oci://` or no scheme, and the
  Artifactory source/destination default to `https://`):
  - `artifacts[].destination` (`destinationType: oci`) with `oci://` is
    rejected by validation (`not a valid OCI repository`).
  - `artifacts[].source` with `oci://` passes validation, then fails at run time
    with a misleading `lookup oci: no such host`, because `oci` is parsed as the
    registry host. This is a missing check, not intended support.
  - Proposed: accept an optional `oci://` prefix on both (`destinationType: oci`
    only; `artifactory` keeps its URL rules), normalize it once in
    `artifacts.New` so `ListTags`, copy, referrers, `verify`, and the report
    fields all see the unprefixed form, and document it in `docs/config.md`.
    If not done, at least reject `oci://` on `source` with a clear message.
  - Current rules for reference: `artifacts` source/destination (`oci`) are
    written without a scheme; `charts` source defaults to `https://` (`http://`
    needs `--insecure`); `charts` OCI destination takes `oci://` or none; both
    Artifactory destinations default to `https://` (`http://` needs `--insecure`).

## Verify gaps (to design)

`Verifier.Verify` only looks for one signature bundle on the descriptor that
the ref resolves to (referrers first, then the cosign `<alg>-<hex>.sig` tag
fallback) and verifies that single signature. Known gaps:

- **V1. Platform-specific signatures are not verified.** For a multi-arch
  image the ref resolves to an index, so only the index signature is checked.
  The child manifests (`linux/amd64`, ...) are copied but their own signatures
  are never verified, and an index that is unsigned while every platform is
  signed is not handled. Needs: iterate child manifests, define the policy
  ("every platform must be signed" vs "index or platforms"), record per-platform
  results.
- **V2. Attestations are not verified.** DSSE-wrapped in-toto statements
  (SLSA provenance, SBOM, ...) are ignored in both discovery paths
  (referrers and the cosign `.att` tag). Needs: DSSE bundle verification,
  `predicateType` filtering, subject digest binding, and a way to require that
  an attestation exists.
- **V3. Config and report surface is undefined.** Candidate fields (for example
  `verify.platforms`, `verify.attestations[]`) and the report `verification`
  shape (per-platform and per-attestation results, failure semantics) need
  design, then `make generate`, `docs/config.md`, `docs/report.md`.
- **V4. Both discovery paths must be covered** for V1 and V2: OCI 1.1
  referrers and the cosign tag scheme (`.sig` / `.att`).
- **V5. Interaction with `destinationType: artifactory`.** A Helm chart is a
  single manifest (no platforms), but attestations may still apply. Signatures
  and attestations are not carried to a Helm repo (no referrers).
- **V6. Performance.** Verification runs serially in `Plan` (see B4); V1 and
  V2 multiply the number of verification requests per tag.
- **V7. Key-based (static key) signatures are not supported.** Only cosign
  keyless is implemented: `verify.matchOIDCIdentity` matches the Fulcio
  certificate identity. A signature published with a fixed key has no
  certificate (only the `dev.cosignproject.cosign/signature` annotation, and
  usually a Rekor `dev.sigstore.cosign/bundle`), so tag-based discovery fails
  with `cosign tag signature has no certificate; key-based signatures are not
  supported` and every selected tag fails verification. Seen on
  `public-registry.wiz.io/charts/wiz-sensor` (tag signatures `sha256-<hex>.sig`,
  no certificate). Needs: a `verify` field for the public key (for example
  `publicKey.value` / `publicKey.fromPath`, mutually exclusive with
  `matchOIDCIdentity`), verification of the signature against that key
  (with and without a Rekor entry), and the same handling for both the
  referrers and the tag discovery paths. `minAge` needs a verified Rekor
  integrated time, so it only applies when the bundle carries one. Until then,
  such sources must be mirrored without `verify`.
- **V8. `charts` (HTTP/S Helm repo source) has no verification at all.**
  `ChartEntry` has no `verify`: cosign signatures live in OCI registries, which
  a classic Helm repo (`index.yaml` plus `.tgz`) does not have. Today
  `helmrepo.HTTPSource.Download` also does not compare the tarball with the
  `digest` in `index.yaml`, so not even integrity is checked; trust rests on
  HTTPS and the source site.
  - Integrity: verify sha256(tgz) against the `index.yaml` `digest` (skip with a
    clear error when the index has none). Cheap; fits together with B3, which
    also reads that digest.
  - Authenticity: verify the Helm provenance file (`<chart>-<version>.tgz.prov`,
    PGP) the way `helm verify` does. Needs a public keyring field in the config
    (same shape of problem as V7's static public key) and a `.prov` download per
    version. A `verify` block under `charts[]` would have to be designed first
    (provider, keyring, whether a missing `.prov` fails the version).
  - Mirroring a chart through OCI and then using `artifacts` with cosign only
    helps when the OCI copy is signed by you.

## Vulnerability scanning gate (to design)

Implementation order (decided): (PR1) the `hooks.pre` skeleton for `artifacts`
(step interface, runner `Gate` phase, per-step `timeout`, `concurrency` and
`retries`, `blocked` status, report fields) together with a minimal `cosign`
provider that only does referrer discovery, so config, validation and report are
tested end to end with a real provider; engine tests use fake steps in Go test
code only, no test-only provider reaches the public schema. (PR2) `cosign` gets
tag discovery and `minAge`, taken over from the `fbeb674` patch, and that patch
is reverted so `verify.go` goes back to upstream (S12). (PR3) the `wizcli`
provider and its initContainer (S1 to S10, S17). Then the chart `hooks` values,
`charts` support, retag (B7) and prune (B8).

Status: PR1, PR2 and the `wizcli` provider of PR3 are implemented in this
repository (`internal/hooks`), and `--verbose` logs each hook run, step and
per-platform unit. Blocked tags print the step and failed policies in the text
output. The `sk8s-flux-mirror` chart (S8) and the initContainer that delivers the
`wizcli` binary (S17) are done and ran in a Kubernetes CronJob. Not done:
`hooks` for `charts` entries, the `AUDIT`-only verdict check (S1), whether
`scan dir` renders chart templates (S3), `cosign` work units per platform
(S5), `hooks.post` (S13), and a `wiz-api` provider (S7). Implemented as decided
in S5: the step `concurrency` counts work units (`tag x platform` for `wizcli`),
and `wizcli.platforms` is required. Later renamed: the `onFailure` control named
in the sections below is now `onError` (an exhausted infrastructure error), and
`onDeny` (`block` or `warn`) was added for a policy denial; the report marks a
deny or error that did not stop the tag with `continued: true`.

Goal: an ordered `hooks.pre` list on `artifacts[]` and `charts[]` whose steps
can block a tag or version from being mirrored, like `verify` but pluggable. The
first step type is a vulnerability and policy scan. Decisions so far:

- Gate only (before copy, on the source digest). No post-copy hook.
- Built-in provider, like `verify`, not a generic `exec` hook. First provider is
  `wizcli`; a `wiz-api` provider (results from the Wiz registry connector) comes
  later.
- Applies to `artifacts` and `charts`. `--dry-run` does not run the scanner.
- A hook step operates on a single tag (or chart version): its input is that
  tag's source and destination tag and digest, its verdict applies to that tag
  only. Operations on the whole tag list (regex, semver, sort, limit) belong to
  the selector, and run-level work (end-of-run notification, report archiving,
  metrics) is not a hook; it uses the `-o json` report outside flux-mirror.
- A rejected tag gets a new `blocked` status with the semantic exit code `3`
  (decided). Exit code priority: failures (`1`) over blocked (`3`) over drift
  (`2`). A new `--blocked-exit-code N` flag (0 to 255, default `3`) works like
  `--drift-exit-code`: when the semantic code is `3` it is replaced by `N` in
  `classifyExit`, the report's `exitCode` stays the semantic value, and the
  flag's value is validated in `validateSyncArgs`. `--drift-exit-code` keeps
  applying only to drift, so each flag changes only its own code (setting
  `--blocked-exit-code=0` keeps blocked-only runs green, for example while
  rolling a scan out in report-only mode). Failures still win over both.
- Credentials only through `WIZ_CLIENT_ID` / `WIZ_CLIENT_SECRET`, never in the
  config. The `wizcli` binary must be in the image.

Pipeline per entry (order matters):

1. Select candidate source tags (regex, semver, sort, limit).
2. Map the destination tag (B7) and reject collisions.
3. Resolve the source digest (one HEAD). Upstream `verify`, when configured,
   still runs here in `Plan` for every selected tag on every run, even for tags
   that are already up to date (compare B4). Our hooks do not.
4. Compare with the destination: equal digests mean the tag is skipped with no
   verification or scan, since no new content enters; drift with
   `overwrite: false` is reported; neither continues.
5. `hooks.pre` for tags that will be copied.
6. Mirror (copy).
7. `hooks.post` after a successful copy.

The comparison today runs in each job's `Run`, after `Plan`. Run `hooks.pre`
after the comparison and before the copy, not in `Plan` like `verify`: this scans
only tags that will be copied and runs under per-step limits instead of serially
(compare B4). It must not run inside the copy `Run` either, because the per-job
`--timeout` and `--retries` would apply to it; use a separate pre phase (see S5).

Sketch of the config (names not final). `hooks.pre` is an ordered list: steps
run in order and the first failing step stops the chain, so cheap checks go
before expensive ones (the scanner last). `hooks.post` is reserved for later.

```yaml
hooks:
  pre:
    - name: signature          # cheap checks first
      provider: cosign         # later, replaces `verify` (S12)
      cosign:                  # provider parameters: one typed sub-object named after the provider
        matchOIDCIdentity:
          - issuer: https://token.actions.githubusercontent.com
            subject: ^https://github\.com/example/.*$
        minAge: 12h            # signature too new: skip the tag (see S12 for how it is derived)
    - name: vuln-scan          # expensive, last
      provider: wizcli
      timeout: 10m             # common controls stay at step level
      concurrency: 2
      retries: 1               # extra attempts after a scan error, not after a policy failure
      onFailure: block         # block (default) | warn
      wizcli:
        policies: [prod-vuln]  # optional: all CLI policies of the account when omitted
        projects: []           # optional
```

Hook package decisions (`internal/hooks`):

- Step config: common controls (`name`, `provider`, `timeout`, `concurrency`,
  `retries`, `onFailure`) at step level, provider parameters in a typed
  sub-object named after the provider; validation requires exactly the
  sub-object that matches `provider`. Strict decoding and the generated JSON
  Schema then catch misplaced fields.
- `Step.Run(ctx, Input) (Outcome, error)`: an error is an infrastructure failure
  and is retried per `retries`; a policy rejection is `Outcome{Verdict: Deny}`,
  never an error, never retried. An error wrapped with `Permanent(err)`
  (bad parameters, missing binary, authentication failure) is not retried.
- The report keeps each provider's own typed result (the report schema grows
  with the providers), not a free-form map.
- The engine resolves the source digest before the first step; steps are built
  once at startup (`Provider.Build`) so bad parameters fail before any network
  work.

Report decisions (`api/v1beta2/report_types.go`):

- `TagResult.Steps []StepResult` (execution order, only steps that ran):
  `name`, `provider`, `verdict` (`allow`, `deny`, `skip`, `error`), `reason`,
  `error`, `attempts`, `duration`, plus the provider's own typed result
  (`cosign` reuses the existing `Verification` shape; `wizcli` gets a new type
  in PR3). The top-level `Verification` stays owned by upstream `verify:` and is
  not filled by hook steps.
- New status `blocked` (kubebuilder `Enum`, `validStatuses`, summary counts, the
  report totals and `PrettyPrint` all learn it).
- Row mapping: all steps allow, the copy outcome as today; a `deny` gives
  `blocked` with `reason` = the step name (the specific reason is in `steps[]`);
  a `skip` gives `skipped` with the step's reason (for example
  `signature-too-new`); an error after the retries with `onFailure: block` gives
  `failed` with `error` = `hook <name>: ...`; an error with `onFailure: warn`
  continues and the step shows `verdict: error`; up-to-date and drifted tags
  never run steps and have no `steps`.

Validation decisions (`internal/config`): `provider` must be registered (PR1:
`cosign`) and match the one filled sub-object (missing or extra sub-objects are
errors); `name` unique within an entry and a valid lowercase identifier;
`timeout` greater than 0, `concurrency` at least 1, `retries` at least 0,
`onFailure` is `block` or `warn`; `hooks` on a `charts` entry is an error in the
first version; an entry with both `verify:` and a `cosign` step is rejected at
load time (it would verify twice); provider parameters are validated by the
provider (for `cosign`: at least one `matchOIDCIdentity` with `issuer` and a
valid `subject` regexp, reusing `validateVerification`).

Runner decisions (`internal/sync`, `internal/artifacts`): `Job` gets an optional
`Gate(ctx) (GateResult, error)` that runs before `Run`, outside the per-job
budget (`--timeout`, `--retries`); `GateResult` carries an optional terminal
`JobResult` (then `Run` is not called) and the `StepResult`s. Per job: a
`PlanError` is recorded as before; otherwise `Gate` runs: a terminal result
(up-to-date `skipped`, `drifted`, `blocked` by a `deny`, `skipped` by a step
`skip`) is recorded with its steps; a step error with `onFailure: block` is a
`failed` row (`hook <name>: ...`); otherwise `runJob` copies with the usual
timeout and retries. In `artifacts`, the gate does the comparison first (equal or
drifted with `overwrite: false` end there, no steps), runs the steps only when
not dry-run and hooks are configured, and caches the comparison for the first
copy attempt (a retry compares again, as today). Dry-run compares but does not run
steps. An entry without hooks has `Gate == nil` and behaves exactly as before;
`charts` keep `Gate == nil`. The comparison requests in the gate use `--timeout`
as their upper bound; each step uses its own `timeout`. A job waiting for a step's
concurrency slot keeps its outer `--concurrency` slot, so `--concurrency` should
not be smaller than a step's `concurrency`. Entries run one after another, so a
step's semaphore is created per entry step and is also its run-wide cap.

The engine resolves the source digest itself before any step, so every step gets
the same digest. Upstream `verify` stays a separate field with its own behavior
(it runs earlier, in `Plan`, see S12); the `cosign` step is the later replacement
that runs only for tags that will be copied.

Facts from `wizcli --help` (local version): `wizcli scan container-image <image>`
takes an image name (tag or digest) or a `.tar`/`.tgz`; `wizcli scan dir <path>`
scans a directory; both accept `--policies`, `--projects`, `--timeout`,
`--no-publish` and `--stdout json`.

- **S1. Spike first.** Run `wizcli` by hand against a ghcr image and a saved tar
  and record: the exit code per policy hit (`BLOCK`/`AUDIT`), the JSON shape, how
  it authenticates to the source registry, how it treats multi-arch indexes, and
  the scan time and disk use.
  Results so far (wizcli 1.82.0, device-code login, 2026-11-05):
  - Scanning an image by name needs a Docker daemon (`/var/run/docker.sock`);
    it fails without one. A `.tar` from `crane pull` scans without a daemon, so
    S2 (save to tar) is required, not just preferred. The scan of a 3.6 MB
    alpine tar took about 10 s.
  - `crane pull <index>` without `--platform` saves a single platform, not the
    whole index. Scanning several platforms means one tar per platform.
  - Without `--policies`, every policy of the account that applies to the CLI
    lifecycle is evaluated (here vulnerabilities, end of life, secrets,
    malware as BLOCK; sensitive data and license as AUDIT). So `policies` is
    optional in our config.
  - JSON (`--stdout json`, or `--json-output-file`) has `status.state`
    (`SUCCESS`) and `status.verdict` (`FAILED_BY_POLICY` and `PASSED_BY_POLICY`
    seen; `WARNED_BY_POLICY` or similar for an `AUDIT` hit is not seen yet), `id`,
    `policies[]` with `enforcementMethod`, the findings
    with `failedPolicyMatches`, and `result.analytics` counts (vulnerabilities,
    secrets, malware, ...). With `--no-publish`, `reportUrl` is only a "did not
    generate a report" message, so a report link needs publishing. The JSON
    includes the user name of the scan: store only the verdict, scan id,
    failed policy names and counts in the report, never the whole document.
  - With stdout JSON the human status line (`FAILED Scan failed - policy
    failure`) follows it; parse a `--json-output-file` instead.
  - End-of-life gates age: `alpine:3.20` failed the "Block End of Life" policy
    (`EOL-OPERATING-SYSTEM`, critical) because 3.20 reached its end of life.
    A selector with a large or no `limit` will then block every old tag on
    every run (see S5: only tags to be copied are scanned, so mirrored tags are
    not re-scanned), which makes the blocked exit code noisy; this feeds S14 and
    an exemption list (S11).
  - A passing scan (`alpine:latest`) has `failedPolicyMatches: null`, no
    `endOfLifeTechnologies`, and all `analytics` counts 0. Fields are `null` when
    empty, not empty lists, so a parser must tolerate `null`.
  - Process exit codes (wizcli 1.83.0, cached device-code session, tar input,
    `--no-publish --json-output-file`, 2026-11-09): pass `0`
    (`PASSED_BY_POLICY`); policy failure `4` (`FAILED_BY_POLICY`, `alpine:3.20`
    on the "Block End of Life" policy); every scan error `1`: missing input
    file, failed authentication (fake client id and secret), and `--timeout 1s`
    (`failed to initiate scan: context deadline exceeded`). So the provider
    maps `0` to allow, `4` to deny and anything else to an error (retryable),
    and reads the verdict from the JSON file as the source of truth.
  - Use `--json-output-file`, not `--stdout json`: a failing scan still writes
    the file, and the human status lines never mix with it.
  - JSON fields to keep: `status.state`, `status.verdict`, `id`,
    `policies[].name` (evaluated), and for a failure
    `result.failedPolicyMatches[].policy.name` plus
    `policy.policyLifecycleEnforcements[]` (`enforcementMethod` `BLOCK`,
    `deploymentLifecycle` `CLI`). `projects` and `outputMessages` are `null`.
    `createdBy` carries the user name: never copy it into the report.
  - `--projects` unset: the scan applies to all Projects associated with the
    authenticated service account (from `wizcli scan container-image --help`);
    the JSON has `projects: null`. The first version passes no `--projects`.
  - `--by-policy-hits` (default `BLOCK`, values `AUDIT`, `DISABLED`, `BLOCK`)
    only filters which results are displayed; it is not a verdict switch.
    Do not rely on it.
  - A Helm chart directory (`wizcli scan dir <extracted chart>`) scans fine and
    exits `0`: the IaC scanner runs (`filesParsed` 2, `queriesExecuted` 4 on
    the podinfo test chart), with no findings. Whether templates are rendered
    before scanning is still not proven; it needs a chart with a deliberate
    misconfiguration in a template (S3).
  - Still to check: the exit code and verdict for an `AUDIT`-only policy hit (no
    account policy produced one here), a Linux/alpine run of the Linux binary,
    the egress domains it needs, and memory on large images.
- **S2. Scan input for images.** Preferred: save the image to a tar (crane) so
  neither a docker daemon nor registry credentials for wizcli are needed, at the
  cost of an extra pull. Multi-arch (decided): `wizcli.platforms` is a list; each
  listed platform is pulled (`crane pull --platform`) and scanned as its own
  scan task. A platform missing from the source index is an error, never a
  silent skip. The copy still mirrors the whole index. No `projects` field in
  the first version: `wizcli` runs with its default project behavior (what that
  default means is still to be checked in S1).
  Optional cheaper input: `wizcli scan dir <dir> --scan-sbom` (also on
  `scan container-image`) scans SBOM files in the target, so an SBOM found as an
  OCI referrer of the source image could be scanned without pulling the image.
  `--sbom-format` and `--sbom-output-file` only generate an SBOM. In practice an
  SBOM is rarely a plain file: it is usually an OCI referrer, either a cosign
  or BuildKit in-toto attestation (a DSSE envelope whose decoded statement has
  the SBOM in `predicate`) or a plain SBOM artifact (`artifactType` CycloneDX or
  SPDX, for example from `cosign attach sbom`). `wizcli` shows no stdin,
  single-file or URL input (`scan dir` takes a path, `scan container-image` an
  image name or tar), so the SBOM must be written to a temp directory first and
  scanned with `scan dir --scan-sbom`, then removed. The referrer discovery of
  `includeReferrers` and the attestation unpacking would be shared with V2. To
  check: supported SBOM formats and versions, whether verdicts and policies
  match an image scan, and the weaker guarantee (the SBOM may not match the
  image, and upstream images without one still need the tar path).
- **S3. `charts` input.** Extract the tgz to a temp dir and use `scan dir`. The
  IaC types of `scan dir` list Kubernetes, Crossplane, Terraform, etc. but not
  Helm, so it is not known whether templates are rendered. Verify in S1; if
  unsupported, scanning charts adds little and `charts` may be dropped from the
  first version.
- **S4. OCI Helm charts under `artifacts`** are not images. Undecided: skip with
  a log line, fail, or extract and use `scan dir` (depends on S3).
- **S5. Execution.** Only scan tags that would be copied (not up-to-date
  skips), once per digest per run, under its own concurrency limit and timeout.
  A copy retry must not re-run the scan. Tags already mirrored are skipped before
  any hook runs, so SBOM extraction and scanning only happen for tags that will be
  copied; dedupe by digest within a run. Blocked tags are not copied, so they are
  evaluated again on every run. Options: (A) accept it; (C) keep known-bad old
  tags out of the selector (`semver`, `limit`); (B) a cross-run record of blocked
  digests, which needs persistent storage a CronJob does not have and must expire
  when policies or the vulnerability data change (a scan verdict is not a stable
  property of a digest; an extracted SBOM is). Start with A and C. Keep the code in `internal/hooks`
  (a generic step interface with the verdicts from S12; the `wizcli` provider
  runs a subprocess).
  - Concurrency unit (decided): a step's `concurrency` counts work units, not
    tags. A unit is one scan or verification task: for `wizcli` one
    `tag x platform` scan, for `cosign` one tag now and later one
    `tag x platform` verification (V1). The step limit therefore caps the real
    number of concurrent `wizcli` processes, which is what bounds CPU, memory,
    tar disk use and API rate. The units of one tag may run in parallel when
    slots allow. Aggregation per tag: every unit allows -> allow; any unit denies
    -> `deny` (the tag is `blocked`); no deny but any unit errors after its
    retries -> the step errors and `onFailure` decides. `retries` and the
    semaphore apply per unit, and the step `timeout` still bounds the whole step
    for the tag. This changes the PR1 interface: `Step` can no longer be a
    single `Run(ctx, Input)` guarded by one semaphore in the runner; a step
    returns its units for a tag and the runner executes them under the step
    semaphore (provider code must not hold a slot while waiting for another).
    `StepResult` then needs per-unit results (for example a `platform` field), to
    be designed with PR3.
  - Per-step limits: each step has its own `timeout` and `concurrency`, which
    apply to that step only (a semaphore per step; the runner handles one entry at
    a time, so within a run this is also that step's global cap). Defaults:
    conservative `concurrency` (for example 2), and a `timeout` a little larger
    than the `--timeout` passed to `wizcli`, so flux-mirror ends a hung process.
    The scan is synchronous; whether Wiz rate-limits (429) is unknown, so
    separate a policy failure (blocked, no retry) from a scan error such as
    network, timeout or throttling (failed, bounded retry with backoff).
  - Per-step `retries`: configurable on each step and independent of the
    runner's `--retries` (which only covers the copy). It counts extra attempts
    after a scan error; a policy failure (`deny`) is never retried. Backoff grows
    between attempts (like the runner's) and stays within the step's `timeout`,
    which covers all attempts, not each one. Each attempt takes a concurrency
    slot again, so a retrying tag does not hold it while it waits. The default is
    a small number (0 or 1); exhausted retries end as `failed`, then `onFailure`
    decides whether that blocks the tag or only warns.
  - The runner's per-job budget does not fit hooks: `runJob` wraps the whole
    `Run` in `--timeout` (default 5 minutes) and calls it again on failure
    (`--retries`, default 3). Hooks inside `Run` would be cut off by that timeout
    (a step with `timeout: 10m` included), spend it while waiting for a free
    slot, and run again on every copy retry. So give `Job` a separate pre phase
    that the runner executes before `runJob`, with its own context, outside
    `PerJobTimeout`, using the step limits above; the copy keeps its own budget
    and retries. This needs the comparison to run before the pre phase, so it
    moves out of the copy `Run` (or the pre phase calls it), a larger change to
    upstream code than a few lines in `Run`; keep it as small as possible.
- **S6. Report.** A per-step result list on the tag row (step name, provider,
  verdict, policy hit count, scan id or URL, duration), the new `blocked` status
  and its exit code. The row records which step blocked. Regenerate the JSON
  Schemas; update `docs/config.md`, `docs/report.md`, `docs/sync.md`.
- **S7. `wiz-api` provider.** Registry-connector results arrive asynchronously.
  Decide what a missing result means: wait with a timeout, fail, or allow.
- **S8. Helm chart `sk8s-flux-mirror` (done, chart 1.3.0).** Values for `hooks` in
  `mirror.defaults.artifacts` and per entry (lists are replaced as a whole by the
  per-entry value, not merged by position; an empty list turns the defaults off),
  `initContainers.wizcli` for the delivery decided in S17, and
  `cronjob.blockedExitCode`. Credentials sit next to their consumers: a host
  `credential` is `{awsSecretId, property}` and `initContainers.wizcli.credential`
  carries the Wiz service account, and the chart builds the ExternalSecret from
  them (`externalSecret.enabled`/`secrets` were removed). The chart `verify`
  values were removed in favor of a `cosign` step. Rendering rejects a provider
  block that does not match `provider`, duplicate step names in an entry, and a
  wizcli step without the image or the credential. Not handled: a `binaryPath`
  inside the `/opt/wiz` mount hides the source binary in the initContainer
  (rejecting it, or a separate init-only mount path, are the options).
- **S9. Tests.** A fake `wizcli` script on `PATH` for pass, block, timeout and
  JSON output; no real Wiz in CI.
- **S10. Open risks.** Whether `wizcli` can be redistributed in a public image;
  ephemeral storage for tars; total run time for many tags.
  `wizcli` is closed source: only binaries are published
  (`https://downloads.wiz.io/v1/wizcli/<version>/wizcli-<os>-<arch>`, with a
  sha256 per platform, 272 MB for 1.82.0 on macOS arm64), built from a private
  repository (module `github.com/wiz-sec/wiz/cli-scanner`), and the `wiz-sec`
  GitHub organization has no CLI source or Go API client. So it can only be run as
  a subprocess. Delivery is decided in S17 (initContainer); pin the version and
  tolerate unknown JSON fields.
  Calling Wiz from the CLI means the analysis runs locally and the CLI talks to
  the Wiz backend for login, policies and results; the public GraphQL API only
  lets us read results or import external findings, so a `wiz-api` provider can
  gate only digests that Wiz already scanned (for example through the registry
  connector). Ask the Wiz contact whether a public API can trigger a scan.
- **S11. Candidate use cases for hooks.** Not planned yet; they show why the
  step interface must stay generic (input: ref, tag, digest; output: allow, deny
  or skip plus reason). A generic `exec` provider is deferred until at least two
  real non-Wiz needs exist, because it lets a config file run arbitrary commands.
  - Pre, gates: approval or allowlist of upstream repositories (ticket, CMDB);
    license or SBOM policy (no GPL, SBOM or SLSA attestation required); a
    cooling-off period for new upstream tags (supply-chain poisoning); image
    config checks (root user, EOL base image, size limit; dockle, conftest/OPA);
    key-based signature verification (V7) via a `cosign` step; an exemption list
    for tags a scan blocked.
  - Pre, preparation (side effects, not gates, keep separate): create the
    missing ECR repository and set tag immutability or lifecycle policy;
    destination path pre-checks (T1).
  - Post (cannot undo the copy): ask the Wiz registry connector to scan the new
    digest or register it; sign the destination digest with our key and attach an
    SBOM; tag or promote it (`latest`, JFrog properties); invalidate caches or
    pull-through proxies; trigger a deployment or downstream pipeline; end-of-run
    notification, report archiving (S3, SIEM), metrics push (Pushgateway), and
    cleanup. The end-of-run ones only need the `-o json` report and can live in
    the CronJob script. Per-tag post failures can only warn or mark the tag.
  - Not hooks: maintenance windows and rate limiting belong to the CronJob
    schedule.
- **S12. `cosign` step in `hooks.pre`, replacing `verify` in our deployments
  (later).** Upstream's `verify` stays untouched, so rebases do not conflict
  with it. The fork adds a `cosign` provider that only reuses the existing
  verifier code (`oci.NewVerifier`, read only) and lives in the new hooks
  package. The `sk8s-flux-mirror` Helm chart never renders `verify:`; once the
  `cosign` step exists, the chart maps its existing `verify` values to a
  `hooks.pre` `cosign` step in its templates, so values stay compatible and no
  Go-side migration or deprecation is needed. A second gain: upstream `verify`
  runs before the comparison for every selected tag on every run, while a
  `cosign` step runs only for tags that will be copied, so up-to-date tags cost
  no verification. An equal digest means identical content, so skipping it loses
  no integrity guarantee. What is no longer re-checked is trust state (a
  signature revoked later, new vulnerabilities); that belongs to continuous
  scanning on the destination side, not to the mirror. Pinning is unchanged: the
  step verifies the digest resolved at the start of the pipeline and the copy uses
  that same digest, never the tag. Design the step interface now:
  - The engine resolves the digest itself when no earlier step did (the verify
    code in `Plan` keeps resolving it as today); every step gets the same digest.
  - A step verdict is `allow`, `deny` or `skip(reason)`. `minAge` stays a field of
    the `cosign` step, not a separate step (kept together on purpose): it maps to
    `skip` with `signature-too-new`, not to a failure.
  - How `minAge` gets the signature time (upstream `internal/oci/verify.go`): the
    verifier checks the cosign bundle with `WithSignedCertificateTimestamps(1)`,
    `WithIntegratedTimestamps(1)` and `WithTransparencyLog(1)`, so the signature
    must carry a Rekor entry. `result.VerifiedTimestamps` are filtered to type
    `Tlog`, and the earliest `Timestamp` (the Rekor `integratedTime`, the moment
    the signature was logged) is the signature time. The age is `now` minus that
    time, floored at 0. Younger than `minAge` returns `SignatureTooNewError`
    (carrying integrated time, age and `minAge`; mapped to `skip`); no Tlog
    timestamp at all is a plain error, since the age cannot be enforced. The time
    is a trustworthy log timestamp, unlike the image `created` field that the
    builder writes. The `cosign` provider reuses this code and does not
    re-implement it.
  - A step may return structured data. It goes in the per-step report result; the
    upstream `Verification` object (identity, issuer, integrated time) stays tied
    to `verify:`. Later steps could read earlier results from a per-tag context if
    a real need appears; none is planned now.
  - Hook steps are judged per tag: unlike `verify`, a failure does not stop
    planning of later tags.
  - Reverting our own verify patch (`fbeb674`, cosign tag-based signature
    discovery): the patch adds 280 lines in `internal/oci/cosign_tag_discovery.go`
    (plus tests and a `go.mod` change) and refactors about 130 lines of upstream
    `internal/oci/verify.go` (referrer discovery became `discoverSignatureBundle`,
    which falls back to the legacy `sha256-<digest>.sig` tag). The `cosign` step
    must keep tag discovery, otherwise images signed only through a tag (for
    example `wiz-sensor`) cannot be verified, so reverting means moving the logic
    into the hooks package, not dropping it. Result: `verify.go` returns to the
    upstream version and the fork has no edits left in upstream files, which
    removes the costliest rebase conflict. Cost: discovery, bundle parsing and
    verification are chained in `verify.go` today, so the `cosign` provider may
    need its own copy of part of the upstream verification code, which then must
    be re-synced by hand when upstream changes it (security-relevant code).
    Alternative to weigh: offer the tag discovery to upstream as a PR; if
    accepted, neither a patch nor a copy has to be maintained.
  - Setting both `verify` and a `cosign` step on one entry verifies twice;
    reject it or warn.
  - V1 and V2 then become extra `cosign` steps. Per-platform verification (V1)
    will be one work unit per `tag x platform`, counted by the step
    `concurrency` like `wizcli` scans (see S5).

- **S13. `hooks.post` design (not planned yet).** Same ordered-list shape and
  step interface as `hooks.pre`, run after the copy. Open points:
  - Level: per tag only, as for `hooks.pre`. End-of-run work (notification,
    report archiving, metrics, cleanup) is not a post hook; it reads the
    `-o json` report in the CronJob script.
  - Failure: the copy cannot be undone, so a failing step can only warn or mark
    the tag (a status such as `post-failed`, with its own exit-code rule). Decide
    whether it affects the exit code at all.
  - Input: destination digest and tag, source tag, copy result (copied,
    overwritten); steps do not run for skipped, drifted or failed tags unless a
    step opts in. `--dry-run` does not run them.
  - Retries: a failed post step must not re-run the copy; it has its own
    per-step `retries` and `timeout`, same as pre steps (see S5).
  - Providers worth building first: `tag` (alias tags) and `cosign-sign`; others
    are listed in S11 and may stay in the CronJob script.

- **S14. `limit` versus blocking steps (decide before building).** The selector
  (regex, semver, sort, limit) works on the whole tag list and stays upstream
  code, ahead of the per-tag pipeline; per-tag filters (cooling-off period, tag
  allowlist) are `skip` steps in `hooks.pre`, not part of the selector. Because
  `limit` applies first, with `limit: 1` a blocked latest tag leaves the entry
  with nothing mirrored instead of falling back to the next tag. Options: (A)
  keep it: simple, and the run reports the block; (B) apply `limit` to the tags
  that pass the steps: matches "mirror the latest acceptable version" but must
  run the steps on more candidates than copied, and the pipeline order changes.
  Decided: (A), documented. A blocked tag occupies a `limit` slot, so with
  `limit: 1` a blocked latest tag leaves nothing mirrored for that entry.
  Revisit (B) only if blocks turn out to be common.

- **S15. `cosign-sign` post step: sign the destination digest with our own key
  (later).** For upstream images that have no signature, or when consumers must
  trust one organization key instead of each upstream identity. Per tag, after a
  successful copy, on the destination digest. Open points:
  - Key source: AWS KMS (`awskms://`, works with the IRSA setup already used for
    ECR) as the first choice, then a key from a mounted Secret; the key is never
    in the config file, only a reference. Keyless signing needs an OIDC identity
    that a CronJob normally does not have.
  - Where the signature goes: an OCI 1.1 referrer on the destination digest or
    the legacy `sha256-<digest>.sig` tag, matching what the consumers' verifiers
    read. Check how `includeReferrers` (upstream signatures copied as is)
    coexists with ours.
  - Idempotent: skip when a valid signature by this key already exists, and run
    for `skipped` (up-to-date) tags too so a failed earlier signing is repaired.
  - Annotations to record: source reference and digest, mirror time. Rekor
    upload is optional (private registries may disable it).
  - Not for `destinationType: artifactory` (a `.tgz` file, no OCI digest).
  - Consumers verify with `cosign verify --key`; this pairs with V7, which is
    key-based verification of the source. Check whether the cosign library used
    by `verify` already provides signing, to avoid a new dependency.
  - Failure only warns or marks the tag (copy cannot be undone), see S13.
- **S16. Scope boundary: admission versus continuous scanning.** `hooks.pre`
  gates content at mirror time only. Tags that are already mirrored (equal
  digest, so skipped) are not verified or scanned again, and the mirror does not
  re-check trust state later (signature revoked, new vulnerabilities, a policy
  that became stricter such as end of life). That belongs to continuous scanning
  of the destination registries, which is a separate process:
  - ECR: Amazon Inspector enhanced scanning (continuous rescans).
  - Wiz: the registry connector for ECR, with results in the same portal.
  - Artifactory: Xray, if licensed (also covers Helm charts).
  Use the same policy set for admission and for continuous scanning, otherwise
  content passes the gate and is flagged right after. The action on a finding
  (quarantine, delete, alert) is taken on the destination side or in Wiz, not by
  flux-mirror; B8 (prune) only covers tags the source no longer has. The
  `wiz-api` provider (S7) and a post step that asks the connector to scan a new
  digest (S11) are links to this process, not replacements for it.
- **S17. Delivering `wizcli` to the CronJob: initContainer (decided, done).**
  flux-mirror
  runs `wizcli` as a subprocess in the main container, so the binary must be on
  its filesystem. Chosen: an initContainer copies the binary from a dedicated
  internal image into an `emptyDir` that the main container mounts (for example at
  `/opt/wiz`), and flux-mirror takes the binary path from its config (default
  `wizcli` on `PATH`), so the code does not depend on the deployment.
  - Why not the flux-mirror image: it would grow from a small alpine image by
    about 272 MB, tie the `wizcli` version to flux-mirror releases, and
    redistribute a Wiz binary if the image (`ghcr.io/ksdpmx/flux-mirror`) is public.
  - Why not a sidecar: `exec` cannot cross containers and `wizcli` has no server
    mode, so a sidecar would need a custom agent and a file protocol; an ordinary
    sidecar also keeps a Job from finishing (native sidecars, Kubernetes 1.28 or
    later, would be needed).
  - The `wizcli` image: built by us from `alpine` plus the `downloads.wiz.io`
    binary with a pinned version and its sha256, pushed to the private ECR. Check
    whether Wiz publishes an official container image and use it if so.
  - Chart work (done): an initContainer copies the binary into an `emptyDir`
    mounted read-only at `/opt/wiz`, and the chart sets the step's
    `wizcli.binary` to `/opt/wiz/wizcli`; a second `emptyDir` at `/tmp/wizcli`
    with a configurable `sizeLimit` (`initContainers.wizcli.workDirSizeLimit`,
    default `2Gi`, about `concurrency` image tarballs at a time) holds tars and
    the `wizcli` state, with `HOME` and `TMPDIR` pointing to it; the Wiz service
    account comes from the ExternalSecret; the image tag is a value. Only the
    CronJobs whose group has a wizcli step get these.
  - Verified: the CronJob runs in Kubernetes with the Linux binary, which
    covers the alpine run, the Wiz egress and memory use. Still open: the
    `AUDIT`-only verdict (S1).
- **S18. The `cosign` step verified signatures only, not attestations
  (tag path done; referrers and per-platform open).** Both discovery paths look
  for a signature and nothing else:
  - Referrers (`cosign_discovery.go`): only a sigstore bundle, that is a
    referrer whose media type starts with `application/vnd.dev.sigstore.bundle`
    and is version `v0.3` or later.
  - Tag discovery (`cosign_tag_discovery.go`): only `sha256-<digest>.sig`, with
    layer media type `application/vnd.dev.cosign.simplesigning.v1+json`, and it
    needs a certificate (keyless). `sha256-<digest>.att` is never read.
  - So an SBOM, a SLSA provenance or any other attestation is neither required
    nor checked, even when it exists or was tampered with. `includeReferrers`
    only copies those referrers as they are. `matchOIDCIdentity` limits who
    signed the image, not what is attached to it.
  - Documented in `docs/config.md` (the `cosign` step): only the listed
    attestation types are checked, and only through the `.att` tag.
  - **Risk to verify: the referrers path takes the first sigstore bundle,
    whatever it holds.** `findReferrerSigstoreBundle` returns the first referrer
    with a single layer whose media type starts with
    `application/vnd.dev.sigstore.bundle`, and verification uses only that one.
    An attestation published as a bundle (a DSSE envelope with an in-toto
    statement) has the same media type as a signature bundle, so it is a
    candidate too. Possible effects, from reading the code and not yet tested:
    the result depends on the order of the referrers; an attestation that comes
    first and fails the identity or digest check denies the tag even though a
    valid signature bundle follows; and an attestation signed by a trusted
    identity for the same digest can pass as if it were the signature. To check
    first: list the referrers of a real `cgr.dev` image, count the bundles and
    look at their order and content type. If confirmed, accept only a bundle
    whose content is a message signature (skip DSSE attestations) and try every
    candidate before denying, with a test for each order. The tag path is not
    affected, because it reads one fixed tag.
  - If attestation checks are wanted: decide the shape first, for example a
    `requireAttestations` list of predicate types (`slsaprovenance`, `spdx`,
    `cyclonedx`, `vuln`) verified against the same `matchOIDCIdentity`, found
    through referrers and the `.att` tag; whether a missing attestation denies or
    only warns (`onFailure`); and, per platform, the work units (S5).
    Chainguard publishes both signatures and attestations, so check a real
    `cgr.dev` image first.
  - **Spike result for the tag path (2026-11-09, `cgr.dev/chainguard/static`,
    sigstore-go 1.3.0): attestations can be verified.**
    - Layout of a multi-arch image: the index and each platform manifest have
      their own `sha256-<digest>.sig` and `.att`. A `.att` manifest has one layer
      per predicate (`https://slsa.dev/provenance/v1`, `https://spdx.dev/Document`,
      `https://apko.dev/image-configuration`). Each layer is a DSSE envelope
      (`application/vnd.dsse.envelope.v1+json`) whose in-toto statement has the
      digest of the image it is attached to as its subject (the index digest for
      the index `.att`, the platform manifest digest for a platform `.att`).
      The signature material is in the layer annotations
      (`dev.cosignproject.cosign/signature`, `/certificate`, `/chain`, `/bundle`),
      like a `.sig`.
    - Verification works: a bundle built from one layer (the DSSE envelope as
      content, the same certificate chain and Rekor SET handling as for a `.sig`,
      bundle version `0.1`) passed `verify.Verify` with `WithArtifactDigest` and a
      certificate identity, for all three layers of the index and of the amd64
      manifest. The Rekor entry kind is `dsse` (`0.0.1`), not `intoto`, so
      `decodeCosignTagTlogEntries` needs no change.
    - Negative cases fail as wanted: an artifact digest that is not the
      statement subject (`provided artifact digest does not match any digest in
      statement`) and a non-matching identity (`no matching CertificateIdentity
      found`).
    - Take the predicate type from the verified statement
      (`result.Statement.PredicateType`), never from the layer annotation
      `predicateType`, which is not signed.
    - The public Chainguard images are signed by the GitHub Actions workflow
      identity (`https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main`,
      issuer `https://token.actions.githubusercontent.com`), not by
      `issuer.enforce.dev` as in our `matchOIDCIdentity`. Check that the same
      identity signs the `.att` of our own `cgr.dev` org images before reusing the
      signature identities for attestations; allow a separate `matchOIDCIdentity`
      per attestation if they differ.
    - Decided: scope is the index only for now (no per-platform units, so the
      work-unit model stays one unit per tag); the list is
      `cosign.attestations`, each item a short alias (`spdx`, `slsa-provenance`,
      `cyclonedx`, a small fixed set) or a full predicate type URI. Open: implement
      as a single change (discovery with a `.att` suffix, a DSSE bundle builder,
      config and validation, the verified predicate types in the report, docs,
      chart schema and tests); per-platform checks wait for S5.
    - The spike program was in `/tmp/spike` (not in the repository): it fetched
      `<digest>.att`, built a bundle per layer and ran `verify.Verify`.
  - **Implemented (tag path, index digest only).** `cosign.attestations` takes
    aliases (`spdx`, `slsa-provenance`, `cyclonedx`) or predicate type URIs;
    `internal/hooks/cosign_attestation_discovery.go` rebuilds each `.att` DSSE
    layer as a bundle, and `Verifier.VerifyAttestations` (in
    `internal/oci/verify_discovery.go`, so `verify.go` stays identical to
    upstream) verifies each bundle against the digest and the same
    `matchOIDCIdentity`, then requires every listed predicate type among the
    verified statements. A missing type denies the tag; `cosign.attestations` in
    the report lists the verified types. Checked end to end against
    `cgr.dev/lexisnexislegal.com/amazon-k8s-cni-init:v1.23.2`: the four
    attestations (SLSA provenance, CycloneDX, SPDX, apko configuration) verify
    with the same `https://issuer.enforce.dev/...` identity as the signature, so
    no separate attestation identity was needed, and requiring a type that is not
    attached blocks the tag. Tests use sigstore-go's virtual sigstore, which adds
    indirect test dependencies to `go.mod`.
  - Still open: attestations through the referrers path (and the first-bundle
    risk above), per-platform `.sig`/`.att` (S5), an optional identity per
    attestation if one is ever signed by another identity, and `.att` layers that
    cannot be read are skipped without a message (the denial only names the
    missing type and the counts).

## Backlog

- **B1.** `charts` Helm source should reuse `hosts` auth. Today
  `helmrepo.HTTPSource` only reads Helm `repositories.yaml`
  (`HELM_REPOSITORY_CONFIG`) and builds its own `http.Client`, so `hosts` is
  ignored. Match by host, use the shared transport, fall back to
  `repositories.yaml` (keeping its TLS/CA settings).
- **B2.** `index.yaml` is cached per `HTTPSource` only, so several `charts`
  entries with the same source URL download it repeatedly (can be tens of MB).
  Share a per-run cache keyed by normalized repo URL.
- **B3.** `charts` drift check downloads every tgz even when already synced.
  Compare the `digest` in `index.yaml` against the destination first and skip
  the download when equal. Behavior change; handle indexes without `digest`.
- **B4.** `artifacts` `verify` still runs serially inside `Plan`, including
  with `--dry-run`; only the digest and referrer snapshot run under
  `--concurrency` (planning concurrency). Move verification into jobs so it
  runs under the concurrency limit while preserving: stop after the first
  verify failure, `signature-too-new` skips, entry-level failure when no digest
  is returned, report row order and `Verification` fields.
- **B5.** Other `destinationType` values (chartmuseum, nexus, ...).
- **B6.** Chart tgz is fully buffered in memory (up to 100MB each, times
  concurrency, plus `LoadArchive`).
  - helm repo source: stream only when needed if `index.yaml` has `digest`;
    otherwise spool to a temp file while hashing.
  - `charts` to OCI: spool to a temp file; read only `<chart>/Chart.yaml` from
    the tar stream instead of `loader.LoadArchive` (keep the checks that
    `Chart.yaml` exists and name/version are non-empty).
  - `artifacts` image to OCI is already streamed by crane; no change.
  - Optionally bound in-memory bytes across jobs with a weighted semaphore.
- **B7. Retag on sync.** Today the destination tag always equals the source tag.
  This is a core feature, not a hook. Post: a post step could only add an alias
  after copying under the source tag, which leaves the source tag behind (it
  cannot be deleted on immutable repositories) and breaks the up-to-date and
  drift checks, which compare the destination tag. Pre: a step that rewrites the
  destination tag conflicts with the hook rules, because `--dry-run` must still
  report the mapped tag, up-to-date tags must be mapped to be compared (S5 skips
  hooks for them), and collisions are only visible at entry level. So compute
  the mapped tag in `Plan` before the hooks run, and hand both tags to them.
  Adding extra alias tags
  (`stable`, `mirror-1.2.3`) is a different feature and fits a post `tag`
  provider (see S11).
  Allow a per-entry template that derives the destination tag from the source
  tag (examples: add a prefix or suffix, strip a leading `v`, add a date).
  Open points:
  - Template syntax: reuse the selector's regex expand (`$version`, named groups
    from `selector.regex`) for consistency, or a Go template with variables such
    as `{{ .Tag }}` and `{{ .Version }}`. Decide which variables exist (tag,
    regex groups, digest).
  - Collisions: two selected source tags that map to one destination tag must be
    rejected at plan time (an entry-level error), and the destination tag must be
    a valid OCI tag.
  - Selection, `limit` and sorting stay on the source tags; the up-to-date and
    drift checks compare the mapped destination tag.
  - Signatures and referrers are found by digest, and the cosign `.sig` tag name
    derives from the digest, so they are unaffected; check the referrer copy
    uses the same digest and not the tag.
  - `destinationType: artifactory` requires the chart version to equal the tag,
    so retagging is rejected there. `charts` to OCI could use it (the tag is the
    version with `+` as `_`); `charts` to Artifactory cannot.
  - Report: a tag row has one `tag` today; add the destination tag (for example
    `destinationTag`) and regenerate the schema; hooks should receive both tags.
  - Helm chart: `mirror.defaults.artifacts` and per-entry value, and a test for
    the rendered config.
- **B8. Source tag deleted: no prune today.** A tag removed from the source is
  not in `ListTags`, so it produces no job, no report row and no deletion; the
  destination copy stays. With `limit`, a removed latest tag makes the selector
  pick the next one, so the destination ends up with both. Nothing signals that
  the source lost a tag. Possible features, off by default:
  - Report only: list destination tags that match the selector but are gone from
    the source (for example `orphaned` rows), with no deletion.
  - `prune: true` on an entry: delete such destination tags. Risks: immutable
    repositories and missing delete permissions (ECR, GAR, Artifactory), removing
    an image still in use, a source outage or listing error looking like "all
    tags gone" (never prune on a failed or empty listing), and the selector
    `limit` window shifting (prune only tags that match the selector's regex and
    semver, never because they fall outside `limit`). Needs `--dry-run` preview,
    its own status and exit-code rule, and a per-run cap.
  - Not for `destinationType: artifactory` first (file deletion semantics).
  - Interacts with S12: if upstream withdraws a tag for security reasons, a
    prune would remove the copy, otherwise detection is left to scanning on the
    destination side.

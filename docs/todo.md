# Fork TODO: Helm repo publishing and verify

Status: `destinationType: artifactory` is implemented for `artifacts` and for
`charts` (OCI Helm chart or HTTP/S Helm repo source to a JFrog Artifactory Helm
repository); see
[Publishing to a Helm repository](config.md#publishing-to-a-helm-repository) and
[Publishing charts to a Helm repository](config.md#publishing-charts-to-a-helm-repository).
`artifacts` and `charts` were both checked against a real JFrog instance.
This file tracks what is still open.

## Open: charts selector

Next, now that `charts` can publish to Artifactory: the `selector` refactor.

- **C0.** Align `charts` version selection with `artifacts` by adding
  `charts[].selector`, the same `Selector` type and `validateSelector` as
  `artifacts` (`regex.pattern`, `regex.extract`, `semver`, `sortBy`, `limit`).
  - `charts[].version` is kept but deprecated: it is an alias for
    `selector.semver`. Setting both `version` and `selector.semver` is a
    validation error. The flat `limit` is kept the same way, as an alias for
    `selector.limit` (inferred, not explicitly agreed); setting both is an
    error.
  - Defaults, deliberately different depending on whether `selector` is set:
    - With `selector`: identical to `artifacts`. No `semver` means no semver
      filter, so prereleases are included (and the default `limit: 1` can pick a
      release candidate). Document this in `docs/config.md`.
    - Without `selector` (existing configs): unchanged legacy behavior,
      `version` defaults to `"*"` and excludes prereleases.
  - Plan: use the entry's selector in `internal/charts/mirror.go` (today it
    builds `Selector{Semver: version, Limit}` only), validate in
    `internal/config`, `make generate`, docs, tests (regex with `extract`,
    prerelease with and without `selector`, alias conflicts).
  - Resolves the `charts` half of T5.
- **C4.** `artifacts` with `destinationType: artifactory` takes the file name
  from the OCI config blob and only compares `version` with the tag. It does not
  check `name`, nor compare the blob with the tarball (the tarball is streamed).
  `charts` now checks both against `Chart.yaml` before an upload; consider a
  `name` check for `artifacts` too.
- Out of scope for the above: B1 (source auth via `hosts`), B2, B3, T5's
  `artifacts` default, V8.

## Follow-ups from real-world testing

- **T1.** A wrong repository path is not caught by `--dry-run`: a `HEAD` 404
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
- **T4.** With `destinationType: artifactory`, a host `credential` that sets
  `username` is resolved through `registryauth.ResolveHostAuth` on every HTTP
  request. A `credential.provider` token source (for example `github`) therefore
  mints a new token per `HEAD`/`PUT`, bypassing the sync token cache, which only
  covers cloud `provider` hosts. Static `value`/`fromPath` and the bearer path
  (no `username`) are unaffected. Resolve once per entry or route it through the
  token cache.
- **T5.** `charts` and `artifacts` select versions differently, so prerelease
  handling is inconsistent:
  - `charts[].version` defaults to `"*"`, so the semver constraint always
    applies and prereleases are excluded. Only a constraint with a prerelease
    suffix (for example `">=1.0.0-0"`) includes them. `charts` has no regex,
    `sortBy`, or `selector`.
  - `artifacts[].selector.semver` has no default, so with no `semver` and no
    `regex` every tag that parses as semver is kept, prereleases included. Sorted
    by semver, `1.2.0-rc.1` ranks above `1.1.0`, so the default `limit: 1` picks
    the release candidate. Adding `semver: "*"` or a `regex` excludes it.
  - Decide whether to align the two (for example default `artifacts` to exclude
    prereleases, add an explicit opt-in, or give `charts` a `selector`), and
    document the behavior in `docs/config.md` either way. Changing the
    `artifacts` default alters which tags existing configs mirror.
  - Decided for `charts`: add `charts[].selector` with `artifacts` semantics (see
    C0). Still open: whether the `artifacts` default should change.
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

# Fork TODO: Helm repo publishing and verify

Status: `artifacts` with `destinationType: artifactory` is implemented and
checked against a real JFrog instance; see
[Publishing to a Helm repository](config.md#publishing-to-a-helm-repository).
This file tracks what is still open.

## Open: charts to a Helm repo

- **C1.** Add `charts[].destinationType` (`oci | artifactory`, default `oci`)
  with the same semantics as `artifacts`: the destination is the directory URL
  (scheme optional, `http://` only with `--insecure`) and no chart name is
  appended. This differs from `charts` to OCI, which appends `/<name>`.
- **C2.** Extract a `chartSink` in `internal/charts` (OCI and Artifactory
  implementations) on top of `helmrepo.Pusher`; plan, drift, and outcome logic
  stay unchanged.
- **C3.** Config validation, `docs/config.md`, `examples/`, tests.

## Follow-ups from real-world testing

- **T1.** A wrong repository path is not caught by `--dry-run`: a `HEAD` 404
  means "file absent", so dry-run reports `would-copy` and the failure only
  shows at `PUT` (for example a missing `/artifactory` context path). The `PUT`
  404 now carries a hint; probing the repository in `Plan` would surface it
  earlier.
- **T2.** Unknown config fields are ignored silently (for example `name:` under
  `artifacts`, which is not a field). Consider strict decoding or a warning in
  `config.Decode`; rejecting them would break existing configs.
- **T3.** Only the `artifacts` to Helm repo path (`destinationType:
  artifactory`) has structured verbose logs (`event`, `source`, `tag`,
  `destination`, `status`, `digest`, `reason`, `error`, `elapsed`). Everything
  else still logs ad hoc fields and should move to the same schema, so that
  `--log-format json` is uniform:
  - `artifacts` to OCI (`internal/artifacts/mirror.go`): `mirroring tag`,
    `tag done`, drift and referrer warnings, `signature too new` use `src`/`dst`
    and no `event`.
  - `charts` (`internal/charts/mirror.go`): `mirroring chart` / `chart done` use
    `chart`/`dst` and no `status` on drift.
  - runner (`internal/sync/runner.go`): `sync started`, `entry started/finished`,
    `plan failed`, `job failed, retrying` have no `event`; failed jobs are only
    logged on the Helm repo path (`chart.failed`).
  - Selector exclusions (`tag excluded by selector`, `version excluded by
    selector`) and the crane progress lines (in JSON they are only wrapped, not
    structured).
  - Decide whether the text format should also show durations in a single unit
    (it prints Go notation such as `850ms` / `4.227s`, while JSON uses seconds).
  - Decide whether the text format should include `msg=` and `level=` like
    JSON. `plainHandler` (`cmd/flux-mirror/logging.go`) is shared by every slog
    line in verbose mode, so changing it (for example to the standard
    `slog.TextHandler` logfmt) is a global change: all lines would become
    `time=… level=INFO msg="…" k=v` with RFC3339 times, and `docs/sync.md`
    examples and tests would need updating. crane's own progress lines would
    still be plain `log` lines in text mode. Today text lines already carry
    `event=…` on the Helm repo path; use `--log-format json` for `msg`/`level`.

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

## Backlog

- **B1.** `charts` Helm source should reuse `hosts` auth. Today
  `helmrepo.HTTPSource` only reads Helm `repositories.yaml`
  (`HELM_REPOSITORIES_CONFIG`) and builds its own `http.Client`, so `hosts` is
  ignored. Match by host, use the shared transport, fall back to
  `repositories.yaml` (keeping its TLS/CA settings).
- **B2.** `index.yaml` is cached per `HTTPSource` only, so several `charts`
  entries with the same source URL download it repeatedly (can be tens of MB).
  Share a per-run cache keyed by normalized repo URL.
- **B3.** `charts` drift check downloads every tgz even when already synced.
  Compare the `digest` in `index.yaml` against the destination first and skip
  the download when equal. Behavior change; handle indexes without `digest`.
- **B4.** `artifacts` `verify` runs serially inside `Plan`, including with
  `--dry-run`. Move it into jobs so it runs under the concurrency limit while
  preserving: stop after the first verify failure, `signature-too-new` skips,
  entry-level failure when no digest is returned, report row order and
  `Verification` fields.
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

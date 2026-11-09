---
weight: 60
---

# Flux Mirror Report

The `flux mirror sync` command can emit a structured report of the mirror
results by setting `--output` to `json` or `yaml`. The envelope shape is
versioned and documented by the JSON Schema in
[`report-v1beta2.json`](report-v1beta2.json); the deprecated
[`report-v1beta1.json`](report-v1beta1.json) remains published for existing
reports.

## Usage

```shell
flux mirror sync config.yaml -o json
```

Structured output always emits every entry regardless of `--verbose`.
Filtering belongs downstream (`jq`, `yq`). The process exit code still
reflects whether any tag failed or drifted (see [exit codes](sync.md#exit-codes)).

## Envelope

Every report is wrapped in a top-level envelope:

| Key                 | Description                                                  |
|---------------------|--------------------------------------------------------------|
| `apiVersion`        | Report API version. Currently `mirror.plugin.fluxcd.io/v1beta2`.    |
| `kind`              | Report API kind. Currently `Report`.                         |
| `$schema`           | URL of the JSON Schema describing the envelope. JSON only.   |
| `report.reporter`   | Identity of the producer, e.g. `flux-mirror/v0.1.0`.         |
| `report.timestamp`  | RFC 3339 UTC timestamp of the run.                           |
| `report.durationMs` | Total wall time of the run, in milliseconds.                 |
| `report.summary`    | Aggregate counts across all entries (see below).             |
| `report.results[]`  | One entry per config entry, in config order.                 |

The `$schema` key is JSON-only — it points at a JSON Schema document and
carries no meaning for YAML consumers, so it is dropped in YAML mode.

## Summary fields

Every field is always present (zero when unused) so consumers can rely on a
stable key set.

| Key              | Description                                                                                  |
|------------------|----------------------------------------------------------------------------------------------|
| `entries`        | Number of config entries processed.                                                          |
| `copied`         | Total tags copied across all entries.                                                        |
| `overwritten`    | Total tags overwritten (drift with `overwrite: true`).                                       |
| `skipped`        | Total tags skipped (already up to date, or deferred by `verify.minAge`).                     |
| `drifted`        | Total tags drifted (different digest, `overwrite: false`), including entries with `ignoreDriftForExitCode: true`. |
| `wouldCopy`      | Dry-run forecast: tags that would have been copied.                                          |
| `wouldOverwrite` | Dry-run forecast: tags that would have been overwritten.                                     |
| `failed`         | Total failures: tag-level failures plus plan-failed entries.                                 |
| `blocked`        | Total tags rejected by a hook policy.                                                       |
| `exitCode`       | Semantic exit code: `0` clean, `1` failures, `2` drift, `3` blocked. Drift on entries with `ignoreDriftForExitCode: true` is excluded. Not affected by CLI exit-code overrides. |

## Result fields

Each `results[]` entry describes one config entry (an artifact or chart source).

| Key           | Description                                                      |
|---------------|------------------------------------------------------------------|
| `source`      | Source repository/reference being mirrored.                      |
| `destination` | Destination repository the entry mirrors into.                   |
| `status`      | Entry-level outcome: `completed` or `failed`.                    |
| `error`       | Plan-time error message. Present only when `status` is `failed`. |
| `ignoreDriftForExitCode` | `true` when the entry's drifted tags were excluded from the exit code. |
| `tags[]`      | Per-tag results, in plan order (deterministic). May be empty.    |

The entry `status` disambiguates an empty `tags` array:

- `completed` + `[]` → the entry was planned and run, but nothing matched the selector.
- `failed` + `[]` (+ `error`) → the entry could not be planned (e.g. tag listing failed).

A `completed` entry can still contain tag-level `failed` rows — those are per-tag
problems, not an entry-level failure.

## Tag fields

| Key            | Description                                                                                     |
|----------------|-------------------------------------------------------------------------------------------------|
| `tag`          | Tag name (artifacts) or chart version (charts).                                                 |
| `status`       | Per-tag outcome — see [Status](#status-values).                                                 |
| `digest`       | Source artifact digest, when resolved. Absent on a verify-failed row.                           |
| `reason`       | Why a tag was skipped, or the hook name that blocked it.                                          |
| `error`        | Error message. Present only when `status` is `failed`.                                          |
| `referrers[]`  | Mirrored sub-artifacts (signatures, SBOMs, attestations). Present only with `includeReferrers`. |
| `verification` | Signature verification metadata. Present only when a signature was confirmed (under `verify:`). |
| `steps[]`      | Hook step results, in execution order; omitted when no hook ran.                                |

### Status values

| Status            | Meaning                                                              |
|-------------------|----------------------------------------------------------------------|
| `copied`          | Destination did not have it; mirrored from source.                   |
| `overwritten`     | Destination had a different digest; replaced (`overwrite: true`).    |
| `skipped`         | Nothing copied; see `reason`.                                        |
| `drifted`         | Destination has a different digest, `overwrite: false` — left alone. |
| `would-copy`      | Dry-run: would have been copied.                                     |
| `would-overwrite` | Dry-run: would have been overwritten.                                |
| `blocked`         | A hook policy rejected the tag before copying.                       |
| `failed`          | The operation errored; see `error`.                                  |

### Reason values

For a `skipped` status, `reason` is always present and uses the values below.
For a `blocked` tag, `reason` is the hook step name.

| Reason              | Meaning                                                                       |
|---------------------|-------------------------------------------------------------------------------|
| `up-to-date`        | Destination already has the same digest.                                      |
| `signature-too-new` | A valid signature was deferred because it is younger than `verify.minAge`.    |

## Referrer fields

Each `referrers[]` entry describes one referrer (e.g. a cosign signature bundle, an
SBOM, or an attestation) mirrored alongside its parent tag.

| Key            | Description                                                |
|----------------|------------------------------------------------------------|
| `digest`       | Referrer manifest digest.                                  |
| `artifactType` | The referrer manifest's `artifactType`, when set.          |
| `status`       | Same [Status](#status-values) enum as a tag.               |
| `reason`       | Present only on `skipped` (same [Reason](#reason-values)). |

Referrers are reported for any tag whose mirror flow reached the referrer step — every
status except `failed` (the tag copy errored first) and the `signature-too-new` skip
(deferred without mirroring). In `--dry-run`, referrers are still evaluated and reported
with `would-copy` / `would-overwrite` / `skipped` statuses.

## Verification fields

Present only when a signature was confirmed (the entry has a `verify:` block). Only
`provider` is guaranteed; the rest is best-effort.

| Key              | Description                                                                                          |
|------------------|------------------------------------------------------------------------------------------------------|
| `provider`       | Verification provider, e.g. `cosign`.                                                                |
| `issuer`         | Matched OIDC issuer from the signing certificate.                                                    |
| `identity`       | Matched certificate identity (subject alternative name).                                             |
| `integratedTime` | Transparency-log integration time (RFC 3339). Present only when the bundle carries a Tlog timestamp. |
| `age`            | Signature age, as a Go duration string. Present only on a `signature-too-new` skip.                  |
| `minAge`         | Configured `verify.minAge`, as a Go duration string. Present only on a `signature-too-new` skip.     |

## Hook step fields

Each `steps[]` row records one pre-copy hook: `name`, `provider`, `verdict`
(`allow`, `deny`, `skip`, or `error`), `attempts`, and `duration`. `reason` is
present for a deny or skip; `error` is present when the step exhausted its
infrastructure retries. A cosign step includes its confirmed signature
metadata in the typed `cosign` object. A denied tag has `status: "blocked"` and
its tag-level `reason` is the step name; provider details remain in `steps[]`.
Errors with `onFailure: block` produce a failed tag, while `onFailure: warn`
records the error and lets mirroring continue.

| Key        | Description                                                        |
|------------|--------------------------------------------------------------------|
| `name`     | Configured step name.                                              |
| `provider` | Hook provider, such as `cosign`.                                   |
| `verdict`  | `allow`, `deny`, `skip`, or `error`.                                |
| `reason`   | Provider explanation for a deny or skip.                           |
| `error`    | Infrastructure error after retries.                                |
| `attempts` | Number of attempts made.                                           |
| `duration` | Total step time, including retries, as a Go duration string.       |
| `cosign`   | Verified signature metadata for a passing cosign step, when set.   |

A verify *failure* (bad/missing signature, OIDC mismatch) is not a `verification` block:
it surfaces as a `status: "failed"` tag row carrying the verify `error`, with no
`verification` and no `digest`. Verification runs at plan time, so the first verify
failure stops the entry (tags verified before it still run); the entry itself stays
`status: "completed"`. A real verify-failed row (the configured OIDC subject regex
did not match the signed identity):

```json
{
  "tag": "6.13.0",
  "status": "failed",
  "error": "verify docker.io/stefanprodan/podinfo:6.13.0: signature verification failed: failed to verify certificate identity: no matching CertificateIdentity found, last error: expected SAN value to match regex \"^https://github\\.com/example/.*$\", got \"https://github.com/stefanprodan/podinfo/.github/workflows/release.yml@refs/tags/6.13.0\""
}
```

## Example

A report from `flux mirror sync … -o json` against a config with cosign
verification (`minAge: 48h`) and `includeReferrers: true`. The first entry
completed: tag `6.13.0` was deferred because its signature is younger than
`minAge`, while `6.12.0` was copied along with its cosign signature bundle. The
second entry failed at plan time because the source repository does not exist.

```json
{
  "apiVersion": "mirror.plugin.fluxcd.io/v1beta2",
  "kind": "Report",
  "$schema": "https://raw.githubusercontent.com/fluxcd/flux-mirror/main/docs/report-v1beta2.json",
  "report": {
    "reporter": "flux-mirror/v0.1.0",
    "timestamp": "2026-06-06T20:12:25Z",
    "durationMs": 16724,
    "summary": {
      "entries": 2,
      "copied": 1,
      "overwritten": 0,
      "skipped": 1,
      "drifted": 0,
      "wouldCopy": 0,
      "wouldOverwrite": 0,
      "failed": 1,
      "blocked": 0,
      "exitCode": 1
    },
    "results": [
      {
        "source": "docker.io/stefanprodan/podinfo",
        "destination": "localhost:5050/podinfo",
        "status": "completed",
        "tags": [
          {
            "tag": "6.13.0",
            "status": "skipped",
            "digest": "sha256:7bdd8cc80b64377b05f5c0a51604c028ed6adea4beaca2e766b9325efa52916c",
            "reason": "signature-too-new",
            "verification": {
              "provider": "cosign",
              "issuer": "https://token.actions.githubusercontent.com",
              "identity": "https://github.com/stefanprodan/podinfo/.github/workflows/release.yml@refs/tags/6.13.0",
              "integratedTime": "2026-06-04T20:59:02Z",
              "age": "47h13m11s",
              "minAge": "48h0m0s"
            }
          },
          {
            "tag": "6.12.0",
            "status": "copied",
            "digest": "sha256:453e2238f70c00dfba6803ddb99a4bb86982ee549f7273f43f90ac58f0714a81",
            "referrers": [
              {
                "digest": "sha256:5892f840c5013230cd0b63fdd5076dd9fe3224a31bd3ebae5c723e3632100b0f",
                "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "status": "copied"
              }
            ],
            "verification": {
              "provider": "cosign",
              "issuer": "https://token.actions.githubusercontent.com",
              "identity": "https://github.com/stefanprodan/podinfo/.github/workflows/release.yml@refs/tags/6.12.0",
              "integratedTime": "2026-05-20T10:16:39Z"
            }
          }
        ]
      },
      {
        "source": "docker.io/library/flux-mirror-nonexistent-zzz",
        "destination": "localhost:5050/nonexistent",
        "status": "failed",
        "error": "list tags docker.io/library/flux-mirror-nonexistent-zzz: GET https://index.docker.io/v2/library/flux-mirror-nonexistent-zzz/tags/list?n=1000: UNAUTHORIZED: authentication required; [map[Action:pull Class: Name:library/flux-mirror-nonexistent-zzz Type:repository]]",
        "tags": []
      }
    ]
  }
}
```

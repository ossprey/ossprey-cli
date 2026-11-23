# OSSBOM model and API client

[Back to the internals index](README.md).

## OSSBOM model (`internal/ossbom`)

`SBOM` is the rich internal model. `MiniBOM` (`minibom.go`) is the compressed
wire format sent to the API — each component becomes `{purl, source, env, location}`
with `purl = pkg:<type>/<name>@<version>`, plus a `vcs_url`/`repository_url`
qualifier for a git or private-registry crate (OSS-2484). The Go model mirrors the Python
`ossbom` library referenced in comments; keep them in sync when the API contract
changes.

## API client (`internal/client`)

`Validate` POSTs the MiniBOM to `/public/v1/scans`, then polls
`/public/v1/scans/status` (capped at `OSSPREY_VERDICT_TIMEOUT`, default
`maxPollAttempts` x `pollInterval` = 15m), and
refuses outright for an ingest client (see "Passive modes and monitor ids"). A
quota-exhausted response surfaces as a typed `*ErrSkipped` that propagates
unwrapped so callers can detect it via `errors.As` and **exit 0** rather than
failing the build (see `reportSkipped` in main.go). Credential resolution order
(`submit.NewClient`): monitor id → `--api-key` flag → stored login →
`OSSPREY_API_KEY` → `API_KEY`. The login beats env keys so a stale exported key
cannot shadow `ossprey login`.

**Transient failures are retried, definite ones are not.** A scan error and a
malware verdict share exit code `1`, so a dropped connection in CI reads as a
detection. `postScan` retries `maxSubmitAttempts` times over `RetryBackoff`, and
the status poll tolerates `maxTransientPolls` consecutive failures within its
existing attempt budget rather than adding sleeps of its own. `retryable` is
deliberately narrow — only 502/503/504. A 4xx is a real answer about the
request, and a 500 means the backend already took the SBOM, so retrying it risks
a duplicate scan against the user's quota for no better odds. Never widen that
set to "any 5xx" for symmetry. The submit endpoint has no idempotency key, so a
retry the backend had already accepted spends a second unit of quota; that is
accepted deliberately, because quota exhaustion fails **open** (`ErrSkipped`,
exit 0) and the failure it prevents fails **closed** and reads as malware. Retries wait via `sleepOrDone` so a cancelled
scan is never held open by a backoff, and `RetryBackoff` is overridable for the
same reason `PollBackoff` is: no test should sleep.

**A poll ceiling is not a scan failure.** It returns `*ErrVerdictTimeout`
naming the scan id and last status, because the scan keeps running and lands
in the dashboard; real scans do exceed 15m at peak (~02:15 UTC). The service's
`ScanExceededClientTimeout` metric counts them, so keep its threshold in step
with the default here. Network timeouts go through `explainTimeout` so a bare
`context deadline exceeded` never reaches the user.

`401`/`403` become `authError`, which names the credential the client actually
used (`--api-key`/env, a stored login, or a monitor id — see
`submit.NewClient`). The raw body is a JSON blob naming no fix, so printing it
told a user with an expired key nothing about how to recover.

`auth.Save` writes through a 0600 temp file and a rename: `os.WriteFile` applies its mode only on create, so an existing 0644 `credentials.json` stayed readable. `ossprey update` compares as semver, never as strings: plain `update`/`--check` only move forward; a downgrade needs `--version` or `--force`.

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`ossprey` is a Go CLI for the [Ossprey](https://ossprey.com) supply-chain malware
platform. It statically catalogs a project's Python/JavaScript dependencies into
an **OSSBOM**, submits it to the Ossprey API, and exits non-zero if any package
is flagged as malware. It never executes the project's package manager during a
scan (no installs, sandbox, or virtualenv) — see the custom catalogers for the
one exception.

## Commands

```sh
make build         # release binary -> bin/ossprey (-trimpath, stripped)
make build-debug   # unstripped build with symbols
make test          # go test ./...
make test-race     # go test -race ./...   (CI runs this)
make test-smoke    # end-to-end: build binary, scan test/test_packages fixtures (-tags smoke)
make test-smoke-short  # smoke tests minus network/GitHub-clone tests
make fmt           # go fmt ./...
make vet           # go vet ./...
make tidy          # go mod tidy  (run first time / after dep changes)
```

Run a single test: `go test ./internal/catalog/ -run TestName -v`.
Smoke tests live behind the `smoke` build tag: `go test -tags smoke -run TestName -v ./test/smoke/...`.

CI (`.github/workflows/ci.yml`) gates on `gofmt -l` being empty, `go vet`,
`go test`, and `go test -race`, on ubuntu and windows. Keep code gofmt-clean.
Requires Go 1.25+.

One smoke job also runs in CI: `pnpm-smoke` runs `-run TestPnpm` against a real
pnpm on both OSes, because that path can only be verified with the real binary
(pnpm on Windows is a `.cmd`, as are the shims). Tests that need the shim
directory must ask `ossprey shim dir` rather than assuming `~/.ossprey/shims` —
Windows resolves it under `%LOCALAPPDATA%`.

## Architecture

`cmd/ossprey/main.go` wires three command families with cobra:

0. **`init [path]`** (`cmd/ossprey/init.go`) — the one-command onboarding path
   (OSS-1387), in three steps: ensure a login, mint an API key, scan the project
   **with that key**. Key creation goes through `client.CreateAPIKey` on
   `/dashboard/v1/api-keys`, which **requires a bearer token** — API keys cannot
   mint API keys, so step 2 never uses `OSSPREY_API_KEY`. `ensureLogin`
   reuses/refreshes a stored login, but only when `matchesTenant` says domain,
   client ID **and** audience all agree, else a prod token would be silently
   reused against a QA `--audience`. All three matter: comparing only domain and
   audience let `--client-id <other-app>` reuse a token minted for a different
   Auth0 application. The device-flow prompt is shared with `login` via
   `runDeviceLogin`.

   Step 3 passes the **new key** to `submit.Validate` rather than falling through
   to the stored login, so a clean scan proves the credential works before the
   user wires it into CI. Note this changes the wire path: an API-key client hits
   `/public/v1` with `x-api-key`, a bearer client `/dashboard/v1`. When key
   creation fails, `keyValue` returns `""` and `submit.Validate` falls back to the
   login, so the scan still happens. That fail-**open** posture is deliberate — a
   key limit must not cost the user their scan.

   The scan is the user's **choice** (`wantScan`): `--scan`/`--no-scan` answer up
   front, otherwise an interactive terminal is prompted and a non-interactive run
   declines, printing how to opt in. Use `term.IsTerminal`, **not** `os.Stat` +
   `ModeCharDevice`, to detect interactivity — `/dev/null` is itself a character
   device, so the naive check treats `ossprey init < /dev/null` as interactive and
   silently takes the prompt default. `TestInitNonInteractiveDoesNotScan` pins
   this with a real `/dev/null` stdin.

   `--key-stdout` writes the bare key to stdout for piping into a secret store
   (`ossprey init --key-stdout | gh secret set OSSPREY_API_KEY`), so every
   human-facing line must go to `logOut` (stderr in that mode) — hence the
   `io.Writer` threaded through `ensureLogin`/`freshLogin`/`runDeviceLogin`. It is
   mutually exclusive with `--scan` because a scan verdict on stdout would corrupt
   the pipe, and with `--no-key` because there would be nothing to print.

   **The key cannot be recovered after creation**: the backend stores only an
   HMAC-SHA256 (`keys/api_db.py: hash_api_key`) and the list endpoint redacts it
   (`keys/get_api_keys.py: redact_key`). So "just look it up in the dashboard" is
   not an option to offer users — print-once plus `--key-stdout` is the whole
   surface, and the dashboard link is for revoking, not retrieving.

   **Re-running is safe but not idempotent:** step 2 mints a *new* key each run
   (fresh random name, retried on a 409 collision). That is deliberate — the
   common re-run reason is "I never saved the key" — but the backend caps keys at
   `MAX_KEYS_PER_USER` (10), so repeated runs can exhaust the quota with orphaned
   keys; `--no-key` skips the step. Do not "fix" this by having init GET existing
   keys and skip: the list endpoint redacts key values, so skipping would leave a
   user who lost their key with no way to get one.

   **`init` writes no files, deliberately.** An earlier revision generated
   `.github/workflows/ossprey.yml`; that was dropped because it made a
   GitHub-shaped assumption about a CLI that otherwise doesn't care about your CI,
   and because it wrote into the user's repo. The knowledge that made the template
   correct now lives in README's "CI usage" section instead, and it is worth
   keeping there: the job needs an `if:` guard so **fork** `pull_request` runs skip
   (GitHub withholds secrets from them, so `OSSPREY_API_KEY` is empty and every
   external PR fails red for a missing key rather than for malware — never close
   that by switching to `pull_request_target`, which hands secrets to untrusted
   code), and actions should be SHA-pinned rather than tag-pinned. If you ever
   reinstate generation, also remember git ref names permit `]`, `#`, `&` and `'`,
   so a branch name dropped raw into `branches: [%s]` yields YAML Actions cannot
   parse — i.e. silently no scanning at all.
1. **`scan [path]`** — catalog a directory, submit, report.
2. **`check -e <pypi|npm> <name[@version]>...`** — check named packages with no project on disk.
3. **Forwarders** (`npm`/`pnpm`/`yarn`/`pip`/`pip3`/`poetry`/`uv`) — registered dynamically from `forward.Managers()`. Each wraps an install, blocks on malware, otherwise execs the real manager. `DisableFlagParsing: true` so every arg reaches the real tool untouched; config comes only from `OSSPREY_API_URL` / `OSSPREY_API_KEY` env vars. `forward.Run` has two modes (`internal/forward/forward.go`): when packages are **named** it checks exactly those (`ParseSpecs` classifies args into `Specs` / `NonPackages` / `ReqFiles`, skipping flag-values, local paths, archives, URLs, VCS refs); when **no** packages are named — a bare `install`/`ci`/`yarn install`/`poetry install`/`uv sync`/`pip install -r` — the manager installs from the project manifest, so it runs a directory scan (`scanProjectFn` → `scan.Run` + `submit.Validate`) and checks every declared dependency rather than falling through unchecked (OSS-1284). Only installs whose sole targets are local/URL refs forward without a check.

   Finding the verb is not just `args[0]`: every manager accepts its global options first (`pnpm --filter web add x`, `npm --prefix /tmp install x`, `pip --quiet install x`), and pnpm workspaces always do. `verbIndex` skips leading flags — consuming a value only for flags listed in `globalValueFlags` — and takes the first non-flag token as the verb. It never scans ahead for a verb-shaped token, so `pnpm run add` stays a script run. Getting that table wrong is asymmetric: omitting a value-taking flag just forwards unchecked (fail open, as before), while wrongly listing a *boolean* flag would swallow the verb and hide a real install — so only add flags known to take a value. Note pnpm's `-w` is boolean where npm's `-w` takes a value.

   The post-verb table (`valueFlags`) carries the same asymmetry and it bites harder there: omitting a value-taking flag makes its value read as a package, checking something that isn't being installed (noisy, safe), while wrongly listing a boolean flag swallows the package name and skips its check (silent, unsafe). Keep a table per manager and never alias one to another — `valueFlags["pnpm"] = valueFlags["npm"]` inherited npm's value-taking `-w` into pnpm, where `-w` is boolean `--workspace-root`, so `pnpm add -w <pkg>` installed unchecked (OSS-1577). `TestPnpmBooleanFlagsAreNotValueFlags` now guards both tables.

   **Not covered, deliberately (for now):** fetch-and-execute — `npm exec`, `pnpm dlx`, `yarn dlx`, `uv tool run`. These name a package but are not install verbs, so they forward unchecked. Do **not** close this by adding `dlx` to a `verbAt` list: only the first non-flag token is a package and the rest is the program's own argv, so `pnpm dlx cowsay moo` would check `moo` (a real npm package) and could block on it. It needs its own matcher alongside `uvInstallAt`, plus handling for `--package=` naming a different package from the command. Note also that `npx` and `uvx` are separate binaries absent from `DefaultManagers()`, so they are not shimmed at all — covering `pnpm dlx` alone buys little. README's "What is not checked" section is the user-facing statement of this.

   **Known gap (pnpm 9 and earlier):** `pnpm run` (and `pnpm exec`) install the project's declared dependencies as a side effect when `node_modules` is missing — `npm run` does not. Since `run` is a pass-through, those packages are never checked. Closing it would put a scan in front of every script invocation, so it is an open product decision. Not reproducible on pnpm 10.34.5 (with or without `CI=1`, `verify-deps-before-run` at its default), so pnpm 10 appears to have stopped auto-installing; `TestPnpmRunAutoInstallsUnchecked` skips with a re-check message rather than passing when it can't reproduce.

4. **`shim install|uninstall|status|dir`** (`cmd/ossprey/shim.go` → `internal/shim`) — writes PATH shims so `npm install` routes through `ossprey npm` with no prefix, covering scripts, CI and coding agents that a shell alias never reaches (OSS-1566). Also driven by `install.sh --override-package-managers` / `install.ps1 -OverridePackageManagers`.

### Shims (`internal/shim`)

A shim is a generated `/bin/sh` script (`.cmd` on Windows) named after the manager, in `~/.ossprey/shims`, which shell profiles prepend to PATH inside a marked block. Four invariants hold it together:

- **Recursion guard, twice.** The script strips its own directory from PATH before exec'ing, *and* `forward.Exec` resolves via `shim.LookPathReal`, which skips any PATH candidate containing `shim.Marker`. Either alone would do in the normal case; the pair covers symlinked/misspelled PATH entries.
- **Fail open.** Missing ossprey binary or `OSSPREY_SHIM_BYPASS` set → exec the real manager with a warning. A scanner that can break `npm install` gets ripped out.
- **The allowlist lives in `forward`, not the script.** Shims forward everything; `forward.Run`'s `installAt` decides what gets checked, so `npm run`/`poetry run` pass straight through. One allowlist, one language.
- **Only our files.** `Uninstall` deletes only marker-carrying files; profile edits live between `# >>> ossprey shims >>>` markers.

`shim` must stay a leaf package (`forward` imports it). `DefaultManagers()` and `forward.Managers()` are kept in agreement by an external test in `internal/shim/forward_agreement_test.go`.

### Core data flow (scan)

`internal/scan` → `internal/catalog` → builds `internal/ossbom.SBOM` →
`.ToMiniBOM()` → `internal/submit` → `internal/client` (POST + poll) →
`sbom.ApplyAPIResponse()` → `scan.MalwareReports()` decides the exit code.

`check` reuses the same `submit`/`client`/`ossbom` path but builds a
one-component-per-spec SBOM instead of cataloging the filesystem. `forward`
reuses `check.Run` after parsing install args.

### Cataloging (`internal/catalog`)

`Catalog()` in `syft.go` deliberately **bypasses `syft.CreateSBOM`** (which
pulls in ~30 MB of unused catalogers). It instantiates a curated set against one
directory `FileResolver` and runs them all unconditionally:

- **Syft built-ins** handle lockfiles + installed-package metadata (Python, JS lock).
- **Custom catalogers** fill resolution gaps where a project ships a manifest but no lockfile:
  - `UVCataloger` — full transitive resolution via `uv` (hatch, uv, bare pyproject).
  - `SetupPyCataloger` — transitives from legacy `setup.py` setuptools projects.
  - `PyProjectCataloger` — direct-deps fallback for `pyproject.toml` when `uv` is absent.
  - `NpmResolveCataloger` — runs `npm install --package-lock-only` to resolve ranges when no lockfile is committed (npm analogue of uv). **This is the one place the CLI shells out to a package manager.**
  - `PackageJSONCataloger` — direct-deps fallback for `package.json`.

Custom catalogers shell out via `exec.LookPath`; if the tool is missing they
**silently skip** (return nil) rather than error. Custom catalogers named via
`isOspreyCataloger` parse deps only; syft's manifest catalogers also emit the
root project itself, which is dropped via `isRootManifestPackage`.

A cataloger's error is **not** a reason to drop its packages: syft's generic
cataloger returns everything it parsed alongside an `unknown` error naming the
lines it could not, exactly as `syft.CreateSBOM` does. Discarding on `err != nil`
emptied the SBOM of every Python package over one `flask>2.0` line — a scan that
silently checked nothing (OSS-1869).

Versions syft reads out of a requirements file are corrected against the file
itself by `requirementPins` (`requirements_pins.go`). Syft captures the
constraint with `[0-9a-zA-Z.*]`, which truncates every PEP 440 separator outside
that class — `==1.0.0-beta.1` becomes `1.0.0`, `==1.2.3+local1` becomes `1.2.3` —
and strips only `==`, so `===1.0` reaches the SBOM as `=1.0`: real-looking purls
naming a release the project never installs (OSS-1869). It **corrects, it does
not catalog** — only requirements that pin exactly one release are touched, so a
range or wildcard is left to syft's guess, and shapes syft drops outright (a bare
`>2.0`, an epoch `==1!2.0.0`) stay missing for the resolver-backed catalogers to
cover.

Output is deduped by `(type, name, version)`. `mergeVersionless` then collapses
a package emitted both versionless (direct-deps fallback) and pinned (uv-resolved)
into the pinned one. Vendored paths (`node_modules/`) are skipped (`isVendoredPath`).

### OSSBOM model (`internal/ossbom`)

`SBOM` is the rich internal model. `MiniBOM` (`minibom.go`) is the compressed
wire format sent to the API — each component becomes `{purl, source, env, location}`
with `purl = pkg:<type>/<name>@<version>`. The Go model mirrors the Python
`ossbom` library referenced in comments; keep them in sync when the API contract
changes.

### API client (`internal/client`)

`Validate` POSTs the MiniBOM to `/public/v1/scans`, then polls
`/public/v1/scans/status` (quadratic backoff, capped at `maxPollAttempts`). A
quota-exhausted response surfaces as a typed `*ErrSkipped` that propagates
unwrapped so callers can detect it via `errors.As` and **exit 0** rather than
failing the build (see `reportSkipped` in main.go). API key resolution order:
`--api-key` flag → `OSSPREY_API_KEY` → `API_KEY`.

## Conventions worth knowing

- **Exit codes:** `0` = clean / informational-only / `--local` dump / quota-skipped; `1` = malware found OR scan errored; `2` = panic (recovered in main). "Clean" and "errored" are not distinguishable by exit code alone — that is what `--report` is for (below).
- **Severity** (`internal/severity`) grades a finding `Info < Low < Medium < High < Critical`, and `FailingFloor` is `Low`. `Info` is the only level below it: the finding is printed as a `Note:` line and the scan still exits 0 (OSS-1432). Parsing is deliberately **fail-closed** — an empty or unrecognised grade is `Unknown`, and `Unknown.Fails()` is true, so an older API that sends no severity and an OSV-sourced finding that carries none both behave exactly as they did before. Never invert that default for convenience; it is the one thing standing between "we could not grade it" and "we passed it".
- **`--report <file>`** (`internal/scan/report.go`, on `scan` and `check`) writes the machine-readable verdict — `clean` / `malware` / `informational` / `skipped` plus per-finding name, version, ecosystem, severity and description — for CI to act on; `ossprey/gh-action` renders its PR comment from it. Three rules hold it together. It never touches **stdout**, which `--local` owns for the OSSBOM (the two flags are rejected together, because `--local` returns before any verdict exists). It is written **before** the `os.Exit(1)`, since a malware run is the one CI most needs it on. And `skipped` is its own verdict, not a flavour of clean: a quota-exhausted scan checked nothing, and a consumer that renders it as "no malware found" is lying. `informational` exists for the same reason: that scan *did* find something and said so, so folding it into `clean` would hide a finding we deliberately surfaced. A consumer that only knows the older three should treat it as non-failing. The JSON keys are a contract with the action — `test/smoke/report_smoke_test.go` redeclares the struct so a rename breaks a test instead of the action.
- **Where the CLI stops.** `--report` states the verdict; that is the whole of what the CLI owes CI. Rendering it (Markdown tables, pull-request comments, job summaries, `::error::` annotations) belongs in the consumer — `ossprey/gh-action` does its own, in bash. Do not move that back here, even when a `--report-format markdown` or a `render` subcommand would delete a hundred lines of someone's shell: every such feature is dead weight to the users installing this CLI for `scan`, `check` and the forwarders, and it makes the CLI's release cadence a dependency of one CI vendor's UI. The test for a new flag is whether a GitLab or Jenkins user would reach for it too.
- **API text is untrusted for display** (`internal/apitext`): finding justifications and descriptions are free text from the wire, printed straight to a developer's terminal. `apitext.OneLine` collapses control and formatting characters so a newline cannot forge an extra report line, a carriage return cannot overwrite one, and an ESC cannot start an ANSI sequence. Run any API-supplied string through it before interpolating it into terminal output.
- **Fail-open vs fail-closed:** the `check`/forward path fails *closed* for unpinned packages it can pin (resolves latest via `internal/registry`), but fails *open* (skips with a warning) when the registry is unreachable or a token has no parseable package name — a registry outage must never block development.
- **Dry-run flags** (`--dry-run-safe`, `--dry-run-malicious`) and `--local` skip the API entirely and need no key — useful for testing catalog output without a live backend.
- **Test seams:** `forward` exposes `execFn`/`checkFn` and `registry` exposes `DefaultHTTP` + base-URL vars so tests run without a real package manager or network. `client.PollBackoff` is overridable for sub-second test polling.
- Test fixtures for every supported ecosystem/manifest combo live under `test/test_packages/` and are driven by the smoke tests.

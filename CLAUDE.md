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

0. **`init [path]`** (`cmd/ossprey/init.go` → `internal/setup`) — the one-command
   onboarding path (OSS-1387): ensure a login, mint a CI API key, write
   `.github/workflows/ossprey.yml`, run the first scan. Key creation goes through
   `client.CreateAPIKey` on `/dashboard/v1/api-keys`, which **requires a bearer
   token** — API keys cannot mint API keys, so `init` never takes an
   `--api-key`. Every step is idempotent: `ensureLogin` reuses/refreshes a stored
   login, `setup.WriteWorkflow` refuses to overwrite an existing file, and each
   run generates a new key name (retrying on a 409 name collision). Key creation
   fails **open** — a warning, then the workflow and scan still run — because the
   scan is the value and the user can always make a key in the dashboard. The
   device-flow prompt is shared with `login` via `runDeviceLogin`.
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

- **Exit codes:** `0` = clean / `--local` dump / quota-skipped; `1` = malware found OR scan errored; `2` = panic (recovered in main). "Clean" and "errored" are not distinguishable by exit code alone — parse stderr or the `-o` OSSBOM.
- **Fail-open vs fail-closed:** the `check`/forward path fails *closed* for unpinned packages it can pin (resolves latest via `internal/registry`), but fails *open* (skips with a warning) when the registry is unreachable or a token has no parseable package name — a registry outage must never block development.
- **Dry-run flags** (`--dry-run-safe`, `--dry-run-malicious`) and `--local` skip the API entirely and need no key — useful for testing catalog output without a live backend.
- **Test seams:** `forward` exposes `execFn`/`checkFn` and `registry` exposes `DefaultHTTP` + base-URL vars so tests run without a real package manager or network. `client.PollBackoff` is overridable for sub-second test polling.
- Test fixtures for every supported ecosystem/manifest combo live under `test/test_packages/` and are driven by the smoke tests.

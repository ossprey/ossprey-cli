# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`ossprey` is a Go CLI for the [Ossprey](https://ossprey.com) supply-chain malware
platform. It statically catalogs a project's Python, JavaScript and Rust
dependencies into an **OSSBOM**, submits it to the Ossprey API, and exits `1` if
any package is flagged as malware. It also sits in front of package managers
(`ossprey npm install …`, or PATH shims) and checks what an install would fetch
before letting it run.

## Where docs go

Three places, each with one job:

- **`README.md`** is the landing page for someone who has never run the tool:
  what it is, install, `init`, scan, and one short section per way of using it,
  each linking onward. No flag tables, edge cases or rationale.
- **`docs/*.md`** is the user-facing reference (`install`, `init`,
  `cli-reference`, `forwarder`, `shims`, `passive-monitoring`, `git`, `brew`,
  `precommit`, `ci`, `output`, `ecosystems`, `trust`, `architecture`, indexed by
  `docs/README.md`). When a behaviour changes, the user-facing statement of it
  lives in exactly one of those pages. `docs/architecture.md` holds the mermaid
  diagrams, so a change to the forwarder's decisions or the scan pipeline needs
  them updated too.
- **`docs/internals/*.md`** keeps the *why*: the bug, review or customer report
  behind each decision, and the invariants a change must keep. It is indexed by
  `docs/internals/README.md`.

**This file is a map, not the record.** Keep it to the overview, how to work
here, and pointers. A new rationale, a `verified against <tool> <version>` note
or a named test goes in the matching `docs/internals` page, not here; add a line
to "Rules that bite" only when breaking the rule would be silent and unsafe.

**Before changing a package, read its internals page** (table below). Those pages
record approaches that were tried and rejected, so the obvious fix is often one
of them.

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

CI (`.github/workflows/ci.yml`) gates on `gofmt -l` being empty and `go vet`
(with and without `-tags smoke`) on ubuntu, and on `go test` and `go test -race`
on ubuntu and windows. Keep code gofmt-clean. Requires Go 1.25+.

The `smoke` job also runs the whole tagged suite on both OSes, because the
forwarders and shims can only be verified with the real binaries (pnpm on
Windows is a `.cmd`, as are the shims). It pins Python 3.12 with `setup-python`:
the Python fixtures pin numpy releases whose wheels stop at 3.12, and on the
26.04 image's newer Python pip builds them from source, so every scan of them
waits out `OSSPREY_RESOLVE_TIMEOUT` and the suite misses its 15m budget. Tests that need the shim
directory must ask `ossprey shim dir` rather than assuming `~/.ossprey/shims` —
Windows resolves it under `%LOCALAPPDATA%`.

## Architecture

`cmd/ossprey/main.go` wires the commands with cobra:

| Command | What it does | Code | Internals |
|---|---|---|---|
| `init [path]` | Log in, mint an API key, optionally scan with it | `cmd/ossprey/init.go` | [init](docs/internals/init.md) |
| `scan [path]` | Catalog a directory, submit, report | `internal/scan`, `internal/catalog` | [catalog](docs/internals/catalog.md), [cargo](docs/internals/cargo.md) |
| `check -e <pypi\|npm\|cargo> <name[@version]>...` | Check named packages with no project on disk | `internal/check`, `internal/registry` | [check](docs/internals/check.md) |
| `npm`, `npx`, `pnpm`, `yarn`, `bun`, `bunx`, `pip`, `pip3`, `poetry`, `uv`, `uvx` | Forwarders: check an install, block on malware, else exec the real manager | `internal/forward` | [forwarder](docs/internals/forwarder.md), [install-expansion](docs/internals/install-expansion.md), [passive](docs/internals/passive.md) |
| `shim install\|uninstall\|status\|dir` | PATH shims so a bare `npm install` routes through the forwarder | `internal/shim` | [shims](docs/internals/shims.md) |
| `git`, `brew` | Opt-in wrappers that check GitHub source repos | `internal/gitscan`, `internal/brewscan` | [wrappers](docs/internals/wrappers.md) |
| `trust list\|add\|remove` | Private registries and npm scopes left out of scans | `internal/trust` | [trust](docs/internals/trust.md) |

Scan data flow:

`internal/scan` → `internal/catalog` → builds `internal/ossbom.SBOM` →
`.ToMiniBOM()` → `internal/submit` → `internal/client` (POST + poll) →
`sbom.ApplyAPIResponse()` → `scan.MalwareReports()` decides the exit code.

`check` reuses the same `submit`/`client`/`ossbom` path with a
one-component-per-spec SBOM. `forward` reuses `check.Run` for named packages and
`scan.Run` when an install names none (a bare `npm install`).

Cataloguing bypasses `syft.CreateSBOM` and runs a curated set against one
directory resolver: syft's Python, JavaScript and `Cargo.lock` catalogers for
lockfiles, plus custom catalogers that resolve a manifest with no lockfile (via
`uv`, `pip` or `npm`) or fall back to its direct dependencies.

Other packages: `internal/alert` + `internal/ansi` (malware box),
`internal/warn` (collected warnings), `internal/progress` (the wait line),
`internal/severity`, `internal/apitext`, `internal/auth`, `internal/update`,
`internal/precommit` + `internal/hook`, `internal/monitor`, `internal/identity`,
`internal/env`. See [output](docs/internals/output.md),
[api](docs/internals/api.md) and [conventions](docs/internals/conventions.md).

## Rules that bite

Each of these fails silently or unsafely when broken. The linked page has the
reasoning and the test that pins it.

- **Exit codes.** `0` clean, informational-only, `--local` or quota-skipped; `1`
  malware and nothing else; `2` any error or panic. Forwarders pass the real
  manager's exit code through. ([conventions](docs/internals/conventions.md))
- **Severity parsing fails closed.** An unreadable grade is `Unknown` and fails
  at every floor; an unreadable *floor* falls back to `Info`. `--fail-on`
  overrides the account's floor in either direction.
  ([conventions](docs/internals/conventions.md))
- **stdout is for machine output.** `--local` owns it for the OSSBOM and
  `init --key-stdout` for the key; progress, warnings and narration go to stderr.
  `--report` writes a file, before the `os.Exit(1)`. Rendering a report (Markdown,
  PR comments) belongs in the consumer, not here.
  ([conventions](docs/internals/conventions.md))
- **Never `exec.LookPath` a package manager.** Use `lookTool`/`toolEnv`
  (`shim.LookPathReal` plus `OSSPREY_SHIM_BYPASS=1`), and `python -m pip` rather
  than `pip`. With shims installed, PATH `npm` is ossprey, and a scan fork-bombs
  itself. ([catalog](docs/internals/catalog.md), [shims](docs/internals/shims.md))
- **A cataloger's error does not drop its packages.** syft returns what it
  parsed alongside the error; keep both and report the error through `warn`.
  ([catalog](docs/internals/catalog.md))
- **The Python and uv resolvers execute package build backends.** Only the npm
  dry run runs nothing. Docs must not claim otherwise.
  ([catalog](docs/internals/catalog.md))
- **Flag tables are asymmetric.** Wrongly listing a *boolean* flag as
  value-taking swallows the verb or package and skips its check, silently. Only
  list flags known to take a value, keep one table per manager, and never alias
  one manager's table to another's. ([forwarder](docs/internals/forwarder.md))
- **A tool run's first positional is the only package.** `uvx cowsay moo` checks
  `cowsay`, never `moo`. Do not add `dlx` or similar to an install-verb list;
  give it a `toolRunAt`/`parseRun`. ([forwarder](docs/internals/forwarder.md))
- **Named-install expansion never runs package code and fails open out loud.**
  When the dry run fails, the names are checked alone and one line says so, even
  when quiet. The dry run must read the configuration the real command reads.
  ([install-expansion](docs/internals/install-expansion.md))
- **Forwarders are quiet by default.** A clean install prints one verdict line.
  Route narration through `note`, drain through `flushWarnings`, draw progress
  through `progressTo()`. A block always prints the full malware report.
  ([forwarder](docs/internals/forwarder.md))
- **Nothing execs the real manager without draining warnings first.** Go through
  `forwardTo`, never `execFn` directly: `syscall.Exec` replaces the process, so
  defers and anything after it never run.
  ([forwarder](docs/internals/forwarder.md), [output](docs/internals/output.md))
- **Warnings are collected, not printed.** `warn.Add(ctx, Entry)` grouped by
  `Class`; never `Fprintf(os.Stderr, …)` a per-package or per-manifest
  diagnostic. `warn` stays a leaf. ([output](docs/internals/output.md))
- **API text is untrusted for display.** Run it through `apitext.OneLine` before
  printing. ([conventions](docs/internals/conventions.md))
- **`shim` stays a leaf package.** Its only first-party import is
  `internal/monitor`; never import `internal/client` from it. Shims fail open.
  ([shims](docs/internals/shims.md))
- **The monitor id pattern is a security boundary.** It reaches a URL path and a
  generated shell script; do not loosen `^ospi_[0-9a-f]{64}$`. A monitor id is
  submit-only and never falls back to another credential.
  ([passive](docs/internals/passive.md))
- **Passive blocks nothing and delays nothing.** It observes the install after
  or beside it, never in front. ([passive](docs/internals/passive.md))
- **Trust rules are narrow on purpose.** No name rule for PyPI, prefix never
  host, provenance only from what a lockfile or resolver recorded, machine-level
  config only. `check` ignores trust. ([trust](docs/internals/trust.md))
- **Retry only 502/503/504.** A 500 means the backend took the SBOM. Quota
  exhaustion is `*ErrSkipped` and exits 0; a poll ceiling is
  `*ErrVerdictTimeout`, not a failure. ([api](docs/internals/api.md))
- **`init` writes no files and mints a new key each run.** The key cannot be
  recovered after creation, so do not "fix" re-runs by listing existing keys.
  ([init](docs/internals/init.md))
- **`git` and `brew` are opt-in and fail open**, unlike the package forwarders.
  ([wrappers](docs/internals/wrappers.md))
- **Cargo files are repository content and may be hostile.** The vendor filter,
  source marks and lockfile bounds each exist because review broke a simpler
  rule; read [cargo](docs/internals/cargo.md) before touching them.

## Testing notes

- Test seams: `forward` exposes `execFn`/`checkFn`/`expandFn`, `registry` exposes
  `DefaultHTTP` and base-URL vars, and `client.PollBackoff`/`RetryBackoff` are
  overridable, so no test needs a real manager, network or sleep.
- Several tests diff a ported table against the installed tool
  (`TestNpmCmdListMatchesNpm`, `TestNpmConfigTableMatchesNpm`,
  `TestNpmParsersMatchNpm`, `TestToolRunValueFlagsMatchUV`). The npm ones track
  **npm 11.19.1**, which CI pins; run them under that npm and bump the pin and
  the tables together.
- Tests asserting "no escapes" on a buffer must clear the CI colour env vars
  first, or they fail on GitHub Actions.
- Smoke tests prove a quiet check ran through the fake API's submitted purls,
  not a stderr line; those that assert on narration use `runForwardVerbose`.
- `--dry-run-safe`, `--dry-run-malicious` and `--local` skip the API and need no
  key.
- Fixtures for every supported ecosystem and manifest combination live under
  `test/test_packages/` and are driven by the smoke tests.

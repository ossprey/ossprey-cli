# CLI reference

Every command, flag and credential the CLI understands.

| Command | What it does |
|---------|--------------|
| [`ossprey init [path]`](init.md) | Set up a project: log in, create an API key, scan with it. |
| [`ossprey scan [path]`](#scan) | Catalogue a directory, submit the OSSBOM, fail on malware. `path` defaults to `.`. |
| [`ossprey check -e <pypi\|npm> <pkg>...`](#check--scan-named-packages) | Check packages by name, no project needed. |
| [`ossprey npm\|npx\|pnpm\|yarn\|pip\|pip3\|poetry\|uv ...`](forwarder.md) | Check, then run the real package manager. Blocks the install on malware. |
| [`ossprey shim install`](shims.md) | Put shims on `PATH` so installs are checked without the `ossprey` prefix. |
| [`ossprey precommit`](precommit.md) | Git pre-commit hook: block commits that stage known-malicious packages. |
| [`ossprey login`](#authentication) | Browser login via Auth0. Stores tokens locally. |
| [`ossprey whoami`](#authentication) | Show who the stored login belongs to. |
| [`ossprey logout`](#authentication) | Remove the stored login. |
| [`ossprey update`](install.md#updating) | Replace the binary with a newer release. |
| `ossprey completion <shell>` | Print a completion script for bash, zsh, fish or PowerShell. |
| `ossprey --version` | Print the CLI version. |

To have the forwarders run without typing `ossprey` every time, see
[how to make Ossprey scan on all package manager commands](forwarder.md#shell-aliases--drop-the-ossprey-prefix-in-your-terminal).

## Exit codes and severity

- `0` — no malware found, only informational findings, `--local` dump, or scan
  skipped by the API (e.g. quota exhausted)
- `1` — malware found, **or** the scan itself failed (bad path, catalog error,
  API/network error, missing key)

A finding graded `Info` is reported as a `Note:` line and does not fail the
scan. Every other grade fails, and so does a finding the API could not grade,
so an older server that sends no grade behaves exactly as before.

Pass `--fail-on-informational` to fail on those too, if you would rather your
build stopped on anything Ossprey reports at all. It only ever makes the check
stricter; there is deliberately no flag to raise the threshold, because that
would let a real detection through.

"Clean" and "errored" share exit code `0` and `1` respectively with other
outcomes, so if CI needs to tell them apart, write a
[`--report` file](output.md#machine-readable-verdict---report): it exists, with
a `verdict`, only when the scan actually reached one.

## Environment variables

| Variable | Equivalent flag | Effect |
| -------- | --------------- | ------ |
| `OSSPREY_API_KEY` | `--api-key` | API key. A stored `ossprey login` still wins. |
| `API_KEY` | — | Legacy spelling of the above, lowest precedence. |
| `OSSPREY_API_URL` | `--url` | Override the API URL. |
| `OSSPREY_VERBOSE=1` | `-v` | Explain every warning, including a failed resolver's output. Works on the forwarders and shims, which parse no flags. |
| `OSSPREY_SKIP_CI=1` | `--skip-ci` | Kill switch: no scan runs at all. |
| `OSSPREY_PASSIVE=1` | `--passive` | Observe-only: submit, never block or fail. |
| `OSSPREY_MONITOR_ID` | `--monitor` | Submit through a monitor id. Implies passive. |
| `OSSPREY_SCAN_TIMEOUT` | `--timeout` | Cap the whole catalogue; emit what resolved. |
| `OSSPREY_RESOLVE_TIMEOUT` | — | Cap one uv/npm resolver invocation (default `2m`). |
| `OSSPREY_SCAN_CONCURRENCY` | — | How many catalogers run at once (default `8`). |
| `OSSPREY_RESOLVE_LATEST=0` | `--no-version-lookup` | Don't resolve unpinned versions from the registry. |
| `OSSPREY_CONFIG_DIR` | — | Where the stored login lives. |
| `OSSPREY_SHIM_DIR` | `--dir` | Where [shims](shims.md) are written. |
| `OSSPREY_SHIM_BYPASS=1` | — | Skip the check for one shimmed command. |
| `OSSPREY_PRECOMMIT_TIMEOUT` | — | Budget for the [pre-commit](precommit.md) lookup (default `10s`). |
| `OSSPREY_CI_CACHE_SCAN_ONLY=1` | `--ci-cache-scan-only` | The original spelling of `--passive`; still works. |

## `scan`

```
ossprey scan [path] [flags]
```

`path` defaults to the current directory.

| Flag | Description |
|------|-------------|
| `-o, --output <file>` | Write the OSSBOM JSON to `<file>` (in addition to running the scan). |
| `-v, --verbose` | List every warned package and manifest, and the full output of any resolver that failed. Also settable as `OSSPREY_VERBOSE=1`, which works on the forwarders and shims too. |
| `--local` | Catalogue only. Dump the OSSBOM to stdout and exit — no API submission, no malware verdict. |
| `--no-version-lookup` | Don't query the registry to resolve unpinned dependencies; leave them versionless. |
| `--timeout <dur>` | Give up cataloguing after this long and emit whatever resolved (or `OSSPREY_SCAN_TIMEOUT`). Off by default. |
| `--url <url>` | Override the Ossprey API URL (default `https://api.ossprey.com`). |
| `--api-key <key>` | Provide the API key on the command line instead of an env var. |
| `--fail-on-informational` | Also fail on informational findings, which are reported but exit 0 by default. |
| `--dry-run-safe` | Skip the API; report an empty vulnerability list. |
| `--dry-run-malicious` | Skip the API; inject a test finding against the first component. |
| `--skip-ci` | Skip the Ossprey scan entirely and exit 0. Also settable as `OSSPREY_SKIP_CI=1`. |
| `--passive` | Submit the scan for the dashboard and return immediately, without waiting for a verdict. Always exits 0, even if the submission fails. Also settable as `OSSPREY_PASSIVE=1`. |
| `--monitor <id>` | Submit passively through a monitor's id, needing no login and no API key. Implies `--passive`. Also settable as `OSSPREY_MONITOR_ID`. |

## `check` — scan named packages

Scan one or more packages by name without a project on disk:

```
ossprey check --eco-system <pypi|npm> <name[@version]>...
```

```sh
ossprey check -e pypi requests@2.31.0
ossprey check -e npm lodash@4.17.21 react@18.2.0
```

When a version is omitted, the latest published version is resolved from the
registry (PyPI / npm) and checked. Both `name@version` and pip's
`name==version` forms are accepted.

| Flag | Description |
|------|-------------|
| `-e, --eco-system <pypi\|npm>` | Package ecosystem (required). |
| `--url <url>` | Override the Ossprey API URL. |
| `--api-key <key>` | API key (or env var). |
| `--dry-run-safe` | Skip the API; report an empty vulnerability list. |
| `--dry-run-malicious` | Skip the API; inject a test finding against the first package. |

Exit codes match `scan`: `1` on a malware verdict or error, `0` otherwise
(an `Info` finding is reported but does not fail).

## Authentication

Two ways to authenticate:

**Browser login (interactive use).** Run `ossprey login` once — it opens your
browser, you confirm a one-time code, and the CLI stores the resulting Auth0
tokens locally (`~/.config/ossprey/credentials.json` on Linux, or the
platform's user config dir; override with `OSSPREY_CONFIG_DIR`). Scans then
authenticate automatically and tokens refresh silently. `ossprey whoami`
shows the current login; `ossprey logout` removes it.

**API key (CI / non-interactive use).** Get a key at
[dashboard.ossprey.com](https://dashboard.ossprey.com) and provide it via
flag or env var.

Credentials are resolved in order:

1. `--api-key` flag (an explicit per-invocation choice)
2. the stored `ossprey login` session (JWT)
3. `OSSPREY_API_KEY` env var
4. `API_KEY` env var

A logged-in session therefore wins over API keys exported in the shell; drop
the login with `ossprey logout` (or pass `--api-key`) to force key auth. The
credential also picks the API surface: JWTs call the `/dashboard/v1` routes,
API keys the `/public/v1` routes — same endpoints, same behaviour.

`--local`, `--dry-run-safe` and `--dry-run-malicious` don't talk to the API
and don't need credentials.

`ossprey login` targets the production Ossprey tenant by default; point it at
another environment with `--auth0-domain`, `--client-id` and `--audience`
flags or the matching `OSSPREY_AUTH0_DOMAIN` / `OSSPREY_AUTH0_CLIENT_ID` /
`OSSPREY_AUTH0_AUDIENCE` env vars. For the QA environment:

```sh
ossprey login \
  --auth0-domain auth.qa.ossprey.com \
  --client-id oT9sXzeqPTyZnRDzpgQ3YjUfd11Xj0Mh \
  --audience https://api.qa.ossprey.com
ossprey scan . --url https://api.qa.ossprey.com
```

The Auth0 application behind the client ID must be a **Native** app with the
**Device Code** and **Refresh Token** grants enabled, and the API must have
**Allow Offline Access** on.

---

[← Back to the docs index](README.md)

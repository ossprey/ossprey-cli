# Ossprey CLI

`ossprey` is the command-line scanner for the [Ossprey](https://ossprey.com)
supply-chain malware platform. It catalogues your project's dependencies into
an OSSBOM, submits it to the Ossprey API, and fails the build if any of those
packages are known to contain malware.

Today the CLI covers Python and JavaScript projects via static parsing of the
manifests and lockfiles already in your repo — no package installs, no
sandbox, no virtualenv.

## Install

### One-liner (Linux / macOS)

```sh
curl -fsSL https://github.com/ossprey/ossprey-cli/releases/latest/download/install.sh | sudo sh
```

The script detects your OS/arch, downloads the matching binary, verifies its
sha256, and installs it to `/usr/local/bin/ossprey`.

Override the defaults with env vars:

```sh
# Pin a specific version
curl -fsSL https://github.com/ossprey/ossprey-cli/releases/latest/download/install.sh \
  | OSSPREY_VERSION=v0.1.0 sudo -E sh

# Install to a user-writable dir (no sudo)
curl -fsSL https://github.com/ossprey/ossprey-cli/releases/latest/download/install.sh \
  | OSSPREY_INSTALL_DIR=$HOME/.local/bin sh
```

### Manual download

Grab the binary direct from the
[releases page](https://github.com/ossprey/ossprey-cli/releases/latest):

| Asset                              | Platform              |
|------------------------------------|-----------------------|
| `ossprey-linux-amd64`              | Linux x86_64          |
| `ossprey-linux-arm64`              | Linux arm64           |
| `ossprey-darwin-amd64`             | macOS Intel           |
| `ossprey-darwin-arm64`             | macOS Apple Silicon   |
| `ossprey-windows-amd64.exe`        | Windows x86_64        |
| `ossprey-windows-arm64.exe`        | Windows arm64         |

`chmod +x` and drop it on your `PATH`. Each asset ships with a `.sha256`
sidecar for verification. Pin a specific tag by replacing `latest/download`
with `download/<tag>` in the URL.

### From source

```sh
git clone https://github.com/ossprey/ossprey-cli.git
cd ossprey-cli
make tidy   # first time
make build  # produces bin/ossprey
```

Requires Go 1.25+.

The release build (`make build`) ships with `-trimpath -ldflags="-s -w"` for a
~16 MB binary. Use `make build-debug` for an unstripped ~21 MB build with
symbols.

## Quick start

```sh
export OSSPREY_API_KEY=sk_live_...
ossprey scan .
```

Exit codes:

- `0` — no malware found, `--local` dump, or scan skipped by the API (e.g. quota exhausted)
- `1` — malware found, **or** the scan itself failed (bad path, catalog error, API/network error, missing key)

If you need to distinguish "clean" from "errored" in CI, check stderr or parse the OSSBOM emitted via `-o`.

Get an API key at [dashboard.ossprey.com](https://dashboard.ossprey.com).

## Usage

```
ossprey scan [path] [flags]
```

`path` defaults to the current directory.

| Flag | Description |
|------|-------------|
| `-o, --output <file>` | Write the OSSBOM JSON to `<file>` (in addition to running the scan). |
| `-v, --verbose` | Verbose logging. |
| `--local` | Catalogue only. Dump the OSSBOM to stdout and exit — no API submission, no malware verdict. |
| `--url <url>` | Override the Ossprey API URL (default `https://api.ossprey.com`). |
| `--api-key <key>` | Provide the API key on the command line instead of an env var. |
| `--version` | Print the CLI version. |

### GitHub attribution

When the scanned path is a GitHub checkout, the CLI records the repo's
`github_org`, `github_repo` and `branch` on the scan so the dashboard titles it
`org/repo@branch` and links back to the source (instead of showing just the
directory name or a scan-id hash). Coordinates come from CI environment
variables (`GITHUB_REPOSITORY`, `GITHUB_REF_NAME` — set by GitHub Actions and
Codespaces) when present, falling back to the local `git remote get-url origin`
for developer-machine scans. Non-GitHub or non-git directories scan exactly as
before.

### Authentication

The API key is read from, in order:

1. `--api-key` flag
2. `OSSPREY_API_KEY` env var
3. `API_KEY` env var

`--local`, `--dry-run-safe` and `--dry-run-malicious` don't talk to the API
and don't need a key.

## `check` — scan named packages or a github repo

Scan one or more packages by name without a project on disk:

```
ossprey check --eco-system <pypi|npm|github> <name[@version] | owner/repo[@ref]>...
```

```sh
ossprey check -e pypi requests@2.31.0
ossprey check -e npm lodash@4.17.21 react@18.2.0
ossprey check -e github Xpra-org/xpra              # scans the repo source itself
ossprey check -e github https://github.com/psf/requests@v2.31.0
```

For `pypi`/`npm`, when a version is omitted the latest published version is
resolved from the registry and checked. Both `name@version` and pip's
`name==version` forms are accepted.

For `github`, the repo *itself* is submitted as a `github` component
(`pkg:github/<owner>/<repo>@<ref>`) — the Ossprey backend fetches the repo
source and scans its own code. The ref defaults to `HEAD`; pass `owner/repo@ref`
to pin a branch, tag, or commit. `owner/repo` shorthand and full github URLs
(https or ssh) are both accepted. A single github check sets the scan's
`github_org`/`github_repo`/`branch` so the dashboard titles it `owner/repo@ref`
and links back to the repo.

| Flag | Description |
|------|-------------|
| `-e, --eco-system <pypi\|npm\|github>` | Package ecosystem (required). |
| `--url <url>` | Override the Ossprey API URL. |
| `--api-key <key>` | API key (or env var). |

Exit codes match `scan`: `1` on a malware verdict or error, `0` otherwise.

## Package-manager forwarder

Wrap an install so packages are checked **before** they hit your machine. If
any are flagged, the install is blocked (exit `1`) and the real package manager
is never invoked; otherwise the command is forwarded unchanged.

```sh
ossprey npm install foo@1.2.3
ossprey yarn add foo@1.2.3
ossprey pip install foo==1.2.3
ossprey poetry add foo
ossprey uv pip install foo==1.2.3
```

Supported managers: `npm`, `yarn`, `pip`, `poetry`, `uv`. Non-install
subcommands (`npm run`, `pip list`, …) are forwarded straight through with no
check.

**Scope:** only the packages named on the command line are checked — transitive
dependencies are **not** resolved here. Run `ossprey scan` after install for
full-tree coverage. Tokens with no parseable package name (`pip install -r
requirements.txt`, VCS/URL installs) are forwarded unchecked with a warning. If
the registry can't be reached to resolve an unpinned version, that package is
skipped (fail-open) so a registry outage never blocks development.

Configuration comes from the environment (flag parsing is disabled so every
argument reaches the real manager):

- `OSSPREY_API_KEY` — API key
- `OSSPREY_API_URL` — override the API URL (default `https://api.ossprey.com`)

## Supported ecosystems

Python and JavaScript, via syft's static catalogers.

| Ecosystem | Files parsed |
|-----------|--------------|
| Python | `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `pdm.lock`, `setup.py`, `pyproject.toml`, wheel / egg metadata |
| JavaScript | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |

The CLI never executes your package manager. If your repo has only a manifest
and no lockfile, expect direct deps only — supply a lockfile for full
transitive coverage.

## CI usage

Typical GitHub Actions step:

```yaml
- name: Ossprey scan
  env:
    OSSPREY_API_KEY: ${{ secrets.OSSPREY_API_KEY }}
  run: ossprey scan .
```

The CLI exits non-zero on a malware verdict, which fails the workflow.

## Output

`ossprey scan` prints `No malware found` on success or one `Error: WARNING:
<pkg>:<ver> contains malware. Remediate this immediately` line per finding on
failure.

Pass `-o sbom.json` to also write the full OSSBOM JSON (components +
vulnerabilities) to disk, or `--local` to emit it to stdout instead of
calling the API.

## Status

Pre-1.0. The CLI surface, OSSBOM schema, and API contract are stable enough
for production use; expect additive changes only.

## Support

- Docs: [docs.ossprey.com](https://docs.ossprey.com)
- Issues: [github.com/ossprey/ossprey-cli/issues](https://github.com/ossprey/ossprey-cli/issues)
- Email: support@ossprey.com

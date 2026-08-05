# Ossprey CLI

`ossprey` is the command-line scanner for the [Ossprey](https://ossprey.com)
supply-chain malware platform. It catalogues your project's dependencies into
an OSSBOM, submits it to the Ossprey API, and fails the build if any of those
packages are known to contain malware.

> **You need an Ossprey account to run scans.** Sign up for a free account at
> [ossprey.com](https://ossprey.com), then either run `ossprey login` to sign
> in via your browser, or provide an API key via `OSSPREY_API_KEY` (see
> [Authentication](#authentication)). The `--local` and `--dry-run-*` modes
> work without credentials.

Today the CLI covers Python and JavaScript projects via static parsing of the
manifests and lockfiles already in your repo — no package installs, no
sandbox, no virtualenv.

## Contents

- [Install](#install) — [Linux / macOS](#one-liner-linux--macos) · [Windows](#one-liner-windows-powershell) · [manual download](#manual-download) · [from source](#from-source) · [updating](#updating)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Authentication](#authentication)
- [`check` — scan named packages](#check--scan-named-packages)
- [Package-manager forwarder](#package-manager-forwarder) — check before install for `npm` / `pnpm` / `yarn` / `pip` / `poetry` / `uv`
- [PATH shims](#path-shims--drop-the-ossprey-prefix) — intercept installs without typing `ossprey`
- [Supported ecosystems](#supported-ecosystems)
- [CI usage](#ci-usage)
- [Output](#output)
- [Status](#status)
- [Support](#support)

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

Add `--override-package-managers` to also install [PATH
shims](#path-shims--drop-the-ossprey-prefix), so `npm install` and `pip install`
are checked without typing `ossprey`:

```sh
curl -fsSL https://github.com/ossprey/ossprey-cli/releases/latest/download/install.sh \
  | sudo sh -s -- --override-package-managers
```

### One-liner (Windows PowerShell)

Runs natively on Windows — no WSL, no admin rights needed. From any
PowerShell prompt:

```powershell
irm https://github.com/ossprey/ossprey-cli/releases/latest/download/install.ps1 | iex
```

Or from cmd.exe:

```bat
powershell -ExecutionPolicy Bypass -Command "irm https://github.com/ossprey/ossprey-cli/releases/latest/download/install.ps1 | iex"
```

The script detects your architecture, downloads the matching `ossprey.exe`,
verifies its sha256, installs it to `%LOCALAPPDATA%\Programs\ossprey`, and
adds that directory to your user `PATH` (open a new terminal to pick it up).

Override the defaults with env vars:

```powershell
# Pin a specific version
$env:OSSPREY_VERSION = 'v0.1.0'
irm https://github.com/ossprey/ossprey-cli/releases/latest/download/install.ps1 | iex

# Custom install location
$env:OSSPREY_INSTALL_DIR = 'C:\tools\ossprey'
irm https://github.com/ossprey/ossprey-cli/releases/latest/download/install.ps1 | iex

# Also install PATH shims over npm/pip/... (see "PATH shims" below)
$env:OSSPREY_OVERRIDE_PACKAGE_MANAGERS = '1'
irm https://github.com/ossprey/ossprey-cli/releases/latest/download/install.ps1 | iex
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

### Updating

Once installed, the CLI can update itself:

```sh
ossprey update                    # update in place to the latest release
ossprey update --check            # just report whether an update is available
ossprey update --version v0.2.0   # install a specific version (up- or downgrade)
ossprey update --force            # reinstall even if already on the target version
```

`update` downloads the release binary matching your OS/architecture, verifies
its sha256, and atomically replaces the running executable. If the binary
lives in a root-owned directory (the `/usr/local/bin` default on Linux/macOS),
run `sudo ossprey update`; the Windows default (`%LOCALAPPDATA%\Programs\ossprey`)
is user-writable, so no elevation is needed.

## Quick start

```sh
# Interactive: log in once via your browser...
ossprey login
ossprey scan .

# ...or non-interactive (CI): use an API key
export OSSPREY_API_KEY=ospy_...
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
| `--no-version-lookup` | Don't query the registry to resolve unpinned dependencies; leave them versionless. |
| `--url <url>` | Override the Ossprey API URL (default `https://api.ossprey.com`). |
| `--api-key <key>` | Provide the API key on the command line instead of an env var. |
| `--version` | Print the CLI version. |

### Authentication

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

Exit codes match `scan`: `1` on a malware verdict or error, `0` otherwise.

## Package-manager forwarder

Wrap an install so packages are checked **before** they hit your machine. If
any are flagged, the install is blocked (exit `1`) and the real package manager
is never invoked; otherwise the command is forwarded unchanged.

```sh
ossprey npm install foo@1.2.3 bar@2.0.0   # checks each named package
ossprey yarn add foo@1.2.3
ossprey pip install foo==1.2.3
ossprey poetry add foo
ossprey uv pip install foo==1.2.3
```

Supported managers: `npm`, `pnpm`, `yarn`, `pip`, `pip3`, `poetry`, `uv`. Non-install
subcommands (`npm run`, `pip list`, …) are forwarded straight through with no
check.

**Two modes, picked automatically:**

- **Named packages** (`ossprey npm install foo bar`, `ossprey pip install
  foo==1 bar`): every package named on the command line is checked. Multiple
  packages, flags, flag-values, local paths, archives and VCS/URL targets are
  all handled — only the real registry packages are checked, the rest are noted
  and forwarded. Transitive dependencies are **not** resolved here; run `ossprey
  scan` after install for full-tree coverage.
- **Manifest install** (bare `ossprey npm install`, `npm ci`, `yarn install`,
  `poetry install`, `uv sync`, or `pip install -r requirements.txt`): no
  packages are named, so the manager installs from the project's
  manifest/lockfile. The forwarder scans the current directory and checks every
  declared dependency before forwarding — it does **not** fall through
  unchecked.

If the registry can't be reached to resolve an unpinned named version, that
package is skipped (fail-open) so a registry outage never blocks development.
An install whose only targets are local paths or URLs (nothing checkable and no
manifest to scan) is forwarded with a warning.

Configuration comes from the environment (flag parsing is disabled so every
argument reaches the real manager):

- `OSSPREY_API_KEY` — API key
- `OSSPREY_API_URL` — override the API URL (default `https://api.ossprey.com`)

## PATH shims — drop the `ossprey` prefix

Remembering to type `ossprey npm install` is the weak point of the forwarder,
and a shell alias does not fix it: aliases only exist in interactive shells, so
Makefiles, CI steps, and the commands your coding agent runs all slip past.

Shims fix it properly. A shim is a small script named after the package manager
in a directory at the **front of your PATH**, so `execvp` finds it wherever the
command is run from — scripts and agents included.

```sh
# During install
curl -fsSL https://github.com/ossprey/ossprey-cli/releases/latest/download/install.sh \
  | sh -s -- --override-package-managers

# Or any time afterwards
ossprey shim install
```

Then just use your package manager as normal:

```console
$ npm install left-pad
ossprey: no malware found, forwarding to npm
added 1 package in 412ms
```

| Command | What it does |
|---------|--------------|
| `ossprey shim install` | Write the shims and put their directory first on PATH |
| `ossprey shim install --dry-run` | Show what would be written and changed; write nothing |
| `ossprey shim status` | Which managers are intercepted right now, and what they run |
| `ossprey shim uninstall` | Remove the shims and the PATH entry |
| `ossprey shim dir` | Print the shim directory (for `ENV PATH=…` in a Dockerfile) |

Useful flags: `--managers npm,pip` to shim a subset, `--all` to shim managers
you have not installed yet, `--no-path` to write the shims but manage PATH
yourself, `--dir` / `$OSSPREY_SHIM_DIR` to relocate them.

**How it behaves**

- **Only installs are checked.** `npm run build`, `poetry run pytest`, `pip
  list` and friends are exec'd straight through. The allowlist is the same one
  the forwarder uses, so there is only one place it can drift.
- **It fails open.** If the ossprey binary goes missing the shim prints a
  warning and runs the real manager anyway. `OSSPREY_SHIM_BYPASS=1 npm install
  …` skips the check for one command, and `ossprey shim uninstall` removes them
  for good.
- **It cannot recurse.** Each shim strips its own directory from PATH before
  exec'ing, and ossprey independently refuses to exec any file carrying the shim
  marker.
- **It only touches its own files.** Shell profiles are edited inside a marked
  block that uninstall removes cleanly, and uninstall deletes only files ossprey
  generated.

Which profiles get the PATH entry: `~/.profile` always; `~/.bashrc`,
`~/.zshrc` and `~/.config/fish/config.fish` if the file exists or that shell is
installed; `~/.bash_profile` and `~/.zprofile` only if they already exist. On
Windows the shims are `.cmd` files and the directory is prepended to your user
PATH.

In a container image, skip the profile edit and set PATH directly:

```dockerfile
RUN ossprey shim install --no-path --all
ENV PATH="/root/.ossprey/shims:${PATH}"
```

> **Note on latency:** a package Ossprey has never seen before takes a scan to
> come back, so the first install of a brand-new version is slower than an
> unprotected one. Subsequent installs hit a cached verdict.

## Supported ecosystems

Python and JavaScript, via syft's static catalogers.

| Ecosystem | Files parsed |
|-----------|--------------|
| Python | `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `pdm.lock`, `setup.py`, `pyproject.toml`, wheel / egg metadata |
| JavaScript | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |

The CLI never executes your package manager. If your repo has only a manifest
and no lockfile, expect direct deps only — supply a lockfile for full
transitive coverage.

When a dependency's version can't be determined — an unpinned range in a
manifest (`click = "^8"`) with no lockfile or resolver to pin it against — the
scan defaults that component to the **latest published version** from its
registry (PyPI / npm): the version a fresh install would pull today. Registry
lookups fail open, so a component whose version can't be resolved (offline,
private, or removed package) is left unversioned rather than dropped or failing
the scan.

To skip these lookups for a fully offline catalog, pass `--no-version-lookup`
(or set `OSSPREY_RESOLVE_LATEST=0`, which also covers the package-manager
forwarders, whose args are passed through untouched). Unpinned components are
then left versionless.

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

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
- [`init` — one-command setup](#init--one-command-setup) — [common invocations](#common-invocations)
- [Usage](#usage)
- [Authentication](#authentication)
- [`check` — scan named packages](#check--scan-named-packages)
- [Package-manager forwarder](#package-manager-forwarder) — check before install for `npm` / `pnpm` / `yarn` / `pip` / `poetry` / `uv`
- [How to make Ossprey scan on all package manager commands](#how-to-make-ossprey-scan-on-all-package-manager-commands) — shell aliases so you don't type `ossprey` first
- [PATH shims](#path-shims--drop-the-ossprey-prefix) — intercept installs in scripts, CI and agents too
- [Pre-commit hook](#pre-commit-hook--block-known-malware-at-commit-time) — check staged dependency changes on every `git commit`
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
# Set up in one command: log in, create an API key, scan with it
ossprey init
```

Or do it by hand:

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

## `init` — one-command setup

```
ossprey init [path] [flags]
```

`ossprey init` gets you from a fresh install to a working, CI-ready setup in one
command. `path` defaults to the current directory. It runs three steps:

1. **Log in.** Reuses a stored login if there is one (refreshing it silently),
   otherwise runs the same browser device flow as `ossprey login`.
2. **Create an API key** and print it once. Keys default to a one-year expiry.
3. **Optionally scan the project using that key**, reporting the verdict exactly
   as `ossprey scan` would.

Step 3 **asks first**. Answer up front with `--scan` or `--no-scan`; when there's
no interactive terminal (CI, or output piped somewhere) it's skipped unless you
pass `--scan`, so `init` never does unrequested work in a script.

The scan deliberately authenticates with the key from step 2 rather than with your
login, so **a clean scan is proof the key works** before you paste it into CI.
`init` writes no files and makes no assumptions about which CI you use — see
[CI usage](#ci-usage) for the snippet to add.

```sh
$ ossprey init
[1/3] Checking login...
Already logged in as you@example.com.
[2/3] Creating an API key...
Created API key "ci-3f9a1c02" (expires 2027-08-14T09:15:00Z).
This is the only time it is shown — it cannot be retrieved later:

    ospy_...

Set it as OSSPREY_API_KEY wherever your scans run. For GitHub Actions:
    gh secret set OSSPREY_API_KEY   # paste the key when prompted

Treat it like a password. It stays in your terminal scrollback, so clear it
when you're done, and don't pipe this command's output to a file or CI log.
Lost it? Create another with `ossprey init`, and delete the unused one at
https://dashboard.ossprey.com — where you can also revoke this one.

Run an example scan of this project now to check the key works? [Y/n] y
[3/3] Scanning with your new API key...
No malware found. See your scans at https://dashboard.ossprey.com

Next steps:
    Add `ossprey scan .` to your CI, with OSSPREY_API_KEY set to this key.
    ossprey shim install         # check every npm/pip install on this machine
    ossprey precommit install    # block commits that add known-malicious packages
```

### Common invocations

**Getting started**

```sh
ossprey init                     # log in, create a key, ask about scanning
ossprey init ./some/project      # same, against another directory
```

**Controlling the scan**

```sh
ossprey init --scan              # scan, don't ask
ossprey init --no-scan           # skip the scan, just get a key
```

In CI — or any time output is piped — the scan is skipped automatically, because
there is nobody to ask. Pass `--scan` if you want it anyway.

**Controlling the key**

```sh
ossprey init --no-key                    # don't create one; scan with your login
ossprey init --key-name my-ci-key        # name it yourself
ossprey init --key-expiry 720h           # 30 days instead of the default year
```

**Piping the key straight into a secret store**

```sh
# GitHub — gh reads the secret value from stdin
ossprey init --key-stdout | gh secret set OSSPREY_API_KEY

# Into a shell variable (progress output goes to stderr, so discard it)
KEY=$(ossprey init --key-stdout 2>/dev/null)
```

`--key-stdout` ends the key with a newline. `gh` strips it, but not every tool
does — if yours doesn't, use command substitution, which strips it for you:

```sh
some-tool set-secret OSSPREY_API_KEY "$(ossprey init --key-stdout 2>/dev/null)"
```

**Just authenticate**

```sh
ossprey init --no-key --no-scan   # login only — same as `ossprey login`
```

**Targeting a non-production tenant**

```sh
ossprey init \
  --url https://api.qa.ossprey.com \
  --auth0-domain auth.qa.ossprey.com \
  --audience https://api.qa.ossprey.com \
  --client-id <qa-app-client-id>

# or via env vars
OSSPREY_AUTH0_DOMAIN=auth.qa.ossprey.com ossprey init

# keep the login out of your real config dir
OSSPREY_CONFIG_DIR=/tmp/ossprey-creds ossprey init
```

**`init` always needs a login.** There is no offline mode: creating a key and
scanning both require credentials, so even `--no-key --no-scan` opens the browser
if you aren't already logged in.

### Getting the key somewhere useful

**The key is shown once and cannot be recovered** — the API stores only an
HMAC hash of it, so neither the dashboard nor the CLI can show it again. If you
lose it, create another and delete the old one.

For scripted setup, `--key-stdout` prints only the key on stdout (all progress
output goes to stderr), so you can pipe it straight into a secret store without
it ever touching your scrollback or disk:

```sh
ossprey init --key-stdout | gh secret set OSSPREY_API_KEY
```

**Re-running creates another key.** Keys are shown only once, so the usual reason
to re-run is that you didn't save the last one — that's the intended path. But
your account is capped at 10 keys, so if you re-run often, pass `--no-key` or
delete the unused keys in the dashboard. If key creation fails for any reason,
`init` warns and still runs the scan (falling back to your login).

Flags:

| Flag | Default | Purpose |
|------|---------|---------|
| `--key-name <name>` | generated (`ci-<random>`) | Name for the created API key (max 20 chars, no whitespace). |
| `--key-expiry <dur>` | `8760h` (1 year) | Lifetime of the created key. The API caps this at 2 years. |
| `--no-key` | off | Don't create a key. The scan then uses your login. |
| `--scan` | ask | Run the example scan without asking. |
| `--no-scan` | ask | Skip the example scan without asking. |
| `--key-stdout` | off | Print only the key on stdout, for piping. Implies no scan. |
| `--url <url>` | `https://api.ossprey.com` | Ossprey API URL. |
| `--auth0-domain <host>` | `auth.ossprey.com` | Auth0 domain (or `OSSPREY_AUTH0_DOMAIN`). |
| `--client-id <id>` | production app | Auth0 client ID (or `OSSPREY_AUTH0_CLIENT_ID`). |
| `--audience <url>` | `https://api.ossprey.com` | Auth0 API audience (or `OSSPREY_AUTH0_AUDIENCE`). |

These three combinations are rejected rather than silently resolved:

| Combination | Why |
|-------------|-----|
| `--scan --no-scan` | Contradictory. |
| `--scan --key-stdout` | A scan verdict on stdout would corrupt the pipe. |
| `--no-key --key-stdout` | No key means nothing to print. |

A stored login is only reused when its domain, client ID and audience all match
the ones this run targets. Point any of those three at a different tenant and
`init` logs in again rather than sending the wrong token to the wrong API.

Creating an API key requires a browser login — API keys cannot mint other API
keys — so step 2 always authenticates via Auth0, never via `OSSPREY_API_KEY`.

`init` does not install the [pre-commit
hook](#pre-commit-hook--block-known-malware-at-commit-time) or [PATH
shims](#path-shims--drop-the-ossprey-prefix), because both change how your
machine behaves outside this project. It prints the commands at the end.

## Usage

| Command | What it does |
|---------|--------------|
| [`ossprey init [path]`](#init--one-command-setup) | Set up a project: log in, create an API key, scan with it. |
| [`ossprey scan [path]`](#scan) | Catalogue a directory, submit the OSSBOM, fail on malware. `path` defaults to `.`. |
| [`ossprey check -e <pypi\|npm> <pkg>...`](#check--scan-named-packages) | Check packages by name, no project needed. |
| [`ossprey npm\|pnpm\|yarn\|pip\|pip3\|poetry\|uv ...`](#package-manager-forwarder) | Check, then run the real package manager. Blocks the install on malware. |
| [`ossprey shim install`](#path-shims--drop-the-ossprey-prefix) | Put shims on `PATH` so installs are checked without the `ossprey` prefix. |
| [`ossprey precommit`](#pre-commit-hook--block-known-malware-at-commit-time) | Git pre-commit hook: block commits that stage known-malicious packages. |
| [`ossprey login`](#authentication) | Browser login via Auth0. Stores tokens locally. |
| [`ossprey whoami`](#authentication) | Show who the stored login belongs to. |
| [`ossprey logout`](#authentication) | Remove the stored login. |
| [`ossprey update`](#updating) | Replace the binary with a newer release. |
| `ossprey completion <shell>` | Print a completion script for bash, zsh, fish or PowerShell. |
| `ossprey --version` | Print the CLI version. |

To have the forwarders run without typing `ossprey` every time, see
[how to make Ossprey scan on all package manager commands](#how-to-make-ossprey-scan-on-all-package-manager-commands).

### `scan`

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
| `--dry-run-safe` | Skip the API; report an empty vulnerability list. |
| `--dry-run-malicious` | Skip the API; inject a test finding against the first component. |
| `--skip-ci` | Skip the Ossprey scan entirely and exit 0. Also settable as `OSSPREY_SKIP_CI=1`. |
| `--ci-cache-scan-only` | Catalogue and submit the scan so results appear in the dashboard, but print no verdict and always exit 0 — the build is never affected, even if the submission fails. Also settable as `OSSPREY_CI_CACHE_SCAN_ONLY=1`. |

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
| `--dry-run-safe` | Skip the API; report an empty vulnerability list. |
| `--dry-run-malicious` | Skip the API; inject a test finding against the first package. |

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

Supported managers: `npm`, `pnpm`, `yarn`, `pip`, `pip3`, `poetry`, `uv`.

### What is checked

Exactly these subcommands. Everything else is forwarded straight through with no
check and no API call.

| Manager | Checked subcommands |
| ------- | ------------------- |
| `npm` | `install`, `i`, `add`, `ci`, `update`, `up` |
| `pnpm` | `install`, `i`, `add`, `update`, `up` |
| `yarn` | `add`, `install`, `upgrade`, `up` |
| `pip`, `pip3` | `install` |
| `poetry` | `add`, `install`, `update`, `lock` |
| `uv` | `add`, `sync`, `pip install` |

Each manager's global options are understood before the subcommand, so
`pnpm --filter web add x` and `npm --prefix ./app install x` are checked like any
other install.

### What is not checked

Pass-through commands are not checked, which is intended for `npm run`,
`pip list` and friends. Three groups are worth calling out, because they can
still put code on your machine:

- **Fetch-and-execute.** `npm exec`, `pnpm dlx`, `yarn dlx` and `uv tool run`
  download a package and run it. They name a package, but it is not an install
  verb, so it is forwarded unchecked. `npx` and `uvx` are separate binaries and
  are not shimmed at all, so they bypass Ossprey entirely.
- **Script runners.** `npm run`, `pnpm run`, `poetry run` and equivalents. The
  scripts themselves are not inspected.
- **Anything the manager resolves that was not named and is not in the
  manifest.** Transitive dependencies of a named install are not resolved here;
  run `ossprey scan` for full-tree coverage.

For these, run `ossprey scan` on the project afterwards.

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

Global options before the subcommand are understood, so the workspace forms are
checked like any other install:

```sh
ossprey pnpm --filter web add left-pad   # checked
ossprey npm --prefix ./app install foo   # checked
ossprey pnpm --filter web run build      # not an install, forwarded
```

If the registry can't be reached to resolve an unpinned named version, that
package is skipped (fail-open) so a registry outage never blocks development.
An install whose only targets are local paths or URLs (nothing checkable and no
manifest to scan) is forwarded with a warning.

> **Known gap (pnpm 9 and earlier):** `pnpm run` and `pnpm exec` install the
> project's declared dependencies as a side effect when `node_modules` is
> missing, which `npm run` does not do. Those are pass-through commands, so the
> packages they pull in are not checked. pnpm 10 no longer appears to do this.
> Either way, run `ossprey pnpm install` (or `ossprey scan`) after a fresh clone
> for coverage.

Flag parsing is disabled so every argument reaches the real manager, which
means the forwarder has no `--api-key` or `--url` of its own. It reads:

- `OSSPREY_API_KEY` — API key
- `OSSPREY_API_URL` — override the API URL (default `https://api.ossprey.com`)
- `OSSPREY_SKIP_CI` — set to `1` to forward every command straight to the real
  manager without any Ossprey check
- `OSSPREY_CI_CACHE_SCAN_ONLY` — set to `1` to still gather and submit the
  packages (results appear in the dashboard) but never block or fail the
  install

A session from `ossprey login` also counts, and takes precedence over
`OSSPREY_API_KEY`, so on your own machine the forwarder usually needs no
environment at all.

## How to make Ossprey scan on all package manager commands

The forwarder only runs when somebody remembers to type `ossprey` first. One
alias per manager removes that step in your own terminal.

Bash or Zsh, in `~/.bashrc` / `~/.zshrc`:

```sh
for mgr in npm pnpm yarn pip pip3 poetry uv; do alias "$mgr=ossprey $mgr"; done
```

Fish, in `~/.config/fish/config.fish`:

```fish
for mgr in npm pnpm yarn pip pip3 poetry uv
    alias $mgr "ossprey $mgr"
end
```

PowerShell, in `$PROFILE` (`Set-Alias` can't carry an argument, so these are
functions):

```powershell
function npm    { ossprey npm    @args }
function pnpm   { ossprey pnpm   @args }
function yarn   { ossprey yarn   @args }
function pip    { ossprey pip    @args }
function pip3   { ossprey pip3   @args }
function poetry { ossprey poetry @args }
function uv     { ossprey uv     @args }
```

Open a new shell to pick them up. There's no recursion to worry about:
`ossprey npm` resolves the real `npm` through `PATH` rather than through your
shell, so the alias doesn't apply a second time. Wrap only the managers
listed above, since `ossprey <anything else>` isn't a command.

An intercepted install needs credentials exactly like `ossprey scan` does, so
run `ossprey login` once (or export `OSSPREY_API_KEY`) before relying on the
aliases. With neither, the install stops on a credentials error rather than
being quietly forwarded.

To check they took, run `type npm`. Non-install commands (`npm run build`, `pip
list`, `poetry run pytest`) go straight through untouched, so an
ordinary-looking `npm --version` means the handoff works. An install prints to
stderr before it forwards:

```console
$ npm install left-pad
ossprey: no malware found, forwarding to npm

added 1 package in 525ms
```

If a check comes back dirty you get the finding, a blocked line naming the
command, and an exit code of `1`. The real manager never starts.

An alias inherits the forwarder's scope: an install that names packages checks
those packages, not their dependencies. Run `ossprey scan` afterwards for the
full tree.

Skip the check for one command by calling the manager directly:

```sh
command npm install ./local-tarball.tgz    # or \npm install ...
```

In PowerShell, `& (Get-Command npm -CommandType Application) install ...` steps
around the profile function. To undo the whole thing, delete the alias lines
and open a new shell.

The limit of aliases is that they exist only in interactive shells. `make
setup`, a `package.json` script, a CI job, and whatever your editor spawns in
the background all miss them. Covering those takes a real executable earlier on
`PATH`, not a shell feature — see [PATH shims](#path-shims--drop-the-ossprey-prefix).

## PATH shims — drop the `ossprey` prefix

Aliases stop at the interactive shell, as above. Shims cover the rest: a shim is
a real executable, so Makefiles, CI steps and the commands your coding agent
spawns go through it too.

A shim is a small script named after the package manager
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

## Pre-commit hook — block known malware at commit time

`ossprey precommit` checks the dependencies a commit **adds or version-bumps**
— staged changes to `package.json`, lockfiles, `requirements.txt`,
`pyproject.toml` and friends — against Ossprey's database of already-confirmed
malware. It runs no new scans: parsing the staged diff is local and typically
takes well under 100 ms, plus one small HTTP request (per 100 packages) for
the lookup. A clean
commit prints nothing at all; a commit that touches no dependency manifest
never calls the API.

It needs an API key via `OSSPREY_API_KEY` (or a stored `ossprey login`
session). Without one it warns and lets the commit through.

**Via the [pre-commit framework](https://pre-commit.com)**, in your
`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/ossprey/ossprey-cli
    rev: v0.11.1  # pin the latest release — or run `pre-commit autoupdate`
                  # to resolve it (the hook first shipped in v0.11.0)
    hooks:
      - id: ossprey
```

`id: ossprey` builds the CLI from source, which needs a Go toolchain. If
`ossprey` is already installed on your `PATH`, use `id: ossprey-system`
instead — no Go required.

**Or as a plain git hook**, no framework needed:

```sh
cd your-repo
ossprey precommit install
```

| Command | What it does |
|---------|--------------|
| `ossprey precommit` | Run the check itself (this is what the hook invokes) |
| `ossprey precommit install` | Write `.git/hooks/pre-commit` in the current repo (respects `core.hooksPath`) |
| `ossprey precommit status` | Show whether the hook is installed in this repo |
| `ossprey precommit uninstall` | Remove the hook — only if ossprey wrote it |

Re-running `install` refreshes an existing ossprey hook in place. A
pre-commit hook that ossprey did **not** write is never overwritten or
removed: chain `ossprey precommit` into it yourself, or let the pre-commit
framework manage both.

**How it behaves**

- **It fails open.** No API key, network outage, API error, git trouble — every
  failure mode short of a confirmed malware hit prints a one-line warning and
  lets the commit through (exit `0`). Exit `1` means exactly one thing: a
  staged package is known-malicious. A hook that can break `git commit` gets
  ripped out, so this one can't. The lookup gets a 10s budget (enough to cover
  the API's cold start) and fails open past it — override with
  `OSSPREY_PRECOMMIT_TIMEOUT` (a Go duration like `15s`).
- **Bypass when you must.** `git commit --no-verify` skips the hook for a
  single commit, at your own risk.
- **It only touches its own files.** `uninstall` deletes the hook only when it
  carries the ossprey marker.

### What is not checked

- **Unpinned ranges.** Only pinned versions are looked up. A manifest change
  like `"left-pad": "^1.3.0"` with no lockfile staged alongside it is skipped —
  resolving "latest" at commit time could block you over a version you'll never
  install. Pin the version or commit a lockfile — a lockfile also gives the
  hook the full transitive tree, where a bare manifest yields direct
  dependencies only.
- **Packages already committed.** The hook diffs the staged manifests against
  `HEAD`, so it only sees what this commit introduces. Auditing what's already
  in the tree is `ossprey scan`'s job.

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

Get a key with [`ossprey init`](#init--one-command-setup) (or from the
dashboard), store it as a secret, and add a scan step. The CLI exits non-zero on
a malware verdict, which fails the build.

The minimal GitHub Actions step:

```yaml
- name: Ossprey scan
  env:
    OSSPREY_API_KEY: ${{ secrets.OSSPREY_API_KEY }}
  run: ossprey scan .
```

A complete workflow, with the two things that are easy to get wrong called out:

```yaml
name: Ossprey malware scan

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  ossprey:
    runs-on: ubuntu-latest
    # GitHub withholds repository secrets from pull_request runs that originate
    # in a fork, so OSSPREY_API_KEY would be empty and the scan would fail for a
    # missing key rather than for malware — a red build no contributor can fix.
    # Skip those runs instead. Do NOT "fix" this by switching the trigger to
    # pull_request_target, which grants your secrets to untrusted code.
    if: >-
      github.event_name != 'pull_request' ||
      github.event.pull_request.head.repo.full_name == github.repository
    steps:
      # Pin actions to a commit SHA, not a mutable tag: a tag can be repointed
      # at new code, which is the same supply-chain risk this job exists to catch.
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: Install ossprey
        run: |
          mkdir -p "$HOME/.local/bin"
          curl -fsSL https://github.com/ossprey/ossprey-cli/releases/latest/download/install.sh \
            | OSSPREY_INSTALL_DIR="$HOME/.local/bin" sh
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"
      - name: Ossprey scan
        env:
          OSSPREY_API_KEY: ${{ secrets.OSSPREY_API_KEY }}
        run: ossprey scan .
```

For other CI systems the shape is the same: install the CLI, set
`OSSPREY_API_KEY` from your secret store, run `ossprey scan .`.

Two env vars help while rolling Ossprey out across a CI estate, and both work
for `ossprey scan` and the package-manager forwarders/shims alike:

- `OSSPREY_SKIP_CI=1` — kill switch: no scan runs at all.
- `OSSPREY_CI_CACHE_SCAN_ONLY=1` — observe-only: scans are gathered and
  submitted so results appear in the dashboard, but the build never fails and
  installs are never blocked.

`ossprey scan` also accepts them as `--skip-ci` / `--ci-cache-scan-only` flags.

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

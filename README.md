# Ossprey CLI

`ossprey` finds malicious packages in your dependencies.

It reads the manifests and lockfiles already in your repo, asks the
[Ossprey](https://ossprey.com) platform whether any of those packages are known
malware, and fails the build if they are. It never installs anything, never runs
your package manager's install, and never needs a sandbox or a virtualenv.

Works with **Python**, **JavaScript** and **Rust** projects.

```console
$ ossprey scan .
No malware found. See your scans at https://dashboard.ossprey.com
```

> **You need a free Ossprey account.** Sign up at
> [ossprey.com](https://ossprey.com). `ossprey login` signs you in from the
> browser; CI uses an API key instead. (The `--local` and `--dry-run-*` modes
> work with no account at all.)

---

## 1. Install

**Linux / macOS**

```sh
curl -fsSL https://github.com/ossprey/ossprey-cli/releases/latest/download/install.sh | sudo sh
```

**Windows (PowerShell)**

```powershell
irm https://github.com/ossprey/ossprey-cli/releases/latest/download/install.ps1 | iex
```

Both scripts verify a sha256 before installing. Pinned versions, custom
directories, manual downloads, building from source and `ossprey update` are all
in [docs/install.md](docs/install.md).

## 2. Set up

```sh
ossprey init
```

One command: it logs you in via the browser, creates an API key, prints it once,
and offers to scan the project to prove the key works. Save that key — it cannot
be shown again.

Prefer to do it by hand?

```sh
ossprey login                       # interactive
export OSSPREY_API_KEY=ospy_...     # or, for CI, a key from the dashboard
```

More in [docs/init.md](docs/init.md).

## 3. Scan something

```sh
ossprey scan .                      # scan a project directory
ossprey check -e npm left-pad@1.3.0 # or just ask about one package
```

**Exit codes are the whole interface:**

| Exit | Meaning |
| ---- | ------- |
| `0` | Nothing malicious found (or the scan was skipped, e.g. quota exhausted) |
| `1` | Malware found — **or** the scan itself failed |

So `ossprey scan .` in a CI job fails the build on malware, with no extra
plumbing. If you need to tell "clean" apart from "errored", or want the findings
as JSON, use [`--report report.json`](docs/output.md#machine-readable-verdict---report).

---

## Stopping malware before it lands

A scan tells you what is already in your project. These three stop something bad
getting in — pick whichever fits how your team works.

### Check installs on your machine

```sh
ossprey npm install left-pad        # checks first, then runs npm
```

If the package is flagged, the install is blocked and `npm` never starts. Works
with `npm`, `pnpm`, `yarn`, `pip`, `pip3`, `poetry` and `uv`.

Tired of typing `ossprey` first?

```sh
ossprey shim install                # now plain `npm install` is checked too
```

Shims are real executables placed early on your `PATH`, so they also cover
Makefiles, CI steps and coding agents — not just your own terminal.

→ [docs/forwarder.md](docs/forwarder.md) for what is and is not checked ·
[docs/shims.md](docs/shims.md) for shims

### Check what a commit adds

```sh
ossprey precommit install
```

Blocks a `git commit` that adds a known-malicious dependency. It looks only at
what the commit changes, takes well under a second, and fails open on any
problem that is not a confirmed hit.

→ [docs/precommit.md](docs/precommit.md)

### Check in CI

```yaml
- uses: ossprey/gh-action@v3   # pin to a commit SHA in a real workflow
  with:
    api-key: ${{ secrets.OSSPREY_API_KEY }}
```

Or run the CLI yourself with `OSSPREY_API_KEY` set. Either way, a malware
verdict is a failed build.

→ [docs/ci.md](docs/ci.md) for a complete workflow, including the fork-PR guard
every repo needs

---

## Watching without blocking

Rolling Ossprey out across a team or a fleet? **Passive mode** submits scans to
the dashboard and never blocks or delays anybody:

```sh
ossprey shim install --watchdog          # uses this machine's login
ossprey shim install --monitor ospi_...  # or a submit-only id, no credential on the machine
```

The install runs first, at full speed; Ossprey reports what was installed
afterwards. Visibility now, gating later.

→ [docs/passive-monitoring.md](docs/passive-monitoring.md)

---

## What gets scanned

| Ecosystem | Read from |
| --------- | --------- |
| Python | `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `pdm.lock`, `setup.py`, `pyproject.toml`, installed metadata |
| JavaScript | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Rust | `Cargo.lock` |

**Commit a lockfile if you can.** A lockfile lists the whole transitive tree; a
bare manifest gives direct dependencies only, and Ossprey has to guess versions
for unpinned ranges. Details, including how unpinned versions are resolved, in
[docs/ecosystems.md](docs/ecosystems.md).

## Common environment variables

| Variable | Effect |
| -------- | ------ |
| `OSSPREY_API_KEY` | Your API key (a stored `ossprey login` takes precedence) |
| `OSSPREY_VERBOSE=1` | Explain every warning, including a failed resolver's own output |
| `OSSPREY_SKIP_CI=1` | Kill switch: no scan runs at all |
| `OSSPREY_PASSIVE=1` | Observe-only: submit scans, never fail a build or block an install |

The full list, and every flag, is in [docs/cli-reference.md](docs/cli-reference.md).

## Documentation

Everything above in depth: **[docs/](docs/README.md)** — [install](docs/install.md)
· [`init`](docs/init.md) · [CLI reference](docs/cli-reference.md) ·
[forwarder](docs/forwarder.md) · [shims](docs/shims.md) ·
[passive monitoring](docs/passive-monitoring.md) ·
[pre-commit](docs/precommit.md) · [CI](docs/ci.md) · [output](docs/output.md) ·
[ecosystems](docs/ecosystems.md) · [how it works](docs/architecture.md)

## Status

Pre-1.0. The CLI surface, OSSBOM schema, and API contract are stable enough
for production use; expect additive changes only.

## Support

- Docs: [docs.ossprey.com](https://docs.ossprey.com)
- Issues: [github.com/ossprey/ossprey-cli/issues](https://github.com/ossprey/ossprey-cli/issues)
- Email: support@ossprey.com

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

### Authentication

The API key is read from, in order:

1. `--api-key` flag
2. `OSSPREY_API_KEY` env var
3. `API_KEY` env var

`--local`, `--dry-run-safe` and `--dry-run-malicious` don't talk to the API
and don't need a key.

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

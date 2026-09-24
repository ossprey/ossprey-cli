# Install

Every way to install and update the CLI, on every supported platform.

## One-liner (Linux / macOS)

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
shims](shims.md), so `npm install` and `pip install`
are checked without typing `ossprey`:

```sh
curl -fsSL https://github.com/ossprey/ossprey-cli/releases/latest/download/install.sh \
  | sudo sh -s -- --override-package-managers
```

## One-liner (Windows PowerShell)

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

## Manual download

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

## From source

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

## Updating

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

After a successful command, ossprey checks for a newer release at most once per
day. When one is available, it prints a short upgrade notice to stderr; update
check failures never affect the command.

---

[← Back to the docs index](README.md)

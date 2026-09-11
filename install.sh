#!/bin/sh
# Ossprey CLI installer.
#
# Usage:
#   curl -fsSL https://github.com/ossprey/ossprey-cli/releases/latest/download/install.sh | sh
#   curl -fsSL https://github.com/ossprey/ossprey-cli/releases/latest/download/install.sh | sudo sh
#
#   # ...and have ossprey intercept npm/pip/... installs automatically:
#   curl -fsSL .../install.sh | sh -s -- --override-package-managers
#
# Flags:
#   --override-package-managers  Install PATH shims so npm, pnpm, yarn, pip,
#                                pip3, poetry and uv route through ossprey
#                                without being prefixed. Equivalent to running
#                                `ossprey shim install` afterwards.
#   --watchdog                   With the shims, submit scans passively using
#                                this machine's login and never block installs.
#   --monitor <id>               With the shims, submit passively through a
#                                monitor's id, needing no credential at all.
#
# Env vars:
#   OSSPREY_VERSION      Tag to install (e.g. v0.1.0). Default: latest.
#   OSSPREY_INSTALL_DIR  Install location. Default: /usr/local/bin.
#   OSSPREY_OVERRIDE_PACKAGE_MANAGERS=1   Same as --override-package-managers.
#   OSSPREY_WATCHDOG=1                    Same as --watchdog.
#   OSSPREY_MONITOR_ID=<id>               Same as --monitor <id>.

set -eu

REPO="ossprey/ossprey-cli"
BIN="ossprey"
VERSION="${OSSPREY_VERSION:-latest}"
INSTALL_DIR="${OSSPREY_INSTALL_DIR:-/usr/local/bin}"
OVERRIDE="${OSSPREY_OVERRIDE_PACKAGE_MANAGERS:-}"
WATCHDOG="${OSSPREY_WATCHDOG:-}"
MONITOR_ID="${OSSPREY_MONITOR_ID:-}"

log()  { printf '==> %s\n' "$*" >&2; }
err()  { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
  cat >&2 <<'EOF'
Ossprey CLI installer.

  curl -fsSL .../install.sh | sh
  curl -fsSL .../install.sh | sh -s -- --override-package-managers

Flags:
  --override-package-managers   Install PATH shims so npm, pnpm, yarn, pip,
                                pip3, poetry and uv route through ossprey
                                without being prefixed (`ossprey shim install`).
  --watchdog                    Passive mode for the shims: submit scans with
                                this machine's login, never block an install.
  --monitor <id>                Passive mode for the shims using a monitor's
                                id, so the machine needs no credential.
  -h, --help                    Show this help.

Env vars:
  OSSPREY_VERSION               Tag to install (e.g. v0.1.0). Default: latest.
  OSSPREY_INSTALL_DIR           Install location. Default: /usr/local/bin.
  OSSPREY_OVERRIDE_PACKAGE_MANAGERS=1   Same as --override-package-managers.
  OSSPREY_WATCHDOG=1            Same as --watchdog.
  OSSPREY_MONITOR_ID=<id>       Same as --monitor <id>.
EOF
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --override-package-managers|--shims) OVERRIDE=1 ;;
    --watchdog) WATCHDOG=1; OVERRIDE=1 ;;
    --monitor)
      shift
      { [ $# -gt 0 ] && [ -n "$1" ]; } || err "--monitor needs an id"
      MONITOR_ID="$1"
      OVERRIDE=1
      ;;
    --monitor=*)
      MONITOR_ID="${1#--monitor=}"
      [ -n "$MONITOR_ID" ] || err "--monitor needs an id"
      OVERRIDE=1
      ;;
    -h|--help) usage ;;
    *) err "unknown option: $1 (try --help)" ;;
  esac
  shift
done

# --- detect OS ---
os_raw="$(uname -s)"
case "$os_raw" in
  Linux)   OS=linux ;;
  Darwin)  OS=darwin ;;
  *)       err "unsupported OS: $os_raw (Windows users: use install.ps1 — see the README)" ;;
esac

# --- detect arch ---
arch_raw="$(uname -m)"
case "$arch_raw" in
  x86_64|amd64)   ARCH=amd64 ;;
  aarch64|arm64)  ARCH=arm64 ;;
  *)              err "unsupported arch: $arch_raw" ;;
esac

ASSET="${BIN}-${OS}-${ARCH}"

if [ "$VERSION" = "latest" ]; then
  BASE="https://github.com/${REPO}/releases/latest/download"
else
  BASE="https://github.com/${REPO}/releases/download/${VERSION}"
fi

URL="${BASE}/${ASSET}"
SUM_URL="${URL}.sha256"

# --- pick downloader ---
if command -v curl >/dev/null 2>&1; then
  DL='curl -fsSL -o'
elif command -v wget >/dev/null 2>&1; then
  DL='wget -qO'
else
  err "need curl or wget"
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

log "downloading $URL"
$DL "$tmpdir/$BIN" "$URL" || err "download failed"

# --- verify sha256 if available ---
if $DL "$tmpdir/$ASSET.sha256" "$SUM_URL" 2>/dev/null; then
  log "verifying sha256"
  expected="$(awk '{print $1}' "$tmpdir/$ASSET.sha256")"
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$tmpdir/$BIN" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$tmpdir/$BIN" | awk '{print $1}')"
  else
    log "no sha256 tool found, skipping verification"
    actual="$expected"
  fi
  [ "$expected" = "$actual" ] || err "sha256 mismatch: expected $expected, got $actual"
else
  log "no sha256 file found, skipping verification"
fi

chmod +x "$tmpdir/$BIN"

# --- install ---
# A custom OSSPREY_INSTALL_DIR often does not exist yet (the README's own
# $HOME/.local/bin example, CI runners). Without this, `test -w` fails on the
# missing directory and we fall through to sudo, which then also fails moving
# into a path that isn't there. Only attempt this for a non-default dir the
# user can create; /usr/local/bin already exists and may need root.
if [ ! -d "$INSTALL_DIR" ] && [ "$INSTALL_DIR" != "/usr/local/bin" ]; then
  mkdir -p "$INSTALL_DIR" 2>/dev/null \
    || log "could not create $INSTALL_DIR; will try with sudo"
fi

if [ -w "$INSTALL_DIR" ]; then
  mv "$tmpdir/$BIN" "$INSTALL_DIR/$BIN"
elif command -v sudo >/dev/null 2>&1; then
  log "installing to $INSTALL_DIR (needs sudo)"
  sudo mv "$tmpdir/$BIN" "$INSTALL_DIR/$BIN"
else
  err "$INSTALL_DIR not writable and sudo unavailable. Set OSSPREY_INSTALL_DIR to a writable path."
fi

log "installed $($INSTALL_DIR/$BIN --version 2>/dev/null || echo "$BIN") to $INSTALL_DIR/$BIN"

# --- optional: PATH shims over the package managers ---
if [ -n "$MONITOR_ID" ] && [ -n "$WATCHDOG" ]; then
  err "--watchdog and --monitor are mutually exclusive"
fi

# Passed through unquoted on purpose: "set --" builds the argument list so an
# empty MODE_ARGS adds no argument at all, and the monitor id is validated by
# `shim install` before it is written anywhere.
if [ -n "$MONITOR_ID" ]; then
  set -- --monitor "$MONITOR_ID"
elif [ -n "$WATCHDOG" ]; then
  set -- --watchdog
else
  set --
fi

if [ -n "$OVERRIDE" ]; then
  log "installing package-manager shims"
  if [ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ]; then
    sudo -u "$SUDO_USER" -H "$INSTALL_DIR/$BIN" shim install "$@" \
      || log "shim install failed; ossprey itself is installed — run 'ossprey shim install' to retry"
  else
    "$INSTALL_DIR/$BIN" shim install "$@" \
      || log "shim install failed; ossprey itself is installed — run 'ossprey shim install' to retry"
  fi
fi

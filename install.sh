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
#   --override-package-managers  Install PATH shims so npm, npx, pnpm, yarn,
#                                bun, bunx, pip, pip3, poetry, uv and uvx route
#                                through ossprey without being prefixed.
#                                Equivalent to running
#                                `ossprey shim install` afterwards.
#   --watchdog                   With the shims, submit scans passively using
#                                this machine's login and never block installs.
#   --monitor <id>               With the shims, submit passively through a
#                                monitor's id, needing no credential at all.
#   --git                        Also shim git (opt-in): check public GitHub
#                                repos on clone/pull. Implies the shims.
#
# Env vars:
#   OSSPREY_VERSION      Tag to install (e.g. v0.1.0). Default: latest.
#   OSSPREY_INSTALL_DIR  Install location. Default: /usr/local/bin.
#   OSSPREY_OVERRIDE_PACKAGE_MANAGERS=1   Same as --override-package-managers.
#   OSSPREY_WATCHDOG=1                    Same as --watchdog.
#   OSSPREY_MONITOR_ID=<id>               Same as --monitor <id>.
#   OSSPREY_SHIM_GIT=1                    Same as --git.
#   OSSPREY_SKIP_CHECKSUM=1               Install without verifying the sha256
#                                         (not recommended).
#
# Upgrading: shims already installed are re-pointed at the new binary, keeping
# each one's mode; nothing else is shimmed and no profile is touched.

set -eu

REPO="ossprey/ossprey-cli"
BIN="ossprey"
VERSION="${OSSPREY_VERSION:-latest}"
INSTALL_DIR="${OSSPREY_INSTALL_DIR:-/usr/local/bin}"
OVERRIDE="${OSSPREY_OVERRIDE_PACKAGE_MANAGERS:-}"
WATCHDOG="${OSSPREY_WATCHDOG:-}"
MONITOR_ID="${OSSPREY_MONITOR_ID:-}"
SHIM_GIT="${OSSPREY_SHIM_GIT:-}"
SKIP_CHECKSUM="${OSSPREY_SKIP_CHECKSUM:-}"

log()  { printf '==> %s\n' "$*" >&2; }
err()  { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
  cat >&2 <<'EOF'
Ossprey CLI installer.

  curl -fsSL .../install.sh | sh
  curl -fsSL .../install.sh | sh -s -- --override-package-managers

Flags:
  --override-package-managers   Install PATH shims so npm, npx, pnpm, yarn,
                                bun, bunx, pip, pip3, poetry, uv and uvx route
                                through ossprey without being prefixed
                                (`ossprey shim install`).
  --watchdog                    Passive mode for the shims: submit scans with
                                this machine's login, never block an install.
  --monitor <id>                Passive mode for the shims using a monitor's
                                id, so the machine needs no credential.
  --git                         Also shim git: check public GitHub repos on
                                clone/pull (opt-in).
  -h, --help                    Show this help.

Env vars:
  OSSPREY_VERSION               Tag to install (e.g. v0.1.0). Default: latest.
  OSSPREY_INSTALL_DIR           Install location. Default: /usr/local/bin.
  OSSPREY_OVERRIDE_PACKAGE_MANAGERS=1   Same as --override-package-managers.
  OSSPREY_WATCHDOG=1            Same as --watchdog.
  OSSPREY_MONITOR_ID=<id>       Same as --monitor <id>.
  OSSPREY_SHIM_GIT=1            Same as --git.
  OSSPREY_SKIP_CHECKSUM=1       Install without verifying the sha256
                                (not recommended).
EOF
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --override-package-managers|--shims) OVERRIDE=1 ;;
    --watchdog) WATCHDOG=1; OVERRIDE=1 ;;
    --git) SHIM_GIT=1; OVERRIDE=1 ;;
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

# --- verify sha256 ---
# Fail closed: a binary we could not verify is not installed. Every release
# asset ships a .sha256 sidecar, so a missing one means something is wrong
# (a proxy, a mirror, a tampered release) -- not a reason to trust the binary.
# OSSPREY_SKIP_CHECKSUM=1 is the explicit, logged escape hatch.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  else
    return 1
  fi
}

if [ -n "$SKIP_CHECKSUM" ]; then
  log "OSSPREY_SKIP_CHECKSUM is set: NOT verifying the sha256 of $ASSET"
else
  $DL "$tmpdir/$ASSET.sha256" "$SUM_URL" \
    || err "could not download $SUM_URL to verify the binary (set OSSPREY_SKIP_CHECKSUM=1 to install unverified)"
  log "verifying sha256"
  expected="$(awk 'NR==1 {print tolower($1)}' "$tmpdir/$ASSET.sha256")"
  case "$expected" in
    *[!0-9a-f]*|'') err "malformed checksum file $SUM_URL" ;;
  esac
  [ "${#expected}" -eq 64 ] || err "malformed checksum file $SUM_URL"
  actual="$(sha256_of "$tmpdir/$BIN")" \
    || err "no sha256 tool found (sha256sum, shasum or openssl) to verify the binary (set OSSPREY_SKIP_CHECKSUM=1 to install unverified)"
  actual="$(printf '%s' "$actual" | tr 'A-F' 'a-f')"
  [ "$expected" = "$actual" ] || err "sha256 mismatch: expected $expected, got $actual"
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

log "installed $("$INSTALL_DIR/$BIN" --version 2>/dev/null || echo "$BIN") to $INSTALL_DIR/$BIN"

# --- optional: PATH shims over the package managers ---
if [ -n "$MONITOR_ID" ] && [ -n "$WATCHDOG" ]; then
  err "--watchdog and --monitor are mutually exclusive"
fi

# Asking for a mode is asking for the shims: the flags set OVERRIDE themselves,
# so without this the env-var spelling installs no shims at all and says nothing
# about it, leaving an operator believing a fleet reports when it does not.
if [ -n "$MONITOR_ID" ] || [ -n "$WATCHDOG" ] || [ -n "$SHIM_GIT" ]; then
  OVERRIDE=1
fi

# "set --" builds the argument list so an empty mode adds no argument at all,
# and the monitor id is validated by `shim install` before it is written
# anywhere.
if [ -n "$MONITOR_ID" ]; then
  set -- --monitor "$MONITOR_ID"
elif [ -n "$WATCHDOG" ]; then
  set -- --watchdog
else
  set --
fi
if [ -n "$SHIM_GIT" ]; then
  set -- "$@" --git
fi

# Run ossprey as the invoking user: under `curl ... | sudo sh` the shims and
# profiles belong to $SUDO_USER, not root.
as_user() {
  if [ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ]; then
    sudo -u "$SUDO_USER" -H "$INSTALL_DIR/$BIN" "$@"
  else
    "$INSTALL_DIR/$BIN" "$@"
  fi
}

# existing_shims prints a comma-separated list of the managers already shimmed
# (files in the shim directory carrying the shim marker), or nothing.
existing_shims() {
  shim_dir="$(as_user shim dir 2>/dev/null)" || return 0
  [ -d "$shim_dir" ] || return 0
  found=''
  for f in "$shim_dir"/*; do
    [ -f "$f" ] && grep -q 'OSSPREY-SHIM-V1' "$f" 2>/dev/null || continue
    name="$(basename "$f")"
    case "$name" in *.*) continue ;; esac  # a leftover npm.tmp, not a manager
    found="${found:+$found,}$name"
  done
  printf '%s' "$found"
}

if [ -n "$OVERRIDE" ]; then
  log "installing package-manager shims"
  as_user shim install "$@" \
    || log "shim install failed; ossprey itself is installed — run 'ossprey shim install' to retry"
else
  # An upgrade re-points the shims already installed, so they call this binary
  # and pick up the current shim script. Explicit --managers and --no-path keep
  # it to exactly that: each shim keeps its own mode, nothing new is shimmed,
  # and no profile is edited.
  shimmed="$(existing_shims)"
  if [ -n "$shimmed" ]; then
    log "re-pointing existing shims ($shimmed)"
    as_user shim install --no-path --managers "$shimmed" >/dev/null \
      || log "could not re-point the shims — run 'ossprey shim install' to retry"
  fi
fi

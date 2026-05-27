#!/bin/sh
# Ossprey CLI installer.
#
# Usage:
#   curl -fsSL https://github.com/ossprey/ossprey-cli/releases/latest/download/install.sh | sh
#   curl -fsSL https://github.com/ossprey/ossprey-cli/releases/latest/download/install.sh | sudo sh
#
# Env vars:
#   OSSPREY_VERSION   Tag to install (e.g. v0.1.0). Default: latest.
#   OSSPREY_INSTALL_DIR  Install location. Default: /usr/local/bin.

set -eu

REPO="ossprey/ossprey-cli"
BIN="ossprey"
VERSION="${OSSPREY_VERSION:-latest}"
INSTALL_DIR="${OSSPREY_INSTALL_DIR:-/usr/local/bin}"

log()  { printf '==> %s\n' "$*" >&2; }
err()  { printf 'error: %s\n' "$*" >&2; exit 1; }

# --- detect OS ---
os_raw="$(uname -s)"
case "$os_raw" in
  Linux)   OS=linux ;;
  Darwin)  OS=darwin ;;
  *)       err "unsupported OS: $os_raw (Windows users: download the .exe from the releases page)" ;;
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
if [ -w "$INSTALL_DIR" ]; then
  mv "$tmpdir/$BIN" "$INSTALL_DIR/$BIN"
elif command -v sudo >/dev/null 2>&1; then
  log "installing to $INSTALL_DIR (needs sudo)"
  sudo mv "$tmpdir/$BIN" "$INSTALL_DIR/$BIN"
else
  err "$INSTALL_DIR not writable and sudo unavailable. Set OSSPREY_INSTALL_DIR to a writable path."
fi

log "installed $($INSTALL_DIR/$BIN --version 2>/dev/null || echo "$BIN") to $INSTALL_DIR/$BIN"

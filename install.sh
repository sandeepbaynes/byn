#!/bin/sh
# byn installer — https://github.com/sandeepbaynes/byn
#
#   curl -fsSL https://raw.githubusercontent.com/sandeepbaynes/byn/main/install.sh | sh
#
# Environment overrides:
#   BYN_VERSION=0.0.1        pin a specific version
#   BYN_DL_BASE=URL          override the download base URL
#   BYN_INSTALL_DIR=DIR      override the install directory
set -eu

VERSION="${BYN_VERSION:-0.0.1}"
BASE="${BYN_DL_BASE:-https://github.com/sandeepbaynes/byn/releases/download/v${VERSION}}"

say() { printf 'byn-install: %s\n' "$*" >&2; }
die() { say "error: $*"; exit 1; }

# ---- detect platform ----------------------------------------------------
os="$(uname -s)"
case "$os" in
  Darwin) os=darwin ;;
  Linux)  os=linux ;;
  *) die "unsupported OS '$os' — try 'go install github.com/sandeepbaynes/byn/cmd/byn@latest' or Homebrew" ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) die "unsupported architecture '$arch'" ;;
esac

asset="byn-${os}-${arch}"
url="${BASE}/${asset}"

# ---- pick an install dir ------------------------------------------------
dir="${BYN_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  if [ -w /usr/local/bin ]; then dir=/usr/local/bin; else dir="$HOME/.local/bin"; fi
fi
mkdir -p "$dir"

fetch() { # fetch URL OUTFILE
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
  else die "need curl or wget"; fi
}

# ---- download -----------------------------------------------------------
tmp="$(mktemp)"
say "downloading $asset ($VERSION) …"
fetch "$url" "$tmp" || die "download failed from $url"

# ---- verify checksum (best-effort) --------------------------------------
sums="$(mktemp)"
if fetch "${BASE}/byn-${VERSION}.sha256" "$sums" 2>/dev/null && [ -s "$sums" ]; then
  want="$(awk -v a="$asset" '$2==a || $2=="*"a {print $1}' "$sums" | head -n1)"
  if [ -n "${want:-}" ]; then
    if command -v shasum >/dev/null 2>&1; then got="$(shasum -a 256 "$tmp" | awk '{print $1}')";
    elif command -v sha256sum >/dev/null 2>&1; then got="$(sha256sum "$tmp" | awk '{print $1}')";
    else got=""; fi
    [ -z "$got" ] || [ "$got" = "$want" ] || die "checksum mismatch for $asset"
    [ -z "$got" ] || say "checksum ok"
  fi
fi
rm -f "$sums"

# ---- install ------------------------------------------------------------
chmod 0755 "$tmp"
dest="$dir/byn"
if ! mv "$tmp" "$dest" 2>/dev/null; then
  say "installing to $dest (needs elevated permissions)"
  sudo mv "$tmp" "$dest" || die "could not install to $dest"
fi

say "installed $dest ($VERSION)"

# ---- ensure the install dir is on PATH ----------------------------------
# Only acts when $dir isn't already on PATH (so /usr/local/bin installs are
# untouched). Appends to the right shell rc, idempotently. Opt out with
# BYN_NO_MODIFY_PATH=1.
case ":$PATH:" in
  *":$dir:"*)
    : ;; # already on PATH — nothing to do
  *)
    line="export PATH=\"$dir:\$PATH\""
    rc=""
    case "${SHELL:-}" in
      *zsh)  rc="$HOME/.zshrc" ;;
      *bash) [ "$os" = darwin ] && rc="$HOME/.bash_profile" || rc="$HOME/.bashrc" ;;
    esac
    if [ "${BYN_NO_MODIFY_PATH:-0}" = "1" ] || [ -z "$rc" ]; then
      say "add '$dir' to your PATH:  $line"
    elif grep -qsF "$dir" "$rc"; then
      say "'$dir' is referenced in $rc already — restart your shell to pick it up"
    else
      printf '\n# Added by the byn installer\n%s\n' "$line" >> "$rc"
      say "added '$dir' to your PATH in $rc"
      say "run:  source $rc   (or open a new terminal)"
    fi
    ;;
esac
say "next:  byn daemon start  &&  byn init"

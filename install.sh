#!/bin/sh
# byn installer — https://github.com/sandeepbaynes/byn
#
#   curl -fsSL https://raw.githubusercontent.com/sandeepbaynes/byn/main/install.sh | sh
#
# Environment overrides:
#   BYN_VERSION=0.2.0        pin a version (default: latest GitHub release)
#   BYN_DL_BASE=URL          override the download base URL
#   BYN_INSTALL_DIR=DIR      override the install directory
#   BYN_NO_MODIFY_PATH=1     don't touch shell rc files
set -eu

say() { printf 'byn-install: %s\n' "$*" >&2; }
die() { say "error: $*"; exit 1; }

fetch() { # fetch URL OUTFILE
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
  else die "need curl or wget"; fi
}

# ---- resolve version (latest release unless pinned) ---------------------
VERSION="${BYN_VERSION:-}"
if [ -z "$VERSION" ]; then
  vf="$(mktemp)"
  if fetch "https://api.github.com/repos/sandeepbaynes/byn/releases/latest" "$vf" 2>/dev/null; then
    VERSION="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/p' "$vf" | head -n1)"
  fi
  rm -f "$vf"
  [ -n "$VERSION" ] || die "could not resolve the latest version — set BYN_VERSION=X.Y.Z"
fi
BASE="${BYN_DL_BASE:-https://github.com/sandeepbaynes/byn/releases/download/v${VERSION}}"

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

asset="byn-${os}-${arch}.tar.gz"
url="${BASE}/${asset}"

# ---- pick an install dir ------------------------------------------------
# Default to /usr/local/bin — a system path that sudo can find. byn requires
# root (sudo byn setup) for privilege separation, so the binary belongs in a
# path that sudo's secure_path includes. The install step below uses sudo if
# the current user can't write there directly.
# Override with BYN_INSTALL_DIR if you need a non-standard location.
dir="${BYN_INSTALL_DIR:-/usr/local/bin}"
mkdir -p "$dir" 2>/dev/null || true

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

# ---- extract ------------------------------------------------------------
work="$(mktemp -d)"
tar -xzf "$tmp" -C "$work" || die "could not extract $asset"
rm -f "$tmp"
[ -f "$work/byn" ] || die "archive did not contain the byn binary"
chmod 0755 "$work/byn"
# byn-exec-helper ships in the same archive for privsep; `byn setup` locates
# it next to the byn binary, so it must land in the same directory.
if [ -f "$work/byn-exec-helper" ]; then
  chmod 0755 "$work/byn-exec-helper"
fi

# ---- install binary -----------------------------------------------------
dest="$dir/byn"
SUDO=""
if ! mv "$work/byn" "$dest" 2>/dev/null; then
  say "installing to $dest (needs elevated permissions)"
  SUDO="sudo"
  $SUDO mv "$work/byn" "$dest" || die "could not install to $dest"
fi
# Restore SELinux file context after mv from a temp dir (Fedora/RHEL only;
# restorecon is a no-op or absent on other distros so ignore failures).
$SUDO restorecon "$dest" 2>/dev/null || true
say "installed $dest ($VERSION)"

# ---- install privsep helper (alongside byn) -----------------------------
# SUDO is already set correctly from the byn install step above (either "" or
# "sudo"). Install the helper to the same $dir so `byn setup` finds it next
# to byn via os.Executable()→dir→"byn-exec-helper".
PRIVSEP_HELPER=0
if [ -f "$work/byn-exec-helper" ]; then
  helper_dest="$dir/byn-exec-helper"
  $SUDO mv "$work/byn-exec-helper" "$helper_dest" || say "warning: could not install byn-exec-helper to $helper_dest"
  $SUDO restorecon "$helper_dest" 2>/dev/null || true
  say "installed $helper_dest (privsep helper)"
  PRIVSEP_HELPER=1
fi

# ---- install man page (best-effort) -------------------------------------
# $prefix/bin → $prefix/share/man/man1, the path `man` searches by default.
if [ -f "$work/man/byn.1" ]; then
  mandir="$(dirname "$dir")/share/man/man1"
  if $SUDO mkdir -p "$mandir" 2>/dev/null && $SUDO cp "$work/man/byn.1" "$mandir/byn.1" 2>/dev/null; then
    say "man page → $mandir/byn.1  (try: man byn)"
  else
    say "man page skipped (could not write $mandir)"
  fi
fi
rm -rf "$work"

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
if [ "$PRIVSEP_HELPER" = "1" ]; then
  say "next:  sudo byn setup  &&  byn init"
else
  say "next:  byn start  &&  byn init"
fi

#!/usr/bin/env bash
# Reproduces the build-cache ownership trap: bundlers (Next.js, Vite) create
# cache directories as the exec user, which the invoking user then cannot
# delete. Run under `byn exec`, then try `rm -rf .next` as yourself.
set -euo pipefail

echo "building (uid $(id -u), gid $(id -g))"
mkdir -p .next/cache/webpack node_modules/.vite/deps
date > .next/BUILD_ID
echo "chunk" > .next/cache/webpack/0.pack
echo "dep" > node_modules/.vite/deps/react.js
echo "build complete; artifacts:"
find .next node_modules/.vite -type f -printf '  %p  owner=%u  mode=%m\n' 2>/dev/null | head

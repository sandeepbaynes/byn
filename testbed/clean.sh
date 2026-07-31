#!/usr/bin/env bash
# Exists only because artifacts created under privsep belong to _byn-exec and
# the invoking user cannot delete them. Must be pinned in .byn [exec] actions
# and re-trusted, or cleanup is impossible without sudo.
set -euo pipefail
rm -rf .next node_modules
echo "cleaned (uid $(id -u))"

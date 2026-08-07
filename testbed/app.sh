#!/usr/bin/env bash
# Stands in for a real service: every config value must arrive from byn.
# Missing vars crash loudly rather than defaulting, matching the rule the
# maison-agent project enforces (no env-var fallback defaults, ever).
set -euo pipefail

require() {
  local name=$1
  if [[ -z "${!name:-}" ]]; then
    echo "FATAL: missing required environment variable: $name" >&2
    exit 78 # EX_CONFIG
  fi
  printf '  %-24s = %s\n' "$name" "${!name}"
}

echo "testbed app starting (pid $$, uid $(id -u))"
for v in "$@"; do require "$v"; done
echo "testbed app OK"

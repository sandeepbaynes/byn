#!/usr/bin/env bash
# Long-running process, like a dev server an agent starts and later restarts.
# Holds its injected env for its whole lifetime — useful for testing what
# happens when a secret is rotated while processes still hold the old value.
set -euo pipefail

: "${TESTBED_DB_URL:?missing TESTBED_DB_URL}"
echo "server listening (pid $$, uid $(id -u)) with TESTBED_DB_URL=$TESTBED_DB_URL"
trap 'echo "server shutting down"; exit 0' TERM INT
while true; do sleep 1; done

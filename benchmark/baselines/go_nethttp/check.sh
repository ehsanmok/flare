#!/bin/bash
# Verify the server is up by making a single request. Exit 0 on 200, else 1.
set -euo pipefail
PORT="${FLARE_BENCH_PORT:-8080}"
URL="http://127.0.0.1:$PORT/plaintext"

# Go needs a moment to compile + initialise; wait up to 20s.
for i in $(seq 1 40); do
    if curl --silent --fail --max-time 1 "$URL" > /dev/null; then
        exit 0
    fi
    sleep 0.5
done
echo "check.sh: server did not answer after 20s at $URL"
exit 1

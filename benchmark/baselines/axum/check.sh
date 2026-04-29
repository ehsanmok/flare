#!/bin/bash
# Verify the axum server is up by making a single request. Exit 0 on 200, else 1.
# Cargo's first build can take ~30-90s; wait up to 120s.
set -euo pipefail
PORT="${FLARE_BENCH_PORT:-8080}"
URL="http://127.0.0.1:$PORT/plaintext"

for i in $(seq 1 240); do
    if curl --silent --fail --max-time 1 "$URL" > /dev/null; then
        exit 0
    fi
    sleep 0.5
done
echo "check.sh: server did not answer after 120s at $URL"
exit 1

#!/bin/bash
set -euo pipefail
PORT="${FLARE_BENCH_PORT:-8080}"
URL="http://127.0.0.1:$PORT/plaintext"
# fasthttp fetches modules on first run; allow up to 30s.
for i in $(seq 1 60); do
    if curl --silent --fail --max-time 1 "$URL" > /dev/null; then
        exit 0
    fi
    sleep 0.5
done
echo "check.sh: server did not answer after 30s at $URL"
exit 1

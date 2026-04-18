#!/bin/bash
set -euo pipefail
PORT="${FLARE_BENCH_PORT:-8080}"
URL="http://127.0.0.1:$PORT/plaintext"
# flare takes a bit longer to come up because mojo is compiling the
# source on first run; give it 30s max.
for i in $(seq 1 60); do
    if curl --silent --fail --max-time 1 "$URL" > /dev/null; then
        exit 0
    fi
    sleep 0.5
done
echo "check.sh: server did not answer after 30s at $URL"
exit 1

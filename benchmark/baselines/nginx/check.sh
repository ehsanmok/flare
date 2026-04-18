#!/bin/bash
set -euo pipefail
PORT="${FLARE_BENCH_PORT:-8080}"
URL="http://127.0.0.1:$PORT/plaintext"
for i in 1 2 3 4 5 6 7 8 9 10; do
    if curl --silent --fail --max-time 1 "$URL" > /dev/null; then
        exit 0
    fi
    sleep 0.2
done
echo "check.sh: server did not answer after 10 tries at $URL"
exit 1

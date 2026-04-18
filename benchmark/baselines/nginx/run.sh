#!/bin/bash
# Launch nginx with a templated config (PID + port substituted).
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="${FLARE_BENCH_PID_FILE:-$DIR/../../results/.server.pid}"
PORT="${FLARE_BENCH_PORT:-8080}"
NGINX_PID="$DIR/nginx.pid"

# Render the config.
RENDERED="$DIR/nginx-rendered.conf"
sed -e "s|{{PORT}}|$PORT|g" -e "s|{{NGINX_PID}}|$NGINX_PID|g" \
    "$DIR/nginx.conf" > "$RENDERED"

# Launch nginx in foreground; background the shell so we can record PID.
nginx -c "$RENDERED" -p "$DIR/" &
NGINX_SHELL_PID=$!
echo "$NGINX_SHELL_PID" > "$PID_FILE"

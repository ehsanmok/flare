#!/bin/bash
# Launch nginx with a templated config (PID + port substituted).
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="${FLARE_BENCH_PID_FILE:-$DIR/../../results/.server.pid}"
PORT="${FLARE_BENCH_PORT:-8080}"
NGINX_PID="$DIR/nginx.pid"

# Ensure nginx's temp-path parent exists. The config (see nginx.conf) pins
# all the http_* temp paths under /tmp/nginx-flare-bench to avoid relying
# on the conda-forge nginx's relative compile-time defaults, which point
# into the bench dir and break on clean checkouts / CI runners.
mkdir -p /tmp/nginx-flare-bench

# Render the config.
RENDERED="$DIR/nginx-rendered.conf"
sed -e "s|{{PORT}}|$PORT|g" -e "s|{{NGINX_PID}}|$NGINX_PID|g" \
    "$DIR/nginx.conf" > "$RENDERED"

# Launch nginx in foreground; background the shell so we can record PID.
# -e /dev/null silences the bootstrap "could not open error log file"
# alert that fires before the config is parsed: the conda-forge build
# bakes in a relative error-log path (var/log/nginx/error.log) that
# nginx tries to open before it sees our "error_log /dev/null emerg"
# directive. On macOS homebrew's nginx already points at a writable
# /usr/local/var path, which is why the alert only shows on Linux.
nginx -c "$RENDERED" -p "$DIR/" -e /dev/null &
NGINX_SHELL_PID=$!
echo "$NGINX_SHELL_PID" > "$PID_FILE"

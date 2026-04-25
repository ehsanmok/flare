#!/usr/bin/env bash
# benchmark/scripts/_make_self_signed.sh
#
# Generate a self-signed cert + key pair for the TLS bench
# (v0.5.0 Step 3 / Track 6.4). Self-signed because wrk does not
# verify the server cert in its request loop, and a real cert
# would tie the bench to a fixed hostname.
#
# Usage:
#   bash benchmark/scripts/_make_self_signed.sh [out_dir]
#
# Output:
#   $out_dir/server.pem   - cert chain (self-signed leaf only)
#   $out_dir/server.key   - private key

set -euo pipefail

OUT_DIR="${1:-$(pwd)/build/tls-bench-certs}"
mkdir -p "$OUT_DIR"

CERT="$OUT_DIR/server.pem"
KEY="$OUT_DIR/server.key"

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
    echo "[bench-tls] cert + key already present at $OUT_DIR"
    exit 0
fi

echo "[bench-tls] generating self-signed cert at $OUT_DIR"
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY" -out "$CERT" -days 365 \
    -subj "/CN=flare-bench/O=flare/OU=bench" \
    >/dev/null 2>&1

echo "[bench-tls] cert: $CERT"
echo "[bench-tls] key:  $KEY"

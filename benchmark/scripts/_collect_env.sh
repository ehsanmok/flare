#!/bin/bash
# Emit a JSON snapshot of the benchmarking environment to stdout.
# Captures hardware, OS, kernel tuning knobs, and exact toolchain versions
# so runs are reproducible and comparable.
set -euo pipefail

OS=$(uname -s)
KERNEL=$(uname -r)
ARCH=$(uname -m)
HOST=$(hostname -s 2>/dev/null || hostname)

CPU_MODEL="unknown"
CPU_COUNT="unknown"
case "$OS" in
    Darwin)
        CPU_MODEL=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)
        CPU_COUNT=$(sysctl -n hw.ncpu 2>/dev/null || echo unknown)
        ;;
    Linux)
        CPU_MODEL=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//' || echo unknown)
        CPU_COUNT=$(nproc 2>/dev/null || echo unknown)
        ;;
esac

GOVERNOR="n/a"
TURBO="n/a"
SOMAXCONN="n/a"
TCP_TW_REUSE="n/a"
if [[ "$OS" == "Linux" ]]; then
    GOVERNOR=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)
    TURBO=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || echo unknown)
    SOMAXCONN=$(sysctl -n net.core.somaxconn 2>/dev/null || echo unknown)
    TCP_TW_REUSE=$(sysctl -n net.ipv4.tcp_tw_reuse 2>/dev/null || echo unknown)
fi

GO_VER=$(go version 2>/dev/null || echo "not available")
MOJO_VER=$(mojo --version 2>/dev/null | tail -1 || echo "not available")
NGINX_VER=$(nginx -v 2>&1 | head -1 || echo "not available")
WRK_VER=$(wrk --version 2>&1 | head -1 || echo "not available")
CURL_VER=$(curl --version 2>/dev/null | head -1 || echo "not available")

FLARE_COMMIT=$(cd "$(dirname "$0")/../.." && git rev-parse --short HEAD 2>/dev/null || echo unknown)

cat <<EOF
{
  "host": "$HOST",
  "os": "$OS $KERNEL",
  "arch": "$ARCH",
  "cpu_model": "$CPU_MODEL",
  "cpu_count": "$CPU_COUNT",
  "governor": "$GOVERNOR",
  "turbo_disabled": "$TURBO",
  "somaxconn": "$SOMAXCONN",
  "tcp_tw_reuse": "$TCP_TW_REUSE",
  "go_version": "$GO_VER",
  "mojo_version": "$MOJO_VER",
  "nginx_version": "$NGINX_VER",
  "wrk_version": "$WRK_VER",
  "curl_version": "$CURL_VER",
  "flare_commit": "$FLARE_COMMIT"
}
EOF

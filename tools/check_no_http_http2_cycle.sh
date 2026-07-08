#!/usr/bin/env bash
# tools/check_no_http_http2_cycle.sh -- enforce the http <-> http2 layering.
#
# The shared handler-facing types -- Request, Response, HeaderMap, Method,
# Status -- are factored into the leaf ``flare.http.wire`` package so the
# h2 server adapter (and the future h3 server adapter) can reach them
# without importing the parent ``flare.http`` namespace.
#
# Contract:
#
#   * ``flare/http2/**`` MUST NOT contain ``from flare.http`` or
#     ``import flare.http`` (the bare parent path). It MAY import
#     ``from flare.http.wire``, ``from flare.http.proto``, or the
#     specific leaf modules (``flare.http.hpack_huffman``,
#     ``flare.http.hpack_huffman_simd``) that the HPACK codec needs.
#
#   * ``flare/http3/**`` MUST NOT contain ``from flare.http`` either. It
#     follows the same allowlist (``flare.http.wire`` / ``flare.http.proto``).
#
#   * ``flare/http/**`` MAY reach into ``flare.http2`` only from the
#     explicitly-listed reactor-bridge modules (``_h2_conn_handle``,
#     ``_unified_reactor_impl``, ``frontend``, and ``proto/__init__``
#     which intentionally re-publishes the h2 codec under the
#     sans-I/O namespace).
#
# Usage: ``pixi run check-no-http-http2-cycle`` (wired in pixi.toml).
#
# Exit code 0 = clean; non-zero = at least one forbidden import found.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# Allowed import prefixes from inside ``flare/http2/**`` and ``flare/http3/**``
# that reach the ``flare.http`` namespace. Anything else triggers the lint.
ALLOWED_HTTP_SUBPATHS=(
    "flare.http.wire"
    "flare.http.proto"
    "flare.http.hpack_huffman"
    "flare.http.hpack_huffman_simd"
)

# Modules under ``flare/http/**`` that ARE allowed to import
# ``flare.http2.*`` (the reactor-bridge files that drive Http2Connection
# from the unified reactor; these are not codec modules and live in
# flare.http because the reactor is here).
ALLOWLISTED_REACTOR_BRIDGES=(
    "flare/http/_h2_conn_handle.mojo"
    "flare/http/_unified_reactor_impl.mojo"
    "flare/http/frontend.mojo"
    "flare/http/proto/__init__.mojo"
    # HttpServer / HttpClient drive H2 directly (Http2Config /
    # Http2ClientConnection are h2 structs, not shared wire types, so
    # they cannot move to flare.http.wire). The cycle is acknowledged
    # here and in flare/__init__.mojo rather than hidden.
    "flare/http/server.mojo"
    "flare/http/client.mojo"
)

violations=0

# Pass 1: flare/http2/** must not import bare ``flare.http``.
while IFS= read -r -d '' file; do
    # Find any ``from flare.http`` / ``import flare.http`` statements, plus
    # the relative ``from ..http`` form (inside flare/http2 and flare/http3,
    # ``..http`` resolves to the absolute ``flare.http``). ``http\b`` does
    # not match ``http2`` so this stays scoped to the parent namespace.
    matches="$(grep -nE '^(from|import)[[:space:]]+(flare\.http|\.\.http)\b' "$file" || true)"
    if [[ -z "$matches" ]]; then
        continue
    fi
    while IFS= read -r line; do
        # Extract the import path (the token after ``from`` / ``import``).
        path="$(echo "$line" \
            | sed -E 's/^[0-9]+:[[:space:]]*(from|import)[[:space:]]+([^[:space:]]+).*/\2/')"
        # Normalize a leading relative ``..`` to its absolute form so the
        # allowlist comparison below catches relative-import bypasses.
        if [[ "${path:0:2}" == ".." ]]; then
            path="flare.${path:2}"
        fi
        allowed=0
        for prefix in "${ALLOWED_HTTP_SUBPATHS[@]}"; do
            if [[ "$path" == "$prefix" ]] || [[ "$path" == "$prefix."* ]]; then
                allowed=1
                break
            fi
        done
        if [[ "$allowed" -eq 0 ]]; then
            echo "check-no-http-http2-cycle: $file: forbidden import:" >&2
            echo "  $line" >&2
            echo "  (only ${ALLOWED_HTTP_SUBPATHS[*]} are allowed from flare/http2/** and flare/http3/**.)" >&2
            violations=$((violations + 1))
        fi
    done <<< "$matches"
done < <(find flare/http2 flare/http3 -name '*.mojo' -print0 2>/dev/null)

# Pass 2: flare/http/** files that aren't on the allowlist must not
# import ``flare.http2.*``.
while IFS= read -r -d '' file; do
    on_allowlist=0
    for allowed in "${ALLOWLISTED_REACTOR_BRIDGES[@]}"; do
        if [[ "$file" == "$allowed" ]]; then
            on_allowlist=1
            break
        fi
    done
    if [[ "$on_allowlist" -eq 1 ]]; then
        continue
    fi
    # Catch both the absolute ``flare.http2`` form and the relative
    # ``..http2`` form (inside flare/http, ``..http2`` resolves to the
    # absolute ``flare.http2``). The relative form previously slipped
    # past this lint -- see flare/http/server.mojo + client.mojo.
    matches="$(grep -nE '^(from|import)[[:space:]]+(flare\.http2|\.\.http2)\b' "$file" || true)"
    if [[ -n "$matches" ]]; then
        echo "check-no-http-http2-cycle: $file: forbidden import (not on reactor-bridge allowlist):" >&2
        while IFS= read -r line; do
            echo "  $line" >&2
        done <<< "$matches"
        violations=$((violations + 1))
    fi
done < <(find flare/http -name '*.mojo' -print0 2>/dev/null)

if [[ $violations -gt 0 ]]; then
    echo "" >&2
    echo "check-no-http-http2-cycle: $violations violation(s) found." >&2
    echo "  Fix: route shared types through flare.http.wire (the neutral" >&2
    echo "  re-export layer for Request / Response / HeaderMap / Method)" >&2
    echo "  rather than the parent flare.http namespace." >&2
    exit 1
fi

echo "check-no-http-http2-cycle: clean."

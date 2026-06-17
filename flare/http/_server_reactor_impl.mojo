"""Reactor-backed HTTP server: per-connection state machine + loops.

This module is a thin re-export surface. After the v0.8 decomposition
the per-connection state machine (``ConnHandle`` + byte-fast-path /
keep-alive helpers) lives in ``flare.http._reactor``; the epoll/kqueue
server loops + connection-lifecycle glue live in
``flare.http._server_reactor_epoll``; the io_uring static + buffer-ring
loops live in ``flare.http._server_reactor_uring``. Every public symbol
is re-exported here so existing
``from flare.http._server_reactor_impl import ...`` call sites across
``flare.http``, ``flare.http2``, ``flare.runtime``, ``tests/`` and
``fuzz/`` keep resolving unchanged.
"""

from ._reactor import (
    STATE_READING,
    STATE_WRITING,
    STATE_CLOSING,
    StepResult,
    ConnHandle,
    _detect_h2c_upgrade_inline,
    _monotonic_ms,
    _is_content_length,
    _is_date,
    _is_connection,
    _connection_is_keepalive,
    _connection_is_close,
    _compact_read_buf_drop_prefix,
    _compute_close_after,
    _wants_close,
)

from ._server_reactor_epoll import (
    _conn_alloc_addr,
    _conn_free_addr,
    _conn_ptr_from_int,
    _apply_step,
    _cleanup_conn,
    _accept_loop,
    _accept_loop_fd,
    run_reactor_loop,
    run_reactor_loop_shared,
    run_reactor_loop_static,
    run_reactor_loop_static_shared,
    run_reactor_loop_cancel,
    run_reactor_loop_view,
)

from ._server_reactor_uring import (
    run_uring_reactor_loop_static,
    run_uring_bufring_reactor_loop,
    run_uring_bufring_reactor_loop_shared,
    _probe_bufring_setup_flags,
)

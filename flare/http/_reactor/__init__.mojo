"""``flare.http._reactor`` -- per-connection state-machine sub-package.

This sub-package owns the per-connection halves of the reactor-backed
HTTP server, split across three sibling files:

* :mod:`flare.http._reactor.conn_handle` -- the ``ConnHandle`` state
  machine itself, the ``BYTE_SOURCE_*`` comptime tags shared by the
  reader entry points, and the per-conn helpers parameterised on
  those tags.
* :mod:`flare.http._reactor.keepalive_scan` -- ``STATE_*`` constants,
  ``StepResult`` return shape, monotonic-clock reader, byte-level
  case-insensitive matchers for the response serializer, raw-bytes
  HTTP/1.0 / ``Connection: close`` scanner, h2c upgrade detection
  wrapper.
* :mod:`flare.http._reactor.write_path` -- response serialisation:
  H1 response → wire bytes, static-response → wire bytes, error
  response builder, h2c ``101 Switching Protocols`` queue helper.

The sister module ``flare.http._server_reactor_impl`` owns the
I/O-bearing pieces (reactor entry-point loops, ``Pool[ConnHandle]``
glue, io_uring buffer-ring glue) and re-exports every public
symbol below for back-compat with existing imports across
``flare/http/``, ``flare/http2/``, ``flare/runtime/``, the test suite,
and the fuzz corpus.

Internal namespace: nothing here is part of the public ``flare`` API.
"""

from .conn_handle import (
    BYTE_SOURCE_BUFRING,
    BYTE_SOURCE_RECV,
    ConnHandle,
)
from .keepalive_scan import (
    STATE_CLOSING,
    STATE_READING,
    STATE_WRITING,
    StepResult,
    _compact_read_buf_drop_prefix,
    _compute_close_after,
    _connection_is_close,
    _connection_is_keepalive,
    _detect_h2c_upgrade_inline,
    _is_connection,
    _is_content_length,
    _is_date,
    _monotonic_ms,
    _wants_close,
)
from .write_path import (
    build_error_response,
    queue_h2c_upgrade_101,
    serialize_response_into,
    serialize_static_into,
)

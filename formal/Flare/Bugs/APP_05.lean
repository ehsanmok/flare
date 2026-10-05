import Flare.L4_App.ConnSM

/-!
# APP-05: when the handler raises on a HEAD request, the error response carries a body

flare/http/_reactor/conn_handle.mojo:910-915 @59bda50 (handler error branch
of `on_readable`) calls `_queue_error` (conn_handle.mojo:1576-1580), which
calls `_serialize_response` (conn_handle.mojo:1589-1594), which calls
`serialize_response_into` without `head_request` (default `False`). The 500
for a HEAD therefore carries the text body `500 Internal Server Error`. The
connection closes afterwards, so the extra bytes cannot be taken for a later
response on this connection, but the HEAD response has content.

Spec (RFC 9110 §9.3.2): no content in any response to HEAD, error statuses
included (`Flare.L4.ConnSM.Framing.HeadSpec`).

Status: resolved. `_serialize_response` passes `self.head_request`; errors
raised before the request is parsed (408, 413, 431, ...) take the flag from
the buffered `HEAD ` prefix (`_note_head_from_buf`). The model `headFlag` is
the shipped flag, `headFlagOld` the pre-fix one. Regression tests:
`tests/http/test_server_reactor_state.mojo::test_handler_error_for_head_has_no_body`,
`::test_parse_errors_for_head_have_no_body` and
`::test_error_after_head_on_keepalive_conn_keeps_body`.
-/
namespace Flare.Bugs.APP_05

open Flare.L4.ConnSM.Framing

/-- Counterexample (pre-fix): on the error path a HEAD gets a 500 with a 25-byte body
emitted (`emitBody = true`); the handler path is correct. -/
theorem handler_error_head_emits_body :
    (serialize 500 25 none (headFlagOld .errorReply true) true).emitBody = true ∧
    (serialize 500 25 none (headFlagOld .handler true) true).emitBody = false ∧
    ¬ HeadSpec headFlagOld := by
  refine ⟨by decide, by decide, fun h => ?_⟩
  have := h .errorReply 500 25 none true (by decide)
  revert this; decide

/-- The shipped flag (`_serialize_response` passes `self.head_request`) meets the spec on
every path, status and body. -/
theorem errorFixed_head_no_body : HeadSpec headFlag := headFlag_spec

end Flare.Bugs.APP_05

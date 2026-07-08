"""HTTP/3 server driver lifecycle walkthrough.

Walks the :class:`flare.http3.Http3Connection` driver carrier through
the lifecycle the QUIC reactor exercises when a peer opens a
fresh connection. This example focuses on the driver's pure
state-machine surface; the full "open a UDP listener, accept
QUIC connections, route to the H3 driver, dispatch to a
Handler" walkthrough lives in
:doc:`examples/advanced/http3_server.mojo`.

This example illustrates:

* Constructing an :class:`Http3Config` with non-default
  SETTINGS (max field section size, CONNECT-Protocol advertised).
* Opening per-stream readers as new QUIC bidirectional streams
  arrive, and closing them after the response FIN.
* Emitting GOAWAY and confirming that new request streams are
  rejected.
* Driving :meth:`Http3Connection.feed_stream_chunk` against a
  mocked request stream and reading the encoded response bytes
  back through :meth:`Http3Connection.take_response_frames`.
"""

from flare.http3 import (
    Http3Connection,
    Http3Config,
    Http3StreamType,
)


def main() raises:
    print("== HTTP/3 server driver lifecycle walkthrough ==")
    print()

    # Step 1: build a config carrier with our SETTINGS.
    var cfg = Http3Config()
    cfg.max_field_section_size = UInt64(8192)
    cfg.enable_connect_protocol = True
    print("Configured H3 with:")
    print("  max_field_section_size = ", cfg.max_field_section_size)
    print("  enable_connect_protocol =", cfg.enable_connect_protocol)
    print()

    # Step 2: construct the connection driver.
    var conn = Http3Connection.with_config(cfg)
    print(
        "Driver state: peer_settings_received =",
        conn.peer_settings_received,
        ", active streams =",
        conn.active_request_count(),
    )
    print()

    # Step 3: the reactor opens streams as datagrams arrive.
    # QUIC bidi streams have IDs of the form 4k (client-initiated).
    print("Opening three request streams (IDs 0, 4, 8):")
    conn.open_request_stream(0)
    conn.open_request_stream(4)
    conn.open_request_stream(8)
    print("  active streams now =", conn.active_request_count())
    print()

    # Step 4: closing happens after the response FIN. Stream 0
    # completes; the driver releases its parser state.
    print("Closing stream 0 (response FIN emitted):")
    conn.close_request_stream(0)
    print("  has_stream(0) =", conn.has_stream(0))
    print("  has_stream(4) =", conn.has_stream(4))
    print("  active streams now =", conn.active_request_count())
    print()

    # Step 5: GOAWAY rejects new streams. The reactor emits GOAWAY
    # under load or on graceful shutdown; subsequent open events
    # raise so the listener can surface the rejection to the QUIC
    # peer with H3_REQUEST_CANCELLED.
    print("Emitting GOAWAY:")
    conn.goaway_emitted = True
    var goaway_raised = False
    try:
        conn.open_request_stream(12)
    except:
        goaway_raised = True
    print("  open_request_stream after GOAWAY raised =", goaway_raised)
    print()

    # Step 6: drive feed_stream_chunk + take_response_frames on
    # an existing request stream id. The Http3RequestReader is
    # tolerant of partial frames (waits for the full frame-type
    # + length + payload before firing the per-frame callback),
    # so a single 0x01 byte is consumed cleanly and the reader
    # parks waiting for more bytes. take_response_frames drains
    # whatever the driver has queued for the stream so far.
    print("Per-stream dispatch boundary:")
    var chunk = List[UInt8]()
    chunk.append(UInt8(0x01))
    conn.feed_stream_chunk(4, chunk^)
    var drained = conn.take_response_frames(4)
    print("  feed_stream_chunk(4, 0x01) consumed cleanly (partial frame)")
    print("  take_response_frames bytes pending =", len(drained))
    print()

    # The four stream-type codepoints the driver dispatches on.
    print("RFC 9114 paragraph 6.2 unidirectional stream types:")
    print("  CONTROL       =", Http3StreamType.CONTROL)
    print("  PUSH          =", Http3StreamType.PUSH)
    print("  QPACK_ENCODER =", Http3StreamType.QPACK_ENCODER)
    print("  QPACK_DECODER =", Http3StreamType.QPACK_DECODER)

import Flare.L3_Protocol.H1.Chunked
import Flare.L3_Protocol.H1.ChunkedSpec
import Flare.L3_Protocol.H1.HeaderText
import Flare.L3_Protocol.H1.ContentLength
import Flare.L3_Protocol.H1.Framing
import Flare.L3_Protocol.H1.FieldValue
import Flare.L3_Protocol.H1.ObsFold
import Flare.L3_Protocol.H1.ClientChunked
import Flare.L3_Protocol.H1.ClientResponse
import Flare.L3_Protocol.H1.ChunkedEncode
import Flare.L3_Protocol.Ws.Frame
import Flare.L3_Protocol.Ws.Recv
import Flare.L3_Protocol.Ws.Handshake
import Flare.L3_Protocol.Ws.Close
import Flare.Bugs.H1_01
import Flare.Bugs.H1_02
import Flare.Bugs.H1_03
import Flare.Bugs.H1_04
import Flare.Bugs.H1_05
import Flare.Bugs.H1_06
import Flare.Bugs.H1_07
import Flare.Bugs.H1_08
import Flare.Bugs.H1_09
import Flare.Bugs.H1_10
import Flare.Bugs.H1_11
import Flare.Bugs.WS_01
import Flare.Bugs.WS_02
import Flare.Bugs.WS_03
import Flare.Bugs.WS_04
import Flare.Bugs.WS_05
import Flare.Bugs.WS_06
import Flare.Bugs.WS_07

/-!
# L3: HTTP/1.1 framing and WebSocket

* `H1.Chunked`, `H1.ChunkedSpec`: the reactor's chunked-body scanner and
  decoder (`flare/http/proto/chunked.mojo`). Covers termination,
  resume = one-shot, scan acceptance ⇒ decoder agreement, and the H1-01 and
  H1-02 fixes.
* `H1.HeaderText`, `H1.ContentLength`: header-text vocabulary and the exact
  Content-Length grammar of `parse_content_length_bytes`.
* `H1.Framing`: reactor framing (`request_te_framing`, `scan_content_length`)
  against the full parser. Proves no smuggling in strict mode; the H1-03 and
  H1-04 fixes.
* `H1.FieldValue`: header-value byte checks and the `String` invariant
  (strict mode safe; the H1-05 fix).
* `H1.ObsFold`: the server's obs-fold unfolding (RFC 9112 §5.2) and
  value validation; the H1-10 fix.
* `H1.ClientChunked`, `H1.ClientResponse`: the client response parser:
  RFC 9112 §6.3 framing, the status line, head lines, connection reuse and
  TLS end of stream; the H1-06, H1-07, H1-08, H1-09 and H1-11 fixes.
* `H1.ChunkedEncode`: the chunked encoders round-trip through all three
  chunked decoders, with empty writes and trailers.
* `Ws.Frame`, `Ws.Recv`: the RFC 6455 frame codec, and the receive paths
  (opcodes, mask direction, message assembly, UTF-8). The WS-01, WS-02 and
  WS-03 fixes.
* `Ws.Handshake`: the opening handshake on the client, the standalone
  server and the reactor (key, accept, Upgrade/Connection, version,
  subprotocol); the WS-04, WS-05 and WS-07 fixes.
* `Ws.Close`: the closing handshake (reply, 1002 on an invalid body, no
  data after CLOSE); the WS-06 fix.

The keep-alive decision (`_wants_close`, `_compute_close_after`) is covered
in `L4_App/KeepAlive.lean` (APP-02, APP-03) and is not duplicated here.
-/

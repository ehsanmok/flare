import Flare.L3_Protocol.H2.Frame
import Flare.L3_Protocol.H2.Names
import Flare.L3_Protocol.H2.HpackTable
import Flare.L3_Protocol.H2.HpackSync
import Flare.L3_Protocol.H2.Hpack
import Flare.L3_Protocol.H2.Validate
import Flare.L3_Protocol.H2.Conn
import Flare.L3_Protocol.H2.ConnSpec
import Flare.L3_Protocol.H2.ContentLength
import Flare.L3_Protocol.H2.ConnWindow
import Flare.L3_Protocol.H2.ConnFlow
import Flare.L3_Protocol.H2.StreamTable
import Flare.L3_Protocol.H2.ConnSeq
import Flare.L3_Protocol.H2.HpackPeer
import Flare.L3_Protocol.H2.HpackCodec
import Flare.L3_Protocol.H2.ConnHpack
import Flare.L3_Protocol.H2.StreamSpec
import Flare.L3_Protocol.H2.RefineAbs
import Flare.L3_Protocol.H2.RefineData
import Flare.L3_Protocol.H2.RefineHdr
import Flare.L3_Protocol.H2.RefineFrame
import Flare.L3_Protocol.H2.RefineLocal
import Flare.L3_Protocol.H2.RefineRun
import Flare.L3_Protocol.H2.Streaming

/-!
# L3: HTTP/2 and HPACK

Aggregate of the HTTP/2 models: frame codec, HPACK dynamic table,
encoder/decoder table synchronisation, header-block decoder, request
header validation, and the connection state machine
(`Http2Connection.handle_frame` plus the server driver) with its RFC 9113
requirements, window invariant and flow-control theorems; the client
driver; the RFC 9113 §5.1 stream-state spec LTS and the connection's
refinement of it; the composition of the connection with the stateful
HPACK decoder on the real L1 Huffman codec; and the client's
streaming-body mode. See `formal/report/L3_h2.md`.
-/

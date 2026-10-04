import Flare.L3_Protocol.H2.Frame
import Flare.L3_Protocol.H2.Names
import Flare.L3_Protocol.H2.HpackTable
import Flare.L3_Protocol.H2.HpackSync
import Flare.L3_Protocol.H2.Hpack
import Flare.L3_Protocol.H2.Validate
import Flare.L3_Protocol.H2.Conn
import Flare.L3_Protocol.H2.ConnSpec
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
import Flare.L3_Protocol.H2.RefineShipped
import Flare.L3_Protocol.H2.Streaming
import Flare.Bugs.H2_Fixtures
import Flare.Bugs.H2_01
import Flare.Bugs.H2_02
import Flare.Bugs.H2_03
import Flare.Bugs.H2_04
import Flare.Bugs.H2_05
import Flare.Bugs.H2_06
import Flare.Bugs.H2_07
import Flare.Bugs.H2_08
import Flare.Bugs.H2_09
import Flare.Bugs.H2_10
import Flare.Bugs.H2_11
import Flare.Bugs.H2_12
import Flare.Bugs.H2_13
import Flare.Bugs.H2_14
import Flare.Bugs.H2_15
import Flare.Bugs.H2_16
import Flare.Bugs.H2_17
import Flare.Bugs.H2_18
import Flare.Bugs.H2_19
import Flare.Bugs.H2_20
import Flare.Bugs.H2_Refine
import Flare.Bugs.HPACK_Fixtures
import Flare.Bugs.HPACK_01
import Flare.Bugs.HPACK_02
import Flare.Bugs.HPACK_03

/-!
# L3: HTTP/2 and HPACK

Aggregate of the HTTP/2 models: frame codec, HPACK dynamic table,
encoder/decoder table synchronisation, header-block decoder, request
header validation, and the connection state machine
(`Http2Connection.handle_frame` plus the server driver) with its RFC 9113
requirements, window invariant and flow-control theorems; the client
driver; the RFC 9113 §5.1 stream-state spec LTS with the refinement of the
fixed model and the classification of the shipped code's departures; the
composition of the connection with the stateful HPACK decoder on the real
L1 Huffman codec; and the client's streaming-body mode. Also imports the
counterexample files of the H2- and HPACK- issues. See
`formal/report/L3_h2.md`.
-/

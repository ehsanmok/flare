import Flare.L3_Protocol.H3.Control
import Flare.L3_Protocol.Quic.Streams

/-!
# H3-07: the server never opens its HTTP/3 control stream

flare/quic/server.mojo:2210-2433 @59bda50 (`_drain_1rtt_coalesced`): the
1-RTT egress writes ACK / HANDSHAKE_DONE / MAX_DATA / MAX_STREAMS /
NEW_CONNECTION_ID and one STREAM frame sequence per entry of
`http3_response_egress`, which is keyed by the client's request stream id.
No server-initiated unidirectional stream is ever opened:
`Http3Connection.emit_initial_settings` (flare/http3/server.mojo:1230-1275)
is called nowhere under `flare/` (only from tests/h3/test_h3_uni_streams.mojo
and examples/advanced/http3_server.mojo:167, which prints its length), and
`control_stream_id` (flare/http3/server.mojo:588) stays -1. The docstring of
`emit_initial_settings` ("The reactor opens a local control uni-stream via
QUIC and emits these bytes") describes code that does not exist.

Spec clause: RFC 9114 §6.2.1: "Each side MUST initiate a single control
stream at the beginning of the connection and send its SETTINGS frame as the
first frame on this stream."

What goes wrong: the client never learns the server's
SETTINGS_MAX_FIELD_SECTION_SIZE, QPACK limits or ENABLE_CONNECT_PROTOCOL; a
client that waits for the peer's SETTINGS before using extensions never gets
them, and a strict client may close with H3_MISSING_SETTINGS.

Model: the server's outbound stream set after the handshake and the first
request/response, as `(stream id, bytes from offset 0)` pairs.
Counterexample (`implOld_no_control`): for any set of client bidirectional
request streams, no server-initiated uni stream exists at all (observed
over loopback: the server sends only on stream 0).
Fix (`implOut`): with the first 1-RTT flight, send stream 3 carrying
`emit_initial_settings()`; `fixed_spec` proves this is the single control
stream and that it starts with type 0x00 and a decodable SETTINGS frame.

Status: resolved. `implOldOut` is the pre-fix outbound set (the counterexample
is about it); the shipped `implOut` meets RFC 9114 §6.2.1 (`fixed_spec`).
`Http3Connection.take_control_stream_start()` hands over the bytes once and
`QuicListener._drain_1rtt_coalesced` sends them as stream 3 at offset 0 with
the first 1-RTT flight. Regression tests: tests/h3/test_h3_uni_streams.mojo
`test_take_control_stream_start_is_once_and_decodes_at_the_peer`,
tests/h3/test_h3_client_e2e.mojo
`test_server_opens_its_control_stream_with_settings`.
-/
namespace Flare.Bugs.H3_07
open Flare.L3.H3

/-- mirrors flare/http3/server.mojo:136-175 @59bda50 (the `Http3Config`
fields read by `emit_initial_settings`) -/
structure Config where
  maxFieldSection : Nat := 65536
  qpackCap : Nat := 0
  qpackBlocked : Nat := 0
  connect : Bool := true

/-- Values a varint can carry. -/
def Config.Valid (c : Config) : Prop :=
  c.maxFieldSection < 2 ^ 62 ∧ c.qpackCap < 2 ^ 62 ∧ c.qpackBlocked < 2 ^ 62

/-- mirrors flare/http3/server.mojo:1332-1357 (fixed, H3-07) -/
def settingsList (c : Config) : List (Nat × Nat) :=
  [(0x06, c.maxFieldSection), (0x01, c.qpackCap), (0x07, c.qpackBlocked)] ++
    (if c.connect then [(0x08, 1)] else [])

/-- mirrors flare/http3/server.mojo:1316-1361 (fixed, H3-07) -/
def emitInitialSettings (enc : Nat → Bytes) (c : Config) : Bytes :=
  enc 0x00 ++ encodeFrame enc 0x04 (encodeSettings enc (settingsList c))

/-- Outbound streams: `(stream id, bytes from offset 0)`. -/
abbrev Out := List (Nat × Bytes)

def serverUni (sid : Nat) : Bool :=
  Flare.L3.Quic.Streams.serverInit sid && Flare.L3.Quic.Streams.isUni sid

/-- The bytes open an HTTP/3 control stream: stream type 0x00, then a SETTINGS
frame whose payload decodes. -/
def ControlStart (b : Bytes) : Prop :=
  ∃ k pl ss, decVarint b = some (0x00, k) ∧ decodeFrame (b.drop k) = some (0x04, pl) ∧
    decodeSettings pl = some ss

/-- RFC 9114 §6.2.1 on the server's outbound streams: some server-initiated
uni stream opens with 0x00 + SETTINGS, and there is only one such stream. -/
def Spec (out : Out) : Prop :=
  (∃ p ∈ out, serverUni p.1 = true ∧ ControlStart p.2) ∧
  ∀ p ∈ out, ∀ q ∈ out, serverUni p.1 = true → serverUni q.1 = true →
    ControlStart p.2 → ControlStart q.2 → p.1 = q.1

/-- Request streams opened by the client are client-initiated bidirectional. -/
def ClientBidi (reqs : List Nat) : Prop := ∀ s ∈ reqs, s % 4 = 0

/-- PRE-FIX outbound set (flare/quic/server.mojo:2210-2433 @59bda50,
`_drain_1rtt_coalesced`: STREAM frames come only from `http3_response_egress`,
keyed by request stream). Kept so the counterexample stays checkable. -/
def implOldOut (resp : Nat → Bytes) (reqs : List Nat) : Out :=
  reqs.map fun s => (s, resp s)

/-- The shipped outbound set: stream 3 with the bytes of
`Http3Connection.take_control_stream_start()` (= `emit_initial_settings()`),
appended in `_drain_1rtt_coalesced` to the first 1-RTT flight, next to
HANDSHAKE_DONE.
mirrors flare/quic/server.mojo:2288-2310 and flare/http3/server.mojo:1363-1380
(fixed, H3-07) -/
def implOut (enc : Nat → Bytes) (c : Config) (resp : Nat → Bytes) (reqs : List Nat) : Out :=
  (3, emitInitialSettings enc c) :: implOldOut resp reqs

theorem implOldOut_not_serverUni (resp : Nat → Bytes) (reqs : List Nat) (h : ClientBidi reqs) :
    ∀ p ∈ implOldOut resp reqs, serverUni p.1 = false := by
  intro p hp
  simp only [implOldOut, List.mem_map] at hp
  obtain ⟨s, hs, rfl⟩ := hp
  have := h s hs
  simp only [serverUni, Flare.L3.Quic.Streams.serverInit, Bool.and_eq_false_iff,
    decide_eq_false_iff_not]
  left; omega

/-- **Counterexample**: whatever the client requests, the server's outbound
streams contain no control stream. -/
theorem implOld_no_control (resp : Nat → Bytes) (reqs : List Nat) (h : ClientBidi reqs) :
    ¬ Spec (implOldOut resp reqs) := by
  rintro ⟨⟨p, hp, hu, _⟩, _⟩
  rw [implOldOut_not_serverUni resp reqs h p hp] at hu
  cases hu

/-- The observed run: one GET on stream 0; the server sends only on stream 0. -/
theorem implOld_observed (resp : Nat → Bytes) :
    (implOldOut resp [0]).map (·.1) = [0] ∧ ¬ Spec (implOldOut resp [0]) :=
  ⟨rfl, implOld_no_control resp [0] (by simp [ClientBidi])⟩

theorem enc_len (enc : Nat → Bytes) (henc : VarintCodec enc) (v : Nat) (hv : v < 2 ^ 62) :
    (enc v).length ≤ 8 := by
  have := henc v [] hv
  rw [List.append_nil] at this
  exact (decVarint_some this).2.1

theorem encodeSettings_len (enc : Nat → Bytes) (henc : VarintCodec enc) (s : List (Nat × Nat))
    (hs : ∀ p ∈ s, p.1 < 2 ^ 62 ∧ p.2 < 2 ^ 62) :
    (encodeSettings enc s).length ≤ 16 * s.length := by
  induction s with
  | nil => simp [encodeSettings]
  | cons hd tl ih =>
    obtain ⟨i, v⟩ := hd
    have hi := hs (i, v) (by simp)
    have h1 := enc_len enc henc i hi.1
    have h2 := enc_len enc henc v hi.2
    have h3 := ih (fun p hp => hs p (by simp [hp]))
    simp only [encodeSettings, List.length_append, List.length_cons]
    omega

theorem settingsList_valid (c : Config) (hc : c.Valid) :
    ∀ p ∈ settingsList c, p.1 < 2 ^ 62 ∧ p.2 < 2 ^ 62 := by
  obtain ⟨h1, h2, h3⟩ := hc
  have h62 : (8 : Nat) < 2 ^ 62 := by decide
  intro p hp
  simp only [settingsList, List.mem_append, List.mem_cons, List.mem_nil_iff, or_false] at hp
  rcases hp with (rfl | rfl | rfl) | hp
  · exact ⟨by omega, h1⟩
  · exact ⟨by omega, h2⟩
  · exact ⟨by omega, h3⟩
  · split at hp
    · simp only [List.mem_cons, List.mem_nil_iff, or_false] at hp
      subst hp; exact ⟨by omega, by omega⟩
    · simp at hp

theorem settingsList_len (c : Config) : (settingsList c).length ≤ 4 := by
  unfold settingsList; split <;> simp

/-- The fixed stream opens with 0x00 and a SETTINGS frame that decodes back to
exactly the configured settings. -/
theorem emit_control_start (enc : Nat → Bytes) (henc : VarintCodec enc)
    (hpos : ∀ v, 1 ≤ (enc v).length) (c : Config) (hc : c.Valid) :
    decVarint (emitInitialSettings enc c) = some (0x00, (enc 0x00).length) ∧
    decodeFrame ((emitInitialSettings enc c).drop (enc 0x00).length) =
      some (0x04, encodeSettings enc (settingsList c)) ∧
    decodeSettings (encodeSettings enc (settingsList c)) = some (settingsList c) := by
  have hv := settingsList_valid c hc
  have hlen : (encodeSettings enc (settingsList c)).length < 2 ^ 62 := by
    have := encodeSettings_len enc henc _ hv
    have := settingsList_len c
    have h62 : (64 : Nat) < 2 ^ 62 := by decide
    omega
  refine ⟨henc 0 _ (by decide), ?_, decodeSettings_encode enc henc hpos _ hv⟩
  unfold emitInitialSettings
  rw [List.drop_left, ← List.append_nil (encodeFrame enc 4 _)]
  exact decodeFrame_encode enc henc 4 _ [] (by decide) hlen hpos

theorem emit_controlStart (enc : Nat → Bytes) (henc : VarintCodec enc)
    (hpos : ∀ v, 1 ≤ (enc v).length) (c : Config) (hc : c.Valid) :
    ControlStart (emitInitialSettings enc c) := by
  obtain ⟨h1, h2, h3⟩ := emit_control_start enc henc hpos c hc
  exact ⟨_, _, _, h1, h2, h3⟩

/-- **Fix**: the fixed outbound set meets RFC 9114 §6.2.1. -/
theorem fixed_spec (enc : Nat → Bytes) (henc : VarintCodec enc)
    (hpos : ∀ v, 1 ≤ (enc v).length) (c : Config) (hc : c.Valid)
    (resp : Nat → Bytes) (reqs : List Nat) (h : ClientBidi reqs) :
    Spec (implOut enc c resp reqs) := by
  have hno := implOldOut_not_serverUni resp reqs h
  have only3 : ∀ p ∈ implOut enc c resp reqs, serverUni p.1 = true → p.1 = 3 := by
    intro p hp hu
    simp only [implOut, List.mem_cons] at hp
    rcases hp with rfl | hp
    · rfl
    · rw [hno p hp] at hu; cases hu
  have h3 : serverUni 3 = true := by decide
  refine ⟨⟨_, List.mem_cons_self, h3, emit_controlStart enc henc hpos c hc⟩, ?_⟩
  intro p hp q hq hup huq _ _
  rw [only3 p hp hup, only3 q hq huq]

/-- Stream 3 is a server-initiated uni stream the server may send on
(reusing the stream-state model of `Quic/Streams.lean`). -/
theorem fixed_stream_sendable :
    serverUni 3 = true ∧ Flare.L3.Quic.Streams.hasSend .server 3 = true ∧
      Flare.L3.Quic.Streams.hasRecv .server 3 = false := by decide

/-- The receiving side's uni-stream classifier (`Control.classify`) treats the
fixed stream's type byte 0x00 on stream 3 as the peer's control stream. -/
theorem fixed_classified :
    Control.classify Control.Fixes.all {} 0x00 3 = .ok ({ ctrl := some 3 }, .control) := by
  simp [Control.classify]

end Flare.Bugs.H3_07

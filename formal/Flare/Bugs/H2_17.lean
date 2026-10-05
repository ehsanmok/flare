import Flare.Bugs.H2_Fixtures
import Flare.L3_Protocol.H2.ConnHpack
import Flare.L3_Protocol.H2.HpackCodec

/-!
# H2-17: client drops PUSH_PROMISE header blocks; HPACK desync, wrong header

Status: resolved. The client no longer intercepts PUSH_PROMISE: it goes to
`handle_frame`, which answers GOAWAY(PROTOCOL_ERROR). The counterexample
below is about `Fix.none` (the code before the fix); `fixed_shipped`
is about `Fix.shipped`.

Before the fix, flare/http2/client.mojo:427-446 @59bda50 intercepted PUSH_PROMISE before
`handle_frame`: it answers RST_STREAM(promised, PROTOCOL_ERROR) and drops
the frame. The field block it carries is never decoded, so any insert the
peer's encoder made in it is missing from flare's decoder table. A later
indexed field then resolves to a *different* entry: flare delivers a
header the server never sent. (Push is disabled by flare's SETTINGS, but
the frame can still arrive: a server may ignore SETTINGS_ENABLE_PUSH, or
send it before our SETTINGS is acknowledged.)

RFC 9113 §8.4: "A client cannot push. [...] receipt of a PUSH_PROMISE frame
[when push is disabled] MUST [be treated] as a connection error (Section
5.4.1) of type PROTOCOL_ERROR"; §4.3: "Header compression is stateful
[...] Each field block is processed as a discrete unit [...] A receiver
MUST [...] process the field block [...] to maintain [the] compression
state."

Witness (the repro's), with flare's real L1 codecs and Huffman-coded
literals: the response on stream 1 inserts `x-b: 2`; the PUSH_PROMISE
inserts `x-a: 1`; the response on stream 3 sends index 62, which the
server means as `x-a: 1`. flare decodes it as `x-b: 2`.
-/
namespace Flare.Bugs.H2_17
open Flare Flare.L3.H2.Conn Flare.Bugs.H2_Fixtures
open Flare.L3.H2.Hpack (Rep Entry encBlock real Peer)

def init : Conn := { isClient := true }

def push : Fr := { ty := tPUSH, sid := 1, eh := true, plen := 5, word := 2, frag := [9] }

theorem bug_frame : outs Fix.none init [.frame settings0, .openLocal 1 true, .frame push] =
    some [[.settingsAck], [], [.rst 2 ePROTOCOL]] := by native_decide

theorem fixed_frame : outs { h2_17 := true } init [.frame settings0, .openLocal 1 true, .frame push] =
    some [[.settingsAck], [], [.goaway 0 ePROTOCOL]] := by native_decide

/-! ## The HPACK consequence, with the stateful decoder -/

def B (s : String) : Bytes := Bytes.ofString s

/-- The server's three field blocks. -/
def rss : List (List Rep) :=
  [[.idx 8, .inc 0 (B "x-b") (B "2") true true],
   [.inc 0 (B "x-a") (B "1") true true],
   [.idx 8, .idx 62]]

def blk (i : Nat) : Bytes := encBlock real Flare.L1.Huffman.encode (rss.getD i [])

def hdrF (sid : Nat) (b : Bytes) : Fr :=
  { ty := tHEADERS, sid := sid, f1 := true, eh := true, plen := b.length, frag := b }

def pushF : Fr :=
  { ty := tPUSH, sid := 1, eh := true, plen := 4 + (blk 1).length, word := 2, frag := blk 1 }

def tr : List Ev :=
  [.frame settings0, .openLocal 1 true, .frame (hdrF 1 (blk 0)), .frame pushF,
   .openLocal 3 true, .frame (hdrF 3 (blk 2))]

def runS (fx : Fix) := runD fx (decAt real 0) init tr

/-- The server's own view: what each block means. -/
theorem peer_view : (pblocks Peer.init rss).map (·.2) =
    some [[⟨B ":status", B "200"⟩, ⟨B "x-b", B "2"⟩], [⟨B "x-a", B "1"⟩],
          [⟨B ":status", B "200"⟩, ⟨B "x-a", B "1"⟩]] := by native_decide

/-- Shipped: no GOAWAY, the push block never reaches the decoder, and the
response on stream 3 decodes to `x-b: 2`. -/
theorem bug : (runS Fix.none).map (fun r => (r.2.all (fun p => !hasGoaway p.2),
      r.1.decLog.length, (decFold real 0 Flare.L3.H2.Hpack.Table.init r.1.decLog).2)) =
    some (true, 2, [[⟨B ":status", B "200"⟩, ⟨B "x-b", B "2"⟩],
                    [⟨B ":status", B "200"⟩, ⟨B "x-b", B "2"⟩]]) := by native_decide

/-- Field `j` of block `i`. -/
def pick (l : List (List Entry)) (i j : Nat) : Option Entry := (l[i]?).bind (·[j]?)

/-- The header flare returned for stream 3 is not the one the server sent
in that position, and no error was raised. -/
theorem counterexample : ∃ c'' trc, runS Fix.none = some (c'', trc) ∧
    trc.all (fun p => !hasGoaway p.2) = true ∧
    pick (decFold real 0 Flare.L3.H2.Hpack.Table.init c''.decLog).2 1 1 = some ⟨B "x-b", B "2"⟩ ∧
    ((pblocks Peer.init rss).map (·.2)).bind (pick · 2 1) = some ⟨B "x-a", B "1"⟩ := by
  have hs : (runS Fix.none).isSome = true := by native_decide
  obtain ⟨⟨c'', trc⟩, h⟩ := Option.isSome_iff_exists.mp hs
  have hb := bug
  rw [h] at hb
  simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at hb
  refine ⟨c'', trc, h, hb.1, ?_, ?_⟩
  · rw [hb.2.2]; rfl
  · rw [peer_view]; rfl

/-- With the fix the PUSH_PROMISE draws GOAWAY(PROTOCOL_ERROR). -/
theorem fixed_trace : (runS { h2_17 := true }).map (fun r => r.2.map (·.2)) =
    some [[.settingsAck], [], [], [.goaway 0 ePROTOCOL], [], []] := by native_decide

/-- **Fixed**: with the H2-17 fix, for every run and every peer, while no
GOAWAY is emitted the decoder sees exactly the server's blocks and returns
only the server's fields (`ConnHpack.lookup_sound_conn`, client role). -/
theorem fixed (fx : Fix) (hfx : fx.h2_17 = true) (budget : Nat) (es : List Ev) (c0 c'' : Conn)
    (trc : List (Ev × List Out)) (rss : List (List Rep)) (pd : Option (Nat × Bytes)) (p' : Peer)
    (fss : List (List Entry))
    (hr : runD fx (decAt real budget) c0 es = some (c'', trc))
    (hg : c0.goawaySent = false) (hd : c0.decLog = []) (hc : c0.continuing = 0)
    (hno : trc.all (fun p => !hasGoaway p.2) = true)
    (hfr : rrun (none, []) (framesOf es) = (pd, rss.map (encBlock real Flare.L1.Huffman.encode)))
    (hpeer : pblocks Peer.init rss = some (p', fss))
    (hv : ∀ rs ∈ rss, ∀ r ∈ rs, Flare.L3.H2.Hpack.RepOK Flare.L1.Huffman.encode r) :
    c''.decLog = rss.map (encBlock real Flare.L1.Huffman.encode) ∧
    Sound fss (decFold real budget Flare.L3.H2.Hpack.Table.init c''.decLog).2 :=
  lookup_sound_conn fx real Flare.L3.H2.Hpack.real_correct Flare.L1.Huffman.encode Flare.L3.H2.Hpack.real_huff budget es c0 c''
    trc rss pd p' fss hr hg hd hc (Or.inl hfx) hno hfr hpeer hv

/-- The shipped model carries the H2-17 fix, so `lookup_sound_conn` holds
for it in client role. -/
theorem fixed_shipped (budget : Nat) (es : List Ev) (c0 c'' : Conn)
    (trc : List (Ev × List Out)) (rss : List (List Rep)) (pd : Option (Nat × Bytes)) (p' : Peer)
    (fss : List (List Entry))
    (hr : runD Fix.shipped (decAt real budget) c0 es = some (c'', trc))
    (hg : c0.goawaySent = false) (hd : c0.decLog = []) (hc : c0.continuing = 0)
    (hno : trc.all (fun p => !hasGoaway p.2) = true)
    (hfr : rrun (none, []) (framesOf es) = (pd, rss.map (encBlock real Flare.L1.Huffman.encode)))
    (hpeer : pblocks Peer.init rss = some (p', fss))
    (hv : ∀ rs ∈ rss, ∀ r ∈ rs, Flare.L3.H2.Hpack.RepOK Flare.L1.Huffman.encode r) :
    c''.decLog = rss.map (encBlock real Flare.L1.Huffman.encode) ∧
    Sound fss (decFold real budget Flare.L3.H2.Hpack.Table.init c''.decLog).2 :=
  fixed Fix.shipped rfl budget es c0 c'' trc rss pd p' fss hr hg hd hc hno hfr hpeer hv

theorem shipped_frame : outs Fix.shipped init [.frame settings0, .openLocal 1 true, .frame push] =
    some [[.settingsAck], [], [.goaway 0 ePROTOCOL]] := by native_decide

end Flare.Bugs.H2_17

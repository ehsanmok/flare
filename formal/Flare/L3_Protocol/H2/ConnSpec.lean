import Flare.L3_Protocol.H2.Conn

/-!
# HTTP/2 connection: RFC 9113 requirements and per-clause theorems

The requirements below are written from RFC 9113 and phrased over what
the connection *emits* (its reply frames), not over flare's internals:

* `IsConnError o code`: the reply is exactly a GOAWAY with `code` (§5.4.1).
* `ConnWindowOK`: a monitor over an input/reply trace. It replays the
  peer's view of the connection receive window (65535, minus every DATA
  payload, plus every WINDOW_UPDATE on stream 0 the receiver emitted,
  §6.9.1) and fails if a DATA frame that overruns it is processed without
  a connection error.
* `peerW`: the same window as a number, used by the credit-conservation
  requirement of §6.9 ("A receiver ... MUST always account for its
  contribution against the connection flow-control window").

Per-clause theorems in this file: each fixed branch answers the
offending frame as the RFC requires, for every connection state.
-/
namespace Flare.L3.H2.Conn

/-! ## Observable requirements -/

def isGoaway : Out → Bool
  | .goaway .. => true
  | _ => false

def hasGoaway (o : List Out) : Bool := o.any isGoaway

/-- §5.4.1: a connection error is reported by a GOAWAY carrying its code. -/
def IsConnError (o : List Out) (code : Nat) : Prop := ∃ last, o = [.goaway last code]

/-- Flow-controlled octets an input carries (§6.9: only DATA). -/
def flowLen : Ev → Nat
  | .frame f => if f.ty = tDATA then f.plen else 0
  | _ => 0

/-- §6.9.1 monitor. `alive`: no GOAWAY emitted yet; `w`: the receive
window the peer sees. -/
def connWindowOK : Bool → Int → List (Ev × List Out) → Bool
  | _, _, [] => true
  | alive, w, (e, o) :: t =>
    !(alive && decide (flowLen e > 0) && !hasGoaway o && decide ((flowLen e : Int) > w)) &&
    connWindowOK (alive && !hasGoaway o) (w - flowLen e + wu0 o) t

def ConnWindowOK (tr : List (Ev × List Out)) : Prop := connWindowOK true 65535 tr = true

/-- The connection window as the peer sees it after a trace. -/
def peerW (w : Int) : List (Ev × List Out) → Int
  | [] => w
  | (e, o) :: t => peerW (w - flowLen e + wu0 o) t

/-! ## Basic lemmas -/

theorem connErr_out (c : Conn) (code : Nat) (h : c.goawaySent = false) :
    connErr c code = ({ c with goawaySent := true }, [.goaway c.lastPeer code]) := by
  simp [connErr, h]

theorem shape_headers (fx : Fix) (c : Conn) (f : Fr) (h : f.ty = tHEADERS) :
    shapeCheck fx c f = none := by
  simp [shapeCheck, h, tHEADERS, tPING, tGOAWAY, tSETTINGS, tPRIORITY, tRST, tWU, tDATA, tPUSH]

theorem shape_goaway (fx : Fix) (c : Conn) (f : Fr) (h : f.ty = tGOAWAY) (h0 : f.sid = 0) :
    shapeCheck fx c f = if fx.h2_07 && f.plen < 8 then some (connErr c eFRAME_SIZE) else none := by
  simp [shapeCheck, h, h0, tPING, tGOAWAY]

theorem dispatch_headers (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (h : f.ty = tHEADERS) :
    dispatch fx dec c f = headersH fx dec c f := by
  simp [dispatch, h, tHEADERS, tSETTINGS, tPING, tWU]

/-! ## H2-06: HEADERS on stream 0 (§6.2) -/

theorem handle_headers0 (fx : Fix) (dec : Dec) (c : Conn) (f : Fr)
    (hc : c.continuing = 0) (ht : f.ty = tHEADERS) (h0 : f.sid = 0) (hl : f.plen ≤ c.localMaxFrame)
    (hlp : c.isClient = true ∨ c.lastPeer = 0) (h02 : fx.h2_02 = false) :
    handle fx dec c f =
      if fx.h2_06 then .ok (connErr c ePROTOCOL) else .error "h2: HEADERS on stream 0" := by
  have hid : idCheck fx c f = .inr c := by
    rcases hlp with h | h <;> simp [idCheck, ht, h0, h, h02]
  simp [handle, hc, shape_headers fx c f ht, Nat.not_lt.mpr hl, hid, dispatch_headers fx dec c f ht,
    headersH, h0]

/-! ## H2-07: short GOAWAY (§6.8, §4.2) -/

theorem handle_goaway_short (fx : Fix) (dec : Dec) (c : Conn) (f : Fr)
    (hc : c.continuing = 0) (ht : f.ty = tGOAWAY) (h0 : f.sid = 0) (hfx : fx.h2_07 = true)
    (hs : f.plen < 8) : handle fx dec c f = .ok (connErr c eFRAME_SIZE) := by
  simp [handle, hc, shape_goaway fx c f ht h0, hfx, hs]

/-! ## H2-02: reuse of a used stream id (§5.1.1) -/

theorem handle_reuse (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (hfx : fx.h2_02 = true)
    (hc : c.continuing = 0) (hs : c.isClient = false) (ht : f.ty = tHEADERS)
    (hl : f.plen ≤ c.localMaxFrame) (hle : f.sid ≤ c.lastPeer) (hm : mem c f.sid = false) :
    handle fx dec c f = .ok (connErr c ePROTOCOL) := by
  have hid : idCheck fx c f = .inl (connErr c ePROTOCOL) := by
    unfold idCheck
    simp only [ht, hs, hfx, hle, hm]
    by_cases h2 : f.sid ≠ 0 ∧ f.sid % 2 = 0 <;> simp_all
  simp [handle, hc, shape_headers fx c f ht, Nat.not_lt.mpr hl, hid]

/-! ## H2-04: client HEADERS on a stream it never opened (§5.1, §5.1.1) -/

theorem handle_client_unopened (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (hfx : fx.h2_04 = true)
    (hc : c.continuing = 0) (hcl : c.isClient = true) (ht : f.ty = tHEADERS) (h0 : f.sid ≠ 0)
    (hl : f.plen ≤ c.localMaxFrame) (hm : mem c f.sid = false) :
    handle fx dec c f = .ok (connErr c ePROTOCOL) := by
  have hid : idCheck fx c f = .inr c := by simp [idCheck, ht, hcl]
  simp [handle, hc, shape_headers fx c f ht, Nat.not_lt.mpr hl, hid, dispatch_headers fx dec c f ht,
    headersH, h0, hfx, hcl, hm]

/-! ## H2-08: the first frame must be SETTINGS (§3.4) -/

theorem drive_first_not_settings (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (h8 : fx.h2_08 = true)
    (hg : c.goawaySent = false) (hs : c.peerSettingsSeen = false) (hl : f.plen ≤ c.localMaxFrame)
    (hn : ¬ (f.ty = tSETTINGS ∧ f.f1 = false)) :
    driveFrame fx dec c f = .ok (connErr c ePROTOCOL) := by
  have hn' : (decide (f.ty = tSETTINGS) && !f.f1) = false := by
    by_cases h : f.ty = tSETTINGS
    · cases hf : f.f1
      · exact absurd ⟨h, hf⟩ hn
      · simp
    · simp [h]
  simp [driveFrame, prefaceGate, hg, hs, h8, Nat.not_lt.mpr hl, hn']

/-! ## H2-03: late WINDOW_UPDATE / RST_STREAM on a stream the client closed (§5.1) -/

theorem handle_client_late_wu (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (h3 : fx.h2_03 = true)
    (hcl : c.isClient = true) (hc : c.continuing = 0) (ht : f.ty = tWU) (hp : f.plen = 4)
    (hl : f.plen ≤ c.localMaxFrame) (hinc : f.word % 2147483648 ≠ 0) (hk : f.sid ≠ 0)
    (hodd : f.sid % 2 = 1) (hle : f.sid ≤ c.maxLocalSid) (hm : get c f.sid = none) :
    handle fx dec c f = .ok (c, []) := by
  have hsh : shapeCheck fx c f = none := by
    simp [shapeCheck, ht, hp, tWU, tPING, tGOAWAY, tSETTINGS, tPRIORITY, tRST]
  have hid : idCheck fx c f = .inr c := by simp [idCheck, ht, hcl]
  have hidle : isIdleId fx c f.sid = false := by
    simp [isIdleId, h3, hcl, Nat.not_lt.mpr hle]; omega
  simp [handle, hc, hsh, Nat.not_lt.mpr hl, hid, dispatch, ht, tWU, tSETTINGS, tPING, wuH, hinc, hk,
    hm, hidle]

theorem handle_client_late_rst (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (h3 : fx.h2_03 = true)
    (hcl : c.isClient = true) (hc : c.continuing = 0) (ht : f.ty = tRST) (hp : f.plen = 4)
    (hl : f.plen ≤ c.localMaxFrame) (hk : f.sid ≠ 0) (hodd : f.sid % 2 = 1)
    (hle : f.sid ≤ c.maxLocalSid) :
    handle fx dec c f = .ok (rstH c f) := by
  have hidle : isIdleId fx c f.sid = false := by
    simp [isIdleId, h3, hcl, Nat.not_lt.mpr hle]; omega
  have hsh : shapeCheck fx c f = none := by
    simp [shapeCheck, ht, hp, hk, hidle, tRST, tPING, tGOAWAY, tSETTINGS, tPRIORITY]
  have hid : idCheck fx c f = .inr c := by simp [idCheck, ht, hcl]
  simp [handle, hc, hsh, Nat.not_lt.mpr hl, hid, dispatch, ht, tRST, tSETTINGS, tPING, tWU, tHEADERS,
    tCONT, tDATA, tGOAWAY]

/-! ## H2-11: SETTINGS_MAX_CONCURRENT_STREAMS = 0 (§5.1.2, §6.5.2) -/

theorem refuse_at_limit (fx : Fix) (c : Conn) (f : Fr) (h11 : fx.h2_11 = true)
    (hs : c.isClient = false) (hm : mem c f.sid = false) (hge : c.maxConcurrent ≤ activeCount c) :
    headersRefuse fx c f 0 = eREFUSED := by
  simp [headersRefuse, h11, hs, hm, hge]

end Flare.L3.H2.Conn

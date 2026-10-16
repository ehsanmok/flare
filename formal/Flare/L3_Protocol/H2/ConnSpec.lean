import Flare.L3_Protocol.H2.Conn
import Flare.L3_Protocol.H2.StreamTable

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

Per-clause theorems in this file: each of these branches answers the
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

theorem shape_headers (c : Conn) (f : Fr) (h : f.ty = tHEADERS) :
    shapeCheck c f = none := by
  simp [shapeCheck, h, tHEADERS, tPING, tGOAWAY, tSETTINGS, tPRIORITY, tRST, tWU, tDATA, tPUSH]

theorem shape_goaway (c : Conn) (f : Fr) (h : f.ty = tGOAWAY) (h0 : f.sid = 0) :
    shapeCheck c f = if f.plen < 8 then some (connErr c eFRAME_SIZE) else none := by
  simp [shapeCheck, h, h0, tPING, tGOAWAY]

theorem dispatch_headers (dec : Dec) (c : Conn) (f : Fr) (h : f.ty = tHEADERS) :
    dispatch dec c f = headersH dec c f := by
  simp [dispatch, h, tHEADERS, tSETTINGS, tPING, tWU]

/-! ## HEADERS on stream 0 (§6.2) -/

theorem handle_headers0 (dec : Dec) (c : Conn) (f : Fr)
    (hc : c.continuing = 0) (ht : f.ty = tHEADERS) (h0 : f.sid = 0) (hl : f.plen ≤ c.localMaxFrame)
    (hlp : c.isClient = true ∨ c.lastPeer = 0) :
    handle dec c f = .ok (connErr c ePROTOCOL) := by
  have hid : idCheck c f = .inr c := by
    rcases hlp with h | h <;> simp [idCheck, ht, h0, h]
  simp [handle, hc, shape_headers c f ht, Nat.not_lt.mpr hl, hid, dispatch_headers dec c f ht,
    headersH, h0]

/-! ## Short GOAWAY (§6.8, §4.2) -/

theorem handle_goaway_short (dec : Dec) (c : Conn) (f : Fr)
    (hc : c.continuing = 0) (ht : f.ty = tGOAWAY) (h0 : f.sid = 0)
    (hs : f.plen < 8) : handle dec c f = .ok (connErr c eFRAME_SIZE) := by
  simp [handle, hc, shape_goaway c f ht h0, hs]

/-! ## Reuse of a used stream id (§5.1.1) -/

theorem handle_reuse (dec : Dec) (c : Conn) (f : Fr)
    (hc : c.continuing = 0) (hs : c.isClient = false) (ht : f.ty = tHEADERS)
    (hl : f.plen ≤ c.localMaxFrame) (hle : f.sid ≤ c.lastPeer) (hpos : 0 < c.lastPeer)
    (hm : mem c f.sid = false) :
    handle dec c f = .ok (connErr c ePROTOCOL) := by
  have hid : idCheck c f = .inl (connErr c ePROTOCOL) := by
    unfold idCheck
    simp only [ht, hs, hle, hpos, hm]
    by_cases h2 : f.sid ≠ 0 ∧ f.sid % 2 = 0 <;> simp_all
  simp [handle, hc, shape_headers c f ht, Nat.not_lt.mpr hl, hid]

/-! ## Client HEADERS on a stream it never opened (§5.1, §5.1.1) -/

theorem handle_client_unopened (dec : Dec) (c : Conn) (f : Fr)
    (hc : c.continuing = 0) (hcl : c.isClient = true) (ht : f.ty = tHEADERS) (h0 : f.sid ≠ 0)
    (hl : f.plen ≤ c.localMaxFrame) (hm : mem c f.sid = false) :
    handle dec c f = .ok (connErr c ePROTOCOL) := by
  have hid : idCheck c f = .inr c := by simp [idCheck, ht, hcl]
  simp [handle, hc, shape_headers c f ht, Nat.not_lt.mpr hl, hid, dispatch_headers dec c f ht,
    headersH, h0, hcl, hm]

/-! ## The first frame must be SETTINGS (§3.4) -/

theorem drive_first_not_settings (dec : Dec) (c : Conn) (f : Fr)
    (hg : c.goawaySent = false) (hs : c.peerSettingsSeen = false) (hl : f.plen ≤ c.localMaxFrame)
    (hn : ¬ (f.ty = tSETTINGS ∧ f.f1 = false)) :
    driveFrame dec c f = .ok (connErr c ePROTOCOL) := by
  have hn' : (decide (f.ty = tSETTINGS) && !f.f1) = false := by
    by_cases h : f.ty = tSETTINGS
    · cases hf : f.f1
      · exact absurd ⟨h, hf⟩ hn
      · simp
    · simp [h]
  simp [driveFrame, prefaceGate, hg, hs, Nat.not_lt.mpr hl, hn']

/-! ## Late WINDOW_UPDATE / RST_STREAM on a stream the client closed (§5.1) -/

theorem handle_client_late_wu (dec : Dec) (c : Conn) (f : Fr)
    (hcl : c.isClient = true) (hc : c.continuing = 0) (ht : f.ty = tWU) (hp : f.plen = 4)
    (hl : f.plen ≤ c.localMaxFrame) (hinc : f.word % 2147483648 ≠ 0) (hk : f.sid ≠ 0)
    (hodd : f.sid % 2 = 1) (hle : f.sid ≤ c.maxLocalSid) (hm : get c f.sid = none) :
    handle dec c f = .ok (c, []) := by
  have hsh : shapeCheck c f = none := by
    simp [shapeCheck, ht, hp, tWU, tPING, tGOAWAY, tSETTINGS, tPRIORITY, tRST]
  have hid : idCheck c f = .inr c := by simp [idCheck, ht, hcl]
  have hidle : isIdleId c f.sid = false := by
    simp [isIdleId, hcl, Nat.not_lt.mpr hle]; omega
  simp [handle, hc, hsh, Nat.not_lt.mpr hl, hid, dispatch, ht, tWU, tSETTINGS, tPING, wuH, hinc, hk,
    hm, hidle]

theorem handle_client_late_rst (dec : Dec) (c : Conn) (f : Fr)
    (hcl : c.isClient = true) (hc : c.continuing = 0) (ht : f.ty = tRST) (hp : f.plen = 4)
    (hl : f.plen ≤ c.localMaxFrame) (hk : f.sid ≠ 0) (hodd : f.sid % 2 = 1)
    (hle : f.sid ≤ c.maxLocalSid) :
    handle dec c f = .ok (rstH c f) := by
  have hidle : isIdleId c f.sid = false := by
    simp [isIdleId, hcl, Nat.not_lt.mpr hle]; omega
  have hsh : shapeCheck c f = none := by
    simp [shapeCheck, ht, hp, hk, hidle, tRST, tPING, tGOAWAY, tSETTINGS, tPRIORITY]
  have hid : idCheck c f = .inr c := by simp [idCheck, ht, hcl]
  simp [handle, hc, hsh, Nat.not_lt.mpr hl, hid, dispatch, ht, tRST, tSETTINGS, tPING, tWU, tHEADERS,
    tCONT, tDATA, tGOAWAY]

/-! ## SETTINGS_MAX_CONCURRENT_STREAMS = 0 (§5.1.2, §6.5.2) -/

theorem refuse_at_limit (c : Conn) (f : Fr)
    (hs : c.isClient = false) (hm : mem c f.sid = false) (hge : c.maxConcurrent ≤ activeCount c) :
    headersRefuse c f 0 = eREFUSED := by
  simp [headersRefuse, hs, hm, hge]

/-! ## Ending a stream locally (§5.1) -/

/-- Our END_STREAM on a half-closed (remote) stream closes it. -/
theorem endLocal_hcr (c : Conn) (k : Nat) (s : Stream)
    (hg : get c k = some s) (hs : s.state = .hcr) :
    get (endLocal c k) k = some { s with state := .closed } := by
  simp [endLocal, hg, hs]

/-- Ending a closed stream changes nothing (it does not reopen it). -/
theorem endLocal_closed (c : Conn) (k : Nat) (s : Stream)
    (hg : get c k = some s) (hs : s.state = .closed) : endLocal c k = c := by
  simp [endLocal, hg, hs]

/-! ## HEADERS on a half-closed (remote) stream (§5.1) -/

theorem headersPre_hcr (c : Conn) (f : Fr) (s : Stream)
    (hg : get c f.sid = some s) (hs : s.state = .hcr) :
    headersPre c f = .inl (connErr c eSTREAM_CLOSED) := by
  simp [headersPre, hg, hs]

/-! ## Frames on idle streams (§5.1) -/

/-- A server never opens an even id, so every even id is idle to it. -/
theorem isIdleId_even (c : Conn) (k : Nat) (hs : c.isClient = false)
    (he : k % 2 = 0) : isIdleId c k = true := by
  simp [isIdleId, hs, he]

theorem shape_rst_even (c : Conn) (f : Fr) (hs : c.isClient = false)
    (ht : f.ty = tRST) (h0 : f.sid ≠ 0) (he : f.sid % 2 = 0) (hp : f.plen = 4)
    (hm : mem c f.sid = false) : shapeCheck c f = some (connErr c ePROTOCOL) := by
  have hi := isIdleId_even c f.sid hs he
  simp [shapeCheck, ht, h0, hp, hm, hi, tRST, tPING, tGOAWAY, tSETTINGS, tPRIORITY]

/-- PRIORITY that makes an idle stream depend on itself. -/
theorem shape_priority_idle (c : Conn) (f : Fr) (ht : f.ty = tPRIORITY)
    (h0 : f.sid ≠ 0) (hp : f.plen = 5) (hd : f.word % 2147483648 = f.sid)
    (hm : mem c f.sid = false) (hi : isIdleId c f.sid = true) :
    shapeCheck c f = some (connErr c ePROTOCOL) := by
  simp [shapeCheck, ht, h0, hp, hd, hm, hi, tPRIORITY, tPING, tGOAWAY, tSETTINGS]

/-- Zero-increment WINDOW_UPDATE on an idle stream. -/
theorem wuH_zero_idle (c : Conn) (f : Fr)
    (h0 : f.sid ≠ 0) (hw : f.word % 2147483648 = 0)
    (hm : mem c f.sid = false) (hi : isIdleId c f.sid = true) :
    wuH c f = connErr c ePROTOCOL := by
  simp [wuH, h0, hw, hm, hi]

/-! ## Oversized frame to the client (§4.2) -/

theorem client_oversize (dec : Dec) (c : Conn) (f : Fr)
    (hc : c.isClient = true) (hl : f.plen > c.localMaxFrame) :
    step dec c (.frame f) = .ok (connErr c eFRAME_SIZE) := by
  simp [step, hc, driveClient, hl]

/-! ## DATA (§5.1, §6.9) -/

/-- No stream WINDOW_UPDATE goes out on a stream that the client's
END_STREAM DATA closes. -/
theorem dataFinish_no_stream_wu (c : Conn) (f : Fr) (s : Stream) (cr : Nat)
    (hc : c.isClient = true) (hk : f.sid ≠ 0) (he : f.f1 = true) (hs : s.state = .hcl)
    (hcl : ¬ (f.f1 = true ∧ (0 : Int) ≤ s.contentLength ∧ (s.received : Int) ≠ s.contentLength)) :
    ∀ n, Out.wu f.sid n ∉ (dataFinish c f s cr).2 := by
  intro n hn
  unfold dataFinish at hn
  rw [if_neg (by simpa [he] using hcl)] at hn
  simp only [he, hc, hs, Bool.true_and, beq_self_eq_true, ite_true] at hn
  unfold dataCredit at hn
  split at hn
  · simp only [Nat.lt_irrefl, ite_false, List.nil_append] at hn
    split at hn
    · simp at hn
    · simp at hn; exact hk hn.1
  · simp at hn

/-- DATA on a closed or half-closed (remote) stream we did not reset. -/
theorem dataH_closed (c : Conn) (f : Fr) (s : Stream)
    (hr : f.sid ∉ c.resetByUs) (hg : get c f.sid = some s) (hs : s.state = .closed ∨ s.state = .hcr) :
    dataH c f = connErr c eSTREAM_CLOSED := by
  simp only [dataH, if_neg hr, hg]
  rcases hs with h | h <;> simp [h]

/-- A client that gets DATA before the response HEADERS resets that stream
with PROTOCOL_ERROR and leaves the connection up (§8.1: a malformed
response is a stream error). -/
def StreamScoped (step : Conn → Fr → Conn × List Out) : Prop :=
  ∀ c f s, c.isClient = true → f.sid ∉ c.resetByUs → get c f.sid = some s →
    s.state ≠ .closed → s.state ≠ .hcr → s.headersComplete = false →
    (∀ l code, Out.goaway l code ∉ (step c f).2) ∧
    Out.rst f.sid ePROTOCOL ∈ (step c f).2 ∧
    (step c f).1.goawaySent = c.goawaySent

theorem dataH_stream_scoped : StreamScoped dataH := by
  intro c f s hc hr hg h1 h2 hh
  have hn : (s.state == .closed || s.state == .hcr) = false := by
    revert h1 h2; cases s.state <;> decide
  simp only [dataH, hr, if_false, hg, hn, hc, hh, Bool.not_false,
    Bool.and_self, if_true, rstCloseX]
  refine ⟨?_, by simp, by simp [put, rstC]⟩
  intro l code hm
  by_cases hp : f.plen > 0 <;> simp [wu0If, put, hp] at hm

end Flare.L3.H2.Conn

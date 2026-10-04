import Flare.L3_Protocol.H2.Conn

/-!
# DOC-03: the HTTP/2 client treats DATA before the response HEADERS as a connection error

* flare file: `flare/http2/state.mojo:1356-1358` @59bda50, in the DATA branch
  of `Connection.handle_frame` (modelled by `Flare.L3.H2.Conn.dataH`):
  `if self.is_client and not s.headers_complete: return self._conn_error(PROTOCOL_ERROR)`.
* Doc clause: `docs/features.md:369` "A malformed response is a stream error
  per RFC 9113 §8.1.1, never a connection error, so one bad stream cannot take
  its siblings down". RFC 9113 §8.1 / §8.1.1: a response that starts with DATA
  is "an otherwise valid sequence of HTTP/2 frames but ... invalid due to the
  presence of extraneous frames" and "MUST be treated as a stream error
  (Section 5.4.2) of type PROTOCOL_ERROR".
* What goes wrong: DATA on a client stream in half-closed (local) whose
  response HEADERS have not arrived queues GOAWAY(PROTOCOL_ERROR); every
  sibling stream is lost. Every existing H2 fix flag (`Fix.all`) leaves this
  branch unchanged.
* Fix (`dataHFixed`): RST_STREAM(sid, PROTOCOL_ERROR), close the stream and
  hand back the frame's connection credit, as the 204-body branch already does
  (`dataBody`, state.mojo:1384-1398).
-/
namespace Flare.Bugs.DOC_03
open Flare.L3.H2.Names Flare.L3.H2.Conn

/-- The doc's promise at the DATA branch: on a client stream whose response
HEADERS are not complete, DATA is a stream error. No GOAWAY is queued, the
stream is reset with PROTOCOL_ERROR, and the connection's GOAWAY state is
untouched. -/
def StreamScoped (step : Conn → Fr → Conn × List Out) : Prop :=
  ∀ c f s, c.isClient = true → f.sid ∉ c.resetByUs → get c f.sid = some s →
    s.headersComplete = false →
    (∀ l code, Out.goaway l code ∉ (step c f).2) ∧
    Out.rst f.sid ePROTOCOL ∈ (step c f).2 ∧
    (step c f).1.goawaySent = c.goawaySent

/-- mirrors flare/http2/state.mojo:1340-1358 @59bda50, with the
`not s.headers_complete` branch answered by a stream error. -/
def dataHFixed (fx : Fix) (c : Conn) (f : Fr) : Conn × List Out :=
  if f.sid ∈ c.resetByUs then (c, wu0If f.plen)
  else match get c f.sid with
  | none => if isIdleId fx c f.sid then connErr c ePROTOCOL else connErr c eSTREAM_CLOSED
  | some s =>
    if c.isClient && !s.headersComplete then rstCloseX c f.sid ePROTOCOL s (wu0If f.plen)
    else if s.state = .closed || s.state = .hcr then connErr c eSTREAM_CLOSED
    else match stripLen f false with
    | none => connErr c ePROTOCOL
    | some body => dataBody fx c f { s with recvW := s.recvW - f.plen } body

/-- GET on streams 1 and 3, both half-closed (local), no response yet. -/
def conn0 : Conn := { isClient := true, streams := [(1, { state := .hcl }), (3, { state := .hcl })] }

/-- DATA(1, END_STREAM, "x") before any HEADERS on stream 1. -/
def dataX : Fr := { ty := tDATA, sid := 1, f1 := true, plen := 1, frag := [120] }

/-- The shipped branch, with every existing H2 fix applied, answers with
GOAWAY(PROTOCOL_ERROR) and nothing else. -/
theorem bug : (dataH Fix.all conn0 dataX).2 = [.goaway 0 ePROTOCOL] ∧
    (dataH Fix.all conn0 dataX).1.goawaySent = true := by
  native_decide

theorem counterexample : ¬ StreamScoped (dataH Fix.all) := by
  intro h
  have := (h conn0 dataX { state := .hcl } rfl (by decide) rfl rfl).1 0 ePROTOCOL
  rw [bug.1] at this
  simp at this

/-- The fixed branch resets stream 1 and returns the octet of connection
credit; stream 3 is untouched. -/
theorem fixed_example : (dataHFixed Fix.all conn0 dataX).2 = [.rst 1 ePROTOCOL, .wu 0 1] ∧
    get (dataHFixed Fix.all conn0 dataX).1 3 = some { state := .hcl } := by
  native_decide

theorem fixed (fx : Fix) : StreamScoped (dataHFixed fx) := by
  intro c f s hc hr hg hh
  simp only [dataHFixed, hr, if_false, hg, hc, hh, Bool.not_false, Bool.and_self, if_true,
    rstCloseX]
  refine ⟨?_, by simp, by simp [put, rstC]⟩
  intro l code
  unfold wu0If
  split <;> simp

end Flare.Bugs.DOC_03

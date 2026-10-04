import Flare.Core.Bytes

/-!
# The interim `100 Continue` and the final response on one connection

`_maybe_send_continue` (flare/http/_reactor/conn_handle.mojo:544-576) writes
`HTTP/1.1 100 Continue\r\n\r\n` once, from STATE_READING, with a single
non-blocking write whose result it ignores. The final response is later
serialised into a cleared `write_buf` (`_finalise_response`, 718-756) and
flushed from offset 0 (`on_writable`, 1286-1312; `_flush_write_buf_tls`,
1213-1240). The model follows the bytes of one request with
`Expect: 100-continue`, after `pre` (everything sent before it).

**Cleartext (`Plain`).** The kernel oracle `k` is how many of the interim
bytes the one `send` takes (0 is EAGAIN). On Linux any `k` up to the
length can happen when the send buffer is nearly full; on BSD/macOS a
non-blocking TCP send smaller than the low-water mark takes all or nothing.

**TLS (`Tls`).** flare sets no SSL mode (flare/tls/ffi/openssl_wrapper.cpp),
so OpenSSL's contract for `SSL_write` is: it returns the full length or a
WANT sentinel, never a short count (no `SSL_MODE_ENABLE_PARTIAL_WRITE`);
after a WANT the record stays pending, and the next `SSL_write` must pass
the same buffer, otherwise it fails with `SSL_R_BAD_WRITE_RETRY` (no
`SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER`). `ok` is whether the interim
record went out whole. Buffers are identified by `Buf`.

**Spec.** RFC 9112 §2.1 and §4, RFC 9110 §15.2: the server sends complete
messages, and the request is answered: after `pre` the wire is the final
response `R`, or the whole interim `I` and then `R`, and the connection
is not torn down.

* `Plain.violates`: for every `0 < k < |I|` flare's wire is
  `pre ++ I.take k ++ R`, which is neither (by length).
* `Plain.fixed_spec`: keeping the unsent tail and putting it in front of
  the response meets the spec for every `k`.
* `Tls.violates`: when the record does not go out whole, flare's flush of
  the response fails and the connection closes with `R` unsent.
* `Tls.fixed_spec`: retrying from the connection's own copy of the interim
  before the response meets the spec for both outcomes.
-/
namespace Flare.L4.Continue

/-- The spec: the final response alone, or the whole interim and then the
final response, and the connection survives. -/
def Spec (pre I R wire : Bytes) (closed : Bool) : Prop :=
  closed = false ∧ (wire = pre ++ R ∨ wire = pre ++ I ++ R)

namespace Plain

structure St where
  wire : Bytes
  wbuf : Bytes
  rest : Bytes

/-- mirrors flare/http/_reactor/conn_handle.mojo:556-576 @59bda50
(the `_send` result is dropped) -/
def sendContinue (I : Bytes) (k : Nat) (s : St) : St :=
  { s with wire := s.wire ++ I.take k }

/-- mirrors flare/http/_reactor/conn_handle.mojo:718-756,1423-1435 @59bda50
(`write_buf` is serialised from scratch, `write_pos := 0`) -/
def finalise (R : Bytes) (s : St) : St :=
  { s with wbuf := R }

/-- mirrors flare/http/_reactor/conn_handle.mojo:1286-1312 @59bda50
(the flush loop, run until `write_pos = len(write_buf)`) -/
def flush (s : St) : St :=
  { s with wire := s.wire ++ s.wbuf, wbuf := [] }

def run (pre I R : Bytes) (k : Nat) : Bytes :=
  (flush (finalise R (sendContinue I k ⟨pre, [], []⟩))).wire

/-- The fix: keep the tail the kernel did not take (only after a short
send; EAGAIN leaves the client's own fallback in charge). -/
def sendContinueFixed (I : Bytes) (k : Nat) (s : St) : St :=
  { s with wire := s.wire ++ I.take k,
           rest := if 0 < k ∧ k < I.length then I.drop k else [] }

/-- The fix: the kept tail goes in front of the response. -/
def finaliseFixed (R : Bytes) (s : St) : St :=
  { s with wbuf := s.rest ++ R, rest := [] }

def runFixed (pre I R : Bytes) (k : Nat) : Bytes :=
  (flush (finaliseFixed R (sendContinueFixed I k ⟨pre, [], []⟩))).wire

theorem run_eq (pre I R : Bytes) (k : Nat) : run pre I R k = pre ++ I.take k ++ R := by
  simp [run, flush, finalise, sendContinue]

theorem violates (pre I R : Bytes) (k : Nat) (h0 : 0 < k) (hk : k < I.length) :
    ¬ Spec pre I R (run pre I R k) false := by
  rw [run_eq]
  rintro ⟨-, h | h⟩
  · have := congrArg List.length h
    simp only [List.length_append, List.length_take] at this
    omega
  · have := congrArg List.length h
    simp only [List.length_append, List.length_take] at this
    omega

theorem fixed_spec (pre I R : Bytes) (k : Nat) : Spec pre I R (runFixed pre I R k) false := by
  refine ⟨rfl, ?_⟩
  simp only [runFixed, flush, finaliseFixed, sendContinueFixed]
  by_cases h : 0 < k ∧ k < I.length
  · right
    rw [if_pos h, ← List.append_assoc, List.append_assoc pre, List.take_append_drop]
  · rw [if_neg h, List.nil_append]
    by_cases hk : k = 0
    · left; simp [hk]
    · right
      have : I.length ≤ k := by omega
      rw [List.take_of_length_le this]

end Plain

namespace Tls

/-- Which buffer an `SSL_write` was given. -/
inductive Buf
  | interim  -- the local `String` in `_maybe_send_continue`
  | own      -- a buffer the connection keeps (the fix)
  | wbuf     -- `write_buf`
  deriving DecidableEq

structure St where
  wire : Bytes
  pending : Option Buf
  closed : Bool

/-- OpenSSL's `SSL_write` under flare's modes: a pending record must be
retried with the same buffer; otherwise `SSL_R_BAD_WRITE_RETRY`, which
flare classifies as fatal. `ok` says whether the record goes out whole. -/
def sslWrite (b : Buf) (data : Bytes) (ok : Bool) (s : St) : St :=
  match s.pending with
  | some b' =>
    if b' = b then { s with wire := s.wire ++ data, pending := none }
    else { s with closed := true }
  | none =>
    if ok then { s with wire := s.wire ++ data } else { s with pending := some b }

/-- mirrors flare/http/_reactor/conn_handle.mojo:564-569 @59bda50
(`tls.send(bytes)`, result dropped) -/
def sendContinue (I : Bytes) (ok : Bool) (s : St) : St :=
  sslWrite .interim I ok s

/-- mirrors flare/http/_reactor/conn_handle.mojo:1213-1240 @59bda50
(`SSL_write` of `write_buf`; the socket has drained, so it would go out) -/
def flush (R : Bytes) (s : St) : St :=
  if s.closed then s else sslWrite .wbuf R true s

def run (pre I R : Bytes) (ok : Bool) : St :=
  flush R (sendContinue I ok ⟨pre, none, false⟩)

/-- The fix: write the interim from a buffer the connection keeps, and
retry it from that buffer before the response. -/
def sendContinueFixed (I : Bytes) (ok : Bool) (s : St) : St :=
  sslWrite .own I ok s

def flushFixed (I R : Bytes) (s : St) : St :=
  let s' := if s.pending = some .own then sslWrite .own I true s else s
  if s'.closed then s' else sslWrite .wbuf R true s'

def runFixed (pre I R : Bytes) (ok : Bool) : St :=
  flushFixed I R (sendContinueFixed I ok ⟨pre, none, false⟩)

theorem violates (pre I R : Bytes) :
    (run pre I R false).closed = true ∧ (run pre I R false).wire = pre ∧
      ¬ Spec pre I R (run pre I R false).wire (run pre I R false).closed := by
  simp [run, flush, sendContinue, sslWrite, Spec]

theorem fixed_spec (pre I R : Bytes) (ok : Bool) :
    Spec pre I R (runFixed pre I R ok).wire (runFixed pre I R ok).closed := by
  cases ok <;> simp [runFixed, flushFixed, sendContinueFixed, sslWrite, Spec]

end Tls

end Flare.L4.Continue

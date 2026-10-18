import Flare.Core.Bytes

/-!
# The interim `100 Continue` and the final response on one connection

`_maybe_send_continue` writes `HTTP/1.1 100 Continue\r\n\r\n` once, from
STATE_READING, with a single non-blocking write. Whatever of it the write
does not take is kept and sent before the final response (APP-49). The
model follows the bytes of one request with `Expect: 100-continue`, after
`pre` (everything sent before it).

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

* `Plain.run_spec`: keeping the unsent tail and putting it in front of the
  response meets the spec for every `k`.
* `Tls.run_spec`: retrying from the connection's own copy of the interim
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

/-- mirrors flare/http/_reactor/conn_handle.mojo#ConnHandle.on_writable sha=97ab3b583fa2 at=59bda50f
(the flush loop, run until `write_pos = len(write_buf)`) -/
def flush (s : St) : St :=
  { s with wire := s.wire ++ s.wbuf, wbuf := [] }

/-- Keep the tail the kernel did not take (only after a short
send; EAGAIN leaves the client's own fallback in charge).
mirrors flare/http/_reactor/conn_handle.mojo#ConnHandle._maybe_send_continue+ConnHandle._keep_unsent_interim+ConnHandle._check_request_complete sha=58c0298dfb61 at=12630564 (fixed, APP-49) -/
def sendContinue (I : Bytes) (k : Nat) (s : St) : St :=
  { s with wire := s.wire ++ I.take k,
           rest := if 0 < k ∧ k < I.length then I.drop k else [] }

/-- The kept tail goes in front of the response.
mirrors flare/http/_reactor/conn_handle.mojo#ConnHandle.close+ConnHandle._transition_to_writing sha=912a371744c0 at=405105c0 (fixed, APP-49) -/
def finalise (R : Bytes) (s : St) : St :=
  { s with wbuf := s.rest ++ R, rest := [] }

def run (pre I R : Bytes) (k : Nat) : Bytes :=
  (flush (finalise R (sendContinue I k ⟨pre, [], []⟩))).wire

theorem run_spec (pre I R : Bytes) (k : Nat) : Spec pre I R (run pre I R k) false := by
  refine ⟨rfl, ?_⟩
  simp only [run, flush, finalise, sendContinue]
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
  | own      -- the interim, in a buffer the connection keeps
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

/-- Write the interim from a buffer the connection keeps
(`continue_pending`).
mirrors flare/http/_reactor/conn_handle.mojo#ConnHandle._maybe_send_continue sha=ea4e768d08f0 at=405105c0 (fixed, APP-49) -/
def sendContinue (I : Bytes) (ok : Bool) (s : St) : St :=
  sslWrite .own I ok s

/-- Retry the kept interim from the same buffer before the response.
mirrors flare/http/_reactor/conn_handle.mojo#ConnHandle.on_readable_static+ConnHandle._flush_write_buf_tls sha=ac0e210f74bc at=12630564 (fixed, APP-49) -/
def flush (I R : Bytes) (s : St) : St :=
  let s' := if s.pending = some .own then sslWrite .own I true s else s
  if s'.closed then s' else sslWrite .wbuf R true s'

def run (pre I R : Bytes) (ok : Bool) : St :=
  flush I R (sendContinue I ok ⟨pre, none, false⟩)

theorem run_spec (pre I R : Bytes) (ok : Bool) :
    Spec pre I R (run pre I R ok).wire (run pre I R ok).closed := by
  cases ok <;> simp [run, flush, sendContinue, sslWrite, Spec]

end Tls

end Flare.L4.Continue

import Flare.Core

/-!
# `TcpStream.connect_timeout`, Linux path

flare/tcp/stream.mojo:254-333: save flags (`F_GETFL`), set `O_NONBLOCK`,
non-blocking `connect`, then on `EINPROGRESS` `poll(POLLOUT, timeout)`
and `getsockopt(SO_ERROR)`. The model is an executable function over the
syscall results (an oracle record) returning the sequence of flag writes
and the outcome. The property of interest: once `O_NONBLOCK` was set, the
saved flags are written back on *every* exit path.
-/
namespace Flare.L2.ConnectTimeout

def EINPROGRESS : Nat := 115
def EINTR : Nat := 4
def ECONNREFUSED : Nat := 111
def ETIMEDOUT : Nat := 110

/-- Syscall results seen by one call. `soErr` is what `getsockopt` would
write; `gsoOk = false` means `getsockopt` itself failed (its return value
is ignored by flare, so `so_err` keeps its initial 0). -/
structure Oracle where
  getfl : Int
  connRc : Int
  connErrno : Nat
  pollRc : Int
  pollErrno : Nat
  gsoOk : Bool
  soErr : Nat
  deriving DecidableEq, Repr

inductive FlagOp where
  | setNonblock | restore
  deriving DecidableEq, Repr

inductive Out where
  | connected
  | refused | timedOut | netError (errno : Nat)
  deriving DecidableEq, Repr

/-- mirrors flare/tcp/stream.mojo:254-333 @59bda50 -/
def run (o : Oracle) : List FlagOp × Out :=
  if o.getfl < 0 then ([], .netError 0)                     -- F_GETFL failed
  else
    let pre := [FlagOp.setNonblock]
    if o.connRc = 0 then (pre ++ [.restore], .connected)     -- immediate success
    else if o.connErrno ≠ EINPROGRESS then
      (pre ++ [.restore],
        if o.connErrno = ECONNREFUSED then .refused
        else if o.connErrno = ETIMEDOUT then .timedOut
        else .netError o.connErrno)
    else if o.pollRc = 0 then (pre ++ [.restore], .timedOut)
    else if o.pollRc < 0 then (pre ++ [.restore], .netError o.pollErrno)
    else
      let err := if o.gsoOk then o.soErr else 0
      (pre ++ [.restore],
        if err = 0 then .connected
        else if err = ECONNREFUSED then .refused
        else if err = ETIMEDOUT then .timedOut
        else .netError err)

/-- Headline: if `F_GETFL` succeeded the flag writes are exactly
`[setNonblock, restore]` on every path; otherwise the flags are untouched. -/
theorem flags_restored (o : Oracle) :
    (run o).1 = (if o.getfl < 0 then [] else [.setNonblock, .restore]) := by
  unfold run
  by_cases h : o.getfl < 0
  · simp [h]
  · simp only [h, if_false]
    repeat' split
    all_goals rfl

/-- Corollary: the socket never leaves `connect_timeout` in non-blocking mode. -/
theorem never_left_nonblocking (o : Oracle) :
    (run o).1.getLast? ≠ some .setNonblock := by
  rw [flags_restored]; split <;> simp

/-- Note: `EINTR` from `poll` is not retried; it raises `NetworkError`. -/
theorem poll_eintr_raises (o : Oracle) (h0 : 0 ≤ o.getfl) (h1 : o.connRc ≠ 0)
    (h2 : o.connErrno = EINPROGRESS) (h3 : o.pollRc = -1) (h4 : o.pollErrno = EINTR) :
    (run o).2 = .netError EINTR := by
  have : ¬ o.getfl < 0 := by omega
  simp [run, this, h1, h2, h3, h4]

/-- Note: a failing `getsockopt` is read as success (its return value is
ignored and `so_err` stays 0). -/
theorem getsockopt_failure_is_success (o : Oracle) (h0 : 0 ≤ o.getfl) (h1 : o.connRc ≠ 0)
    (h2 : o.connErrno = EINPROGRESS) (h3 : 0 < o.pollRc) (h4 : o.gsoOk = false) :
    (run o).2 = .connected := by
  have : ¬ o.getfl < 0 := by omega
  have : ¬ o.pollRc = 0 := by omega
  have : ¬ o.pollRc < 0 := by omega
  simp [run, *]

end Flare.L2.ConnectTimeout

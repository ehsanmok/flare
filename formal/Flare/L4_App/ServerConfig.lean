import Flare.Core

/-!
# `ServerConfig.check` and the deadlines the connection machine uses

`ServerConfig.check[cfg]()` (flare/http/_server/config.mojo:251-329) is a
list of `comptime assert`s. Here it is a decidable predicate on the numeric
fields. The connection machine (flare/http/_reactor/conn_handle.mojo) turns
the fields into `StepResult.idle_timeout_ms` timer instructions
(`-1` = leave the timer alone, `0` = clear it, `> 0` = re-arm), and checks
`request_timeout_ms` as an absolute budget on every readable event.

Results:

* `default_check`: the default config passes `check`.
* `timer_instr_nonneg`: under `check` every timer instruction issued by the
  read and write phases is `≥ 0`, so each phase transition replaces the
  previous phase's timer (a write timer never survives into the read phase).
* `body_timer_le_request`: under `check`, when both are enabled, the timer
  armed while a body is arriving is at most `request_timeout_ms`.
* `closeTime_le`: with `request_timeout_ms = R > 0` and every read re-arming
  a timer of at most `T` ms, the read phase of one request ends (408 or timer
  close) no later than `t0 + R + T`, where `t0` is the first byte's time.
  General (all traces), not bounded.
* `overCapOld` / `overCapSpec`: the read-buffer size cap, with Mojo `Int`
  wrapping, used by `Flare.Bugs.APP_06`.
-/
namespace Flare.L4.ServerConfig

/-- The numeric fields of `ServerConfig` that `check` and the connection
machine read. Mojo `Int` fields are modelled as `Int` (their values in a
checked config fit `Int64`; the one place where wrapping matters, the size
cap, is modelled separately with `Int64`).
mirrors flare/http/_server/config.mojo:132-144 @59bda50 -/
structure Cfg where
  readBufferSize : Int
  maxHeaderSize : Int
  maxBodySize : Int
  maxUriLength : Int
  keepAlive : Bool
  maxKeepaliveRequests : Int
  idleTimeoutMs : Int
  writeTimeoutMs : Int
  readBodyTimeoutMs : Int
  handlerTimeoutMs : Int
  requestTimeoutMs : Int
  deriving DecidableEq, Repr

/-- Defaults of `ServerConfig.__init__`.
mirrors flare/http/_server/config.mojo:206-221 @59bda50 -/
def default : Cfg where
  readBufferSize := 8192
  maxHeaderSize := 8192
  maxBodySize := 10 * 1024 * 1024
  maxUriLength := 8192
  keepAlive := true
  maxKeepaliveRequests := 100
  idleTimeoutMs := 500
  writeTimeoutMs := 5000
  readBodyTimeoutMs := 30000
  handlerTimeoutMs := 30000
  requestTimeoutMs := 60000

/-- `ServerConfig.check`: the conjunction of its `comptime assert`s.
mirrors flare/http/_server/config.mojo:276-329 @59bda50 -/
def check (c : Cfg) : Prop :=
  c.readBufferSize > 0 ∧ c.maxHeaderSize > 0 ∧ c.maxUriLength > 0 ∧
  c.maxBodySize ≥ c.maxHeaderSize ∧ c.maxKeepaliveRequests ≥ 1 ∧
  c.idleTimeoutMs ≥ 0 ∧ c.writeTimeoutMs ≥ 0 ∧ c.readBodyTimeoutMs ≥ 0 ∧
  c.handlerTimeoutMs ≥ 0 ∧ c.requestTimeoutMs ≥ 0 ∧
  (c.requestTimeoutMs = 0 ∨ c.handlerTimeoutMs = 0 ∨
    c.requestTimeoutMs ≥ c.handlerTimeoutMs) ∧
  (c.requestTimeoutMs = 0 ∨ c.readBodyTimeoutMs = 0 ∨
    c.requestTimeoutMs ≥ c.readBodyTimeoutMs)

instance (c : Cfg) : Decidable (check c) := by unfold check; infer_instance

theorem default_check : check default := by decide

/-- `check` implies `max_keepalive_requests ≥ 1`, which the keep-alive bound
in `Flare.L4.ConnSM` uses to read `ka ≤ max 1 maxKA` as `ka ≤ maxKA`. -/
theorem check_maxKA (c : Cfg) (h : check c) : 1 ≤ c.maxKeepaliveRequests := h.2.2.2.2.1

/-! ## Timer instructions issued by the machine -/

/-- Head still arriving: `idle_timeout_ms`.
mirrors flare/http/_reactor/conn_handle.mojo:614-620 @59bda50 -/
def headTimer (c : Cfg) : Int := c.idleTimeoutMs

/-- Body still arriving: `body_timeout_ms if body_timeout_ms > 0 else
idle_timeout_ms`, with `body_timeout_ms = read_body_timeout_ms` from every
`on_readable*` reader except the static one.
mirrors flare/http/_reactor/conn_handle.mojo:667-691 @59bda50 -/
def bodyTimer (c : Cfg) : Int :=
  if c.readBodyTimeoutMs > 0 then c.readBodyTimeoutMs else c.idleTimeoutMs

/-- Partial write / stream yield: `write_timeout_ms`.
mirrors flare/http/_reactor/conn_handle.mojo:1314-1320 @59bda50 -/
def writeTimer (c : Cfg) : Int := c.writeTimeoutMs

/-- Flushed, back to keep-alive reading: `idle_timeout_ms`.
mirrors flare/http/_reactor/conn_handle.mojo:1370-1375 @59bda50 -/
def keepaliveTimer (c : Cfg) : Int := c.idleTimeoutMs

/-- Under `check` no phase issues the "leave unchanged" instruction (`-1`
or any negative), so a timer armed in one phase is always replaced or
cleared when the next phase starts. -/
theorem timer_instr_nonneg (c : Cfg) (h : check c) :
    0 ≤ headTimer c ∧ 0 ≤ bodyTimer c ∧ 0 ≤ writeTimer c ∧ 0 ≤ keepaliveTimer c := by
  obtain ⟨-, -, -, -, -, hi, hw, hb, -⟩ := h
  unfold headTimer bodyTimer writeTimer keepaliveTimer
  refine ⟨hi, ?_, hw, hi⟩
  split <;> omega

/-- Deadline ordering: when `request_timeout_ms` and `read_body_timeout_ms`
are both enabled, the body-phase timer does not exceed the request budget. -/
theorem body_timer_le_request (c : Cfg) (h : check c)
    (hr : c.requestTimeoutMs > 0) (hb : c.readBodyTimeoutMs > 0) :
    bodyTimer c ≤ c.requestTimeoutMs := by
  obtain ⟨-, -, -, -, -, -, -, -, -, -, -, h2⟩ := h
  unfold bodyTimer; simp only [hb, if_true]; omega

/-- A config `check` accepts in which the body timer is *larger* than the
request budget does not exist; but `idle_timeout_ms` is not ordered against
`request_timeout_ms`, so the head-phase timer can exceed it. Witness. -/
theorem head_timer_unordered :
    ∃ c, check c ∧ c.requestTimeoutMs > 0 ∧ headTimer c > c.requestTimeoutMs :=
  ⟨{ default with idleTimeoutMs := 120000 }, by decide, by decide, by decide⟩

/-! ## The read phase is bounded by `R + T`

`_check_request_complete` (conn_handle.mojo:598-605) records the time of the
first readable event that sees bytes and answers 408 on any later readable
event with `now - started > R`. Between reads, the idle/body timer (re-armed
with at most `T` ms on every read) closes the connection when it fires. -/

/-- Close time of one request's read phase. `t0` is the first byte's time,
`last` the previous readable event, and the list the later readable event
times. Each event either comes after the armed timer fired (close at
`last + T`), trips the absolute budget (408 at `t`), or re-arms.
mirrors flare/http/_reactor/conn_handle.mojo:598-605,614-620,681-691 @59bda50 -/
def closeTime (R T t0 last : Nat) : List Nat → Nat
  | [] => last + T
  | t :: ts =>
    if last + T < t then last + T
    else if t - t0 > R then t
    else closeTime R T t0 t ts

/-- The whole read phase ends by `t0 + R + T` for every trace of readable
events (monotone clock assumed, `Flare.Assumptions.MonotoneClock`). -/
theorem closeTime_le (R T t0 : Nat) :
    ∀ (ts : List Nat) (last : Nat), Flare.Assumptions.MonotoneClock (last :: ts) →
      t0 ≤ last → last - t0 ≤ R → closeTime R T t0 last ts ≤ t0 + R + T := by
  intro ts
  induction ts with
  | nil => intro last _ h1 h2; simp only [closeTime]; omega
  | cons t ts ih =>
    intro last hm h1 h2
    unfold Flare.Assumptions.MonotoneClock at hm
    have hlt : last ≤ t := List.rel_of_pairwise_cons hm (by simp)
    have hm' : List.Pairwise (· ≤ ·) (t :: ts) := List.Pairwise.of_cons hm
    simp only [closeTime]
    split
    · omega
    · split
      · omega
      · exact ih t hm' (by omega) (by omega)

/-! ## The read-buffer size cap -/

/-- The cap test before the APP-06 fix: `len(self.read_buf) >
config.max_header_size + config.max_body_size`, in Mojo `Int` (wrapping
`Int64`).
mirrors flare/http/_reactor/conn_handle.mojo:448-453 @59bda50
(identical at 492-497 and 536-541) -/
def overCapOld (len maxH maxB : Int64) : Bool := len > maxH + maxB

/-- Intended meaning, on mathematical integers: the buffer is larger than
the largest legal head plus the largest legal body. -/
def overCapSpec (len maxH maxB : Int) : Bool := decide (len > maxH + maxB)

/-- The cap test as shipped (fixed, APP-06): `len(self.read_buf) -
config.max_header_size > config.max_body_size` at all three sites of
conn_handle.mojo (and `_parse_http_request`).
mirrors flare/http/_reactor/conn_handle.mojo:460-463, 505-508, 550-553 (fixed,
APP-06) -/
def overCapImpl (len maxH maxB : Int64) : Bool := len - maxH > maxB

/-- The shipped test agrees with the spec whenever `0 ≤ len`, `0 ≤ maxH` and `maxB`
is any `Int64` (no wrapping can occur in `len - maxH`). -/
theorem overCapImpl_eq_spec (len maxH maxB : Int64)
    (hl : 0 ≤ len.toInt) (hh : 0 ≤ maxH.toInt) :
    overCapImpl len maxH maxB = overCapSpec len.toInt maxH.toInt maxB.toInt := by
  unfold overCapImpl overCapSpec
  have hsub : (len - maxH).toInt = len.toInt - maxH.toInt := by
    rw [Int64.toInt_sub]
    have h1 := Int64.toInt_lt len; have h2 := Int64.toInt_lt maxH
    apply Int.bmod_eq_of_le <;> omega
  simp only [decide_eq_decide, Int64.lt_iff_toInt_lt, hsub]
  omega

end Flare.L4.ServerConfig

import Flare.L4_App.ClientPool

/-!
# `HttpClient` plain-TCP pool leases: no double release

Can `HttpClient` hand the same pooled fd back to `ClientPool` twice (and so
hand it out to two requests)? Two parts.

**Per request.** `_send_h1_pooled` (flare/http/client.mojo:2509-2593) is
the only caller of `ClientPool.acquire`/`release` (`_pool`, an fd pool).
It wraps the acquired fd (or a fresh dial) in a `TcpStream`; the stream's
destructor and `close()` close the fd at most once (RawSocket sets
`fd = INVALID_FD`, flare/net/socket.mojo:199-218), and before `release` the
code moves the fd out of the stream (`stream._socket.fd = INVALID_FD`), so
the destructor no longer owns it. `sendPooled` models every path through
the function, with an oracle choosing which call raises (`_arm_read_timeout`,
`write_all`, the framed read, `release` itself, `_may_replay`, the fresh
dial). `dispose_first`/`dispose_second`: each connection the function
opens or acquires is disposed of (released or closed) exactly once, on
every path; in particular it is released at most once.

**Across requests.** `Client` composes the pool (`ClientPool.St`) with the
set of fds currently held by requests (`out`). The transitions are
`acquire`, `release` and `close` of a held fd (the per-request result says
these are the only things a request does with its fd, once), and `dial`
of a fresh fd; that the kernel never returns an fd number that is
currently open is an environment hypothesis, encoded as the guard of
`dial`. `inv_reachable`: every fd number occurs at most once across the
pool's deques and the held set. `acquire_not_held`: `acquire` never
returns an fd that some request still holds, and `pool_fd_once`: no fd is
filed twice in the pool.

The TLS and QUIC pools hold `TlsStream`/`H3Connection` values that are
moved (`^`) into `release`; `HttpClient` and these types are `Movable`,
not `Copyable` (client.mojo:232, 552-560), so a second release of the same
value is a compile-time error. They are not modelled.
-/
namespace Flare.L4.ClientLease

open Flare.L4.ClientPool

/-! ## Per request: `_send_h1_pooled` -/

/-- `first`: the pooled fd (or the first fresh dial); `second`: the fresh
connection of the replay path. -/
inductive Conn | first | second
deriving DecidableEq

inductive Act | release (c : Conn) | close (c : Conn)
deriving DecidableEq

def Act.conn : Act → Conn
  | .release c => c
  | .close c => c

def Act.isRelease : Act → Bool
  | .release _ => true
  | .close _ => false

/-- Which call raises. `read1`/`read2`: `none` when the framed read raises,
else `some can_reuse`. `rel1Raises`: `release` raises after filing the fd
(the worst case). -/
structure Orc where
  dial1 : Bool
  arm1 : Bool
  write1 : Bool
  read1 : Option Bool
  rel1Raises : Bool
  replay : Bool
  dial2 : Bool
  arm2 : Bool
  write2 : Bool
  read2 : Option Bool

/-- The replay on a fresh connection. A raise anywhere after the dial runs
`fresh`'s destructor; `release` is preceded by moving the fd out, so a
raise inside it closes nothing.
mirrors flare/http/client.mojo:2578-2593 @59bda50 -/
def retry (o : Orc) : List Act × Bool :=
  if !o.dial2 then ([], false)
  else if !o.arm2 then ([.close .second], false)
  else if !o.write2 then ([.close .second], false)
  else match o.read2 with
    | none => ([.close .second], false)
    | some true => ([.release .second], true)
    | some false => ([.close .second], true)

/-- After `stream.close()` on the failure path: raise unless the fd was
pooled and the request may be replayed.
mirrors flare/http/client.mojo:2566-2577 @59bda50 -/
def tail (attempted : Bool) (o : Orc) : List Act × Bool :=
  if !attempted then ([], false) else if !o.replay then ([], false) else retry o

/-- `_send_h1_pooled`; `attempted` is `acquire(key) >= 0`. Returns the
disposal actions in order and whether the call returned normally.
mirrors flare/http/client.mojo:2509-2593 @59bda50 -/
def sendPooled (attempted : Bool) (o : Orc) : List Act × Bool :=
  if !attempted && !o.dial1 then ([], false)
  else if !o.arm1 then ([.close .first], false)
  else if !o.write1 then (.close .first :: (tail attempted o).1, (tail attempted o).2)
  else match o.read1 with
    | some true =>
      if o.rel1Raises then (.release .first :: (tail attempted o).1, (tail attempted o).2)
      else ([.release .first], true)
    | some false => ([.close .first], true)
    | none => (.close .first :: (tail attempted o).1, (tail attempted o).2)

/-- Number of actions on connection `c`. -/
def uses (c : Conn) (acts : List Act) : Nat := (acts.filter (fun a => a.conn == c)).length

/-- Number of releases of connection `c`. -/
def releases (c : Conn) (acts : List Act) : Nat :=
  (acts.filter (fun a => a.conn == c && a.isRelease)).length

theorem releases_le_uses (c : Conn) (acts : List Act) : releases c acts ≤ uses c acts := by
  induction acts with
  | nil => simp [releases, uses]
  | cons a acts ih =>
    simp only [releases, uses, List.filter_cons] at ih ⊢
    cases a.conn == c <;> cases a.isRelease <;> simp <;> omega

theorem retry_first (o : Orc) : uses .first (retry o).1 = 0 := by
  unfold retry
  split
  · rfl
  split
  · rfl
  split
  · rfl
  split <;> rfl

theorem retry_second (o : Orc) : uses .second (retry o).1 = if o.dial2 then 1 else 0 := by
  unfold retry
  cases o.dial2 <;> simp only [Bool.not_false, Bool.not_true, if_true, if_false,
    Bool.false_eq_true]
  · rfl
  split
  · rfl
  split
  · rfl
  split <;> rfl

theorem tail_first (a : Bool) (o : Orc) : uses .first (tail a o).1 = 0 := by
  unfold tail
  split
  · rfl
  split
  · rfl
  exact retry_first o

theorem tail_second_le (a : Bool) (o : Orc) : uses .second (tail a o).1 ≤ 1 := by
  unfold tail
  split
  · simp [uses]
  split
  · simp [uses]
  rw [retry_second]; split <;> omega

theorem uses_cons_first (l : List Act) :
    uses .first (Act.release .first :: l) = uses .first l + 1 ∧
    uses .first (Act.close .first :: l) = uses .first l + 1 ∧
    uses .second (Act.release .first :: l) = uses .second l ∧
    uses .second (Act.close .first :: l) = uses .second l := by
  simp [uses, Act.conn]

/-- **Exactly once.** The pooled (or first fresh) connection is disposed
of exactly once on every path, and not at all when it was never opened. -/
theorem dispose_first (a : Bool) (o : Orc) :
    uses .first (sendPooled a o).1 = if a || o.dial1 then 1 else 0 := by
  have hc := uses_cons_first
  have ht := tail_first a o
  unfold sendPooled
  split
  · rename_i h
    simp only [Bool.and_eq_true, Bool.not_eq_true'] at h
    obtain ⟨rfl, h2⟩ := h
    simp [h2, uses]
  · rename_i h
    have hor : (a || o.dial1) = true := by
      cases a <;> cases hd : o.dial1 <;> simp_all
    rw [if_pos hor]
    split
    · rfl
    split
    · rw [(hc _).2.1, ht]
    split
    · split
      · rw [(hc _).1, ht]
      · rfl
    · rfl
    · rw [(hc _).2.1, ht]

/-- The replay connection is disposed of at most once. -/
theorem dispose_second (a : Bool) (o : Orc) : uses .second (sendPooled a o).1 ≤ 1 := by
  have hc := uses_cons_first
  have ht := tail_second_le a o
  unfold sendPooled
  split
  · simp [uses]
  split
  · simp [uses, Act.conn]
  split
  · rw [(hc _).2.2.2]; exact ht
  split
  · split
    · rw [(hc _).2.2.1]; exact ht
    · simp [uses, Act.conn]
  · simp [uses, Act.conn]
  · rw [(hc _).2.2.2]; exact ht

/-- **At most one release per acquire**, for each connection. -/
theorem release_once (a : Bool) (o : Orc) (c : Conn) : releases c (sendPooled a o).1 ≤ 1 := by
  have := releases_le_uses c (sendPooled a o).1
  cases c
  · have := dispose_first a o; split at this <;> omega
  · have := dispose_second a o; omega

/-! ## Across requests: pool plus held fds -/

/-- All fds filed in the pool, over every key. -/
def fds (e : Entries) : List Nat := (e.map Prod.snd).flatten

def cnt (x : Nat) (e : Entries) : Nat := (fds e).count x

theorem cnt_split (x : Nat) (e : Entries) (k : Key) (h : (keys e).Nodup) :
    cnt x e = cnt x (erase e k) + (getD e k).count x := by
  induction e with
  | nil => simp [cnt, fds, erase, getD]
  | cons p e ih =>
    obtain ⟨k', v⟩ := p
    simp only [keys, List.map_cons, List.nodup_cons] at h
    have ih' := ih h.2
    rw [getD_cons]
    by_cases hk : k' = k
    · subst hk
      have hnot : ∀ q ∈ e, (q.1 != k') = true := by
        intro q hq; simp only [bne_iff_ne, ne_eq]
        intro he; exact h.1 (List.mem_map.2 ⟨q, hq, he⟩)
      have hf : erase e k' = e := List.filter_eq_self.2 hnot
      simp only [erase, List.filter_cons, bne_self_eq_false, Bool.false_eq_true, if_false,
        if_true] at hf ⊢
      rw [hf]; simp [cnt, fds, List.count_append]; omega
    · simp only [erase, List.filter_cons, bne_iff_ne, ne_eq, hk, not_false_eq_true, if_true,
        if_false] at ih' ⊢
      simp only [cnt, fds, List.map_cons, List.flatten_cons, List.count_append] at ih' ⊢
      omega

theorem cnt_put (x : Nat) (e : Entries) (k : Key) (v : List Nat) :
    cnt x (put e k v) = cnt x (erase e k) + v.count x := by
  simp [cnt, fds, put, erase, List.count_append]

theorem cnt_erase_le (x : Nat) (e : Entries) (k : Key) (h : (keys e).Nodup) :
    cnt x (erase e k) ≤ cnt x e := by
  rw [cnt_split x e k h]; omega

/-- The eviction loop returns a suffix of its input, minus the evicted
prefix and the returned fd. -/
theorem popLoop_split (c : Cfg) (ts : List (Nat × Int)) (now : Int) :
    ∀ (l : List Nat) (fd : Nat) (rest : List Nat), popLoop c ts now l = (some fd, rest) →
      ∃ pre, l = pre ++ fd :: rest
  | [], fd, rest, h => by simp [popLoop] at h
  | y :: l, fd, rest, h => by
    simp only [popLoop] at h
    split at h
    · obtain ⟨pre, hp⟩ := popLoop_split c ts now l fd rest h
      exact ⟨y :: pre, by simp [hp]⟩
    · simp only [Prod.mk.injEq, Option.some.injEq] at h; obtain ⟨rfl, rfl⟩ := h
      exact ⟨[], rfl⟩

structure CSt where
  pool : St
  out : List Nat

inductive CEv
  | acquire (k : Key) (now : Int)
  | release (k : Key) (fd : Nat) (now : Int)
  | close (fd : Nat)
  | dial (fd : Nat)

/-- Client-side composition. `release`/`close` act on an fd the request
holds (`dispose_first`/`dispose_second`); `dial` returns an fd number
that is not open, i.e. neither pooled nor held. -/
def cstep (c : Cfg) (s : CSt) : CEv → Option CSt
  | .acquire k now =>
    let r := acquire c s.pool k now
    some ⟨r.1, match r.2 with | some fd => fd :: s.out | none => s.out⟩
  | .release k fd now =>
    if fd ∈ s.out then some ⟨release c s.pool k fd now, s.out.erase fd⟩ else none
  | .close fd => if fd ∈ s.out then some ⟨s.pool, s.out.erase fd⟩ else none
  | .dial fd =>
    if fd ∉ fds s.pool.entries ∧ fd ∉ s.out then some ⟨s.pool, fd :: s.out⟩ else none

def client (c : Cfg) : LTS CSt CEv := LTS.ofFn (· = ⟨init, []⟩) (cstep c)

/-- Every fd number occurs at most once across the pool and the held set. -/
structure CInv (c : Cfg) (s : CSt) : Prop where
  pool : Inv c s.pool
  once : ∀ x, cnt x s.pool.entries + s.out.count x ≤ 1

theorem cinv_init (c : Cfg) : CInv c ⟨init, []⟩ :=
  ⟨inv_init c, by intro x; simp [cnt, fds, init]⟩

theorem count_erase_mem (x fd : Nat) (l : List Nat) (h : fd ∈ l) :
    (l.erase fd).count x + (if x = fd then 1 else 0) = l.count x := by
  rw [List.count_erase]
  by_cases hx : x = fd
  · subst hx
    have := List.count_pos_iff.2 h
    simp; omega
  · have : (fd == x) = false := by simp; exact fun h => hx h.symm
    simp [hx, this]

theorem cinv_release (c : Cfg) (s : CSt) (k : Key) (fd : Nat) (now : Int) (h : CInv c s)
    (hfd : fd ∈ s.out) : CInv c ⟨release c s.pool k fd now, s.out.erase fd⟩ := by
  refine ⟨inv_release c s.pool k fd now h.pool, ?_⟩
  intro x
  have h1 := h.once x
  have h2 := count_erase_mem x fd s.out hfd
  have hs := cnt_split x s.pool.entries k h.pool.nodup
  dsimp only
  unfold release
  split
  · omega
  split
  · omega
  split
  · dsimp only; rw [cnt_put]; omega
  · dsimp only; rw [cnt_put, List.count_append]
    by_cases hx : x = fd
    · subst hx; rw [if_pos rfl] at h2; simp only [List.count_singleton_self]; omega
    · have : ([fd] : List Nat).count x = 0 := List.count_eq_zero.2 (by simpa using hx)
      rw [this]; rw [if_neg hx] at h2; omega

theorem cinv_acquire (c : Cfg) (s : CSt) (k : Key) (now : Int) (h : CInv c s) :
    CInv c ⟨(acquire c s.pool k now).1,
      match (acquire c s.pool k now).2 with | some fd => fd :: s.out | none => s.out⟩ := by
  refine ⟨inv_acquire c s.pool k now h.pool, ?_⟩
  intro x
  have h1 := h.once x
  have hs := cnt_split x s.pool.entries k h.pool.nodup
  unfold acquire
  split
  · exact h1
  split
  · rename_i fd rest hpop
    obtain ⟨pre, hl⟩ := popLoop_split c s.pool.ts now _ fd rest hpop
    have hc : (getD s.pool.entries k).count x = pre.count x + (fd :: rest).count x := by
      rw [← List.count_reverse (l := getD s.pool.entries k), hl, List.count_append]
    dsimp only
    rw [cnt_put, List.count_reverse, List.count_cons]
    by_cases hb : (fd == x) = true <;> simp [hb, List.count_cons] at hc ⊢ <;> omega
  · dsimp only
    have := cnt_erase_le x s.pool.entries k h.pool.nodup
    omega

theorem cinv_step (c : Cfg) (s s' : CSt) (e : CEv) (h : CInv c s) (hs : cstep c s e = some s') :
    CInv c s' := by
  cases e with
  | acquire k now =>
    simp only [cstep, Option.some.injEq] at hs; subst hs
    exact cinv_acquire c s k now h
  | release k fd now =>
    simp only [cstep] at hs
    split at hs
    · rename_i hfd; simp only [Option.some.injEq] at hs; subst hs
      exact cinv_release c s k fd now h hfd
    · cases hs
  | close fd =>
    simp only [cstep] at hs
    split at hs
    · rename_i hfd; simp only [Option.some.injEq] at hs; subst hs
      refine ⟨h.pool, fun x => ?_⟩
      have := h.once x; have := count_erase_mem x fd s.out hfd; dsimp only; omega
    · cases hs
  | dial fd =>
    simp only [cstep] at hs
    split at hs
    · rename_i hfd; simp only [Option.some.injEq] at hs; subst hs
      refine ⟨h.pool, fun x => ?_⟩
      have h1 := h.once x
      dsimp only; rw [List.count_cons]
      split
      · rename_i hb; simp only [beq_iff_eq] at hb; subst hb
        have a1 : cnt fd s.pool.entries = 0 := List.count_eq_zero.2 hfd.1
        have a2 : s.out.count fd = 0 := List.count_eq_zero.2 hfd.2
        omega
      · omega
    · cases hs

theorem cinv_inductive (c : Cfg) : (client c).Inductive (CInv c) where
  init := by intro s hs; rw [hs]; exact cinv_init c
  step := by
    intro s e s' h hs
    exact cinv_step c s s' e h hs

theorem inv_reachable (c : Cfg) (s : CSt) (h : (client c).Reachable s) : CInv c s :=
  (cinv_inductive c).reachable s h

/-- **No double hand-out.** `acquire` never returns an fd that a request
still holds. -/
theorem acquire_not_held (c : Cfg) (s : CSt) (k : Key) (now : Int) (fd : Nat)
    (h : (client c).Reachable s) (ha : (acquire c s.pool k now).2 = some fd) : fd ∉ s.out := by
  have hi := inv_reachable c s h
  have hin : fd ∈ getD s.pool.entries k := by
    unfold acquire at ha
    split at ha
    · cases ha
    split at ha
    · rename_i fd' rest hpop
      simp only [Option.some.injEq] at ha; subst ha
      obtain ⟨-, -, ho⟩ := popLoop_sub c s.pool.ts now _ _ _ hpop
      simpa using ho fd' rfl
    · cases ha
  have h1 := hi.once fd
  have hs := cnt_split fd s.pool.entries k hi.pool.nodup
  have := List.count_pos_iff.2 hin
  intro hout
  have := List.count_pos_iff.2 hout
  omega

/-- **No fd filed twice.** In every reachable state each fd number occurs
at most once in the pool's deques. -/
theorem pool_fd_once (c : Cfg) (s : CSt) (h : (client c).Reachable s) (x : Nat) :
    cnt x s.pool.entries ≤ 1 := by
  have := (inv_reachable c s h).once x; omega

end Flare.L4.ClientLease

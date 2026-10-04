import Flare.Core

/-!
# HTTP/1.1 client connection pool (`ClientPool`)

Model of flare/http/client_pool.mojo: per-origin LIFO deques of idle fds
(`entries : Dict[String, List[Int]]`), the insertion-time map
(`insertion_ts_ms`), `release` (push back, or close when a cap is reached)
and `acquire` (pop from the back, closing entries older than
`idle_timeout_ms`, until a fresh one is found).

The `Dict` is an association list whose keys the invariant keeps unique.
A ghost list `rel` records every `(key, fd)` the pool accepted.

Results (all general):
* `inv_reachable`: in every reachable state, each origin holds at most
  `max_idle_per_host` idle fds, the pool holds at most `max_idle_total`
  in total (when that cap is enabled), keys are unique, and every pooled
  fd was released under the key it is filed under.
* `acquire_same_origin`: `acquire key` only ever returns an fd that was
  released under the same `key` (no connection to one origin is handed
  out for another).

Limitations: the key is the caller-built `scheme://host:port` string, not
lowercased (`build_key`, client_pool.mojo:191-201), so `API.example.com` and
`api.example.com` use separate buckets (a missed reuse, not a safety
problem; see APP-44). The pool trusts the caller to release each fd once:
a double `release` files the fd twice, and the second `acquire` of it in
Mojo raises `KeyError` on `insertion_ts_ms[fd]`. The model reads a missing
timestamp as 0 and does not delete timestamps (they only feed the age
test).
-/
namespace Flare.L4.ClientPool

abbrev Key := String
abbrev Entries := List (Key × List Nat)

/-- `max_idle_per_host`, `max_idle_total`, `idle_timeout_ms`.
mirrors flare/http/client_pool.mojo:86-102 @59bda50 -/
structure Cfg where
  perHost : Int
  total : Int
  idleMs : Int

structure St where
  entries : Entries
  ts : List (Nat × Int)
  /-- ghost: every `(key, fd)` the pool accepted -/
  rel : List (Key × Nat)

def init : St := ⟨[], [], []⟩

/-- `entries[key]` (empty when absent). -/
def getD (e : Entries) (k : Key) : List Nat :=
  match e.find? (fun p => p.1 == k) with
  | some p => p.2
  | none => []

def hasKey (e : Entries) (k : Key) : Bool := e.any (fun p => p.1 == k)

/-- `entries[key] = v`. -/
def put (e : Entries) (k : Key) (v : List Nat) : Entries := e.filter (fun p => p.1 != k) ++ [(k, v)]

/-- `entries.pop(key)`. -/
def erase (e : Entries) (k : Key) : Entries := e.filter (fun p => p.1 != k)

/-- `_total_idle`.
mirrors flare/http/client_pool.mojo:279-293 @59bda50 -/
def total (e : Entries) : Nat := (e.map fun p => p.2.length).sum

/-- `release(key, fd)`: close (state unchanged) when pooling is off for
the host, when the total cap is reached, or when the host's deque is full;
otherwise append.
mirrors flare/http/client_pool.mojo:244-277 @59bda50 -/
def release (c : Cfg) (s : St) (k : Key) (fd : Nat) (now : Int) : St :=
  if c.perHost ≤ 0 then s
  else if 0 < c.total ∧ c.total ≤ (total s.entries : Int) then s
  else
    if c.perHost ≤ ((getD s.entries k).length : Int) then
      { s with entries := put s.entries k (getD s.entries k) }
    else { s with entries := put s.entries k (getD s.entries k ++ [fd]), ts := (fd, now) :: s.ts,
                  rel := (k, fd) :: s.rel }

def tsOf (ts : List (Nat × Int)) (fd : Nat) : Int := ((ts.find? (·.1 == fd)).map (·.2)).getD 0

/-- The eviction loop of `acquire`, over the deque from the back: close an
entry older than `idle_timeout_ms` and continue, else hand it out. Returns
the fd and the rest of the (reversed) deque.
mirrors flare/http/client_pool.mojo:226-238 @59bda50 -/
def popLoop (c : Cfg) (ts : List (Nat × Int)) (now : Int) : List Nat → Option Nat × List Nat
  | [] => (none, [])
  | fd :: rest =>
    if 0 < c.idleMs ∧ c.idleMs < now - tsOf ts fd then popLoop c ts now rest
    else (some fd, rest)

/-- `acquire(key)`.
mirrors flare/http/client_pool.mojo:203-242 @59bda50 -/
def acquire (c : Cfg) (s : St) (k : Key) (now : Int) : St × Option Nat :=
  if !hasKey s.entries k then (s, none)
  else
    match popLoop c s.ts now (getD s.entries k).reverse with
    | (some fd, rest) => ({ s with entries := put s.entries k rest.reverse }, some fd)
    | (none, _) => ({ s with entries := erase s.entries k }, none)

inductive Ev
  | release (k : Key) (fd : Nat) (now : Int)
  | acquire (k : Key) (now : Int)

def step (c : Cfg) (s : St) : Ev → St
  | .release k fd now => release c s k fd now
  | .acquire k now => (acquire c s k now).1

def lts (c : Cfg) : LTS St Ev := LTS.ofFn (· = init) (fun s e => some (step c s e))

/-! ## Association-list lemmas -/

def keys (e : Entries) : List Key := e.map Prod.fst

theorem mem_put {e : Entries} {k : Key} {v : List Nat} {p : Key × List Nat} :
    p ∈ put e k v ↔ (p ∈ e ∧ p.1 ≠ k) ∨ p = (k, v) := by
  simp [put, List.mem_filter]

theorem mem_erase {e : Entries} {k : Key} {p : Key × List Nat} :
    p ∈ erase e k → p ∈ e := by
  simp only [erase, List.mem_filter]; exact fun h => h.1

theorem keys_filter_nodup (e : Entries) (f : Key × List Nat → Bool) (h : (keys e).Nodup) :
    (keys (e.filter f)).Nodup :=
  (List.Sublist.map Prod.fst (List.filter_sublist)).nodup h

theorem nodup_put (e : Entries) (k : Key) (v : List Nat) (h : (keys e).Nodup) :
    (keys (put e k v)).Nodup := by
  unfold put keys
  rw [List.map_append, List.nodup_append]
  refine ⟨keys_filter_nodup e _ h, by simp, ?_⟩
  intro a ha b hb
  simp only [List.mem_map, List.mem_filter, bne_iff_ne, ne_eq] at ha
  simp only [List.map_cons, List.map_nil, List.mem_singleton] at hb
  obtain ⟨p, ⟨-, hp⟩, rfl⟩ := ha
  subst hb; exact hp

theorem getD_cons (k k' : Key) (v : List Nat) (e : Entries) :
    getD ((k', v) :: e) k = if k' = k then v else getD e k := by
  unfold getD
  by_cases h : k' = k <;> simp [h]

/-- With unique keys, the total splits into the key's deque and the rest. -/
theorem total_split (e : Entries) (k : Key) (h : (keys e).Nodup) :
    total e = total (erase e k) + (getD e k).length := by
  induction e with
  | nil => simp [total, erase, getD]
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
      have hg : getD e k' = [] := by
        unfold getD
        rw [List.find?_eq_none.2]
        intro q hq; simpa using hnot q hq
      simp only [erase, List.filter_cons, bne_self_eq_false, Bool.false_eq_true, if_false,
        if_true] at hf ⊢
      rw [hf]; simp [total]; omega
    · simp only [erase, List.filter_cons, bne_iff_ne, ne_eq, hk, not_false_eq_true, if_true,
        if_false] at ih' ⊢
      simp only [total, List.map_cons, List.sum_cons] at ih' ⊢
      omega

theorem total_put (e : Entries) (k : Key) (v : List Nat) (h : (keys e).Nodup) :
    total (put e k v) + (getD e k).length = total e + v.length := by
  rw [total_split e k h]
  simp [put, erase, total]
  omega

theorem total_erase_le (e : Entries) (k : Key) (h : (keys e).Nodup) :
    total (erase e k) ≤ total e := by
  rw [total_split e k h]; omega

theorem getD_mem (e : Entries) (k : Key) (x : Nat) (hx : x ∈ getD e k) :
    (k, getD e k) ∈ e := by
  unfold getD at hx ⊢
  cases hf : e.find? (fun p => p.1 == k) with
  | none => simp [hf] at hx
  | some p =>
    have hm := List.mem_of_find?_eq_some hf
    have hk : p.1 = k := by simpa using List.find?_some hf
    obtain ⟨k', v⟩ := p
    simp only at hk; subst hk
    simpa using hm

theorem popLoop_sub (c : Cfg) (ts : List (Nat × Int)) (now : Int) :
    ∀ (l : List Nat) (o : Option Nat) (rest : List Nat), popLoop c ts now l = (o, rest) →
      rest.length ≤ l.length ∧ (∀ x ∈ rest, x ∈ l) ∧ (∀ fd, o = some fd → fd ∈ l)
  | [], o, rest, h => by simp [popLoop] at h; obtain ⟨rfl, rfl⟩ := h; simp
  | fd :: l, o, rest, h => by
    simp only [popLoop] at h
    split at h
    · obtain ⟨h1, h2, h3⟩ := popLoop_sub c ts now l o rest h
      refine ⟨by simp; omega, fun x hx => List.mem_cons_of_mem _ (h2 x hx),
        fun f hf => List.mem_cons_of_mem _ (h3 f hf)⟩
    · simp only [Prod.mk.injEq] at h; obtain ⟨rfl, rfl⟩ := h
      refine ⟨by simp, fun x hx => List.mem_cons_of_mem _ hx, ?_⟩
      intro f hf; cases hf; exact List.mem_cons_self

/-! ## Invariant -/

structure Inv (c : Cfg) (s : St) : Prop where
  nodup : (keys s.entries).Nodup
  perHost : ∀ p ∈ s.entries, (p.2.length : Int) ≤ max c.perHost 0
  total : 0 < c.total → (total s.entries : Int) ≤ c.total
  origin : ∀ p ∈ s.entries, ∀ fd ∈ p.2, (p.1, fd) ∈ s.rel

theorem inv_init (c : Cfg) : Inv c init := ⟨by simp [init, keys], by simp [init],
  by intro hc; simp [init, total]; omega, by simp [init]⟩

theorem getD_len (c : Cfg) (s : St) (k : Key) (h : Inv c s) :
    ((getD s.entries k).length : Int) ≤ max c.perHost 0 := by
  by_cases hn : getD s.entries k = []
  · rw [hn]; simp; omega
  · obtain ⟨x, hx⟩ := List.exists_mem_of_ne_nil _ hn
    exact h.perHost _ (getD_mem _ _ x hx)

theorem inv_release (c : Cfg) (s : St) (k : Key) (fd : Nat) (now : Int) (h : Inv c s) :
    Inv c (release c s k fd now) := by
  unfold release
  split
  · exact h
  split
  · exact h
  rename_i hph htot
  have htp := total_put s.entries k
  split
  · rename_i hfull
    refine ⟨nodup_put _ _ _ h.nodup, ?_, ?_, ?_⟩
    · intro p hp
      rcases mem_put.1 hp with ⟨hp, -⟩ | rfl
      · exact h.perHost p hp
      · exact getD_len c s k h
    · intro hc; dsimp only
      have := htp (getD s.entries k) h.nodup
      have := h.total hc; omega
    · intro p hp fd' hfd
      rcases mem_put.1 hp with ⟨hp, -⟩ | rfl
      · exact h.origin p hp fd' hfd
      · exact h.origin _ (getD_mem _ _ fd' hfd) fd' hfd
  · rename_i hroom
    refine ⟨nodup_put _ _ _ h.nodup, ?_, ?_, ?_⟩
    · intro p hp
      rcases mem_put.1 hp with ⟨hp, -⟩ | rfl
      · exact h.perHost p hp
      · simp only [List.length_append, List.length_singleton]; omega
    · intro hc; dsimp only
      have := htp (getD s.entries k ++ [fd]) h.nodup
      simp only [List.length_append, List.length_singleton] at this
      simp only [not_and, Int.not_le] at htot
      have := htot hc; omega
    · intro p hp fd' hfd
      rcases mem_put.1 hp with ⟨hp, -⟩ | rfl
      · exact List.mem_cons_of_mem _ (h.origin p hp fd' hfd)
      · simp only [List.mem_append, List.mem_singleton] at hfd
        rcases hfd with hfd | rfl
        · exact List.mem_cons_of_mem _ (h.origin _ (getD_mem _ _ fd' hfd) fd' hfd)
        · exact List.mem_cons_self

theorem inv_acquire (c : Cfg) (s : St) (k : Key) (now : Int) (h : Inv c s) :
    Inv c (acquire c s k now).1 := by
  unfold acquire
  split
  · exact h
  split
  · rename_i fd rest hpop
    obtain ⟨hl, hm, -⟩ := popLoop_sub c s.ts now _ _ _ hpop
    simp only [List.length_reverse] at hl
    refine ⟨nodup_put _ _ _ h.nodup, ?_, ?_, ?_⟩
    · intro p hp
      rcases mem_put.1 hp with ⟨hp, -⟩ | rfl
      · exact h.perHost p hp
      · have := getD_len c s k h
        simp only [List.length_reverse]; omega
    · intro hc; dsimp only
      have := total_put s.entries k rest.reverse h.nodup
      simp only [List.length_reverse] at this
      have := h.total hc; omega
    · intro p hp fd' hfd
      rcases mem_put.1 hp with ⟨hp, -⟩ | rfl
      · exact h.origin p hp fd' hfd
      · have hin : fd' ∈ getD s.entries k := by
          simpa using hm fd' (by simpa using hfd)
        exact h.origin _ (getD_mem _ _ fd' hin) fd' hin
  · refine ⟨keys_filter_nodup _ _ h.nodup, fun p hp => h.perHost p (mem_erase hp), ?_,
      fun p hp => h.origin p (mem_erase hp)⟩
    intro hc; dsimp only
    have := total_erase_le s.entries k h.nodup
    have := h.total hc; omega

theorem inv_step (c : Cfg) (s : St) (e : Ev) (h : Inv c s) : Inv c (step c s e) := by
  cases e with
  | release k fd now => exact inv_release c s k fd now h
  | acquire k now => exact inv_acquire c s k now h

theorem inv_inductive (c : Cfg) : (lts c).Inductive (Inv c) where
  init := by intro s hs; rw [hs]; exact inv_init c
  step := by
    intro s e s' h hs
    simp only [lts, LTS.ofFn, Option.some.injEq] at hs
    rw [← hs]; exact inv_step c s e h

/-- **Caps.** In every reachable state each origin has at most
`max_idle_per_host` idle fds and, when the total cap is enabled, the pool
has at most `max_idle_total`. -/
theorem inv_reachable (c : Cfg) (s : St) (h : (lts c).Reachable s) : Inv c s :=
  (inv_inductive c).reachable s h

theorem caps (c : Cfg) (s : St) (h : (lts c).Reachable s) :
    (∀ p ∈ s.entries, (p.2.length : Int) ≤ max c.perHost 0) ∧
    (0 < c.total → (total s.entries : Int) ≤ c.total) :=
  ⟨(inv_reachable c s h).perHost, (inv_reachable c s h).total⟩

/-- **No cross-origin reuse.** `acquire key` returns only fds that the pool
accepted under the same `key`. -/
theorem acquire_same_origin (c : Cfg) (s : St) (k : Key) (now : Int) (fd : Nat)
    (h : Inv c s) (ha : (acquire c s k now).2 = some fd) : (k, fd) ∈ s.rel := by
  unfold acquire at ha
  split at ha
  · cases ha
  split at ha
  · rename_i fd' rest hpop
    simp only [Option.some.injEq] at ha; subst ha
    obtain ⟨-, -, ho⟩ := popLoop_sub c s.ts now _ _ _ hpop
    have hin : fd' ∈ getD s.entries k := by simpa using ho fd' rfl
    exact h.origin _ (getD_mem _ _ fd' hin) fd' hin
  · cases ha

end Flare.L4.ClientPool

import Flare.Core

/-!
# DnsCache: TTL-bounded resolution cache

`flare/dns/cache.mojo:51-142`. The `Dict[String, _CachedAddrs]` is an
association list in insertion order (Mojo's `Dict` iterates in insertion
order and `d[k] = v` on an existing key updates in place). Host keys are
abstracted to `Nat` (already normalised by `_key`); the address lists are
irrelevant to the properties here and are dropped. Times and the TTL are
Mojo `Int`, modelled as `Int64` with wrapping `+`.

The resolver call is abstracted as always succeeding (a failure raises
before `_store`, leaving the cache unchanged, and is not modelled). The
`oldest != ""` sentinel is modelled as `Option`.
-/
namespace Flare.L2.DnsCache

abbrev Dict := List (Nat × Int64)

structure Cache where
  byHost : Dict
  ttl : Int64
  maxEntries : Nat
  resolves : Nat
  hits : Nat

/-- `__init__` (clamps `max_entries` to at least 1).
mirrors flare/dns/cache.mojo:69-79 @59bda50 -/
def Cache.new (ttl : Int64) (maxEntries : Nat) : Cache :=
  ⟨[], ttl, if maxEntries > 0 then maxEntries else 1, 0, 0⟩

/-- Host normalisation: drop one trailing `.` (if the name is longer than
one byte) and ASCII-lowercase.
mirrors flare/dns/cache.mojo:81-94 @59bda50 -/
def key (b : Bytes) : Bytes :=
  let n := if b.length > 1 ∧ b.getLast? = some 46 then b.length - 1 else b.length
  (b.take n).map fun c => if 65 ≤ c ∧ c ≤ 90 then c + 32 else c

/-- `Example.COM.` and `example.com` share a key ... -/
theorem key_fqdn_case : key [69, 46, 67, 46] = key [101, 46, 99] := by decide

/-- ... but only one trailing dot is stripped, so `key` is not idempotent:
`a..` and `a.` get different keys (two cache entries for names the
resolver treats alike or rejects; harmless). -/
theorem key_not_idempotent : key [97, 46, 46] = [97, 46] ∧ key (key [97, 46, 46]) = [97] := by
  decide

/-- `Dict.__getitem__` -/
def lookup : Dict → Nat → Option Int64
  | [], _ => none
  | (k', e) :: rest, k => if k' = k then some e else lookup rest k

/-- `Dict.__setitem__`: update in place, else append -/
def setKey : Dict → Nat → Int64 → Dict
  | [], k, v => [(k, v)]
  | (k', e) :: rest, k, v => if k' = k then (k, v) :: rest else (k', e) :: setKey rest k v

/-- the scan's comparison: flare's strict `<` (`le = false`) or `<=` -/
def better (le : Bool) (e best : Int64) : Bool :=
  if le then decide (e ≤ best) else decide (e < best)

/-- The eviction scan over live entries, starting from `best = Int.MAX`;
`le = false` is flare's strict `<`, `le = true` the fixed `<=`.
mirrors flare/dns/cache.mojo:99-106 @59bda50 -/
def oldestGo (le : Bool) (now : Int64) : Dict → Int64 → Option Nat → Option Nat
  | [], _, o => o
  | (k, e) :: rest, best, o =>
    if e ≤ now then oldestGo le now rest best o
    else if better le e best then oldestGo le now rest e (some k)
    else oldestGo le now rest best o

/-- Make room for a new key (the `if key not in ... and len >= max` block).
mirrors flare/dns/cache.mojo:96-116 @59bda50 -/
def evict (le : Bool) (c : Cache) (k : Nat) (now : Int64) : Dict :=
  if (lookup c.byHost k).isNone ∧ c.byHost.length ≥ c.maxEntries then
    let oldest := oldestGo le now c.byHost Int64.maxValue none
    let L1 := c.byHost.filter (fun p => !(decide (p.2 ≤ now)))
    match oldest with
    | some o => if L1.length ≥ c.maxEntries then L1.filter (fun p => p.1 != o) else L1
    | none => L1
  else c.byHost

/-- mirrors flare/dns/cache.mojo:96-119 @59bda50 -/
def store (c : Cache) (k : Nat) (now : Int64) : Cache :=
  { c with byHost := setKey (evict false c k now) k (now + c.ttl) }

/-- `now + ttl`, saturating at `Int.MAX` (valid for `now ≥ 0`). -/
def satAdd (now ttl : Int64) : Int64 :=
  if ttl > Int64.maxValue - now then Int64.maxValue else now + ttl

/-- The minimal fix: saturate the expiry and use `<=` in the eviction scan. -/
def storeFixed (c : Cache) (k : Nat) (now : Int64) : Cache :=
  { c with byHost := setKey (evict true c k now) k (satAdd now c.ttl) }

/-- `resolve`: serve a fresh entry, else resolve and `_store`. Returns
whether the lookup was a hit.
mirrors flare/dns/cache.mojo:121-142 @59bda50 -/
def resolveWith (st : Cache → Nat → Int64 → Cache) (c : Cache) (k : Nat) (now : Int64) :
    Cache × Bool :=
  match lookup c.byHost k with
  | some e =>
    if now < e then ({ c with hits := c.hits + 1 }, true)
    else ({ st c k now with resolves := c.resolves + 1 }, false)
  | none => ({ st c k now with resolves := c.resolves + 1 }, false)

def resolve := resolveWith store
def resolveFixed := resolveWith storeFixed

/-! ## Lemmas -/

theorem lookup_setKey (L : Dict) (k : Nat) (v : Int64) : lookup (setKey L k v) k = some v := by
  induction L with
  | nil => simp [setKey, lookup]
  | cons p rest ih =>
    obtain ⟨k', e⟩ := p
    simp only [setKey]
    split
    · simp [lookup]
    · rename_i hne; simp only [lookup]; rw [if_neg hne]; exact ih

theorem length_setKey_le (L : Dict) (k : Nat) (v : Int64) : (setKey L k v).length ≤ L.length + 1 := by
  induction L with
  | nil => simp [setKey]
  | cons p rest ih =>
    obtain ⟨k', e⟩ := p
    simp only [setKey]; split <;> simp <;> omega

theorem length_setKey_of_mem (L : Dict) (k : Nat) (v : Int64) (h : (lookup L k).isSome) :
    (setKey L k v).length = L.length := by
  induction L with
  | nil => simp [lookup] at h
  | cons p rest ih =>
    obtain ⟨k', e⟩ := p
    simp only [setKey]
    split
    · simp
    · rename_i hne; simp only [lookup] at h; rw [if_neg hne] at h; simp [ih h]

theorem length_filter_lt {α : Type} (p : α → Bool) (l : List α) (x : α) (hx : x ∈ l) (hp : p x = false) :
    (l.filter p).length < l.length := by
  induction l with
  | nil => cases hx
  | cons y ys ih =>
    rcases List.mem_cons.1 hx with rfl | hx
    · rw [List.filter_cons_of_neg (by simp [hp])]
      have := List.length_filter_le p ys; simp only [List.length_cons]; omega
    · simp only [List.filter_cons]
      have := ih hx
      split <;> simp only [List.length_cons] <;> omega

theorem le_maxValue (x : Int64) : x ≤ Int64.maxValue := by
  rw [Int64.le_iff_toInt_le]; exact Int64.toInt_le x

/-- the scan returns its accumulator or the key of a live entry -/
theorem oldestGo_mem (le : Bool) (now : Int64) :
    ∀ (L : Dict) best acc, oldestGo le now L best acc = acc ∨
      ∃ o e, oldestGo le now L best acc = some o ∧ (o, e) ∈ L ∧ ¬ e ≤ now
  | [], _, _ => Or.inl rfl
  | (k, e) :: rest, best, acc => by
    simp only [oldestGo]
    split
    · rcases oldestGo_mem le now rest best acc with h | ⟨o, e', h1, h2, h3⟩
      · exact Or.inl h
      · exact Or.inr ⟨o, e', h1, List.mem_cons_of_mem _ h2, h3⟩
    · rename_i hlive
      split
      · rcases oldestGo_mem le now rest e (some k) with h | ⟨o, e', h1, h2, h3⟩
        · exact Or.inr ⟨k, e, h, List.mem_cons_self, hlive⟩
        · exact Or.inr ⟨o, e', h1, List.mem_cons_of_mem _ h2, h3⟩
      · rcases oldestGo_mem le now rest best acc with h | ⟨o, e', h1, h2, h3⟩
        · exact Or.inl h
        · exact Or.inr ⟨o, e', h1, List.mem_cons_of_mem _ h2, h3⟩

/-- with `<=` the scan finds a live entry whenever one is at most `best` -/
theorem oldestGo_le_finds (now : Int64) :
    ∀ (L : Dict) best acc, (∃ k e, (k, e) ∈ L ∧ ¬ e ≤ now ∧ e ≤ best) →
      ∃ o e, oldestGo true now L best acc = some o ∧ (o, e) ∈ L ∧ ¬ e ≤ now
  | [], _, _, ⟨_, _, h, _⟩ => by cases h
  | (k, e) :: rest, best, acc, ⟨k', e', hm, hl, hb⟩ => by
    simp only [oldestGo]
    split
    · rename_i hdead
      rcases List.mem_cons.1 hm with heq | hm
      · cases heq; exact absurd hdead hl
      · obtain ⟨o, e'', h1, h2, h3⟩ := oldestGo_le_finds now rest best acc ⟨k', e', hm, hl, hb⟩
        exact ⟨o, e'', h1, List.mem_cons_of_mem _ h2, h3⟩
    · rename_i hlive
      split
      · rcases oldestGo_mem true now rest e (some k) with h | ⟨o, e'', h1, h2, h3⟩
        · exact ⟨k, e, h, List.mem_cons_self, hlive⟩
        · exact ⟨o, e'', h1, List.mem_cons_of_mem _ h2, h3⟩
      · rename_i hnb
        rcases List.mem_cons.1 hm with heq | hm
        · cases heq; exact absurd hb (by simpa [better] using hnb)
        · obtain ⟨o, e'', h1, h2, h3⟩ := oldestGo_le_finds now rest best acc ⟨k', e', hm, hl, hb⟩
          exact ⟨o, e'', h1, List.mem_cons_of_mem _ h2, h3⟩

/-! ## The fixed store: size bound and TTL -/

/-- **Size bound (fix)**: `storeFixed` keeps `size() ≤ max_entries`. -/
theorem storeFixed_size_bound (c : Cache) (k : Nat) (now : Int64) (hmax : 1 ≤ c.maxEntries)
    (h : c.byHost.length ≤ c.maxEntries) : (storeFixed c k now).byHost.length ≤ c.maxEntries := by
  unfold storeFixed evict
  dsimp only
  split
  · rename_i hfull
    obtain ⟨habs, hge⟩ := hfull
    have hL1 := List.length_filter_le (fun p : Nat × Int64 => !(decide (p.2 ≤ now))) c.byHost
    generalize hL1def : c.byHost.filter (fun p => !(decide (p.2 ≤ now))) = L1 at hL1
    split
    · rename_i o ho
      split
      · rename_i hbig
        -- L1 is non-empty, so it holds a live entry and the scan found one
        have hne : L1 ≠ [] := by intro h0; rw [h0] at hbig; simp at hbig; omega
        obtain ⟨⟨k1, e1⟩, hmem⟩ := List.exists_mem_of_ne_nil L1 hne
        have hmem' : (k1, e1) ∈ c.byHost ∧ ¬ e1 ≤ now := by
          rw [← hL1def, List.mem_filter] at hmem; simpa using hmem
        obtain ⟨o', e', ho', hmo, hlo⟩ := oldestGo_le_finds now c.byHost Int64.maxValue none
          ⟨k1, e1, hmem'.1, hmem'.2, le_maxValue e1⟩
        rw [ho] at ho'; cases ho'
        have hin : (o, e') ∈ L1 := by
          rw [← hL1def, List.mem_filter]; exact ⟨hmo, by simpa using hlo⟩
        have := length_filter_lt (fun p : Nat × Int64 => p.1 != o) L1 (o, e') hin (by simp)
        have := length_setKey_le (L1.filter fun p => p.1 != o) k (satAdd now c.ttl)
        omega
      · rename_i hsmall
        have := length_setKey_le L1 k (satAdd now c.ttl); omega
    · have := length_setKey_le L1 k (satAdd now c.ttl)
      rename_i hnone
      -- no live entry was found, so every entry was expired and L1 is empty
      have hL1e : L1 = [] := by
        rw [← hL1def]; rw [List.filter_eq_nil_iff]
        intro p hp hlive
        obtain ⟨o', e', ho', _, _⟩ := oldestGo_le_finds now c.byHost Int64.maxValue none
          ⟨p.1, p.2, hp, by simpa using hlive, le_maxValue p.2⟩
        rw [hnone] at ho'; cases ho'
      rw [hL1e]; simp [setKey]; omega
  · rename_i hnot
    by_cases hk : (lookup c.byHost k).isSome
    · rw [length_setKey_of_mem _ _ _ hk]; exact h
    · have := length_setKey_le c.byHost k (satAdd now c.ttl)
      have : c.byHost.length < c.maxEntries := by
        rcases Nat.lt_or_ge c.byHost.length c.maxEntries with h1 | h1
        · exact h1
        · exact absurd ⟨by simpa using hk, h1⟩ hnot
      omega

/-- the saturating expiry is the mathematical `now + ttl`, capped at `Int.MAX` -/
theorem satAdd_toInt (now ttl : Int64) (hn : 0 ≤ now.toInt) :
    (satAdd now ttl).toInt = min (now.toInt + ttl.toInt) Int64.maxValue.toInt := by
  unfold satAdd
  have hmax : Int64.maxValue.toInt = 2 ^ 63 - 1 := by decide
  have hlo := Int64.le_toInt ttl
  have hhi := Int64.toInt_le ttl
  have hsub : (Int64.maxValue - now).toInt = Int64.maxValue.toInt - now.toInt := by
    rw [Int64.toInt_sub]; rw [hmax]
    have := Int64.toInt_le now; rw [hmax] at this
    exact Int.bmod_eq_of_le (by omega) (by omega)
  split
  · rename_i hgt
    rw [gt_iff_lt, Int64.lt_iff_toInt_lt, hsub] at hgt
    omega
  · rename_i hle
    rw [gt_iff_lt, Int64.lt_iff_toInt_lt, hsub] at hle
    rw [Int64.toInt_add]
    rw [Int.bmod_eq_of_le (by simp only [Int.natCast_pow]; omega) (by simp only [Int.natCast_pow]; omega)]
    omega

/-- **TTL (fix)**: after a fixed store at `now ≥ 0`, a lookup at any later
`now'` strictly inside the TTL window (and below `Int.MAX`) is a hit. -/
theorem storeFixed_hits_within_ttl (c : Cache) (k : Nat) (now now' : Int64)
    (hn : 0 ≤ now.toInt) (_h1 : now.toInt ≤ now'.toInt)
    (h2 : now'.toInt < now.toInt + c.ttl.toInt) (h3 : now'.toInt < Int64.maxValue.toInt) :
    (resolveFixed (storeFixed c k now) k now').2 = true := by
  unfold resolveFixed resolveWith storeFixed
  dsimp only
  rw [lookup_setKey]
  dsimp only
  rw [if_pos (by rw [Int64.lt_iff_toInt_lt, satAdd_toInt now c.ttl hn]; omega)]

/-! ## flare's store: the wrapping expiry -/

/-- With `ttl = Int.MAX` and any clock reading `now ≥ 1`, the stored expiry
`now + ttl` wraps negative, so no lookup at a non-negative time is ever a
hit. -/
theorem huge_ttl_expiry_wraps (now now' : Int64) (hn : 1 ≤ now.toInt) (hn' : 0 ≤ now'.toInt) :
    ¬ now' < now + Int64.maxValue := by
  rw [Int64.lt_iff_toInt_lt, Int64.toInt_add]
  have hmax : Int64.maxValue.toInt = 2 ^ 63 - 1 := by decide
  have := Int64.toInt_le now; rw [hmax] at this ⊢
  rw [Int.bmod_def]
  have : (now.toInt + (2 ^ 63 - 1)) % (2 ^ 64 : Nat) = now.toInt + (2 ^ 63 - 1) := by
    apply Int.emod_eq_of_lt <;> omega
  rw [this]
  split <;> omega

theorem resolve_store_miss (c : Cache) (k : Nat) (now now' : Int64)
    (hn : 1 ≤ now.toInt) (hn' : 0 ≤ now'.toInt) (httl : c.ttl = Int64.maxValue) :
    (resolve (store c k now) k now').2 = false := by
  unfold resolve resolveWith store
  dsimp only
  rw [lookup_setKey]
  dsimp only
  rw [httl, if_neg (huge_ttl_expiry_wraps now now' hn hn')]

end Flare.L2.DnsCache

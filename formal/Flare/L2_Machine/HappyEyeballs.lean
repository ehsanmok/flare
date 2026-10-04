import Flare.Core

/-!
# Happy-eyeballs address ordering (RFC 8305 §4)

Model of `order_happy_eyeballs` in `flare/dns/async_resolve.mojo:154-177`.
Addresses are an abstract type `α` with a family test `isV6` (`IpAddr.is_v6`).

flare's docstring: "Interleaves the IPv6 and IPv4 results (`v6[0], v4[0],
v6[1], v4[1], ...`) preserving each family's relative order". RFC 8305 §4
(with a First Address Family Count of 1) asks for the same interleaving,
but starting with the family of the *first address of the sorted input*
("Whichever address family is first in the list should be followed by an
address of the other address family"). flare always starts with IPv6.

Proved here:
* `order_eq`: the Mojo loops compute `inter (v6s) (v4s)`;
* `order_perm`: the result is a permutation of the input;
* `order_filter_v6` / `order_filter_v4`: each family keeps its order;
* `order_get_even` / `order_get_odd`: strict alternation v6, v4, v6, ... over
  the first `2 * min n6 n4` positions;
* `orderFixed_head`: the fix keeps the input's first address first, which is
  the clause flare violates (NET-10).
-/
namespace Flare.L2.HappyEyeballs

variable {α : Type} (isV6 : α → Bool)

/-- the reference interleaving: `a0, b0, a1, b1, ...`, then the rest of the
longer list -/
def inter : List α → List α → List α
  | a :: as, b :: bs => a :: b :: inter as bs
  | [], bs => bs
  | as, [] => as

@[simp] theorem inter_nil_left (bs : List α) : inter [] bs = bs := by cases bs <;> rfl
@[simp] theorem inter_nil_right (as : List α) : inter as [] = as := by cases as <;> rfl
@[simp] theorem inter_cons_cons (a b : α) (as bs : List α) :
    inter (a :: as) (b :: bs) = a :: b :: inter as bs := rfl

/-- one iteration of the family split loop.
mirrors flare/dns/async_resolve.mojo:162-168 @59bda50 -/
def splitStep (p : List α × List α) (a : α) : List α × List α :=
  if isV6 a then (p.1 ++ [a], p.2) else (p.1, p.2 ++ [a])

/-- the interleaving loop (`while i < len(v6) or i < len(v4)`).
mirrors flare/dns/async_resolve.mojo:169-177 @59bda50 -/
def loop (v6 v4 : List α) (out : List α) (i : Nat) : List α :=
  if i < v6.length ∨ i < v4.length then
    loop v6 v4 (out ++ v6[i]?.toList ++ v4[i]?.toList) (i + 1)
  else out
termination_by v6.length + v4.length - i

/-- mirrors flare/dns/async_resolve.mojo:154-177 @59bda50 -/
def order (addrs : List α) : List α :=
  let p := addrs.foldl (splitStep isV6) ([], [])
  loop p.1 p.2 [] 0

theorem split_fold (addrs : List α) : ∀ A B : List α,
    addrs.foldl (splitStep isV6) (A, B) =
      (A ++ addrs.filter isV6, B ++ addrs.filter (fun a => !isV6 a)) := by
  induction addrs with
  | nil => intro A B; simp
  | cons a as ih =>
    intro A B
    rw [List.foldl_cons]
    cases h : isV6 a
    · rw [show splitStep isV6 (A, B) a = (A, B ++ [a]) by simp [splitStep, h], ih]
      simp [h]
    · rw [show splitStep isV6 (A, B) a = (A ++ [a], B) by simp [splitStep, h], ih]
      simp [h]

theorem drop_split (v : List α) (i : Nat) : v.drop i = v[i]?.toList ++ v.drop (i + 1) := by
  by_cases h : i < v.length
  · rw [List.getElem?_eq_getElem h, List.drop_eq_getElem_cons h]; rfl
  · rw [List.getElem?_eq_none (by omega), List.drop_eq_nil_of_le (by omega),
      List.drop_eq_nil_of_le (by omega)]; rfl

theorem loop_eq (v6 v4 : List α) : ∀ k i out, v6.length + v4.length - i = k →
    loop v6 v4 out i = out ++ inter (v6.drop i) (v4.drop i) := by
  intro k
  induction k with
  | zero =>
    intro i out hk
    unfold loop
    rw [if_neg (by omega), List.drop_eq_nil_of_le (by omega), List.drop_eq_nil_of_le (by omega)]
    simp
  | succ k ih =>
    intro i out hk
    unfold loop
    by_cases hc : i < v6.length ∨ i < v4.length
    · rw [if_pos hc, ih (i + 1) _ (by omega)]
      by_cases h6 : i < v6.length
      · by_cases h4 : i < v4.length
        · rw [List.getElem?_eq_getElem h6, List.getElem?_eq_getElem h4,
            List.drop_eq_getElem_cons h6, List.drop_eq_getElem_cons h4, inter_cons_cons]
          simp only [Option.toList_some, List.append_assoc,
            List.cons_append, List.nil_append]
        · have e4 : v4.drop i = [] := List.drop_eq_nil_of_le (by omega)
          have e4' : v4.drop (i + 1) = [] := List.drop_eq_nil_of_le (by omega)
          rw [List.getElem?_eq_getElem h6, List.getElem?_eq_none (by omega),
            List.drop_eq_getElem_cons h6, e4, e4', inter_nil_right, inter_nil_right]
          simp only [Option.toList_some, Option.toList_none, List.append_nil, List.append_assoc,
            List.singleton_append]
      · have e6 : v6.drop i = [] := List.drop_eq_nil_of_le (by omega)
        have e6' : v6.drop (i + 1) = [] := List.drop_eq_nil_of_le (by omega)
        have h4 : i < v4.length := by omega
        rw [List.getElem?_eq_none (by omega), List.getElem?_eq_getElem h4,
          List.drop_eq_getElem_cons h4, e6, e6', inter_nil_left, inter_nil_left]
        simp only [Option.toList_some, Option.toList_none, List.nil_append, List.append_assoc,
          List.singleton_append]
    · rw [if_neg hc, List.drop_eq_nil_of_le (by omega), List.drop_eq_nil_of_le (by omega)]
      simp

/-- **The Mojo loops compute the reference interleaving** of the IPv6
sublist and the IPv4 sublist. -/
theorem order_eq (addrs : List α) :
    order isV6 addrs = inter (addrs.filter isV6) (addrs.filter (fun a => !isV6 a)) := by
  unfold order
  rw [split_fold]
  dsimp only
  rw [loop_eq _ _ _ 0 [] rfl]
  simp

theorem inter_perm : ∀ (A B : List α), (inter A B).Perm (A ++ B)
  | a :: as, b :: bs => by
    rw [inter_cons_cons]
    refine List.Perm.cons a ?_
    have := (inter_perm as bs).cons b
    exact this.trans (List.perm_middle).symm
  | [], bs => by simp
  | _ :: _, [] => by simp

/-- **Permutation**: nothing is lost or duplicated. -/
theorem order_perm (addrs : List α) : (order isV6 addrs).Perm addrs := by
  rw [order_eq]
  exact (inter_perm _ _).trans (List.filter_append_perm _ _)

theorem filter_inter (p : α → Bool) : ∀ (A B : List α),
    (∀ a ∈ A, p a = true) → (∀ b ∈ B, p b = false) → (inter A B).filter p = A
  | a :: as, b :: bs, hA, hB => by
    rw [inter_cons_cons, List.filter_cons_of_pos (hA a List.mem_cons_self),
      List.filter_cons_of_neg (by simp [hB b List.mem_cons_self]),
      filter_inter p as bs (fun x hx => hA x (List.mem_cons_of_mem _ hx))
        (fun x hx => hB x (List.mem_cons_of_mem _ hx))]
  | [], bs, _, hB => by
    rw [inter_nil_left, List.filter_eq_nil_iff]; intro b hb; simp [hB b hb]
  | as@(_ :: _), [], hA, _ => by
    rw [inter_nil_right, List.filter_eq_self]; exact hA

/-- **IPv6 order preserved.** -/
theorem order_filter_v6 (addrs : List α) :
    (order isV6 addrs).filter isV6 = addrs.filter isV6 := by
  rw [order_eq]
  exact filter_inter isV6 _ _ (fun a ha => (List.mem_filter.1 ha).2)
    (fun b hb => by have := (List.mem_filter.1 hb).2; simpa using this)

/-- **IPv4 order preserved.** -/
theorem order_filter_v4 (addrs : List α) :
    (order isV6 addrs).filter (fun a => !isV6 a) = addrs.filter (fun a => !isV6 a) := by
  rw [order_eq]
  have key : ∀ (A B : List α), (∀ a ∈ A, isV6 a = true) → (∀ b ∈ B, isV6 b = false) →
      (inter A B).filter (fun a => !isV6 a) = B := by
    intro A B
    induction A generalizing B with
    | nil => intro _ hB; rw [inter_nil_left, List.filter_eq_self]; intro b hb; simp [hB b hb]
    | cons a as ih =>
      intro hA hB
      cases B with
      | nil =>
        rw [inter_nil_right, List.filter_eq_nil_iff]; intro x hx; simp [hA x hx]
      | cons b bs =>
        rw [inter_cons_cons, List.filter_cons_of_neg (by simp [hA a List.mem_cons_self]),
          List.filter_cons_of_pos (by simp [hB b List.mem_cons_self]),
          ih bs (fun x hx => hA x (List.mem_cons_of_mem _ hx))
            (fun x hx => hB x (List.mem_cons_of_mem _ hx))]
  exact key _ _ (fun a ha => (List.mem_filter.1 ha).2)
    (fun b hb => by have := (List.mem_filter.1 hb).2; simpa using this)

theorem inter_get_even : ∀ (A B : List α) (i : Nat), i < A.length → i < B.length →
    (inter A B)[2 * i]? = A[i]?
  | a :: as, b :: bs, 0, _, _ => rfl
  | a :: as, b :: bs, i + 1, h1, h2 => by
    rw [inter_cons_cons, show 2 * (i + 1) = (2 * i) + 1 + 1 by omega]
    simp only [List.getElem?_cons_succ]
    exact inter_get_even as bs i (by simp at h1; omega) (by simp at h2; omega)
  | [], _, _, h, _ => by simp at h
  | _ :: _, [], _, _, h => by simp at h

theorem inter_get_odd : ∀ (A B : List α) (i : Nat), i < A.length → i < B.length →
    (inter A B)[2 * i + 1]? = B[i]?
  | a :: as, b :: bs, 0, _, _ => rfl
  | a :: as, b :: bs, i + 1, h1, h2 => by
    rw [inter_cons_cons, show 2 * (i + 1) + 1 = (2 * i + 1) + 1 + 1 by omega]
    simp only [List.getElem?_cons_succ]
    exact inter_get_odd as bs i (by simp at h1; omega) (by simp at h2; omega)
  | [], _, _, h, _ => by simp at h
  | _ :: _, [], _, _, h => by simp at h

/-- **Alternation (even positions).** While both families have addresses
left, position `2i` is the `i`-th IPv6 address. -/
theorem order_get_even (addrs : List α) (i : Nat)
    (h6 : i < (addrs.filter isV6).length) (h4 : i < (addrs.filter (fun a => !isV6 a)).length) :
    (order isV6 addrs)[2 * i]? = (addrs.filter isV6)[i]? := by
  rw [order_eq]; exact inter_get_even _ _ i h6 h4

/-- **Alternation (odd positions).** Position `2i+1` is the `i`-th IPv4
address. -/
theorem order_get_odd (addrs : List α) (i : Nat)
    (h6 : i < (addrs.filter isV6).length) (h4 : i < (addrs.filter (fun a => !isV6 a)).length) :
    (order isV6 addrs)[2 * i + 1]? = (addrs.filter (fun a => !isV6 a))[i]? := by
  rw [order_eq]; exact inter_get_odd _ _ i h6 h4

/-- flare's first attempt is always an IPv6 address when there is one,
whatever family the (RFC 6724-sorted) input put first. -/
theorem order_head (addrs : List α) :
    (order isV6 addrs).head? =
      match addrs.filter isV6 with
      | a :: _ => some a
      | [] => (addrs.filter (fun a => !isV6 a)).head? := by
  rw [order_eq]
  cases h : addrs.filter isV6 with
  | nil => simp
  | cons a as =>
    cases addrs.filter (fun a => !isV6 a) <;> rfl

/-- The fix (NET-10): interleave starting with the family of the first
input address, as RFC 8305 §4 asks. -/
def orderFixed (addrs : List α) : List α :=
  match addrs with
  | [] => []
  | a :: _ =>
    if isV6 a then inter (addrs.filter isV6) (addrs.filter (fun a => !isV6 a))
    else inter (addrs.filter (fun a => !isV6 a)) (addrs.filter isV6)

/-- the fixed order keeps the preferred (first) address first -/
theorem orderFixed_head (a : α) (rest : List α) :
    (orderFixed isV6 (a :: rest)).head? = some a := by
  have hd : ∀ (A B : List α), (inter (a :: A) B).head? = some a := by
    intro A B; cases B <;> rfl
  unfold orderFixed
  dsimp only
  cases h : isV6 a
  · rw [if_neg (by simp), List.filter_cons_of_pos (by simp [h])]; exact hd _ _
  · rw [if_pos rfl, List.filter_cons_of_pos h]; exact hd _ _

/-- the fixed order is still a permutation -/
theorem orderFixed_perm (addrs : List α) : (orderFixed isV6 addrs).Perm addrs := by
  unfold orderFixed
  cases addrs with
  | nil => exact List.Perm.refl _
  | cons a rest =>
    dsimp only
    split
    · exact (inter_perm _ _).trans (List.filter_append_perm _ _)
    · exact (inter_perm _ _).trans (List.perm_append_comm.trans (List.filter_append_perm _ _))

end Flare.L2.HappyEyeballs

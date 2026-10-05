import Flare.L4_App.Redirect

/-!
# APP-45: relative `Location` references are not resolved per RFC 3986 §5.2

flare/http/redirect_policy.mojo:173-185 @59bda50, pre-fix. Every reference that does
not start with `/` or a scheme is appended to the directory of the current
request target. Two consequences:

* a query-only reference (`?page=2`) drops the last path segment:
  against `http://h/list/items` it gives `http://h:80/list/?page=2`
  (a different resource) instead of `http://h:80/list/items?page=2`;
* dot segments are kept verbatim: `../g` against `http://h/b/c/d` gives
  `http://h:80/b/c/../g` instead of `http://h:80/b/g`.

Spec: RFC 3986 §5.2.2 (`T.path = Base.path` when `R.path` is empty;
otherwise merge then remove_dot_segments) and the §5.4.1 examples
(`?y` → `http://a/b/c/d;p?y`, `../g` → `http://a/b/g`).

Status: resolved. `_resolve_location` handles `?` and `#` references (the
whole base path is kept, the base query is replaced), merges a relative path
with the base *path*'s directory (a `/` in the base query is no longer a
separator), and passes the path through `_remove_dot_segments`
(flare/http/redirect_policy.mojo:154-250); the shipped model is
`Flare.L4.Redirect.resolveLocation` (with `removeDotSegments`). The
counterexamples below are about the explicitly pre-fix `resolveLocationOld`.
Regression tests: tests/http/test_redirect_policy.mojo::
test_query_only_reference_keeps_the_base_path,
test_dot_segments_are_removed_from_a_relative_reference,
test_dot_segments_are_removed_from_an_origin_relative_reference,
test_merge_uses_the_base_path_not_its_query and
test_rfc3986_section_5_4_1_normal_examples (the RFC's normal examples).
-/
namespace Flare.Bugs.APP_45

open Flare.L4.Redirect

def base : Str := "http://h/list/items".toList

/-- Counterexample 1 (pre-fix `resolveLocationOld`): the query-only
reference loses `items`. -/
theorem query_only_reference_wrong :
    resolveLocationOld base "?page=2".toList = some "http://h:80/list/?page=2".toList ∧
    resolveLocationOld base "?page=2".toList ≠ some "http://h:80/list/items?page=2".toList := by
  native_decide

/-- Counterexample 2 (pre-fix): dot segments survive resolution. -/
theorem dot_segments_kept :
    resolveLocationOld "http://h/b/c/d".toList "../g".toList = some "http://h:80/b/c/../g".toList ∧
    resolveLocationOld "http://h/b/c/d".toList "../g".toList ≠ some "http://h:80/b/g".toList := by
  native_decide

/-- **Fix meets spec (query-only)**: the shipped resolver meets RFC 3986
§5.2.2 for every query-only reference on every base that parses: scheme,
authority and path come from the base, the query from the reference (and the
base's query and fragment are dropped). -/
theorem resolveLocation_query_only (b q : Str) (u : Url) (hb : parse b = some u) :
    resolveLocation b ('?' :: q) = some (originStr u ++ u.path ++ '?' :: q) := by
  simp [resolveLocation, hb]

/-- **Fix meets spec (dot segments)**: the stack walk never leaves a `.` or
`..` segment in its output, whatever it starts from (as long as the stack
holds none). -/
theorem rdsAux_no_dots (segs st : List Str)
    (h : ∀ x ∈ st, x ≠ ".".toList ∧ x ≠ "..".toList) :
    ∀ x ∈ rdsAux segs st, x ≠ ".".toList ∧ x ≠ "..".toList := by
  induction segs generalizing st with
  | nil => simpa [rdsAux] using h
  | cons s rest ih =>
    cases rest with
    | nil =>
      intro x hx
      simp only [rdsAux] at hx
      by_cases h1 : s = ".".toList
      · rw [if_pos h1] at hx
        rcases List.mem_cons.mp hx with hx | hx
        · subst hx; simp
        · exact h x hx
      · rw [if_neg h1] at hx
        by_cases h2 : s = "..".toList
        · rw [if_pos h2] at hx
          rcases List.mem_cons.mp hx with hx | hx
          · subst hx; simp
          · exact h x (List.mem_of_mem_tail hx)
        · rw [if_neg h2] at hx
          rcases List.mem_cons.mp hx with hx | hx
          · subst hx; exact ⟨h1, h2⟩
          · exact h x hx
    | cons t rest' =>
      simp only [rdsAux]
      apply ih
      by_cases h1 : s = ".".toList
      · rw [if_pos h1]; exact h
      · rw [if_neg h1]
        by_cases h2 : s = "..".toList
        · rw [if_pos h2]
          intro x hx
          exact h x (List.mem_of_mem_tail hx)
        · rw [if_neg h2]
          intro x hx
          rcases List.mem_cons.mp hx with hx | hx
          · subst hx; exact ⟨h1, h2⟩
          · exact h x hx

/-- RFC 3986 §5.4.1 normal examples, against base `http://a/b/c/d;p?q`. -/
def rfcBase : Str := "http://a/b/c/d;p?q".toList

theorem rfc_5_4_1_examples :
    resolveLocation rfcBase "g".toList = some "http://a:80/b/c/g".toList ∧
    resolveLocation rfcBase "./g".toList = some "http://a:80/b/c/g".toList ∧
    resolveLocation rfcBase "g/".toList = some "http://a:80/b/c/g/".toList ∧
    resolveLocation rfcBase "/g".toList = some "http://a:80/g".toList ∧
    resolveLocation rfcBase "?y".toList = some "http://a:80/b/c/d;p?y".toList ∧
    resolveLocation rfcBase "g?y".toList = some "http://a:80/b/c/g?y".toList ∧
    resolveLocation rfcBase ";x".toList = some "http://a:80/b/c/;x".toList ∧
    resolveLocation rfcBase ".".toList = some "http://a:80/b/c/".toList ∧
    resolveLocation rfcBase "./".toList = some "http://a:80/b/c/".toList ∧
    resolveLocation rfcBase "..".toList = some "http://a:80/b/".toList ∧
    resolveLocation rfcBase "../".toList = some "http://a:80/b/".toList ∧
    resolveLocation rfcBase "../g".toList = some "http://a:80/b/g".toList ∧
    resolveLocation rfcBase "../..".toList = some "http://a:80/".toList ∧
    resolveLocation rfcBase "../../g".toList = some "http://a:80/g".toList ∧
    resolveLocation rfcBase "../../../g".toList = some "http://a:80/g".toList ∧
    resolveLocation rfcBase "/./g".toList = some "http://a:80/g".toList ∧
    resolveLocation rfcBase "/../g".toList = some "http://a:80/g".toList ∧
    resolveLocation rfcBase "./../g".toList = some "http://a:80/b/g".toList ∧
    resolveLocation rfcBase "./g/.".toList = some "http://a:80/b/c/g/".toList ∧
    resolveLocation rfcBase "g/./h".toList = some "http://a:80/b/c/g/h".toList ∧
    resolveLocation rfcBase "g/../h".toList = some "http://a:80/b/c/h".toList ∧
    resolveLocation rfcBase "g;x=1/../y".toList = some "http://a:80/b/c/y".toList := by
  native_decide

theorem fixed_on_example :
    resolveLocation base "?page=2".toList = some "http://h:80/list/items?page=2".toList ∧
    resolveLocation "http://h/b/c/d".toList "../g".toList = some "http://h:80/b/g".toList := by
  native_decide

end Flare.Bugs.APP_45

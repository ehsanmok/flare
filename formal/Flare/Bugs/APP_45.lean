import Flare.L4_App.Redirect

/-!
# APP-45: relative `Location` references are not resolved per RFC 3986 §5.2

flare/http/redirect_policy.mojo:173-185 @59bda50. Every reference that does
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
The fix proved here covers the query-only case (the one the repro checks).
-/
namespace Flare.Bugs.APP_45

open Flare.L4.Redirect

def base : Str := "http://h/list/items".toList

/-- Counterexample 1: the query-only reference loses `items`. -/
theorem query_only_reference_wrong :
    resolveLocation base "?page=2".toList = some "http://h:80/list/?page=2".toList ∧
    resolveLocation base "?page=2".toList ≠ some "http://h:80/list/items?page=2".toList := by
  native_decide

/-- Counterexample 2: dot segments survive resolution. -/
theorem dot_segments_kept :
    resolveLocation "http://h/b/c/d".toList "../g".toList = some "http://h:80/b/c/../g".toList ∧
    resolveLocation "http://h/b/c/d".toList "../g".toList ≠ some "http://h:80/b/g".toList := by
  native_decide

/-- Minimal fix for query-only references: keep the base path. -/
def resolveFixed (b l : Str) : Option Str :=
  match l with
  | '?' :: _ => (parse b).map fun u => originStr u ++ u.path ++ l
  | _ => resolveLocation b l

/-- The fix meets RFC 3986 §5.2.2 for every query-only reference on every
base that parses: scheme, authority and path come from the base, the query
from the reference (and the base's query and fragment are dropped). -/
theorem resolveFixed_query_only (b q : Str) (u : Url) (hb : parse b = some u) :
    resolveFixed b ('?' :: q) = some (originStr u ++ u.path ++ '?' :: q) := by
  simp [resolveFixed, hb]

theorem fixed_on_example :
    resolveFixed base "?page=2".toList = some "http://h:80/list/items?page=2".toList := by
  native_decide

end Flare.Bugs.APP_45

import Flare.L3_Protocol.H1.ObsFold
import Flare.Bugs.H1_06

/-!
# H1-10: obs-fold continuation lines are not validated

* flare file: `flare/http/_server/parse.mojo:203-320` @59bda50: with
  `allow_obs_fold`, a continuation line is stripped and appended to the
  previous value; the control-byte check runs only on first lines.
* Spec clause: RFC 9112 §5.2 (obs-fold is replaced by SP, the folded value
  is still a field-value) and RFC 9110 §5.5 (no CTL other than HTAB).
* What goes wrong: `X: a` followed by ` \x01\x7f` stores `a \x01\x7f`;
  the same bytes on a first line are refused.
* Fix (`fieldsFixed`): run `valueOk` on each continuation.
  `fieldsFixed_valid` proves every stored value passes it.
-/
namespace Flare.Bugs.H1_10
open Flare Flare.L3.H1.FieldValue Flare.L3.H1.ObsFold

open Flare.Bugs.H1_06 (okEq errEq okEq_eq errEq_eq)

def lines : List Bytes := [[88, 58, 32, 97], [32, 1, 127], []]

theorem shipped_stores : fields true false none lines = .ok [([88], [97, 32, 1, 127])] :=
  okEq_eq (by native_decide)

theorem invalid : valueOk false [97, 32, 1, 127] = false := by native_decide

theorem counterexample : ¬ ∀ ls hs, fields true false none ls = .ok hs → AllValid false hs := by
  intro h
  have := h _ _ shipped_stores ([88], [97, 32, 1, 127]) (by simp)
  rw [invalid] at this
  cases this

theorem fixed_valid (ls : List Bytes) (hs : List Field) (h : fieldsFixed true false none ls = .ok hs) :
    AllValid false hs :=
  fieldsFixed_valid true false ls none hs (by intro kv hk; cases hk) h

theorem fixed_rejects : fieldsFixed true false none lines = .error "invalid header value" :=
  errEq_eq (by native_decide)

end Flare.Bugs.H1_10

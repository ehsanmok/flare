import Flare.L2_Machine.Hostname

/-!
# NET-08: `resolve` rejects valid 254-byte absolute hostnames

flare/dns/resolver.mojo:78-87 @59bda50.

Spec (the rule flare cites, RFC 1035 §2.3.4): a name is at most 255 octets
on the wire, i.e. at most 253 text bytes not counting a trailing root dot;
labels at most 63 bytes (`Flare.L2.Hostname.Valid`).

What goes wrong: flare compares the raw byte length with 253, so the
absolute spelling of a maximal name (253 bytes plus the trailing `.`,
254 bytes) is rejected with "hostname too long" although it is the same
name `getaddrinfo` accepts without the dot. `validate_gap` shows this is
the only valid input flare rejects.

Repro: formal/repro/NET-08_hostname_trailing_dot_too_long.mojo.
-/
namespace Flare.Bugs.NET_08
open Flare.L2.Hostname

def label (n : Nat) : Flare.Bytes := List.replicate n 0x61

/-- 63 + 1 + 63 + 1 + 63 + 1 + 61 + 1 = 254 bytes, ending in `.` -/
def host : Flare.Bytes := label 63 ++ [dot] ++ label 63 ++ [dot] ++ label 63 ++ [dot] ++ label 61 ++ [dot]

/-- **Counterexample**: `host` is valid but flare rejects it as too long. -/
theorem valid_but_rejected :
    host.length = 254 ∧ Valid host ∧ validate host = .tooLong := by
  native_decide

/-- the fixed check accepts it -/
theorem fixed_accepts : validateFixed host = .ok := by native_decide

/-- **Fix meets spec**: the fixed check accepts exactly the valid names. -/
theorem validateFixed_spec (h : Flare.Bytes) : validateFixed h = .ok ↔ Valid h :=
  validateFixed_iff h

end Flare.Bugs.NET_08

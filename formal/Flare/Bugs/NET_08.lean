import Flare.L2_Machine.Hostname

/-!
# NET-08: `resolve` rejects valid 254-byte absolute hostnames

Status: resolved. `resolve` now compares the length without one trailing
root dot against 253; `Flare.L2.Hostname.validate` mirrors the shipped code
and the counterexample below is about the pre-fix `validateOld`.

Pre-fix code: flare/dns/resolver.mojo:78-87 @59bda50.

Spec (the rule flare cites, RFC 1035 §2.3.4): a name is at most 255 octets
on the wire, i.e. at most 253 text bytes not counting a trailing root dot;
labels at most 63 bytes (`Flare.L2.Hostname.Valid`).

What goes wrong: flare compares the raw byte length with 253, so the
absolute spelling of a maximal name (253 bytes plus the trailing `.`,
254 bytes) is rejected with "hostname too long" although it is the same
name `getaddrinfo` accepts without the dot. `validateOld_gap` shows this is
the only valid input the old check rejected.

Repro: formal/repro/NET-08_hostname_trailing_dot_too_long.mojo.
-/
namespace Flare.Bugs.NET_08
open Flare.L2.Hostname

def label (n : Nat) : Flare.Bytes := List.replicate n 0x61

/-- 63 + 1 + 63 + 1 + 63 + 1 + 61 + 1 = 254 bytes, ending in `.` -/
def host : Flare.Bytes := label 63 ++ [dot] ++ label 63 ++ [dot] ++ label 63 ++ [dot] ++ label 61 ++ [dot]

/-- **Counterexample**: `host` is valid but the pre-fix check rejects it as
too long. -/
theorem valid_but_rejected :
    host.length = 254 ∧ Valid host ∧ validateOld host = .tooLong := by
  native_decide

/-- the shipped check accepts it -/
theorem fixed_accepts : validate host = .ok := by native_decide

/-- **Fix meets spec**: the shipped check accepts exactly the valid names. -/
theorem validateFixed_spec (h : Flare.Bytes) : validate h = .ok ↔ Valid h :=
  validate_iff h

end Flare.Bugs.NET_08

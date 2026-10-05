import Flare.L2_Machine.WriteLoop

/-!
# NET-02: `write_all` livelocks when `send(2)` returns 0

Status: resolved. Both streams now run the shared loop
`write_all_chunks` (flare/net/_write_loop.mojo), which raises when a chunk
write returns 0; `Flare.L2.WriteLoop.writeAll` / `udsWriteAll` mirror the
shipped code and the counterexample below is about the pre-fix
`writeAllOld`.

Pre-fix code: `TcpStream.write_all` (flare/tcp/stream.mojo:497-519) and
`UnixStream.write_all` (flare/uds/stream.mojo:156-163) add the `write`
result to `sent` / subtract it from `remaining` with no check for 0.
POSIX permits `send` to return 0 for a non-empty buffer
(`Flare.Assumptions.SendContract`); then the loop spins forever.
Spec: `write_all` either writes every byte or raises.
Severity low: Linux and macOS never return 0 from a blocking TCP/UDS
`send` with `len > 0`, so this is latent.
Repro: formal/repro/NET-02_write_all_zero_send_livelock.mojo, by fault
injection (an interposed `send`; DYLD_INSERT_LIBRARIES on macOS,
LD_PRELOAD on Linux): 1000 zero returns without progress.
-/
namespace Flare.Bugs.NET_02
open Flare.L2.WriteLoop

/-- Spec: a `write_all` loop `F` run under the POSIX contract terminates
(done or raise) once given enough fuel. -/
def TerminatesWithin (F : Nat → (Nat → Nat → Int) → Nat → Nat → Nat → Res) (total : Nat)
    (o : Nat → Nat → Int) (fuel : Nat) : Prop :=
  ∃ n, F total o fuel 0 0 = .done n ∨ F total o fuel 0 0 = .err

/-- Counterexample: the POSIX-legal constant-0 oracle, one byte to send,
no fuel bound lets the pre-fix loop terminate. -/
theorem writeAll_livelock :
    Weak zeroOracle ∧ ∀ fuel, ¬ TerminatesWithin writeAllOld 1 zeroOracle fuel := by
  refine ⟨zeroOracle_weak, fun fuel => ?_⟩
  rintro ⟨n, h | h⟩ <;> rw [writeAllOld_livelock_weak 1 (by decide) fuel 0] at h <;> cases h

/-- Concrete instance, checked by evaluation. -/
theorem writeAll_livelock_concrete :
    writeAllOld 5 zeroOracle 1000 0 0 = .outOfFuel 0 := by native_decide

/-- The shipped loop (raise on a 0 return) terminates under the weak contract. -/
theorem writeAllFixed_terminates (total : Nat) (o : Nat → Nat → Int) (h : Weak o) :
    writeAll total o total 0 0 = .done total ∨ writeAll total o total 0 0 = .err :=
  writeAll_terminates_weak total o h total 0 0 (by omega) (by omega)

/-- ... in particular, with the constant-0 oracle the shipped loop raises
at once. -/
theorem writeAll_zero_raises : writeAll 5 zeroOracle 1000 0 0 = .err := by
  decide

end Flare.Bugs.NET_02

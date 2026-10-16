import Flare.Core

/-!
# UnixListener: stale-socket takeover and the destructor guard

Model of `flare/uds/listener.mojo`:
* `bind_with_options(unlink_existing=True)` (lines 193-210, with the probe
  `_socket_path_is_stale` at 50-70): `lstat` the path; a non-socket raises;
  a socket is probed with a throwaway `connect(2)`; only a refusal
  (`ECONNREFUSED`/`ENOENT`) makes it stale and unlinks it, any other probe
  outcome is `AddressInUse` (fixed, NET-07; before, every failed probe
  counted as stale);
* `__init__` (99-121) records `(dev, ino)` of the socket file right after
  `bind`; `__deinit__` (123-146) closes the socket and unlinks the path only
  if it still names a socket with that `(dev, ino)` and `ino ≠ 0`.

Spec (docstring at 146-153): "Remove a stale socket at `path` before
`bind(2)`: one no process is listening on. A live socket raises
`AddressInUse`." The destructor: "removes that file and not one that
replaced it" (69-70).

Environment facts are Prop hypotheses:
* `ConnectFacts`: `connect(2)` on a socket path returns `ECONNREFUSED` only
  if nobody listens (true on Linux and macOS; a full backlog gives
  `EAGAIN` on Linux and `ECONNREFUSED` on macOS, see the report), and it
  succeeds if somebody listens and the caller may write the file.
  `EACCES` (no write permission on the socket file) says nothing about
  liveness.
* `InodesUnique`: two distinct files that exist at the same time have
  distinct `(dev, ino)`; a bound socket keeps its inode allocated until
  its fd is closed.

Proved: `prep` only unlinks after `ECONNREFUSED` and never removes a live
socket (`prep_safe`). The destructor guard is exact when the
close-lstat-unlink sequence is not interleaved with another process
(`deinit_spec`); `deinit_race` shows the interleaving that defeats it,
which no POSIX call can close (there is no unlink-if-inode).
-/
namespace Flare.L2.UdsListener

/-- what `lstat_kind` reports (uds/_libc.mojo:152-186) -/
inductive Kind where
  | none
  | sock (dev ino : Nat)
  | other
  deriving DecidableEq, Repr

/-- outcome of the probe `connect(2)` (`_socket_path_is_stale`,
uds/listener.mojo:50-70): success, a refusal (ECONNREFUSED / ENOENT) or
another errno -/
inductive Conn where
  | ok
  | refused
  | err (errno : Nat)
  deriving DecidableEq, Repr

def EACCES : Nat := 13

/-- what `bind_with_options` does before `bind(2)` -/
inductive Prep where
  | notSocket   -- raise NetworkError
  | inUse       -- raise AddressInUse
  | unlinkBind  -- unlink(path), then bind
  | bind        -- nothing there, bind
  deriving DecidableEq, Repr

/-- mirrors flare/uds/listener.mojo#UnixListener.bind_with_options sha=87118004d219 at=c279917d (fixed, NET-07): only a refused
probe proves the socket stale; any other probe outcome raises `AddressInUse`. -/
def prep (k : Kind) (c : Conn) : Prep :=
  match k with
  | .other => .notSocket
  | .none => .bind
  | .sock _ _ => if c = .refused then .unlinkBind else .inUse

/-- the socket file's real state: is a process listening on it, may we
write it -/
structure Peer where
  listening : Bool
  writable : Bool

/-- Environment hypothesis on `connect(2)` for a socket path. -/
def ConnectFacts (p : Peer) (c : Conn) : Prop :=
  (c = .refused → p.listening = false) ∧
  (p.listening = true ∧ p.writable = true → c = .ok)

/-- **Fix meets spec** (shipped `prep`): it never unlinks a socket somebody
listens on, and still recovers every stale socket that refuses. -/
theorem prep_safe (k : Kind) (p : Peer) (c : Conn) (hc : ConnectFacts p c) :
    (prep k c = .unlinkBind → p.listening = false) ∧
    (∀ d i, k = .sock d i → c = .refused → prep k c = .unlinkBind) := by
  refine ⟨fun h => ?_, fun d i hk hr => by subst hk; subst hr; rfl⟩
  unfold prep at h
  split at h
  · cases h
  · cases h
  · split at h
    · rename_i hr; exact hc.1 hr
    · cases h

/-! ## The destructor guard -/

/-- a file system restricted to one path: what is there, as `(dev, ino)` -/
abbrev FS := Option (Nat × Nat)

/-- `(dev, ino)` recorded by `__init__`: `lstat` right after `bind`, zero
if it is not a socket or `lstat` fails.
mirrors flare/uds/listener.mojo#UnixListener.__init__ sha=2c6687cf3ce2 at=c279917d -/
def record (fs : FS) : Nat × Nat :=
  match fs with
  | some (d, i) => (d, i)
  | none => (0, 0)

/-- does `__deinit__` unlink the path.
mirrors flare/uds/listener.mojo#UnixListener.__deinit__ sha=7ff0a9a927f5 at=c279917d -/
def deinitUnlinks (cleanup : Bool) (rec : Nat × Nat) (fs : FS) : Bool :=
  cleanup && match fs with
    | some (d, i) => d == rec.1 && i == rec.2 && rec.2 != 0
    | none => false

/-- Environment hypothesis: the file at the path has the identity `f` iff
it is the same file — (dev, ino) pairs of files that exist at the same
time are distinct, and the listener's inode is still allocated (it is
pinned by the bound socket until the destructor runs; the model treats
close-lstat-unlink as one step). -/
def InodesUnique (mine : Nat × Nat) (fs : FS) (isMine : Prop) : Prop :=
  fs = some mine ↔ isMine

/-- **Destructor guard (sequential)**: with cleanup on and a recorded inode,
the destructor unlinks exactly when the path still names the listener's
own socket file. -/
theorem deinit_spec (mine : Nat × Nat) (hino : mine.2 ≠ 0) (fs : FS) (isMine : Prop)
    (hu : InodesUnique mine fs isMine) :
    deinitUnlinks true (record (some mine)) fs = true ↔ isMine := by
  rw [← (show fs = some mine ↔ isMine from hu)]
  obtain ⟨d, i⟩ := mine
  simp only [record] at hino ⊢
  cases fs with
  | none => simp [deinitUnlinks]
  | some p =>
    obtain ⟨d', i'⟩ := p
    simp only [deinitUnlinks, Bool.true_and, Option.some.injEq, Prod.mk.injEq]
    constructor
    · intro h; simp only [Bool.and_eq_true, beq_iff_eq, bne_iff_ne, ne_eq] at h
      exact ⟨h.1.1, h.1.2⟩
    · rintro ⟨rfl, rfl⟩; simp [hino]

/-- if `__init__` could not record the inode, the destructor never unlinks -/
theorem deinit_no_record (fs : FS) : deinitUnlinks true (record none) fs = false := by
  cases fs with
  | none => rfl
  | some p => obtain ⟨d, i⟩ := p; simp [deinitUnlinks, record]

/-- with `cleanup_path=False` the destructor never unlinks -/
theorem deinit_no_cleanup (rec : Nat × Nat) (fs : FS) : deinitUnlinks false rec fs = false := rfl

/-- **The residual race.** The destructor closes the socket before its
`lstat`. If, in between, another process (that earlier removed the path)
binds the path and the file system hands it the inode just freed, the
`(dev, ino)` check passes on a file that is not the listener's. The
sequential hypothesis `InodesUnique` does not hold across that window. -/
theorem deinit_race :
    let mine := (1, 42)
    let theirs := (1, 42)       -- the freed inode reused by the new bind
    deinitUnlinks true (record (some mine)) (some theirs) = true := by
  decide

end Flare.L2.UdsListener

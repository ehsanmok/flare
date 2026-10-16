import Oracle.Registry
/-!
`flare-oracle IN OUT` answers every case in IN (see Oracle.Codec for the
format) and writes one line per case to OUT. `flare-oracle --list` prints
the target names.
-/
open Oracle

def answer (line : String) : String :=
  match line.splitOn "\t" with
  | [name, hex] =>
    match find? name, ofHex? hex with
    | some t, some b => run t b
    | none, _ => s!"BAD:unknown target {name}\t-"
    | _, none => "BAD:hex\t-"
  | _ => "BAD:line\t-"

def main (args : List String) : IO UInt32 := do
  match args with
  | ["--list"] =>
    for t in targets do IO.println t.name
    return 0
  | [inp, out] =>
    let txt ← IO.FS.readFile inp
    let cases := (txt.splitOn "\n").filter (· ≠ "")
    IO.FS.writeFile out (String.intercalate "\n" (cases.map answer) ++ "\n")
    return 0
  | _ =>
    IO.eprintln "usage: flare-oracle IN OUT | flare-oracle --list"
    return 2

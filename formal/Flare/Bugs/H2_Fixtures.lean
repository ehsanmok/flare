import Flare.L3_Protocol.H2.ConnFlow

/-!
# Shared fixtures for the H2 counterexample traces

A fixed HPACK outcome table (`dec`: the header block `[k]` decodes to the
k-th field list below) and frame builders. Every trace is run through the
connection model `Flare.L3.H2.Conn.run` from a freshly configured
connection, once with `Fix.none` (the shipped code) and once with the
issue's fix flag.
-/
namespace Flare.Bugs.H2_Fixtures
open Flare Flare.L3.H2.Conn
open Flare.L3.H2.Hpack (Entry)

def H (n v : String) : Entry := ⟨Bytes.ofString n, Bytes.ofString v⟩

def getReq : List Entry := [H ":method" "GET", H ":scheme" "https", H ":path" "/"]

def postCL (v : String) : List Entry :=
  [H ":method" "POST", H ":scheme" "https", H ":path" "/", H "content-length" v]

/-- Block `[1]`: GET; `[2]`: POST with content-length 2^64+5; `[3]`: POST
with content-length 100000; `[4]`: `:status 200`; `[5]`: POST without
content-length; `[6]`: POST with content-length 5 then 10; `[7]`: the trailer `x-t: 1`. -/
def dec : Dec := fun b =>
  if b = [1] then .ok getReq
  else if b = [2] then .ok (postCL "18446744073709551621")
  else if b = [3] then .ok (postCL "100000")
  else if b = [4] then .ok [H ":status" "200"]
  else if b = [5] then .ok [H ":method" "POST", H ":scheme" "https", H ":path" "/"]
  else if b = [6] then .ok (postCL "5" ++ [H "content-length" "10"])
  else if b = [7] then .ok [H "x-t" "1"]
  else .fail

def settings0 : Fr := { ty := tSETTINGS }
def hdrs (sid : Nat) (es : Bool) (k : UInt8) : Fr :=
  { ty := tHEADERS, sid := sid, f1 := es, eh := true, plen := 1, frag := [k] }
def dataF (sid n : Nat) (es : Bool) : Fr := { ty := tDATA, sid := sid, f1 := es, plen := n }
def rstF (sid : Nat) : Fr := { ty := tRST, sid := sid, plen := 4 }
def wuF (sid inc : Nat) : Fr := { ty := tWU, sid := sid, plen := 4, word := inc }

/-- The replies of a run (`none` = a step raised). -/
def outs (fx : Fix) (c : Conn) (es : List Ev) : Option (List (List Out)) :=
  (run fx dec c es).map (fun r => r.2.map (·.2))

/-- The reply to the last input of a run. -/
def lastOut (fx : Fix) (c : Conn) (es : List Ev) : Option (List Out) :=
  (outs fx c es).bind List.getLast?

theorem not_connError_nil (code : Nat) : ¬ IsConnError [] code := by
  rintro ⟨_, h⟩; cases h

/-- The final state of stream `k` after a run. -/
def stateOf (fx : Fix) (c : Conn) (es : List Ev) (k : Nat) : Option St :=
  (run fx dec c es).bind (fun r => (get r.1 k).map (·.state))

/-- The input/reply trace of a run. -/
def trace (fx : Fix) (c : Conn) (es : List Ev) : List (Ev × List Out) :=
  match run fx dec c es with
  | some r => r.2
  | none => []

theorem fresh_default : Fresh ({} : Conn) := by
  refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem fresh_client : Fresh ({ isClient := true } : Conn) := by
  refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem fresh_mc (n : Nat) : Fresh ({ maxConcurrent := n } : Conn) := by
  refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

end Flare.Bugs.H2_Fixtures

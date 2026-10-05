import Flare.L1_Encoding.Base64
import Flare.L3_Protocol.H1.ClientChunked

/-!
# WebSocket opening handshake (RFC 6455 §4.1, §4.2, §11.3)

SHA-1 is a black box (`Sha1 := Bytes → Bytes`); the key/GUID concatenation
and the base64 step are the L1 model (`Flare.L1.Base64.encodeStd`/`decode`).

Header fields are given as the `(name, value)` pairs of the colon-containing
lines, both stripped, exactly what the three handshake loops build before
they compare anything; names are compared after `lowerB`.

* **Key.** `genKey_valid`: the client's key (base64 of the 16-byte nonce)
  is a valid `Sec-WebSocket-Key` (`KeyOK`: decodes to 16 bytes).
* **Client** (`WsClient._connect_impl`). `clientAcceptsOld` checked only the
  `HTTP/1.1 101` prefix and `Sec-WebSocket-Accept`. `ClientOK` is the
  RFC 6455 §4.1 list (Upgrade `websocket`, Connection token `upgrade`, the
  accept value, no unrequested subprotocol or extension). Finding WS-04;
  the shipped `clientAccepts` decides exactly `ClientOK`: `clientAccepts_ok`.
* **Standalone server** (`_parse_ws_upgrade_bytes`). `srvShipped` skips the
  request line, tests Connection by substring, and checks neither key format
  nor version. `ServerOK` is RFC 6455 §4.2.1 plus §11.3.1/§11.3.5 (the key
  and version fields appear once). Finding WS-05; `srvFixed_ok`.
* **Reactor** (`ConnHandle._handle_ws_upgrade` behind the 426 check).
  `reactor_upgrade_v13`: the shipped reactor only upgrades version 13.
  It still tests Connection by substring and does not decode the key:
  finding WS-07; `reactorFixed_ok`.
* **Pairing.** `handshake_complete`: flare's own client request passes both
  fixed servers, and the standalone server's 101 passes the fixed client, for
  every SHA-1 and every valid key.

The server never sends `Sec-WebSocket-Protocol` (RFC 6455 lets a server
select none), so subprotocol selection on the server side is "none", and
the client's request offers none; `ClientOK` therefore requires that the
101 names none.
-/
namespace Flare.L3.Ws.Handshake

open Flare.L1.Base64
open Flare.L3.H1.ClientChunked (lowerB pyStrip)

/-- `258EAFA5-E914-47DA-95CA-C5AB0DC85B11` (RFC 6455 §1.3). -/
def GUID : Bytes :=
  [50, 53, 56, 69, 65, 70, 65, 53, 45, 69, 57, 49, 52, 45, 52, 55, 68, 65, 45, 57, 53, 67, 65,
    45, 67, 53, 65, 66, 48, 68, 67, 56, 53, 66, 49, 49]
def WEBSOCKET : Bytes := [119, 101, 98, 115, 111, 99, 107, 101, 116]
def UPGRADE : Bytes := [117, 112, 103, 114, 97, 100, 101]
def N_CONNECTION : Bytes := [99, 111, 110, 110, 101, 99, 116, 105, 111, 110]
def N_KEY : Bytes := [115, 101, 99, 45, 119, 101, 98, 115, 111, 99, 107, 101, 116, 45, 107, 101, 121]
def N_ACCEPT : Bytes :=
  [115, 101, 99, 45, 119, 101, 98, 115, 111, 99, 107, 101, 116, 45, 97, 99, 99, 101, 112, 116]
def N_VERSION : Bytes :=
  [115, 101, 99, 45, 119, 101, 98, 115, 111, 99, 107, 101, 116, 45, 118, 101, 114, 115, 105,
    111, 110]
def N_PROTOCOL : Bytes :=
  [115, 101, 99, 45, 119, 101, 98, 115, 111, 99, 107, 101, 116, 45, 112, 114, 111, 116, 111,
    99, 111, 108]
def N_EXT : Bytes :=
  [115, 101, 99, 45, 119, 101, 98, 115, 111, 99, 107, 101, 116, 45, 101, 120, 116, 101, 110,
    115, 105, 111, 110, 115]
def V13 : Bytes := [49, 51]
def GET : Bytes := [71, 69, 84]
def HTTP11 : Bytes := [72, 84, 84, 80, 47, 49, 46, 49]
def HTTP10 : Bytes := [72, 84, 84, 80, 47, 49, 46, 48]
def STATUS101 : Bytes := [72, 84, 84, 80, 47, 49, 46, 49, 32, 49, 48, 49]
/-- `Upgrade` as flare writes it in field names and the Connection value. -/
def UPGRADE_CAP : Bytes := [85, 112, 103, 114, 97, 100, 101]
def CONNECTION_CAP : Bytes := [67, 111, 110, 110, 101, 99, 116, 105, 111, 110]
def KEY_CAP : Bytes :=
  [83, 101, 99, 45, 87, 101, 98, 83, 111, 99, 107, 101, 116, 45, 75, 101, 121]
def VERSION_CAP : Bytes :=
  [83, 101, 99, 45, 87, 101, 98, 83, 111, 99, 107, 101, 116, 45, 86, 101, 114, 115, 105, 111, 110]
def ACCEPT_CAP : Bytes :=
  [83, 101, 99, 45, 87, 101, 98, 83, 111, 99, 107, 101, 116, 45, 65, 99, 99, 101, 112, 116]
def HOST_CAP : Bytes := [72, 111, 115, 116]
/-- `HTTP/1.1 101 Switching Protocols`. -/
def SWITCHING : Bytes :=
  STATUS101 ++ [32, 83, 119, 105, 116, 99, 104, 105, 110, 103, 32, 80, 114, 111, 116, 111, 99,
    111, 108, 115]

/-! ## Key and accept -/

abbrev Sha1 := Bytes → Bytes

/-- mirrors flare/ws/client.mojo:134-148 and flare/ws/server.mojo:100-111 @59bda50 -/
def acceptOf (sha1 : Sha1) (key : Bytes) : Bytes := encodeStd (sha1 (key ++ GUID))

/-- RFC 6455 §4.1/§11.3.1: base64 of 16 bytes. -/
def KeyOK (k : Bytes) : Prop := ∃ n, decode k = some n ∧ n.length = 16

def keyOk (k : Bytes) : Bool :=
  match decode k with
  | some n => n.length == 16
  | none => false

theorem keyOk_iff (k : Bytes) : keyOk k = true ↔ KeyOK k := by
  unfold keyOk KeyOK
  cases decode k <;> simp

/-- mirrors flare/ws/client.mojo:118-131 @59bda50 (`nonce` = `random_bytes(16)`) -/
def genKey (nonce : Bytes) : Bytes := encodeStd nonce

theorem genKey_valid {nonce : Bytes} (h : nonce.length = 16) : KeyOK (genKey nonce) :=
  ⟨nonce, decode_encodeStd nonce, h⟩

/-! ## Fields -/

abbrev Fields := List (Bytes × Bytes)

def named (k : Bytes) (f : Bytes × Bytes) : Bool := lowerB f.1 == k
def vals (fs : Fields) (k : Bytes) : List Bytes := (fs.filter (named k)).map Prod.snd
/-- A repeated field keeps the last value (the `var = v` loops). -/
def lastVal (fs : Fields) (k : Bytes) : Option Bytes := (vals fs k).getLast?
/-- `HeaderMap.get`: the first value. mirrors flare/http/headers.mojo:172-184 @59bda50 -/
def firstVal (fs : Fields) (k : Bytes) : Option Bytes := (vals fs k).head?

/-- `needle in haystack`. -/
def infixB (n : Bytes) : Bytes → Bool
  | [] => n.isEmpty
  | h :: t => n.isPrefixOf (h :: t) || infixB n t

def splitComma : Bytes → List Bytes
  | [] => [[]]
  | c :: t =>
    if c = 44 then [] :: splitComma t
    else match splitComma t with
      | [] => [[c]]
      | x :: r => (c :: x) :: r

/-- `tok` is one of the comma-separated, case-insensitive tokens of `v`. -/
def hasTok (v tok : Bytes) : Bool := ((splitComma v).map fun t => lowerB (pyStrip t)).contains tok

/-! ## Client -/

/-- The status-line and field checks of the 101 (both branches) before the
WS-04 fix.
mirrors flare/ws/client.mojo:562-603 (TLS) and 609-646 (TCP) @59bda50 -/
def clientAcceptsOld (sha1 : Sha1) (key status : Bytes) (fs : Fields) : Bool :=
  STATUS101.isPrefixOf status && (lastVal fs N_ACCEPT).getD [] == acceptOf sha1 key

/-- RFC 6455 §4.1 (client requirements on the server's handshake), for a
request that offered no subprotocol and no extension. -/
def ClientOK (sha1 : Sha1) (key status : Bytes) (fs : Fields) : Prop :=
  STATUS101.isPrefixOf status = true ∧
  (vals fs UPGRADE).any (fun v => lowerB v == WEBSOCKET) = true ∧
  (vals fs N_CONNECTION).any (fun v => hasTok v UPGRADE) = true ∧
  lastVal fs N_ACCEPT = some (acceptOf sha1 key) ∧
  vals fs N_PROTOCOL = [] ∧ vals fs N_EXT = []

/-- The shipped client check (`_UpgradeResponse.verify` after the status-line
check, both branches): the whole RFC 6455 §4.1 list.
mirrors flare/ws/client.mojo `_connect_impl` (fixed, WS-04) -/
def clientAccepts (sha1 : Sha1) (key status : Bytes) (fs : Fields) : Bool :=
  STATUS101.isPrefixOf status &&
  (vals fs UPGRADE).any (fun v => lowerB v == WEBSOCKET) &&
  (vals fs N_CONNECTION).any (fun v => hasTok v UPGRADE) &&
  lastVal fs N_ACCEPT == some (acceptOf sha1 key) &&
  (vals fs N_PROTOCOL).isEmpty && (vals fs N_EXT).isEmpty

theorem clientAccepts_ok (sha1 : Sha1) (key status : Bytes) (fs : Fields) :
    clientAccepts sha1 key status fs = true ↔ ClientOK sha1 key status fs := by
  simp only [clientAccepts, ClientOK, Bool.and_eq_true, beq_iff_eq, List.isEmpty_iff, and_assoc]

/-- The shipped check only adds conjuncts to the old one. -/
theorem clientAccepts_le_old {sha1 : Sha1} {key status : Bytes} {fs : Fields}
    (h : clientAccepts sha1 key status fs = true) : clientAcceptsOld sha1 key status fs = true := by
  obtain ⟨h1, -, -, h4, -⟩ := (clientAccepts_ok sha1 key status fs).1 h
  simp [clientAcceptsOld, h1, h4]

/-! ## Server -/

structure Req where
  method : Bytes
  target : Bytes
  version : Bytes
  fields : Fields

/-- RFC 6455 §4.2.1, with §11.3.1 and §11.3.5 (key and version once). -/
def ServerOK (r : Req) (key : Bytes) : Prop :=
  r.method = GET ∧ r.version = HTTP11 ∧
  (vals r.fields UPGRADE).any (fun v => hasTok v WEBSOCKET) = true ∧
  (vals r.fields N_CONNECTION).any (fun v => hasTok v UPGRADE) = true ∧
  vals r.fields N_KEY = [key] ∧ KeyOK key ∧ vals r.fields N_VERSION = [V13]

/-- The request line is read and dropped; `key` is the last
`Sec-WebSocket-Key`. mirrors flare/ws/server.mojo:188-261 (and the stream
twin 264-321) @59bda50 -/
def srvShipped (r : Req) : Option Bytes :=
  let key := (lastVal r.fields N_KEY).getD []
  if (vals r.fields UPGRADE).any (fun v => lowerB v == WEBSOCKET) &&
      (vals r.fields N_CONNECTION).any (fun v => infixB UPGRADE (lowerB v)) && !key.isEmpty then
    some key
  else none

/-- The checks shared by both fixed servers. -/
def qualFixed (r : Req) (key : Bytes) : Bool :=
  r.method == GET && r.version == HTTP11 &&
  (vals r.fields UPGRADE).any (fun v => hasTok v WEBSOCKET) &&
  (vals r.fields N_CONNECTION).any (fun v => hasTok v UPGRADE) &&
  keyOk key && vals r.fields N_VERSION == [V13]

def srvFixed (r : Req) : Option Bytes :=
  match vals r.fields N_KEY with
  | [key] => if qualFixed r key then some key else none
  | _ => none

theorem qualFixed_ok {r : Req} {key : Bytes} (hk : vals r.fields N_KEY = [key])
    (h : qualFixed r key = true) : ServerOK r key := by
  simp only [qualFixed, Bool.and_eq_true, beq_iff_eq] at h
  obtain ⟨⟨⟨⟨⟨hm, hv⟩, hu⟩, hc⟩, hko⟩, hver⟩ := h
  exact ⟨hm, hv, hu, hc, hk, (keyOk_iff key).1 hko, hver⟩

theorem srvFixed_ok {r : Req} {key : Bytes} (h : srvFixed r = some key) : ServerOK r key := by
  unfold srvFixed at h
  split at h
  · rename_i k hk
    by_cases hq : qualFixed r k = true
    · rw [if_pos hq] at h
      cases h
      exact qualFixed_ok hk hq
    · rw [if_neg hq] at h; cases h
  · cases h

/-! ## Reactor -/

inductive ROut where
  | http
  | reject426
  | upgrade (key : Bytes)
  deriving DecidableEq, Repr

def hdr (r : Req) (k : Bytes) : Bytes := (firstVal r.fields k).getD []

/-- mirrors flare/http/_reactor/conn_handle.mojo:143-152 @59bda50 -/
def versionMismatch (r : Req) : Bool :=
  r.method == GET && lowerB (hdr r UPGRADE) == WEBSOCKET && !(hdr r N_KEY).isEmpty &&
  pyStrip (hdr r N_VERSION) != V13

/-- mirrors flare/http/_reactor/conn_handle.mojo:1512-1523 @59bda50 -/
def reactorQual (r : Req) : Bool :=
  r.method == GET && r.version != HTTP10 && lowerB (hdr r UPGRADE) == WEBSOCKET &&
  infixB UPGRADE (lowerB (hdr r N_CONNECTION)) && !(hdr r N_KEY).isEmpty

/-- The 426 branch runs first. mirrors flare/http/_reactor/conn_handle.mojo:835-860 @59bda50 -/
def reactor (r : Req) : ROut :=
  if versionMismatch r then .reject426
  else if reactorQual r then .upgrade (hdr r N_KEY) else .http

/-- The shipped reactor never upgrades a version other than 13. -/
theorem reactor_upgrade_v13 {r : Req} {k : Bytes} (h : reactor r = .upgrade k) :
    pyStrip (hdr r N_VERSION) = V13 := by
  unfold reactor at h
  by_cases hm : versionMismatch r = true
  · rw [if_pos hm] at h; cases h
  rw [if_neg hm] at h
  by_cases hq : reactorQual r = true
  · simp only [reactorQual, Bool.and_eq_true, bne_iff_ne, ne_eq, beq_iff_eq,
      Bool.not_eq_eq_eq_not, Bool.not_true] at hq
    simp only [versionMismatch, Bool.and_eq_true, bne_iff_ne, ne_eq, beq_iff_eq,
      Bool.not_eq_eq_eq_not, Bool.not_true, not_and, Classical.not_not] at hm
    exact hm ⟨⟨hq.1.1.1.1, hq.1.1.2⟩, hq.2⟩
  · rw [if_neg hq] at h; cases h

def reactorFixed (r : Req) : ROut :=
  if versionMismatch r then .reject426
  else match vals r.fields N_KEY with
    | [key] => if qualFixed r key then .upgrade key else .http
    | _ => .http

theorem reactorFixed_ok {r : Req} {key : Bytes} (h : reactorFixed r = .upgrade key) :
    ServerOK r key := by
  unfold reactorFixed at h
  by_cases hm : versionMismatch r = true
  · rw [if_pos hm] at h; cases h
  rw [if_neg hm] at h
  split at h
  · rename_i k hk
    by_cases hq : qualFixed r k = true
    · rw [if_pos hq] at h
      cases h
      exact qualFixed_ok hk hq
    · rw [if_neg hq] at h; cases h
  · cases h

/-! ## Pairing flare's client with flare's servers -/

/-- mirrors flare/ws/client.mojo:536-550 @59bda50 -/
def clientRequest (host target key : Bytes) : Req :=
  { method := GET, target := target, version := HTTP11,
    fields := [(HOST_CAP, host), (UPGRADE_CAP, WEBSOCKET), (CONNECTION_CAP, UPGRADE_CAP),
      (KEY_CAP, key), (VERSION_CAP, V13)] }

/-- mirrors flare/ws/server.mojo:324-340 @59bda50 -/
def srvResponse (sha1 : Sha1) (key : Bytes) : Fields :=
  [(UPGRADE_CAP, WEBSOCKET), (CONNECTION_CAP, UPGRADE_CAP), (ACCEPT_CAP, acceptOf sha1 key)]

theorem vals_cons (fs : Fields) (k n v : Bytes) :
    vals ((n, v) :: fs) k = if lowerB n == k then v :: vals fs k else vals fs k := by
  unfold vals named
  by_cases h : (lowerB n == k) = true
  · simp [h]
  · simp [h]

theorem vals_nil (k : Bytes) : vals [] k = [] := rfl

theorem handshake_complete (sha1 : Sha1) (host target key : Bytes) (hk : KeyOK key) :
    srvFixed (clientRequest host target key) = some key ∧
    reactorFixed (clientRequest host target key) = .upgrade key ∧
    clientAccepts sha1 key SWITCHING (srvResponse sha1 key) = true := by
  have hko : keyOk key = true := (keyOk_iff key).2 hk
  have hne : key ≠ [] := by
    intro h; subst h; obtain ⟨n, hn, hl⟩ := hk
    simp [decode, padCount, trailingEq] at hn
    subst hn; simp at hl
  have hq : qualFixed (clientRequest host target key) key = true := by
    simp (config := { decide := true }) [qualFixed, clientRequest, vals_cons, vals_nil, hko]
  have hv : vals (clientRequest host target key).fields N_KEY = [key] := by
    simp (config := { decide := true }) [clientRequest, vals_cons, vals_nil]
  have hmm : versionMismatch (clientRequest host target key) = false := by
    simp (config := { decide := true }) [versionMismatch, hdr, firstVal, clientRequest, vals_cons,
      vals_nil]
  refine ⟨?_, ?_, ?_⟩
  · simp only [srvFixed, hv, hq, if_true]
  · simp only [reactorFixed, hmm, hv, hq, if_true]; rfl
  · simp (config := { decide := true }) [clientAccepts, srvResponse, vals_cons, vals_nil, lastVal]

end Flare.L3.Ws.Handshake

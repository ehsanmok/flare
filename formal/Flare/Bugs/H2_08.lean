import Flare.Bugs.H2_Fixtures

/-!
# H2-08: the first frame after the preface need not be SETTINGS

`Http2Connection.feed` (flare/http2/server.mojo:358-438 @59bda50)
consumes the 24-octet client preface and hands every following frame to
`handle_frame`; nothing checks that the first one is SETTINGS. A PING as
the first frame is answered with a PING ACK.

RFC 9113 §3.4: "That is, the connection preface starts with the string
PRI * HTTP/2.0 [...]. This sequence MUST be followed by a SETTINGS frame
[...]. Clients and servers MUST treat an invalid connection preface as a
connection error (Section 5.4.1) of type PROTOCOL_ERROR."
-/
namespace Flare.Bugs.H2_08
open Flare Flare.L3.H2.Conn Flare.Bugs.H2_Fixtures

def tr : List Ev := [.frame { ty := tPING, plen := 8 }]

theorem bug : lastOut Fix.none {} tr = some [.pingAck] := by native_decide

theorem counterexample : ∀ o, lastOut Fix.none {} tr = some o → ¬ IsConnError o ePROTOCOL := by
  intro o h; rw [bug] at h; cases h; rintro ⟨_, h⟩; cases h

theorem fixed_trace : lastOut { h2_08 := true } {} tr = some [.goaway 0 ePROTOCOL] := by native_decide

/-- **Fixed** (a `peer_settings_seen` flag in `feed`): in every state
where no SETTINGS has arrived yet, any other first frame is
GOAWAY(PROTOCOL_ERROR). -/
theorem fixed (fx : Fix) (dec : Dec) (c : Conn) (f : Fr) (h8 : fx.h2_08 = true)
    (hg : c.goawaySent = false) (hs : c.peerSettingsSeen = false) (hl : f.plen ≤ c.localMaxFrame)
    (hn : ¬ (f.ty = tSETTINGS ∧ f.f1 = false)) :
    driveFrame fx dec c f = .ok (connErr c ePROTOCOL) :=
  drive_first_not_settings fx dec c f h8 hg hs hl hn

end Flare.Bugs.H2_08

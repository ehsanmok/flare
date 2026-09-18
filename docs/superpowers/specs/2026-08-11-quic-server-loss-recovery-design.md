# QUIC server-side loss recovery (RFC 9002)

- Tracked in `flare/quic/server.mojo`'s `_on_pto_expired` docstring
  ("scoped properly during v0.10").
- Status: **implemented in v0.11.0.** Items 1-5 and 7 landed as
  described. Item 6, the congestion-window gate on the fresh-egress H3
  DATA pump, is deferred with send pacing to v0.12: the window is now
  live and correct, but nothing reads it on that path yet.
- Resolved from "Open implementation decisions": `_rearm_pto_timer`
  batches once per dispatch tick rather than once per `on_sent`,
  matching the cadence at which the client calls `_check_pto`. Of the
  six `_build_1rtt_response` call sites, five are ack-eliciting and are
  tracked; the migration-probe site is deliberately not, because it
  sends to a candidate address under an anti-amplification budget and
  RFC 9002 keeps congestion state per path.

## Problem

The QUIC server never recovers from packet loss. Per the honest
scoping left in the code:

> Server-side 1-RTT retransmit is not wired. A fired PTO re-flushes
> whatever 1-RTT egress is still pending ... but not loss recovery.
> The server does not parse inbound ACK frames at all.

This is fine on a lossless loopback bench, and actively wrong on a
real (lossy) network: a dropped response or dropped STREAM data never
gets retransmitted, so the connection just stalls until the RFC 9000
§10.1 idle timeout (default 30s) kills it.

The client already has a complete, tested, RFC 9002-compliant
implementation of exactly this (`flare/quic/_loss_recovery.mojo` +
its call sites in `flare/quic/client.mojo`). This spec ports that
same pattern to the server, which needs it more (one server, many
peers, no control over the network path to any of them).

## What already exists (verified by reading the code, not assumed)

- `LossRecovery` (`_loss_recovery.mojo`) is **already
  connection-agnostic sans-I/O state** -- RTT estimation, ACK-based
  loss detection, PTO scheduling, and the CC gate (`can_send`/
  `window`), with zero client-specific imports. It is unit-tested
  (`tests/quic/test_loss_recovery.mojo`, 9 cases). No changes needed
  to this module.
- The shared codec/state-machine layer
  (`flare.quic.state.handle_frame_buf`, called from both
  `QuicClientConnection` and the server's
  `QuicConnection.dispatch_plaintext`) **already parses inbound ACK
  frames** into `ConnectionEvents.acked_packets` for every 1-RTT
  packet. The server's dispatch loop
  (`server.mojo:_route_http3_stream_chunks` and neighbors) just never
  reads that field. This is a bug-fix-sized change, not new parsing.
- The timer-wheel plumbing for `TIMER_KIND_PTO` already exists
  server-side (`server.mojo` `advance_timers` /
  `_on_pto_expired`) and already dispatches correctly by connection
  slot; it just calls a stub today.
- `_build_1rtt_response` (`server.mojo:2400`) is the single choke
  point where every 1-RTT packet gets its packet number
  (`connections[slot].tx_1rtt_pn`) -- the natural `on_sent` hook.

## Design: port the client's pattern

The client's per-poll sequence (`client.mojo:590-594`) is the
reference implementation:

```
if len(events.acked_packets) > 0:
    _ = self._loss.on_ack(events.acked_packets, now_ms)
    self._retransmit_lost()   # detect_lost() -> re-send each lost packet's frames
self._drain_egress()
self._check_pto()             # pto_deadline() reached? -> fire_pto() -> re-send
```

And `_build_1rtt`'s `on_sent` hook (`client.mojo:1184-1221`): an
explicit `ack_eliciting: Bool` parameter from the caller (the caller
already knows whether it packed STREAM/CRYPTO frames vs. ACK-only/
PADDING-only) snapshots the frame bytes and registers them with
`LossRecovery.on_sent` after the packet number is assigned.

### 1. Per-slot `LossRecovery` slab

Add `var loss: List[LossRecovery]` to `QuicListener`, parallel to
`connections` (mirrors the existing `crypto_reasm` /
`early_guard`-style per-slot slabs). Grown/shrunk in lockstep with
`connections` at accept / slot-retire time.

### 2. Consume `acked_packets`

New `_consume_acks(slot, events)` helper, called alongside
`_route_http3_stream_chunks` wherever `dispatch_plaintext`'s `events`
are handled (the 1-RTT, 0-RTT -- 0-RTT/1-RTT share one packet-number
space per RFC 9000 §12.3 -- and post-handshake dispatch sites):

```
if len(events.acked_packets) > 0:
    _ = self.loss[slot].on_ack(events.acked_packets, now_ms)
    self._retransmit_lost(slot)   # detect_lost() -> rebuild + resend
    self._rearm_pto_timer(slot)   # pto_deadline() changed; reschedule
```

### 3. `on_sent` at packet build

`_build_1rtt_response` gains an `ack_eliciting: Bool = False`
parameter (default False keeps every existing call site's behavior
unchanged until each is audited). Mirrors `_build_1rtt` exactly:
snapshot `plaintext.copy()` before it's consumed when
`ack_eliciting`, call `self.loss[slot].on_sent(pn, frames_copy^,
now_ms)` after `tx_1rtt_pn` advances.

Every existing call site of `_build_1rtt_response` gets an explicit
`ack_eliciting=` argument in this pass (implementation plan
enumerates them): STREAM-frame H3 response bytes -> `True`; pure
post-handshake CRYPTO-only or ACK-only frames -> `False`. This is a
mechanical audit, not a design question -- RFC 9002 §2's rule (ack-
eliciting iff the packet carries anything other than ACK/PADDING/
CONNECTION_CLOSE) is unambiguous per call site.

### 4. Real PTO

Replace `_on_pto_expired`'s "re-flush pending egress" stub:

```
def _on_pto_expired(mut self, slot):
    var frames = self.loss[slot].fire_pto()
    if len(frames) > 0:
        var dg = self._build_1rtt_response(slot, frames^, ack_eliciting=True)
        self.send_to(dg, self.peer_addrs[slot])
    self._rearm_pto_timer(slot)
```

New `_rearm_pto_timer(slot)` helper (mirrors the existing
`_arm_idle_timer`): cancels any existing PTO wheel entry, and if
`loss[slot].outstanding() > 0`, schedules a fresh one at
`loss[slot].pto_deadline()`. Called after every `on_sent` (arms the
first timer) and after every `on_ack`/`detect_lost` (deadline may
have moved or the in-flight set may now be empty, in which case no
new timer is armed).

### 5. Retransmission

`_retransmit_lost(slot)`: `detect_lost(now_ms)` returns lost packets'
frame bytes; each rides a fresh `_build_1rtt_response(slot, frames,
ack_eliciting=True)` call (own packet number, per RFC 9002 -- frames
are retransmitted, packets are not) and gets sent to
`peer_addrs[slot]`.

### 6. Congestion-window gate on fresh egress

Once (1)-(5) land, `loss[slot].can_send(n)` / `.window()` are live
and correct. Every call site that packs *fresh* (non-retransmit)
STREAM data into a `_build_1rtt_response` payload (the H3 response
writer's per-tick DATA-frame pump) must check `can_send` before
including more than the window allows, and skip / defer to the next
ACK-driven opportunity otherwise -- exactly the gate the existing
docstring says `send_segmented`/GSO needs to avoid the
naked-GSO-tail-drop shape. The implementation plan enumerates the
exact pump call sites (H3 response DATA framing in `server.mojo` /
`_server_support.mojo`).

### 7. Giving up on a wedged connection

A connection whose peer has gone completely dark (no ACKs, ever)
keeps re-arming PTOs with exponential backoff
(`_PTO_BACKOFF_CAP = 6`, i.e. capped at 64x the base interval) --
`LossRecovery` already bounds the *backoff*, but nothing currently
bounds how long the server keeps probing. Add a
`QuicServerConfig.max_pto_count: Int` (new field, default 10 --
comfortably past the 6-shift backoff cap so a slow-but-alive path
isn't punished, but well short of "forever"). When
`loss[slot].pto_count` exceeds it in `_on_pto_expired`, close the
connection with `CONNECTION_CLOSE` (transport error) instead of
re-arming, and let the normal slot-retire path run. This reuses
`LossRecovery`'s existing counter (no new tracking) and gives a
bounded worst case on both memory (a `sent` list bounded by the CC
window while alive, discarded on close) and wall-clock (bounded PTO
attempts) without inventing a separate byte-cap policy axis.

## Testing plan

Mirrors the client's existing coverage shape:

- `tests/quic/test_quic_server_loss_recovery.mojo` -- unit-level,
  wires a `QuicListener`'s per-slot slab directly (no real socket):
  feed synthetic `ConnectionEvents` with `acked_packets`, assert
  `on_sent`/`on_ack`/`detect_lost`/`fire_pto` interplay matches the
  existing `test_loss_recovery.mojo` client-side cases (same RFC 9002
  vectors, server plumbing).
- A lossy-loopback integration test (extends
  `tests/quic/test_quic_loopback_integration.mojo`'s pattern): wrap
  the loopback UDP socket with a deterministic drop function (drop
  every Nth datagram) and assert the H3 request/response still
  completes -- proof the retransmit path fires for real, not just in
  unit isolation.
- A `max_pto_count` test: a connection whose peer sends the initial
  flight then goes silent forever hits the cap and the server closes
  the slot (frees resources) rather than probing indefinitely.
- Existing `tests/quic/test_quic_cc.mojo` /
  `test_loss_recovery.mojo` (client-side) stay untouched -- confirms
  no regression to the client path this pass reuses.

## Non-goals for this pass

- No changes to `LossRecovery` itself -- it is reused as-is.
- No changes to the client (`flare/quic/client.mojo`) -- already
  correct; used only as the reference pattern.
- Send pacing (RFC 9002 §7.7, inter-packet timer) stays out of scope
  -- the docstring's known-limits already separate it from loss
  recovery, and the congestion window alone (this pass's item 6)
  gates burst size without needing a pacing timer.
- 0-RTT-specific loss recovery nuances beyond "0-RTT and 1-RTT share
  one packet-number space, so a 0-RTT send's `on_sent` uses the same
  slab" are out of scope; 0-RTT is a minority path
  (`rustls_config` opt-in) and already has its own anti-replay
  admission logic this pass doesn't touch.

## Docs to update

No new public symbols ship (only a new field on the already-exported
`QuicServerConfig`), so `flare/quic/__init__.mojo` and the top-level
`flare/__init__.mojo` need no changes, and no example demonstrates
new API. Three existing doc claims go stale once this lands and need
correcting in the same pass:

- `docs/features.md`, congestion-control row -- currently describes
  the RTT/loss/PTO/CC path as client-only; note the server now
  shares it.
- `docs/features.md`, QUIC server reactor row -- currently says PTO
  "re-flushes 1-RTT egress" and that "full server-side loss-driven
  retransmit ... [is] tracked v0.9.x follow-ups"; rewrite to describe
  the real retransmit path, keep pacing noted as still deferred (see
  Non-goals).
- `docs/architecture.md` (~line 141-144) -- currently claims "CC +
  pacing budget gate the egress path" for the server; correct to say
  CC gates egress, pacing does not (yet).

## Open implementation decisions for the plan phase

- Exact enumeration of every `_build_1rtt_response` call site and its
  correct `ack_eliciting` value (mechanical audit against RFC 9002
  §2, listed above as a category but not exhaustively enumerated
  here).
- Exact enumeration of the H3 response DATA-pump call site(s) that
  need the `can_send` gate for item 6.
- Whether `_rearm_pto_timer` needs to run on every single `on_sent`
  call (arguably wasteful -- one cancel+reschedule per packet) or can
  batch to "once per dispatch-loop tick" the way the client's
  `_check_pto` is called once per `poll()` rather than per packet.
  Leaning toward the latter (matches the client's actual cadence).

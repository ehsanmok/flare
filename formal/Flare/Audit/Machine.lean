import Flare.Machine
import Flare.Bugs.MACH_01
import Flare.MachineHttp
import Flare.MachineWorkers
import Flare.MachineWheel
/-! Worker-loop machine: axiom footprint of the headline theorems. Expected:
`propext`, `Quot.sound` (some use none); the `MachineHttp` theorems also
use `Classical.choice`, through `ConnSM`. -/

#print axioms Flare.Machine.inv_reachable
#print axioms Flare.Machine.no_stale_timer
#print axioms Flare.Machine.no_early_close
#print axioms Flare.Machine.no_late_close
#print axioms Flare.Machine.dispatch_isolated
#print axioms Flare.Machine.conn_invariant_lifts
#print axioms Flare.Machine.routing_ok
#print axioms Flare.Machine.fd0_never_served
#print axioms Flare.Machine.fd0_reachable
#print axioms Flare.Machine.reuse_with_cancel
#print axioms Flare.Machine.stale_timer_without_cancel
#print axioms Flare.Machine.stale_event_redelivered
#print axioms Flare.Bugs.MACH_01.client_on_fd0
#print axioms Flare.Bugs.MACH_01.fd0_event_lost
#print axioms Flare.Bugs.MACH_01.fixed_no_conn_on_listener_token
#print axioms Flare.MachineHttp.server_conns_inv
#print axioms Flare.MachineHttp.server_responses_fifo
#print axioms Flare.MachineHttp.server_ka_bound
#print axioms Flare.MachineHttp.server_no_stale_timer
#print axioms Flare.Machine.step_dom
#print axioms Flare.Machine.poll_needs_empty_batch
#print axioms Flare.Machine.batch_progress
#print axioms Flare.Machine.no_deadlock
#print axioms Flare.Machine.sys_component_reachable
#print axioms Flare.Machine.sys_disjoint
#print axioms Flare.Machine.sys_no_stale_timer
#print axioms Flare.Machine.sys_conn_invariant_lifts
#print axioms Flare.Machine.sys_routing_ok
#print axioms Flare.MachineWheel.inv_any
#print axioms Flare.MachineWheel.no_stale_timer_any
#print axioms Flare.MachineWheel.reachable_le_any
#print axioms Flare.MachineWheel.R_init
#print axioms Flare.MachineWheel.R_schedule
#print axioms Flare.MachineWheel.R_cancel
#print axioms Flare.MachineWheel.R_advance
#print axioms Flare.MachineWheel.real_wheel_poll

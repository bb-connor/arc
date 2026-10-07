# P6 Task 4: settlement headroom and host integration

Two dedicated native settlement workers own at most two outstanding jobs, including queued and disconnected work. Fallible listener construction prevents partial startup. Intake has separate fixed permits; panic and shutdown retain accepted ownership without blocking router destruction or creating a retry.

The real Linux overload case first failed at the declared two-second settlement deadline with the shared blocking pool. Current production sources passed the same case after four captured provider calls, caller disconnects and saturated review intake. All five independently counted effects remained exactly one, with unchanged fifth-operation charge after actual writer restart. Three worker lifecycle cases and the owning transport case passed.

Actual LangGraph 1.2.12 StateGraph and CrewAI 1.15.23 Crew each used an unchanged Rust-owned command over TCP to the protected Linux listener. Each produced one useful workload effect, identical native replay and fresh refusal after capability revocation. Their checkpoints and tool outputs contained only fixed categories and opaque references. The pinned adapter/bounds suite passed four tests; upstream CrewAI deprecation warnings are retained.

The native positive uncovered a stale consumption timestamp sampled before reconciliation. A non-cloneable kernel-prepared commit now supplies the fresh trusted clock after lease acquisition, outside all locks. Physical commit rechecks the original signed grant, original deadline, lease and current flow. No existing timestamped evidence is renewed. The default-stack native capture/replay case and two affine ownership compile-fail cases passed.

Both qualification hosts explicitly select the same bounded 120-second debug-fixture HTTP wait. The client default remains 20 seconds. Neither wait budget changes native authority, outstanding-work bounds or retry behavior.

Evidence: `evidence/task-4-host-acceptance/result.json`, actual native/transport logs and the task ledger. These model-free integration results are separate from Task 5's live-model comparative trials.

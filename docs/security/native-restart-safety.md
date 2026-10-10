# Native failure and restart safety

M2 qualifies the native lifecycle over disposable SQLite authorities and real
child processes. The process matrix lives in
[the control-plane harness](../../crates/platform/chio-control-plane/src/security/adapters/native_flow_process_recovery.rs).
The complete named inventory and affected local gates passed on 2026-09-12;
see the [acceptance closeout](launch-status.md#m2-local-acceptance-closeout).
This is not confinement, external-caller, deployment or release evidence.

## Safety contract

The process/race campaign found and fixed an overlapping-start ownership bug:
an exact retry could attach to a still-live operation, enter recovery and reverse
the first evaluation's hold. The existing serving-fence sequencer now owns a
process-local set of live tool operations. An affine guard excludes duplicate
evaluation and background recovery until the original evaluation returns, is
cancelled or unwinds. It does not hold the mutation mutex across callbacks or
awaits and is not a durable lease or dispatch permit. Independent operation IDs
remain concurrent; actual SQL fences and credential custody remain mandatory.

The dispatch commitment is an accounting boundary, not proof that an external
effect happened. A process can die after capture and before the connector accepts
the call. Recovery retains that capture as outcome-unknown, even when this test's
independent effect log contains zero effects. Absence from a local log is not an
authenticated downstream non-acceptance proof.

No historical ledger, receipt, input taint join, declassification consumption or
signed nonce becomes a new live dispatch or release owner. A new serving epoch
fences the old owner, verifies the anchored history, and reconciles the original
operation before declaring readiness. Unresolved release custody blocks readiness.

## Named cutpoint matrix

All rows use the production native resolver, real combined SQLite capture and
the normal registered connector. Hooks observe boundaries or terminate the child;
they do not fabricate successful capture or output owners.

| Boundary | Native process cases | Required observation after restart |
| --- | --- | --- |
| Before participant acquisition | `baseline_before_participants` | No effect or quota reservation; original operation compensated |
| Reversible reservation | `baseline_reversible_reservation`, `combined_reversible_reservation` | Original hold reversed once; runtime, approval and DPoP release episodes retained |
| Before combined commit | `*_capture_transaction_rollback` | Process dies with an open physical transaction; capture, accounting and credential transitions roll back together |
| Commit before anchor synchronization | `*_database_commit_before_anchor` | Database extension verified on new-owner open; capture retained and unknown, no refund or resend |
| Capture before connector acceptance | `baseline_capture_before_connector` | Zero observed effects but captured quota and unknown disposition remain |
| Effect may have started | `*_effect_started` | Exactly one synced test effect, no repeat invocation, outcome unknown |
| Outcome persistence/evaluation | `baseline_return_persisted`, `baseline_evaluation_started`, `baseline_output_resolved` | Original outcome retained; missing live release owner never reconstructed |
| Output/use outcome join | `declassification_output_joined` | Use outcome stays released (connector reached), not proof of delivered output; no release checkpoint invented |
| Release acknowledgement/checkpoint | `baseline_release_acknowledged`, `*_release_checkpointed` | Missing checkpoint blocks output; existing exact checkpoint recovers original signed terminal receipt |
| Terminal projection before receipt append | `baseline_terminal_projected` | Original receipt projection repaired and replayed; no second effect or release |
| Authority restart/replacement | Every child case | Old fence rejected; competing serving owner refused; same retained request and original commitment preserved |

The profile prefixes are baseline, combined runtime/approval/DPoP, nonce,
declassification, and cumulative approval accounting. The matrix exercises each
interaction where it changes an invariant, not a Cartesian product. Cumulative
cases preserve the original USD 60 authorization and the shared account's exact
reserved/captured totals. Nonce tests execute a real signed preflight before the
child's dispatch. Declassification consumption preceding capture remains pending
on rollback or unknown effect; it is not refunded and inherited taint is not lowered.

Run the focused gate on a Unix host with the repository toolchain:

```bash
./scripts/check-native-restart-safety.sh
```

The gate requires 34 named process/race tests (31 child-death scenarios and three
live races), plus five live-ownership tests. The existing exact-inventory runner
rejects missing, unexpected, failed or ignored tests. The same tests are required
by the composed `check-flow-security.sh` gate; a successful filtered Cargo command
alone is not the inventory check.

## Races

- `duplicate_native_start_cannot_steal_the_live_operation`: a second request
  overlaps the first operation's capture boundary. It cannot compensate, capture
  or execute on behalf of that live owner.
- `revocation_wins_before_native_capture`: revocation completes before capture;
  there is no effect or captured quota.
- `revocation_after_native_capture_fences_connector_handoff`: revocation after
  capture blocks connector handoff while retaining capture.
- `competing_native_recovery_workers_converge_on_original_terminalization`:
  concurrent workers reconcile the checkpointed original; repeated receipt replay
  has identical canonical bytes.
- `late_caller_report_cannot_replace_native_unknown_outcome`: a report races
  restart recovery of a nonce-bound native effect. The caller transport is not
  authorized for that original operation and cannot replace its unknown outcome.

## Downstream effects and output delivery

This milestone makes no generic exactly-once network-effect promise. A connector
that needs retryable remote effects must supply both a stable operation-bound
idempotency key and an authenticated status/non-acceptance contract. Status must
bind the original destination, request and effect identity; a timeout, missing
reply, stale ledger read or unauthenticated absence does not satisfy that contract.
Without it, the supported disposition is retained uncertainty, not automatic
resend, refund or a fresh credential reservation.

A release checkpoint authorizes replay of the exact guarded response and receipt.
It does not prove that a client received the response. The synchronous API may
return that same response again when a client retries; this is not a second
connector invocation or a second release callback. Durable remote delivery and
caller start/report semantics belong to M3. Missing original release custody is
a fail-closed recovery requirement, not a permission to re-run guards with a new
owner or claim successful delivery.

This preserves the existing
[durable final-release contract](launch-plan.md#durable-final-release-checkpoint-and-replay-containment).
Losing a live release owner without a checkpoint is a tested fail-closed stop:
`Finalizing`, captured quota and the original outcome remain retained, and startup
withholds readiness. It is not successful automatic terminal recovery. This
availability limitation must remain explicit in deployment and recovery claims.

## Qualification boundary

The local process tests deliberately terminate without Rust destructors, after
syncing their external effect witness. They reopen actual files under a new
serving epoch. They do not simulate power loss, disk-controller cache failure,
host compromise, Linux x86_64 cage enforcement or the M6 enterprise topology.
The user-approved M1 confinement deferral remains in
[the status index](launch-status.md#m1-confined-process-qualification-deferral).

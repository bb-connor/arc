# Maintained recovery lifecycle and owners

Status: intended production path traced, with a concrete integration gap.
This is not a currently passing end-to-end execution or a runtime qualification.

The public surface is `RecoveryRuntime` and the recovery HTTP router in
`crates/platform/chio-control-plane/src/recovery/`. The Kernel owns authorization
and native execution; Process owns frozen request identity and logical-call
custody; the serving Store owns authenticated durable projections.

The selected native output-retention route calls
`ChioKernel::prepare_original_native_finishing_before_first_purpose`. It holds
the native mutation sequencer, reloads the exact retained original, obtains a
recovery lease and calls `AdmissionOperationStore::prepare_original_native_finishing`.
That default returns Unsupported/Unavailable. A marker or fabricated success
would not supply the missing physical account, Process enrollment or receipt
producer. This is an incomplete production connection, not redundant code that
can be bypassed to make the existing contract pass.

## Traced public support-disclosure route

| Step | Concrete owner and source | Required boundary |
|---|---|---|
| Decode HTTP envelope and command | ControlPlane `recovery/transport.rs:145` | Raw size/duplicate/type validation precedes authenticated work allocation. |
| Admit bounded command work | `transport.rs:155`, `runtime.rs:176`, `command_executor.rs:230` | Caller disconnect cannot cancel accepted native work; principal fairness and reserved settlement capacity survive. |
| Create/select/replay command | Kernel `recovery_runtime/command_selection.rs:96`, concrete recovery port | Process original snapshot precedes native BEGIN; selected command generation cannot be upgraded by an alias. |
| Materialize exact action | ControlPlane `materialize.rs:64` | Freeze source label, observed basis, original identity, recipient, purpose and action before the Process cross-store reservation. |
| Reserve Process call | `chio-process/src/recovery.rs:91`, `store/recovery.rs:33` | One logical-call charge; repeat reservation compares exact immutable bytes. |
| Review and approve | `materialize.rs:256`, `materialize.rs:292`, Kernel reserve/command ports | Audience-safe exact preview, current actor and basis; no effect authority from a rendered summary. |
| Issue and retain signed grant | `materialize.rs:354` | Existing reservation, coverage and bounded deadlines; signing outside Store transactions; exact retained issuance survives lost acknowledgement. |
| Finalize frozen Process call | `chio-process/src/recovery.rs:118`, `store/recovery.rs:86` | Native-verified custody, complete route/security/retry binding, original nonce only. |
| Invoke | `runtime.rs:301`, `chio-process/src/lib.rs:425` | `known_outcome_only=true`; unknown outcomes never create a second attempt. Ordinary Process invoke is reused. |
| Prepare physical completion ownership | Kernel `credential_reservation/operation_owned.rs:54` and `native_finishing.rs:30` | This is the missing current native integration described above. It occurs before one-shot/native purpose acquisition. |
| Observe/release result | `runtime.rs:312`, Kernel `recovery_runtime.rs:159` | Fresh current actor/source clearance; retained Completed operation and native output custody determine release. |
| Reconcile after interruption | Kernel `recovery_runtime.rs:232` | Operate on exact original; compensate pre-dispatch, settle Finalizing, retain uncertain dispatch. No generic invoke retry. |
| Explicit settlement | `runtime.rs:384`, `transport.rs:204` | Separate Settle permission and owned reserved workers; no new continuation. |
| External finality lookup | `runtime.rs:411` | Current observation authority/deadline and reserved lookup budget, then fresh authentication on return. |

This trace identifies the intended continuation and recovery path. It does not
claim that the missing physical finishing stage currently succeeds. Full
capture/Store retirement internals remain to be examined within allowed scope.

The original is not selected from a bare request ID. Process
`store/original_snapshot.rs:51` opens the retained journal read-only, verifies
its namespace, authority, key and file identity, and requires exactly one
matching charged call. Store `recovery/original_resolution.rs:5` verifies the
host-issued scope and exact native namespace; `:127` permits only a
`ToolDispatch` already `CompensatedBeforeDispatch` with no dispatch commit.
Subsequent revalidation reloads that exact operation and terminal projection.
Those are required ownership checks across two databases, not redundant
lookups that can be collapsed into trusting a client request ID.

The provider-aware Kernel entry points do exist at
`evaluation/evaluation_entry.rs:52` and `:65`. They carry an optional actual
Process source to the preparation hook. The pinned repository search found no
Process caller of either entry point. The concrete Store has no override of
`prepare_original_native_finishing`; the trait default at
`admission_operation/store.rs:188` refuses. Thus this is an incomplete
integration on both sides of the public hook, not an absent API declaration.

## Duplication and ownership observations

The Process facade and its SQLite reservation writer are not competing runtimes:
the facade verifies Kernel custody and complete request identity; the Store
performs the atomic identity/charge commit. Keep this separation.

The HTTP command path currently retains an outer admission permit in a Tokio
blocking task, calls `Handle::block_on`, then waits for a separate owned command
worker with its own Tokio runtime and principal permit. This is a concrete
consolidation candidate. A replacement must transfer the outer permit to the
accepted owned job, not drop it with a disconnected HTTP future. Independent
settlement/finality capacity and pre-admission authentication remain required.

`execute_command` canonicalizes and validates an immutable command before
cloning it into the owned job. Its private `execute_command_inner` repeats the
same pure canonicalization/decoding. Remove the inner duplicate pass after
verifying its only caller; keep raw HTTP validation, public typed-entry bounds
and all fresh authority checks. This proposal is distinct from removing repeated
authentication, which is intentionally required across mutable authority cuts.

The older Kernel `execute_recovery_command` and
`execute_recovery_command_with_origin` routes share an older private command
pipeline. The maintained ControlPlane uses
`execute_recovery_command_outcome_with_origin`, which returns the immutable
selected generation and prevents historical/alias replies from driving fresh
work. Pinned source searches found the old routes' call sites in tests, not
another production host. Consolidate command selection and origin preparation
behind one core; retain thin compatibility wrappers only if they are a declared
public API. Retarget meaningful replay/conflict/alias tests to that core rather
than keeping two security-sensitive pipelines because tests call both.

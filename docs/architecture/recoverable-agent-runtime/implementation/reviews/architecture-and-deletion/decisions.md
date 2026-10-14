# Deletion and consolidation decisions

Status: bounded architecture review recorded against the subject in README.md.
These are specific proposed edits, not applied changes or runtime acceptance.
No deletion-line estimate is offered without an implementation and its diff.

Paths below are relative to the named crate's `src/` directory unless a full
repository path is given. Line numbers refer to the pin, not the moving checkout.
Confidence is high for observed code/callers, moderate for the eventual net
reduction, and unknown for external consumers of experimental formats.

## Small changes with direct source justification

| Proposed change | Source and caller evidence | Required preservation |
|---|---|---|
| Delete the private duplicate command encode/decode | ControlPlane `recovery/runtime.rs:208-211`. Public `execute_command:176` performs the same pure validation before cloning the immutable command; `:199` is the sole caller of private `execute_command_inner`. | Keep raw HTTP decoding, public typed-entry validation and fresh actor/mediation checks at `:212` onward. Existing typed/raw malformed-command tests must still pass. |
| Delete the never-produced advisory variant and import | `chio-recovery/decision.rs:33`, `WorkflowDirective::RequestApproval(ApprovalIntentRef)`. `workflow.rs` never produces it; no in-repository constructor or match was found. | Keep `ResumeNativeApproval`, reconciliation and the current workflow tests. This is a new public non-wire enum; check declared external API consumers before publishing the change. |
| Rename current restore `Legacy` to `Inline` | Store `knowledge/checkpoints/restore/encoding.rs:35`, `:242`, `:265`. The current writer emits this representation at `:248`, so it is not an obsolete decoder. | Preserve untagged serialized bytes, variant order, canonical preimages, small/large label bounds and compact/chunked decoding. This removes misleading terminology, not persisted data. |

The first deletion is a directly local implementation simplification. The enum
change is safe for observed repository consumers; this review cannot prove
there are no external Git consumers. None requires deleting security tests.

## Consolidate owners and mechanisms

| Proposed change | Exact surface and destination | Exit checks before accepting the change |
|---|---|---|
| One command-selection implementation | Kernel `admission_coordinator/recovery_runtime.rs` older `execute_recovery_command` / `_with_origin` private pipeline and `recovery_runtime/command_selection.rs`. The maintained ControlPlane calls `_outcome_with_origin`; old entry points have test callers. Make immutable selection/origin preparation the shared core. | Preserve historical-response read-only behavior, generation CAS, alias identity, origin proof and fresh authorization. Thin public wrappers may remain if supported; do not retain a second security pipeline solely for old test call sites. |
| One accepted HTTP job owner | ControlPlane `recovery/transport.rs:165` outer `spawn_blocking` / `Handle::block_on`, `recovery/runtime.rs:198` and `recovery/command_executor.rs`. Transfer the outer admission permit into the existing accepted job and remove the extra waiting blocking task. | Caller disconnect must not cancel accepted work or release capacity early. Preserve authentication before intake, principal fairness, overload refusal, and separate settlement/finality workers. Do not replace this with an unbounded generic task spawn. |
| Replace reservation JSON round trips with typed conversion | Process `recovery.rs:15` `RecoveryCallReservation`, Kernel `recovery/records.rs:424` `RecoveryProcessReservationV1`; conversions occur at ControlPlane `materialize.rs:243` and Process `recovery.rs:186`. The nine fields match. Put explicit conversion in Process, which already depends on Kernel, or use one shared data representation. | Keep private Process construction and actual journal verification. The public DTO remains descriptive data, never a custody proof. Preserve exact persisted canonical bytes and request/binding comparison. Do not introduce a reverse crate dependency or expose private mutation authority. |
| One exact predecessor-catalog verification per migration transaction | Store `schema.rs::migrate_schema`, `schema/recovery_format_migration.rs`, `command_alias_format.rs`, `captured_terminal_format.rs`, `knowledge_encoding_format.rs` repeatedly verify versions 35/36. Centralize the shared catalog check in the owning transaction. | Preserve all family-specific exclusions of future data, exact schema validation, rollback, quarantine and downgrade refusal. Delete repeated checks only after proving they observe the same transaction snapshot. |
| Express required setup dependencies in the type | ControlPlane `recovery/setup.rs:68`, `:125` reject missing knowledge immediately. Make the supported host composition take its required knowledge mediator directly. | Keep typed configuration errors at the external construction boundary; check public constructor consumers. Preserve the actual native benign/denial/restart exercise. |
| Factor bounded graph validation only where semantics agree | `chio-semantic-contracts/graph.rs:48`, `plans.rs:6`. Identity/dependency/cycle checks overlap; sequential smallest-ready order and sorted-layer order differ. | Preserve each format's ordering, future-output rules, bounded work and limits. Prefer a small private helper, not a generic graph subsystem. Do not fold the small package acyclicity loop into a new framework just to claim deduplication. |

The HTTP ownership and migration consolidations are architectural repairs, not
mechanical deletions. They need their stated public-interface checks. The small
DAG and setup changes are lower priority than completing the native lifecycle.

## Conditional removal of experimental compatibility

Choose and publish the supported incoming formats before changing these paths.
The proposed default is the pre-recovery baseline plus the selected current
format, with explicit refusal or a separate offline migration for unsupported
intermediate data. Actual external consumers are unknown. Existing development
data must have a disposition; absence from a release tag is not that disposition.

| Removal unit | Concrete paths | Conditions and tests that remain |
|---|---|---|
| PR-local admission predecessors | Store `schema/` guards for incoming 35-39 and their modeled-upgrade helpers | Remove only incoming compatibility branches proven unnecessary by the support decision. Keep current 40 tables/features, baseline guarded migration, exact catalog refusal, current restart and downgrade refusal. These guards may still contain checks needed by the retained path, so do not simply delete the four files. |
| Old checkpoint keys | `knowledge/checkpoints/head.rs:35`, `:109`, `:143` and `checkpoints/legacy_test_support.rs` | Remove raw-key/ambiguous-slot/highest-revision fallback together with the old-format acceptance claim. Keep framed current keys, exact id/revision verification, atomic pins and adversarial current-key tests. |
| Publication identity without actor binding | `admission_operation_store/knowledge.rs:188-207` and the optional predecessor publication principal | Require a migration attribution or quarantine policy for retained records. Never assign historical records to a new actor by guessing. |
| Earlier reference-readiness markers | `knowledge/references/ready.rs:48-67` and conservative history-scan branches at `knowledge/lifecycle.rs:247-301` | Remove as one format-support unit. Current V3 writer coverage, authenticated activation and reference custody stay. An empty incomplete index must not mean collectible. |
| Shared-object predecessor collection keys | `knowledge/lifecycle.rs:39-54`, `:111-192`, `:509-524` | Confirm supported objects use independent `object:<uuid>` seals. Preserve barriers for all owners of any remaining shared bytes and exact modern seal verification/orphan cleanup. |
| Old interned-label journal reader | `security_participant_state/knowledge/encoding.rs` old `interned_labels_v1` branch and `knowledge/encoding/legacy_labels.rs` | Establish retained native-journal compatibility first. Keep current atom/chunk codec, restricted labels, row bounds and exact authenticated reconstruction. |
| Modeled semantic predecessor producers | `chio-semantic-contracts/verification.rs:141-196`; Store `semantic/legacy_annotation_capture.rs`, `legacy_status_capture.rs`, `legacy_input_floor.rs` test-support consumers | Replace with provenance-bound immutable fixtures or an offline generator if their supported upgrade obligation remains. If it does not, remove the old-only fixture/test family. Keep current annotation/status/input-floor refusal tests and public native positive-path tests. |
| Wider retained semantic plans | `chio-semantic-contracts/plans.rs:11`, retained sixteen-step bound versus fresh eight-step validation | Decide whether retained wider plans are a supported historical format. Preserve current fresh bounds and exact replay identity. Do not silently truncate old plans. |

Process journal versions 2-7 also represent enforced operating modes, not merely
obsolete row layouts. Do not remove them as a numeric range. Preserve the
knowledge-enforced/raw-refused state, unused-reservation closure and delivery
ordering against Stop in the chosen representation. Pre-existing unlabeled
blob quarantine and Process ABI compatibility are required independently of
whether PR-local input formats remain supported.

## Required, incomplete and optional surfaces

| Surface | Classification | Decision |
|---|---|---|
| Kernel/Store native finishing hook, Process participant capsule methods | Incomplete | Concrete Store methods still default to `Unavailable`; Process does not call the provider-aware Kernel entry point. Keep the gap explicit. Implement the coherent connection within permitted scope, or remove the whole feature from supported claims. Do not bypass the refusal or label the unused hooks redundant. |
| Kernel authorization, native Store durable state, Process charge/request journal | Required, distinct owners | Keep cross-owner identity and custody checks. They are not three implementations of one state machine. |
| Workflow control, effect observation and output release state | Required, distinct facts | A cancelled workflow can still owe settlement; a completed effect can still be withheld. Do not flatten into one success/failure enum. |
| Historical deployment roots and captured custody | Required | Settlement after same-version key/policy rotation still requires original evidence. Removing experimental database upgrades does not remove this requirement. Current disclosure authorization remains fresh. |
| Pure explanation engine and semantic contract verifier | Required, distinct layers | Retain effect-free dependencies, audience projection before search and full report recomputation. A semantic verdict grants no native effect authority. |
| `advise_workflow` pure utility | Optional supported API, not the native driver | Observed consumers are workflow tests, a pure benchmark and `fixtures/recovery-portable-consumer`. Keep with accurate claims, or remove it and update the benchmark/portability fixture after deciding the public surface. Do not add a production call merely to silence unused-code concerns. |
| LangGraph and CrewAI adapters | Required thin framework surfaces | Both reuse one native session/client. Keep framework-specific async/sync behavior and exact command identity; no second recovery engine was found here. |
| Confined host around `chio-cage` | Required integration, acceptance incomplete | Reuses the existing launch implementation. Keep current disabled channels, fresh audience checks, non-cloneable return custody and delivery acknowledgment. This review supplies no Linux acceptance. |
| The questioned legacy terminal assertion | Required while that regression is supported | It proves the workflow actually reached capture, admission closure and settlement before retirement is inspected. Deleting it would weaken the test into possible false success. Remove the entire unsupported predecessor scenario only after the format decision; keep current lifecycle acceptance. |

## Packaging proposals

Historical evidence and generated output need different treatment from runtime
source. [Packaging](packaging.md) specifies archive integrity, current versus
historical verifiers, generated consumers and maintained vendor patches. These
are distribution/contributor-experience changes, not proof of fewer runtime
implementations. Archive retrieval must work before expanded evidence is removed.

## Execution order

1. Reconcile this pin with the executing session before touching shared source.
   Keep one owner for Kernel/Store/Process; do not apply line-based deletions to
   a changed file without inspecting the new implementation.
2. Apply the small local duplicate removal and misleading-name correction.
   Review the new enum's supported API, then remove its unused variant.
3. Decide supported incoming data. Prune each unsupported predecessor as one
   unit with its old-only helpers, tests and documentation; preserve current
   security regressions. Do not invent another permanent compatibility layer.
4. Consolidate command selection, accepted-job ownership, reservation conversion
   and migration verification. Complete the native connection before claiming
   the lifecycle works. Parked dependencies stay explicit, without bypasses.
5. Package history separately. Modularize the owned qualification verifier
   without making it trust producer output or weakening recorded thresholds.
6. Run the affected public-interface checks, then broader acceptance on a fixed
   source. These review proposals are not P1/P2 closures and do not change the
   existing remediation register. Qualification remains open.

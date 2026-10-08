# Current Chio kernel readiness for macOS

> Historical research snapshot retained for provenance. [ADR-0038](../../../../adr/ADR-0038-desktop-operator-program.md), the [program map](../../../../architecture/PROGRAM-MAP.md) and [macOS annex](../ANNEX.md) supersede this document's former implementation choices. Old NK identifiers and platform methods below are historical proposal labels, not current APIs or blanket desktop prerequisites. The shared program retains the needed admission, crossing and ABI safety properties through their owning contracts; it does not require all three redesign keystones before the first product.

Status: inspected source, not runtime qualification. Confidence: high for the named presence/absence findings; unknown for a delivered Mac execution profile. Inspected 2026-10-07. This report supersedes older research assumptions about what exists on main, without promoting candidate designs to implementation.

## Source identities and method

| Source ID | Exact inspected identity | Use |
| --- | --- | --- |
| CHIO-MAIN | `6573b8980a1e5331028b7e688169f033a39d0384`, current specification worktree base | Current code, ownership, available tests |
| CHIO-NORTHSTAR | `8dffff3da53dfb56da8e60019af5e3ae896f7f5b`, separate local source checkout | Proposed kernel architecture; not code availability |
| OMARCHY-SPEC | Local Omarchy specification worktree at `docs/superpowers/specs/2026-10-07-omarchy-integration/` | Precedent for one authority and evidence gates; no inherited qualification |
| MAC-RESEARCH | Approved `research.md` retained beside this report by the package owner | Product and platform research; source findings refreshed here |

These IDs denote source inputs. Their local paths and pin metadata are recorded in `source-pins.json`. Code paths below are relative to the source ID, so an absent main path cannot accidentally be read as a shipped API. `git rev-parse HEAD`, a tracked-file census, symbol searches over `crates/`, and focused reads established the findings. No build, installed executable, signed app, entitlement activation, or runtime test was performed for this report.

## Existing code and precise limits

| ID | CHIO-MAIN path and symbol | Existing behavior | Limit for this program |
| --- | --- | --- | --- |
| CK-01 | `crates/kernel/chio-kernel/src/admission_operation/identity.rs`, `AdmissionOperationBindingV1`, `AdmissionReplayKey`, `DurableAdmissionMode` | Native operation identity, request/policy/participant binding and replay keys; durable modes distinguish coverage | A desktop request UUID is not this identity; the current vocabulary is not the proposed pure machine |
| CK-02 | `crates/kernel/chio-kernel/src/admission_operation/store.rs`, `AdmissionOperationStore::{begin,load_by_operation_id,load_by_replay_key,compare_and_swap,list_recoverable,load_terminal_replay}` | Created/exact replay/conflict outcomes, versioned mutations, recoverable listing, retained terminal result | No generic desktop task/process API follows from these storage methods |
| CK-03 | Same file, `QualifiedAdmissionOperationStoreExt::claim_recovery`; `admission_operation/sequencer.rs`, `AdmissionMutationSequencer` | Recovery claims re-read exact persisted state and historical coordinator lease under a fence; mutation sequencing is fence-scoped | Claim qualification is a native trust boundary; a caller-provided claim cannot substitute |
| CK-04 | `crates/platform/chio-store-sqlite/src/serving_owner.rs`, `SqliteAuthorityStore::{provision,open_serving,mutation_fence,budget_store,revocation_store,admission_operation_store,tool_outcome_store}` | One shared connection and owner fence for these projections; provisioned path/device/inode checks; exclusive serving lock | This is a usable ownership substrate, not the north-star exhaustive crossing transaction |
| CK-05 | `crates/platform/chio-store-sqlite/src/serving_owner/global_commit_chain.rs`, `rollback_anchor.rs`, `lease_history.rs` | Durable commit chain, rollback anchor and serving lease history | Restoring database and local anchor together is not proven safe by this mechanism alone |
| CK-06 | `crates/platform/chio-store-sqlite/src/rollback_generation.rs`, `require_separate_snapshot_domain` | A particular generation-anchor helper rejects database and anchor on the same device | This is not a universal whole-Mac anti-rollback service; APFS volume names or adjacent files do not establish independence |
| CK-07 | `crates/kernel/chio-kernel/src/tool_outcome.rs`, `tool_outcome/release.rs`, `tool_outcome/post_return.rs`; SQLite `tool_outcome_store.rs` | Durable tool-return and post-return contracts, bounded retained output, typed release authority | Host effect, return capture, delivery and monetary release remain distinct facts |
| CK-08 | `crates/kernel/chio-kernel/src/kernel/construction.rs`, `emergency_stop`, `emergency_resume`, `is_emergency_stopped`; `kernel/kernel_struct.rs` | In-memory `AtomicBool`, time and reason; initialized to running during construction | No durable stop chain or restart-surviving stop generation is present |
| CK-09 | `crates/kernel/chio-kernel/src/approval.rs`, `ApprovalRequest`, `ApprovalToken::verify_against`, `ApprovalStore` | Request/parameter/subject/approver/time checks and governed approval token; canonical parameter hash | Does not establish current knowledge commitment, selector, deployment-roster or semantic endorsement adaptation |
| CK-10 | `crates/kernel/chio-kernel/src/authority.rs`, `ensure_capability_issuance_supported` | Function currently returns `Ok(())`; response validation separately checks issuer, signature, subject, scope and expiry | It does not currently reject unsupported `RequiredIntegrity`, which is itself absent; enforcement support must be added with that constraint |
| CK-11 | `crates/kernel/chio-kernel/src/capability_lineage.rs`; SQLite `capability_lineage.rs`, `record_capability_snapshot`, `get_lineage`, `get_delegation_chain` | Receipt-linked capability snapshots and lineage query | Historical lineage observation is not an eager fenced capability derivation tree |
| CK-12 | `crates/economy/chio-metering/src/budget_hierarchy.rs`, `BudgetTree::{insert,validate,ancestors,descendants,evaluate}`; SQLite `budget_store/composite/` | Hierarchical budget evaluation and separate atomic composite budget machinery | Does not prove one sealed process-tree ledger, child signer custody or every budget dimension in one crossing |
| CK-13 | `crates/kernel/chio-kernel/src/custody.rs`, `PasskeyCapabilityVerifier`; SQLite `authority.rs`, `SqliteCapabilityAuthority` | Passkey capability signature/audience/expiry verification; native authority persistence and rotation | Neither a Swift approval signer nor process/child custody should be inferred from these APIs |
| CK-14 | `crates/kernel/chio-kernel/src/evidence_export.rs`, `EvidenceExportQuery`, `EvidenceExportBundle`; SQLite `evidence_export.rs`, `build_evidence_export_bundle` | Receipt export with explicit read boundary, lineage, checkpoint inclusion proofs, uncheckpointed rows and retention metadata | Current export does not by itself contain Mac launch/ES/NE/VM evidence or complete native operation closure |
| CK-15 | `crates/kernel/chio-kernel/src/checkpoint.rs`, `validate_checkpoint`, `verify_checkpoint_transparency_records`; `checkpoint/consistency.rs` | Signed checkpoints, continuity and transparency-record validation | Local checkpoints and derived witness records do not prove an independently operated public witness |

## Missing contracts and native owners

Exact symbol search over CHIO-MAIN `crates/` found no declarations for `AdmissionState`, `KernelOp`, `CrossingKind`, `StopEpochV1`, `RequiredIntegrity`, `InfluenceStateV1`, `ScopedEndorsementV1`, `ProcessRuntime` or `CausalLineageStore`. The `crates/kernel/chio-process/`, `crates/products/chio-desktop/` and `integrations/macos/` implementation scaffolds are absent. This absence is pinned to CHIO-MAIN, not a claim about every development branch.

| Gate | CHIO-NORTHSTAR design source | Required owner and disposition |
| --- | --- | --- |
| NK-01 | `docs/superpowers/specs/2026-10-04-pure-admission-machine-design.md` | Kernel-core owns pure `AdmissionState`/`AdmissionEvent`/`Transition`; kernel shell and recovery are drivers, not alternate classifiers |
| NK-02 | `docs/superpowers/specs/2026-10-04-crossing-primitive-design.md` | Native admission store and serving writer own checks, expected-version CAS, reservations, record, commit and required anchor before acknowledgement |
| NK-03 | `docs/superpowers/specs/2026-10-04-closed-kernel-abi-design.md` | Kernel-core owns registry; every live binding/route has an op/non-op classification and L0 descent; native resource intake and publication preparation require authenticated bridge/census registration; published version must reflect delivered symbols |
| NK-04 | `docs/superpowers/specs/2026-10-04-durable-stop-epoch-design.md` | Native owner implements signed generations, pending intent durability, restrictive latch, current-head resume and per-crossing dispositions |
| NK-05 | `docs/superpowers/specs/2026-10-04-integrity-gated-admission-design.md` | Native knowledge owner supplies monotone observation sets; same-writer endorsement adaptation, action selectors, freshness and consumption; resource owner binds sealed bootstrap before task readiness and current publication policy/influence; desktop only requests review |
| NK-06 | `docs/superpowers/specs/2026-10-04-authority-space-teardown-design.md` | Native lineage/closure owner supplies complete descendant cut or explicit incomplete/refused result; no PID-only authority tree |
| NK-07 | `docs/superpowers/specs/2026-10-04-typed-reservations-design.md` | Kernel reservations owner supplies compensable holds versus irreversible commitments, explicit release authority, post-effect obligations and recovery |
| NK-08 | `docs/superpowers/specs/2026-10-04-unified-event-queue-design.md` | Session-record owner supplies stable subscription identity; notification positions do not authorize or establish crossing order |
| NK-09 | `docs/research/2026-10-04-chio-kernel-north-star.md`, bets 4 and 7 | Process/custody maintainer must deliver process tree, child custody and generation-safe restoration; these research bets are not delivered contracts |

The plans assign acceptance work to these native owners. A missing native owner blocks mutation and execution for the dependent profile. A controller may report an unavailable prerequisite; it cannot implement a parallel positive-authorization ledger to close it.

Two concrete resource prerequisites remain unavailable on this inspected baseline and are delivered under NK-03/NK-05 with the native resource/authority owners. First, authenticated trusted intake accepts a bounded selected-resource handle and task-input capture, seals separate workspace and task-input resources, and returns verified native `resource_ref`/`input_ref` before `task.create`. Second, typed native publication preparation accepts the sealed artifact, enrolled destination identity/generation, exact filename, expected-absent target condition and current policy/influence bindings, then returns the original native operation reference used by `review.open`/`approval.submit`. Preparation creates no filesystem publication effect. Both routes require closed native census and actual native verification; neither is an extra public operator method, an `evidence.export` shortcut or authority implemented in the desktop. [The current artifact and resource handoff](../ANNEX.md#optional-sealed-coding-work-approvals-and-safe-artifacts) and the shared work/runner owners now control the acceptance handoff; the M0/M4 references belonged to the retired program.

## Cross-program dispositions

| Earlier proposition | Disposition for Mac |
| --- | --- |
| Candidate process-host APIs are available on main | Rejected for this base. CK-01 through CK-15 are present; NK-09 must be selected, integrated and tested separately |
| Passing component approval tests qualifies exact publication | Rejected. Publication requires native review binding, same-writer consumption and observed exact host effect |
| Linux x64 cage evidence covers an ARM64 Linux guest | Rejected. Guest architecture, confinement policy, inherited channels and host release must be measured on the exact profile |
| A local emergency-stop flag proves reboot-safe stop | Rejected. CK-08 is only the current in-memory mechanism; NK-04 and recovery acceptance remain open |
| A verified signature makes external input trusted | Rejected. Signature proves a signer; authority to assert bootstrap trust or endorse one action is separate and generation-bound |
| The three-commit path proves a Mac performance target | Rejected. It is a proposed optimization with participant exceptions and no Mac baseline here |
| Hints and ES/NE observations establish operation order | Rejected. Native crossing order, sensor event IDs and stable subscription IDs are different domains |

## Existing regression entry points and future closure

Useful current commands are `cargo test -p chio-store-sqlite --lib recovery_claims_`, `cargo test -p chio-store-sqlite --lib serving_owner::tests`, `cargo test -p chio-kernel --lib emergency_`, and `cargo test -p chio-kernel --test durable_admission_sqlite`. They are future execution commands, not tests run during this source-only pass. Their named source tests cover claim fencing/time, owner concurrency, snapshot rollback and current stop behavior. They do not close NK-01 through NK-09.

For every gate, retain source revision and blob hashes, actual exported symbols, component test results, installed binary hashes, exact OS/CPU/runtime/ABI/store tuple and independently observed acceptance outcomes as separate evidence classes. Missing, synthetic, skipped, stale, wrong-architecture or incompatible evidence yields unavailable. Read-only `observe-v1` can show that state; all other profiles require their declared native and platform gates in [shared qualification](../../2026-10-07-desktop-integration/QUALIFICATION.md). The task and evidence recovery behavior is specified in [shared operator projection](../../2026-10-07-desktop-integration/OPERATOR.md).

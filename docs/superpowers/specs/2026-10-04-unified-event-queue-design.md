# Design: session event log and shared hint vocabulary

- Status: PROPOSED (revision 3, re-baselined 2026-10-04 on #1160 + #1173 + #1172 + uncommitted recovery P0-P5 (W:))
- Date: 2026-10-04
- Scope:
  - Bound and terminalize the kernel session late-event queue used by the MCP edge (local and hosted).
  - Fix two hosted SSE replay defects.
  - Define one closed hint-subject vocabulary that each surface (kernel sessions, agent processes, recovery workflows, work) projects through the delivery mechanism it already has.
  - No new bus, no new durable event log, no signed events.
- Owners:
  - `chio-kernel`: session event log, subscription authorization, source router.
  - `chio-mcp-edge`: MCP projection.
  - `chio-mcp-remote`: hosted SSE replay, lag handling and restore.
  - `chio-process`: `inspect` hint revision.
  - `chio-core-types`: hint subject vocabulary.
- Related:
  - `spec/WIRE_PROTOCOL.md` section 3.2.
  - `spec/PROTOCOL.md` sections 4.3, 8.2 and 11.
  - M: `crates/kernel/chio-process/MAILBOXES.md` and `WORKER_PROTOCOL.md`.
  - R: `docs/architecture/recoverable-agent-runtime/03-recovery-protocol.md` and `08-protocol-operations.md`.
  - V: `docs/superpowers/specs/2026-10-03-work-runtime-design.md`.
  - `2026-07-12-admission-operation-design.md`: operational rows are not signed audit evidence.
- Origin: lessons from the FTL (nuta/ftl) review.
- Siblings:
  - `2026-10-04-ftl-lessons-program-design.md` (umbrella)
  - `2026-10-04-closed-kernel-abi-design.md`
  - `2026-10-04-authority-faults-design.md`
  - `2026-10-04-typed-reservations-design.md`
  - `2026-10-04-authority-space-teardown-design.md`
  - `2026-10-04-opaque-adapter-context-design.md`
  - `2026-10-04-microkernel-isolation-backend-design.md`
- Citations:
  - M: = `origin/integration/process-security-m4` at `19df31ad9` (PR #1160). V: = `origin/work/verifiable-work-session-20261003` at `14477aaac` (PR #1173). R: = `origin/research/openappa-recovery-20261001` at `de84fc306` (PR #1172). All three are treated as shipped.
  - W: = the uncommitted working tree of `standalone/arc-worktrees/recoverable-agent-runtime-20261002` (branch `feat/recoverable-agent-runtime-20261002`; recovery P0-P5 implemented locally, built on #1160 checkpoint `f25cd61f4`). It is treated as shipped. Line references reflect the working tree on 2026-10-04 and may drift.
  - R: and W1-W4 interfaces with no code are marked "assumed shipped (contract anchor)". Recovery documents that describe something absent from W: are marked "doc-only, not implemented in W:".
  - The cited kernel and `chio-mcp-remote` lines are identical on M: and V: unless a V: path is given.

## Revision 3 changes

- **Recovery hints come from the event chain, not an outbox.** W: implements no `recovery_deliveries` outbox, delivery cursor or per-delivery audience recheck (doc-only, R: `03-recovery-protocol.md:114`). Section 5.3 now projects `Recovery` and `Approval` hints from the hash-chained `admission_operation_recovery_events` (W: `crates/platform/chio-store-sqlite/src/admission_operation_recovery.sql:29-44`). Consumers re-read through `InspectWorkflow`, whose `revision` gives H8 resync.
- **Implemented vocabulary.** Hint meanings map to `WorkflowControlV1`, `EffectObservationV1` and `ReleaseDispositionV1` (W: `crates/security/chio-security-types/src/recovery/observation.rs:80-169`), not the doc-only adapter states (`WaitingForApproval` and so on).
- **The non-goal is restated.** No durable recovery outbox exists today. Hints are rebuilt from the event chain. If recovery later adds an outbox, hints project from it.
- **New rule H9 (audience).** Hints obey audience policy (P4 ART-10). An artifact appears only as an audience-scoped opaque handle. A confined child's status is withheld unless its return contract enables a status channel.
- **Confined-child leak check.** The revision 2 inference that confined-child status leaks through `wait_children` or `inspect` was checked against W:, and the worker-facing surfaces do not leak it today (section 2).
- **New finding: `inspect` fails under enforced knowledge.** The W: worker `inspect` handler always calls `storage()`, which refuses once durable knowledge is enforced. The whole op therefore errors (W: `crates/kernel/chio-process/src/worker.rs:156-162`, `src/lib.rs:282-288`, `src/store/knowledge.rs:16-26`). Section 5.2 adds rule P6: under enforcement, `inspect` returns the redacted public snapshot and omits `storage`. This is a W: defect independent of this design, unless the enforced profile deliberately excludes the worker service (W: states no such exclusion).
- **Open decision 1 is forced.** M: bumped `PROCESS_ABI` from v2 to v3 for native broker routes (commit `2a4c2fbe4`). W: independently bumped v2 to v3 for knowledge and recovery (W: `crates/kernel/chio-process/src/lib.rs:54`; base `f25cd61f4` is v2). The union is `chio.process.abi.v4`, and the `inspect` fields ride it.

## Revision 2 changes

- **Narrowed `SessionEventLog` to kernel sessions.** Agent process calls go through `evaluate_tool_call_with_metadata` and never open a kernel `Session` (brief-process A.1). Revision 1 hung every control subject off `Session`, which would have given the primary agent runtime no events.
- **Replaced "one queue for everything" with one closed subject vocabulary (section 4).** It is projected per surface (section 5). Processes, workflows and work keep their existing delivery mechanisms:
  - processes: mailbox `wait_ms`, `wait_children`, and the `inspect` hint revision;
  - workflows: recovery delivery cursors;
  - work: `WorkViewV1` re-query.
- **Added a recommended process-hint decision (section 5.2).** `inspect` gains an optional level-triggered wait. It consumes no call budget, emits no receipt, and leaves the six-op worker protocol unchanged. Mailbox channels and a seventh `wait` op were considered and rejected.
- **Approval and recovery hints now project from the recovery lane's outbox** (`recovery_deliveries`, R: 03:114) instead of a parallel source. The `AuthorityFault` subject is replaced by `Recovery`, because authority faults now feed recovery (`2026-10-04-authority-faults-design.md`).
- **Dropped the proposed `stream_incarnation` field.** The existing `resume_generation` seeds event sequences. It must be bumped and persisted on restore, because it advances only when a record is written (section 6.2).
- **Updated defect citations to M:/V:.** Lag sites are `http_service.rs:517,608,702,817,860`. Event-id seeds are `session_core/factory.rs:468,684`. The A2A `PendingApproval` mapping is fixed on M:/V: (now `Working`), so section 6.3 shrinks.
- **Cross-owner hints are recorded as a known gap with a direction (section 7)**, replacing the bare non-goal.
- **Dropped:** the kernel `EventRouter` for cross-session sources and the `Delegate`/`AuthorityFault` session subjects as v1 deliverables. Process and workflow surfaces already own those sources.

## 1. Decision summary

Chio has several partial event mechanisms, and each is shaped like FTL's poll. This design keeps them and gives them one vocabulary and one set of rules:

| Surface | Existing mechanism | Gap |
|---|---|---|
| Kernel session (MCP edge, local and hosted) | `late_events: RwLock<VecDeque<LateSessionEvent>>` drained into `notifications/*` | Unbounded, uncoalesced, cleared on close with no terminal event; control sources are poll-only |
| Hosted SSE transport | `{session_id}-{seq}` ids, a 64-event replay window, `409` outside it | Lag is warn-and-continue (silent loss). A restore restarts the sequence at 0, so a stale cursor aliases into new events |
| Agent process | Mailbox `receive` with `wait_ms` and re-arm by a new operation key; `wait_children`/`settle_children` with exit-75 suspension; `inspect` for own state | No cheap wait for control changes (cancel, capability expiry, budget, recovery) |
| Recovery workflow | `admission_operation_recovery_events`, an immutable hash chain keyed by `(record_key, record_version)`; `InspectWorkflow` and command responses carry `revision` (W:) | No push, outbox or cursor (the `recovery_deliveries` outbox is doc-only). This design projects hints from the event chain |
| Work | `WorkViewV1` per-authority observations, by query (assumed shipped, contract anchor) | No hint to re-query |

The rules adopted from FTL's poll hold across all surfaces:

- **A hint names a subject and a kind.** Authoritative state stays in the owning store. Consumers re-read after a hint. Hints are operational, unsigned, never receipts, and never an input to a decision.
- **Each subscription or wait holds at most one pending hint.** Changes coalesce into it. Draining re-arms it. Arming checks the current level, so a source that is already dirty fires at once.
- **Bounded by construction.** Capacity is reserved when a subscription is created, so posting cannot fail. A surface with a terminal state delivers exactly one terminal hint, last.

## 2. Verified current state

Kernel session queue:

- `Session` holds `subscriptions: SubscriptionRegistry` and `late_events: RwLock<VecDeque<LateSessionEvent>>` (M: `crates/kernel/chio-kernel/src/session.rs:773-777`).
- `SubscriptionSubject` is resource-only (`session.rs:394`). `LateSessionEvent` has five variants: elicitation completed, resource updated, three list-changed kinds (`session.rs:425-436`).
- `queue_late_event` calls `push_back` with no bound (`session.rs:1098-1100`). `take_late_events` drains everything (`session.rs:1102-1104`). `queue_tool_server_event` filters unsubscribed resource updates (`session.rs:1107`).
- Closing clears subscriptions and `late_events` with no terminal event (`session.rs:1331-1338`).
- Resource subscription is capability-authorized (M: `kernel/session_ops.rs:320-329`). This is the precedent for authorized subjects.
- The tool-server drain is now fallible (`try_drain_tool_server_events`, M: `kernel/validation.rs:131`). It is still pushed into one named session (`queue_session_tool_server_events`, `validation.rs:205-216`). The MCP edge assumes one ready session per runtime (M: `chio-mcp-edge/src/runtime/runtime_flow.rs:369`, `:510`).
- The edge buffers notifications in an unbounded `pending_notifications: Vec<Value>` (M: `chio-mcp-edge/src/runtime.rs:149`). Late events become notifications in `flush_session_late_events` (`runtime_flow.rs:397`).

Hosted SSE (M: `crates/protocol/chio-mcp-remote/src/remote_mcp/`):

- Event ids are `{session_id}-{next}`, taken from `next_event_id` (`session_core.rs:1051-1052`). The retained window is 64 (`session_core.rs:111`, trimmed at `:1061`). Parsing is `parse_session_event_id` (`http_service.rs:1095`).
- `replay_notifications_after` returns `409` when the window is empty or the cursor is outside `[oldest - 1, newest]` (`session_core/session.rs:115-148`). This matches `spec/WIRE_PROTOCOL.md:267-272`.
- Every live consumer treats `RecvError::Lagged` as warn and keep looping (`http_service.rs:517`, `:608`, `:702`, `:817`, `:860`; the same on V:). Skipped events are never reported. A POST stream whose skipped event was its terminal response waits until the channel closes.
- Both session construction paths seed `next_event_id` with 0 (`session_core/factory.rs:468`, `:684`).
- `resume_generation` is restored from the record (`factory.rs:722`, `session.rs:52`). It advances through `clock::next_counter` each time a resume record is built (`session.rs:266`) or a terminal persistence epoch is taken (`session.rs:320`). It is covered by the v2 HMAC envelope (`session_resume.rs:802-824`). It therefore advances per persisted write, not per restore.

Agent processes (M: `crates/kernel/chio-process/`):

- The worker protocol has six closed operations (`WORKER_PROTOCOL.md:50-57`), with no administrative operation (`:59-61`). There is one request per connection, at most 32 active connections, and five-second frame and write deadlines (`:30-32`). Unknown fields reject (`:43-44`). Older hosts reject new fields, and clients must not strip them on retry (`:118-121`, the `known_outcome_only` precedent).
- `inspect` returns own process id, parent and root, state, depth, limits, shared call count, checkpoint and storage usage (`WORKER_PROTOCOL.md:52`). `ProcessState` is `Running | Cancelled` (`src/types.rs:126-129`).
- Mailboxes are native `chio-ipc` tools called through ordinary kernel invocations, with capability checks, guards, call budgets and receipts. There is no extra worker method (`MAILBOXES.md:3-7`).
  - `receive` waits up to `wait_ms <= 30000`.
  - After a completed empty poll, a new logical operation key is required (`:97-105`).
  - Claims give at-least-once delivery (`:113-143`). Bounds are fixed (`:207-227`).
- Each mediated call costs about 40 durable writes and 11 authority commits (M: `docs/architecture/AGENT_PROCESS_DIRECTION.md:162-166`). The direction is "Keep the public operation vocabulary small: spawn, invoke, checkpoint, inspect, cancel, then send/receive/join" (`:64-66`).
- `wait_children` plus exit 75 suspends a worker until its children are recorded (M: `crates/products/chio-cli/PROCESS_RUNNER.md:160-161`). `settle_children` uses the same suspension (`:211-222`).

Recovery (implemented in W:):

- `admission_operation_recovery_records` holds `deployment`, `workflow` and `command` records. Versions advance by exactly one, identity is immutable, and records cannot be deleted. `admission_operation_recovery_events` is an immutable hash chain, one row per `(record_key, record_version)`, carrying `record_digest`, `previous_digest`, `event_digest` and `observed_at` (W: `crates/platform/chio-store-sqlite/src/admission_operation_recovery.sql:3-44`).
- Clients observe state through command responses and `InspectWorkflow`: `RecoveryCommandResponseV1 { command_id, workflow_id, revision, control, effect, release }` (W: `crates/kernel/chio-kernel/src/recovery/records.rs:216-223`).
- The vocabulary has three parts (W: `crates/security/chio-security-types/src/recovery/observation.rs`):
  - `WorkflowControlV1 { Active, CancelRequested, Cancelled, Quarantined }` (`:164-169`);
  - `EffectObservationV1 { NeverAdmitted, AdmissionUnresolved, ClosedBeforeEffect, AwaitingApproval, InFlight, AwaitingCallerReport, Unknown }` (`:80-100`);
  - `ReleaseDispositionV1 { NotAvailable, Pending, Withheld, Released, Denied }` (`:154-160`).
- Doc-only, not implemented in W:: the `recovery_deliveries` "transactional notification outbox" (R: `03-recovery-protocol.md:114`), replayable delivery cursors with per-delivery audience recheck (R: `08-protocol-operations.md:19`, `:31`), and the adapter state names such as `WaitingForApproval`. No push, notification or cursor API exists.
- The doc rule that an unavailable notification sink cannot trigger execution or refund (R: `08:94`) still binds any future sink.

Confined children (W: P5):

- A root may attach a confined reader child. The child's process id is host-allocated as `confined_{id}` (W: `crates/platform/chio-store-sqlite/src/admission_operation_store/knowledge/confinement.rs:278`). The child is spawned into the ordinary journal with no tool grants (W: `crates/platform/chio-control-plane/src/confinement.rs:117-150`).
- The P5 contract withholds every non-value route, including progress and completion bodies (W: `docs/architecture/recoverable-agent-runtime/implementation/p5/OPERATIONS.md:40-46`).
- Leak check on the worker-facing surfaces, verified against W: (CLI runner host):
  - `wait_children` accepts only targets scheduled in the active run plan or prefixed `dyn_`, so it refuses a `confined_` id (W: `crates/products/chio-cli/src/cli/process_host/lifecycle.rs:207-221`). It reads only the runner's `run_workers` table, where a cage-launched confined child has no row (`:179-187`).
  - `inspect` reports only the caller's own process (W: `crates/kernel/chio-process/src/worker.rs:156-162`). `tree_calls` is unaffected, because the child has `tool_calls == 0`.
  - The child holds no `chio-ipc` grant, so it cannot post to a mailbox.
  - No leak was found. Other hosts must hold the same rule (H9).

Work (assumed shipped, contract anchor):
- `WorkViewV1` holds independent execution, acceptance, result, recovery, settlement and bilateral-delivery observations, each `NotApplicable | Pending | Available | Unavailable`. Revisions are per authority, and a view "is not a globally atomic snapshot" (V: `2026-10-03-work-runtime-design.md:99`).
- Queries make no mutations (`:87`).

A2A: `PendingApproval` now maps to `TaskStatus::Working` with a pending-approval message (M: `crates/protocol/chio-a2a-edge/src/conversion.rs:99`; V: `:101`).

## 3. Goals and non-goals

Goals:

- One closed hint-subject vocabulary with the same meaning on every surface.
- A bounded, coalesced, terminalized kernel session event log, and transport delivery with no silent gaps.
- A cheap way for agent processes to wait on control changes, with no new worker op and no call-budget charge.
- Approval and recovery hints sourced from the recovery outbox, not duplicated.
- Opt-in MCP exposure of control subjects, leaving MCP semantics unchanged for peers that don't negotiate it.

Non-goals:

- A new durable event log. No durable recovery outbox exists in W:; the durable recovery truth is the hash-chained event log, and hints are rebuilt from it and from other authoritative state after a restart. If recovery later adds the documented outbox, hints project from it instead.
- Signed events, receipt-bearing events, or events as audit evidence.
- Exactly-once delivery.
- Cross-owner delivery in v1 (section 7 records it as a gap).
- Replacing mailboxes as an application data channel. Mailboxes carry application messages; hints carry "re-read your state".
- Incremental A2A push.

## 4. Shared hint model

```rust
// chio-core-types::hint (closed; wire schema `chio.hint-subject.v1`)
pub enum HintSubject {
    // MCP catalog and resource subjects (kernel sessions only).
    Resource(String),
    ResourceCatalog,
    ToolCatalog,
    PromptCatalog,
    Elicitation(String),
    // Control subjects (every surface that owns the source).
    Operation(RequestId),
    Approval(String),
    Capability(String),
    Budget { capability_id: String, grant_index: u32 },
    Children,
    Recovery { workflow_ref: String },
    Work { handle_ref: String },
    Lifecycle,
    Stop { scope_ref: String },   // durable stop epoch changed; re-read stop status (never Terminal)
}

pub enum HintKind {
    Changed,                                  // re-read the subject's owning state
    ThresholdCrossed { level_bps: u16 },      // Budget only
    SubscriptionEnded { reason: EndReason },  // authority withdrawn or subject gone
    Terminal { reason: TerminalReason },      // Lifecycle only; always last
}
```

A hint carries no state, tokens or arguments. It is the analog of FTL's packed `(kind, handle)` event.

Rules H1-H8 bind every surface:

1. **H1. Not inputs.** No kernel, guard, policy, budget, recovery or approval path may branch on a hint. Decisions read authoritative stores only.
2. **H2. Commit, then hint.** A source posts only after its authoritative state commits. Re-reading after a hint observes at least the hinted change.
3. **H3. One pending per subscription.** Further changes increment a coalesce counter and keep the first sequence number. Delivery re-arms.
4. **H4. Level-triggered arming.** Creating a subscription, or starting a wait, checks the source's current level and fires immediately if it is already dirty. There is no window between "changed" and "subscribed" in which a change is lost.
5. **H5. Reserve on subscribe.** Capacity for one pending hint is reserved before a subscription exists. If reservation fails, the subscription is denied with a typed capacity error. Posting never allocates.
6. **H6. Terminal is last.** A surface with a lifecycle delivers exactly one `Terminal` hint, after discarding pending hints, from a slot reserved at creation. After it, posting is a no-op and subscribing fails.
7. **H7. Authority follows the source.** A consumer may subscribe to, or wait on, a subject only with the authority it needs to read that subject's state. When that authority is withdrawn, it receives one `SubscriptionEnded`.
8. **H8. Gaps resync.** Any transport loss surfaces as an explicit resync: `409`, stream termination, or a revision jump. It never surfaces as silent loss.
9. **H9. Audience.** A hint is an existence and status channel, so it obeys the audience policy of its subject.
   - It may name an artifact only by an audience-scoped opaque handle, never by digest. Existence, error, digest and deduplication channels must obey audience policy (W: `docs/architecture/recoverable-agent-runtime/06-artifacts-memory.md:9`, `:80`, ART-10).
   - A hint about a confined child is withheld from the parent unless the child's isolation boundary enables a contract-approved status projection (W: `07-confined-returns.md:39`). The P5 profile enables none.
   - Under enforced durable knowledge, a hint never reveals a knowledge-protected change, such as a checkpoint value or an artifact behind the caller's clearance.

```text
bounded(s)          -> |pending(s)| <= |subscriptions(s)| + 1
no_silent_loss(sub) -> committed(c, source(sub)) and c after last_delivery(sub)
                       -> eventually delivered(hint(sub)) or delivered(SubscriptionEnded(sub))
                          or delivered(Terminal)
not_authority(h)    -> forall decisions d: h not in inputs(d)
```

## 5. Projection per surface

Every surface uses the delivery path it already has:

| Subject | Kernel session (MCP) | Agent process | Recovery workflow | Work |
|---|---|---|---|---|
| Resource and catalogs, `Elicitation` | `SessionEventLog` -> `notifications/*` | n/a | n/a | n/a |
| `Operation` | session-owned request terminal | `invoke` replay with the same key; `inspect` revision | continuation state | execution observation |
| `Approval` | projected from the approval store or the recovery event chain | `invoke` replay returns the new verdict; `inspect` revision | `EffectObservationV1::AwaitingApproval` leaving that state | recovery observation |
| `Capability` | held capability revoked or expired | own process capability (`inspect` revision) | n/a | n/a |
| `Budget` | threshold on a held grant | shared call count and limits (`inspect` revision) | n/a | n/a |
| `Children` | n/a | `wait_children`/`settle_children` (unchanged) | n/a | child acceptance observation |
| `Recovery` | projected from the recovery event chain | `inspect` revision (link only) | new `(record_key, record_version)`; re-read `InspectWorkflow` | `WorkRecoveryLinkV1` observation |
| `Work` | n/a | n/a | n/a | re-query `WorkQueryV1::Work` |
| `Lifecycle` | `Terminal` on session close | `ProcessState::Cancelled` (confined children: withheld per H9) | `WorkflowControlV1::Cancelled` or `Quarantined` | per-authority terminal |
| `Stop` | `Changed` to sessions in the affected scope after the stop or resume commits (H2) | the `hint_revision` advances for processes in the affected tenant or kernel scope | denials of the resume and capture commands are the signal; no extra hint | n/a |

### 5.1 Kernel sessions: `SessionEventLog`

`late_events` and `SubscriptionRegistry` are replaced by one `SessionEventLog`. It is a pure data structure, so loom and proptest can drive it.

```rust
pub struct SessionEventLog {
    next_seq: u64,
    max_subscriptions: usize,                  // default 256
    subscriptions: HashMap<SubscriptionId, SubscriptionEntry>,
    pending: BTreeMap<u64, SubscriptionId>,    // seq order
    terminal: TerminalSlot,                    // reserved at construction
}
impl SessionEventLog {
    pub fn subscribe(&mut self, subject: HintSubject, authority: SubscriptionAuthority,
                     level: SourceLevel) -> Result<SubscriptionId, EventLogError>;
    pub fn post(&mut self, subject: &HintSubject, kind: HintKind);   // infallible (H5)
    pub fn drain(&mut self, max: usize) -> Vec<SessionHint>;
    pub fn end_subscriptions_for(&mut self, capability_id: &str, reason: EndReason);
    pub fn terminate(&mut self, reason: TerminalReason);              // H6
}
```

Session rules:

1. `close` and `close_persisted` call `terminate` instead of clearing (replacing `session.rs:1338`).
2. Auth rotation through `set_auth_context` (`session.rs:1161`) ends the subscriptions authorized by capabilities that leave the session (H7).
3. Authorization reuses the `subscribe_session_resource` order (`session_ops.rs:320-329`): validate the capability, check scope, check the subject exists.
   - `Operation` and `Approval`: session-owned.
   - `Capability`: requires the id in the session's issued capabilities or an ancestor link of one.
   - `Budget`: requires a held capability and a `BudgetStore` that serves mutation events. Otherwise `Unsupported`, never a subscription that cannot fire.
4. The edge drains at most the free space in a bounded `pending_notifications` (replacing the unbounded `Vec`, `runtime.rs:149`).
5. The single-session-per-runtime assumption of `queue_session_tool_server_events` (`validation.rs:205-216`) is written down as an invariant. It is checked when an edge attaches a second ready session, which fails closed. A cross-session router is deferred until a deployment needs it.
6. Control subjects are emitted only to peers that negotiated `capabilities.experimental.chioEvents = { "version": 1 }`, as `notifications/chio/event` with `{seq, subject, kind}`. Other peers get standard notifications only.

### 5.2 Agent processes: `inspect` hint revision (recommended)

Processes already have FTL-style waits for data: mailbox `receive` with `wait_ms` plus re-arm by a new key, and `wait_children` plus exit-75 suspension. They lack a cheap wait for control changes: own cancellation, capability expiry or revocation, budget thresholds, an approval resolved for an own operation, and a recovery link becoming available.

Three options:

| Option | Cost per wait | Call budget | Receipt | Op set |
|---|---|---|---|---|
| A. Reserved system mailbox channel (`chio-ipc` `receive_chio_control`) | One mediated call: about 40 durable writes and 11 authority commits (`AGENT_PROCESS_DIRECTION.md:162-166`), plus the host's send | Consumed | Yes | Unchanged |
| B. Seventh worker op `wait` | Journal read, no commit | Not consumed | No | Grows to seven |
| C. `inspect` gains optional `after_revision` and `wait_ms` | Journal read, no commit | Not consumed | No | Unchanged |

**Decision: option C.**

Option A is rejected for control hints for three reasons:
- A process that has exhausted its call budget could no longer learn it was cancelled or revoked. The hint channel would fail exactly when it matters.
- Each empty poll costs a full mediated admission.
- Mailbox receive needs a fresh logical key after every empty poll (`MAILBOXES.md:97-99`), so each wait journals a new operation.

Option B grows the vocabulary the direction document wants kept small, for behavior that `inspect` (already a non-mediated, credential-scoped read of own state) can carry.

Shape (worker protocol, M: `WORKER_PROTOCOL.md:50-57`):

```json
{"op":"inspect","after_revision":"41","wait_ms":30000}
```

Response additions: `hint_revision` (a canonical decimal string) and `hints`. `hints` is a sorted, deduplicated list of `HintSubject` kinds that changed after `after_revision`, coalesced, with no payloads.

Rules:

1. **P1. Revision source.** `hint_revision` is a per-process monotonic counter in the process journal. It advances in the same transaction as:
   - the process's `ProcessState` change;
   - a credential or capability binding change;
   - a crossing of a configured shared-call threshold;
   - the attachment of a recovery link to an own operation (assumed shipped, contract anchor).

   Approval resolution for an own pending operation advances it when the host records the resolution. A source that commits outside the journal posts after its commit, per H2.
2. **P2. Level-triggered.** If the current revision exceeds `after_revision`, `inspect` returns at once. Otherwise it waits up to `wait_ms` (at most 30000, matching mailbox `wait_ms`) for an advance, then returns the current snapshot. Omitting both fields gives exactly today's `inspect`.
3. **P3. Bounds.** A waiting `inspect` counts against a separate `max_waiting_connections` (default 32), not the 32 active-connection limit (`WORKER_PROTOCOL.md:30-32`). Waits are limited to one per credential.
   - A wait over the bound returns immediately with the current snapshot. It is not refused.
   - Authentication is re-checked before returning (`WORKER_PROTOCOL.md:124-128`). A credential revoked during the wait gets `unauthenticated`, which is itself the cancellation signal.
4. **P4. No authority.** The response reveals only state that `inspect` already reveals for the caller's own process. It never names other processes, policy, or remaining sibling budget (H1, H7).
5. **P5. Compatibility.** The new fields follow the `known_outcome_only` precedent: older hosts reject unknown fields, and clients must not strip the fields on retry (`WORKER_PROTOCOL.md:118-121`). M: and W: each define an incompatible `chio.process.abi.v3`, so the union is `chio.process.abi.v4`, and the fields ship under v4 (open decision 1).
6. **P6. Enforced knowledge.** When durable knowledge is enforced, `inspect` MUST:
   - return the redacted public snapshot (checkpoint value null, W: `crates/kernel/chio-process/src/store/knowledge.rs:64-70`);
   - omit `storage` instead of failing;
   - advance `hint_revision` for knowledge-protected changes only as a generic `Changed` on `Lifecycle` or `Capability`, never naming the protected subject (H9).

   W: currently fails the entire `inspect` op under enforcement, because the handler always calls `storage()`, which refuses at journal version 3 or later (W: `crates/kernel/chio-process/src/worker.rs:156-162`; `src/lib.rs:282-288`; `src/store/knowledge.rs:16-26`). Fixing this is a prerequisite for process hints in enforced deployments.

Data still flows through mailboxes. Child joins still go through `wait_children`. `inspect` only says what to re-read.

### 5.3 Recovery workflows: project from the event chain

The recovery lane's durable truth is the hash-chained `admission_operation_recovery_events`, inside the serving authority's global commit chain (W: `admission_operation_recovery.sql:29-44`). It has no outbox, cursor or push today. This design adds no durable log.

1. **Source.** A new `(record_key, record_version)` for a `workflow` record whose scope the session or process owns posts a `Recovery` hint. It posts an `Approval` hint when the workflow's `EffectObservationV1` leaves `AwaitingApproval`. The hint is posted after the event commits (H2) and carries only the workflow reference.
2. **Re-read.** The consumer re-reads through `InspectWorkflow` under its own capability, assignment, revocation and clearance checks. The response's `revision` makes resync explicit (H8). A consumer that sees a revision jump re-reads; it never assumes intermediate states.
3. **Control states.** `WorkflowControlV1::CancelRequested`, `Cancelled` and `Quarantined` post `Changed` on `Recovery`. A terminal disposition posts no `Lifecycle` `Terminal` for the session, because a workflow is not the session.
4. **Processes.** A process `Recovery` hint advances `hint_revision` when a workflow in the process's scope changes revision. Recovery control remains host-only: the worker sees only the hint, and never a recovery command.
5. **Outbox.** If recovery adds the documented `recovery_deliveries` outbox, hints project from it instead, with its per-delivery audience recheck. The event-chain source then retires. An unavailable hint sink never triggers execution or refund (R: `08:94`).

### 5.4 Work: hint to re-query

`WorkViewV1` observations are per authority and not atomic (assumed shipped, contract anchor; V: `work-runtime-design.md:99`). A `Work { handle_ref }` hint means "re-query `WorkQueryV1::Work`". It is posted by an owning authority on the same host when one of its observations changes revision. The query performs the current audience check (`work-runtime-design.md:87`, `:101`). A hint never carries an observation value, because observations can be confidential (`:101`).

## 6. Transport delivery

### 6.1 MCP edge

Standard subjects keep their existing `notifications/*` methods and peer gates (`runtime_flow.rs:397`). MCP subscriptions are persistent, and their notifications are re-read hints, so coalescing preserves MCP semantics. Control subjects require `chioEvents` (section 5.1, rule 6).

### 6.2 Hosted SSE corrections

1. **Lag terminates the stream.**
   - On `RecvError::Lagged`, the server ends the stream and increments `chio_mcp_remote_stream_lag_terminations_total`. This replaces the loop-on-lag at `http_service.rs:517`, `:608`, `:702`, `:817` and `:860`.
   - The client reconnects with `Last-Event-ID`: inside the window it gets replay, outside it gets `409`.
   - A POST stream that ends without its response is retried with the same request id. Admission idempotency returns the bound terminal result and never redispatches.
2. **Sequences are monotonic across restore, seeded from `resume_generation`.**
   - Before a restored session serves any stream, `restore_session` takes `g = clock::next_counter(resume_generation)` and persists a resume record carrying `g`, under the v2 HMAC (`session_resume.rs:802-824`).
   - It then seeds `next_event_id = g << 32`, replacing the zero seeds at `factory.rs:468` and `:684`.
   - The bump is required because the counter advances only per persisted write (section 2). Without it, a session restored twice with no intervening write would reuse a seed.
   - Fresh sessions seed from their initial generation the same way.
   - Every id from an earlier incarnation is then below `oldest - 1`, so `replay_notifications_after` refuses it with `409` (`session_core/session.rs:141`).
   - The wire format `{session_id}-{sequence}` and its parser (`http_service.rs:1095`) are unchanged.
   - If the low 32 bits of a sequence would overflow within one incarnation, the session takes a new generation the same way (persist, then reseed). If persistence fails, the stream terminates.
3. **Terminal ends the stream.** A session `Terminal` hint is written, then the stream closes. Later requests follow the `spec/WIRE_PROTOCOL.md` section 3.3 terminal-state rules.

### 6.3 A2A

No change. `PendingApproval` maps to `Working` on M:/V: (section 2). Any later A2A status push must source from the hint model and inherit H1-H8.

## 7. Cross-owner hints: known gap

In multi-owner work, cross-owner state is poll-only, through the W2 work query (assumed shipped, contract anchor). Several useful hints have no channel: child accepted, verifier decision recorded, graph head advanced, bilateral co-sign pending.

The P2P push lanes today are:
- revocation epoch roots on iroh lane b, pushed plus catch-up (V: `crates/trust/chio-federation-transport-iroh/src/lanes/revocation.rs:1-40`);
- an experimental, library-only, pheromone-only per-treaty fan-out on lane c (V: `src/lanes/fanout.rs:1-10`).

Direction (not v1):

- **Option 1: a hint-only direct lane per treaty party.** It reuses the lane admission gate and verified directory shared by lanes a, b and d. Payloads are `{subject, kind, owner_revision}` and never authoritative. Receivers select trust before reading (V: `docs/papers/verifiable-work/PROTOCOL.md:22-25`).
- **Option 2: a W2 subscription endpoint** with R:'s outbox semantics: replayable cursors and an audience recheck per delivery.

Either option must hold the same rules H1-H8 and must not depend on lane c, whose passive-observation residual is documented. No multi-owner result has been independently operated yet, so this stays a direction until W2 runs across real owners.

## 8. Failure modes and fail-closed behavior

| Failure | Behavior |
|---|---|
| Subscription capacity or reservation exhausted | Subscribe denied with a typed capacity error. An implicit subscription needed by a new request denies that request before admission |
| Authority withdrawn | One `SubscriptionEnded`, then the subscription is removed |
| Backend cannot serve the subject (budget mutation events) | `Unsupported`. A subscription that cannot fire is never created |
| SSE consumer lags | Stream terminated; replay or `409` on reconnect |
| Restore | Generation bumped and persisted before serving. If the persist fails, the session is not served |
| Process wait over the bound | Immediate snapshot. Never a refused request, never a hang |
| Credential revoked during a process wait | `unauthenticated` at the return check |
| Durable knowledge enforced | `inspect` returns a redacted snapshot without `storage` (P6); hints never name protected subjects (H9) |
| Hint about a confined child | Withheld unless the boundary enables a status projection (H9) |
| Second ready session on an edge runtime | Refused (section 5.1, rule 5) |
| Edge, host or transport crash | Hints in flight are lost. Consumers resync from authoritative state. No authority or state is lost (H1) |
| Forged or tampered hint | Harmless to safety (H1). It can only prompt a re-read |

## 9. Protocol, schema and wire impact

- **`spec/WIRE_PROTOCOL.md` section 3.2** gains three rules:
  - a lagged live stream MUST be terminated;
  - sequences MUST be monotonic across restore;
  - a terminal hint MUST be the final event on a stream.
- **`spec/PROTOCOL.md`:**
  - section 4.3 adds the negotiated `chioEvents` extension, and section 8.2 lists it under MCP compatibility;
  - the hint vocabulary is documented as operational, never signed.
- **`spec/versions/chio-protocol-negotiation.v1.json`** adds `chioEvents` (optional, version 1).
- **New schemas** under `spec/schemas/`, generated by `chio-spec-codegen`:
  - `chio.hint-subject.v1`;
  - `notifications/chio/event` params;
  - `chio/events/subscribe` requests.
- **Worker protocol:** `inspect` gains `after_revision`, `wait_ms`, `hint_revision` and `hints`, and omits `storage` under enforced knowledge (P6). This updates `WORKER_PROTOCOL.md` and ships under the union `chio.process.abi.v4` (open decision 1).
- **No change** to capability, receipt, manifest or other signed schemas. No receipt kind is added.

## 10. Rollout and migration

1. **Transport hardening** first, as independent bug fixes with no negotiation: lag termination and generation-seeded restore.
2. **Kernel session log:** `SessionEventLog`, the bounded edge buffer, the terminal hint, and the single-session invariant. MCP-visible behavior is unchanged except that duplicate list-changed notifications coalesce.
3. **Process `inspect` revision**, behind a host configuration flag until conformance passes. It lands with the union `chio.process.abi.v4` and the P6 fix for enforced knowledge.
4. **Recovery projection** from the W: event chain once the recovery work merges. **Work projection** once the W1 query lands (contract anchor today).
5. **Session control subjects** behind `chioEvents`.

## 11. Tests and conformance evidence

- **Unit (`chio-kernel`):**
  - capacity denial;
  - infallible post after subscribe;
  - coalescing keeps the first sequence;
  - level-triggered arm;
  - terminal is last and idempotent;
  - `SubscriptionEnded` on revocation and auth rotation;
  - second-session refusal.
- **Proptest:** model-based subscribe/post/drain/revoke/terminate sequences against a reference model, checking section 4's predicates.
- **Loom:** a `post` racing a `drain` on `Session` (the file already gates on `cfg(loom)`). No lost re-arm.
- **`chio-mcp-remote`:**
  - a broadcast capacity of 8 forces lag and asserts termination;
  - restore twice with no intervening write, then a stale cursor, asserts `409`;
  - replay inside the window is gap-free;
  - a failed generation persist refuses serving.
- **`chio-process`:**
  - `inspect` with `after_revision` below current returns immediately;
  - a wait returns on cancel, on capability revocation (as `unauthenticated`), and on threshold crossing;
  - over-bound waits return snapshots;
  - waits consume no call budget and produce no receipt;
  - an old host rejects the new fields;
  - under enforced durable knowledge, `inspect` returns a redacted snapshot without `storage`, and never fails (P6).
- **Audience (H9):**
  - a `confined_` child id is refused by `wait_children`;
  - no hint reveals confined-child progress or completion;
  - an artifact hint carries no digest;
  - recovery hints follow event-chain revisions, and a skipped revision forces an `InspectWorkflow` re-read.
- **Fuzz:** `parse_session_event_id` over generation-seeded `u64` values and hostile session ids.
- **chio-conformance:**
  - replay across restart;
  - lag resync;
  - `chioEvents` negotiated versus not;
  - a revoked capability yields `Changed` and then `SubscriptionEnded`;
  - exactly one terminal per session;
  - a process sees its own cancellation through `inspect` without spending budget.

## 12. Residual risks and open decisions

Residual risks:

- Consumers that ignore hints keep today's latency. Safety is unchanged.
- A long-poll `inspect` holds a host connection. The separate waiter bound limits starvation of `invoke`, but hosts must size it.
- The recovery projection depends on uncommitted W: code built on an older #1160 checkpoint. Event-chain table and type names must be re-pinned at merge. Work projections depend on contract anchors.

Open decisions:

1. **Process ABI version (forced).** The choice is no longer between v3 and v4 for these fields:
   - M: moved `PROCESS_ABI` from v2 to v3 in commit `2a4c2fbe4` (native broker routes).
   - W: independently moved v2 to v3 for durable knowledge and recovery (W: `crates/kernel/chio-process/src/lib.rs:54`; base `f25cd61f4` is v2).
   - Both are "an incompatible change to any covered surface" (M: `crates/products/chio-cli/PROCESS_HOST.md:203-212`), so the union must be `chio.process.abi.v4`, with an explicit migration rule.

   Decision: the `inspect` fields and the P6 fix ship in v4. The remaining question belongs to the merge owners: whether v4 accepts journals from either v3, or only fresh initialization.
2. **Scope pushback on "hosted MCP only".** The directive was to narrow `SessionEventLog` to hosted MCP sessions. The kernel `Session` is also used by the local stdio MCP edge (`runtime_flow.rs:369`, `:397`), whose `late_events` queue is equally unbounded and cleared without a terminal event. This revision therefore scopes the log to kernel sessions (both edge modes) and keeps the transport fixes hosted-only. Narrow it further only if the stdio edge is retired.
3. Whether to add an agent-level aggregate stream across one agent's sessions. This draft keeps streams per session.
4. Budget thresholds: caller-chosen basis points, or fixed by policy to limit what a holder learns about shared pools.
5. Native `chio-wire-v1` framing for hints, or MCP-only in v1.
6. Which cross-owner direction (section 7) to pursue once W2 operates across independent owners.

## Appendix A. FTL reference

What FTL does (`/Users/connor/Medica/backbay/ftl`):

- A `Poll` is a queue plus waiters. `enqueue` reserves before pushing (`kernel/src/poll.rs:49-75`). Close marks it destroyed and wakes waiters (`poll.rs:126-136`).
- An event packs `kind << 24 | handle_id` with no payload (`libs/ftl_types/src/poll.rs:20-31`).
- Subscribing needs READ on the source and WRITE on the poll (`kernel/src/thread.rs:346-353`).
- Subscriptions are one-shot. The NIC pops its notifier on receive (`libs/ftl_netmux/src/nic.rs:103-107`). Arming is level-checked: queued packets notify at once (`nic.rs:71-77`), and so does an already-exited thread (`kernel/src/thread.rs:112-116`).
- The LX loop re-arms after handling each source (`lx/src/container/mod.rs:44-45`, `:75-86`).

Chio already has the FTL shape in places. Mailbox `receive` with `wait_ms` plus a new operation key after an empty poll is a one-shot, re-armed, level-checked wait (`MAILBOXES.md:97-105`). The `inspect` revision extends the same shape to control state.

Where the analogy breaks:

- FTL can drop notifications on allocation failure (`thread.rs:282-283`; `nic.rs:106`). Chio reserves at subscribe (H5).
- FTL has no transport or restart. Chio crosses process and network boundaries, so it needs cursors, windows, lag termination and generation-seeded sequences.
- FTL rights are the whole authorization story. Chio subscriptions derive from revocable capabilities, so they must end with their authority (H7).
- An FTL wait is free. A Chio mediated call is not (about 40 durable writes), which is why process control hints ride `inspect` rather than a mediated tool.

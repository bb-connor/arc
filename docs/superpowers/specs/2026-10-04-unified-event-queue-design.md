# Design: session event delivery fixes and a deferred hint vocabulary

- Status: PROPOSED (revision 4, re-baselined 2026-10-05 on #1160 + #1173 + #1172 + uncommitted recovery P0-P5 (W:), after adversarial review `review-spec5`)
- Date: 2026-10-04 (revision 4: 2026-10-05)
- Scope:
  - **Part A, bug-fix lane.** Close the hosted SSE delivery defects (D3 lag, D4 restore aliasing), make subscriptions survive a hosted restore, fix the W: worker `inspect` failure under enforced knowledge (N14) and the confined-child count leak in `cancel`. Part A needs no approval of the larger designs.
  - **Part B, deferred.** One closed hint-subject vocabulary, a bounded kernel `SessionEventLog`, the process `inspect` long-poll, `chioEvents`, and the recovery and work projections. Part B lands only when a second surface consumes hints on the wire. Until then `HintSubject` stays crate-internal and spec 9's `HintPort` is a no-op.
  - No new bus, no new durable event log, no signed events.
- Owners:
  - `chio-mcp-remote`: hosted SSE delivery, response slots, restore (Part A).
  - `chio-mcp-edge` and `chio-kernel` session: resync requests (Part A); session event log, subscription authorization (Part B).
  - `chio-process`: enforced `inspect`, `cancel` count (Part A); `inspect` hint revision (Part B).
  - `chio-kernel`: `HintPort` and hint vocabulary (Part B).
- Related:
  - `spec/WIRE_PROTOCOL.md` sections 3.2 and 3.3.
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
  - `2026-10-04-durable-stop-epoch-design.md` (spec 8: shared `StopHeads`)
  - `2026-10-04-pure-admission-machine-design.md` (spec 9: `Effect::Hint`)
  - `2026-10-04-crossing-primitive-design.md` (spec 10: commit classes)
- Citations:
  - M: = `origin/integration/process-security-m4` at `19df31ad9` (PR #1160). V: = `origin/work/verifiable-work-session-20261003` at `14477aaac` (PR #1173). R: = `origin/research/openappa-recovery-20261001` at `de84fc306` (PR #1172). All three are treated as shipped.
  - W: = the uncommitted working tree of `standalone/arc-worktrees/recoverable-agent-runtime-20261002` (branch `feat/recoverable-agent-runtime-20261002`; recovery P0-P5 implemented locally, built on #1160 checkpoint `f25cd61f4`). It is treated as shipped. Line references reflect the working tree on 2026-10-05 and may drift.
  - R: and W1-W4 interfaces with no code are marked "assumed shipped (contract anchor)". Recovery documents that describe something absent from W: are marked "doc-only, not implemented in W:".
  - The cited kernel and `chio-mcp-remote` lines are identical on M: and V: unless a V: path is given. Unprefixed `http_service.rs`, `session_core.rs`, `factory.rs` and `session_recovery.rs` paths are under M: `crates/protocol/chio-mcp-remote/src/remote_mcp/`.

## Revision 4 changes

- **Split into Part A and Part B (S5-10).** The umbrella's bug-fix lane says N14 and the SSE defects need no approval of the larger designs. Part A (sections 4-10) is that lane. Part B (sections 11-18) holds the vocabulary, the session log, the long-poll and the projections, deferred until a second surface consumes hints on the wire. The wire schema `chio.hint-subject.v1` is no longer frozen in advance.
- **D3 fix rebuilt (S5-01 Blocker, S5-02, S5-12, S5-17).** Revision 3 terminated a lagged stream and told clients to retry "with the same request id". No idempotency exists for ordinary calls without `_meta.chioRequestId`, credential sessions fence instead of replaying, and replay never carries responses. Revision 4:
  - delivers each POST request's terminal response and its correlated server-to-client requests through a non-lossy per-request slot (section 4.1);
  - runs `finish_call` in a session-owned completion task, so a call completes whether or not the HTTP consumer survives (section 4.2);
  - subscribes after the per-session request lock, and subscribes a GET replay stream before taking its replay snapshot (section 4.3);
  - answers notification lag with a coalesced resync burst in standard MCP vocabulary instead of terminating streams (section 4.4);
  - handles the initialize and idle collectors per site and adds a per-session cancellation token (section 4.5);
  - restates the retry rule per surface (section 4.6).
- **D4 fix corrected (S5-03, S5-18, S5-19).** The generation bump is computed before construction but persisted only after the post-restore deadline check, a per-session persist failure retains the record inactive instead of aborting startup, the shift is checked, low-bit exhaustion fails closed, and fresh sessions seed 0 without persisting. The test now fails on current code (section 5).
- **Subscriptions survive a hosted restore (S5-04).** They are persisted in the HMAC-covered resume record, re-authorized at restore, and followed by one catch-up `resources/updated` per restored URI (section 6). A session whose standard subscription cannot be re-authorized is terminated rather than restored without it (A25, pass 6).
- **N14 narrowed to P6 bullets 1-2** and shipped W:-local under whatever ABI W: lands (section 7.1). **New Part A item: the `cancel` count** reveals whether a confined child was still running (S5-21, section 7.2).
- **New finding during revision: GET replay gap.** The GET replay path takes its replay snapshot before it subscribes (`http_service.rs:829` then `:839`), so a notification published between the two is in neither (section 2, fixed in section 4.3).
- **Part B hint integration with specs 9 and 10 defined (S5-11).** `HintPort`, `Hint`, `HintAudience` and `HintOwnerRef` are defined here (section 11.2). Hint effects run in a trailing group after the commit group's `Committed` acknowledgement. H2 is restated per spec 10 commit class.
- **Part B rule fixes.**
  - H4 is subscribe-then-check; `Resource` and catalog subjects are edge-triggered (S5-05).
  - H7 revalidates authority at drain time and on auth rotation (S5-06).
  - Recovery re-reads use the non-persisting `read_recovery_workflow`, never a command (S5-07).
  - The process projection is restricted to subjects `inspect` can show: `Lifecycle` and `Budget` (S5-08).
  - Process waits use an in-memory `watch` channel with register-before-read, both sources commit in the process journal, waits are bounded by credential expiry, and enforced reads stop committing (S5-09).
  - Coalescing precedence, one-shot subject retirement, separate implicit and explicit pools, never denying a call for hint capacity (S5-15, S5-16).
  - Knowledge-protected changes never advance `hint_revision` (S5-20).
  - H1 gains a dependency ban and a differential test (S5-24).
- **Stop hints read spec 8's shared `StopHeads` notification**, and `Capability` posts match by lineage (S5-14).
- **Server requests are routed by cause (Codex round 2).** Each inbound message carries a session-local sequence. The edge stamps every outgoing event with the sequence of the message it is handling, and the writer routes server-to-client requests by that cause instead of by the active slot (A1a-A1c).
- **Restore keeps the v3 envelope, and expiry is scheduled (Codex round 7).** A17's boot re-sign carries the complete record, `subscriptions` included, and never lowers the envelope version (A28, A29). Capability expiry has its own schedule, re-armed at restore, so a quiet expiry still ends the subscription (H7a).
- **Ended subscriptions wait for acknowledgement, and termination flushes before cancelling (Codex rounds 8 and 33).** An ended subscription is `Terminalized` and keeps its slot until its `SubscriptionEnded` is explicitly acknowledged or unsubscribe commits (H5a); session termination subsumes it. Termination copies `Terminal` into each stream's reserved frame and waits for every stream to flush it, within a deadline, before cancelling the session token (H6a).
- **Factual corrections (S5-26).** `EffectObservationV1` has ten variants; the replay window holds 64 notifications, not 64 events; `:608` and `:702` are buffered collectors; `resume_generation` advances per signed record; the recovery events `sequence` column is a global cursor.

## Revision 3 changes

- **Recovery hints come from the event chain, not an outbox.** W: implements no `recovery_deliveries` outbox, delivery cursor or per-delivery audience recheck (doc-only, R: `03-recovery-protocol.md:114`). Recovery hints project from the hash-chained `admission_operation_recovery_events` (W: `crates/platform/chio-store-sqlite/src/admission_operation_recovery.sql:29-44`). Revision 4 replaces the `InspectWorkflow` re-read with `read_recovery_workflow`.
- **Implemented vocabulary.** Hint meanings map to `WorkflowControlV1`, `EffectObservationV1` and `ReleaseDispositionV1` (W: `crates/security/chio-security-types/src/recovery/observation.rs:80-169`).
- **New rule H9 (audience).** Hints obey audience policy (P4 ART-10).
- **Confined-child leak check** against W: (section 2). Revision 4 adds the `cancel` count, which the revision 3 check missed.
- **New finding: `inspect` fails under enforced knowledge** (N14). Revision 4 moves the fix to Part A.
- **Process ABI collision.** M: and W: each define an incompatible `PROCESS_ABI` v3, so the union is v4. Revision 4 decouples Part A from that union.

## Revision 2 changes

- Narrowed `SessionEventLog` to kernel sessions; one closed subject vocabulary projected per surface; the process-hint option C; hints from the recovery lane; `resume_generation` seeding instead of `stream_incarnation`; M:/V: citations; cross-owner hints recorded as a gap; the kernel `EventRouter` and the `Delegate`/`AuthorityFault` session subjects dropped.

## 1. Decision summary

Chio has several partial event mechanisms. Two hosted ones lose data today, and two process ones leak or fail:

| Surface | Existing mechanism | Defect or gap | Part |
|---|---|---|---|
| Hosted SSE transport | `{session_id}-{seq}` ids; a 256-event broadcast per session; a replay window of 64 notifications; `409` outside it | Lag is warn-and-continue (silent loss, D3). A lagged POST stream can lose its own terminal response, which leaves a credential call `pending` and fenced. A restore restarts sequences at 0, so a stale cursor aliases into new events (D4). A restore drops every resource subscription. GET replay has a snapshot-then-subscribe gap | A |
| Agent process (W:) | `inspect`, `cancel` over the worker socket | `inspect` fails entirely under enforced knowledge (N14). The `cancel` count reveals confined-child completion | A |
| Kernel session (MCP edge, local and hosted) | `late_events: RwLock<VecDeque<LateSessionEvent>>` drained into `notifications/*` | Unbounded, uncoalesced, cleared on close with no terminal event; control sources are poll-only | B |
| Agent process | Mailbox `receive` with `wait_ms`; `wait_children`/`settle_children`; `inspect` | No low-latency wait for own cancellation or budget thresholds | B |
| Recovery workflow (W:) | `admission_operation_recovery_events` hash chain; `revision` on reads | No push or outbox (doc-only) | B |
| Work | `WorkViewV1` by query (contract anchor) | No hint to re-query | B |

Part A fixes defects with no new vocabulary and no negotiation. Part B adopts FTL's poll rules for the rest:

- **A hint names a subject and a kind.** Authoritative state stays in the owning store. Consumers re-read after a hint. Hints are operational, unsigned, never receipts, and never an input to a decision.
- **Each subscription or wait holds at most one pending hint.** Changes coalesce into it by precedence. Draining re-arms it. Subscribing inserts the entry before checking the source level, so a change between the check and the subscription is captured.
- **Bounded by construction.** Capacity is reserved at subscription, so posting cannot fail. A surface with a terminal state delivers exactly one terminal hint, last.

## 2. Verified current state

Hosted SSE (M: `crates/protocol/chio-mcp-remote/src/remote_mcp/`):

- **Ids and windows.** Event ids are `{session_id}-{next}` from `next_event_id` (`session_core.rs:1051-1052`). Each session has one `broadcast::channel` of capacity 256 (`factory.rs:465`, `:681`). Only `Notification`-kind events are retained, 64 of them (`session_core.rs:111`, `:1055-1063`). Responses and server-to-client requests are never retained.
- **Replay.** `replay_notifications_after` returns `409` when the window is empty or the cursor is outside `[oldest - 1, newest]` (`session_core/session.rs:115-148`), matching `spec/WIRE_PROTOCOL.md:267-272`. GET replay filters to notifications (`http_service.rs:839-860`). WIRE_PROTOCOL 3.2 says nothing about what a client does after a `409`.
- **GET replay gap (new in revision 4).** The replay branch calls `replay_notifications_after` (`http_service.rs:829`), then `try_attach_notification_stream`, then `session.subscribe()` (`:839`). A notification published between the snapshot and the subscription is in neither. The loop already deduplicates by `seq` (`:853`), so subscribing first is safe.
- **POST request streams.** The handler subscribes before it waits on the per-session request mutex: `session.subscribe()` at `http_service.rs:425`, `active_request_stream.lock_owned().await` at `:426`, `session.send` at `:465`. A request queued behind a streaming request receives that request's events first.
  - The stream emits notifications only when no GET stream is attached, and request-correlated events when they are this request's terminal response or a server-to-client request (`http_service_auth.rs:1-14`). Credential sessions emit only the terminal response (`http_service.rs:504-505`).
  - `finish_call` runs only inside the stream consumer when it observes the terminal response (`http_service.rs:484-497`). If lag skips that response, or the consumer is dropped, the call row stays `pending`.
- **Lag and close.** Every consumer treats `RecvError::Lagged` as warn and keep looping (`http_service.rs:517`, `:608`, `:702`, `:817`, `:860`; the same on V:). `:608` is the initialize collector and `:702` is `collect_session_events_until_idle`; both buffer events before responding, they are not live streams. `RecvError::Closed` never fires while a stream runs: the stream holds an `Arc<RemoteSession>` that owns `event_tx` (`session_core.rs:627`; `http_service.rs:470`), and the edge writer holds another sender (`session_core.rs:1026`). A POST stream whose terminal response was skipped therefore waits indefinitely while holding `active_request_stream`, and every later POST on the session blocks at `:426`. At `:608`, a skipped initialize response hangs the handler, and the spawned session is never inserted or terminalized.
- **Request identity.** `_meta.chioRequestId` is optional for ordinary `tools/call` (M: `crates/protocol/chio-mcp-edge/src/runtime/tool_calls.rs:293-313`; required only with approval artifacts or supplemental authorization). Without it, every request gets a fresh kernel identity `mcp-edge-req-{uuid}`, because JSON-RPC ids may be reused after a response (M: `chio-mcp-edge/src/runtime/protocol/parsing.rs:139-146`). Strict-nonce retries reuse the identity bound into the nonce.
- **Credential calls.** A restricted call requires `chioRequestId`. `reserve_at` replays only `completed_unacknowledged | acknowledged | fenced` rows and otherwise returns `fence_error()`, 409 "pending or uncertain call; operator reconciliation is required" (M: `session_credentials.rs:661-688`, `:529-533`). An unacknowledged latch then blocks every later call on the credential (`:689-694`).
- **Sequence seeds.** Both session construction paths seed `next_event_id` with 0 (`factory.rs:468`, `:684`).
- **Generations.** `resume_generation` is restored from the record (`factory.rs:722`). It advances through `clock::next_counter` (checked add) each time a resume record is signed (`session_core/session.rs:266`) or a terminal persistence epoch is taken (`:320`), before the persist and even if the persist fails. It is covered by the v2 HMAC envelope (`session_resume.rs:802-824`), which lists its fields explicitly. Zero is rejected (`:837`), and the store enforces a strictly increasing generation (`session_store.rs:1197`).
- **Restore.** Restore runs serially at startup inside `restore_persisted_sessions`, before the router is built (`http_service.rs:83-91`), under the store-ownership lease. Any `Err` from the restore closure aborts startup for every session (`session_recovery.rs:84-88`). After restore, a deadline check can find the session expired (`:51-64`); `expire_record` then builds the terminal epoch as `record.resume_generation.checked_add(1)` from the loaded record (`:107-111`), and `prepare_terminal_session_transition` refuses an epoch that does not exceed the active generation (`session_store.rs:980-985`).
- **Subscriptions.** The resume record carries no subscriptions (`session_core.rs:264-281`). Restore builds a fresh kernel and session (`factory.rs:576` onward). `queue_tool_server_event` drops `ResourceUpdated` for unsubscribed URIs (M: `crates/kernel/chio-kernel/src/session.rs:1119-1123`), so after a restart a client's `resources/subscribe` silently stops firing.

Kernel session queue (Part B context):

- `Session` holds `subscriptions: SubscriptionRegistry` and `late_events: RwLock<VecDeque<LateSessionEvent>>` (M: `session.rs:773-777`). `SubscriptionSubject` is resource-only (`:393-395`). `LateSessionEvent` has five variants (`:425-436`).
- `queue_late_event` calls `push_back` with no bound (`:1098-1100`); `take_late_events` drains everything (`:1102-1104`); `queue_tool_server_event` is `cfg(not(loom))` (`:1106`) and filters unsubscribed resource updates (`:1107-1123`). Closing clears subscriptions and `late_events` with no terminal event (`:1331-1338`).
- Resource subscription is capability-authorized in the order validate, scope, exists (M: `kernel/session_ops.rs:320-338`). `issued_capabilities` is an immutable `Vec` (`session.rs:771`); auth rotation replaces only the auth context and anchor epoch (`:1196-1220`).
- The tool-server drain is fallible (`try_drain_tool_server_events`, M: `kernel/validation.rs:131`) and pushes into one named session (`validation.rs:205-216`). The MCP edge assumes one ready session per runtime (M: `chio-mcp-edge/src/runtime/runtime_flow.rs:369-372`). Hosted builds one kernel per session (`factory.rs:381`).
- The edge buffers notifications in an unbounded `pending_notifications: Vec<Value>` (M: `chio-mcp-edge/src/runtime.rs:149`). Nested flow pushes progress, log, tool-chunk and server-request messages into the same `Vec` (M: `chio-mcp-edge/src/runtime/nested_flow.rs:56`, `:169`, `:465-736`).

Agent processes:

- The worker protocol has six closed operations (M: `WORKER_PROTOCOL.md:50-57`), one request per connection, at most 32 active connections, and five-second frame and write deadlines (`:30-32`). Unknown fields reject (`:43-44`). W: drops a connection at accept when `tasks.len() >= 32`, before any frame is parsed (W: `crates/kernel/chio-process/src/worker/unix.rs:13`, `:77-79`).
- `inspect` returns own id, parent and root, state, depth, limits, `tree_calls`, storage and checkpoint (W: `crates/kernel/chio-process/src/worker.rs:156-162`; `src/types.rs:136-146`). It reports no capability expiry or revocation status, recovery link, approval status or stop status.
- **N14.** The W: `inspect` handler calls `storage()` unconditionally (`worker.rs:158`). `storage()` requires raw knowledge at both the runtime and the store (W: `src/lib.rs:282-288`; `src/store/knowledge.rs:16-28`), so under enforcement the whole op fails as `runtime_error`. `public_process` already redacts the checkpoint value (`store/knowledge.rs:64-70`). No test exercises enforced `inspect`.
- **Enforced reads commit.** Every `process()` call under enforcement runs `store.enable_knowledge()`, an IMMEDIATE transaction with an UPDATE, a `CREATE TRIGGER IF NOT EXISTS` and a COMMIT (W: `src/lib.rs:240-251`; `store/knowledge.rs:4-15`).
- **`cancel` count.** `cancel` cancels the caller and its running descendants and returns how many rows changed (W: `src/store.rs:301-313`; `worker.rs:246`, `{"cancelled_processes": n}`). Confined children are spawned under the root (W: `crates/platform/chio-control-plane/src/confinement.rs:139-145`), so the count reveals whether a confined child was still running. That completion bit is one the P5 contract withholds (W: `docs/architecture/recoverable-agent-runtime/07-confined-returns.md:39`).
- Other confined-child surfaces do not leak: `wait_children` refuses targets that are neither in the run plan nor prefixed `dyn_` (W: `crates/products/chio-cli/src/cli/process_host/lifecycle.rs:207-221`); `inspect` reports only the caller's own process; the child holds no `chio-ipc` grant.
- Mailboxes are native `chio-ipc` tools under ordinary invocation (M: `MAILBOXES.md:3-7`): `receive` waits up to `wait_ms <= 30000`, a fresh key is required after an empty poll (`:97-105`), claims are at-least-once (`:113-143`). All W: store access serializes on one `Mutex<Store>` (W: `src/lib.rs:595-601`).

Recovery (W:):

- `admission_operation_recovery_records` and the immutable hash-chained `admission_operation_recovery_events`, one row per `(record_key, record_version)`, with a global monotonic `sequence` column (W: `admission_operation_recovery.sql:3-44`, `:30`). Records and events cannot be deleted (`:26-28`, `:42-44`).
- `InspectWorkflow` is a `RecoveryCommandBodyV1` that goes through the command executor, which persists a command record and appends a chain event against permanent quotas (`MAX_RECOVERY_COMMANDS = 4096` per tenant, 8192 globally; W: `crates/kernel/chio-kernel/src/recovery/records.rs:13`; `admission_operation_store/recovery/commands.rs:44-66`, `:236-247`; `recovery/storage.rs:157-202`). A repeated `command_id` returns the cached original response (`commands.rs:35-42`).
- `ChioKernel::read_recovery_workflow` revalidates the actor and loads the workflow without persisting anything (W: `crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery_runtime.rs:325-334`; callers at W: `chio-control-plane/src/recovery/runtime.rs:162`, `:249`, `:323`).
- `EffectObservationV1` has ten variants (W: `observation.rs:80-113`), including `Complete`, `Partial` and `FailedAfterEffect`. `WorkflowControlV1` is at `:164-169` and `ReleaseDispositionV1` at `:154-160`.
- Doc-only, not implemented in W:: the `recovery_deliveries` outbox (R: `03-recovery-protocol.md:114`), replayable delivery cursors with per-delivery audience recheck (R: `08-protocol-operations.md:19`, `:31`). The rule that an unavailable notification sink cannot trigger execution or refund (R: `08:94`) binds any future sink.

Work (assumed shipped, contract anchor): `WorkViewV1` observations are per authority and "not a globally atomic snapshot" (V: `2026-10-03-work-runtime-design.md:99`); queries make no mutations (`:87`).

A2A: `PendingApproval` maps to `TaskStatus::Working` (M: `crates/protocol/chio-a2a-edge/src/conversion.rs:99`; V: `:101`).

## 3. Goals and non-goals

Goals:

- **Part A.** No hosted transport path loses a terminal response or a correlated server request. Notification loss always surfaces as an explicit resync. Sequences are monotonic across restore. Subscriptions survive restore. Enforced `inspect` works. No worker op reveals confined-child status.
- **Part B.** One closed hint vocabulary with the same meaning on every surface; a bounded, coalesced, terminalized kernel session log; a low-latency process wait for own cancellation and budget thresholds with no call-budget charge; hints integrated with spec 9 effects without becoming decision inputs.

Non-goals:

- A new durable event log. Hints are rebuilt from authoritative state after a restart.
- Signed events, receipt-bearing events, or events as audit evidence.
- Exactly-once delivery of notifications. Part A guarantees exactly-once delivery attempts of terminal responses only within the slot's lifetime, not across a broken TCP connection.
- Bounding producers other than hints in the edge's `pending_notifications` (section 12.1 rule 4).
- Cross-owner delivery (section 14).
- Replacing mailboxes as an application data channel.
- Incremental A2A push.

---

# Part A. Bug-fix lane

Part A ships as independent fixes in `chio-mcp-remote`, `chio-mcp-edge` and W: `chio-process`. It adds no negotiated capability, no hint vocabulary and no process ABI field.

## 4. Hosted SSE delivery (D3)

### 4.1 Per-request response slot

Each POST request that expects a response registers a slot on the session **before** `session.send`:

```rust
pub struct InboundSeq(NonZeroU64);                       // session-local, monotonic, starts at 1, assigned at send (A1a); 0 is the no-cause sentinel
pub struct RequestSlot {
    request_id: Value,                                   // the JSON-RPC id of this POST
    cause: InboundSeq,                                   // the sequence its message is sent with
    response: oneshot::Sender<RemoteSessionEvent>,       // exactly one terminal response
    server_requests: SlotQueue<RemoteSessionEvent>,      // server-to-client requests caused by this POST
}
impl RemoteSession {
    fn reserve_inbound_seq(&self) -> Result<InboundSeq, SlotError>;   // first value 1, checked add; never issues 0; exhaustion fails closed
    fn register_request_slot(&self, cause: InboundSeq, request_id: Value,
                             credential_call: Option<PendingCall>)
        -> Result<RequestSlotReceiver, SlotError>;      // at most one active request slot per session
    fn send_with_seq(&self, seq: InboundSeq, message: Value) -> Result<(), SessionSendError>;
}
```

The POST handler reserves the sequence, registers the slot, then sends with that sequence, all while holding `active_request_stream`, so a fast response can never precede its slot.

Rules:

1. **A1. Writer routing by cause.** `BroadcastJsonRpcWriter::next_event` routes every request-correlated event by its **cause** (A1a), never by which slot happens to be active, before it publishes on the broadcast:
   - a response whose id equals a slot's `request_id` **and** whose cause equals that slot's `cause` fills `response`. Matching the cause as well as the id makes a reused JSON-RPC id harmless (M: `chio-mcp-edge/src/runtime/protocol/parsing.rs:139-146` notes that clients may reuse ids);
   - a server-to-client request (a message with both `method` and `id`) whose cause equals a live slot's `cause` is pushed to that slot's `server_requests`;
   - every other server-to-client request follows A1b.

   The broadcast still carries every event for compatibility, but POST streams no longer read request-correlated events from it.

   **Why not temporal correlation.** Revision 4 first correlated every server request emitted while a slot was active with that slot, on the grounds that `active_request_stream` serializes POSTs. Notification POSTs and client responses do not take that lock. The handler sends them even when `try_lock_owned()` fails, and on credential sessions it sends them without trying (M: `http_service.rs:363-394`; `main` `:390-399`). The edge runtime is serial, so a notification that arrives during call X is deferred, or waits in the input channel, and is handled after X's terminal response (M: `chio-mcp-edge/src/runtime.rs:426-449`; `nested_flow.rs:243-253`). A server request it causes, such as the `roots/list` that `notifications/roots/list_changed` queues (`runtime/requests.rs:127-133`, then `runtime_flow.rs:88-110`), is therefore emitted while some later POST's slot is active, and temporal correlation would hand it to that unrelated POST. Today's filter has the same defect in a weaker form: every POST stream emits every server-to-client request (`http_service_auth.rs:1-14`, the `event.message.get("method").is_some()` arm).
   - **A1a. Causal identity.** Every message the HTTP layer hands to the session input carries a session-local `InboundSeq`, assigned by `send_with_seq` under the input sender, so channel order equals sequence order.
     - The edge's hosted input becomes `InboundEnvelope { seq, message }`, replacing the bare `Value` of `serve_message_channels`. The stdio path assigns its own sequence in `pump_client_messages`.
     - The edge runtime holds a cause cell shared with the writer, an `Arc<AtomicU64>` where 0 means no cause. Zero is reserved for that sentinel: the session's counter starts at 1, `InboundSeq` wraps `NonZeroU64` so a zero sequence cannot be constructed, and exhaustion fails closed. The first request's response therefore always reaches its slot. The edge loop sets it to the envelope's sequence before handling a message, including a deferred one: `deferred_client_messages` (M: `runtime.rs:150`) stores envelopes, not bare values. The cell stays set through that message's pending actions and its terminal response.
     - **Nested client responses resume under the parent's cause.** A client response, meaning a reply to a server-to-client sampling, elicitation or roots request, arrives as its own inbound envelope with its own `seq`. Its `seq` is used only for transport bookkeeping. It never becomes the cause.
       - Each pending server request records `parent_cause`: the cause cell's value when it was issued.
       - When the response is matched to that request by JSON-RPC id, the edge sets the cell to `parent_cause` for the resumed continuation, and restores the previous value afterwards.
       - The parent call's eventual terminal response therefore carries the parent's original cause and reaches its slot, so the slot-owned request lock is released. The loop clears it before background servicing, task processing and runtime-event forwarding (`runtime.rs:426-449`; `runtime/tasks.rs:710-723`).
     - Pending actions capture their cause when queued. `EdgeAction::RefreshRoots` gains `cause: Option<InboundSeq>`, and processing the action sets the cell from it. A refresh queued at restore (`runtime.rs:318`) has no cause, so it is never attributed to the first request after restore.
     - The writer is driven synchronously from the edge worker thread (M: `session_core.rs:1094-1110`), and the edge changes the cell only between whole lines. The value `next_event` reads is therefore exactly the cause of the line it is publishing. `RemoteSessionEvent` gains `cause: Option<InboundSeq>`.
   - **A1b. Server requests with no request slot.** A server-to-client request caused by a notification, by a client response, by a request whose slot has already closed, or by nothing (background tasks, restore, late events) is never routed to a request slot:
     - with a GET notification stream attached, it is pushed to that attachment's **GET server-request queue** (A1d), never to the broadcast;
     - with none, the writer answers it locally at once with a JSON-RPC error (`-32603`, "no client stream for an uncorrelated server request") through the session input and increments `chio_mcp_remote_server_request_unroutable_total`. The edge takes its existing error path; for a roots refresh that is the `roots_refresh_failed` log (`runtime_flow.rs:96-107`).
   - **A1d. GET server-request queue.** Today both GET branches skip every event that is not a notification (M: `http_service.rs:810-812`, `:853`), so routing a server request to the GET stream through the broadcast would drop it at once. A1b instead delivers through a non-lossy queue owned by the GET attachment, with the same guarantees a POST slot gives in A2 and A2a:
     - **Ownership.** `try_attach_notification_stream` creates the queue together with the attachment, and dropping `NotificationStreamAttachment` closes it. The writer reads the attachment and pushes in one step under the session's attachment lock, so a request is either queued on a live attachment or takes the no-GET path. It is never pushed to a queue that has already closed.
     - **Bound.** The queue is bounded by `max_pending_server_requests`. On overflow the writer answers the excess request locally with the A2 error and increments `chio_mcp_remote_server_request_overflow_total`.
     - **Delivery tracking.** Each entry is `queued` until the GET stream yields it, then `delivered`. A delivered request stays answerable, because client responses bypass the request lock and reach the session input directly.
     - **Detach and disconnect.** When the attachment drops, every `queued` entry is answered locally at once with "client stream closed before the server request was delivered". A `delivered` entry with no answer is answered locally after `orphaned_server_request_grace`, as A2a does. Each local answer increments `chio_mcp_remote_server_request_orphaned_total`. Later uncorrelated requests take the no-GET path.
     - **Lag.** The queue is not the broadcast, so broadcast lag cannot skip a server request. A GET consumer that lags on notifications gets the A7 resync, and its queued server requests are unaffected.
     - **Replay.** Server requests are not retained in the replay window, which holds notifications only. A request that was still `queued` when the previous GET connection dropped was already answered locally at detach, so a reconnect with `Last-Event-ID` cannot silently miss one.
   - **A1c. Notification POSTs keep today's buffered response.** A notification POST that obtains the free lock (M: `http_service.rs:386-420`) registers a **notification slot** for its own sequence. The slot has no `response`, and it ends when the edge goes idle, as `collect_session_events_until_idle` does today. Server requests the notification causes, for example `roots/list` after `notifications/roots/list_changed`, still ride that POST's `post_notification_sse` response. A notification POST that finds the lock busy registers nothing and returns `202` as today, and A1b routes what it causes.
   - **Serialization was rejected.** Making notification POSTs wait for the request lock would also correlate correctly. But cancellations and client responses must bypass the lock: a cancellation must reach the active call, and a nested flow waits on a client response (M: `http_service.rs:364-366`; `nested_flow.rs:207-226`). Every other notification would then wait for the full duration of an in-flight tool call.
2. **A2. Non-lossy.** `response` is a `oneshot`, so it cannot overflow. `server_requests` is bounded by `max_pending_server_requests` (default 16). On overflow the writer never drops silently: it answers the excess server request locally with a JSON-RPC error (`-32603`, "server request queue full") through the session input, so the tool sees its elicitation or sampling request fail, and it increments `chio_mcp_remote_server_request_overflow_total`.
   - **A2a. Receiver loss is treated like overflow.** When the HTTP client disconnects, the POST stream drops the slot's receiving half. The receiver's `Drop` marks the slot `receiver_closed`, and the writer also checks the closed flag on every push. From that point, no server request correlated with the slot can wait forever on a client that is gone. The nested flow's `send_client_request` blocks on client input with no timeout of its own (M: `chio-mcp-edge/src/runtime/nested_flow.rs:207-226`).
     - Every server request queued in `server_requests` but never yielded to the client is answered locally at once with a JSON-RPC error (`-32603`, "client stream closed before the server request was delivered") through the session input.
     - Every later server request correlated with the slot is answered the same way when the writer routes it, without queueing.
     - A server request already yielded to the client stays answerable, because client responses bypass the request lock and reach the session input directly (M: `http_service.rs:362-394`). If no answer arrives within `orphaned_server_request_grace` (default 30 s, measured on the session's monotonic clock), the session answers it locally with "client stream closed; no response within grace".
     - Each local answer increments `chio_mcp_remote_server_request_orphaned_total`. A local answer is always an error, never a fabricated result.
     - The nested flow takes its existing error path, so the tool sees its sampling or elicitation request fail and returns. The slot then receives its terminal response, and the completion task (section 4.2) terminalizes the call. A local error for each orphaned request is preferred over cancelling the parent call, because the tool decides whether it can finish without the nested result, as with overflow in A2.
   - **A2b. The slot owns the request lock.** At registration, the `active_request_stream` guard moves from the stream into the slot. The slot releases it only when its terminal response has been routed, or when the session is cancelled (A12). The response is routed when it is handed to the stream or the completion task, or discarded because both receivers are gone.
     - A POST that arrives after its predecessor's client disconnected therefore still queues behind the running call. Every server request emitted meanwhile is routed by its cause (A1), so none reaches the queued POST's slot.
     - A2a bounds that wait for a call blocked on the client to at most `orphaned_server_request_grace`.
     - A call that never talks to the client waits exactly as long as the edge's serial runtime already makes it wait today: a new request is deferred while a nested flow is in flight (`nested_flow.rs:243-254`).
3. **A3. The stream reads the slot.** The POST stream selects over the slot receiver, the broadcast receiver (notifications only), and the session cancellation token (section 4.5). It emits the terminal response from the slot, then ends. Credential sessions emit only the terminal response, as today.
4. **A4. Initialize uses a slot.** The initialize handler registers a slot for the initialize request, so its response cannot be lost either.

### 4.2 Session-side call completion

`finish_call` moves out of the HTTP stream consumer:

- `register_request_slot` takes the pending credential call and spawns a **session-owned completion task**. The task awaits the terminal response from the slot, runs `finish_call` (through `spawn_blocking`, because it opens SQLite), applies `restrict_response`, and forwards the result to the stream through a second `oneshot`.
- The task runs whether or not the HTTP consumer survives. A client that disconnects after dispatch therefore leaves the call `completed_unacknowledged`, and a retry with the same `chioRequestId` replays it (`session_credentials.rs:661-688`). Transport loss no longer produces the operator fence.
- The task never depends on the departed client for progress. A2a fails the call's server requests once the stream's receiver is gone, so a tool blocked on sampling or elicitation returns and the terminal response arrives.
- The task also selects on the session cancellation token (A12). If the session is cancelled before the terminal response, the task leaves the durable pending fence, which is the honest outcome-unknown case.
- If `finish_call` fails, the behavior is today's: the task forwards the "credential outcome persistence failed; effect is uncertain" error and leaves the durable pending fence (`http_service.rs:486-493`). That fence now signals a real persistence failure, never a slow reader.
- Non-credential slots spawn no task; the stream awaits the slot directly.

### 4.3 Subscription order

- **A5. POST.** The POST handler subscribes to the broadcast after acquiring `active_request_stream` and immediately before `session.send` (replacing `http_service.rs:425-426`). A queued request no longer receives the events of the request ahead of it. Request-correlated events never come from the broadcast (A1), so a broadcast lag on a POST stream can only skip notifications.
- **A6. GET replay.** The GET replay branch subscribes **before** it takes the replay snapshot (moving `http_service.rs:839` above `:829`). The existing `event.seq <= delivered_through` filter (`:853`) removes the overlap. Both the live branch and the replay branch keep their notifications-only broadcast filter (`:810-812`, `:853`). Each also selects over the attachment's GET server-request queue (A1d), the only path by which a server request reaches a GET stream.

### 4.4 Lag: resync, never silent

After A1 and A1d, lag can skip only notifications. Correlated responses and server requests ride POST slots, and uncorrelated server requests ride the GET server-request queue; neither depends on the broadcast. Notifications are re-read hints (list changed, resource updated) plus advisory progress and log messages. Revision 4 answers lag with a resync in standard MCP vocabulary instead of terminating streams, because termination with a 64-notification window almost always yields `409` and a reconnect loop against the per-IP rate limiter (S5-12).

1. **A7. Resync request.** On `RecvError::Lagged(n)` at `:517`, `:702`, `:817` or `:860`, the consumer increments `chio_mcp_remote_stream_lag_total`, calls `session.request_resync(consumer_id, n)`, and keeps going.
   - **One record per attached consumer.** A GET stream or POST notification consumer owns its pending flag, skipped count, pass counter, follow-up flag and `ResyncCursor`. Detach drops only that record. A new attachment starts its own pass; it never inherits another consumer's progress.
   - **Complete pass cursor.** At pass start, take a bounded snapshot of the declared catalog notifications, optional warning with this pass's skipped count, and subscribed URIs in stable order. The existing subscription limit bounds the snapshot. `ResyncCursor = Prefix { next_index } | Resources { next_index } | Complete` indexes that snapshot, including every catalog and warning, not only URIs. Initialize at `Prefix { 0 }`, advance only after transport handoff of that item, and move to Resources only after the entire prefix. Exhaustion moves to Complete. Retain the cursor in the attachment's memory across loop iterations; it is not a durable resume-record field. A follow-up starts a fresh snapshot and Prefix cursor.
2. **A8. Consumer-directed, paced resync.** The existing session notification writer allocates ordinary event ids and retains each synthetic notification in the same session replay window, but routes its initial delivery only to the requesting consumer. It does not publish resync items to the shared broadcast. Ordinary source notifications keep their existing broadcast path. This splits routing in the same writer, not sequence allocation, retention, authorization or lifecycle ownership.
   - The pass contains one `notifications/{tools,resources,prompts}/list_changed` for each declared catalog, one `notifications/resources/updated` per snapshotted URI, and, if logging is enabled, one warning naming the skipped count. Current A30 authority and unsubscribe checks still run before any resource update is handed off.
   - **Backpressure before production.** Generate the next item only when that consumer's transport-facing notification slot has capacity. Reserve one bounded resync slot per attached consumer using the existing stream ownership bound, with at most one unhanded item; no whole pass or unbounded queue is materialized. A blocked consumer leaves its cursor unchanged and cannot fill another consumer's broadcast receiver. Multiplex ordinary and resync items in event-id order; buffered ordinary items preceding a synthetic id are drained, or accounted for by an explicit Lagged/resync transition, before that synthetic item is handed off. Request terminal slots and server-request queues remain independent under A1/A1d.
   - **Budget and fairness.** Across all consumers, generate at most `resync_chunk = broadcast_capacity / 4` items per loop iteration; configuration requires `broadcast_capacity >= 4`. Service ready consumers fairly. A prefix larger than the remaining budget spans chunks through `Prefix.next_index`. Another consumer's pass creates no broadcast entries and cannot itself cause this consumer's `Lagged` count to rise. Retention stays bounded by A10: on reconnect, synthetic notifications may be replayed as ordinary session-scoped re-read hints, without rebroadcasting or generating another pass. A cursor outside that window follows A11.
   - **Follow-up and convergence.** If ordinary source traffic causes another `Lagged` while a consumer has an unfinished pass, finish its current snapshot, then run at most one coalesced full follow-up from Prefix. Further lags add to that consumer's skipped count. Neither transport backpressure nor another consumer's resync increments its lag/pass-failure counter. With ordinary producers quiet, two initially lagged consumers converge even if their combined passes exceed the broadcast window.
   - **Perpetual source lag ends only that stream.** If one consumer lags on ordinary source traffic during `resync_max_passes` consecutive passes (default 3), a GET stream ends with `event: chio-resync-required`; a POST notification channel closes while its terminal response still uses A1's non-lossy slot. Drop only that consumer's record. The reconnect uses A10/A11. A slow or broken socket is handled by the existing transport timeout/cancellation, not counted as another source-lag pass.
3. **A9. Coverage.** Every list-changed and resource-updated meaning that a lag can skip is covered by the burst, because each is a re-read instruction. Lost progress and log messages cannot be reconstructed; the logging warning makes that loss explicit when logging is on, and progress notifications are advisory under MCP. A burst may deliver a re-read hint for something that did not change, which is always safe.
4. **A10. Window.** The retained window grows to 256 notifications, the broadcast capacity. A lagged consumer that reconnects with `Last-Event-ID` gets replay whenever fewer than 256 notifications passed since its cursor. Adjacent duplicates in the window coalesce: a newer `list_changed` of the same kind or `resources/updated` of the same URI replaces the older retained one. Coalescing only ever raises `oldest`, so a cursor before a removed entry gets `409`, which is conservative.
5. **A11. Client action after `409`.** WIRE_PROTOCOL 3.2 gains: after a `409` on `Last-Event-ID`, a client MUST re-list every catalog it uses, re-read every resource it is subscribed to, and reconnect without `Last-Event-ID`. Its subscriptions persist (section 6), so it does not re-subscribe.

### 4.5 Per-site handling and session cancellation

- **A12. Cancellation token.** Each `RemoteSession` owns a `CancellationToken` that every stream and collector selects on. Session termination, expiry, fail-closed teardown and shutdown cancel it. This replaces the reliance on `RecvError::Closed`, which cannot fire (section 2).
- **A13. POST stream on cancel.** A POST stream cancelled before its terminal response emits an explicit JSON-RPC error for its request id (`-32603`, "session ended before the response; outcome unknown") and ends. It never ends silently.
- **A14. Initialize (`:608`).** The response comes from the slot (A4). A lag while buffering the notifications that precede it fails closed: the handler returns 5xx and runs the existing fail-closed session teardown (`fail_closed_session_after_persistence_error`); the session is never inserted.
- **A15. Idle collector (`:702`).** A lag appends a resync request (A7) and the collector returns what it buffered. The burst reaches the client on its next stream.
- **A16. Wedge.** With A1, A2a, A2b and A12, the slot holding `active_request_stream` always completes, in one of three ways:
  - its terminal response arrives;
  - the session is cancelled;
  - the HTTP client disconnects, and A2a fails the call's undelivered and future server requests at once and its delivered ones after the grace window, so the tool can return.

  The stream ending does not release the lock by itself (A2b). The session-owned completion task (section 4.2) is unaffected by the stream ending.

### 4.6 Retry rule

A POST whose HTTP connection breaks before its response arrives has an unknown outcome at the client. Revision 4 states when a retry is safe, per surface:

| Surface | Safe retry | Why |
|---|---|---|
| Credential session | Same `chioRequestId` | The completion task records the outcome regardless of the consumer (section 4.2); `reserve_at` replays `completed_unacknowledged`. A real persistence failure still fences |
| Non-credential, durable admission, with `chioRequestId` | Same `chioRequestId` | The stable request id binds one admission operation; a replay returns the bound terminal result and never redispatches |
| Strict-nonce request | Same nonce | The request identity is bound into the nonce (`parsing.rs:136-139`) |
| Anything else (no `chioRequestId`, or a non-durable call) | **Not safe** | A retry gets a fresh kernel identity (`parsing.rs:139-146`) and redispatches |

- WIRE_PROTOCOL 3.2 gains: a client that needs retry safety for a side-effecting tool MUST send `_meta.chioRequestId`; a client without it MUST treat a broken POST as outcome unknown and MUST NOT retry blindly.
- Where the server can still reach the client (A13), it sends the explicit outcome-unknown error.
- Revision 3's sentence "admission idempotency returns the bound terminal result" is withdrawn for the general case.

## 5. Monotonic sequences across restore (D4)

Restored sessions seed sequences from a fresh generation, so ids from an earlier incarnation fall below every id in the new one.

1. **A17. Compute before, persist after.** In `restore_persisted_sessions`, for each loaded record:
   - require `record.resume_generation < 2^32 - 1` to form the next event-id seed; otherwise retain the record inactive (A19) and log. This is an event-seeding bound only, not the native persistence-counter bound (A22a);
   - compute `g = record.resume_generation + 1` (checked) **without persisting**, and pass the seed `g << 32` (checked shift) to the restore constructor, replacing the zero seeds at `factory.rs:468` and `:684`. Initialize the candidate's existing `resume_generation` counter to `g` as well; retain the loaded record at `g - 1` separately for the pre-persist expiry/terminal path. A17 signs its candidate at `g` directly, without a second increment through the ordinary resume-record signer;
   - while the restored candidate is still unserved and the stored generation is unchanged, stage A25's subscription restore in a candidate copy of the complete record. Recheck every standard subscription after all subscription I/O, arm A30's authority/expiry gate, and recheck the original monotonic deadline (`session_recovery.rs:51-64`) immediately before persisting. Neither constructing the candidate nor restoring its subscriptions writes an active resume record;
   - **Part B marker preparation is in this same stage.** Apply H5a/H7 to negotiated entries, staging newly ended subscriptions and retaining every existing `Ended` marker's logical identity and reason. Allocate each pending end a distinct event id from the candidate's sequence allocator in generation `g`; store that exact id in its candidate marker and staged event. Advance the allocator past all of them before catch-up or other events can allocate ids. These are in-memory candidate updates, not independent marker persists;
   - only after the checks pass, set `resume_generation = g` on the complete candidate record, sign it under A28 and persist it **once**, including every staged subscription transition and rebased `end_event_id`. Unchanged entries and unrelated fields carry over intact. A17 never rewrites a v3 record under the v2 HMAC. No staged event is visible before this commit;
   - then activate through A30's gate, including a fresh authority/expiry check after the persistence I/O, and call `insert_active` only if it passes. With Part B, re-queue the exact committed end ids before catch-up. Failure after active `g` has committed uses A30's existing persistence counter, now at least `g`, not A25's pre-persist terminal epoch `g`. A crash before activation exposes no events; the next boot loads the committed record and rebases again.
2. **A18. Expiry path.** If the deadline check finds the session expired, nothing with generation `g` has been persisted, so `expire_record`'s terminal epoch `record.resume_generation + 1 = g` exceeds the active generation and the store accepts it (`session_store.rs:980-985`). The session was never served.
3. **A19. Per-session failure.** If the persist of `g` fails, the restored session's upstream transport is stopped and the record is retained inactive (the existing "retaining incompatible MCP session without activating it" branch). Startup continues for other sessions. Events the unserved incarnation produced were never visible to a client, and the next restart computes the same `g` from the unchanged persisted generation, which is safe for the same reason.
   - With Part B, a failed candidate persist that includes a newly terminalized negotiated entry takes H5a's failed-marker path through A31 instead: journal and complete the session terminal before further restore. It must not fall back to the old `Negotiated` entry and later resurrect it. A failed rebase of an already durable `Ended` marker alone can retain the session inactive, because the old marker still preserves the logical end.
4. **A20. Why the persist is required.** `resume_generation` advances only per signed record (section 2). Without persisting `g`, a session restored twice with no intervening write would compute the same seed twice and serve both incarnations from it.
5. **A21. Fresh sessions** seed `next_event_id = 0` and persist nothing before Ready (`resume_record` returns `None` before Ready, `session_core/session.rs:182-195`). Their first resume record has generation at least 1, so the first restore seeds at least `2 << 32`, above every fresh-incarnation id.
6. **A22. Low-bit exhaustion.** Reserve the last low-bit value (`u32::MAX`) of each incarnation for its one terminal event. Nonterminal allocation stops before using that value and invokes the terminal persistence path; it never reseeds inside the writer. Compute the terminal event id as `(g << 32) | u32::MAX`, with checked `u64` operations, rather than `(g + 1) << 32`, which overflows at the last seed. The terminal slot owns that reserved id on exhaustion; an earlier ordinary close may allocate its next unused id normally. No two events use the same id.
   - **A22a. Persistence counters are wider than event prefixes.** The native `resume_generation`, fence generation and `terminal_epoch` are `u64`, and `next_terminal_persistence_epoch()` returns `u64` (V3: `session_core.rs:275-307`; `session_core/session.rs:319-320`). Keep those types and their native store validation. The 32-bit seed restriction never applies to a terminal write or an ordinary persistence-counter increment. A restored event incarnation at `g = 2^32 - 1` can close at native persistence generation `2^32` (or later if ordinary signed writes advanced the counter); that terminal generation is never shifted into an event id. A31/H6a bind the full-width persistence generation and the separate transport event id. The new profile explicitly caps persisted generations at `MAX_SESSION_PERSISTENCE_GENERATION = i64::MAX as u64`, compatible with the native SQLite INTEGER terminal_epoch column (`session_store.rs:671`, `:1026`), and checks that bound on load and before increment. Reserve terminal headroom at that limit too: before an ordinary record increment would consume its final representable generation, stop active writes and use that final generation for the journaled terminal transition. An already invalid/exhausted imported counter is refused at load rather than activated.
7. **A23. Unchanged.** The wire format `{session_id}-{sequence}` and its parser (`http_service.rs:1095-1104`) are unchanged. Every earlier-incarnation id falls below `oldest - 1`, so `replay_notifications_after` refuses it with `409` (`session_core/session.rs:141`).

## 6. Subscriptions survive restore

Revision 4 persists subscriptions rather than asking clients to re-subscribe, because MCP has no "subscription ended" notification that existing clients understand.

1. **A24. Persisted set.** The resume record gains `subscriptions: Vec<PersistedSubscription>`. Part A covers only standard MCP resource subscriptions, keyed the way the existing session owner keys them: by URI within the session (V3: `chio-kernel/src/kernel/session_ops.rs:319-354`; `chio-mcp-edge/src/runtime/requests.rs:551-582`, `:597-618`). V3 = #1173 at `79d0c8a97`; the seam is unchanged from M:.
   - `PersistedSubscription = Standard { uri, capability_id }`. Part A has no end marker: a standard subscription that fails authority at restore or later ends its session (A25, A30).
   - Standard MCP has no client-visible subscription id. `resources/subscribe { uri }` returns `{}`, and `resources/unsubscribe` takes the URI. The URI is the key, and a repeated subscribe to the same URI is idempotent, as in the session owner today.
   - The set sits inside the integrity envelope under a new schema label, `chio.remote-mcp.resume-record-integrity.v3`. A successful `resources/subscribe` or `resources/unsubscribe` signs and persists a new resume record. If that persist fails, the call returns an error and the registry change is rolled back, so the client never holds a subscription the store does not know.
   - **Part B extends the same record and owner.** It adds `Negotiated { subscription_id, subject, capability_id }` and its end marker `Ended { subscription_id, subject, capability_id, reason, end_event_id }` (H5a), for subscriptions created by `chio/events/subscribe` only. The stable `subscription_id` identifies the one possible logical end for that subscription; `end_event_id` is its current transport/replay sequence only and may be rebased without changing acknowledgement identity (H5a). A standard entry never gains an id. The kernel registers a URI upstream once, whether a standard entry, a negotiated one or both hold it. Part A neither requires nor emits any Part B method or notification.
2. **A25. Re-authorization at restore.** Before A17's generation persist and before `insert_active`, restore branches on each standard entry:
   - **`Standard` entries** use the ordinary `resources/subscribe` authorization and registration logic in an unserved restore mode: validate the capability, check scope, check the subject exists (`session_ops.rs:320-338`), then register it, including any upstream forwarding. This mode produces no client acknowledgement and performs none of A24's per-subscribe resume-record writes. It stages subscriptions only in the candidate; A17 persists the complete record once after all entries and the final deadline check pass. The session owner shares the checks rather than maintaining a second authorization path.
   - **A failed re-authorization ends the session, not just the subscription.** A `Standard` entry may fail because its capability expired or was revoked, or because its subject is gone. Then restore stops the candidate's upstream transport and does not serve the session at all. It terminalizes it through A18's existing terminal path: the terminal epoch `g` is written to the session store, which accepts it over the unchanged stored generation `g - 1` (`session_store.rs:980-985`), with reason `subscription_not_restored`. No active record at generation `g` has been written, even if an earlier entry restored successfully. The store's strictly-newer terminal-epoch requirement is unchanged.
     - **Why the session.** Standard MCP has no notification that a subscription ended, and nothing else the client observes can carry it. Read and subscribe authority are matched separately (V3: `chio-kernel/src/request_matching.rs:1065-1071`; `chio-mcp-edge/src/runtime/protocol/capabilities.rs:25-46`). A read can therefore succeed with a valid read grant after the subscribe grant expired, and a subject missing at restore can reappear before the read. So a successful update and read look exactly like a live subscription, while later updates are dropped (V3: `chio-kernel/src/session.rs:1121-1124`). A terminated session is unambiguous.
     - **What the client sees.** The client reconnects, receives the existing terminal-state response for that session (WIRE_PROTOCOL 3.3), initializes a new session and subscribes again. The new subscribe runs the ordinary authorization path. A subscription that is still unauthorized is refused explicitly there, even when a read of the same resource is allowed.
     - **Durability.** A31 journals the exact terminal intent before the existing terminal path prepares its fence and finalizes its tombstone (`session_recovery.rs:138-139`). A journaled failure is completed before any session restore, even if its cause later clears. Only a failure of the journal write itself can leave the unchanged active record for re-evaluation after a crash, under A31's stated limit. A committed fence always blocks restore; the diagnostic terminal-state response is promised only after the tombstone commits. A session missing one of its persisted subscriptions is never served.
     - A read is never treated as evidence about a subscription, and no authorized read is ever refused to encode subscription state.
3. **A26. Catch-up.** Updates during downtime were lost, so restore posts one `notifications/resources/updated` for every restored URI. Every persisted subscription of a served session was re-authorized, because one that fails ends the session (A25). A client that negotiated Part B receives `SubscriptionEnded` for its own negotiated subscriptions instead of a session terminal (H5a). A failed standard subscription in the same session still terminalizes the session.
4. **A27. Downgrade.** A binary that predates the v3 envelope fails integrity on such a record and treats it as malformed (`session_recovery.rs:30-31` deletes it). Downgrade therefore loses sessions with subscriptions rather than restoring them without subscriptions. This is stated as a migration note.
5. **A28. Envelope selection on every re-sign.** Today's tag covers a fixed v2 field list with no `subscriptions` (M: `session_resume.rs:801-829`). The record therefore names its envelope in `resume_integrity.envelope`, and an absent value means `v2` for records written before this change. The version is part of the MAC'd bytes, because the schema label differs, so relabeling a record changes its tag. Every re-sign applies the same rule: A17's generation bump, A24's subscribe and unsubscribe persists, and terminal records, with A32 requiring v3 whenever a typed terminal reason is present.
   - A record with a non-empty `subscriptions` is signed `v3`.
   - A record loaded as `v3` is signed `v3` again, even after its last subscription is removed. The version never decreases.
   - Otherwise the writer uses the deployment's `resume_record_envelope_floor`. The default is `v3`. Set it to `v2` only during an upgrade window in which an older binary may still open the store.
   - The signer has no path that writes a `v3` record's fields under `v2`. If the selection would ever lower the version, the re-sign is refused fail closed and the session is retained inactive (A19).
6. **A29. Verification.** The loader verifies a record under the envelope it names.
   - A `v3`-named record that fails `v3` verification is malformed (the existing deletion path), and it is never retried under `v2`. A relabeled record therefore cannot pass with its subscriptions stripped or unauthenticated.
   - A `v2`-named record with a non-empty `subscriptions` is malformed, because `v2` does not authenticate that field.
   - A27's downgrade note covers every record signed `v3`, including records upgraded by the floor.
7. **A30. Standard subscription authority stays live (Part A).** URI membership is routing state, never sufficient delivery authority. V3's `queue_tool_server_event` only tests that membership (`chio-kernel/src/session.rs:1121-1124`), so Part A adds the following checks to the existing session owner, for newly subscribed and restored standard entries alike:
   - **One checker.** Retain each URI's authorizing capability id and current auth-context generation. Share the ordinary subscribe validator (capability and lineage, current revocation, scope, resource existence and authority time), using subscribe authority rather than a read grant. Do not silently replace a failed grant with another capability. This is a read-only authorization check: it neither re-subscribes nor creates an admission or consumes an invocation budget, and it preserves spec 8's SessionEventRelay stop disposition. Standard and negotiated entries later use the same checker, with their existing operation-specific authority predicates.
   - **Check at emission.** First discard queued notifications for URIs the client has unsubscribed from; ordinary unsubscribe is not an authority failure and does not end the session. For entries still subscribed, revalidate immediately before handing each standard `resources/updated` frame to the transport. This covers live GET and POST notifications, buffered collectors, replay, restore catch-up and A8 resync. Queueing a URI is only a candidate notification. The gate serializes emission with auth rotation and the terminal latch; a result checked under an old auth generation cannot be emitted under a new one. No earlier enqueue-time check or replayed frame bypasses it. A frame already handed to the transport cannot be recalled; queued frames are checked when handed off.
   - **Rotation and activation.** Auth rotation revalidates every standard subscription against the new context before further emission and re-arms its expiry. Removal of its bound capability, failed scope or lineage validation, revocation, missing resource or unavailable authority refuses the session. Restore repeats the check after its persistence I/O and before activation, closing the window where an early subscription expires while later entries are being restored. Revocation notifications may wake checks sooner, but no delivery depends on receiving such a notification.
   - **Quiet expiry.** Part A owns the session's bounded `ExpirySchedule`, keyed by each subscription's earliest authorizing capability/lineage deadline. Subscribe reserves schedule capacity before persisting or acknowledging the URI, using `max_subscriptions` (default 256), the same client-subscription bound Part B extends; failure refuses the subscribe without changing the registry. Restore and auth rotation re-arm it before serving; unsubscribe removes its entry. Failure to restore capacity retains the session inactive, never active without its timer. A monotonic timer wakes at the earliest deadline and confirms it against the authority clock. A scan every `expiry_scan_ms` (default 1000) catches authority-clock adjustments. A backward adjustment never extends an armed monotonic deadline; if time cannot be confirmed safely at that deadline, fail closed rather than re-arm it later. The check runs without a pending event or active request. Clock unavailability fails closed for time-bounded entries; it never extends their grants. Part B extends this same schedule to negotiated subjects (H7a), rather than creating another timer owner.
   - **Failure ends the standard session.** Latch the session terminal before any further resource-update emission, discard pending resource updates and stop its upstream transport. Use reason `subscription_not_restored` before activation and `subscription_authority_lost` afterwards, then A31's existing terminal-store path and A12 cancellation. No Part B wire method, id or notification is used. A pre-persist restore failure still uses A25's epoch `g`; once an active record has been persisted, serialize against outstanding session-record writes and use the existing `next_terminal_persistence_epoch` counter (V3: `session_core/session.rs:319-320`). A17 initializes that counter to `g`; ordinary resume-record signing advances it before submitting each write (`:266`), so its next value exceeds both the committed generation and any submitted write whose acknowledgement was lost. This needs no database read during an outage. Never reuse the restore seed as a terminal epoch. A failed persist leaves delivery stopped. If Part B is negotiated, its terminal event may also be emitted under H6a, but a failed standard entry always ends the whole session.
8. **A31. Shared durable terminal intent (Part A foundation).** The `pending_terminal` storage helper described in H6a ships with Part A's standard-subscription lifecycle. There is one journal and one terminal-store owner, independent of whether the client negotiates Part B.
   - Before signing or attempting either SQLite terminal write, fsync the complete intent in `pending_terminal` under the session-store ownership lease: session id, typed `TerminalReason` (A32), complete native fence and tombstone payloads, and their generation and terminal timestamp. Then sign under A28/A32 and atomically persist the exact signed records in that same journal entry before any SQLite write. A signing failure leaves the durable intent pending and the store not ready; it cannot restore the session. Once signed records are journaled, replay reuses those exact bytes and identities. Part B extends the same entry with its retained `terminal_event` and replay metadata; Part A requires none of that wire state.
   - Then prepare the fence and finalize the tombstone. Remove the journal entry only after finalization commits. On a write failure, the session stays stopped and the store is not ready; retry the same intent. On boot, complete every pending intent before restoring any active record. Replay first reads the native terminal state: an identical finalized tombstone completes the intent without preparing or signing again; an identical fence needs only finalization; no fence requires preparation then finalization. Any identity or byte mismatch leaves the store not ready. A fence-only crash therefore cannot resurrect a subscription or lose the pending diagnostic tombstone, and a crash after finalization but before journal cleanup cannot wedge replay.
   - If the initial intent journal write itself fails, stop serving the session store and do not attempt an unjournaled terminal write. No writable durable medium has recorded the refusal; a crash in this one window may restore the old session, but A25/A30 must re-authorize all its subscriptions before serving it. This is the same journal-write limit as H5a/H6a, not a claim that an in-memory stop survives a crash.
9. **A32. One terminal-reason vocabulary.** Define `TerminalReason` in the existing session lifecycle types, independent of the hint module. It is a closed, snake-case serialized enum shared by terminal persistence and Part B's `HintKind::Terminal`:

   | Rust variant | Serialized value | Native terminal state and use |
   |---|---|---|
   | `Deleted` | `deleted` | `Deleted`, explicit session deletion |
   | `Expired` | `expired` | `Expired`, session lifecycle deadline (including A18) |
   | `Closed` | `closed` | `Closed`, ordinary close or another fail-closed termination, including sequence exhaustion or a failed negotiated end-marker persist |
   | `SubscriptionNotRestored` | `subscription_not_restored` | `Closed`, A25/A30 standard-subscription failure before activation |
   | `SubscriptionAuthorityLost` | `subscription_authority_lost` | `Closed`, A30 standard-subscription failure after activation, including expiry, revocation or unavailable authority |

   - **Persist the cause, not only the state.** V3's native diagnostic and fence records contain lifecycle state but no reason (`session_core.rs:252-307`); the state cannot distinguish the two subscription failures. Add `terminal_reason: TerminalReason` to the new diagnostic/tombstone and fence payloads, and use the same value in A31's intent. A32's state/reason pairing is checked before signing and on load. The first terminal transition chooses it once; retry, crash recovery and Part B delivery preserve it even if authority later recovers. Other diagnostics may explain a generic `closed`, but are not new reason variants.
   - **Signed representation.** Extend A28's envelope discriminator to the existing terminal record family. New reason-bearing records use `chio.remote-mcp.terminal-fence-integrity.v3` and `chio.remote-mcp.terminal-tombstone-integrity.v3`; V3 currently uses the corresponding `.v2` labels (`session_resume.rs:972`, `:992`). The v3 fence MAC covers `terminal_reason` alongside all existing fence fields; the v3 tombstone MAC covers the complete diagnostic record including that reason. `resume_integrity.envelope = v3` selects these envelopes. No reason-bearing terminal is signed under v2, even during a v2 resume-record upgrade window. The journal records the selected schemas and complete payloads before signing, then their exact signed bytes under A31. Fence/tombstone matching and journal readback compare the reason as well as the native identity, state and generation.
   - **Compatibility and failure.** Legacy v2 terminal records have no reason; verify their unchanged v2 field list and retain them without inventing a subscription cause. They carry no new Part B terminal replay. A v2 record that supplies `terminal_reason`, a v3 record missing it, an unknown value or an invalid state/reason pair is refused. Never strip the field, fall back to v2 verification or restore an active session to recover from a terminal-record error: retain the terminal fence/journal and keep the store not ready. Existing exact signed journal entries replay under their recorded version; upgrading does not re-sign them. Qualify v3 terminal codecs with A24-A31 before enabling subscriptions. A writer without v3 terminal support cannot take over a store retaining these records or intents; downgrade requires an explicit terminal-store migration that preserves their fences.
   - **Part A and Part B.** Part A's client still receives only the existing terminal-state response; this adds no MCP method or notification. Part B imports this exact enum for `Terminal { reason }` and its generated notification schema. Its retained event, journal, signed fence and tombstone must agree on the reason. The hint remains unsigned and non-authoritative; its reason is copied from the owning terminal transition, not reconstructed from a generic `Closed` state. `EndReason` is a separate subscription-scoped vocabulary and cannot substitute for `TerminalReason`.

## 7. Process worker fixes (W:)

### 7.1 N14: enforced `inspect` (P6 bullets 1-2)

6. **P6. Enforced knowledge.** When durable knowledge is enforced, `inspect` MUST:
   - return the redacted public snapshot (checkpoint value null, W: `store/knowledge.rs:64-70`);
   - omit `storage` instead of failing.

   The handler decides from the enforcement state (`self.runtime` reports it), not by matching the refusal message, so any other `storage()` error still fails the op.

- Ships in W: under whatever `PROCESS_ABI` W: lands. Omitting a response field needs no new request field, so it does not wait for the v4 union. `WORKER_PROTOCOL.md` states that `storage` is absent under enforcement.
- Under enforcement every `inspect` still commits (`enable_knowledge` per read, section 2). Part A does not change that; Part B's long-poll requires the enable-once fix (section 12.2, P2).
- Revision 3's third P6 bullet (advance `hint_revision` for protected changes) is replaced in Part B by S5-20: protected changes never advance it.

### 7.2 `cancel` count excludes confined children

- `Store::cancel` still cancels every running descendant, confined children included. The returned count excludes ids prefixed `confined_`: the UPDATE uses `RETURNING id` and counts only non-confined ids.
- Hosts state that `Children` and shared-budget projections exclude confined children (H9).

## 8. Failure modes (Part A)

| Failure | Behavior |
|---|---|
| Broadcast lag on any stream | Metric, coalesced resync request, burst of re-read notifications (A7-A9). Responses and server requests are unaffected (A1, A1d) |
| Correlated server-request overflow | Excess request answered locally with a JSON-RPC error; never dropped silently (A2) |
| Server request caused by a notification, a client response, a closed request or background work | The GET server-request queue if a GET stream is attached, otherwise answered locally with an error; never routed to the active request slot (A1b, A1d) |
| GET server-request queue overflow, or GET stream detaches | Excess or undelivered requests answered locally at once; a delivered one after `orphaned_server_request_grace`; never dropped silently (A1d) |
| Inbound sequence exhausted | Session terminated fail closed (unreachable in practice) (A1a) |
| HTTP client disconnects mid-call | Stream dropped; the slot keeps the lock until the terminal response (A2b); completion task records the credential outcome (section 4.2) |
| HTTP client disconnects while the tool waits on a server request | Undelivered and later server requests answered locally with an error at once; a delivered one after `orphaned_server_request_grace`; the tool returns and the call terminalizes (A2a) |
| Session terminates before a response | Explicit outcome-unknown error on the POST stream (A13) |
| Lag during initialize | 5xx and fail-closed teardown; session never inserted (A14) |
| `finish_call` persistence fails | Today's uncertain-effect error and durable fence (section 4.2) |
| Retry without `chioRequestId` | Not safe; documented outcome unknown (section 4.6) |
| Restore: generation persist fails | That session retained inactive; startup continues (A19) |
| Restore: expired after construction | Terminal record with epoch `g`, accepted (A18) |
| Generation at `2^32 - 1`, or low bits exhausted | Retained inactive, or terminated fail closed (A17, A22) |
| Subscribe persist fails | Subscribe returns an error; registry unchanged (A24) |
| Standard subscription fails re-authorization at restore or activation | The session is never served. A25/A30 journal the terminal intent through A31 with reason `subscription_not_restored`; boot completes it before restore. Only a failed journal write permits later re-authorization after a crash |
| Standard subscription expires or fails delivery/auth-rotation revalidation | Latch and terminate the session with `subscription_authority_lost` through A30/A31. No queued, replayed or resync resource update bypasses the check, and quiet expiry needs no incoming event |
| A re-sign would lower a `v3` record to `v2` | Refused fail closed; session retained inactive (A28) |
| `v3` record fails `v3` verification, or a `v2` record carries `subscriptions` | Malformed; existing deletion path; never retried under `v2` (A29) |
| Enforced `inspect` | Redacted snapshot without `storage` (P6) |

## 9. Wire impact and rollout (Part A)

- **`spec/WIRE_PROTOCOL.md` section 3.2** gains:
  - a lagged stream MUST NOT drop events silently; the server emits a resync burst of re-read notifications (A8);
  - a terminal response and its correlated server requests MUST NOT be lost to lag (A1);
  - a server-to-client request is delivered only on the POST stream of the request or notification that caused it, or on the GET stream. A server request that cannot be delivered is answered locally with a JSON-RPC error, never dropped silently (A1d). A client that wants server requests caused by its own lock-contended notifications (for example `roots/list` after `notifications/roots/list_changed`) keeps a GET stream open (A1b, A1c);
  - sequences MUST be monotonic across restore (section 5);
  - the client action after `409` (A11);
  - the retry rule (section 4.6).
- **Hosted resume record:** `subscriptions`, `resume_integrity.envelope` and the v3 integrity envelope; the `resume_record_envelope_floor` setting (A24, A27-A29).
- **Session terminal reasons and persistence:** A32 defines `TerminalReason`, including both `subscription_not_restored` (A25/A30 before activation) and `subscription_authority_lost` (A30 after activation). It versions and authenticates that field in the native terminal fence/tombstone v3 envelopes and retains it in A31's journal. Clients see only the existing terminal-state response (WIRE_PROTOCOL 3.3); no new method or notification is added.
- **`WORKER_PROTOCOL.md`:** `storage` absent under enforced knowledge; `cancelled_processes` excludes confined children.
- **Internal API, not wire:** `chio-mcp-edge` `serve_message_channels` takes `InboundEnvelope` values and a cause cell (A1a).
- **No change** to negotiation, capability, receipt or manifest schemas. The hosted resume and terminal integrity schemas change as specified above.

Rollout order, each an independent change: (1) A5, A6 and A12 (ordering and cancellation, smallest diff); (2) causal identity, slots and session-side completion (A1-A4 including A1a-A1c, section 4.2); (3) resync (A7-A11); (4) generation seeding (section 5); (5) persisted subscriptions together with ongoing authority checks, the expiry schedule, shared terminal-intent persistence and versioned terminal reasons (A24-A32, section 6); (6) W: P6 and `cancel` count. Step 5 does not wait for any Part B protocol.

## 10. Tests (Part A)

- **`chio-mcp-remote`:**
  - **resync routing and complete cursors (A7/A8):** use one GET and one POST notification consumer and enough URIs that their combined passes exceed the broadcast capacity. Cause initial lag on both, then quiesce ordinary producers. Slow one transport arbitrarily: neither resync writes to the shared broadcast, neither causes a new Lagged/pass-failure count, and the ready consumer finishes independently. Each receives a full prefix and URI pass, with at most one unhanded synthetic item and one shared generation budget per loop. Start the second pass when the first is in its URI suffix, detach/re-attach one consumer, and inject ordinary source lag into only one consumer; cursors and follow-ups remain independent. With broadcast_capacity 4, resync_chunk is 1: emit every enabled catalog and warning exactly once in order before URIs, retaining the prefix index between iterations. Reject capacities below 4. Replay retained synthetic hints without rebroadcasting; evicted cursors get 409. Assert monotonically ordered ids across ordinary and directed delivery;
  - **generation boundary (A22/A22a):** restore from `2^32 - 2`, persist/activate event seed `2^32 - 1`, then expire, close, or lose subscription authority. Each terminal fence/tombstone uses full-width persistence generation `2^32` or the counter's later next value and commits successfully. With Part B, exhaust ordinary low bits and use the reserved final event id without overflow; the terminal epoch and event id are distinct fields. At the native persistence-domain boundary, ordinary writes leave the final counter value for a terminal. No boundary case activates an un-fenceable session;
  - **terminal reason conformance (A32):** round-trip every declared reason and its permitted terminal state through the intent journal, signed v3 fence and signed v3 tombstone. Pre-activation failure preserves `subscription_not_restored`; expiry/revocation after activation preserves `subscription_authority_lost`, including a quiet session. Crash before signing, after fence preparation and after tombstone finalization; replay keeps the exact cause and signed bytes. Tamper only with the reason, remove it, supply an unknown value, change the state/reason pair or relabel as v2: verification refuses without restoring the session. Legacy v2 fixtures still verify without a reason. With Part B negotiated, the retained and replayed `Terminal` carries exactly the committed reason; a standard client receives no new notification;
  - broadcast capacity 8 with a streaming tool and no `chioRequestId`: the terminal response is delivered, the tool is dispatched exactly once, and a resync burst follows the lag;
  - the same on a credential session: the call ends `completed_unacknowledged`, never `pending`, and a retry with the same `chioRequestId` replays;
  - drop the HTTP consumer after dispatch on a credential session: the completion task still finishes the call;
  - a request queued behind a long streaming request receives none of the earlier request's events (A5);
  - GET replay with a notification injected between snapshot and subscribe (test hook): delivered exactly once (A6);
  - server-request overflow answers locally and increments the metric (A2);
  - **notification-caused server request while a slot is active (A1, A1b). Fails on current code.** A tool call X sleeps without talking to the client, and the client POSTs `notifications/roots/list_changed`, which gets `202` because the lock is busy. A POST Y queues behind X.
    - When X returns, the edge emits `roots/list` stamped with the notification's cause.
    - With a GET stream attached it arrives on the GET stream. Without one it is answered locally, `roots_refresh_failed` is logged and the unroutable metric increments.
    - It never appears on X's stream or Y's stream. Today's filter (`http_service_auth.rs:1-14`) emits it on Y's stream.
  - **GET-bound server requests (A1d).** In each case a `notifications/roots/list_changed` POST finds the lock busy, so the `roots/list` it causes has no slot and is GET-bound:
    - ordinary delivery: with a GET stream attached, `roots/list` arrives on the GET stream exactly once, and the client's answer reaches the edge. Fails on current code, whose live filter (`http_service.rs:810-812`) drops it;
    - lag: with broadcast capacity 8, a GET consumer lags on notifications while `roots/list` is queued. The request is still delivered, and a resync burst follows;
    - detach: the GET stream drops while `roots/list` is queued. It is answered locally at once, `roots_refresh_failed` is logged and the orphaned metric increments. A delivered but unanswered request is answered locally at the grace bound (test clock);
    - overflow: `max_pending_server_requests + 1` GET-bound requests yield one local overflow error;
  - **id reuse (A1).** Two sequential POSTs reuse one JSON-RPC id. A response stamped with the first POST's cause never fills the second slot;
  - **free lock (A1c).** `notifications/roots/list_changed` on an idle session still returns `post_notification_sse` carrying the `roots/list` request;
  - **receiver loss (A2a), credential session.** A tool blocks on `sampling/createMessage`, then the HTTP client disconnects:
    - request not yet yielded: it is answered locally at once, the tool returns, the call ends `completed_unacknowledged`, and the next POST on the session proceeds;
    - request already yielded: a client POST answer within the grace window reaches the tool; without one, the local error arrives at the grace bound (test clock);
    - in both cases a later server request from the same call is answered locally without queueing;
  - after a disconnect, a second POST waits for the first slot's terminal response, and no server request from the first call is routed to the second slot (A2b);
  - session termination mid-call yields the outcome-unknown error (A13); a later POST on the session is not blocked (A16);
  - lag during initialize returns 5xx and the session is absent from the ledger (A14);
  - **D4, fails on current code:** restore, restore again with no intervening write, then emit at least as many notifications as the stale cursor's sequence; replay with the stale cursor returns `409` with the fix, and a negative control that forces seed 0 shows the aliased replay;
  - expired-after-construction restore succeeds and persists the terminal record (A18);
  - **restore write ordering (A17, A18, A25):** with an active record at generation `r`, let the first subscription restore and the second fail. Assert that no active record at `g = r + 1` was written, the candidate transport stops, and the terminal write at `g` succeeds against the real store's strictly-newer check. Repeat with `r = 2^32 - 2`; terminalization needs no second increment. A negative control that persists active `g` before re-authorization must reject the same terminal write. When all subscriptions pass, the complete active record is persisted exactly once at `g` before activation. Expiry during subscription I/O takes A18 with the original monotonic deadline and no active `g` write;
  - generation persist failure retains that session inactive and restores the others (A19);
  - **standard client, no negotiation (A24-A26, R-5-03, R-5-04):** a client that negotiates no experimental capability subscribes and unsubscribes by URI and gets `{}`. Subscribe, restart, upstream resource update: the client receives `resources/updated`, and a catch-up `resources/updated` arrives right after restore. No `chio/*` method or notification is required or emitted. A later negotiated client on the same host uses the same persisted record with its own id, and the URI is registered upstream once. Separate cases for a restore that cannot keep a subscription:
    - **valid read grant, expired subscribe grant:** restore terminalizes the session with `subscription_not_restored`, and reconnect gets the terminal-state response. In the new session, `resources/read` succeeds and `resources/subscribe` is refused by the ordinary path. The old session is never served with the subscription silently missing;
    - **subject absent at restore, recreated before any read:** the session is terminalized all the same, and the new session's subscribe succeeds;
    - **crash after the terminal record and before reconnect:** the session is never restored, and reconnect still gets the terminal-state response;
    - **journal commits, terminal preparation fails, then restart:** the store stays not ready and the session unserved. Boot finishes the exact journaled terminal before restore, even if the cause cleared. A successful ordinary read is never taken as evidence of a subscription;
    - **fence commits, then finalization fails or the host crashes:** the retained fence blocks restore even if the authorization cause clears. Boot completes the journaled tombstone with the same epoch and timestamp, then reconnect receives its diagnostic terminal-state response. A crash after finalization but before journal cleanup is recognized by exact readback and does not retry preparation;
    - **signing fails after intent journaling:** the session remains unserved and boot finishes the retained intent after the signer recovers, without re-authorizing the old active record;
    - **initial terminal journal write fails, then crash:** the store stops serving in memory. With no durable intent, the next boot re-authorizes every subscription and may restore the session only if they all pass (A31's journal-write limit);
  - **standard authority remains live with Part B disabled (A30):** use separate valid read and expiring subscribe grants. Test a quiet expiry with no updates or client requests, revocation between queue and drain, and auth rotation that removes the bound grant. Repeat delivery checks for live GET, POST/collector, replay, restore catch-up and lag resync; no resource update is handed off after its authorization check fails. Unsubscribing with a queued update drops that update while other authorized subscriptions remain live. Terminalization uses ordinary session closure, never a negotiated id or event. Clock failure and authority lookup failure fail closed; a backward clock adjustment delays the expiry scan by at most `expiry_scan_ms`;
  - **restore authority races (A17, A30):** let the first subscription expire while a later upstream registration blocks, then let expiry or revocation occur during the generation persist. The former terminalizes at `g` over stored `g - 1`; the latter never activates and terminalizes above persisted `g`. Repeat at the last permitted restore generation. Pending updates cannot escape either gate, and auth rotation racing a drain cannot reuse validation from the old auth generation. After a successful restore, ordinary signing advances the same counter beyond `g`; a terminal epoch also exceeds a submitted generation whose acknowledgement was lost;
  - **subscriptions across two restarts (A17, A28, A29):** restore with subscriptions, restart, restart again. After each restart the record verifies under `v3`, `subscriptions` is intact and re-authorized, and `resume_generation` has advanced by one per restart. A negative control that re-signs the bumped record under `v2` fails verification at the next boot, and a `v2`-named record with non-empty `subscriptions` is rejected;
  - **envelope floor (A28):** a `v2` record with no subscriptions stays `v2` under `resume_record_envelope_floor = v2` and becomes `v3` under the default; a `v3` record whose last subscription was removed stays `v3`.
- **`chio-mcp-edge` (A1a):**
  - a `notifications/roots/list_changed` deferred during a nested flow is handled under its own sequence, not the outer request's;
  - the roots refresh queued at restore runs with no cause;
  - a cause change never splits a line (writer unit test with a recording cause cell).
- **Fuzz:** `parse_session_event_id` over generation-seeded `u64` values and hostile session ids.
- **`chio-process` (W:):**
  - enforced `inspect` returns a redacted snapshot without `storage`, and never fails (P6);
  - a non-knowledge `storage()` error still fails `inspect`;
  - a root with a running confined child calls `cancel`: the count excludes the child, and the child is cancelled.
- **chio-conformance:** lag resync on a hosted session; replay across restart; subscription across restart.

---

# Part B. Deferred hint vocabulary

Part B lands only when a second surface consumes hints on the wire. Until then `HintSubject` and `HintKind` are crate-internal, spec 9's `HintPort` is a no-op, and no hint schema is published.

## 11. Shared hint model

### 11.1 Vocabulary

```rust
// chio-kernel::hint (crate-internal until a wire consumer exists)
pub enum HintSubject {
    // MCP catalog and resource subjects (kernel sessions only; edge-triggered, see H4).
    Resource(String),
    ResourceCatalog,
    ToolCatalog,
    PromptCatalog,
    Elicitation(String),           // one-shot
    // Control subjects (every surface that owns the source).
    Operation(RequestId),          // one-shot
    Approval(String),
    Capability(String),            // matched by lineage, rule 12.1(3)
    Budget { capability_id: String, grant_index: u32 },
    Children,
    Recovery { workflow_ref: String },
    Work { handle_ref: String },
    Lifecycle,
    Stop { scope_ref: String },    // durable stop head changed; re-read stop status (never Terminal)
}

pub enum HintKind {
    Changed,                                  // re-read the subject's owning state
    ThresholdCrossed,                         // Budget only; re-read the level
    SubscriptionEnded { reason: EndReason },  // authority withdrawn or subject gone
    Terminal { reason: TerminalReason },      // Lifecycle only; always last
}

pub enum EndReason { Revoked, Expired, AuthorityTimeUnavailable, AuthRotated, SubjectGone }
```

`TerminalReason` is A32's shared session lifecycle enum, including `SubscriptionNotRestored` and `SubscriptionAuthorityLost`; the generated `Terminal.reason` schema uses its exact snake-case values. Part B defines no parallel reason type.

A hint carries no state, tokens or arguments. Revision 4 removes `level_bps` from `ThresholdCrossed` (S5-15): it was state carried in a hint, and coalescing could understate it.

### 11.2 The hint port (spec 9 integration)

```rust
pub trait HintPort: Send + Sync {
    /// Infallible, non-blocking, best-effort. Never awaited by a decision path.
    fn post(&self, hint: Hint);
}
pub struct Hint { pub subject: HintSubject, pub kind: HintKind, pub audience: HintAudience }
pub enum HintAudience { Owner(HintOwnerRef), Tenant(TenantId), Kernel }
pub enum HintOwnerRef { Session(SessionId), Process(ProcessId), Operation(AdmissionOperationId) }
```

- **Effect.** Spec 9 emits `Effect::Hint { hint: Hint }`. The machine fills `audience` from the operation's owner, `HintAudience::Owner(HintOwnerRef::Operation(id))` by default.
- **Trailing group.** Hint effects occupy a trailing effect group that the driver runs only after the commit group's `Committed` acknowledgement (spec 10 `CrossingResult::Committed`, which follows the batch `COMMIT` and any required anchor sync). A hint never runs after a savepoint, `Retry`, `Refused` or `CommitOutcomeUnknown`.
- **Routing.** The port resolves `Operation(id)` to the session that owns the request namespace (hosted session ledger or the edge's ready session) or to the process that issued it (process registry). A hint with no resolvable audience is dropped; that is best-effort, not loss of state (H1).
- **No-op until Part B.** The kernel installs a no-op port. Spec 9's machine and tests do not depend on any port behavior.

### 11.3 Rules

Rules H1-H10 bind every surface:

1. **H1. Not inputs.** No kernel, guard, policy, budget, recovery or approval path may branch on a hint. Decisions read authoritative stores only. Enforcement (S5-24):
   - an xtask dependency check forbids kernel-core, guard, policy, budget and recovery-decision modules from importing the hint module;
   - spec 9's `AdmissionEvent` has no hint-derived variant (asserted by a compile-time test over the enum);
   - a differential conformance test drops or forges every hint and asserts identical verdicts and receipts.
2. **H2. Commit, then hint, per commit class.** A source posts only after its authoritative state commits, through the trailing group (section 11.2).
   - After a crossing-authorizing or restrictive commit (spec 10 section 5), `Committed` implies anchored, so re-reading observes at least the hinted change, across restore.
   - After a progress-only commit (for example a return record), the hint follows `Committed`, but a `Restore(k)` within the anchor lag can undo the hinted change. Consumers re-read and treat an absent change as a resync, never as an error.
   - A source outside the delivering structure's own transaction (admission store, recovery chain, stop heads, revocation head) posts after its own commit returns. That in-process post is only a latency fast path; delivery is guaranteed by the durable source cursor (H10).
3. **H3. One pending per subscription, by precedence.** A pending hint is replaced in place by precedence: `SubscriptionEnded` > `ThresholdCrossed` > `Changed`. The pending entry keeps its first sequence number and a coalesce counter. Delivery re-arms.
4. **H4. Subscribe, then check.** Subscribing inserts an armed entry first. The caller then reads the source level and calls `fire_if_dirty(id, level)`, which posts if the level is already dirty. A post that lands between insertion and the read is captured by the entry; a duplicate hint is acceptable. `SourceLevel` is defined per subject (Operation: terminal recorded; Approval: resolved; Capability: revoked or expired; Budget: threshold crossed; Recovery and Stop: revision or epoch above the caller's last seen; Elicitation: completed). `Resource` and the catalogs have no level: they are edge-triggered and carry no H4 guarantee.
5. **H5. Reserve on subscribe.** Capacity for one pending hint is reserved before a subscription exists. An explicit subscription that cannot reserve is denied with a typed capacity error. Posting never allocates: pending entries live in a pre-sized ring of capacity `max_subscriptions` (S5-27).
   - **H5a. An ended negotiated subscription keeps its slot until its end is acknowledged.** Every path that ends a negotiated subscription moves it to `Terminalized { reason }` with `SubscriptionEnded { reason }` pending in its own slot, and never removes it at that point. The paths are: H7 revalidation at drain or at auth rotation, H7a expiry (including expiry found at restore), a source reporting the subject gone, and clock failure. Standard entries instead terminate the session under A25/A30, even when Part B is enabled.
     - A terminalized subscription keeps its slot, subject, audience and authority metadata, so a later drain can still deliver its hint.
     - It accepts no new posts: a matching post is a no-op, and H3 precedence would keep `SubscriptionEnded` anyway. It is not revalidated again, because its hint already asserts withdrawal and carries no state.
     - Transport handoff or flush marks the item offered on that attachment but returns no subscription capacity. Its slot and durable marker remain until explicit acknowledgement or unsubscribe commits. If the edge's reserved `hint_share` (section 12.1 rule 4) is full, the drain stops and the entry waits; it never allocates an unbounded retry queue.
     - **Durable from terminalization until acknowledged.** The `Ended` marker is persisted when the subscription terminalizes, not at hand-off. The transition to `Terminalized` re-signs the resume record with the entry as Part B's `Ended { reason, end_event_id }` arm of A24's record (A28), before any wait for transport capacity. During unserved restore, newly ended entries and rebased markers are staged in A17's candidate and committed in its single generation persist, with no independent per-marker write. A failed commit containing a new end takes the failed-marker path below (A19). Standard entries use A25/A30 instead.
       - **If that persist fails, the session fails closed through H6a.** It terminates the session with `Terminal` (H6) by H6a's sequence:
         - step 1a first journals the complete terminal payload in the fsynced `pending_terminal` file;
         - it then attempts the terminal session transition, which writes a terminal fence with a higher `resume_generation` that the store enforces (M: `session_store.rs:980-985`).
       - **If the terminal transition also fails,** the store refuses every write and the host reports the session store not ready. The `pending_terminal` entry stays, and boot completes that transition before restoring any session (H6a).
       - **What restore then guarantees.** The stale `Live` record is never restored and never re-authorized. A terminalized subscription cannot be resurrected even if a transient cause has cleared, because the session it belonged to is terminated.
       - **The journal-write limit.** The only residual is a failure of the `pending_terminal` write itself. H6a then stops serving the session store, but that stop lives only in memory, because no writable durable medium remains to record it. A crash before the journal becomes writable leaves neither an `Ended` marker nor a journal entry. Boot then sees the still-valid resume record and restores the session as an ordinary restore: A17 stages negotiated re-authorization under H7/H7a and A25/A30 check standard entries, so an expired, revoked or vanished cause ends it again. A30/H7 recheck every delivery. A transient cause that has cleared can then yield a validly re-authorized subscription. No rule in this spec claims that an unpersisted stop survives a crash.
       - **Delivery is still checked.** H7 rechecks authorization on every delivery, so no update is ever delivered under an authorization that fails at delivery time.
       - **Stable subscription acknowledgement.** The marker is removed only after authenticated `chio/events/ack { subscription_id }` or `chio/events/unsubscribe` commits a signed resume record without it, or the session terminal subsumes it. The ack is scoped to the authenticated session owner, not to the now-revoked resource grant. The client sends it after observing that subscription's `SubscriptionEnded` on any stream. The owner requires the named entry to be `Ended`; an ack for a still-live subscription refuses without mutation. An absent id returns idempotent success without changing any entry. There is at most one logical end per subscription, and subscription ids are never reused within the session, including after removal or restore. Allocate each new negotiated id from the session's generation-seeded unique sequence namespace and persist it before returning it; an aborted allocation is not recycled. Thus `(authenticated session_id, subscription_id)` is sufficient to identify the end, without a new acknowledgement token or a history of transport ids. `seq` and persisted `end_event_id` remain transport/replay data and are not ack inputs. A socket flush, transport handoff or Last-Event-ID alone cannot acknowledge an end: another attached stream may have delivered a higher id without delivering this end.
       - **Serialize removal with rebasing.** The existing session owner serializes every active resume-record mutation from candidate snapshot through signing, persistence and in-memory publication, including subscribe/unsubscribe, end creation, ack removal and live rebase. Merely assigning increasing native resume generations is insufficient to prevent stale contents (V3: `session_core/session.rs:266`; `session_store.rs:1197-1201`). If rebase commits first, an ack still removes the same stable subscription id. If ack commits first, a rebase must omit the removed entry; a candidate copied earlier is discarded/rebuilt, never signed at a newer generation to resurrect it. Capacity is freed only after the signed removal commits. A definite write failure retains the marker and slot for retry; an ambiguous result blocks further record mutation until the existing persistence readback/failure gate establishes which complete record committed. A duplicate ack after a committed removal, including a lost response or restart, is a no-op. This uses the existing record owner and persistence path, with no per-stream acknowledgement ledger.
       - **Restore rebases end ids atomically with the generation.** Each marker keeps a logical end identity, `(subscription_id, reason)`, for deduplication. A17 allocates each re-queued `SubscriptionEnded` a distinct fresh transport event id in generation `g`, stages that id in both its marker and event, and re-signs the complete candidate record once. No rebased event is served before that same record commits. The stable subscription id and immutable end reason survive that rebase. An ack formed after observing an earlier-generation end remains valid after activation; it does not have to observe the new transport id. The client deduplicates by logical identity and may repeat the same subscription-scoped ack for duplicate delivery. Rebasing never creates a second, different end.
       - Every new GET attachment also requeues unacknowledged ends before catch-up, even when Last-Event-ID is higher than an old end. Rebase those markers to distinct fresh sequence ids in the current incarnation through the same session owner, persist their exact new ids together before emission, then enqueue those ids. This prevents A6's delivered-through filter from discarding a still-unacknowledged end. The attachment is not served if this rebase cannot commit; old markers remain durable, and ambiguous persistence follows the existing store readback/failure gate. An existing stream may see the same logical end again, but acknowledgement of an already observed end never depends on redelivery or on the new stream remaining connected. The stable subscription-scoped ack stays valid if that new stream disconnects before emission. Removal and rebase obey the serialization rule above. Restore performs this rebase only once through A17, not again during first activation.
       - Restore re-queues `SubscriptionEnded` from every marker before the catch-up. Once the marker is persisted, a crash at any later point cannot resurrect the subscription as `Live` or lose the end notification, even if the clock recovers or the subject is recreated before restore. If the marker persist failed, the pending-terminal gate above applies instead: boot completes the journaled terminal transition before restoring any session (H6a), so the stale `Live` record is never restored. The one case with no durable end is the failed `pending_terminal` write, whose limit is stated above.
       - Markers count against the persisted subscription bound and expire with the session's terminal.
     - Capacity: H5 and the explicit and implicit pools count terminalized entries until removal, and `bounded(s)` counts them as subscriptions. A subscribe can therefore be denied while ended subscriptions await acknowledgement. This is bounded backpressure: an unresponsive client retains capacity until it acknowledges, unsubscribes, or the session expires; the server never evicts an unacknowledged end to make room.
     - A client unsubscribe of a terminalized subscription removes it once its signed removal commits. `Terminal` (H6) discards every pending hint, `SubscriptionEnded` included, and removes every subscription, because the terminal subsumes them.
     - Persistence: a persisted negotiated subscription (A24's Part B arms) leaves the persisted set only after acknowledged removal, explicit unsubscribe, or session terminal. While unacknowledged, reconnect and restore requeue its end before catch-up, including after a reported flush. At-least-once delivery assumes a reconnecting/reading client before session expiry; no transport flush is proof of client observation.
6. **H6. Terminal is last.** A surface with a lifecycle delivers exactly one `Terminal` hint, after discarding pending hints, from a slot reserved at creation. After it, posting is a no-op and subscribing fails.
   - **H6a. Flush, then cancel.** Writing `Terminal` into the log does not by itself make any stream emit it. A stream selecting between its event source and the cancellation token could see the cancellation first, or close before draining the slot. Session termination therefore runs in this order:
     1. **Log.** `terminate` discards pending hints, writes `Terminal { reason }` into the reserved terminal slot with a fixed sequence number, and refuses further posts and subscriptions.
     1a. **Journal, then persist.** Use Part A's shared A31 helper and `pending_terminal` file in the session store's lock root, outside the database. Before signing or any SQLite write, journal the complete native terminal payloads plus Part B's `{ session_id, terminal_generation, event_id, reason, retention_deadline }` and retained replay metadata. A31 retains the exact signed records in the same journal before SQLite writes. There is no second journal or terminal owner. The entry is removed only after finalization commits, and boot completes every listed transition before restoring any session. A crash after journal commit therefore leaves the exact terminal intent. Then, before any flush wait, the session's terminal store transition (the existing terminal fence, M: `session_store.rs:980-985`) durably records `terminal_event { event_id, reason, retention_deadline, replay_consumed: false }` in the terminal tombstone.
        - After a crash during the flush wait, the tombstone, not the lost in-memory log, serves the retained replay: the first reconnect presenting a `Last-Event-ID` below `event_id`, before `retention_deadline`, receives the `Terminal` once, and `replay_consumed` is set durably.
        - **If this persist fails, the old resume record is still fenced.** The terminal transition is the durable fence against restoring the session, so its failure is handled like H5a's double failure, not skipped.
          - The session still terminates in memory.
          - The session store is reported not ready, and the terminal transition is retried with backoff. No new session is served from this store until it commits.
          - The `pending_terminal` entry written at the start of step 1a stays in place, so boot completes the transition before restoring any session.
          - If the `pending_terminal` write itself fails at the start of step 1a, termination does not attempt the SQLite transition unjournaled. The host stops serving the session store entirely, fail-closed, until the journal is writable. That stop is in memory only. A crash before the journal becomes writable leaves no durable trace of the termination, so boot restores the session from its resume record as an ordinary restore (H5a's journal-write limit).
          - Once the `pending_terminal` entry or the terminal fence is durable, a terminated session can never be restored from its still-valid resume record. Crash-survivable replay of the `Terminal` itself is claimed only once the transition commits.
     2. **Stream slots.** The transport copies the terminal hint into each attached stream's reserved terminal frame. Every stream reserves one at attach, so this step never blocks or allocates. A POST stream still waiting for its response first emits A13's outcome-unknown error for its request id.
     3. **Flush.** Each stream emits the frames already handed to it, then the terminal frame as its last frame, then acknowledges once the frame is written and flushed to the HTTP body. Streams poll their terminal frame before the cancellation token (a biased select), so a stream that observes both emits the terminal first.
     4. **Await.** The session waits for every attached stream's acknowledgement, bounded by `terminal_flush_deadline_ms` (default 2000).
     5. **Cancel.** Only then does it cancel the session token (A12). A stream that has not acknowledged by the deadline is closed by the cancellation.
   - **Exactly once.** The log produces one `Terminal` per session. Every attached stream carries the same hint with the same event id, so a client that sees it on two streams sees one logical event.
   - **Slow streams.** A stream closed at the deadline without flushing leaves the terminal retrievable for one replay. The session keeps the terminal hint for `terminal_retention_ms` (default 60000) after termination. The first reconnect presenting a `Last-Event-ID` below it receives it once. After that, and after the retention window, requests get the WIRE_PROTOCOL 3.3 terminal-state response.
7. **H7. Authority follows the source.** Part B extends A30's checker and emission gate to negotiated subjects; it does not replace the standard-subscription checks. A consumer may subscribe to, or wait on, a negotiated subject only with the authority it needs to read that subject's state. Authority is revalidated at **drain time** (revocation store, plus expiry against the authority clock) before each hint is delivered; a failed negotiated revalidation terminalizes that subscription and delivers one `SubscriptionEnded` instead, in this drain if the share allows and otherwise in the next one, after which its end marker and slot remain until committed acknowledgement, unsubscribe or session termination (H5a). Auth rotation revalidates every subscription against the new auth context. A failed standard entry terminates the whole session under A30; negotiated entries follow H5a.
   - **H7a. Expiry extends Part A's schedule.** A quiet expiry needs no triggering source-store commit and may have no pending hint to drain; terminalizing it still persists H5a's end marker. Every negotiated subscription whose authorizing capability has an expiry arms an entry in the same `ExpirySchedule` that A30 owns, at subscribe, restore and auth rotation. Part B reserves capacity through H5 and extends the subject key; it creates no second schedule. Standard entries always retain A30's whole-session failure disposition. For negotiated entries:
     - **Firing.** The schedule wakes on the monotonic clock at the earliest deadline and confirms it against the authority clock. When the authority clock reaches `expires_at`, it terminalizes the subscription with `SubscriptionEnded { reason: Expired }` pending (H3 precedence, H5a). The next drain offers it; the subscription remains until committed acknowledgement, unsubscribe or session termination (H5a). No source commit is needed. A scan every `expiry_scan_ms` (default 1000) re-checks the heap head against the authority clock, so a clock adjustment cannot postpone an expiry by more than one scan.
     - **Restore.** Restore re-arms the schedule from the persisted subscriptions (A24, generalized to subjects in Part B) and each authorizing capability's `expires_at`. An expiry that passed while the host was down terminalizes the subscription during restore, before the catch-up of H10's restore step 2, and the first drain after restore delivers it (H5a). The consumer therefore receives `SubscriptionEnded`, never a catch-up `Changed`, for an expired subscription.
     - **Clock failure.** If the authority clock is unavailable when the schedule fires or scans, every subscription whose capability has an `expires_at` is terminalized fail closed with `SubscriptionEnded { reason: AuthorityTimeUnavailable }` (H5a). Subscriptions whose capability has no expiry are unaffected. An expiry is never assumed not to have happened.
8. **H8. Gaps resync.** Any transport loss surfaces as an explicit resync: a resync burst (A8), `409`, or a revision jump. It never surfaces as silent loss.
9. **H9. Audience.** A hint is an existence and status channel, so it obeys the audience policy of its subject.
   - It may name an artifact only by an audience-scoped opaque handle, never by digest (W: `docs/architecture/recoverable-agent-runtime/06-artifacts-memory.md:9`, `:80`, ART-10).
   - A hint about a confined child is withheld from the parent unless the child's isolation boundary enables a contract-approved status projection (W: `07-confined-returns.md:39`). The P5 profile enables none.
   - A knowledge-protected change never produces a hint and never advances a revision (S5-20).
10. **H10. Durable source cursors.** Every source that commits outside the delivering structure's own transaction is read through a durable monotonic cursor in its own store, so no crash between a commit and a post loses a hint. The design needs no cross-store outbox. Every source except the approval store already has a monotonic sequence, and the approval store gains one inside its own transactions (H10a):

    | Subjects | Durable cursor |
    |---|---|
    | `Operation` | The admission store's global commit sequence, `authority_global_commits.commit_sequence` (M: `chio-store-sqlite/src/serving_owner/global_commit_chain.rs:43-50`, projection kind `admission`) |
    | `Approval` | The approval store's own `chio_hitl_events.sequence` (H10a). Approvals do not commit through the admission chain, so its sequence never covers them |
    | `Capability` (revocation) | The same chain, projection kind `revocation` |
    | `Capability` (expiry) | None: expiry commits nothing. The H7a `ExpirySchedule`, re-armed at restore from the persisted subscriptions, is the source |
    | `Budget` (kernel session) | The same chain, projection kind `budget`: every budget mutation committed under a joint serving owner appends its chain record, keyed by the mutation's `event_id`, in the mutation's own transaction (M: `chio-store-sqlite/src/budget_store/store.rs:314-328`). The tail loads that mutation, matches it to `Budget { capability_id, grant_index }`, re-reads the grant's usage and posts `ThresholdCrossed` when a subscribed threshold is crossed (H4's level). A `BudgetStore` opened without a joint serving owner appends no chain record (`:40-46`), so it does not serve mutation events and a `Budget` subscription on it is `Unsupported` (section 12.1 rule 3). Mutations imported from a replication peer append no local chain record; they are cross-owner changes (section 14) |
    | `Recovery` | `admission_operation_recovery_events.sequence` (W: `admission_operation_recovery.sql:30`) |
    | `Stop` | The store-global `authority_global_commits.commit_sequence` of stop records, which cover every scope, through the shared `StopHeads` (spec 8 S1, S24). Epochs are monotonic only within one scope, so a per-source epoch cursor could skip tenant B's first stop after observing tenant A at a higher epoch. The cursor is the global commit sequence, and each tailed record is matched to sessions by its scope |

    The rules:
    - **Tail.** The delivering process holds one in-memory cursor per source and store. It advances the cursor by tailing records above it, every `hint_source_poll_ms` (default 250) and immediately on the in-process notify. Each tailed record maps to its audience and posts. If the source process crashes after its commit and before its notify, the tail still delivers the hint.
    - **Restore.** If the delivering process crashes, it loses its cursors, and restore re-arms them in this order:
      1. read each source head;
      2. post one catch-up `Changed` on every restored subscription;
      3. tail from the heads read in step 1.

      A change committed before step 1 is covered by the consumer's re-read after the catch-up. A change committed after step 1 is tailed. A change between steps 1 and 2 may arrive twice, which H3 coalesces and H1 makes harmless.
    - **Subscriptions persist.** When Part B lands, its `Negotiated` and `Ended` arms join A24's record, keyed by `subscription_id` and `subject`, under the same persist-before-acknowledge rule. Standard entries stay URI-keyed. Control subscriptions therefore survive restore and receive the catch-up, as resource subscriptions do (A26).
    - **Processes.** No cursor is needed: both process sources advance `hint_revision` in the same journal transaction as the change (P1).

    **H10a. The approval store's cursor.** On M:, approvals live in a separate SQLite store. `SqliteApprovalStore` opens its own file, or the receipt store's file when co-located for `chio api protect` (M: `chio-store-sqlite/src/approval_store.rs:85-103`). Its `resolve` commits in its own `IMMEDIATE` transaction and writes nothing to `authority_global_commits` (`:558-620`). So an approval resolved by a component that crashes before its in-process post was invisible to every cursor in the H10 table, and no tail could find it. The approval store also has no usable cursor today: `chio_hitl_resolved` is keyed by `approval_id TEXT PRIMARY KEY` (`:265-273`). Its implicit `rowid` may be reused and gives no order across the pending, resolved and reservation tables.
    - **Event table.** The approval store gains an append-only table in the same file:
      `chio_hitl_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT, approval_id TEXT NOT NULL, kind TEXT NOT NULL, subject_id TEXT NOT NULL, operation_id TEXT, audience_owner TEXT NOT NULL, committed_at INTEGER NOT NULL)`. `audience_owner` is the canonical `HintOwnerRef` (session id or operation id) of the request that created the approval, written when the pending request is stored. It is never derived later from `subject_id`. The table has a `BEFORE UPDATE` trigger that `RAISE(ABORT)`s, following the store's existing tombstone triggers (`:331-363`), and a `BEFORE DELETE` trigger that `RAISE(ABORT)`s unless the row's `sequence` is at or below the retention floor (Retention, below). `AUTOINCREMENT` guarantees a strictly increasing sequence that is never reused, even after the highest row is gone. The kinds are `pending`, `resolved`, `reservation_committed`, `reservation_cancelled` and `threshold_finalized`.
    - **Same transaction.** Every approval-store write that changes approval state appends its event row inside the transaction that makes the change: `store_pending`, `resolve`, the operation-reservation transitions (`reserved` to `committed` or `cancelled`), and threshold-collector finalization. A committed approval change therefore always has its event, and a rolled-back one never does. No transaction ever spans the approval store and the admission store.
    - **Retention.** The table is a bounded hint log, not an audit record. A single-row `chio_hitl_event_floor(floor_sequence)` holds the highest pruned sequence, and its triggers reject a decrease and any delete. Each appending transaction raises the floor to `max(floor_sequence, new_sequence - approval_event_retain)` and deletes the rows at or below it in the same transaction, so the table never holds more than `approval_event_retain` rows (default 65536). Configuration rejects an `approval_event_retain` below `approval_replay_max` at load time. The newest row is never pruned, so the head stays `MAX(sequence)`, and `AUTOINCREMENT` never reissues a pruned sequence. Pruning never loses a hint silently, because every reader treats a cursor below the floor as a gap (H8):
      - a tailer whose in-memory cursor is below `floor_sequence` first captures the current head, then posts a catch-up `Changed` on every live `Approval` subscription it serves, then tails from that captured head, so a resolution committed after the capture is still read and posted even if its source crashes before notifying (the same ordering H10 uses on restore);
      - a restore whose `approval_watermark` is below the floor skips the specific replay and keeps step 2's catch-up, as for a gap longer than `approval_replay_max`.
    - **Read API.** `ApprovalStore` gains `approval_event_head() -> u64`, `approval_event_floor() -> u64` and `approval_events_after(sequence, limit) -> Vec<ApprovalEvent>`, read-only and outside any write transaction. The audience of an event is its persisted `audience_owner`, never a lookup by `subject_id`. Two sessions of the same agent subject therefore never receive each other's approval hints, and a tailer recovering after a crash routes each event without ambiguity. An event whose `audience_owner` names no live or restorable session is dropped, because its owner has gone and hints carry no state. `ApprovalRequest` and `chio_hitl_pending` gain the same `audience_owner` field, set from the creating session's authenticated context.
    - **In-memory store.** `InMemoryApprovalStore` (M: `kernel/approval.rs:1134`) keeps an in-memory counter with the same API. It is not durable, so it makes no crash claim, consistent with its use in tests and development.
    - **Watermark across restart.** The approval cursor is tailed like the others. In addition, each session records the highest approval `sequence` it has delivered as `approval_watermark` in its resume record, covered by the integrity envelope (A24, A28) and updated whenever the record is re-signed. At restore, after step 1 reads the heads, the session replays every approval event with `approval_watermark < sequence <= head` whose audience is that session, up to `approval_replay_max` events (default 1024). Each replayed event posts its own `Changed` on `Approval(id)`, so an approval committed just before a crash reaches its subscriber as a specific hint, not only as the generic catch-up. A gap longer than `approval_replay_max` falls back to the step 2 catch-up. Replay is at-least-once. A watermark that is stale because the record was re-signed before the last delivery only produces duplicates, which H3 coalesces and H1 makes harmless.
    - **Restore order.** In step 1, the approval store's `approval_event_head()` is read with the other heads. Tailing then resumes from that head (step 3).

```text
bounded(s)          -> |pending(s)| <= |subscriptions(s)| + 1
no_silent_loss(sub) -> committed(c, source(sub)) and c after last_delivery(sub)
                       -> eventually delivered(hint(sub)) or delivered(SubscriptionEnded(sub))
                          or delivered(Terminal) or delivered(resync(sub))
not_authority(h)    -> forall decisions d: h not in inputs(d)
ended(sub)          -> removed(sub) only after ack_committed(session(sub), subscription_id(sub))
                       or unsubscribe_committed(sub) or session_terminal(sub) (H5a)
terminated(s)       -> forall attached streams t: emitted(Terminal, t) before cancelled(t)
                       or (deadline(t) and retained_for_replay(Terminal, s))   (H6a)
```

`no_silent_loss` holds across a crash of either the source or the delivering process. Process revisions commit with their change (P1), and every other source is read through a durable cursor with catch-up on restore (H10). Only sources outside these stores remain uncovered, namely cross-owner hints (section 14).

## 12. Projection per surface

| Subject | Kernel session (MCP) | Agent process | Recovery workflow | Work |
|---|---|---|---|---|
| Resource and catalogs, `Elicitation` | `SessionEventLog` -> `notifications/*` | n/a | n/a | n/a |
| `Operation` | session-owned request terminal (one-shot) | `invoke` replay with the same key (unchanged; no hint) | continuation state | execution observation |
| `Approval` | projected from the approval store | `invoke` replay returns the new verdict (no hint) | approval recorded for the workflow's operation | recovery observation |
| `Capability` | held capability revoked or expired, by lineage | n/a: credential revocation surfaces as `unauthenticated` (P3) | n/a | n/a |
| `Budget` | threshold on a held grant | tree-level threshold (`inspect` revision) | n/a | n/a |
| `Children` | n/a | `wait_children`/`settle_children` (unchanged) | n/a | child acceptance observation |
| `Recovery` | projected from the recovery event chain | n/a (S5-08) | new `(record_key, record_version)`; re-read with `read_recovery_workflow` | `WorkRecoveryLinkV1` observation |
| `Work` | n/a | n/a | n/a | re-query `WorkQueryV1::Work` |
| `Lifecycle` | `Terminal` on session close | `ProcessState::Cancelled` (`inspect` revision; confined children withheld per H9) | `WorkflowControlV1::Cancelled` or `Quarantined` | per-authority terminal |
| `Stop` | `Changed` to sessions in the affected scope, from the shared `StopHeads` notification (section 12.5) | n/a: a stop surfaces as `kernel_stopped` on `invoke` | denials of resume and capture commands are the signal | n/a |

### 12.1 Kernel sessions: `SessionEventLog`

`late_events` and `SubscriptionRegistry` are replaced by one `SessionEventLog`, a pure data structure that loom and proptest can drive.

```rust
pub struct SessionEventLog {
    next_seq: u64,
    explicit: SubscriptionPool,                // max_subscriptions, default 256 (client subscriptions); entries Live or Terminalized (H5a)
    implicit: SubscriptionPool,                // sized from the in-flight request bound (one-shot subjects)
    pending: PendingRing,                      // pre-sized; one slot per subscription (H5)
    terminal: TerminalSlot,                    // reserved at construction
    expiry: ExpirySchedule,                    // the Part A schedule, extended to negotiated subjects (A30, H7a)
}
impl SessionEventLog {
    pub fn subscribe(&mut self, subject: HintSubject, authority: SubscriptionAuthority)
        -> Result<SubscriptionId, EventLogError>;
    pub fn fire_if_dirty(&mut self, id: SubscriptionId, level: SourceLevel);       // H4
    pub fn post(&mut self, subject: &HintSubject, kind: HintKind);                 // infallible (H5)
    pub fn drain(&mut self, max: usize, revalidate: &dyn Fn(&SubscriptionAuthority) -> bool)
        -> Vec<SessionHint>;                                                        // H7 at drain
    pub fn revalidate_all(&mut self, revalidate: &dyn Fn(&SubscriptionAuthority) -> bool); // auth rotation
    pub fn expire_due(&mut self, authority_now: Result<UnixMillis, AuthorityTimeError>); // H7a; Err ends expiring subscriptions
    pub fn terminate(&mut self, reason: TerminalReason) -> TerminalHint;           // H6; the transport flushes it before cancelling (H6a)
}
```

Session rules:

1. `close` and `close_persisted` call `terminate` instead of clearing (replacing `session.rs:1338`).
2. Auth rotation through `set_auth_context` calls `revalidate_all` against the new context (H7). Revision 3's "capabilities that leave the session" is withdrawn: `issued_capabilities` never changes.
3. Authorization reuses the `subscribe_session_resource` order (`session_ops.rs:320-338`).
   - `Operation` and `Approval`: session-owned.
   - `Capability`: the id must be in the session's issued capabilities or an ancestor of one. The subscription stores the held capability's lineage, and a post on `Capability(x)` matches every subscription whose lineage contains `x` (S5-14). A revocation of a root therefore reaches a session holding a descendant.
   - `Budget`: requires a held capability and a `BudgetStore` that serves mutation events, meaning one whose mutations append `budget` records to the global commit chain under a joint serving owner (H10). Otherwise `Unsupported`.
4. **Edge buffer.** Hints drain into a reserved share of the edge's `pending_notifications` (`hint_share`, default 64). Other producers (progress, log, tool chunks, server requests from nested flow) keep their current behavior; bounding them is outside this design (S5-25).
5. **One-shot subjects.** `Elicitation` and `Operation` subscriptions live in the implicit pool and are removed after their hint is delivered (S5-16). If the implicit pool is exhausted, the request proceeds without the implicit hint and the consumer relies on the response itself. A tool call is never denied for hint capacity.
6. **Single session.** The single-session-per-runtime assumption of `queue_session_tool_server_events` (`validation.rs:205-216`) is an invariant, checked when an edge attaches a second ready session, which fails closed. Hosted builds one kernel per session, so it holds there.
7. **Negotiation.** Control subjects are emitted only to peers that negotiated `capabilities.experimental.chioEvents = { "version": 1 }`, as `notifications/chio/event` with `{seq, subject, kind, subscription_id?}`. `subscription_id` is the id `chio/events/subscribe` returned, persisted in A24's Part B arms. It is required on every subscription-scoped kind (`Changed`, `ThresholdCrossed`, `SubscriptionEnded`), so a client with two subscriptions to one subject knows which one ended and deduplicates a rebased end by `(subscription_id, reason)`. It is absent only on the session `Terminal { reason }` from the dedicated terminal slot (H6), which belongs to no subscription and is identified by its single event id per session (H6a). The control methods are specified in section 16.

### 12.2 Agent processes: `inspect` hint revision

Processes already learn their cancellation from plain `inspect` (`state`) or from `invoke` returning `cancelled`. What they lack is a low-latency wait. The long-poll buys latency, not capability (S5-28).

| Option | Cost per wait | Call budget | Receipt | Op set |
|---|---|---|---|---|
| A. Reserved system mailbox channel | One mediated call (about 40 durable writes and 11 authority commits, M: `docs/architecture/AGENT_PROCESS_DIRECTION.md:162-166`) | Consumed | Yes | Unchanged |
| B. Seventh worker op `wait` | Journal read | Not consumed | No | Grows to seven |
| C. `inspect` gains optional `after_revision` and `wait_ms` | Journal read; under enforcement, read-only only after the enable-once fix (P2) | Not consumed | No | Unchanged |

**Decision: option C.** Option A makes each empty poll a full mediated admission and needs a fresh key after every empty poll (`MAILBOXES.md:97-99`). Option B grows the vocabulary the direction document keeps small (`AGENT_PROCESS_DIRECTION.md:64-66`).

Shape:

```json
{"op":"inspect","after_revision":"41.7","wait_ms":30000}
```

Response additions: `hint_revision` (an opaque string the client echoes), `hints`, and `waited` (boolean), plus `retry_after_ms` when the host declined to wait.

Rules:

1. **P1. Revision source (restricted, S5-08).** The process projection carries only subjects `inspect` can show:
   - `Lifecycle`: an own revision that advances in the same journal transaction as the process's `ProcessState` change;
   - `Budget`: a tree-level revision that advances in the same `invoke` transaction that moves `tree_calls` across a configured threshold. One row per tree, so no fan-out to every process (S5-22).

   `hint_revision` is `"{own}.{tree}"`. Each kind stores its `last_revision` (bounded by the vocabulary size), and `hints` lists every kind whose `last_revision` exceeds the matching component of `after_revision`. Both sources commit in the process journal, so no crash gap exists between a change and its revision. `Stop`, `Recovery`, `Capability` and `Approval` are not projected to processes; their signals are `kernel_stopped` on `invoke`, host-side recovery, `unauthenticated` (P3) and `invoke` replay.
2. **P2. Level-triggered, register-before-read (S5-09).**
   - Each process has an in-memory `watch` channel signalled after the journal commit that advanced a revision. A waiting `inspect` registers its receiver, then reads the revision, then waits.
   - If either component exceeds `after_revision`, `inspect` returns at once. Otherwise it waits up to `min(wait_ms, credential expiry)` (at most 30000) and returns the current snapshot. Omitting both fields gives exactly today's `inspect`.
   - At host startup, revisions are read from the journal, so no reconciliation from other stores is needed.
   - Under enforcement, the runtime enables knowledge once, when it first observes enforcement, and caches that; later reads are read-only (fixing the per-read IMMEDIATE commit in `lib.rs:240-251`).
3. **P3. Bounds (S5-13).**
   - After the frame is parsed, a waiting `inspect` moves out of the 32 active-connection count into a separate `max_waiting_connections` (default 32). Waits are limited to one per credential.
   - A wait over either bound returns at once with `waited: false` and `retry_after_ms`, so clients back off instead of spinning on the store mutex.
   - Graceful shutdown wakes every waiter. The host polls peer readability while waiting and abandons a wait whose peer disconnected.
   - Authentication is re-checked before returning (`WORKER_PROTOCOL.md:124-128`). A credential revoked during the wait gets `unauthenticated`, which is itself the cancellation signal.
4. **P4. No authority.** The response reveals only state that `inspect` already reveals for the caller's own process. It never names other processes, policy, or remaining sibling budget (H1, H7).
5. **P5. Compatibility.** Older hosts reject the new fields. A read is safe to retry, so a client MAY fall back to plain `inspect` on an older host (the `known_outcome_only` no-strip rule exists for effects, `WORKER_PROTOCOL.md:118-121`). The fields ship under the union `PROCESS_ABI` v4 (open decision 1).
6. **P6.** Part A section 7.1. Under Part B, knowledge-protected changes never advance `hint_revision` (H9).

Data still flows through mailboxes. Child joins still go through `wait_children`. `inspect` only says what to re-read.

### 12.3 Recovery workflows: project from the event chain

The recovery lane's durable truth is the hash-chained `admission_operation_recovery_events`, whose `sequence` column is a global monotonic cursor (W: `admission_operation_recovery.sql:30`). This design adds no durable log.

1. **Source.** A new `(record_key, record_version)` for a `workflow` record posts `Recovery { workflow_ref }` to its audience. An approval recorded in the approval store for the workflow's operation posts `Approval` from the approval store's own event cursor (`chio_hitl_events.sequence`, H10a), not from `EffectObservationV1`, whose `effect` field changes only inside the `ResumeWorkflow` handler (W: `chio-control-plane/src/recovery/runtime.rs:159-168`; S5-23).
2. **Audience mapping.** A workflow's scope names its original operation. The audience is the session that owns that operation's request namespace (`HintOwnerRef::Operation` resolved per section 11.2). Processes receive no recovery hints (P1).
3. **Re-read.** The consumer re-reads with `read_recovery_workflow` under its own actor revalidation (W: `recovery_runtime.rs:325-334`). It never issues a recovery command for a hint re-read, because commands consume permanent quota and a repeated `command_id` returns a stale cached response (S5-07). Re-reads are rate-limited per consumer (`min_reread_interval_ms`, default 250); coalescing (H3) already bounds pending hints to one.
4. **Control states.** `WorkflowControlV1::CancelRequested`, `Cancelled` and `Quarantined` post `Changed` on `Recovery`. A terminal disposition posts no session `Terminal`.
5. **Crash.** Recovery hints are delivered by tailing the chain's `sequence` (H10). Approval hints are delivered by tailing `chio_hitl_events.sequence` (H10a). A recovery or approval component that crashes after committing and before notifying is covered by the tail. A delivering host that crashes is covered by the restore catch-up, after which tailing resumes from the head read before the catch-up. A consumer that reconnects still compares the workflow `revision` it last saw with a fresh read (H8).
6. **Outbox.** If recovery adds the documented outbox, hints project from it instead, with its per-delivery audience recheck. An unavailable hint sink never triggers execution or refund (R: `08:94`).

### 12.4 Work: hint to re-query

A `Work { handle_ref }` hint means "re-query `WorkQueryV1::Work`". It is posted by an owning authority on the same host when one of its observations changes revision. The query performs the current audience check (V: `work-runtime-design.md:87`, `:101`). A hint never carries an observation value (assumed shipped, contract anchor).

### 12.5 Stop and revocation sources

- **Stop.** Spec 8 makes `StopHeads` shared per store across every kernel attached to it in a process (spec 8). Its change notification (`watch`) is the only source of `Stop` hints. Each session's log subscribes to it, so a stop committed by any component reaches every session in scope, without a cross-session router. Remote durable admission inherits spec 8's polling staleness bound.
- **Revocation.** Revocations committed in the same store notify through the store handle.
  - **Other processes.** Sessions in other processes poll the revocation head (H10's admission-chain cursor). When the head advances, the poller reads the new revocation entries and posts `Changed` on `Capability(id)` for every subscription whose authorizing capability, or any capability in its lineage, appears in them. Posts match by lineage (section 12.1 rule 3).
  - **What the post does.** It makes the subscription dirty, so a drain runs, and H7's drain-time revalidation then ends the subscription with `SubscriptionEnded { Revoked }`. A quiet subscription therefore learns of a cross-process revocation within one polling interval, and no event of its own is needed.
  - **Missed polls.** A poll missed across a crash is replayed from the cursor at restore (H10).

## 13. Transport and edge (Part B)

1. **MCP edge.** Standard subjects keep their `notifications/*` methods and peer gates (`runtime_flow.rs:397`). Coalescing preserves MCP semantics, because those notifications are re-read hints. Control subjects require `chioEvents` (section 12.1 rule 7).
2. **Terminal ends the stream, in order.** The session writes `Terminal`, copies it into each attached stream's reserved terminal frame, waits until every stream has emitted and flushed it or `terminal_flush_deadline_ms` passes, and only then cancels the session token (A12). A stream closed at the deadline leaves the terminal retrievable for one replay (H6a). Later requests follow the WIRE_PROTOCOL 3.3 terminal-state rules. When Part B lands, Part A's A12 cancellation on session termination runs after this flush.
3. **A2A.** No change. Any later A2A status push sources from the hint model and inherits H1-H10.

## 14. Cross-owner hints: known gap

In multi-owner work, cross-owner state is poll-only through the W2 work query (assumed shipped, contract anchor). Child accepted, verifier decision recorded, graph head advanced and bilateral co-sign pending have no channel. The P2P push lanes today are revocation epoch roots on iroh lane b (V: `crates/trust/chio-federation-transport-iroh/src/lanes/revocation.rs:1-40`) and an experimental pheromone-only fan-out on lane c (V: `src/lanes/fanout.rs:1-10`).

Direction (not v1): a hint-only direct lane per treaty party reusing the lane admission gate and verified directory (payloads `{subject, kind, owner_revision}`, never authoritative; V: `docs/papers/verifiable-work/PROTOCOL.md:22-25`), or a W2 subscription endpoint with R:'s outbox semantics. Either must hold H1-H10 and must not depend on lane c.

## 15. Failure modes (Part B)

| Failure | Behavior |
|---|---|
| Explicit subscription capacity exhausted | Subscribe denied with a typed capacity error |
| Implicit pool exhausted | Request proceeds without the implicit hint (rule 12.1(5)) |
| Authority withdrawn | Detected at drain or rotation; the subscription is terminalized, one logical `SubscriptionEnded` is delivered at least once; committed acknowledgement or unsubscribe removes its retained marker and slot (H7, H5a) |
| Capability expires with no other activity | `ExpirySchedule` terminalizes the subscription with `SubscriptionEnded { Expired }` pending at the deadline; the next drain offers it; explicit ack/unsubscribe commits removal (H7a, H5a) |
| Ended subscription not yet drained | Keeps its slot and metadata, accepts no posts, counts against capacity, and is removed only after committed acknowledgement, unsubscribe or session termination (H5a) |
| Session terminates while streams are attached | Each stream emits the terminal frame and acknowledges before the token is cancelled (H6a) |
| A stream cannot flush the terminal within `terminal_flush_deadline_ms` | Closed by the cancellation; the terminal is retained for one replay within `terminal_retention_ms` (H6a) |
| Capability expired while the host was down | Fires during restore, before the catch-up (H7a) |
| Authority clock unavailable at an expiry check | Subscriptions with an `expires_at` end with `AuthorityTimeUnavailable`; others are unaffected (H7a) |
| Backend cannot serve the subject | `Unsupported`; a subscription that cannot fire is never created |
| Hint posted after a progress-only commit, then restore | Re-read shows no change; treated as resync (H2) |
| Commit outcome unknown or refused | No hint (trailing group) |
| Process wait over the bound | `waited: false`, `retry_after_ms`; never refused, never a hang |
| Credential revoked during a process wait | `unauthenticated` at the return check |
| Host shutdown during a wait | Waiter woken with the current snapshot |
| Hint about a confined child or a protected change | Withheld (H9) |
| Second ready session on an edge runtime | Refused |
| Source crashes after its commit, before its notify | The delivering process's tail of the source's durable cursor posts the hint (H10) |
| Delivering host crashes | Restore reads source heads, posts one catch-up `Changed` per restored subscription, then tails from those heads (H10) |
| Transport loss | Explicit resync: burst, `409` or revision jump (H8) |
| Forged or tampered hint | Harmless to safety (H1); it can only prompt a re-read |

## 16. Protocol, schema and wire impact (Part B)

- **`spec/PROTOCOL.md`:** section 4.3 adds the negotiated `chioEvents` extension, section 8.2 lists it under MCP compatibility; the hint vocabulary is documented as operational, never signed.
- **Control methods** under `chioEvents`:
  - `chio/events/subscribe { subject }` -> `{ subscription_id }`; errors: capacity, unsupported, unauthorized;
  - `chio/events/unsubscribe { subscription_id }` -> `{}`;
  - `chio/events/ack { subscription_id }` -> `{}` after committed removal of that session's ended entry, or idempotently for an absent id; a live entry refuses without mutation (H5a). The client sends this only after observing that subscription's end on any stream. Transport sequence ids are not part of this proposed method;
  - `chio/events/list {}` -> `{ subscriptions: [{ subscription_id, subject }] }`;
  - `notifications/chio/event { seq, subject, kind, subscription_id? }`: `subscription_id` is required for subscription-scoped kinds and absent for the session `Terminal`.
- **`spec/versions/chio-protocol-negotiation.v1.json`** adds `chioEvents` (optional, version 1).
- **New schemas** under `spec/schemas/`, generated by `chio-spec-codegen`, published only when Part B lands: `chio.hint-subject.v1`, `notifications/chio/event` params, the four control methods, including stable subscription-scoped end acknowledgement. The ack schema contains only `subscription_id`, with unknown fields rejected; Part B is still proposed and has no published ack schema to preserve. The notification's closed `Terminal.reason` enum is generated from A32, including `subscription_not_restored` and `subscription_authority_lost`, with negative vectors for unknown values. Replay uses the identical reason retained by A31/A32.
- **Worker protocol:** `inspect` gains `after_revision`, `wait_ms`, `hint_revision`, `hints`, `waited` and `retry_after_ms`, under the union `PROCESS_ABI` v4.
- **No change** to capability, receipt or manifest schemas. Part B reuses Part A's versioned terminal reasons and signed persistence envelopes (A32); the notification itself remains unsigned.

## 17. Rollout (Part B)

Part B starts only after Part A ships and a second surface commits to consuming hints on the wire.

1. `HintPort` stays a no-op in spec 9 until step 2.
2. Kernel session log: `SessionEventLog`, the hint share of the edge buffer, the terminal hint, the single-session invariant. MCP-visible behavior is unchanged except that duplicate list-changed notifications coalesce.
3. Process `inspect` revision, behind a host configuration flag until conformance passes, with the union v4 and the enable-once fix.
4. Recovery projection once the W: recovery work merges; work projection once the W1 query lands.
5. Session control subjects behind `chioEvents`; publish the schemas.

## 18. Tests (Part B)

- **End acknowledgement (H5a):** flush SubscriptionEnded, break the socket before client observation, crash and restore; the marker survives, rebases and replays. A higher Last-Event-ID from a different stream never removes it; live reattachment rebases and persists a fresh id above that cursor before the GET filter, and failed rebase refuses the attachment without losing the old marker. A matching authenticated ack removes it only after the signed persist commits; loss of that ack response is idempotent. Wrong-session authority refuses, a live subscription cannot be acknowledged, and an absent id cannot mutate another entry. Duplicate logical ends are deduplicated and re-acknowledged using the same stable subscription id, regardless of their transport ids. Failed removal persistence retains capacity and the marker; no-ack clients hit the existing subscription bound until unsubscribe/ack/session terminal. No ack method is required by Part A.

- **Acknowledgement survives concurrent rebase (H5a):** GET A delivers an end for subscription S at sequence e1. Before A's acknowledgement is processed, GET B attaches, persists the rebase to e2, then disconnects before delivering it. The acknowledgement `{ subscription_id: S }` based on A's observation still commits removal and frees exactly one slot, without redelivery to A. Repeat across restore and several reattachments. Exercise both serialization orders: rebase first then ack, and a rebase candidate prepared before an ack that commits first; the latter candidate is discarded/rebuilt and cannot reinsert S. Crash after removal commits but before its response, restart, and retry the same ack as a no-op. A new subscription to the same subject gets a different id, so a delayed S acknowledgement cannot remove it. Failed or ambiguous removal persistence never permits a stale candidate to overwrite the authoritative record. Generated ack vectors reject the obsolete transport-id field. No unbounded list of former event ids is retained.

- **Unit (`chio-kernel`):** capacity denial for explicit subscriptions; implicit exhaustion never denies a call; infallible post after subscribe; coalescing precedence (`SubscriptionEnded` > `ThresholdCrossed` > `Changed`); subscribe-then-check catches a post between insertion and level read; one-shot retirement after delivery; terminal last and idempotent; drain-time revalidation ends a revoked or expired subscription; auth rotation revalidates; **quiet expiry:** a subscription whose capability expires with no other activity receives `SubscriptionEnded { Expired }` at the deadline (test clock), with no external drain trigger or source-store commit; **expiry across restart:** the capability expires while the host is down, and restore delivers `SubscriptionEnded` before any catch-up and retains the marker until committed acknowledgement; **clock unavailable:** the authority clock fails at an expiry check, subscriptions with an `expires_at` end with `AuthorityTimeUnavailable`, and subscriptions without an expiry remain; a backward clock step postpones no expiry by more than one `expiry_scan_ms`; lineage matching delivers a root revocation to a descendant holder; second-session refusal.
  - **Terminalized retention (H5a):** a quiet expiry with no drain for a while keeps the entry; a post to it is a no-op; it counts against `max_subscriptions` and a subscribe at capacity is denied; the next drain delivers `SubscriptionEnded`, but only the subsequent committed acknowledgement removes the entry and frees capacity. The same holds for a revalidation failure when the hint share is full, and for an expiry found at restore.
  - **Terminal ordering (H6a):** a race where the cancellation token and the event source are both ready still emits the terminal frame before the stream ends (biased select, cancel only after acknowledgement); every attached stream (GET and a pending POST) emits the terminal with the same event id, and the POST stream emits A13's error first; a slow stream that cannot flush within `terminal_flush_deadline_ms` is closed, and its reconnect with an older `Last-Event-ID` receives the terminal exactly once, then the 3.3 terminal-state response.
  - **Atomic marker rebase (A17, H5a):** restore several durable `Ended` markers beside live standard and negotiated entries. Each pending end gets a distinct id in generation `g`; the emitted ids exactly equal the ids in the one signed generation write, and every catch-up id comes afterwards. An old-generation Last-Event-ID cannot remove a rebased marker. Crash before the candidate write, after it but before activation, and after emission but before cleanup; repeated restores retain logical end identities, rebase again and never restore an ended entry as live. Fail a rebase-only persist and confirm the old durable markers survive; separately fail a candidate persist containing a newly ended negotiated entry and confirm H5a/A31 terminalize the session before restore, even after its cause clears. Verify the v3 MAC covers every changed marker.
- **Proptest:** model-based subscribe/fire_if_dirty/post/drain/revoke/terminate sequences against a reference model, checking section 11.3's predicates.
- **Loom:** `post` racing `drain` and `subscribe` racing `post` on `SessionEventLog` behind the session lock. `queue_tool_server_event` is `cfg(not(loom))` (`session.rs:1106`), so the loom target is the log itself or the post path is un-gated.
- **Spec 9 integration:** no hint effect runs after `Refused`, `Retry` or `CommitOutcomeUnknown`; the no-op port changes no machine output.
- **H1 differential:** drop or forge every hint; verdicts and receipts identical. `AdmissionEvent` has no hint-derived variant.
- **`chio-process`:** `inspect` with `after_revision` below current returns immediately; a wait returns on cancel and on a tree threshold crossing; register-before-read never misses a commit between read and wait; a wait ends at credential expiry; over-bound waits return `waited: false` with `retry_after_ms`; shutdown wakes waiters; a disconnected peer's wait is abandoned; waits consume no call budget and produce no receipt; enforced reads perform no write after the first; an old host rejects the new fields and the client falls back to plain `inspect`.
- **Audience (H9):** no hint reveals confined-child progress or completion; an artifact hint carries no digest; a protected change advances no revision; recovery hints follow chain revisions and a skipped revision forces a `read_recovery_workflow` re-read that issues no command.
- **Stop:** a stop committed by one kernel produces `Changed` on `Stop` in every session of a host sharing the store.
- **Crash safety (H10):**
  - commit an approval and a recovery event, then kill the notifying component before its in-process post: the tail delivers `Changed` within `hint_source_poll_ms`;
  - **approval, same-process crash (H10a):** a session subscribes to `Approval(id)` and the resume record persists `approval_watermark = w`. `resolve` then commits, appending `chio_hitl_events` row `w + 1` in its transaction, and the process is killed before the in-process post. At restart, restore reads `approval_event_head() = w + 1` and replays row `w + 1` from the cursor. The subscriber receives `Changed` on `Approval(id)` for that specific approval, beside the generic catch-up;
  - **approval cursor integrity:** a rolled-back `resolve` leaves no event row; `UPDATE` on `chio_hitl_events`, and `DELETE` of a row above the floor, abort; the sequence stays strictly increasing after the highest row's approval is gone; a gap longer than `approval_replay_max` falls back to catch-up only;
  - **approval retention (H10a):** with `approval_event_retain = 4`, append ten events: at most four rows remain, the floor is 6, the head is 10 and the next sequence is 11. A tailer whose cursor is 3 posts a catch-up `Changed` on each live `Approval` subscription, and a restore with `approval_watermark = 2` uses the catch-up only. A floor decrease aborts, and configuration with `approval_event_retain` below `approval_replay_max` is rejected at load;
  - **budget, source crash (H10):** a structured budget mutation crosses a subscribed threshold and its source component is killed after commit and before the in-process post: the tail of the `budget` chain records delivers `ThresholdCrossed` on `Budget { capability_id, grant_index }` within `hint_source_poll_ms`, with no restart. A `Budget` subscription on a `BudgetStore` without a joint serving owner is `Unsupported`;
  - kill the delivering host after a source commit and before delivery, then restore: each restored subscription receives a catch-up `Changed`, and a change committed after restore's head read is tailed;
  - DST over crash points between source commit, notify, tail and catch-up: `no_silent_loss` holds in every interleaving.
  - **failed end marker (H5a, H6a):** a subscription terminalizes, its `Ended` persist fails, `pending_terminal` is journaled, and the terminal transition also fails. Kill the host, clear the transient cause, and restart. Boot completes the terminal transition before restoring any session, the old `Live` subscription is never reconstructed or re-authorized, and a reconnect receives the terminal-state response. A negative control that also fails the `pending_terminal` write shows the stated journal-write limit: the session is restored and its subscription is re-authorized through A25.
- **chio-conformance:** `chioEvents` negotiated versus not; a revoked capability yields a delivered `SubscriptionEnded`; exactly one terminal per session; a process sees its own cancellation through `inspect` without spending budget.

## 19. Residual risks and open decisions

Residual risks:

- Part A's resync burst may deliver re-read hints for unchanged subjects. Clients that re-read eagerly pay extra reads after a lag.
- Lost progress and log notifications are explicit only when logging is enabled.
- A broken TCP connection still leaves the outcome unknown at a client that sent no `chioRequestId`. Section 4.6 makes that explicit; it does not remove it.
- Persisted subscriptions re-authorize at restore against capabilities that may have expired during downtime. One standard subscription that fails at restore, activation, live delivery, auth rotation or quiet expiry costs its whole session: the client must initialize again and re-subscribe (A25, A30). That is the price of an unambiguous outcome for clients that understand no subscription-ended notification.
- If both the session store and the `pending_terminal` journal are unwritable when a session terminates, the termination is held only in memory. A crash in that window restores the session and re-authorizes its subscriptions (H5a, H6a). Once an intent is journaled, boot completes it before restore (A31, H6a).
- A long-poll `inspect` holds a host connection. The waiter bound limits starvation of `invoke`, but hosts must size it.
- The recovery projection depends on uncommitted W: code built on an older #1160 checkpoint. Work projections depend on contract anchors.

Open decisions:

1. **Process ABI version.** M: (`2a4c2fbe4`) and W: (`lib.rs:54`, from base `f25cd61f4` at v2) each define an incompatible `PROCESS_ABI` v3, so the union is v4 (M: `crates/products/chio-cli/PROCESS_HOST.md:203-212`). Part A no longer waits on it. Part B's `inspect` fields ship in v4. The merge owners decide whether v4 accepts journals from either v3 or only fresh initialization.
2. **Scope of `SessionEventLog`.** It covers kernel sessions in both edge modes, because the stdio edge's `late_events` queue is equally unbounded (`runtime_flow.rs:369`, `:397`). Narrow it only if the stdio edge is retired.
3. Whether to add an agent-level aggregate stream across one agent's sessions.
4. Budget thresholds: caller-chosen or fixed by policy. Revision 4 already removes the level from the hint.
5. Native `chio-wire-v1` framing for hints, or MCP-only.
6. Which cross-owner direction (section 14) to pursue once W2 operates across independent owners.
7. Whether the resync burst (A8) should also be offered to peers as an explicit `notifications/chio/resync` once `chioEvents` exists, so aware clients can distinguish a resync from real changes.

## Review disposition

| Finding | Severity | Disposition |
|---|---|---|
| S5-01 | Blocker | Applied: per-request slot (4.1), session-side `finish_call` (4.2), per-surface retry rule and outcome-unknown error (4.6, A13). Applied differently for "terminate only for notification loss": notification loss triggers a coalesced resync burst (4.4) instead of termination, because termination with a 64-entry window loops through `409` (S5-12); the burst carries the same re-read meaning without reconnecting |
| S5-02 | Major | Applied: subscribe after the request lock (A5); request-correlated events no longer ride the broadcast (A1) |
| S5-03 | Major | Applied: compute `g` before construction, persist after the deadline check, retain inactive on persist failure (A17-A19) |
| S5-04 | Major | Applied: persisted, re-authorized subscriptions with a catch-up hint (section 6) and a conformance test |
| S5-05 | Major | Applied: subscribe-then-check with `fire_if_dirty`; per-subject `SourceLevel`; `Resource` edge-triggered (H4); processes register the `watch` receiver before reading (P2) |
| S5-06 | Major | Applied: drain-time revalidation and rotation revalidation (H7, rule 12.1(2)) |
| S5-07 | Major | Applied: `read_recovery_workflow`, never a command; per-consumer re-read rate limit (12.3) |
| S5-08 | Major | Applied (restrict option): process projection limited to `Lifecycle` and `Budget` (P1). Spec 8 section 11 must drop its process `Stop` hint (edits needed elsewhere) |
| S5-09 | Major | Applied: in-memory `watch` with register-before-read; both process sources commit in the journal, so no crash gap; waits bounded by credential expiry; enable knowledge once; cost row corrected (P1, P2, table) |
| S5-10 | Major | Applied: Part A / Part B split; `HintSubject` crate-internal; schemas published only with Part B |
| S5-11 | Major | Applied: `HintPort`, `Hint`, `HintAudience`, `HintOwnerRef` (11.2); trailing group; H2 per commit class; routing; no-op until Part B |
| S5-12 | Minor | Applied: window raised to 256 with duplicate coalescing (A10); client action after `409` (A11); resync burst removes the reconnect loop (A7-A9) |
| S5-13 | Minor | Applied: `waited`/`retry_after_ms`, waiter accounting after parse, shutdown wake, peer readability (P3) |
| S5-14 | Minor | Applied: Stop from shared `StopHeads` (12.5); lineage matching (12.1(3)). Spec 4 section 9 wording is an edit needed elsewhere |
| S5-15 | Minor | Applied: precedence (H3); `level_bps` removed; conformance reworded to "a delivered `SubscriptionEnded`" |
| S5-16 | Minor | Applied: one-shot retirement, separate implicit and explicit pools, never deny a call for hint capacity (12.1(5)) |
| S5-17 | Minor | Applied: per-site handling for `:608` and `:702` (A14, A15); cancellation token (A12); section 2 corrected (`Closed` cannot fire) |
| S5-18 | Minor | Applied: the D4 test emits enough new-incarnation notifications and includes a seed-0 negative control (section 10) |
| S5-19 | Minor | Applied: checked shift and `g < 2^32 - 1`; low-bit exhaustion terminates fail closed; fresh sessions seed 0 without persisting (A17, A21, A22) |
| S5-20 | Minor | Applied: protected changes never advance a revision (H9, P6) |
| S5-21 | Minor | Applied: `cancel` count excludes confined children; Children and shared-budget projections exclude them (7.2) |
| S5-22 | Minor | Applied: per-kind `last_revision`; tree-level budget revision with no fan-out (P1) |
| S5-23 | Minor | Applied: approvals projected from the approval store; audience mapping through the operation owner (12.3) |
| S5-24 | Minor | Applied: dependency ban, `AdmissionEvent` assertion, differential test (H1); control methods specified (16) |
| S5-25 | Minor | Applied: hints use a reserved share of the edge buffer; other producers explicitly unchanged and out of scope (12.1(4)) |
| S5-26 | Nit | Applied in section 2 |
| S5-27 | Nit | Applied: pre-sized pending ring (H5); loom target note (18) |
| S5-28 | Nit | Applied: plain-`inspect` fallback allowed for reads (P5); option A rejection reworded to latency (12.2) |
| (new) GET replay gap | Found in revision | Applied: subscribe before snapshot (A6) and a test |

### Codex review (PR #1174, round 1)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180389985 | Make subscription arming atomic with source changes | Already addressed in revision 4. `subscribe` takes no caller-sampled level. It inserts the armed entry first, then the caller reads the level and calls `fire_if_dirty`, so a post in the window is captured and a post before insertion is visible in the later level read. `Resource` is edge-triggered by declaration | H4; section 12.1 `subscribe`/`fire_if_dirty`; section 18 unit and loom cases |
| 4180435337 | Make external-source hint posting crash-safe | Fixed now. Processes already had no gap in revision 4 (P1 commits the revision in the change's journal transaction). Sessions now read every outside source through an existing durable monotonic cursor, with restore re-arming in the order heads, then catch-up, then tail | H2, new H10, `no_silent_loss` scope, 12.3(5), section 15, section 18 |
| 4180731777 | Cancel nested requests when their POST stream disappears | Fixed now. Losing the receiver is treated like overflow: undelivered and later server requests fail locally at once, delivered ones after a grace bound. The slot owns the request lock until its terminal response, so correlation holds and the completion task terminalizes | A2a, A2b, section 4.2, A16, section 8, section 10 |

### Codex review (PR #1174, round 2)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180839023 | Serialize notification POSTs with active request slots | Fixed now. Confirmed on M: and `main`: notification POSTs and client responses are sent without the request lock, and the serial edge handles a deferred notification after the active call, so temporal correlation misroutes what it causes. Server requests are now routed by explicit causal identity. Uncorrelated ones go to the GET stream or are answered locally, and a lock-holding notification POST keeps its buffered response. Serialization was rejected because cancellations and client responses must bypass the lock | A1, A1a, A1b, A1c, A2b, section 8, section 9, section 10 |

### Independent review (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-5-01 | Round-2 GET routing bypasses the non-lossy server-request path | Fixed. Confirmed on M: that both GET branches filter to notifications (`http_service.rs:810-812`, `:853`). GET-bound server requests now ride a bounded, non-lossy queue owned by the GET attachment, with delivery tracking, a local error on overflow, local answers on detach (immediate for undelivered, after the grace window for delivered), and no dependence on the broadcast. The live and replay filters stay notifications-only and also select the queue. The lag claim is restated. Tests cover ordinary delivery, lag, detach and overflow | A1b; A1d; A6; section 4.4; sections 8, 9, 10 |

### Codex review (PR #1174, round 7)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4185260831 | Persist restored subscriptions under the v3 envelope | Fixed now. A17's boot re-sign carries the complete record, `subscriptions` included, and changes only the generation. New A28 selects the envelope on every re-sign: `v3` when `subscriptions` is non-empty or the record was loaded as `v3`, otherwise the deployment floor (default `v3`). The version never decreases, and a would-be downgrade is refused fail closed. New A29 verifies under the named envelope, never retries a `v3` record under `v2`, and rejects `v2` records that carry subscriptions. Test: restore with subscriptions, restart twice, subscriptions intact and verified | A17; A28; A29; sections 8, 9, 10 |
| 4185260873 | Schedule capability-expiry hints | Fixed now. New H7a adds a per-session `ExpirySchedule` (a pre-sized min-heap by `expires_at`). It wakes on the monotonic clock, confirms against the authority clock, and is backed by a periodic scan. It posts `SubscriptionEnded { Expired }` with no store commit needed. Restore re-arms it from the persisted subscriptions and fires expiries that passed during downtime before the catch-up. An unavailable authority clock ends expiring subscriptions fail closed. Tests cover quiet expiry, expiry across restart, and clock unavailable | H7a; H10 table; `EndReason`; section 12.1; sections 15, 18 |

### Codex review (PR #1174, round 9)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4185756929 | Tail approvals from their actual durable store | Fixed now. Confirmed on M: that `SqliteApprovalStore` is a separate store whose `resolve` commits in its own transaction and never writes `authority_global_commits` (`approval_store.rs:85-103`, `:558-620`). It also has no monotonic cursor (`approval_id TEXT PRIMARY KEY`). New H10a adds an append-only `chio_hitl_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT, ...)`, written inside each approval-state transaction and protected by immutability triggers, as the `Approval` source cursor with its own head and tail. Each session's resume record carries `approval_watermark`, so restore replays the specific approval events committed before a crash, up to `approval_replay_max`. Projecting into the admission chain was rejected because the two stores can be separate files | H10 table; H10a; section 12.3 items 1 and 5; section 18 crash tests |

### Codex review (PR #1174, round 8)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4185510067 | Retain expired subscriptions until the end hint is delivered | Fixed now. Every path that ends a subscription moves it to `Terminalized` with `SubscriptionEnded` pending in its own slot: expiry (including at restore), revalidation, subject gone, clock failure. It keeps its slot and metadata, accepts no posts, counts against capacity, and was originally removed after transport handoff. Round 33 supersedes that removal rule: persisted end markers and capacity remain until committed explicit acknowledgement, unsubscribe or session termination | H5a; H7; H7a; section 11.3 predicates; section 12.1; section 15; section 18 |
| 4185510114 | Flush the terminal hint before cancelling streams | Fixed now. Termination runs in order: write `Terminal` to the log, copy it into each stream's reserved terminal frame, wait for every stream to emit and flush it (biased select, bounded by `terminal_flush_deadline_ms`), and only then cancel the session token. A stream closed at the deadline leaves the terminal retrievable for one replay within `terminal_retention_ms`. One logical terminal per session, with the same event id on every stream | H6a; section 13 item 2; section 11.3 predicates; section 15; section 18 |

### Codex review (PR #1174, round 10)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4185993994 | Reserve sequence zero for the no-cause sentinel | Fixed now. `InboundSeq` wraps `NonZeroU64`, the session counter starts at 1, `reserve_inbound_seq` never issues 0, and exhaustion fails closed. Zero is only the cause cell's no-cause sentinel | section 4 API; A1a |

### Codex review (PR #1174, round 11)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4186194360 | Persist the end hint until delivery is known | Superseded by round 33: persist Ended at terminalization and retain it until explicit client ack, unsubscribe or session terminal. Transport flush and Last-Event-ID alone are insufficient proof | H5a |

### Codex review (PR #1174, round 12)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4186364927 | Encode durable end markers in the resume schema | Fixed now. A24's persisted entry is a tagged `PersistedSubscription = Live { .. } \| Ended { uri, capability_id, reason, end_event_id }`, inside the v3 integrity envelope, so H5a's end marker is representable and authenticated | A24; H5a |
| 4186364968 | Bind approval events to their owning session | Fixed now. `chio_hitl_events`, `ApprovalRequest` and `chio_hitl_pending` carry `audience_owner`, the creating request's canonical `HintOwnerRef`, written in the event's transaction. Routing uses it, never `subject_id`, so two sessions of one subject never cross | H10a |

### Codex review (PR #1174, round 13)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4186619810 | Preserve ended subscriptions during restore | Fixed now. A25 branches on the tag. `Ended` markers are re-queued and never re-authorized. A `Live` entry that fails re-authorization is terminalized into an `Ended` marker with its `SubscriptionEnded`, not dropped. A26 sends catch-up updates only for `Live` entries that passed | A25; A26 |

### Codex review (PR #1174, round 14)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4186767776 | Reconcile the restore failure contract | Fixed now. The failure-table row and the restore test now require terminalization: an `Ended` marker with the reason, `SubscriptionEnded` queued and persisted until acknowledged (round 33), and no catch-up update | section 8 failure table; section 10 tests |

### Codex review (PR #1174, round 15)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4186909736 | Persist terminalization before hand-off | Fixed now. The `Ended` marker is persisted by re-signing the resume record at the moment of terminalization, before any wait for transport capacity, and it is retained until emission. A crash after terminalization can no longer leave a `Live` entry that restore might re-authorize | H5a |

### Codex review (PR #1174, round 16)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187050279 | Fail closed when persisting an end marker fails | Fixed now. A failed `Ended` persist durably invalidates the resume record through the store's terminal session transition (higher `resume_generation`) and ends the session. If that also fails, the session store is not ready. After that double failure only, restore re-authorizes from scratch: permanent causes end, a transient cause that cleared yields a validly re-authorized subscription, and H7 still checks every delivery | H5a |
| 4187050292 | Trigger a pending hint for cross-process revocations | Fixed now. The cross-process revocation poller posts a lineage-matched `Changed` on `Capability(id)` for each affected subscription. That triggers a drain, and H7 revalidation ends the subscription with `SubscriptionEnded { Revoked }`, even when the subscription is otherwise quiet | section 12.5 |
| 4187050296 | Bound resync bursts below the broadcast capacity | Fixed now. A resync burst emits at most `broadcast_capacity / 4` events per iteration, catalog and logging events first, and continues from a `resync_cursor` retained in each consumer's record (clarified in round 32). A lag finishes the current pass and queues one full follow-up under A8; repeated lag is bounded by resync_max_passes | A8 |

### Codex review (PR #1174, round 18)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187315386 | Schedule a full follow-up resync after mid-burst lag | Fixed now. A lag during a pass lets the pass finish and queues one full follow-up pass, coalesced to at most one pending, which re-sends every hint the lag skipped. A pass cannot cause its own lag, and a consumer that lags on every pass uses the reconnect path | A8 convergence |
| 4187315390 | Rebase restored end notifications onto the new generation | Fixed now. Each marker keeps a logical end identity, `(subscription_id, reason)`. Before serving, restore assigns the re-queued `SubscriptionEnded` a fresh event id in the restored generation and re-signs the marker, so replay uses an id the client can actually hold. Round 34 decouples acknowledgement from that transport id: the stable subscription id acknowledges the same logical end across every rebase | H5a |

### Codex review (PR #1174, round 19)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187433104 | Rebase ended markers in the normative restore path | Fixed now. A25 keeps the logical end identity, assigns a fresh `end_event_id` in the restored generation and re-signs, and only then re-queues. A stale id is never re-queued, matching H5a | A25 |
| 4187433110 | Define when a perpetually lagging consumer disconnects | Fixed now. After lag during `resync_max_passes` (default 3) consecutive passes, the server ends that stream with a `chio-resync-required` frame, or closes a POST stream's notification channel while keeping its non-lossy terminal response. It clears that consumer's resync flag, and A10 and A11 take over on reconnect | A8 |
| 4187433136 | Scope stop hint cursors by stop scope | Fixed now. The `Stop` source tails stop records by the store-global commit sequence, not by epoch, and matches each record to sessions by its scope. A higher epoch in tenant A can no longer hide tenant B's first stop | H10 table |

### Codex review (PR #1174, round 20)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187512204 | Track resync state per stream before clearing it | Fixed now. The resync flag, skipped count, pass counter and cursor are per consumer (`consumer_id`). Passes are emitted while any consumer has a pending request, and records advance and clear independently. Ending a perpetually lagging stream drops only its own record | A7; A8 |

### Codex review (PR #1174, round 21)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187599047 | Persist subscription IDs in the resume record | Fixed now. Both A24 arms carry the client-visible `subscription_id`, inside the v3 integrity envelope. Restore reconstructs the same id, duplicates stay distinct, `unsubscribe` keeps working after restart, and the end marker's `(subscription_id, reason)` identity is defined | A24 |

### Codex review (PR #1174, round 22)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187663051 | Include the subscription ID in end notifications | Fixed now. `notifications/chio/event` carries `{seq, subject, kind, subscription_id}`, so the client can tell which duplicate subscription ended and can deduplicate a rebased end by `(subscription_id, reason)`, the identity that is now on the wire | section 13 negotiation; section 16 wire |

### Codex review (PR #1174, round 23)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187740942 | Define an ID for session terminal events | Fixed now. `subscription_id` is required on subscription-scoped kinds (`Changed`, `ThresholdCrossed`, `SubscriptionEnded`) and absent on the session `Terminal`. The terminal belongs to no subscription and is identified by its single per-session event id, so the frame is serializable under the declared shape | section 13 negotiation; section 16 wire |

### Codex review (PR #1174, round 24)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187829610 | Persist terminal hints before waiting for stream flushes | Fixed now. H6a step 1a durably records the terminal event (id, reason, retention deadline, consumed flag) in the terminal tombstone before any flush wait. After a crash, the tombstone serves the one retained replay, and consumption is recorded durably | H6a |

### Codex review (PR #1174, round 25)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187931952 | Prevent restore after terminal persistence fails | Fixed now. A failed terminal-transition persist no longer just proceeds. The session store goes not ready and the transition is retried, and boot completes any pending terminal transition before restoring sessions, so a terminated session can never be restored from its old record | H6a step 1a |

### Codex review (PR #1174, round 26)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187992989 | Journal the termination before attempting its fence | Fixed now. Step 1a writes and fsyncs the `pending_terminal` entry before any SQLite write, and removes it only after the terminal transition commits. A crash at any point leaves either the fence or the journal entry, which boot completes before restoring sessions. A failed journal write stops serving the session store | H6a step 1a |

### Codex review (PR #1174, round 27)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4188089175 | Journal the full terminal transition payload | Fixed now. `pending_terminal` holds the complete terminal payload `{ session_id, terminal_generation, event_id, reason, retention_deadline }`, so boot completes the exact tombstone, including the retained replay, after a crash | H6a step 1a |
| 4188089185 | Keep failed subscription endings fenced on restore | Fixed now. A failed `Ended` persist terminates the session through H6a: the payload is journaled in `pending_terminal`, then the fence is attempted, and boot completes it before restoring any session. The stale `Live` record is never restored or re-authorized | H5a |
| 4188089202 | Preserve the parent cause across nested client responses | Fixed now. A client response's own `seq` is transport bookkeeping only. Each pending server request records `parent_cause`, and the matched response's continuation runs under that cause, so the parent's terminal response reaches its slot and releases the lock | A1a |

### Independent review pass 5 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-5-02 | One normative restore sentence still permits the resurrection round 27 forbids | Fixed. The obsolete "double store failure ... re-authorizes from scratch" exception is removed. A failed marker persist now points to the pending-terminal gate, so boot completes the journaled terminal transition and never restores the stale `Live` record. The journal-write limit is stated once and consistently in H5a, H6a and the residual risks: a failed `pending_terminal` write leaves only an in-memory stop, so a crash in that window restores the session as an ordinary restore. Nothing claims that an unpersisted stop survives a crash. A crash test covers the journaled double failure and a negative control for the journal-write limit | H5a; H6a step 1a; section 18 crash safety; section 19 |

### PR #1174 review round 28 (Greptile)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4190460693 | Part A depends on Part B | Fixed now. A24-A26 define standard resource subscriptions on their own. They are keyed by URI as the existing session owner keys them, with no client-visible id. A standard subscription that fails re-authorization at restore ends its whole session through A18's existing terminal path, with reason `subscription_not_restored`. The session is never served without it, and reconnect gets the terminal-state response, so no new notification is needed. A failed terminal write retains the record inactive and unserved. `subscription_id`, `Negotiated`/`Ended` entries and `SubscriptionEnded` belong to Part B, which extends the same persisted record and owner, and the URI registers upstream once | A24, A25, A26; section 8 failure table; section 10 test; section 19; H5a; section 11.3 rules 4 and 7 |

### Independent review pass 6 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-5-03 | Part A subscription restore requires the deferred Part B wire protocol | Fixed with round 28's comment 4190460693 (above). The acceptance test uses a client that negotiates nothing: subscribe, unsubscribe, a successful restore, and a failed re-authorization observed through a standard `resources/updated` and a failing re-read across another crash. No Part B method or event is required or emitted, and a later negotiated client shares the same durable owner | A24-A26; section 10 |
| R-5-04 | A normal resource update cannot reliably signal that a subscription has ended | Fixed. The first round-28 fix used one `resources/updated` plus a failing re-read as the end signal. Read and subscribe grants are matched separately (V3: `request_matching.rs:1065-1071`), so that read can succeed. The `EndPending` marker is removed. A standard subscription that cannot be re-authorized now terminalizes its session through A18's terminal path before anything is served, and a failed terminal write leaves the session unserved. Tests cover a valid read grant with an expired subscribe grant, a subject recreated before the read, a crash before reconnect, and a failed terminal write | A24, A25, A26; section 8; section 10; section 19 |

### PR #1174 review round 29

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4190686691 (Greptile), 4190699721 (Codex) | Keep the terminal epoch ahead of the stored active generation | Fixed. Subscription restore runs on the unserved candidate before the generation persist, sharing ordinary checks without A24 per-subscribe writes. A failed entry stops the candidate and writes terminal g over stored g - 1. Cases cover a later subscription failing, the generation bound, expiry during subscription I/O, crash and terminal-write failure | A17, A25; section 10 |

### PR #1174 review round 30

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4197054908 | Keep standard subscription authority current after restore | Fixed. A30 ships the shared authority gate and expiry schedule in Part A, covering live delivery, replay, resync, auth rotation and post-persist activation. Failed standard authority ends the session without requiring Part B wire support. A31 promotes the one terminal-intent helper to Part A so failed writes cannot resurrect a journaled refusal. H7/H7a extend the same checker and schedule | A17, A25, A30, A31; sections 8-10; H5a, H6a, H7/H7a; section 19 |
| 4197054921 | Persist rebased end ids with the restore generation | Fixed. A17 stages subscription transitions, allocates distinct end ids in the restored generation, and writes the complete candidate once. H5a emits only those committed ids and preserves logical end identities across repeated restore. Failed new-end persistence takes the existing terminal path; failed rebase-only persistence preserves the old durable end | A17, A19; H5a; section 18 atomic marker rebase cases |

### PR #1174 review round 31

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4197555214 | Declare the live authority-loss terminal reason | Fixed. A32 defines the shared closed TerminalReason enum, including both subscription failure reasons and their lifecycle-state mapping. Native v3 terminal fence/tombstone MACs, the intent journal and Part B Terminal use the same value; legacy verification, unknown-value refusal, crash replay and downgrade boundaries are explicit | A28, A31, A32; sections 9-11, 16; terminal-reason conformance cases |

### PR #1174 review round 32

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4197876482 | Keep the resync cursor per consumer | Fixed. A7/A8 retain and advance resync_cursor only in its consumer_id record. A later consumer starts at the catalog prefix, follow-ups reset only that consumer, and detach cannot clear another pass. Shared emission keeps one session-wide chunk budget and fair service | A7, A8; section 10 staggered-consumer cases |

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
- FTL has no transport or restart. Chio crosses process and network boundaries, so it needs response slots, resync, cursors, windows and generation-seeded sequences.
- FTL rights are the whole authorization story. Chio subscriptions derive from revocable capabilities, so they are revalidated at delivery (H7).
- An FTL wait is free. A Chio mediated call is not, which is why process control hints ride `inspect` rather than a mediated tool.

### PR #1174 review round 33

| Review | Issue | Disposition | Contract |
|---|---|---|---|
| 4198048487 | Stop resync traffic from amplifying lag | Fixed. Synthetic resync frames use consumer-directed delivery through the existing sequence/replay writer, never the broadcast ring. One reserved transport slot per consumer and one fair session budget bound work; only ordinary-source lag consumes the failed-pass budget | A7-A8; section 10 |
| 4198110097 | Retain prefix progress | Fixed. ResyncCursor covers Prefix, Resources and Complete with explicit indexes into a bounded pass snapshot. Partial catalog/warning prefixes resume exactly, including chunk size one | A7-A8; section 10 |
| 4198110108 | Keep terminal counter headroom | Fixed. Native persistence generations are full-width and distinct from the 32-bit event seed. Checked signed-SQLite-domain counters reserve terminal headroom; the final low-bit event slot is reserved for Terminal without overflowing the last seed | A17; A22-A22a; section 10 |
| 4198110130 | Retain end markers until acknowledged | Fixed. Flush is only handoff. Part B adds authenticated end acknowledgement, signed marker removal and unique subscription ids; round 34 makes acknowledgement subscription-scoped rather than dependent on the current transport id; higher cursors alone never remove ends. Restore and live reattachment persist rebased ends before emission, retaining capacity until acknowledgement/unsubscribe/session terminal | H5a; H7; sections 11.3, 15-16, 18 |

### PR #1174 review round 34

| Review | Issue | Disposition | Contract |
|---|---|---|---|
| 4198496611 | Rebasing invalidates an already observed end | Fixed. Ack names the stable, never-reused subscription id in the authenticated session; transport ids may rebase without invalidating it. The existing session-record owner serializes removal and rebase, so stale candidates cannot resurrect an acknowledged marker. Cases cover two GET streams, disconnect before rebased delivery, restore, both writer orders, lost ack responses and a new subscription to the same subject | A24; H5a; section 11.3; sections 16 and 18 |

### PR #1174 review round 36 (review bots)

| Review | Issue | Disposition | Contract |
|---|---|---|---|
| 4228925623 | Budget hints had no durable cursor | Fixed. The H10 table gains a `Budget` row: structured budget mutations already append `budget` records to the global commit chain in their own transaction (M: `budget_store/store.rs:314-328`), so the tail maps each record to its grant and posts `ThresholdCrossed`. A `BudgetStore` without a joint serving owner writes no chain record and is therefore `Unsupported` for `Budget` subscriptions | H10; section 12.1 rule 3; section 18 |
| 4228925665 | `chio_hitl_events` grew without bound | Fixed. H10a retention keeps at most `approval_event_retain` rows (default 65536, at least `approval_replay_max`) by raising a monotonic floor and pruning at or below it in each appending transaction; the delete trigger permits only rows at or below the floor. A tailer or restore whose cursor is below the floor resyncs through catch-up, so pruning never loses a hint silently | H10a; section 18 |

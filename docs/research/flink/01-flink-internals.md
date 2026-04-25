# Flink Internals for Chio Streaming Exactly-Once Receipts

Research findings that settle open questions in `../chio-streaming-flink-integration.md`. Evidence is cited inline (Flink javadoc, release announcements, source).

## Answers

### 1. TwoPhaseCommitSinkFunction contract

`TwoPhaseCommitSinkFunction<IN, TXN, CONTEXT>` is the base class Flink ships for implementing end-to-end exactly-once sinks on top of `CheckpointedFunction` + `CheckpointListener`. The required override methods (all `protected abstract` except `recoverAndCommit`):

```java
protected abstract TXN  beginTransaction()                    throws Exception;
protected abstract void invoke(TXN txn, IN value, Context c)  throws Exception;
protected abstract void preCommit(TXN transaction)            throws Exception;
protected abstract void commit(TXN transaction);
protected abstract void abort(TXN transaction);
protected          void recoverAndCommit(TXN transaction);   // default: commit(txn)
```

Ordering relative to checkpoint barriers (from the Flink 2018 end-to-end EOS blog post and the javadoc):

1. `beginTransaction()` runs at the start of each checkpoint interval. Everything written via `invoke(txn, ...)` between barriers N and N+1 belongs to transaction N+1.
2. When the checkpoint barrier for N reaches the sink, Flink calls `snapshotState()`, which internally invokes `preCommit(txn_N)`. The sink must flush and ensure any subsequent `commit` cannot fail due to its own state (flush writes, fsync, close file, pre-publish Kafka txn markers). The pending `TXN` is added to operator state and snapshotted.
3. Once the JobManager confirms the entire checkpoint is complete, every operator's `notifyCheckpointComplete(checkpointId)` fires; for the sink this calls `commit(txn_N)`. "commits must be idempotent" because the JM's notify is best-effort - the sink may see it twice, or not at all, with `recoverAndCommit` picking up on restart.
4. If any operator fails before the JM records the checkpoint complete, `abort(txn)` runs on restart and the transaction is rolled back.

For "emit receipts to Kafka" we do not need to write our own: Flink's `KafkaSink` with `DeliveryGuarantee.EXACTLY_ONCE` already implements this via Kafka transactions ("KafkaSink will write all messages in a Kafka transaction that will be committed to Kafka on a checkpoint"). Required config: `.setTransactionalIdPrefix("chio-receipts-<jobname>")` unique per job on the cluster, and `transaction.timeout.ms` > (max checkpoint interval + max restart time) or transactions expire and receipts are lost.

Evidence: `TwoPhaseCommitSinkFunction` javadoc (release-1.20), "End-to-end Exactly-Once Processing" blog (flink.apache.org/2018/02/28), Kafka connector docs (release-1.20/docs/connectors/datastream/kafka).

### 2. Side output timing and checkpoints

Side outputs emitted via `ctx.output(tag, value)` from `ProcessFunction.processElement` are just a second output edge of the same operator. They are governed by the same barrier-alignment mechanism as the main output: the operator emits records (main and side) onto outgoing streams in order, and the checkpoint barrier N follows all records produced before it. So a side-output record emitted during processElement of an event that arrived before barrier N is part of checkpoint N, and the downstream operator (or sink) consuming the side output sees it exactly once under the same rules as the main stream.

This means side outputs do NOT give us exactly-once on their own. Side outputs ride Flink's barrier semantics to the *next* operator. For end-to-end exactly-once out of the job, whatever sink consumes the side output still has to participate in checkpointing (2PC or an exactly-once sink).

Evidence: "When an intermediate operator has received a barrier for snapshot n from all of its input streams, it emits a barrier for snapshot n into all of its outgoing streams" (release-1.3/internals/stream_checkpointing, unchanged semantics). Also `Context#output(OutputTag, value)` is implemented on the same `Output` collector as main output, not a separate uncheckpointed channel.

Consequence for us: the preliminary design ("side outputs are the right primitive because they ride Flink's checkpoint snapshots end-to-end") is correct, but the language "the receipt is emitted by the checkpoint" is loose. Receipts are emitted *per record* and are *part of* a checkpoint's set of outputs; the 2PC at the sink is what makes them atomic externally.

### 3. Failure scenarios

All four, assuming KafkaSink (EXACTLY_ONCE) for receipts + DLQ and a replayable source (Kafka consumer with offsets in checkpoint):

- **Task failure mid-processing (before checkpoint N barrier arrives at sink):** Flink restarts, restores state from checkpoint N-1, the source rewinds to the offsets in N-1, and *the sidecar gets re-called* for every event after that offset. The in-flight Kafka transaction is `abort`ed; no receipts from this run are visible to the receipt consumer. User-visible: replay, no duplicates externally.
- **Task failure after preCommit (Kafka txn in PREPARED state) but before commit:** The checkpoint either completed globally (notifyCheckpointComplete will fire on recovery and `recoverAndCommit` replays the commit, receipts appear atomically) or it did not (the Kafka transaction will be aborted by the new incarnation using the same `transactionalIdPrefix + subtaskIndex`, which fences the old one). User-visible: either receipts appear exactly once or they don't appear at all; never split.
- **JobManager failure during 2PC:** The JM runs the checkpoint coordinator; on failover the new JM reads the last-completed checkpoint from persistent storage. If the old JM had recorded checkpoint N complete, new JM issues `notifyCheckpointComplete` on restart and `recoverAndCommit` runs. If not, N is treated as failed and all `TXN`s for N are aborted on recovery. Same outcome as task failure post-preCommit.
- **Kafka unavailable during `commit`:** `commit()` is retried according to the job restart strategy; `TwoPhaseCommitSinkFunction`'s contract is that commit MUST eventually succeed or the job stays down. There is no data loss (the txn is in Kafka's PREPARED state already) but receipts are delayed until Kafka recovers. The sidecar is NOT re-called during this retry loop since the source offsets in checkpoint N include the already-evaluated events.

Sidecar re-call summary: the sidecar is called again only on source rewind, which happens only when the checkpoint containing those events did not commit. Deterministic Chio policy evaluation makes re-calls produce byte-identical receipts, and the aborted Kafka transaction ensures the first run's receipts are never visible.

Evidence: "End-to-end Exactly-Once Processing" blog, KafkaSink javadoc on `transactionalIdPrefix` fencing semantics, `TwoPhaseCommitSinkFunction.recoverAndCommit` contract.

### 4. AsyncFunction vs ProcessFunction for sidecar calls

`AsyncFunction` (used via `AsyncDataStream.unorderedWait(stream, fn, timeout, capacity)`) lets a single parallel operator instance have up to `capacity` in-flight requests. At 5ms RTT, a synchronous `ProcessFunction` with parallelism P tops out at `P * 200 events/sec`. An `AsyncFunction` with capacity C and the same P can reach `P * C / RTT`, i.e. with C=100 it is 100x higher throughput per slot. This is the shape Flink itself recommends for "external data access" (asyncio docs).

Checkpointing works correctly: "It stores the records for in-flight asynchronous requests in checkpoints and restores/re-triggers the requests when recovering from a failure." Records whose `ResultFuture` has not completed at barrier N are snapshotted and replayed after recovery. `unorderedWait` still respects watermark boundaries, so event-time correctness is preserved.

**Side outputs on AsyncFunction: not natively supported.** The `AsyncFunction<IN, OUT>` interface is `void asyncInvoke(IN input, ResultFuture<OUT> resultFuture)`, with no `Context` parameter and therefore no `ctx.output(tag, ...)`. `ResultFuture` has only `complete(Collection<OUT>)` / `completeExceptionally(Throwable)`. This is a hard architectural constraint: async results carry only the main-output type. Workarounds:

1. Emit a *sum type* (sealed `AllowResult | DenyResult | ReceiptOnly`) as the single `OUT`, then a downstream `ProcessFunction` splits into main / receipt / DLQ side outputs. This is the idiomatic Flink pattern and costs essentially nothing (no extra network; chained operators run in the same thread).
2. Use `AsyncFunction` only for the sidecar call and a subsequent `ProcessFunction` for emission + side-output routing. Same as (1) just phrased as two operators.

Evidence: `AsyncFunction.java` source on apache/flink master (`void asyncInvoke(IN, ResultFuture<OUT>)`), `ResultFuture.java` interface, release-1.20 asyncio docs.

### 5. Minimum Flink version

**Recommend Flink 1.20** as the minimum, with 1.19 as a soft floor.

- Java `AsyncFunction`, Kafka 2PC sink (`KafkaSink` with `DeliveryGuarantee.EXACTLY_ONCE`), and keyed state accessors are all stable and long-predate 1.18 on the JVM side.
- Python (`pyflink.datastream.AsyncFunction` with `async def async_invoke(self, value) -> List[OUT]`) is present in 1.18/1.19 but the interface has been iterated on: FLINK-38563 (docs), FLINK-38591 (examples), FLINK-38615 (more Pythonic interface) all landed on master recently (2026). 1.19 added retry support (FLIP-232). On 1.18, Python `AsyncFunction` works but lacks built-in retry and has documentation gaps.
- 1.18 is enough to ship; 1.19 gets us `AsyncRetryStrategy` without us implementing retry; 1.20 is the current LTS target.

Decision: pin `apache-flink >= 1.19, < 2.0` in the `[flink]` extra. Document 1.20 as tested. The prelim doc's `>= 1.18` is safe but we lose built-in retry.

Evidence: Flink 1.18/1.19/1.20 release notes, FLIP-232 (Add Retry Support For Async I/O), FLINK-38563/38591/38615 Jira tickets.

### 6. Checkpoint barrier alignment and backpressure

Synchronous sidecar inside `processElement` at 100ms RTT back-pressures correctly but badly: the operator's task thread blocks for 100ms per element, upstream network buffers fill, credit-based flow control signals upstream operators to stop sending, all the way to the source (which stops consuming Kafka). This is "correct" (no OOM, no lost events) but checkpoint barriers queue up behind the buffered elements, inflating alignment time and end-to-end checkpoint duration. "When a Flink job is running under heavy backpressure, the dominant factor in the end-to-end time of a checkpoint can be the time to propagate checkpoint barriers" (checkpointing_under_backpressure).

Two mitigations relevant to us:

1. **AsyncFunction** (question 4) - the task thread returns immediately after registering the future, so the operator never holds up barriers beyond a single element's CPU cost. The in-flight requests are stored in snapshot state and replayed on recovery.
2. **Unaligned checkpoints** - `env.getCheckpointConfig().enableUnalignedCheckpoints()` lets barriers overtake queued buffers; in-flight records are captured into the snapshot instead of waiting. Not strictly needed if we use AsyncFunction, but a safety net for users on sync ProcessFunction mode.

Recommendation: the latency-critical operator should be AsyncFunction; ship unaligned checkpoints as a docs recommendation for users who stay on ProcessFunction.

Evidence: release-1.20/docs/ops/state/checkpointing_under_backpressure, "buffer debloating" intro in Flink 1.14.

## Implications for our design

- **Use AsyncFunction for the sidecar call, not ProcessFunction.** Throughput win of 1-2 orders of magnitude at realistic RTT, and it keeps barrier alignment fast. The preliminary doc's "ship ProcessFunction + AsyncFunction pair" should collapse to "AsyncFunction is the primary; ProcessFunction is only for users who need full `Context` access e.g. timers".
- **Compose AsyncFunction with a trailing ProcessFunction for side outputs.** AsyncFunction cannot emit to `OutputTag`. Emit a sealed `EvaluationResult` union from the async call, then a chained ProcessFunction routes `Allow -> main`, `Deny -> DLQ tag`, `receipt -> RECEIPT tag`. Chained operators incur no serialization cost.
- **Do NOT write our own `TwoPhaseCommitSinkFunction` for Kafka.** Use `KafkaSink` with `DeliveryGuarantee.EXACTLY_ONCE` and a unique `transactionalIdPrefix`. Our 2PC story kicks in only if users plug a non-Kafka sink for receipts (JDBC, S3, etc.), and then we point them at Flink's existing 2PC sinks rather than writing a bespoke one.
- **Document the `transaction.timeout.ms` gotcha.** If the receipt sink runs on Kafka < 2.5 or the user's checkpoint interval is long, transactions can expire and receipts are lost. Add this to the integration README.
- **Receipts are NOT "emitted by the checkpoint"; they are emitted during processElement and committed atomically at checkpoint complete.** The prelim doc's phrasing needs a small correction: the sink is what makes it atomic, not the operator.
- **Pin `apache-flink >= 1.19`.** Gets us built-in `AsyncRetryStrategy` and a stable Python AsyncFunction. Tested surface is 1.20.
- **Recommend `env.enableUnalignedCheckpoints()` in the docs.** Safety net for users on slow sidecars + ProcessFunction mode. No cost if they're already on AsyncFunction.
- **Sidecar determinism is a correctness requirement, not just a nice-to-have.** Because replay re-calls the sidecar and replays produce the receipt sink writes, a non-deterministic policy (e.g. "random 1% sample allow") would produce different receipts across retries. The prelim doc already notes Chio is deterministic on `(policy_hash, input)`; this research confirms the dependency is load-bearing.

## Remaining uncertainty

- **PyFlink Python AsyncFunction stability on 1.18 vs 1.19.** The FLINK-38xxx tickets are dated 2026 and target master (likely 2.0+), suggesting the *interface* may shift. 1.19 is stable enough but we should integration-test against 1.19 and 1.20 before pinning a minimum. The prelim doc says 1.18; I recommend tightening to 1.19.
- **Whether PyFlink's `AsyncFunction.async_invoke` supports returning multiple results.** Java `ResultFuture.complete(Collection<OUT>)` supports it; the Python `async def async_invoke(self, value) -> List[OUT]` nominally does too. Not confirmed whether the downstream ProcessFunction sees them as separate records vs a list. Worth a small experiment.
- **Exact behavior of `notifyCheckpointComplete` being "best effort".** Documentation repeatedly says notifications "can sometimes be skipped." `recoverAndCommit` covers the case where the notification is lost but the checkpoint committed. Not clear whether there's a case where `notifyCheckpointComplete` fires but the txn has not yet been recorded committed in state; the javadoc implies the sink must write the pending-commit list to state *before* commit can run, which should prevent it.
- **Side outputs from a non-keyed AsyncFunction followed by a keyBy.** If the receipt side output from the trailing ProcessFunction is itself keyed (by request_id say) for dedupe, there's a shuffle between the operator and the receipt sink. Barrier alignment across that shuffle is standard Flink but worth confirming doesn't interact badly with the transactional sink's commit ordering.

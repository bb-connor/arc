# Flink Integration for Chio Streaming

## Status

Research / design proposal. No code. Supersedes nothing.

## Goal

Let Flink jobs evaluate each event against a Chio capability, emit signed receipts, and route denials to a DLQ — with the same semantics the other broker middlewares promise (fail-closed, deduplicable, receipts chain via `request_id`).

Scope boundary: this is a *native* Flink integration. Running the existing `chio_streaming.middleware` (Kafka) from a `RichFlatMapFunction` would work but would throw away the parts of Flink that make the integration worth doing.

## Why not just run the Kafka middleware inside Flink

A Flink job backed by Kafka can in principle use `ChioKafkaMiddleware` inside a `ProcessFunction`:

- consume from Kafka source
- call `mw.dispatch(record, handler)` per event
- sink handler output to another Kafka topic

Reasons this is a poor fit:

- **Ownership of checkpointing conflicts.** The Kafka middleware drives `commit_transaction` / `send_offsets_to_transaction` itself. Flink also manages exactly-once via aligned barriers and a two-phase commit sink. Two transaction coordinators on the same stream fight over the same offsets.
- **Per-event ack is coarser than Flink's granularity.** Flink can emit partial results within a checkpoint interval, buffer them, and only materialise on checkpoint commit. The Kafka middleware acks every event as it is processed — so side effects from the handler are committed independently of Flink's checkpoint state.
- **No access to operator state.** Keyed state, windows, CEP patterns, joins — none of that is visible to the middleware. Chio can only evaluate on raw event fields, not on *derived* state like "this user's rolling spend in the last 10 minutes" or "this event is the third retry of a failed upstream task."
- **Backpressure is wrong.** `Slots(max_in_flight)` is a per-middleware semaphore; Flink already has its own credit-based flow control. Two competing backpressure systems produces pathological stalls.

So: the Kafka middleware is usable as a stopgap, but a native integration does strictly more, and the two are not interchangeable.

## What a native Flink integration looks like

The primary shape is an **operator**, not a middleware. Users wrap a Flink stream in a Chio operator, and receipts flow out as a **side output**.

### Operator surface

```
class ChioEvaluateOperator[IN, OUT] extends ProcessFunction[IN, OUT]
    with CheckpointedFunction
```

```
stream
  .process(new ChioEvaluateOperator[Event, Event](config))
  .getSideOutput(RECEIPT_TAG) -> receiptSink       // Kafka / file / whatever
  .getSideOutput(DLQ_TAG)     -> dlqSink
```

Inputs:

- the source stream of domain events
- a `ChioClient` handle (sidecar URL + credentials)
- a Chio `capability_id`, `tool_server`, and scope mapping (topic or key -> `tool_name`)
- an optional keyed path, so evaluation can see keyed state

Outputs:

- **Main output:** the original event on allow, or nothing on deny (user-configurable: drop, pass through annotated, emit deny marker).
- **Side output `RECEIPT_TAG`:** receipt envelopes (same byte format as `receipt.build_envelope`).
- **Side output `DLQ_TAG`:** `DLQRecord` envelopes for denies.

Side outputs are the right primitive because they ride Flink's checkpoint snapshots end-to-end — the receipt is emitted *by* the checkpoint, not alongside it.

### Checkpoint-coupled receipts (the key design choice)

The non-Flink brokers do publish-then-ack, which is not atomic. Duplicates are expected and tolerated via `request_id` dedupe downstream.

Flink can do strictly better:

- Emit the receipt into the side output stream during `processElement`.
- Do NOT flush the receipt sink until `snapshotState()` is called on the checkpoint barrier.
- The receipt sink must be a 2PC sink (Kafka has a native one; for other sinks implement `TwoPhaseCommitSinkFunction`).
- On checkpoint commit: receipts are visible atomically. On replay after failure: the source rewinds, events are re-evaluated, and the previous receipts (which never committed) are discarded by the transactional sink.

Result: **no duplicate receipts and no lost receipts across operator restarts**, as long as the sidecar evaluation is deterministic on the same input (which it is — Chio is a pure evaluation against a known policy hash).

The Kafka middleware's EOS story extends only across `(source topic, DLQ/receipt topic, offset commit)`. A Flink 2PC-sink story extends across *any* sink you plug in, including non-Kafka.

### Window-scoped and keyed evaluation

Because the operator lives inside a Flink dataflow, users can put it after windows, joins, or keyed state:

```
stream
  .keyBy(_.userId)
  .window(TumblingEventTime(minutes=5))
  .aggregate(new SpendAggregator)
  .process(new ChioEvaluateOperator[SpendSummary, Approval](config))
```

The Chio evaluation now runs on *windowed aggregates*, not raw events. This is a genuinely new capability the broker middlewares cannot express.

Open design question: should the operator have a `KeyedChioEvaluateOperator` variant that can consult Flink keyed state in its parameter builder? Probably yes — the plainest use case is "approve this transaction *if* this user hasn't been flagged in the last hour," which needs per-key state.

### Handler semantics

Two deployment modes:

1. **Transform mode:** the operator is purely a gate — allow passes the event through, deny routes to DLQ side output, receipts go to the receipt side output. The "handler" is the downstream operator.
2. **Callback mode:** the user provides a `Function[(IN, ChioReceipt), OUT]` invoked on allow. Matches the Python middleware API more closely. Less idiomatic in Flink since downstream operators usually do the work.

Recommendation: ship transform mode as primary. Callback mode is a thin adapter on top.

## Distribution story

Flink's users split cleanly into two camps:

### PyFlink

- Distributed via `pyproject.toml` extras: `chio-streaming[flink]`
- Provides `chio_streaming.flink.ChioEvaluateFunction` — a `ProcessFunction` callable from PyFlink's Table API or DataStream API.
- Reuses `chio_streaming.core` (`ChioClientLike`, `evaluate_with_chio`, `new_request_id`, `resolve_scope`) verbatim. The operator is a thin wrapper.
- PyFlink runs user functions in a Python worker via Beam's portable runner. The sidecar call is a normal async HTTP; the wrapper bridges Flink's sync function signature to `asyncio.run` on the first call and re-uses the event loop across invocations.

### JVM (Java / Scala / Kotlin)

- Distributed as a new artifact: `com.backbay:chio-streaming-flink` (Maven coordinates TBD).
- Depends on `chio-sdk-java` (not yet written — see gap below).
- Provides the same `ChioEvaluateOperator` surface as a first-class `ProcessFunction` subclass.
- Probably the more serious target: most production Flink runs are JVM.

**Gap:** there is currently no Java SDK for Chio. The JVM Flink story is blocked on a Java port of `chio_sdk.client` (evaluate_tool_call over HTTP, receipt models, error types). Two options:

- Build a minimal `chio-sdk-java` with just the client + models. ~1-2 weeks.
- Ship the Flink integration PyFlink-first; defer JVM to a follow-up milestone.

Recommendation: **PyFlink-first**, defer JVM. Gets value to Python teams using PyFlink without blocking on Java SDK work.

## Wire compatibility

The receipt envelope format (`chio-streaming/v1`) is shared byte-for-byte across brokers. The Flink integration must emit envelopes that are byte-identical to what the Kafka / NATS / etc. middlewares emit, so the same receipt consumer works regardless of source.

Concretely, reuse `chio_streaming.receipt.build_envelope` unchanged from PyFlink. From JVM, port `canonical_json` and `build_envelope` verbatim (small, well-specified).

## Risks

1. **Sidecar RTT inside an operator.** Flink operators are latency-sensitive; a synchronous sidecar call per event bounds throughput to `1 / RTT * parallelism`. Mitigation: Flink's `AsyncDataStream.unorderedWait` / `AsyncFunction` lets the sidecar call be async, so the operator stays non-blocking. The Python middleware already uses async; the Flink wrapper would plug into `AsyncFunction` rather than `ProcessFunction` for the latency-critical path.
2. **Checkpoint size growth.** If we hold receipts in operator state until checkpoint commit, a slow checkpoint backs up unbounded receipts. Mitigation: receipts go straight to the side output (Flink buffers them in the sink), not into operator state. Only the sink needs 2PC semantics.
3. **PyFlink worker startup cost.** PyFlink's Python workers have per-job startup overhead. Negligible for long-running streams; measurable for CI jobs. No mitigation — this is Flink's own constraint.
4. **JVM gap is real.** Without a Java SDK, the Flink integration serves only the PyFlink subset of users, which is not the majority. A separate milestone for `chio-sdk-java` may end up being a prerequisite.

## Scope estimate

PyFlink operator on top of the existing Python SDK:

- `chio_streaming/flink.py` — `ChioEvaluateFunction(ProcessFunction)`, `ChioAsyncEvaluateFunction(AsyncFunction)`, config + side-output tags.
- Tests using a Flink mini-cluster fixture (the PyFlink test utilities). Covers checkpoint commit semantics on both success and failure-replay paths.
- README section + example job.
- `[flink]` extra in `pyproject.toml` pinning `apache-flink >= 1.18`.

Rough size: ~400-600 lines of source, comparable to the Pulsar or Pub/Sub middlewares but with the extra test apparatus for checkpointing.

JVM operator is a separate effort, blocked on `chio-sdk-java`. Estimate once that exists: similar size to the PyFlink side, plus Maven publishing setup.

## Recommendation

Start with PyFlink. Write the operator as a ProcessFunction + AsyncFunction pair so latency-sensitive jobs can opt into the async path. Wire the receipt sink via Flink's native Kafka 2PC sink for the common case; document the `TwoPhaseCommitSinkFunction` contract for other sinks. Defer JVM until there's a `chio-sdk-java`.

Open questions before implementation starts:

1. Transform-mode only, or support callback mode from day one?
2. Keyed-state-aware variant now or in a follow-up?
3. Minimum PyFlink / Flink version? 1.18 has the stable async I/O in Python, 1.17 doesn't.
4. Do we ship an example job (e.g. real-time fraud scoring over a Kafka source) or just the operator + unit tests?

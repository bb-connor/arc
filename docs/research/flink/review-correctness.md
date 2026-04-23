# Flink Integration Review: Correctness + Semantics

## Summary

The Flink integration is largely correct and preserves fail-closed invariants. The narrow-exception regression that hit NATS/Pulsar/Pub/Sub before f36b5e2 does not manifest here because Flink transform mode has no handler - the code path is simpler and exceptions propagate cleanly. Byte-identity with other middlewares is preserved (no re-serialization). I found one P2 semantic drift (envelope `source_topic` is populated with the receipt destination topic rather than the originating subject), one P2 lifecycle bug (async `close()` drops the shutdown task when a loop is already running), one P3 per-element allocation, and a handful of minor documentation issues. Overall: ship-ready after the P2 fixes.

## Findings

### [P2] Envelope `source_topic` is the receipt destination, not the originating subject

`sdks/python/chio-streaming/src/chio_streaming/flink.py:543-547`.

`build_envelope(..., source_topic=self._config.receipt_topic)` passes the receipt topic as `source_topic`. The `source_topic` parameter of `build_envelope` (receipt.py:101-103, receipt.py:129-130) is the *originating* topic / subject - Pulsar uses `msg.topic_name()` (pulsar.py:278) and Pub/Sub uses the resolved `subject` (pubsub.py:295). With the current code, every Flink-emitted envelope will carry the configured `receipt_topic` as its `source_topic`, which breaks audit queries that correlate receipts back to the event source. High confidence: direct contract violation visible in a line-by-line comparison with the other middlewares.

**Fix:** pass the resolved `subject` (already computed on line 508) as `source_topic`, not `self._config.receipt_topic`. The `receipt_topic` is a sink target, not an audit-payload field.

### [P2] `ChioAsyncEvaluateFunction.close()` drops the shutdown task when a loop is running

`sdks/python/chio-streaming/src/chio_streaming/flink.py:662-668`.

```python
if running is not None:
    running.create_task(self._evaluator.shutdown())
    return
```

The created task is scheduled and `close()` returns immediately. In production PyFlink this branch is unlikely (workers drive `close()` synchronously with no running loop), but the code path does exist, is advertised in the docstring as the fallback for "in-process tests / odd runtime shapes," and silently leaks the HTTP connection pool inside `ChioClient`. Medium confidence on hit likelihood, high confidence on severity if hit (resource leak across task restarts).

**Fix:** either remove the running-loop branch and document that `close()` must be called without a running loop, or synchronize on the scheduled task (`running.run_until_complete` is not available from within the same loop; use `asyncio.ensure_future` + `asyncio.gather` or require the caller to `await shutdown()` explicitly).

### [P3] Per-element `OutputTag` construction in `ChioVerdictSplitFunction.process_element`

`sdks/python/chio-streaming/src/chio_streaming/flink.py:701-703` and `712-715`.

```python
def process_element(self, value, ctx):
    receipt_tag = _receipt_tag()
    dlq_tag = _dlq_tag()
```

Each invocation calls `_receipt_tag()` / `_dlq_tag()`, which re-import `pyflink.common.typeinfo.Types` and `pyflink.datastream.OutputTag` and allocate a new tag object. This is per-element. The same pattern is duplicated in `_yield_outcome` for the sync operator. Correctness is fine, but it is a measurable hot-path allocation at high throughput.

**Fix:** lazily cache on `self` in `open()` (the async split function has no `open()` today; add a minimal one) or hoist to module level behind a `_HAVE_PYFLINK` guard.

### [P3] Default `subject_extractor` is a near-guaranteed failure

`sdks/python/chio-streaming/src/chio_streaming/flink.py:312-323`.

The default tries `ctx.topic()`, but PyFlink's `ProcessFunction` / `AsyncFunction` contexts do not expose a `topic()` method. The extractor will return `""` in all realistic cases, and `resolve_scope` then raises `ChioStreamingConfigError`. That is the fail-closed outcome (good), and it is documented in the config docstring (line 175-178), but the "try `ctx.topic()`" lookup is dead code that misleads readers into thinking a default will work. Low severity (doc/clarity), but worth tightening.

**Fix:** drop the `ctx.topic()` probe and make the default extractor raise a clearer `ChioStreamingConfigError("subject_extractor is required for Flink sources")` at first use, or at config validation in `__post_init__`.

### [P3] `_default_subject_extractor` swallows `ctx.topic()` exceptions broadly

`sdks/python/chio-streaming/src/chio_streaming/flink.py:318-321`.

`except Exception: return ""` is a catch-all. Combined with the above, if PyFlink ever does expose `topic()` and it raises a real error, the middleware silently falls through to an empty subject which then fails closed via `resolve_scope`. Net effect is fine (fail-closed) but diagnostic signal is lost. Same fix as the previous finding - drop the probe.

### [P3] `parameters_extractor` bypasses `body_length` / `body_hash` when a custom extractor is supplied

`sdks/python/chio-streaming/src/chio_streaming/flink.py:475-481`.

`_parameters_for` calls `extractor(element)` and then only `setdefault`s `request_id` and `subject`. It does *not* merge in `body_length` / `body_hash`. Other middlewares always populate these (pulsar.py:374-381, pubsub via parameters dict). A user who overrides the extractor loses the body hash from the Chio evaluation input, which weakens replay determinism (a fail-closed-adjacent invariant). This is consistent with the documented `(element) -> dict` contract but worth flagging.

**Fix:** either document "custom extractors must include `body_length` / `body_hash`" more prominently, or merge the defaults under `setdefault` the same way `request_id` and `subject` are merged.

## Non-findings (things I checked and confirmed correct)

- **Sidecar error routing honors `on_sidecar_error`.** flink.py:528-539 re-raises `ChioStreamingError` unless `on_sidecar_error="deny"`, matching pulsar/pubsub/nats. Under `"raise"`, propagation lets the Flink task fail and the source rewinds.
- **Synthesized deny carries `SYNTHETIC_RECEIPT_MARKER` structurally.** `synthesize_deny_receipt` in core.py:154-157 sets `chio_streaming_synthetic_marker` in metadata, `signature=""` / `kernel_key=""`, and prefixes the reason with `[unsigned]`. Flink uses the shared builder unchanged.
- **Deny path always emits DLQ bytes.** flink.py:550-571 builds the DLQ record inside the sole branch guarded by `receipt.is_denied`, and the outcome / `EvaluationResult` carries `dlq_bytes=dlq_record.value`. `ChioVerdictSplitFunction` always yields `(dlq_tag, dlq_bytes)` when present. Side-output emit failures propagate (no `except` wrapping `yield`).
- **Narrow exception scope.** `except ChioStreamingError` wraps only `evaluate_with_chio` (flink.py:516-539). `build_envelope`, `dlq_router.build_record`, and `ctx.output`/`yield` are all outside the catch. The trap f36b5e2 fixed in the other middlewares is absent here.
- **Byte-identical envelopes and DLQ records.** `receipt_bytes = envelope.value` (flink.py:548) and `dlq_bytes = dlq_record.value` (flink.py:569) are direct assignments. No re-canonicalization, no mutation. `ENVELOPE_VERSION`, `RECEIPT_HEADER`, `VERDICT_HEADER` are preserved via the shared `build_envelope`.
- **`async_invoke` return shape.** flink.py:675-684 returns `list[EvaluationResult]` of length 1. Well-formed. Empty-return is not a reachable path (every code branch constructs the single item).
- **Allow + `receipt_topic=None` splitter behavior.** flink.py:704-709 skips RECEIPT_TAG when `receipt_bytes is None`, which matches `build_envelope` being gated on `receipt_topic is not None` (flink.py:541-548). Consistent with pulsar/pubsub.
- **Deny path in splitter.** `if value.allowed: yield value.element` (flink.py:704-705) correctly suppresses main emission on deny; receipt + DLQ tags still flow.
- **Factory lifecycle.** `bind()` (flink.py:438-454) is called from `open()` once per subtask; client and router are cached on `self`; `shutdown()` closes the client.
- **Event loop reuse in sync operator.** `ChioEvaluateFunction.open()` creates `self._loop = asyncio.new_event_loop()` once and `process_element` reuses it via `self._loop.run_until_complete(...)` (flink.py:610-628).
- **Request-id prefix.** `new_request_id(self._config.request_id_prefix)` (flink.py:507) with default `"chio-flink"`. Matches the `chio-pulsar`/`chio-pubsub`/`chio-nats` convention.
- **DLQ `build_record` contract.** `include_original_value` defaults to True; flink passes `original_value=_canonical_body_bytes(element)` so the DLQ envelope always carries a redriveable body. Consistent with pulsar/pubsub.
- **Slots semaphore.** `Slots.acquire()` is called before evaluation (flink.py:495) and released in `finally` (flink.py:498). Reuses the shared lazy-bind implementation from core.py.
- **PyFlink optional import guard.** The `_HAVE_PYFLINK` fallback + `_require_pyflink` at each constructor gives a clean error when the `[flink]` extra is missing, without breaking `import chio_streaming.flink` in test envs.
- **Sync operator emits receipt + DLQ via generator.** `_yield_outcome` (flink.py:712-721) mirrors the split function exactly, keeping sync and async paths byte-equivalent.

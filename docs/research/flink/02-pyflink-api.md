# PyFlink API for the Chio Evaluate Operator

Research notes for `chio-streaming[flink]`. Target: a `ChioEvaluateFunction` that evaluates each event via the Chio sidecar, emits the original event on allow, receipts to a side output, and denies to a DLQ side output.

Versions referenced: Flink 2.2.0 is the current stable (released December 2025). AsyncFunction for the Python DataStream API was completed via FLINK-38560 / 38561 / 38563 / 38591 and shipped as part of 2.2.0. PyFlink 1.18 is the oldest release with stable ProcessFunction side outputs and the new Kafka source/sink builders.

## Answers

### 1. ProcessFunction and side outputs

Available since PyFlink 1.16 and stable from 1.18. The Python subclass overrides `process_element(self, value, ctx)` and uses `yield` to emit. Side outputs are emitted by yielding a `(OutputTag, value)` pair rather than calling `ctx.output(tag, value)` - the generator pattern is the PyFlink idiom, unlike the Java `Collector.collect` / `ctx.output` split.

`OutputTag` lives at `pyflink.datastream.output_tag.OutputTag` and takes a name plus an explicit `TypeInformation`:

```python
from pyflink.datastream import ProcessFunction, OutputTag
from pyflink.common.typeinfo import Types

RECEIPT_TAG = OutputTag("chio-receipt", Types.PICKLED_BYTE_ARRAY())
DLQ_TAG     = OutputTag("chio-dlq",     Types.PICKLED_BYTE_ARRAY())

class MyFn(ProcessFunction):
    def process_element(self, value, ctx):
        yield value                             # main output
        yield RECEIPT_TAG, receipt_envelope     # side output
```

Retrieving: `main = ds.process(MyFn()); receipts = main.get_side_output(RECEIPT_TAG)`. Returns a normal `DataStream`.

### 2. AsyncFunction

Shipped in Flink 2.2.0 for PyFlink (FLIP-equivalent work under FLINK-38560..38591). Python subclasses `pyflink.datastream.AsyncFunction` and implements a **real coroutine** `async_invoke`:

```python
from pyflink.datastream import AsyncDataStream, AsyncFunction, AsyncRetryStrategy, async_retry_predicates
from pyflink.common.time import Time

class Fn(AsyncFunction):
    def open(self, runtime_context): ...
    def close(self): ...
    async def async_invoke(self, value) -> list:
        # may do:  result = await aiohttp_session.post(...)
        return [result]
```

The function returns a `list` - multiple results per input are fan-out; `return []` on timeout means "drop." Apache's shipping example at `flink-python/pyflink/examples/datastream/asyncio/remote_model_inference.py` uses `await asyncio.sleep(...)` inside `async_invoke`; `aiohttp` (or any asyncio HTTP client) works identically because PyFlink runs the coroutine on a managed event loop per Python worker.

Dispatch:

```python
AsyncDataStream.unordered_wait_with_retry(
    data_stream=ds,
    async_function=Fn(),
    timeout=Time.seconds(10),
    async_retry_strategy=AsyncRetryStrategy.fixed_delay_retry(3, 500, async_retry_predicates.EMPTY_RESULT_PREDICATE),
    capacity=1000,
    output_type=Types.STRING(),
)
```

`unordered_wait` (no retry) drops `async_retry_strategy`. `capacity` = per-instance in-flight ceiling, analogous to the NATS/Pulsar middleware `max_in_flight`.

Side outputs from `AsyncFunction` are **not** supported - async operators only emit to main. Material limitation: the async path must be followed by a `ProcessFunction` that splits by verdict into receipt/DLQ tags.

### 3. Keyed state

`KeyedProcessFunction` (Python) supports `ValueState`, `ListState`, `MapState`, `ReducingState`, `AggregatingState`. State is accessed in `open()` via `RuntimeContext.get_state(ValueStateDescriptor(...))` / `get_map_state(MapStateDescriptor(...))` / etc. TTL is configured per-descriptor:

```python
from pyflink.datastream import KeyedProcessFunction, RuntimeContext
from pyflink.datastream.state import ValueStateDescriptor, StateTtlConfig
from pyflink.common.time import Duration

class Fn(KeyedProcessFunction):
    def open(self, ctx: RuntimeContext):
        ttl = (StateTtlConfig.new_builder(Duration.ofMinutes(10))
               .set_update_type(StateTtlConfig.UpdateType.OnCreateAndWrite)
               .set_state_visibility(StateTtlConfig.StateVisibility.NeverReturnExpired)
               .build())
        desc = ValueStateDescriptor("last_seen", Types.STRING())
        desc.enable_time_to_live(ttl)
        self.last = ctx.get_state(desc)
```

Supported since FLIP-153 (Flink 1.12 for basic, 1.13 for TTL); stable path for all state types is 1.16+.

### 4. Kafka source / sink with EOS

DataStream `KafkaSource` + `KafkaSink` is the idiomatic PyFlink path (Table API works but hides the side-output shape we need). Both live at `pyflink.datastream.connectors.kafka`. Exactly-once requires:

- `env.enable_checkpointing(interval_ms)` and a persistent state backend for production (JobManager memory is the unsafe default).
- `KafkaSink.builder()....set_delivery_guarantee(DeliveryGuarantee.EXACTLY_ONCE).set_transactional_id_prefix("chio-receipt-")`.
- Kafka broker `transaction.max.timeout.ms` at least as large as the checkpoint interval plus commit latency.

```python
from pyflink.datastream.connectors.kafka import (
    KafkaSource, KafkaSink, KafkaRecordSerializationSchema,
    KafkaOffsetsInitializer, DeliveryGuarantee,
)

source = (KafkaSource.builder()
          .set_bootstrap_servers("broker:9092")
          .set_topics("events")
          .set_group_id("chio")
          .set_starting_offsets(KafkaOffsetsInitializer.committed_offsets())
          .set_value_only_deserializer(SimpleStringSchema())
          .build())

sink = (KafkaSink.builder()
        .set_bootstrap_servers("broker:9092")
        .set_record_serializer(KafkaRecordSerializationSchema.builder()
            .set_topic("chio-receipts")
            .set_value_serialization_schema(SimpleStringSchema()).build())
        .set_delivery_guarantee(DeliveryGuarantee.EXACTLY_ONCE)
        .set_transactional_id_prefix("chio-receipt-")
        .build())
```

`KafkaSink` is the native 2PC sink (`TwoPhaseCommitSinkFunction` under the hood). Receipts go through it directly - we do not need to implement our own 2PC.

### 5. Dependency management

PyFlink runs user Python in worker processes under Beam's portable runner. Three hooks on `StreamExecutionEnvironment`:

- `add_python_file(path)` - single `.py`, package directory, or `.zip`; prepended to `PYTHONPATH`. Right for our own source.
- `set_python_requirements(requirements_txt, cache_dir=None)` - `pip install -r` is run on workers at startup. `cache_dir` (pre-downloaded wheels) is required for offline/restricted clusters.
- `add_python_archive(archive_path, target_dir=None)` plus `set_python_executable("venv/bin/python")` - ships a zipped virtualenv and points workers at it. This is the only approach that handles C extensions reliably across heterogeneous worker images.

Recommended layering for `chio-streaming[flink]`: `add_python_file()` for the chio source, `set_python_requirements()` for `aiohttp`, `chio-sdk`, transport deps. Air-gapped clusters or C-extension pain fall back to the virtualenv archive.

### 6. Testing

`pyflink.testing.test_case_utils.PyFlinkStreamingTestCase` is the right base class. It spins up a `MiniClusterWithClientResource` (2 task slots, parallelism 2, streaming mode) and exposes `self.env: StreamExecutionEnvironment`. Results are harvested via `DataStreamTestSinkFunction()` (same module), added as a sink, and read with `get_results(False)` after `self.env.execute()`.

Flink's standalone `ProcessFunctionTestHarnesses` is Java-only - no Python binding. Realistic unit tests for our operator sit on top of `PyFlinkStreamingTestCase`, with the Chio sidecar mocked at the `ChioClientLike` protocol boundary (same shape the existing middleware tests use). Reference: `apache/flink` master `flink-python/pyflink/datastream/tests/test_async_function.py`.

### 7. Versioning

- Flink stable: **2.2.0** (Dec 2025).
- Minimum version we need: **2.2.0** if we want `AsyncFunction` in PyFlink. If we ship a sync-only first cut, **1.18** suffices (stable `ProcessFunction` + `OutputTag` + new Kafka connectors + `DeliveryGuarantee.EXACTLY_ONCE`).
- Python: PyFlink 1.18 supports CPython 3.8-3.11; PyFlink 2.x tracks 3.9-3.12. Our `chio-streaming` package already requires 3.11, so we are compatible.

Recommendation: pin `apache-flink >= 2.2` in the `[flink]` extra. A fallback `[flink-sync]` extra at `>= 1.18` is cheap to keep if an async-incapable deployment exists.

## API sketch

```python
# chio_streaming/flink.py  (sketch, not production)

from pyflink.common.time import Time
from pyflink.common.typeinfo import Types
from pyflink.datastream import (
    AsyncDataStream, AsyncFunction, ProcessFunction, RuntimeContext, OutputTag,
)

from chio_streaming.core import (
    ChioClientLike, evaluate_with_chio, new_request_id, resolve_scope,
    synthesize_deny_receipt,
)
from chio_streaming.dlq import DLQRouter
from chio_streaming.receipt import build_envelope

RECEIPT_TAG = OutputTag("chio-receipt", Types.PICKLED_BYTE_ARRAY())
DLQ_TAG     = OutputTag("chio-dlq",     Types.PICKLED_BYTE_ARRAY())


class ChioEvaluateFunction(ProcessFunction):
    """Synchronous path. Latency ~= sidecar RTT.

    For high-throughput jobs use ChioAsyncEvaluateFunction followed by
    ChioVerdictSplitFunction, because AsyncFunction cannot emit side outputs.
    """

    def __init__(self, *, client_factory, config, dlq_router):
        self._client_factory = client_factory
        self._config = config
        self._dlq_router = dlq_router

    def open(self, ctx: RuntimeContext):
        self._client: ChioClientLike = self._client_factory()
        # one asyncio loop per worker; reuse across process_element calls
        import asyncio
        self._loop = asyncio.new_event_loop()

    def close(self):
        self._loop.close()

    def process_element(self, value, ctx):
        request_id = new_request_id("chio-flink")
        topic = ctx.metadata().get("topic", "") if hasattr(ctx, "metadata") else ""
        tool_name = resolve_scope(scope_map=self._config.scope_map, subject=topic)
        params = {"request_id": request_id, "topic": topic, "body_hash": hash_body(value)}

        try:
            receipt = self._loop.run_until_complete(evaluate_with_chio(
                chio_client=self._client,
                capability_id=self._config.capability_id,
                tool_server=self._config.tool_server,
                tool_name=tool_name,
                parameters=params,
                failure_context={"topic": topic, "request_id": request_id},
            ))
        except ChioStreamingError:
            if self._config.on_sidecar_error != "deny":
                raise
            receipt = synthesize_deny_receipt(...)  # fail-closed

        envelope = build_envelope(request_id=request_id, receipt=receipt, source_topic=topic)
        yield RECEIPT_TAG, envelope

        if receipt.is_denied:
            record = self._dlq_router.build_record(
                source_topic=topic, ..., request_id=request_id, receipt=receipt,
            )
            yield DLQ_TAG, record
            return  # do not emit to main

        yield value  # allow: pass-through


# Usage
main = ds.process(ChioEvaluateFunction(...))
receipts = main.get_side_output(RECEIPT_TAG)
dlq     = main.get_side_output(DLQ_TAG)

receipts.sink_to(kafka_receipt_sink_eos)
dlq.sink_to(kafka_dlq_sink_eos)
main.sink_to(downstream_sink)
```

Async variant (sketch):

```python
class ChioAsyncEvaluateFunction(AsyncFunction):
    async def async_invoke(self, value) -> list:
        receipt = await evaluate_with_chio(...)   # real coroutine
        envelope = build_envelope(...)
        # tuple shape: (verdict, original, envelope, dlq_or_none)
        return [("allow" if not receipt.is_denied else "deny", value, envelope, dlq)]

evaluated = AsyncDataStream.unordered_wait(
    ds, ChioAsyncEvaluateFunction(), Time.seconds(5), capacity=256,
    output_type=Types.PICKLED_BYTE_ARRAY(),
)
# split verdicts into main/receipt/dlq via a subsequent ProcessFunction
main = evaluated.process(ChioVerdictSplitFunction())
```

## Packaging recommendation

Ship `chio-streaming[flink]` as a normal Python package. At runtime users call:

```python
env.add_python_file("/path/to/chio_streaming_pkg_or_zip")
env.set_python_requirements("/path/to/requirements.txt")  # aiohttp, chio-sdk, ...
```

Provide a helper `chio_streaming.flink.register_dependencies(env, *, requirements_path=None)` that wraps those two calls so users do not have to remember the incantation. Document the `add_python_archive` + `set_python_executable` virtualenv route as the fallback for C-extension-hostile worker images.

Do **not** try to bundle `chio-streaming` as a fat wheel or vendored zip - `set_python_requirements` resolves `chio-streaming[flink]` transitively on workers and is the path of least surprise for users already managing Python workers.

## Remaining uncertainty

1. **Async + side outputs interaction.** PyFlink `AsyncFunction` emits only to the main stream. The cleanest shape is `AsyncFunction -> ProcessFunction(split by verdict) -> side outputs`. Confirm there is no 2.2 addition that lets async functions yield tagged outputs directly; if not, the two-operator shape is canonical.
2. **Checkpoint-coupled receipts.** The design doc promises "no duplicate receipts" via Flink's 2PC sink commit. `KafkaSink` with `DeliveryGuarantee.EXACTLY_ONCE` delivers this for Kafka receipt sinks. For non-Kafka sinks (HTTP receipt store, etc.), users must provide their own `TwoPhaseCommitSinkFunction` - there is **no** Python base class for 2PC sinks, only Java. This is a real limitation to document.
3. **Event loop lifecycle in workers.** Reusing a single `asyncio` loop across `process_element` calls is the obvious optimization but interacts subtly with PyFlink's per-operator lifecycle (open/close per task). Verify on a mini-cluster that closing the loop on `close()` is sufficient and that loop state does not leak across checkpoints.
4. **Flink 2.2 ecosystem churn.** Connectors are released on their own cadence now (post-1.17 split). Confirm `flink-connector-kafka` has a 2.2-compatible Python-wheel release before pinning 2.2 as the floor. If not, we may be stuck at 1.18 for a window.
5. **Parallelism vs sidecar.** `capacity=N` bounds per-task in-flight. Total in-flight against the sidecar is `N * parallelism`. Document sizing guidance so teams do not accidentally DoS their own sidecar.

Sources:
- [Side Outputs (Flink docs)](https://nightlies.apache.org/flink/flink-docs-master/docs/dev/datastream/side_output/)
- [PyFlink sideoutput reference](https://nightlies.apache.org/flink/flink-docs-master/api/python/reference/pyflink.datastream/sideoutput.html)
- [Async I/O (Flink docs)](https://nightlies.apache.org/flink/flink-docs-master/docs/dev/datastream/operators/asyncio/)
- [Flink master `asyncio/remote_model_inference.py`](https://github.com/apache/flink/blob/master/flink-python/pyflink/examples/datastream/asyncio/remote_model_inference.py)
- [Working with State](https://nightlies.apache.org/flink/flink-docs-master/docs/dev/datastream/fault-tolerance/state/)
- [FLIP-153 keyed state in Python](https://cwiki.apache.org/confluence/display/FLINK/FLIP-153:+Support+state+access+in+Python+DataStream+API)
- [KafkaSink Python reference](https://nightlies.apache.org/flink/flink-docs-stable/api/python/reference/pyflink.datastream/api/pyflink.datastream.connectors.kafka.KafkaSinkBuilder.html)
- [Dependency Management](https://nightlies.apache.org/flink/flink-docs-stable/docs/dev/python/dependency_management/)
- [`test_case_utils.py`](https://github.com/apache/flink/blob/master/flink-python/pyflink/testing/test_case_utils.py)
- [Flink 2.2.0 release announcement](https://flink.apache.org/2025/12/04/apache-flink-2.2.0-advancing-real-time-data--ai-and-empowering-stream-processing-for-the-ai-era/)
- [`test_async_function.py`](https://github.com/apache/flink/blob/master/flink-python/pyflink/datastream/tests/test_async_function.py)

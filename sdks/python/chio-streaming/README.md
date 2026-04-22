# chio-streaming

Kafka consumer middleware for the [Chio protocol](../../../spec/PROTOCOL.md).
Wraps `confluent-kafka` so every consumed event is evaluated through the
Chio sidecar before the application handler runs. Denied events are
routed to a dead-letter queue (DLQ) with a denial receipt attached, and
the DLQ publish commits transactionally together with the consumer
offset so either both become visible or both roll back.

## Install

```bash
uv pip install chio-streaming
# or
pip install chio-streaming
```

The package depends on `chio-sdk-python`, `confluent-kafka>=2.4,<3`, and
`pydantic>=2.5`.

### Kafka library choice

`chio-streaming` targets **`confluent-kafka`** (the
`librdkafka`-based client). This is the only mainstream Python Kafka
client with a fully-featured transactional producer (EOS v2), which is
what the middleware relies on for atomic offset-commit + DLQ publish.
`aiokafka` does expose transactional APIs but its EOS support is still
evolving and does not yet cover all of the `send_offsets_to_transaction`
semantics we need.

The middleware accepts duck-typed consumers / producers (via the
`KafkaConsumerLike`, `KafkaProducerLike`, `KafkaMessageLike`
protocols), so drop-in adapters for `aiokafka` or test doubles work
without modifying the SDK.

## Quickstart

```python
import asyncio

from chio_sdk.client import ChioClient
from chio_streaming import (
    ChioConsumerConfig,
    ChioConsumerMiddleware,
    DLQRouter,
)
from confluent_kafka import Consumer, Producer


def build_consumer() -> Consumer:
    return Consumer(
        {
            "bootstrap.servers": "localhost:9092",
            "group.id": "research-agents",
            "enable.auto.commit": False,
            "isolation.level": "read_committed",
        }
    )


def build_producer() -> Producer:
    producer = Producer(
        {
            "bootstrap.servers": "localhost:9092",
            "transactional.id": "research-agents-tx",
            "enable.idempotence": True,
        }
    )
    producer.init_transactions()
    return producer


async def run() -> None:
    consumer = build_consumer()
    producer = build_producer()
    consumer.subscribe(["research-tasks"])

    async with ChioClient("http://127.0.0.1:9090") as chio:
        middleware = ChioConsumerMiddleware(
            consumer=consumer,
            producer=producer,
            chio_client=chio,
            dlq_router=DLQRouter(default_topic="chio-denied-events"),
            config=ChioConsumerConfig(
                capability_id="cap-research-agents",
                tool_server="kafka://prod",
                scope_map={
                    "research-tasks": "events:consume:research-tasks",
                },
                receipt_topic="chio-receipts",
                transactional=True,
                max_in_flight=32,
                consumer_group_id="research-agents",
            ),
        )

        async def handle(msg, receipt):
            # msg is a confluent-kafka Message; receipt is the signed
            # Chio receipt. Tool calls from here are separately
            # Chio-evaluated via chio-sdk-python.
            ...

        while True:
            outcome = await middleware.poll_and_process(handle)
            if outcome is None:
                continue
            # Optional: surface metrics based on outcome.allowed /
            # outcome.committed.


asyncio.run(run())
```

## How it works

1. `poll_and_process` polls one message from the underlying
   `confluent-kafka` consumer.
2. The middleware calls
   `ChioClient.evaluate_tool_call(capability_id, tool_server, tool_name,
   parameters)` where `tool_name` is resolved from
   `config.scope_map[topic]` (falls back to `events:consume:<topic>`)
   and `parameters` carries message metadata (topic, partition,
   offset, headers, body hash, body length). The raw body is **not**
   forwarded to the sidecar by default; guards that need to pin the
   specific payload can re-hash from the producer or use the
   `body_hash`.
3. **Allow verdict** -- the application handler runs; on success the
   middleware produces a receipt envelope to `config.receipt_topic`
   and sends the consumer offset inside the Kafka transaction, then
   `commit_transaction`.
4. **Deny verdict** -- the `DLQRouter` builds a denial envelope (with
   the receipt id, guard, reason, originating topic/partition/offset,
   and -- optionally -- the original value). The envelope is produced
   to the routed DLQ topic inside the Kafka transaction, the offset
   is sent inside the same transaction, and `commit_transaction` makes
   both visible atomically.
5. **Handler error or broker failure** -- the middleware calls
   `abort_transaction`. Neither the offset nor the produced record is
   visible downstream, and Kafka redelivers the event.

## Transactional semantics

`chio-streaming` uses Kafka's transactional producer (EOS v2). A single
transaction wraps the relevant produces together with
`send_offsets_to_transaction`.

### Atomic

- **Allow**: offset commit + receipt publish become visible together
  or not at all.
- **Deny**: offset commit + DLQ publish become visible together or not
  at all.
- **Handler error**: both the staged produce and the offset are
  rolled back; Kafka redelivers the event.
- **Broker failure during commit**: offsets and produced records are
  both rolled back.

### NOT atomic

- **External side-effects inside your handler** (HTTP, DB writes, ...).
  Kafka transactions only cover Kafka state. Use the outbox pattern if
  the handler needs at-most-once external effects.
- **DLQ on a different cluster**. A Kafka transaction is
  cluster-scoped. Keep the DLQ on the same cluster as the source topic
  for end-to-end exactly-once.
- **Sidecar calls**. The Chio sidecar evaluation is a local RPC; the
  receipt the sidecar persists server-side is on its own durability
  track. If the transaction aborts, the sidecar may still have the
  receipt recorded with a verdict whose effects were rolled back
  locally; the receipt envelope published to the receipt topic only
  appears on successful commit.

### Non-transactional mode

Set `config.transactional=False` to degrade to best-effort at-least-once
semantics. In this mode the middleware produces the receipt / DLQ
record outside any transaction and then calls
`Consumer.commit(message)` directly. Use this only when you cannot
provision a transactional producer (for example on brokers without EOS
support) and accept that a crash between the produce and commit can
result in a duplicate.

## Backpressure

`config.max_in_flight` caps the number of concurrent outstanding
evaluations. When the limit is reached, `poll_and_process` blocks on a
threading condition until a previous evaluation releases its slot.
This prevents the middleware from stampeding the sidecar on bursty
topics.

## Testing

All core paths exercise an in-process fake broker:

- allow path runs the handler and commits the offset transactionally
  alongside the receipt publish,
- deny path routes the denial envelope to the DLQ and commits the
  offset transactionally,
- a simulated commit-side failure rolls back both the DLQ publish and
  the offset,
- `max_in_flight=1` enforces backpressure across concurrent
  invocations.

See `tests/test_middleware.py` and `tests/test_dlq_router.py`.

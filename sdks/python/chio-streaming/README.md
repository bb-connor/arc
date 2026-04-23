# chio-streaming

Chio protocol middleware for every mainstream event bus.

| Broker | Module | Consumer wire | Allow side effect | Deny side effect |
|---|---|---|---|---|
| Kafka | `chio_streaming` (top-level) | `confluent-kafka` | receipt produce + offset commit (transactional, EOS v2) | DLQ produce + offset commit (same transaction) |
| NATS JetStream | `chio_streaming.nats` | `nats-py` | `js.publish(receipt_subject, ...)` + `msg.ack()` | `js.publish(dlq_subject, ...)` + `msg.ack()` (or `term`) |
| Apache Pulsar | `chio_streaming.pulsar` | `pulsar-client` (sync or async) | receipt producer `send` + `consumer.acknowledge` | DLQ producer `send` + `consumer.acknowledge` |
| AWS EventBridge | `chio_streaming.eventbridge` | Lambda target | `events.put_events(receipt_bus, ...)` | `events.put_events(dlq_bus, ...)` |
| Google Cloud Pub/Sub | `chio_streaming.pubsub` | `google-cloud-pubsub` | `publisher.publish(receipt_topic, ...)` + `message.ack()` | `publisher.publish(dlq_topic, ...)` + `message.ack()` (or `nack`) |
| Redis Streams | `chio_streaming.redis_streams` | `redis.asyncio` | `XADD receipt_stream ...` + `XACK` | `XADD dlq_stream ...` + `XACK` (or keep in PEL) |

Every middleware shares the same evaluation pipeline: call the Chio
sidecar with ``(capability_id, tool_server, tool_name, parameters)``,
and route the outcome to the allow or deny path. The only differences
are the broker's native ack / ordering semantics and what "publish"
means to that broker.

## Install

```bash
# core only (Kafka middleware compiles but confluent-kafka is not installed)
pip install chio-streaming

# pick your brokers
pip install "chio-streaming[kafka]"
pip install "chio-streaming[nats]"
pip install "chio-streaming[pulsar]"
pip install "chio-streaming[eventbridge]"
pip install "chio-streaming[pubsub]"
pip install "chio-streaming[redis]"

# everything
pip install "chio-streaming[all]"
```

## Shared primitives

All broker modules build on a handful of primitives in
`chio_streaming.core`:

- `ChioClientLike` -- the async sidecar protocol every middleware
  speaks.
- `DLQRouter` -- picks the DLQ topic / subject / stream per source and
  builds the canonical denial envelope. Same class on every broker.
- `ReceiptEnvelope` / `build_envelope` -- canonical JSON receipt
  envelope produced on allow. Same wire format everywhere.
- `Slots` -- lazy asyncio semaphore used by every middleware to cap
  in-flight evaluations and protect the sidecar from bursty topics.

You rarely need these directly; they show up in the middleware
constructors.

## Kafka

Kafka is the only broker with native EOS, so it gets a dedicated
transactional path. Offset commit + receipt publish (allow) or offset
commit + DLQ publish (deny) become visible together or not at all.

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
                scope_map={"research-tasks": "events:consume:research-tasks"},
                receipt_topic="chio-receipts",
                transactional=True,
                max_in_flight=32,
                consumer_group_id="research-agents",
            ),
        )

        async def handle(msg, receipt):
            ...

        while True:
            await middleware.poll_and_process(handle)


asyncio.run(run())
```

Transactional semantics (atomic):

- **Allow**: offset commit + receipt publish visible together or not at all.
- **Deny**: offset commit + DLQ publish visible together or not at all.
- **Handler error / broker failure**: both rolled back; Kafka redelivers.

Not atomic:

- External side-effects inside your handler (HTTP, DB writes). Use an
  outbox.
- DLQ on a different cluster. Keep the DLQ co-located.
- Sidecar RPC. If the transaction aborts, the sidecar may still have a
  receipt recorded; the receipt *envelope* only appears on commit.

Set `config.transactional=False` to degrade to best-effort
at-least-once when brokers without EOS are involved.

## NATS JetStream

```python
from chio_streaming.nats import (
    ChioNatsConsumerConfig,
    build_nats_middleware,
)
from chio_streaming.dlq import DLQRouter
import nats

nc = await nats.connect("nats://localhost:4222")
js = nc.jetstream()

mw = build_nats_middleware(
    publisher=js,
    chio_client=chio,
    dlq_router=DLQRouter(default_topic="chio.dlq"),
    config=ChioNatsConsumerConfig(
        capability_id="cap-research",
        tool_server="nats://prod",
        scope_map={"tasks.research": "events:consume:tasks.research"},
        receipt_subject="chio.receipts",
    ),
)

sub = await js.pull_subscribe("tasks.research", durable="research-agent")

async def handler(msg, receipt):
    ...

while True:
    msgs = await sub.fetch(32, timeout=1.0)
    for msg in msgs:
        await mw.dispatch(msg, handler)
```

- `receipt_subject` receives the allow envelope.
- Deny XACKs (or terms, if configured) after the DLQ publish so the
  source stream does not redeliver.
- Handler errors `nak` (or `term`) to trigger JetStream redelivery.

## Apache Pulsar

```python
from chio_streaming.pulsar import (
    ChioPulsarConsumerConfig,
    build_pulsar_middleware,
)
import pulsar

client = pulsar.Client("pulsar://localhost:6650")
consumer = client.subscribe(
    "persistent://public/default/orders",
    subscription_name="order-agents",
)
receipt_producer = client.create_producer(
    "persistent://public/default/chio-receipts"
)
dlq_producer = client.create_producer(
    "persistent://public/default/chio-dlq"
)

mw = build_pulsar_middleware(
    consumer=consumer,
    receipt_producer=receipt_producer,
    dlq_producer=dlq_producer,
    chio_client=chio,
    dlq_topic="persistent://public/default/chio-dlq",
    config=ChioPulsarConsumerConfig(
        capability_id="cap-orders",
        tool_server="pulsar://prod",
        scope_map={
            "persistent://public/default/orders": "events:consume:orders",
        },
        receipt_topic="persistent://public/default/chio-receipts",
    ),
)

async def handler(msg, receipt):
    ...

while True:
    msg = consumer.receive()
    await mw.dispatch(msg, handler)
```

- Works with both the sync `pulsar-client` API and the async wrapper:
  the middleware awaits whichever shape the consumer / producer
  returns.
- Deny publishes to the Chio DLQ topic and acknowledges so Pulsar's
  native DLQ policy is not also triggered.

## AWS EventBridge

```python
import asyncio
import boto3
from chio_streaming.eventbridge import (
    ChioEventBridgeConfig,
    build_eventbridge_handler,
)

events_client = boto3.client("events")

handler = build_eventbridge_handler(
    chio_client=chio,
    events_client=events_client,
    config=ChioEventBridgeConfig(
        capability_id="cap-lambda",
        tool_server="aws:events://prod",
        scope_map={"OrderPlaced": "events:consume:OrderPlaced"},
        receipt_bus="chio-receipt-bus",
        dlq_bus="chio-dlq-bus",
    ),
)


async def process(event, receipt):
    ...


def lambda_handler(event, context):
    outcome = asyncio.run(handler.evaluate(event, handler=process))
    return outcome.lambda_response()
```

- `on_sidecar_error="deny"` fails closed so EventBridge does not retry
  while the sidecar is down (useful for targets behind circuit
  breakers).
- Denials are put on the DLQ bus with the canonical Chio denial
  envelope; the Lambda response carries `{statusCode: 403, reason, guard}`.

## Google Cloud Pub/Sub

```python
import asyncio
from google.cloud import pubsub_v1
from chio_streaming.pubsub import (
    ChioPubSubConfig,
    build_pubsub_middleware,
)

subscriber = pubsub_v1.SubscriberClient()
publisher = pubsub_v1.PublisherClient()

mw = build_pubsub_middleware(
    publisher=publisher,
    chio_client=chio,
    config=ChioPubSubConfig(
        capability_id="cap-agents",
        tool_server="gcp:pubsub://prod",
        subscription="projects/my-project/subscriptions/agent-tasks",
        receipt_topic="projects/my-project/topics/chio-receipts",
        dlq_topic="projects/my-project/topics/chio-dlq",
    ),
)


async def process(msg, receipt):
    ...


def callback(msg):
    asyncio.run(mw.dispatch(msg, handler=process))


future = subscriber.subscribe(
    "projects/my-project/subscriptions/agent-tasks",
    callback=callback,
)
future.result()
```

- Scope resolution order: `X-Chio-Subject` attribute, `subject`
  attribute, subscription name.
- Deny `ack`s by default so the subscription's native dead-letter
  policy is not also triggered. Set `deny_strategy="nack"` to
  delegate to the native DLQ instead.

## Redis Streams

```python
import asyncio
import redis.asyncio as redis
from chio_streaming.redis_streams import (
    ChioRedisStreamsConfig,
    build_redis_streams_middleware,
)

r = redis.Redis.from_url("redis://localhost:6379")

mw = build_redis_streams_middleware(
    client=r,
    chio_client=chio,
    config=ChioRedisStreamsConfig(
        capability_id="cap-agents",
        tool_server="redis://prod",
        group_name="agent-swarm",
        scope_map={"tasks": "events:consume:tasks"},
        receipt_stream="chio-receipts",
        receipt_maxlen=1_000_000,
        dlq_maxlen=1_000_000,
    ),
    dlq_stream="chio-dlq",
)

await r.xgroup_create("tasks", "agent-swarm", id="0", mkstream=True)

async def handler(entry, receipt):
    ...  # entry.stream / entry.entry_id / entry.fields

while True:
    resp = await r.xreadgroup(
        "agent-swarm", "agent-1", {"tasks": ">"}, count=10, block=1000
    )
    for stream, messages in resp:
        stream_name = stream.decode() if isinstance(stream, bytes) else stream
        for entry_id, fields in messages:
            entry_id_str = (
                entry_id.decode() if isinstance(entry_id, bytes) else entry_id
            )
            await mw.dispatch(
                stream=stream_name,
                entry_id=entry_id_str,
                fields=fields,
                handler=handler,
            )
```

- Receipt and DLQ envelopes are written as `XADD` entries with
  canonical JSON in a `payload` field plus the Chio headers surfaced
  as top-level fields for `XRANGE` filtering.
- Deny XACKs by default so the PEL does not grow unboundedly. Set
  `deny_strategy="keep"` if you want to triage denials via
  `XPENDING` / `XAUTOCLAIM` before acknowledging.
- Handler errors leave the entry in the PEL by default; Redis's
  consumer-group redelivery (or `XAUTOCLAIM`) handles retries.

## Transactional semantics summary

| Broker | Allow atomicity | Deny atomicity | Handler error |
|---|---|---|---|
| Kafka | offset + receipt transactional | offset + DLQ transactional | abort -> redeliver |
| NATS JetStream | publish then ack | publish then ack / term | nak (or term) |
| Pulsar | send then acknowledge | send then acknowledge | nack (or ack) |
| EventBridge | put_events then return | put_events then return | raise -> Lambda retry |
| Pub/Sub | publish then ack | publish then ack (or nack) | nack (or ack) |
| Redis Streams | XADD then XACK | XADD then XACK (or keep) | leave in PEL (or XACK) |

Everything except Kafka is publish-then-ack: a crash between the
publish and the ack costs a duplicate receipt or DLQ entry, which
downstream consumers should dedupe on `request_id`.

## Testing

Every broker ships a test suite against in-process fakes, so no live
broker is required. See `tests/test_middleware.py`
(Kafka), `tests/test_nats.py`, `tests/test_pulsar.py`,
`tests/test_eventbridge.py`, `tests/test_pubsub.py`, and
`tests/test_redis_streams.py`.

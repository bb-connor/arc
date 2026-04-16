# Event Streaming Integration: Governing Agent Choreography

> **Status**: Proposed April 2026
> **Priority**: High -- event-driven agent architectures lack a governance
> layer. Orchestration has a coordinator to wrap; choreography does not.
> ARC fills the governance gap for agents that react autonomously to event
> streams. Covers Kafka, NATS, Pulsar, EventBridge, Pub/Sub, Redis Streams.

## 1. Why Event Streaming Matters for ARC

The initial instinct was to skip event streaming: "ARC operates at
tool-call granularity, not message routing." That framing was wrong.

The real pattern is not ARC routing messages. The real pattern is:

```
Event arrives on topic
  -> Agent consumes it
  -> Agent decides what to do
  -> Agent calls tools in response
  -> Agent produces result events
```

The Kafka consumer IS the agent's trigger loop. The tools it calls inside
that loop are the capability boundary. And the result events it produces
carry receipts proving what was authorized.

### The Choreography Governance Problem

Orchestration (Temporal, Airflow, LangGraph) has a coordinator -- a
workflow engine that sequences steps. You wrap the coordinator and
governance flows through a single point.

Choreography has no coordinator. Agents independently react to events they
observe. There is no single place to enforce policy. Each consumer in a
consumer group is an autonomous agent with its own capability scope,
making its own decisions about what tools to call.

This is the hardest governance problem in multi-agent systems. And it is
exactly where ARC provides the most value -- because without a protocol
like ARC, choreography-based agent systems are structurally ungovernable.

### What ARC Adds to Event-Driven Agents

| Event streaming alone | Event streaming + ARC |
|-----------------------|-----------------------|
| Agents consume events freely | Agents need capabilities to process event types |
| No audit of what agents did in response | Signed receipts on every tool call triggered by events |
| Consumer groups scale horizontally | Budget shared across consumer group, enforced per-consumer |
| Schema Registry governs data shape | ARC governs what agents DO with the data |
| Dead letter = processing failed | Dead letter = processing unauthorized (security signal) |
| Exactly-once = no duplicate processing | Exactly-once + receipt = no duplicate AND attested processing |
| No cross-consumer coordination | Shared capability grants scope the entire consumer group |

## 2. Architecture

### 2.1 Consumer-Side Enforcement

ARC evaluates at the point where the agent acts on an event -- not at the
broker level. The broker remains untouched. Governance happens inside the
consumer:

```
Kafka / NATS / Pulsar Broker
         |
         | events
         v
+-----------------------------------------------+
| Agent Consumer Process                        |
|                                               |
|  Event Loop:                                  |
|    event = consumer.poll()                    |
|         |                                     |
|         v                                     |
|    ARC: evaluate(                             |
|      tool = event.topic,                      |
|      scope = derive_scope(event),             |
|      identity = consumer.group_id,            |
|    )                                          |
|         |                                     |
|    +----+----+                                |
|    |         |                                |
|  allow     deny                               |
|    |         |                                |
|    v         v                                |
|  process   DLQ + denial receipt               |
|  event                                        |
|    |                                          |
|    v                                          |
|  tool_calls (each ARC-evaluated)              |
|    |                                          |
|    v                                          |
|  produce result events (receipt attached)     |
|    |                                          |
|    v                                          |
|  commit offset + receipt (transactional)      |
|                                               |
|  ARC Sidecar (:9090) <---------------------->  |
+-----------------------------------------------+
```

### 2.2 Two Evaluation Points

There are two distinct capability boundaries per event:

1. **Event consumption** -- is this agent authorized to process this event
   type? Scope: `events:consume:{topic}`.
2. **Tool invocation** -- for each tool the agent calls in response to the
   event, is it authorized? Scope: `tools:{tool_name}`.

```
Event: order.placed (topic: orders)
  |
  +-- ARC evaluate: scope="events:consume:orders"  (can this agent see orders?)
  |
  +-- Agent decides: need to check inventory
  |     +-- ARC evaluate: scope="tools:inventory:read"  (can it read inventory?)
  |
  +-- Agent decides: need to charge payment
  |     +-- ARC evaluate: scope="tools:payment:charge"  (can it charge?)
  |
  +-- Agent produces: order.confirmed -> topic: order-events
        +-- ARC evaluate: scope="events:produce:order-events"  (can it write here?)
        +-- Receipt attached to produced event headers
```

### 2.3 Transactional Receipt Commit

Kafka's exactly-once semantics allow atomic commit of offset + receipt:

```
Kafka Transaction:
  1. consume(event, offset=42)
  2. arc.evaluate(tool, scope) -> receipt_id
  3. process(event) -> result
  4. produce(result_event, headers={"X-Arc-Receipt": receipt_id})
  5. commit(offset=42)  // atomic with produce

If any step fails, the transaction aborts:
  - offset not committed (event will be redelivered)
  - result event not produced
  - receipt marked as rolled back
```

## 3. Kafka Integration

### 3.1 Consumer Middleware

```python
from confluent_kafka import Consumer, Producer, KafkaError
from arc_streaming import ArcConsumerMiddleware, ArcProducerMiddleware

# Wrap a Kafka consumer with ARC governance
consumer = Consumer({
    "bootstrap.servers": "localhost:9092",
    "group.id": "research-agents",
    "enable.auto.commit": False,
})

arc_consumer = ArcConsumerMiddleware(
    consumer=consumer,
    sidecar_url="http://127.0.0.1:9090",
    # Map topics to capability scopes
    scope_map={
        "research-tasks": "events:consume:research-tasks",
        "urgent-tasks": "events:consume:urgent-tasks",
    },
    # Consumer group identity used for capability evaluation
    identity="research-agent-group",
    # Events the agent is not authorized to process go here
    dlq_topic="arc-denied-events",
)

# Usage -- same consumer interface, ARC-governed
while True:
    event = arc_consumer.poll(timeout=1.0)
    if event is None:
        continue

    # If we get here, ARC authorized consumption of this event
    # event.arc_receipt_id is set
    process(event)

    # Tool calls within processing are separately ARC-evaluated
    # (via the standard arc-sdk-python / arc-fastapi / etc.)

    arc_consumer.commit(event)
```

### 3.2 Producer Middleware

Outbound events carry receipts:

```python
producer = Producer({"bootstrap.servers": "localhost:9092"})

arc_producer = ArcProducerMiddleware(
    producer=producer,
    sidecar_url="http://127.0.0.1:9090",
    scope_map={
        "order-events": "events:produce:order-events",
        "notifications": "events:produce:notifications",
    },
)

# Produce with ARC evaluation
arc_producer.produce(
    topic="order-events",
    value=json.dumps({"order_id": "123", "status": "confirmed"}),
    # Receipt automatically attached as message header
    # Headers: {"X-Arc-Receipt": "rcpt_abc123", "X-Arc-Scope": "events:produce:order-events"}
)
```

### 3.3 Transactional Consumer-Producer (Exactly-Once + Receipts)

```python
from arc_streaming.kafka import ArcTransactionalProcessor

processor = ArcTransactionalProcessor(
    bootstrap_servers="localhost:9092",
    group_id="order-agents",
    consume_topics=["orders"],
    sidecar_url="http://127.0.0.1:9090",
    consume_scope="events:consume:orders",
    produce_scope_map={
        "order-events": "events:produce:order-events",
        "payment-requests": "events:produce:payment-requests",
    },
)

async def handle_order(event, ctx):
    """Process an order event. Runs inside a Kafka transaction."""
    order = json.loads(event.value())

    # Tool call -- separately ARC-evaluated
    inventory = await ctx.arc.invoke(
        tool="check-inventory",
        scope="tools:inventory:read",
        arguments={"sku": order["sku"]},
    )

    if inventory["available"]:
        # Produce within the same transaction
        await ctx.produce(
            topic="payment-requests",
            value=json.dumps({"order_id": order["id"], "amount": order["total"]}),
        )
        # Receipt for this produce is auto-attached

    # Transaction commits: offset + produced messages + receipts
    # All atomic -- either all succeed or none do

processor.register("orders", handle_order)
processor.run()
```

### 3.4 Consumer Group as Agent Swarm

A consumer group is structurally an agent swarm. ARC provides swarm-level
governance:

```python
from arc_streaming.kafka import ArcConsumerGroup

group = ArcConsumerGroup(
    group_id="research-swarm",
    topics=["research-tasks"],
    sidecar_url="http://127.0.0.1:9090",

    # Group-level capability grant
    group_scope="agent:research-swarm",
    group_capabilities=[
        "events:consume:research-tasks",
        "tools:search",
        "tools:browse",
        "tools:summarize",
    ],

    # Shared budget across all consumers in the group
    group_budget={
        "max_calls": 10000,       # total across all consumers
        "max_cost_usd": 50.00,    # total across all consumers
    },

    # Per-consumer budget slice
    per_consumer_budget={
        "max_calls": 500,         # per consumer instance
        "max_cost_usd": 5.00,
    },

    # Rebalance hook: redistribute budget on scale-up/down
    on_rebalance="redistribute_budget",
)
```

### 3.5 Schema Registry + ARC: Noun + Verb Governance

Schema Registry governs what the data LOOKS LIKE. ARC governs what agents
DO with the data. They are complementary:

```
Schema Registry                    ARC
+--------------------------+       +--------------------------+
| "orders" topic schema:   |       | "orders" topic policy:   |
|   order_id: string       |       |   consume:               |
|   amount: decimal        |       |     scope: events:orders  |
|   customer_pii: string   |       |     guards:               |
|                          |       |       - pii-filter        |
| Validates: data shape    |       |       - rate-limit        |
| Rejects: malformed data  |       |   Validates: authorization|
+--------------------------+       |   Rejects: unauthorized   |
                                   +--------------------------+
```

The `pii-filter` guard can use the Schema Registry to know that the
`customer_pii` field exists and requires special handling:

```python
# Guard that reads schema to identify sensitive fields
class PiiFilterGuard:
    async def evaluate(self, context):
        schema = await schema_registry.get_schema(context.topic)
        pii_fields = [f for f in schema.fields if f.has_tag("pii")]

        if pii_fields and not context.has_scope("data:pii:read"):
            return Deny(f"Event contains PII fields {pii_fields}, "
                        f"requires data:pii:read scope")
        return Allow()
```

## 4. NATS Integration

NATS is lighter-weight than Kafka and popular in cloud-native
architectures. Its request-reply and JetStream persistence models
map cleanly:

### 4.1 NATS Subscription Middleware

```python
import nats
from arc_streaming.nats import ArcNatsMiddleware

async def main():
    nc = await nats.connect("nats://localhost:4222")
    js = nc.jetstream()

    arc_sub = ArcNatsMiddleware(
        jetstream=js,
        sidecar_url="http://127.0.0.1:9090",
    )

    # Subscribe with ARC governance
    @arc_sub.subscribe(
        subject="tasks.research.*",
        scope="events:consume:tasks.research",
        durable="research-agent",
    )
    async def handle_research(msg):
        # ARC authorized this subscription and this specific message
        data = json.loads(msg.data)
        result = await process_research(data)
        await msg.ack()

    # NATS request-reply with ARC
    @arc_sub.service(
        subject="tools.search",
        scope="tools:search",
    )
    async def search_handler(msg):
        # Both the request consumption and the reply are ARC-evaluated
        query = json.loads(msg.data)
        results = await search(query)
        await msg.respond(json.dumps(results).encode())
```

### 4.2 NATS Key-Value as Capability Store

NATS JetStream Key-Value can serve as a distributed capability cache:

```python
from arc_streaming.nats import ArcNatsCapabilityStore

# Use NATS KV as the capability token store
# Grants are replicated across NATS cluster nodes
cap_store = ArcNatsCapabilityStore(
    jetstream=js,
    bucket="arc-capabilities",
    # Capabilities expire with NATS KV TTL
    ttl=3600,
)
```

## 5. Amazon EventBridge Integration

EventBridge is serverless event routing. ARC integrates at the target
Lambda/consumer level:

```python
from arc_streaming.eventbridge import ArcEventBridgeHandler

handler = ArcEventBridgeHandler(
    sidecar_url="http://127.0.0.1:9090",
    scope_map={
        # Map EventBridge detail-type to ARC scopes
        "OrderPlaced": "events:consume:order-placed",
        "IncidentDetected": "events:consume:incident",
    },
)

def lambda_handler(event, context):
    """Lambda triggered by EventBridge rule."""
    verdict = handler.evaluate(event)

    if verdict.denied:
        # Return to EventBridge -- can trigger DLQ rule
        return {"statusCode": 403, "error": verdict.reason}

    result = process_event(event)

    handler.record(verdict)
    return {"statusCode": 200, "result": result}
```

### EventBridge Rule Pattern

```json
{
  "source": ["arc.protocol"],
  "detail-type": ["CapabilityDenied"],
  "detail": {
    "denial_count": [{"numeric": [">=", 5]}]
  }
}
```

This rule triggers when ARC denies 5+ events -- enabling automated
circuit-breaking via EventBridge's native pattern matching.

## 6. Google Pub/Sub Integration

```python
from google.cloud import pubsub_v1
from arc_streaming.pubsub import ArcPubSubMiddleware

subscriber = pubsub_v1.SubscriberClient()
arc_sub = ArcPubSubMiddleware(
    subscriber=subscriber,
    sidecar_url="http://127.0.0.1:9090",
)

def callback(message):
    # ArcPubSubMiddleware wraps the callback
    # Evaluates capability before callback executes
    # Attaches receipt to message attributes on ack
    data = json.loads(message.data)
    process(data)
    message.ack()

arc_sub.subscribe(
    subscription="projects/my-project/subscriptions/agent-tasks",
    scope="events:consume:agent-tasks",
    callback=callback,
)
```

## 7. Redis Streams Integration

```python
import redis.asyncio as redis
from arc_streaming.redis import ArcRedisStreamConsumer

r = redis.Redis()

consumer = ArcRedisStreamConsumer(
    redis=r,
    sidecar_url="http://127.0.0.1:9090",
    group="agent-swarm",
    consumer_name="agent-1",
    scope_map={
        "task-stream": "events:consume:tasks",
    },
)

async def process():
    async for stream, messages in consumer.read("task-stream"):
        for msg_id, fields in messages:
            # ARC evaluated before yielding
            result = await handle_task(fields)
            await consumer.ack("task-stream", msg_id)
            # Receipt committed with ack
```

## 8. Dead Letter Governance

DLQ in an ARC-governed streaming system serves a fundamentally different
purpose than traditional DLQ. It is a security audit trail, not just an
error recovery mechanism:

```
Traditional DLQ:
  Event -> Consumer -> Processing failed -> DLQ
  Meaning: "We tried and couldn't"

ARC-governed DLQ:
  Event -> Consumer -> ARC denied -> DLQ + denial receipt
  Meaning: "We were not authorized to process this"

The DLQ becomes a security signal:
  - High DLQ volume = agents attempting unauthorized actions
  - Specific denial patterns = misconfigured capabilities or attack
  - Receipt-enriched DLQ = auditable proof of enforcement
```

```python
class ArcDeadLetterProducer:
    """Route denied events to DLQ with full ARC context."""

    async def send_to_dlq(self, event, verdict):
        dlq_event = {
            "original_topic": event.topic(),
            "original_key": event.key(),
            "original_value": event.value(),
            "original_timestamp": event.timestamp(),
            "arc_denial": {
                "receipt_id": verdict.receipt_id,
                "reason": verdict.reason,
                "scope_requested": verdict.scope,
                "identity": verdict.identity,
                "guards_evaluated": verdict.guards,
                "timestamp": verdict.timestamp,
            },
        }

        await self.producer.produce(
            topic=self.dlq_topic,
            value=json.dumps(dlq_event),
            headers={
                "X-Arc-Receipt": verdict.receipt_id,
                "X-Arc-Denial-Reason": verdict.reason,
                "X-Arc-Original-Topic": event.topic(),
            },
        )
```

### DLQ Analytics

```sql
-- BigQuery / Redshift: analyze denial patterns
SELECT
    json_extract_scalar(arc_denial, '$.reason') AS denial_reason,
    json_extract_scalar(arc_denial, '$.scope_requested') AS scope,
    json_extract_scalar(arc_denial, '$.identity') AS agent_id,
    COUNT(*) AS denial_count,
    MIN(event_timestamp) AS first_seen,
    MAX(event_timestamp) AS last_seen
FROM arc_dlq_events
WHERE event_date >= CURRENT_DATE - INTERVAL 7 DAY
GROUP BY 1, 2, 3
ORDER BY denial_count DESC;
```

## 9. Choreography Receipts: Cross-Agent Event Chains

In a choreography, events flow between agents with no coordinator.
Receipts chain across these boundaries:

```
Agent A (order-service)                  Agent B (payment-service)
  |                                        |
  | produce: order.placed                  |
  | receipt: rcpt_001                      |
  | header: X-Arc-Receipt=rcpt_001         |
  |                                        |
  +------> [topic: orders] ------>---------+
                                           |
                                    consume: order.placed
                                    evaluate: scope=events:consume:orders
                                    receipt: rcpt_002
                                    parent_receipt: rcpt_001 (from header)
                                           |
                                    call tool: charge_payment
                                    receipt: rcpt_003
                                    parent_receipt: rcpt_002
                                           |
                                    produce: payment.charged
                                    receipt: rcpt_004
                                    header: X-Arc-Receipt=rcpt_004
                                    header: X-Arc-Chain=rcpt_001->rcpt_002->rcpt_003->rcpt_004
                                           |
  +------> [topic: payments] <----<--------+
  |
  consume: payment.charged
  receipt: rcpt_005
  parent_receipt: rcpt_004
```

The receipt chain creates a cryptographic audit trail across the entire
choreography -- even though no single agent or coordinator has a global
view. Any receipt can be traced forward and backward through the chain.

```python
# Querying the choreography chain
arc receipt chain rcpt_001 --direction forward
# rcpt_001 (order.placed produced by order-service)
#   -> rcpt_002 (order.placed consumed by payment-service)
#     -> rcpt_003 (charge_payment tool call)
#       -> rcpt_004 (payment.charged produced by payment-service)
#         -> rcpt_005 (payment.charged consumed by order-service)

arc receipt chain rcpt_005 --direction backward
# Traces back to the original order.placed event
```

## 10. Rust Substrate: `arc-streaming-core`

A Rust crate providing the core streaming evaluation model, used by the
Python/TS/Go SDK wrappers:

```rust
//! Core types for ARC event streaming integration.

use arc_core::{CapabilityToken, Receipt, Scope};
use serde::{Deserialize, Serialize};

/// Evaluation context for an event consumption or production.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamEventContext {
    /// Topic/subject/stream name
    pub topic: String,
    /// Consumer group or subscription ID
    pub group_id: String,
    /// Direction: consume or produce
    pub direction: StreamDirection,
    /// Event key (for partitioned streams)
    pub key: Option<String>,
    /// Event schema ID (from schema registry)
    pub schema_id: Option<String>,
    /// Parent receipt ID (from upstream event headers)
    pub parent_receipt_id: Option<String>,
    /// Partition (for Kafka-style partitioned topics)
    pub partition: Option<i32>,
    /// Consumer offset (for exactly-once tracking)
    pub offset: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamDirection {
    Consume,
    Produce,
}

/// Receipt metadata specific to streaming events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamReceiptMeta {
    pub topic: String,
    pub direction: StreamDirection,
    pub partition: Option<i32>,
    pub offset: Option<i64>,
    pub parent_receipt_id: Option<String>,
    pub consumer_group: String,
    /// Chain head: receipt ID of the first event in the choreography
    pub chain_head: Option<String>,
}
```

## 11. Package Structure

```
crates/
  arc-streaming-core/
    Cargo.toml              # deps: arc-core
    src/
      lib.rs                # StreamEventContext, StreamReceiptMeta
      evaluate.rs           # Event-to-evaluation mapping
      chain.rs              # Receipt chain traversal

sdks/python/arc-streaming/
  pyproject.toml            # deps: arc-sdk-python
  src/arc_streaming/
    __init__.py
    kafka/
      __init__.py
      consumer.py           # ArcConsumerMiddleware
      producer.py           # ArcProducerMiddleware
      transactional.py      # ArcTransactionalProcessor
      group.py              # ArcConsumerGroup (swarm model)
    nats/
      __init__.py
      middleware.py          # ArcNatsMiddleware
      capability_store.py   # NATS KV capability store
    pubsub/
      __init__.py
      middleware.py          # ArcPubSubMiddleware
    eventbridge/
      __init__.py
      handler.py            # ArcEventBridgeHandler
    redis/
      __init__.py
      consumer.py           # ArcRedisStreamConsumer
    dlq.py                  # ArcDeadLetterProducer
    chain.py                # Receipt chain utilities
  tests/
    test_kafka_consumer.py
    test_kafka_transactional.py
    test_nats.py
    test_dlq.py
    test_receipt_chain.py

sdks/typescript/arc-streaming/
  package.json              # deps: @arc-protocol/node-http
  src/
    kafka/                  # kafkajs integration
    nats/                   # nats.js integration
    index.ts
```

## 12. Open Questions

1. **Broker-level enforcement.** This design evaluates at the consumer,
   not the broker. Should ARC offer a Kafka interceptor plugin or NATS
   authorization callout that evaluates at the broker level? Pro: earlier
   enforcement. Con: broker coupling, latency on the hot path.

2. **Compacted topics.** Kafka compacted topics retain the latest value
   per key. If a capability is revoked after an event is compacted, can
   the agent still consume the compacted event? The receipt trail says
   it was authorized at original write time.

3. **Multi-cluster streaming.** Kafka MirrorMaker / Confluent Cluster
   Linking replicate events across clusters. Should receipts replicate
   with the events, or should each cluster maintain its own receipt chain?

4. **Backpressure.** If ARC denies a high volume of events, the DLQ may
   become a bottleneck. Should the consumer apply backpressure to the
   source topic, or should denial rate trigger consumer group shutdown?

5. **Event replay.** Kafka consumers can reset offsets to replay events.
   Should ARC re-evaluate capabilities on replay (they may have changed),
   or honor the original evaluation from the receipt chain?

6. **Windowed aggregations.** Kafka Streams / Flink windowed aggregations
   consume many events to produce one result. Should ARC evaluate per-event
   or per-window? Per-window is more practical but loses per-event
   granularity.

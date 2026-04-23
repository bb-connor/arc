"""Chio streaming integrations for agent choreography governance.

The package wraps every mainstream event bus Chio supports so each
consumed event is evaluated through the Chio sidecar before the
application handler runs. Denials are routed to a broker-specific DLQ
alongside a signed denial receipt; allows publish a receipt envelope
to a receipt topic so the full choreography becomes attestable.

Supported brokers:

* **Kafka** via :class:`ChioConsumerMiddleware` (EOS v2 transactions).
* **NATS JetStream** via :class:`ChioNatsMiddleware`.
* **Apache Pulsar** via :class:`ChioPulsarMiddleware`.
* **AWS EventBridge** via :class:`ChioEventBridgeHandler` (Lambda
  targets).
* **Google Cloud Pub/Sub** via :class:`ChioPubSubMiddleware`.
* **Redis Streams** via :class:`ChioRedisStreamsMiddleware`.

All middlewares share :class:`DLQRouter`, :class:`ReceiptEnvelope`, and
the :data:`RECEIPT_HEADER` / :data:`VERDICT_HEADER` wire constants, and
every per-broker ``*ProcessingOutcome`` subclasses
:class:`BaseProcessingOutcome`.

Per-broker submodules (``chio_streaming.nats``,
``chio_streaming.pulsar``, ``chio_streaming.eventbridge``,
``chio_streaming.pubsub``, ``chio_streaming.redis_streams``) remain
importable for callers that prefer fully-qualified paths.
"""

from chio_streaming.core import BaseProcessingOutcome
from chio_streaming.dlq import DLQRecord, DLQRouter
from chio_streaming.errors import ChioStreamingConfigError, ChioStreamingError
from chio_streaming.eventbridge import (
    ChioEventBridgeConfig,
    ChioEventBridgeHandler,
    EventBridgeProcessingOutcome,
    build_eventbridge_handler,
)
from chio_streaming.flink import (
    DLQ_TAG_NAME,
    RECEIPT_TAG_NAME,
    ChioAsyncEvaluateFunction,
    ChioEvaluateFunction,
    ChioFlinkConfig,
    ChioVerdictSplitFunction,
    EvaluationResult,
    FlinkProcessingOutcome,
    register_dependencies,
)
from chio_streaming.middleware import (
    ChioClientLike,
    ChioConsumerConfig,
    ChioConsumerMiddleware,
    KafkaConsumerLike,
    KafkaMessageLike,
    KafkaProducerLike,
    MessageHandler,
    ProcessingOutcome,
    build_middleware,
)
from chio_streaming.nats import (
    ChioNatsConsumerConfig,
    ChioNatsMiddleware,
    NatsProcessingOutcome,
    build_nats_middleware,
)
from chio_streaming.pubsub import (
    ChioPubSubConfig,
    ChioPubSubMiddleware,
    PubSubProcessingOutcome,
    build_pubsub_middleware,
)
from chio_streaming.pulsar import (
    ChioPulsarConsumerConfig,
    ChioPulsarMiddleware,
    PulsarProcessingOutcome,
    build_pulsar_middleware,
)
from chio_streaming.receipt import (
    ENVELOPE_VERSION,
    RECEIPT_HEADER,
    VERDICT_HEADER,
    ReceiptEnvelope,
    build_envelope,
    canonical_json,
    new_request_id,
)
from chio_streaming.redis_streams import (
    ChioRedisStreamsConfig,
    ChioRedisStreamsMiddleware,
    RedisStreamEntry,
    RedisStreamsProcessingOutcome,
    build_redis_streams_middleware,
)

__all__ = [
    "DLQ_TAG_NAME",
    "ENVELOPE_VERSION",
    "RECEIPT_HEADER",
    "RECEIPT_TAG_NAME",
    "VERDICT_HEADER",
    "BaseProcessingOutcome",
    "ChioAsyncEvaluateFunction",
    "ChioClientLike",
    "ChioConsumerConfig",
    "ChioConsumerMiddleware",
    "ChioEvaluateFunction",
    "ChioEventBridgeConfig",
    "ChioEventBridgeHandler",
    "ChioFlinkConfig",
    "ChioNatsConsumerConfig",
    "ChioNatsMiddleware",
    "ChioPubSubConfig",
    "ChioPubSubMiddleware",
    "ChioPulsarConsumerConfig",
    "ChioPulsarMiddleware",
    "ChioRedisStreamsConfig",
    "ChioRedisStreamsMiddleware",
    "ChioStreamingConfigError",
    "ChioStreamingError",
    "ChioVerdictSplitFunction",
    "DLQRecord",
    "DLQRouter",
    "EvaluationResult",
    "EventBridgeProcessingOutcome",
    "FlinkProcessingOutcome",
    "KafkaConsumerLike",
    "KafkaMessageLike",
    "KafkaProducerLike",
    "MessageHandler",
    "NatsProcessingOutcome",
    "ProcessingOutcome",
    "PubSubProcessingOutcome",
    "PulsarProcessingOutcome",
    "ReceiptEnvelope",
    "RedisStreamEntry",
    "RedisStreamsProcessingOutcome",
    "build_envelope",
    "build_eventbridge_handler",
    "build_middleware",
    "build_nats_middleware",
    "build_pubsub_middleware",
    "build_pulsar_middleware",
    "build_redis_streams_middleware",
    "canonical_json",
    "new_request_id",
    "register_dependencies",
]

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
* **Apache Flink** via :class:`ChioAsyncEvaluateFunction` +
  :class:`ChioVerdictSplitFunction`.

All middlewares share :class:`DLQRouter`, :class:`ReceiptEnvelope`, and
the :data:`RECEIPT_HEADER` / :data:`VERDICT_HEADER` wire constants, and
every per-broker ``*ProcessingOutcome`` subclasses
:class:`BaseProcessingOutcome`.

Per-broker submodules (``chio_streaming.nats``,
``chio_streaming.pulsar``, ``chio_streaming.eventbridge``,
``chio_streaming.pubsub``, ``chio_streaming.redis_streams``,
``chio_streaming.flink``) remain importable for callers that prefer
fully-qualified paths.

Broker submodules are resolved lazily via PEP 562 ``__getattr__`` so a
bare ``import chio_streaming`` does not eagerly import every broker's
client library. Only the symbols a caller actually uses trigger the
underlying submodule import.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from chio_streaming.core import BaseProcessingOutcome
from chio_streaming.dlq import DLQRecord, DLQRouter
from chio_streaming.errors import ChioStreamingConfigError, ChioStreamingError
from chio_streaming.receipt import (
    ENVELOPE_VERSION,
    RECEIPT_HEADER,
    VERDICT_HEADER,
    ReceiptEnvelope,
    build_envelope,
    canonical_json,
    new_request_id,
)

if TYPE_CHECKING:  # pragma: no cover - typing-only re-exports
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
    from chio_streaming.redis_streams import (
        ChioRedisStreamsConfig,
        ChioRedisStreamsMiddleware,
        RedisStreamEntry,
        RedisStreamsProcessingOutcome,
        build_redis_streams_middleware,
    )


# Map each lazily-exported name to the submodule that defines it. One
# entry per symbol so ``from chio_streaming import X`` triggers exactly
# one submodule import regardless of how many symbols a caller uses.
_LAZY_EXPORTS: dict[str, str] = {
    # eventbridge
    "ChioEventBridgeConfig": "chio_streaming.eventbridge",
    "ChioEventBridgeHandler": "chio_streaming.eventbridge",
    "EventBridgeProcessingOutcome": "chio_streaming.eventbridge",
    "build_eventbridge_handler": "chio_streaming.eventbridge",
    # flink
    "DLQ_TAG_NAME": "chio_streaming.flink",
    "RECEIPT_TAG_NAME": "chio_streaming.flink",
    "ChioAsyncEvaluateFunction": "chio_streaming.flink",
    "ChioEvaluateFunction": "chio_streaming.flink",
    "ChioFlinkConfig": "chio_streaming.flink",
    "ChioVerdictSplitFunction": "chio_streaming.flink",
    "EvaluationResult": "chio_streaming.flink",
    "FlinkProcessingOutcome": "chio_streaming.flink",
    "register_dependencies": "chio_streaming.flink",
    # kafka (middleware.py)
    "ChioClientLike": "chio_streaming.middleware",
    "ChioConsumerConfig": "chio_streaming.middleware",
    "ChioConsumerMiddleware": "chio_streaming.middleware",
    "KafkaConsumerLike": "chio_streaming.middleware",
    "KafkaMessageLike": "chio_streaming.middleware",
    "KafkaProducerLike": "chio_streaming.middleware",
    "MessageHandler": "chio_streaming.middleware",
    "ProcessingOutcome": "chio_streaming.middleware",
    "build_middleware": "chio_streaming.middleware",
    # nats
    "ChioNatsConsumerConfig": "chio_streaming.nats",
    "ChioNatsMiddleware": "chio_streaming.nats",
    "NatsProcessingOutcome": "chio_streaming.nats",
    "build_nats_middleware": "chio_streaming.nats",
    # pubsub
    "ChioPubSubConfig": "chio_streaming.pubsub",
    "ChioPubSubMiddleware": "chio_streaming.pubsub",
    "PubSubProcessingOutcome": "chio_streaming.pubsub",
    "build_pubsub_middleware": "chio_streaming.pubsub",
    # pulsar
    "ChioPulsarConsumerConfig": "chio_streaming.pulsar",
    "ChioPulsarMiddleware": "chio_streaming.pulsar",
    "PulsarProcessingOutcome": "chio_streaming.pulsar",
    "build_pulsar_middleware": "chio_streaming.pulsar",
    # redis streams
    "ChioRedisStreamsConfig": "chio_streaming.redis_streams",
    "ChioRedisStreamsMiddleware": "chio_streaming.redis_streams",
    "RedisStreamEntry": "chio_streaming.redis_streams",
    "RedisStreamsProcessingOutcome": "chio_streaming.redis_streams",
    "build_redis_streams_middleware": "chio_streaming.redis_streams",
}


def __getattr__(name: str) -> Any:
    """PEP 562 lazy re-export for broker submodules.

    A bare ``import chio_streaming`` imports only the shared primitives
    above. Broker submodules are imported on first access, so users who
    install only the ``[redis]`` extra do not pay the cost (or risk) of
    loading ``confluent_kafka`` / ``pyflink`` / ``pulsar-client``.
    """
    module_path = _LAZY_EXPORTS.get(name)
    if module_path is None:
        raise AttributeError(f"module 'chio_streaming' has no attribute {name!r}")
    import importlib

    module = importlib.import_module(module_path)
    value = getattr(module, name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY_EXPORTS))


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

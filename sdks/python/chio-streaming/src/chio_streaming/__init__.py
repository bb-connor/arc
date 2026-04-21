"""Chio streaming integration for Kafka consumers.

Wraps ``confluent-kafka`` so every consumed event is evaluated through
the Chio sidecar before the application handler runs. Denials are
routed to a DLQ via :class:`DLQRouter`; the DLQ publish and consumer
offset commit run inside a single Kafka transaction so either both
become visible or both roll back.

Public surface:

* :class:`ChioConsumerMiddleware` -- the consumer-side middleware.
* :class:`ChioConsumerConfig` -- dataclass capturing capability id,
  tool server, scope map, transactional wiring, and backpressure
  limits.
* :class:`DLQRouter` -- DLQ topic router + denial envelope builder.
* :class:`ProcessingOutcome` -- per-message outcome struct returned by
  :meth:`ChioConsumerMiddleware.poll_and_process`.
* :class:`ChioStreamingError` / :class:`ChioStreamingConfigError` --
  error types.
* :data:`ENVELOPE_VERSION`, :data:`RECEIPT_HEADER`,
  :data:`VERDICT_HEADER` -- wire constants.
"""

from chio_streaming.dlq import DLQRecord, DLQRouter
from chio_streaming.errors import ChioStreamingConfigError, ChioStreamingError
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
from chio_streaming.receipt import (
    ENVELOPE_VERSION,
    RECEIPT_HEADER,
    VERDICT_HEADER,
    ReceiptEnvelope,
    build_envelope,
    canonical_json,
    new_request_id,
)

__all__ = [
    "ChioClientLike",
    "ChioConsumerConfig",
    "ChioConsumerMiddleware",
    "ChioStreamingConfigError",
    "ChioStreamingError",
    "DLQRecord",
    "DLQRouter",
    "ENVELOPE_VERSION",
    "KafkaConsumerLike",
    "KafkaMessageLike",
    "KafkaProducerLike",
    "MessageHandler",
    "ProcessingOutcome",
    "RECEIPT_HEADER",
    "ReceiptEnvelope",
    "VERDICT_HEADER",
    "build_envelope",
    "build_middleware",
    "canonical_json",
    "new_request_id",
]

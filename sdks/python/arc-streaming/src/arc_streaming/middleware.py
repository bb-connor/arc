"""ARC-governed Kafka consumer middleware.

:class:`ArcConsumerMiddleware` wraps a confluent-kafka ``Consumer`` so
every consumed message is evaluated through the ARC sidecar before the
application processes it. The middleware drives two tightly-coupled
post-processing paths:

* **Allow path** -- the application processes the event, and the
  middleware commits the offset *transactionally* alongside a
  produced receipt envelope. If the transaction aborts (Kafka broker
  failure, producer fenced, application handler raised), neither the
  offset nor the receipt is visible downstream.

* **Deny path** -- the ARC verdict comes back ``deny``. The middleware
  uses the :class:`arc_streaming.DLQRouter` to build a denial envelope
  and publishes it to the configured DLQ topic *transactionally*
  alongside the offset commit. If the transaction aborts, the DLQ
  publish and the offset commit both roll back so the event will be
  redelivered.

## Transactional guarantees

The middleware relies on Kafka's transactional producer
(``transactional.id`` / EOS v2). A single Kafka transaction wraps:

1. ``Producer.produce(DLQ_topic, ...)`` on deny, or
2. ``Producer.produce(receipt_topic, ...)`` on allow after successful
   processing, and in both cases
3. ``Producer.send_offsets_to_transaction(...)`` for the consumed
   offset.

Atomicity guarantees:

* **Atomic** -- Offset commit + receipt produce (allow) and
  offset commit + DLQ produce (deny) become visible together or
  not at all.
* **Atomic** -- Application processing errors cause the middleware
  to call ``abort_transaction`` before returning so neither the
  produced event nor the offset advances.
* **NOT atomic** -- External side-effects (HTTP calls, DB writes)
  performed by the application handler. Kafka transactions only
  cover Kafka state. Use the outbox pattern if your handler needs
  at-most-once external effects.
* **NOT atomic across brokers** -- If you run the DLQ topic on a
  different Kafka cluster, the transaction only covers the primary
  cluster. Put the DLQ on the same cluster for end-to-end EOS.

## Backpressure

``max_in_flight`` caps how many evaluations can be outstanding at once.
When the limit is reached :meth:`poll` blocks (in a bounded way) on a
condition variable until a previous evaluation drains. This prevents
the middleware from stampeding the sidecar on bursty topics.

## Mocking

Tests pass a :class:`confluent_kafka`-compatible *duck-typed* consumer
and producer, so the middleware does not require a live broker. See
``tests/test_middleware.py`` for the harness.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from arc_sdk.errors import ArcDeniedError, ArcError
from arc_sdk.models import ArcReceipt

from arc_streaming.dlq import DLQRecord, DLQRouter
from arc_streaming.errors import ArcStreamingConfigError, ArcStreamingError
from arc_streaming.receipt import (
    ReceiptEnvelope,
    build_envelope,
    new_request_id,
)

if TYPE_CHECKING:  # pragma: no cover - typing-only imports
    from arc_sdk.client import ArcClient

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Protocols -- lets us accept mocks as well as the real ArcClient / Kafka
# ---------------------------------------------------------------------------


@runtime_checkable
class ArcClientLike(Protocol):
    """Subset of :class:`arc_sdk.client.ArcClient` the middleware uses."""

    async def evaluate_tool_call(
        self,
        *,
        capability_id: str,
        tool_server: str,
        tool_name: str,
        parameters: dict[str, Any],
    ) -> ArcReceipt:
        ...


@runtime_checkable
class KafkaMessageLike(Protocol):
    """Subset of ``confluent_kafka.Message`` the middleware reads."""

    def error(self) -> Any | None: ...
    def topic(self) -> str | None: ...
    def partition(self) -> int | None: ...
    def offset(self) -> int | None: ...
    def key(self) -> bytes | None: ...
    def value(self) -> bytes | None: ...
    def headers(self) -> list[tuple[str, bytes]] | None: ...


@runtime_checkable
class KafkaConsumerLike(Protocol):
    """Subset of ``confluent_kafka.Consumer`` the middleware drives."""

    def poll(self, timeout: float) -> KafkaMessageLike | None: ...
    def commit(
        self,
        *,
        message: KafkaMessageLike | None = ...,
        asynchronous: bool = ...,
    ) -> Any: ...
    def close(self) -> None: ...


@runtime_checkable
class KafkaProducerLike(Protocol):
    """Subset of ``confluent_kafka.Producer`` the middleware drives.

    Transactional methods are optional; the middleware falls back to
    non-transactional produce + commit when
    :class:`ArcConsumerConfig.transactional` is ``False``.
    """

    def produce(
        self,
        topic: str,
        value: bytes | None = ...,
        key: bytes | None = ...,
        headers: list[tuple[str, bytes]] | None = ...,
    ) -> None: ...

    def flush(self, timeout: float = ...) -> int: ...


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass
class ArcConsumerConfig:
    """Configuration for :class:`ArcConsumerMiddleware`.

    Attributes
    ----------
    capability_id:
        Capability token id the middleware passes to the ARC sidecar
        for every evaluation. Scoped to the consumer group.
    tool_server:
        The ARC "tool server" id representing the Kafka cluster or
        logical bus. Used as the ``tool_server`` argument to
        :meth:`ArcClient.evaluate_tool_call`.
    scope_map:
        Map from Kafka topic -> logical ARC ``tool_name`` used when
        evaluating. Defaults to the topic name prefixed with
        ``events:consume:``.
    receipt_topic:
        Kafka topic to publish the receipt envelope to on allow.
        Required when ``transactional=True``.
    transactional:
        When ``True`` (default), the middleware drives a transactional
        producer. The caller must have already called
        ``Producer.init_transactions()``. When ``False``, the
        middleware produces the receipt/DLQ record non-transactionally
        and commits the consumer offset separately -- atomicity
        degrades to at-least-once with best-effort coupling.
    max_in_flight:
        Maximum number of concurrent outstanding evaluations. When
        exceeded, ``poll()`` blocks until a previous call completes.
        Defaults to 64.
    poll_timeout:
        Default timeout (seconds) passed to ``Consumer.poll``.
    produce_timeout:
        Timeout (seconds) passed to ``Producer.flush`` / transactional
        commit calls.
    transaction_timeout:
        Timeout (seconds) passed to ``begin_transaction`` /
        ``commit_transaction`` / ``send_offsets_to_transaction``.
    consumer_group_id:
        Consumer group id used when calling
        ``send_offsets_to_transaction``. Required when
        ``transactional=True``.
    """

    capability_id: str
    tool_server: str
    scope_map: Mapping[str, str] = field(default_factory=dict)
    receipt_topic: str | None = None
    transactional: bool = True
    max_in_flight: int = 64
    poll_timeout: float = 1.0
    produce_timeout: float = 10.0
    transaction_timeout: float = 10.0
    consumer_group_id: str | None = None

    def __post_init__(self) -> None:
        if not self.capability_id:
            raise ArcStreamingConfigError(
                "ArcConsumerConfig.capability_id must be a non-empty string"
            )
        if not self.tool_server:
            raise ArcStreamingConfigError(
                "ArcConsumerConfig.tool_server must be a non-empty string"
            )
        if self.max_in_flight < 1:
            raise ArcStreamingConfigError(
                "ArcConsumerConfig.max_in_flight must be >= 1"
            )
        if self.transactional:
            if not self.receipt_topic:
                raise ArcStreamingConfigError(
                    "ArcConsumerConfig.receipt_topic is required when "
                    "transactional=True"
                )
            if not self.consumer_group_id:
                raise ArcStreamingConfigError(
                    "ArcConsumerConfig.consumer_group_id is required when "
                    "transactional=True"
                )


# ---------------------------------------------------------------------------
# Processing result
# ---------------------------------------------------------------------------


@dataclass
class ProcessingOutcome:
    """Result of processing a single Kafka message.

    Attributes
    ----------
    allowed:
        ``True`` if ARC allowed the event and the application handler
        ran successfully.
    receipt:
        The ARC receipt (allow or deny).
    request_id:
        Synthesised request id used for the evaluation.
    message:
        The originating Kafka message.
    dlq_record:
        Populated on deny with the DLQ record that was published.
    committed:
        ``True`` if the offset was committed (transaction succeeded or
        non-transactional commit returned). ``False`` if the
        transaction aborted.
    handler_error:
        Populated when the application handler raised; the middleware
        aborted the transaction and left the offset uncommitted.
    """

    allowed: bool
    receipt: ArcReceipt
    request_id: str
    message: KafkaMessageLike
    dlq_record: DLQRecord | None = None
    committed: bool = False
    handler_error: BaseException | None = None


# ---------------------------------------------------------------------------
# The middleware
# ---------------------------------------------------------------------------


MessageHandler = Callable[[KafkaMessageLike, ArcReceipt], Awaitable[None] | None]
"""Application callback invoked on allow. May be sync or async."""


class ArcConsumerMiddleware:
    """ARC-governed wrapper around a confluent-kafka Consumer.

    Parameters
    ----------
    consumer:
        The underlying confluent-kafka ``Consumer`` (or a duck-typed
        test double). The middleware owns the poll/commit loop but
        leaves subscription management to the caller.
    producer:
        The confluent-kafka ``Producer`` used for receipts and DLQ
        publishes. When ``config.transactional=True`` the producer
        must already be initialised via ``init_transactions()``.
    arc_client:
        An :class:`arc_sdk.client.ArcClient` (or compatible mock) used
        to evaluate every event. The middleware does not own the
        client's lifecycle.
    dlq_router:
        :class:`DLQRouter` for denied events.
    config:
        :class:`ArcConsumerConfig` with capability / transactional
        wiring.
    """

    def __init__(
        self,
        *,
        consumer: KafkaConsumerLike,
        producer: KafkaProducerLike,
        arc_client: ArcClientLike,
        dlq_router: DLQRouter,
        config: ArcConsumerConfig,
    ) -> None:
        if consumer is None:
            raise ArcStreamingConfigError("consumer is required")
        if producer is None:
            raise ArcStreamingConfigError("producer is required")
        if arc_client is None:
            raise ArcStreamingConfigError("arc_client is required")
        if dlq_router is None:
            raise ArcStreamingConfigError("dlq_router is required")

        self._consumer = consumer
        self._producer = producer
        self._arc_client = arc_client
        self._dlq_router = dlq_router
        self._config = config
        self._closed = False
        self._in_flight = 0
        # Asyncio semaphore caps concurrent evaluations. Lazily bound
        # to a running loop on first acquire so the middleware stays
        # constructable outside of any loop (e.g. in a factory).
        self._slots: asyncio.Semaphore | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @property
    def config(self) -> ArcConsumerConfig:
        """Return the active :class:`ArcConsumerConfig`."""
        return self._config

    @property
    def in_flight(self) -> int:
        """Return the number of evaluations currently in-flight."""
        return self._in_flight

    def close(self) -> None:
        """Close the underlying Kafka consumer.

        Idempotent. The producer and ARC client lifecycles are owned
        by the caller.
        """
        if self._closed:
            return
        self._closed = True
        try:
            self._consumer.close()
        except Exception:  # noqa: BLE001 - close is best-effort
            logger.exception("arc-streaming: error closing consumer")

    # ------------------------------------------------------------------
    # Main poll + process loop
    # ------------------------------------------------------------------

    async def poll_and_process(
        self,
        handler: MessageHandler,
        *,
        timeout: float | None = None,
    ) -> ProcessingOutcome | None:
        """Poll a single message, evaluate via ARC, and dispatch.

        Parameters
        ----------
        handler:
            Application callback invoked on allow with
            ``(message, receipt)``. Return values are ignored.
            Exceptions cause the transaction to abort; the offset is
            not committed and the receipt is not published.
        timeout:
            Poll timeout in seconds. Defaults to
            ``config.poll_timeout``.

        Returns
        -------
        :class:`ProcessingOutcome` describing the outcome (allow vs
        deny, commit status, any handler error), or ``None`` if no
        message was available within ``timeout``.
        """
        poll_timeout = self._config.poll_timeout if timeout is None else timeout
        message = self._consumer.poll(poll_timeout)
        if message is None:
            return None
        err = message.error()
        if err is not None:
            # Let the caller handle broker-level errors; ARC only
            # governs application-payload events.
            logger.warning("arc-streaming: consumer error: %s", err)
            return None

        await self._acquire_slot()
        try:
            return await self._process_message(message, handler)
        finally:
            self._release_slot()

    # ------------------------------------------------------------------
    # Per-message pipeline
    # ------------------------------------------------------------------

    async def _process_message(
        self,
        message: KafkaMessageLike,
        handler: MessageHandler,
    ) -> ProcessingOutcome:
        """Evaluate ``message`` via ARC and drive the allow/deny path."""
        request_id = new_request_id()
        topic = message.topic() or ""
        tool_name = self._scope_for(topic)
        parameters = self._parameters_for(message, request_id=request_id)

        receipt: ArcReceipt
        try:
            receipt = await self._arc_client.evaluate_tool_call(
                capability_id=self._config.capability_id,
                tool_server=self._config.tool_server,
                tool_name=tool_name,
                parameters=parameters,
            )
        except ArcDeniedError as exc:
            # The real ArcClient raises on HTTP 403 rather than
            # returning a deny receipt. Materialise a deny receipt so
            # the downstream pipeline is uniform.
            receipt = _synthesize_deny_receipt(
                capability_id=self._config.capability_id,
                tool_server=self._config.tool_server,
                tool_name=tool_name,
                parameters=parameters,
                reason=exc.reason or exc.message or "denied",
                guard=exc.guard or "unknown",
            )
        except ArcError as exc:
            # Sidecar unavailable -- we cannot safely process the
            # event. Surface the error to the caller; the offset is
            # NOT committed so the broker will redeliver once the
            # sidecar recovers.
            raise ArcStreamingError(
                f"ARC sidecar evaluation failed: {exc}",
                topic=topic,
                partition=message.partition(),
                offset=message.offset(),
                request_id=request_id,
            ) from exc

        if receipt.is_denied:
            return self._handle_deny(
                message=message,
                receipt=receipt,
                request_id=request_id,
            )
        return await self._handle_allow(
            message=message,
            receipt=receipt,
            request_id=request_id,
            handler=handler,
        )

    # ------------------------------------------------------------------
    # Allow path
    # ------------------------------------------------------------------

    async def _handle_allow(
        self,
        *,
        message: KafkaMessageLike,
        receipt: ArcReceipt,
        request_id: str,
        handler: MessageHandler,
    ) -> ProcessingOutcome:
        """Run the application handler and commit atomically on success."""
        envelope = build_envelope(
            request_id=request_id,
            receipt=receipt,
            source_topic=message.topic(),
            source_partition=message.partition(),
            source_offset=message.offset(),
        )

        self._begin_transaction()
        handler_error: BaseException | None = None
        try:
            await self._invoke_handler(handler, message, receipt)
            if self._config.receipt_topic is not None:
                self._produce_envelope(self._config.receipt_topic, envelope)
            self._commit_transaction(message)
            committed = True
        except BaseException as exc:  # noqa: BLE001 - must cover BaseException
            handler_error = exc
            self._abort_transaction_safely()
            committed = False

        if handler_error is not None:
            logger.warning(
                "arc-streaming: handler raised for topic=%s offset=%s; aborted "
                "transaction: %s",
                message.topic(),
                message.offset(),
                handler_error,
            )

        return ProcessingOutcome(
            allowed=True,
            receipt=receipt,
            request_id=request_id,
            message=message,
            dlq_record=None,
            committed=committed,
            handler_error=handler_error,
        )

    async def _invoke_handler(
        self,
        handler: MessageHandler,
        message: KafkaMessageLike,
        receipt: ArcReceipt,
    ) -> None:
        """Call the application handler, awaiting if it returned a coroutine."""
        result = handler(message, receipt)
        if result is None:
            return
        if isinstance(result, Awaitable):
            await result

    # ------------------------------------------------------------------
    # Deny path
    # ------------------------------------------------------------------

    def _handle_deny(
        self,
        *,
        message: KafkaMessageLike,
        receipt: ArcReceipt,
        request_id: str,
    ) -> ProcessingOutcome:
        """Publish the DLQ envelope + commit offset atomically."""
        record = self._dlq_router.build_record(
            source_topic=message.topic() or "",
            source_partition=message.partition(),
            source_offset=message.offset(),
            original_key=message.key(),
            original_value=message.value(),
            request_id=request_id,
            receipt=receipt,
        )

        self._begin_transaction()
        try:
            self._produce_dlq(record)
            self._commit_transaction(message)
            committed = True
        except Exception:
            self._abort_transaction_safely()
            committed = False
            raise
        return ProcessingOutcome(
            allowed=False,
            receipt=receipt,
            request_id=request_id,
            message=message,
            dlq_record=record,
            committed=committed,
        )

    # ------------------------------------------------------------------
    # Kafka transaction / produce helpers
    # ------------------------------------------------------------------

    def _begin_transaction(self) -> None:
        """Begin a Kafka transaction (no-op when non-transactional)."""
        if not self._config.transactional:
            return
        begin = getattr(self._producer, "begin_transaction", None)
        if begin is None:
            raise ArcStreamingConfigError(
                "transactional=True but producer has no begin_transaction() "
                "method; make sure init_transactions() was called on a "
                "transactional confluent-kafka Producer"
            )
        begin()

    def _commit_transaction(self, message: KafkaMessageLike) -> None:
        """Send offsets + commit the transaction (or commit directly)."""
        if not self._config.transactional:
            self._producer.flush(self._config.produce_timeout)
            self._consumer.commit(message=message, asynchronous=False)
            return

        # Transactional commit: send the offset *inside* the
        # transaction so the produce + offset become visible
        # together. confluent-kafka's API accepts a list of
        # TopicPartition with the offset set to the *next* offset to
        # consume (i.e. current + 1).
        topic = message.topic() or ""
        partition = message.partition() or 0
        offset = message.offset()
        if offset is None:
            raise ArcStreamingError(
                "cannot commit transaction for message without an offset",
                topic=topic,
                partition=partition,
            )
        next_offset = int(offset) + 1

        topic_partition = _build_topic_partition(topic, partition, next_offset)
        consumer_group_metadata = _consumer_group_metadata(
            consumer=self._consumer,
            fallback_group_id=self._config.consumer_group_id,
        )

        send_offsets = getattr(self._producer, "send_offsets_to_transaction", None)
        commit = getattr(self._producer, "commit_transaction", None)
        if send_offsets is None or commit is None:
            raise ArcStreamingConfigError(
                "transactional=True but producer is missing "
                "send_offsets_to_transaction / commit_transaction"
            )
        send_offsets(
            [topic_partition],
            consumer_group_metadata,
            self._config.transaction_timeout,
        )
        commit(self._config.transaction_timeout)

    def _abort_transaction_safely(self) -> None:
        """Call ``abort_transaction`` ignoring absence / best-effort errors."""
        if not self._config.transactional:
            return
        abort = getattr(self._producer, "abort_transaction", None)
        if abort is None:
            logger.warning(
                "arc-streaming: producer has no abort_transaction(); commit "
                "may be non-atomic"
            )
            return
        try:
            abort(self._config.transaction_timeout)
        except Exception:  # noqa: BLE001 - abort must not mask the cause
            logger.exception("arc-streaming: abort_transaction raised; swallowing")

    def _produce_envelope(self, topic: str, envelope: ReceiptEnvelope) -> None:
        """Produce a receipt envelope to ``topic``."""
        self._producer.produce(
            topic,
            value=envelope.value,
            key=envelope.key,
            headers=list(envelope.headers),
        )

    def _produce_dlq(self, record: DLQRecord) -> None:
        """Produce a DLQ record."""
        self._producer.produce(
            record.topic,
            value=record.value,
            key=record.key,
            headers=list(record.headers),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _scope_for(self, topic: str) -> str:
        """Resolve the ARC tool_name for ``topic``."""
        if not topic:
            raise ArcStreamingConfigError(
                "consumed message has no topic; ARC evaluation requires one"
            )
        mapped = self._config.scope_map.get(topic)
        if mapped:
            return mapped
        return f"events:consume:{topic}"

    def _parameters_for(
        self,
        message: KafkaMessageLike,
        *,
        request_id: str,
    ) -> dict[str, Any]:
        """Extract the parameter dict sent to the ARC sidecar.

        We do NOT forward the raw event body to the sidecar by default
        -- policies evaluate on headers + metadata. The body hash is
        available via ``parameters['body_hash']`` for guards that need
        to pin the specific payload.
        """
        headers = message.headers() or []
        header_dict = {
            name: (value.decode("utf-8", errors="replace") if isinstance(value, bytes | bytearray) else value)
            for name, value in headers
        }
        key_bytes = message.key()
        key_repr: str | None
        if key_bytes is None:
            key_repr = None
        else:
            try:
                key_repr = key_bytes.decode("utf-8")
            except UnicodeDecodeError:
                key_repr = key_bytes.hex()
        body = message.value() or b""
        import hashlib

        return {
            "request_id": request_id,
            "topic": message.topic(),
            "partition": message.partition(),
            "offset": message.offset(),
            "key": key_repr,
            "headers": header_dict,
            "body_length": len(body),
            "body_hash": hashlib.sha256(body).hexdigest() if body else None,
        }

    # ------------------------------------------------------------------
    # Backpressure
    # ------------------------------------------------------------------

    async def _acquire_slot(self) -> None:
        """Await a concurrency slot, yielding to the event loop if full."""
        if self._slots is None:
            self._slots = asyncio.Semaphore(self._config.max_in_flight)
        await self._slots.acquire()
        self._in_flight += 1

    def _release_slot(self) -> None:
        """Release a concurrency slot."""
        if self._in_flight > 0:
            self._in_flight -= 1
        if self._slots is not None:
            self._slots.release()


# ---------------------------------------------------------------------------
# Module-private helpers
# ---------------------------------------------------------------------------


def _synthesize_deny_receipt(
    *,
    capability_id: str,
    tool_server: str,
    tool_name: str,
    parameters: dict[str, Any],
    reason: str,
    guard: str,
) -> ArcReceipt:
    """Build a deny receipt when the sidecar raised instead of returning one."""
    import hashlib
    import json
    import time
    import uuid

    from arc_sdk.models import Decision, ToolCallAction

    canonical = json.dumps(
        parameters, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    param_hash = hashlib.sha256(canonical).hexdigest()
    return ArcReceipt(
        id=f"arc-streaming-synth-{uuid.uuid4().hex[:10]}",
        timestamp=int(time.time()),
        capability_id=capability_id,
        tool_server=tool_server,
        tool_name=tool_name,
        action=ToolCallAction(
            parameters=dict(parameters),
            parameter_hash=param_hash,
        ),
        decision=Decision.deny(reason=reason, guard=guard),
        content_hash=hashlib.sha256(canonical).hexdigest(),
        policy_hash="unknown",
        evidence=[],
        kernel_key="unknown",
        signature="synthetic",
    )


def _build_topic_partition(topic: str, partition: int, offset: int) -> Any:
    """Build a TopicPartition the producer can pass to the transaction API.

    We import lazily so the module stays importable without
    confluent-kafka at hand for type checking (and so tests that mock
    the producer can skip the call path entirely).
    """
    try:
        from confluent_kafka import TopicPartition
    except ImportError as exc:  # pragma: no cover - exercised only without the dep
        raise ArcStreamingConfigError(
            "transactional=True requires confluent-kafka to be installed"
        ) from exc
    return TopicPartition(topic=topic, partition=int(partition), offset=int(offset))


def _consumer_group_metadata(
    *,
    consumer: KafkaConsumerLike,
    fallback_group_id: str | None,
) -> Any:
    """Fetch the consumer group metadata used for the transactional API.

    ``confluent-kafka``'s ``Consumer.consumer_group_metadata()`` returns
    an opaque metadata object the producer's
    ``send_offsets_to_transaction`` requires. When the consumer is a
    mock without that method, we fall back to the plain group id
    string -- which the real Kafka client will reject, but test doubles
    accept.
    """
    getter = getattr(consumer, "consumer_group_metadata", None)
    if getter is not None:
        return getter()
    if fallback_group_id is None:
        raise ArcStreamingConfigError(
            "consumer has no consumer_group_metadata() and no "
            "consumer_group_id fallback is configured"
        )
    return fallback_group_id


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------


def build_middleware(
    *,
    consumer: KafkaConsumerLike,
    producer: KafkaProducerLike,
    arc_client: ArcClient | ArcClientLike,
    config: ArcConsumerConfig,
    dlq_router: DLQRouter | None = None,
    dlq_topic: str | None = None,
) -> ArcConsumerMiddleware:
    """Convenience constructor that wires a default :class:`DLQRouter`.

    Parameters
    ----------
    dlq_router:
        Explicit router. When supplied, ``dlq_topic`` is ignored.
    dlq_topic:
        Default DLQ topic when no router is supplied. Equivalent to
        ``DLQRouter(default_topic=dlq_topic)``.
    """
    if dlq_router is None:
        if not dlq_topic:
            raise ArcStreamingConfigError(
                "build_middleware requires dlq_router or dlq_topic"
            )
        dlq_router = DLQRouter(default_topic=dlq_topic)
    return ArcConsumerMiddleware(
        consumer=consumer,
        producer=producer,
        arc_client=arc_client,
        dlq_router=dlq_router,
        config=config,
    )


__all__ = [
    "ArcClientLike",
    "ArcConsumerConfig",
    "ArcConsumerMiddleware",
    "KafkaConsumerLike",
    "KafkaMessageLike",
    "KafkaProducerLike",
    "MessageHandler",
    "ProcessingOutcome",
    "build_middleware",
]

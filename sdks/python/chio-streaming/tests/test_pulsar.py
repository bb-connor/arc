"""Unit tests for :mod:`chio_streaming.pulsar`."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from chio_sdk.errors import ChioConnectionError
from chio_sdk.testing import allow_all, deny_all

from chio_streaming import VERDICT_HEADER
from chio_streaming.errors import ChioStreamingConfigError, ChioStreamingError
from chio_streaming.pulsar import (
    ChioPulsarConsumerConfig,
    ChioPulsarMiddleware,
    build_pulsar_middleware,
)
from chio_streaming.receipt import build_envelope


class FakePulsarMessage:
    """Duck-typed ``pulsar.Message``."""

    def __init__(
        self,
        *,
        topic: str,
        data: bytes = b"",
        properties: dict[str, str] | None = None,
        partition_key: str | None = None,
    ) -> None:
        self._topic = topic
        self._data = data
        self._props = properties or {}
        self._key = partition_key
        self._mid = object()

    def data(self) -> bytes:
        return self._data

    def properties(self) -> dict[str, str]:
        return self._props

    def topic_name(self) -> str:
        return self._topic

    def partition_key(self) -> str | None:
        return self._key

    def message_id(self) -> Any:
        return self._mid


class FakePulsarConsumer:
    """Duck-typed ``pulsar.Consumer`` recording ack / nack calls."""

    def __init__(self) -> None:
        self.acked: list[Any] = []
        # Kept as a (message, None) tuple for backwards-compatible test
        # assertions; the middleware now calls negative_acknowledge(msg)
        # without a delay_ms argument (that is a consumer-construction
        # option in the real client).
        self.nacked: list[tuple[Any, int | None]] = []

    def acknowledge(self, message: Any) -> None:
        self.acked.append(message)

    def negative_acknowledge(self, message: Any) -> None:
        self.nacked.append((message, None))


class FakePulsarProducer:
    """Duck-typed ``pulsar.Producer``."""

    def __init__(self, *, fail: bool = False) -> None:
        self.sent: list[dict[str, Any]] = []
        self._fail = fail

    def send(
        self,
        content: bytes,
        properties: dict[str, str] | None = None,
        partition_key: str | None = None,
    ) -> Any:
        if self._fail:
            raise RuntimeError("send failed")
        self.sent.append(
            {
                "content": content,
                "properties": dict(properties or {}),
                "partition_key": partition_key,
            }
        )
        return {"message_id": f"mid-{len(self.sent)}"}


def _cfg(**overrides: Any) -> ChioPulsarConsumerConfig:
    base: dict[str, Any] = dict(
        capability_id="cap-pulsar",
        tool_server="pulsar://prod",
        scope_map={"persistent://public/default/orders": "events:consume:orders"},
        receipt_topic="persistent://public/default/chio-receipts",
        max_in_flight=4,
    )
    base.update(overrides)
    return ChioPulsarConsumerConfig(**base)


def _middleware(
    *,
    chio_client: Any,
    config: ChioPulsarConsumerConfig | None = None,
    dlq_topic: str = "persistent://public/default/chio-dlq",
    receipt_producer: FakePulsarProducer | None = None,
    dlq_producer: FakePulsarProducer | None = None,
) -> tuple[ChioPulsarMiddleware, FakePulsarConsumer, FakePulsarProducer, FakePulsarProducer]:
    consumer = FakePulsarConsumer()
    receipt = receipt_producer or FakePulsarProducer()
    dlq = dlq_producer or FakePulsarProducer()
    mw = build_pulsar_middleware(
        consumer=consumer,
        receipt_producer=receipt,
        dlq_producer=dlq,
        chio_client=chio_client,
        config=config or _cfg(),
        dlq_topic=dlq_topic,
    )
    return mw, consumer, receipt, dlq


# ---------------------------------------------------------------------------
# Allow
# ---------------------------------------------------------------------------


async def test_allow_sends_receipt_and_acks() -> None:
    mw, consumer, receipt_prod, dlq_prod = _middleware(chio_client=allow_all())
    msg = FakePulsarMessage(
        topic="persistent://public/default/orders",
        data=b'{"id":1}',
        properties={"trace": "abc"},
        partition_key="k-1",
    )

    seen: list[str] = []

    async def handler(m: Any, _r: Any) -> None:
        seen.append(m.topic_name())

    outcome = await mw.dispatch(msg, handler)
    assert outcome.allowed is True
    assert outcome.acked is True
    assert outcome.handler_error is None
    assert seen == ["persistent://public/default/orders"]
    assert len(consumer.acked) == 1
    assert consumer.nacked == []
    assert len(receipt_prod.sent) == 1
    env = json.loads(receipt_prod.sent[0]["content"].decode("utf-8"))
    assert env["verdict"] == "allow"
    assert receipt_prod.sent[0]["properties"][VERDICT_HEADER] == "allow"
    assert dlq_prod.sent == []


async def test_allow_without_receipt_topic_skips_publish() -> None:
    cfg = _cfg(receipt_topic=None)
    mw, consumer, receipt_prod, _ = _middleware(chio_client=allow_all(), config=cfg)
    msg = FakePulsarMessage(topic="persistent://public/default/orders", data=b"x")

    async def handler(_m: Any, _r: Any) -> None:
        return None

    outcome = await mw.dispatch(msg, handler)
    assert outcome.acked is True
    assert receipt_prod.sent == []
    assert len(consumer.acked) == 1


async def test_allow_handler_error_negative_acks() -> None:
    mw, consumer, receipt_prod, _ = _middleware(chio_client=allow_all())
    msg = FakePulsarMessage(topic="persistent://public/default/orders")

    def handler(_m: Any, _r: Any) -> None:
        raise RuntimeError("boom")

    outcome = await mw.dispatch(msg, handler)
    assert outcome.allowed is True
    assert outcome.acked is False
    assert isinstance(outcome.handler_error, RuntimeError)
    assert receipt_prod.sent == []
    assert consumer.acked == []
    assert len(consumer.nacked) == 1
    assert consumer.nacked[0][1] is None


@pytest.mark.parametrize("shutdown_exc", [SystemExit, KeyboardInterrupt, asyncio.CancelledError])
async def test_handler_shutdown_signals_propagate(shutdown_exc: type) -> None:
    # Wave 1 replaced `except BaseException` with `except Exception` so
    # shutdown signals must surface out of dispatch unchanged.
    mw, consumer, receipt_prod, dlq_prod = _middleware(chio_client=allow_all())
    msg = FakePulsarMessage(topic="persistent://public/default/orders")

    def handler(_m: Any, _r: Any) -> None:
        raise shutdown_exc()

    with pytest.raises(shutdown_exc):
        await mw.dispatch(msg, handler)
    assert consumer.acked == []
    assert consumer.nacked == []
    assert receipt_prod.sent == []
    assert dlq_prod.sent == []


async def test_allow_handler_error_calls_plain_negative_ack() -> None:
    # The real pulsar-client only exposes negative_acknowledge(msg);
    # redelivery delay is a consumer-construction option
    # (negative_ack_redelivery_delay_ms) rather than a per-call arg.
    mw, consumer, _receipt, _dlq = _middleware(chio_client=allow_all())
    msg = FakePulsarMessage(topic="persistent://public/default/orders")

    def handler(_m: Any, _r: Any) -> None:
        raise RuntimeError("boom")

    await mw.dispatch(msg, handler)
    assert len(consumer.nacked) == 1
    # No delay threaded through by the middleware.
    assert consumer.nacked[0][1] is None


async def test_allow_handler_error_acknowledge_strategy() -> None:
    cfg = _cfg(handler_error_strategy="ack")
    mw, consumer, _, _ = _middleware(chio_client=allow_all(), config=cfg)
    msg = FakePulsarMessage(topic="persistent://public/default/orders")

    def handler(_m: Any, _r: Any) -> None:
        raise RuntimeError("boom")

    outcome = await mw.dispatch(msg, handler)
    # acked reflects broker-level acknowledgement; the handler still
    # failed (surfaced via handler_error) but the message was acked.
    assert outcome.acked is True
    assert outcome.handler_error is not None
    assert len(consumer.acked) == 1
    assert consumer.nacked == []


# ---------------------------------------------------------------------------
# Deny
# ---------------------------------------------------------------------------


async def test_deny_sends_dlq_and_acks() -> None:
    chio = deny_all("missing scope", guard="scope-guard", raise_on_deny=False)
    mw, consumer, receipt_prod, dlq_prod = _middleware(chio_client=chio)
    msg = FakePulsarMessage(
        topic="persistent://public/default/orders",
        data=b'{"evil":true}',
        partition_key="user-9",
    )

    async def handler(_m: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on deny")

    outcome = await mw.dispatch(msg, handler)
    assert outcome.allowed is False
    assert outcome.acked is True
    assert len(consumer.acked) == 1
    assert receipt_prod.sent == []  # deny does not publish to receipt topic
    assert len(dlq_prod.sent) == 1
    dlq_payload = json.loads(dlq_prod.sent[0]["content"].decode("utf-8"))
    assert dlq_payload["verdict"] == "deny"
    assert dlq_payload["reason"] == "missing scope"
    # Original partition key preserved so re-drive can recover partitioning.
    assert dlq_prod.sent[0]["partition_key"] == "user-9"


async def test_deny_synthesises_receipt_when_sidecar_raises() -> None:
    chio = deny_all("forbidden", raise_on_deny=True)
    mw, consumer, _, dlq = _middleware(chio_client=chio)
    msg = FakePulsarMessage(topic="persistent://public/default/orders")

    async def handler(_m: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on deny")

    outcome = await mw.dispatch(msg, handler)
    assert outcome.receipt.is_denied
    assert len(consumer.acked) == 1
    assert len(dlq.sent) == 1


# ---------------------------------------------------------------------------
# Sidecar unreachable
# ---------------------------------------------------------------------------


async def test_sidecar_failure_raises_without_ack_or_send() -> None:
    class FailingChio:
        async def evaluate_tool_call(self, **_kwargs: Any) -> Any:
            raise ChioConnectionError("down")

    mw, consumer, receipt, dlq = _middleware(chio_client=FailingChio())
    msg = FakePulsarMessage(topic="persistent://public/default/orders")

    async def handler(_m: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run")

    with pytest.raises(ChioStreamingError):
        await mw.dispatch(msg, handler)

    assert consumer.acked == []
    assert consumer.nacked == []
    assert receipt.sent == []
    assert dlq.sent == []


async def test_sidecar_error_can_fail_closed() -> None:
    class FailingChio:
        async def evaluate_tool_call(self, **_kwargs: Any) -> Any:
            raise ChioConnectionError("down")

    cfg = _cfg(on_sidecar_error="deny")
    mw, consumer, _receipt, dlq = _middleware(chio_client=FailingChio(), config=cfg)
    msg = FakePulsarMessage(topic="persistent://public/default/orders")

    async def handler(_m: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on synthesised deny")

    outcome = await mw.dispatch(msg, handler)
    assert outcome.allowed is False
    assert outcome.receipt.decision.guard == "chio-streaming-sidecar"
    assert len(consumer.acked) == 1
    assert len(dlq.sent) == 1


# ---------------------------------------------------------------------------
# Async (awaitable) consumer / producer
# ---------------------------------------------------------------------------


async def test_async_consumer_and_producer_are_awaited() -> None:
    """Pulsar's async client returns coroutines from ack/send; the
    middleware must await them via the ``_maybe_await`` helper."""

    class AsyncConsumer:
        def __init__(self) -> None:
            self.acked: list[Any] = []

        async def acknowledge(self, msg: Any) -> None:
            self.acked.append(msg)

        async def negative_acknowledge(self, msg: Any) -> None:
            self.acked.append(("nack", msg))

    class AsyncProducer:
        def __init__(self) -> None:
            self.sent: list[bytes] = []

        async def send(
            self,
            content: bytes,
            properties: Any = None,
            partition_key: Any = None,
        ) -> Any:
            self.sent.append(content)

    consumer = AsyncConsumer()
    receipt = AsyncProducer()
    dlq = AsyncProducer()
    mw = build_pulsar_middleware(
        consumer=consumer,
        receipt_producer=receipt,
        dlq_producer=dlq,
        chio_client=allow_all(),
        config=_cfg(),
        dlq_topic="persistent://public/default/chio-dlq",
    )
    msg = FakePulsarMessage(topic="persistent://public/default/orders", data=b"hi")

    async def handler(_m: Any, _r: Any) -> None:
        return None

    outcome = await mw.dispatch(msg, handler)
    assert outcome.acked is True
    assert consumer.acked == [msg]
    assert len(receipt.sent) == 1


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def test_config_rejects_bad_handler_strategy() -> None:
    with pytest.raises(ChioStreamingConfigError):
        ChioPulsarConsumerConfig(
            capability_id="c",
            tool_server="t",
            handler_error_strategy="skip",  # type: ignore[arg-type]
        )


def test_middleware_requires_receipt_producer_when_topic_set() -> None:
    with pytest.raises(ChioStreamingConfigError):
        build_pulsar_middleware(
            consumer=FakePulsarConsumer(),
            receipt_producer=None,
            dlq_producer=FakePulsarProducer(),
            chio_client=allow_all(),
            config=_cfg(),
            dlq_topic="persistent://public/default/chio-dlq",
        )


def test_middleware_requires_dlq_router_or_topic() -> None:
    with pytest.raises(ChioStreamingConfigError):
        build_pulsar_middleware(
            consumer=FakePulsarConsumer(),
            receipt_producer=FakePulsarProducer(),
            dlq_producer=FakePulsarProducer(),
            chio_client=allow_all(),
            config=_cfg(),
        )


# ---------------------------------------------------------------------------
# Backpressure
# ---------------------------------------------------------------------------


async def test_backpressure_blocks_when_max_in_flight_reached() -> None:
    cfg = _cfg(max_in_flight=1)
    mw, _c, _r, _d = _middleware(chio_client=allow_all(), config=cfg)

    release = asyncio.Event()
    started = 0
    first_started = asyncio.Event()

    async def slow_handler(_m: Any, _r: Any) -> None:
        nonlocal started
        started += 1
        if started == 1:
            first_started.set()
        await release.wait()

    msg1 = FakePulsarMessage(topic="persistent://public/default/orders")
    msg2 = FakePulsarMessage(topic="persistent://public/default/orders")

    t1 = asyncio.create_task(mw.dispatch(msg1, slow_handler))
    await first_started.wait()
    assert mw.in_flight == 1
    assert started == 1

    t2 = asyncio.create_task(mw.dispatch(msg2, slow_handler))
    await asyncio.sleep(0.1)
    assert started == 1, "second handler ran before slot released"

    release.set()
    await asyncio.wait_for(t1, timeout=2.0)
    await asyncio.wait_for(t2, timeout=2.0)
    assert started == 2
    assert mw.in_flight == 0


# ---------------------------------------------------------------------------
# Publish failure paths
# ---------------------------------------------------------------------------


async def test_dlq_publish_failure_raises_and_does_not_ack() -> None:
    chio = deny_all("missing scope", raise_on_deny=False)
    dlq = FakePulsarProducer(fail=True)
    mw, consumer, _receipt, _ = _middleware(chio_client=chio, dlq_producer=dlq)
    msg = FakePulsarMessage(topic="persistent://public/default/orders")

    async def handler(_m: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on deny")

    with pytest.raises(RuntimeError, match="send failed"):
        await mw.dispatch(msg, handler)

    assert consumer.acked == []
    assert consumer.nacked == []
    assert dlq.sent == []
    assert mw.in_flight == 0


async def test_receipt_publish_failure_does_not_ack() -> None:
    receipt = FakePulsarProducer(fail=True)
    mw, consumer, _receipt_p, _dlq = _middleware(chio_client=allow_all(), receipt_producer=receipt)
    msg = FakePulsarMessage(topic="persistent://public/default/orders")

    ran: list[int] = []

    async def handler(_m: Any, _r: Any) -> None:
        ran.append(1)

    outcome = await mw.dispatch(msg, handler)
    assert ran == [1]
    assert outcome.allowed is True
    assert outcome.acked is False
    assert isinstance(outcome.handler_error, RuntimeError)
    assert consumer.acked == []
    # Handler error path nacks the source.
    assert len(consumer.nacked) == 1
    assert mw.in_flight == 0


# ---------------------------------------------------------------------------
# Receipt envelope byte-exact parity
# ---------------------------------------------------------------------------


async def test_receipt_envelope_matches_build_envelope() -> None:
    mw, _c, receipt_p, _d = _middleware(chio_client=allow_all())
    msg = FakePulsarMessage(
        topic="persistent://public/default/orders",
        data=b'{"k":"v"}',
        properties={"trace": "t"},
        partition_key="k-1",
    )

    async def handler(_m: Any, _r: Any) -> None:
        return None

    outcome = await mw.dispatch(msg, handler)
    expected = build_envelope(
        request_id=outcome.request_id,
        receipt=outcome.receipt,
        source_topic="persistent://public/default/orders",
    )
    assert receipt_p.sent[0]["content"] == expected.value

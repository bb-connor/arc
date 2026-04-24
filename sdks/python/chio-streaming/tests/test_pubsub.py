"""Unit tests for :mod:`chio_streaming.pubsub`."""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
from typing import Any

import pytest
from chio_sdk.errors import ChioConnectionError
from chio_sdk.testing import allow_all, deny_all

from chio_streaming import VERDICT_HEADER
from chio_streaming.errors import ChioStreamingConfigError, ChioStreamingError
from chio_streaming.pubsub import (
    ChioPubSubConfig,
    ChioPubSubMiddleware,
    build_pubsub_middleware,
)
from chio_streaming.receipt import build_envelope


class FakePubSubMessage:
    """Duck-typed
    :class:`google.cloud.pubsub_v1.subscriber.message.Message`."""

    def __init__(
        self,
        *,
        data: bytes = b"",
        attributes: dict[str, str] | None = None,
        message_id: str = "mid-1",
        ordering_key: str = "",
    ) -> None:
        self._data = data
        self._attrs = attributes or {}
        self._mid = message_id
        self._key = ordering_key
        self.ack_called = False
        self.nack_called = False

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def attributes(self) -> dict[str, str]:
        return self._attrs

    @property
    def message_id(self) -> str:
        return self._mid

    @property
    def ordering_key(self) -> str:
        return self._key

    def ack(self) -> None:
        self.ack_called = True

    def nack(self) -> None:
        self.nack_called = True


class FakeFuturePublisher:
    """Sync PublisherClient double returning ``concurrent.futures.Future``.

    ``fail`` makes every publish fail; ``fail_topics`` scopes failures
    to specific topic names so receipt-vs-DLQ failure paths can be
    isolated in tests.
    """

    def __init__(
        self,
        *,
        fail: bool = False,
        fail_topics: set[str] | None = None,
    ) -> None:
        self.published: list[dict[str, Any]] = []
        self._fail = fail
        self._fail_topics = fail_topics or set()

    def publish(
        self,
        topic: str,
        data: bytes,
        *,
        ordering_key: str = "",
        **attributes: str,
    ) -> concurrent.futures.Future[str]:
        fut: concurrent.futures.Future[str] = concurrent.futures.Future()
        if self._fail or topic in self._fail_topics:
            fut.set_exception(RuntimeError("publish failed"))
        else:
            self.published.append(
                {
                    "topic": topic,
                    "data": data,
                    "attributes": dict(attributes),
                    "ordering_key": ordering_key,
                }
            )
            fut.set_result(f"mid-{len(self.published)}")
        return fut


class FakeAwaitablePublisher:
    """Async PublisherClient double returning coroutines."""

    def __init__(self) -> None:
        self.published: list[dict[str, Any]] = []

    def publish(
        self,
        topic: str,
        data: bytes,
        *,
        ordering_key: str = "",
        **attributes: str,
    ) -> Any:
        async def _run() -> str:
            self.published.append(
                {
                    "topic": topic,
                    "data": data,
                    "attributes": dict(attributes),
                }
            )
            return f"mid-{len(self.published)}"

        return _run()


def _cfg(**overrides: Any) -> ChioPubSubConfig:
    base: dict[str, Any] = dict(
        capability_id="cap-pubsub",
        tool_server="gcp:pubsub://prod",
        subscription="projects/p/subscriptions/agent-tasks",
        scope_map={"tasks:research": "events:consume:tasks.research"},
        receipt_topic="projects/p/topics/chio-receipts",
        dlq_topic="projects/p/topics/chio-dlq",
        max_in_flight=4,
    )
    base.update(overrides)
    return ChioPubSubConfig(**base)


def _middleware(
    *,
    chio_client: Any,
    publisher: Any | None = None,
    config: ChioPubSubConfig | None = None,
) -> tuple[ChioPubSubMiddleware, Any]:
    pub = publisher or FakeFuturePublisher()
    mw = build_pubsub_middleware(
        publisher=pub,
        chio_client=chio_client,
        config=config or _cfg(),
        dlq_fallback_topic="chio-pubsub-dlq",
    )
    return mw, pub


# ---------------------------------------------------------------------------
# Allow
# ---------------------------------------------------------------------------


async def test_allow_publishes_receipt_and_acks() -> None:
    mw, pub = _middleware(chio_client=allow_all())
    msg = FakePubSubMessage(
        data=b'{"ok":true}',
        attributes={"subject": "tasks:research", "trace": "abc"},
        message_id="mid-42",
    )

    seen: list[str] = []

    async def handler(m: Any, _r: Any) -> None:
        seen.append(m.message_id)

    outcome = await mw.dispatch(msg, handler)
    assert outcome.allowed is True
    assert outcome.acked is True
    assert msg.ack_called is True
    assert msg.nack_called is False
    assert seen == ["mid-42"]
    assert len(pub.published) == 1
    published = pub.published[0]
    assert published["topic"] == "projects/p/topics/chio-receipts"
    env = json.loads(published["data"].decode("utf-8"))
    assert env["verdict"] == "allow"
    assert published["attributes"][VERDICT_HEADER] == "allow"


async def test_allow_without_receipt_topic_still_acks() -> None:
    cfg = _cfg(receipt_topic=None)
    mw, pub = _middleware(chio_client=allow_all(), config=cfg)
    msg = FakePubSubMessage(attributes={"subject": "tasks:research"})

    async def handler(_m: Any, _r: Any) -> None:
        return None

    outcome = await mw.dispatch(msg, handler)
    assert outcome.acked is True
    assert pub.published == []
    assert msg.ack_called is True


async def test_allow_handler_error_nacks_by_default() -> None:
    mw, pub = _middleware(chio_client=allow_all())
    msg = FakePubSubMessage(attributes={"subject": "tasks:research"})

    def handler(_m: Any, _r: Any) -> None:
        raise RuntimeError("boom")

    outcome = await mw.dispatch(msg, handler)
    assert outcome.allowed is True
    assert outcome.acked is False
    assert isinstance(outcome.handler_error, RuntimeError)
    assert msg.nack_called is True
    assert msg.ack_called is False
    assert pub.published == []


@pytest.mark.parametrize("shutdown_exc", [SystemExit, KeyboardInterrupt, asyncio.CancelledError])
async def test_handler_shutdown_signals_propagate(shutdown_exc: type) -> None:
    # Shutdown signals must surface out of dispatch unchanged.
    mw, pub = _middleware(chio_client=allow_all())
    msg = FakePubSubMessage(attributes={"subject": "tasks:research"})

    def handler(_m: Any, _r: Any) -> None:
        raise shutdown_exc()

    with pytest.raises(shutdown_exc):
        await mw.dispatch(msg, handler)
    assert msg.ack_called is False
    assert msg.nack_called is False
    assert pub.published == []


async def test_allow_handler_error_can_ack() -> None:
    cfg = _cfg(handler_error_strategy="ack")
    mw, _pub = _middleware(chio_client=allow_all(), config=cfg)
    msg = FakePubSubMessage(attributes={"subject": "tasks:research"})

    def handler(_m: Any, _r: Any) -> None:
        raise RuntimeError("boom")

    outcome = await mw.dispatch(msg, handler)
    assert outcome.handler_error is not None
    # acked reflects the broker-level ack; handler failure is surfaced
    # separately via handler_error.
    assert outcome.acked is True
    assert msg.ack_called is True
    assert msg.nack_called is False


# ---------------------------------------------------------------------------
# Deny
# ---------------------------------------------------------------------------


async def test_deny_publishes_dlq_and_acks() -> None:
    chio = deny_all("missing scope", guard="scope-guard", raise_on_deny=False)
    mw, pub = _middleware(chio_client=chio)
    msg = FakePubSubMessage(
        data=b'{"evil":true}',
        attributes={"subject": "tasks:research"},
        message_id="mid-X",
    )

    async def handler(_m: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on deny")

    outcome = await mw.dispatch(msg, handler)
    assert outcome.allowed is False
    assert outcome.acked is True
    assert msg.ack_called is True
    assert len(pub.published) == 1
    dlq = pub.published[0]
    assert dlq["topic"] == "projects/p/topics/chio-dlq"
    payload = json.loads(dlq["data"].decode("utf-8"))
    assert payload["verdict"] == "deny"
    assert payload["reason"] == "missing scope"
    assert payload["metadata"]["pubsub_message_id"] == "mid-X"


async def test_deny_can_nack_to_trigger_native_dlq() -> None:
    chio = deny_all("nope", raise_on_deny=False)
    cfg = _cfg(deny_strategy="nack", dlq_topic=None)
    mw, pub = _middleware(chio_client=chio, config=cfg)
    msg = FakePubSubMessage(attributes={"subject": "tasks:research"})

    async def handler(_m: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on deny")

    outcome = await mw.dispatch(msg, handler)
    assert outcome.allowed is False
    assert outcome.acked is False
    assert msg.nack_called is True
    assert pub.published == []


async def test_deny_nack_strategy_skips_chio_dlq_publish() -> None:
    # Even when a dlq_topic is configured, nack strategy must not
    # publish our DLQ envelope -- doing so would cause a redelivery
    # loop (nack -> redeliver -> re-publish DLQ -> nack ...).
    chio = deny_all("nope", raise_on_deny=False)
    cfg = _cfg(deny_strategy="nack")  # keeps the default dlq_topic
    mw, pub = _middleware(chio_client=chio, config=cfg)
    msg = FakePubSubMessage(attributes={"subject": "tasks:research"})

    async def handler(_m: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on deny")

    outcome = await mw.dispatch(msg, handler)
    assert outcome.allowed is False
    assert outcome.acked is False
    assert msg.nack_called is True
    # Redelivery-loop guard: no DLQ publish under "nack".
    assert pub.published == []
    # Record still surfaces to the caller for observability.
    assert outcome.dlq_record is not None


async def test_deny_with_dlq_topic_unset_still_builds_record() -> None:
    chio = deny_all("no", raise_on_deny=False)
    cfg = _cfg(dlq_topic=None)
    mw, pub = _middleware(chio_client=chio, config=cfg)
    msg = FakePubSubMessage(attributes={"subject": "tasks:research"})

    async def handler(_m: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail()

    outcome = await mw.dispatch(msg, handler)
    assert outcome.dlq_record is not None  # still surfaced to caller
    assert pub.published == []
    assert msg.ack_called is True  # deny_strategy default is "ack"


# ---------------------------------------------------------------------------
# Subject resolution
# ---------------------------------------------------------------------------


async def test_x_chio_subject_wins_over_subject_attribute() -> None:
    captured: list[str] = []

    class Recorder:
        async def evaluate_tool_call(self, **kwargs: Any) -> Any:
            captured.append(kwargs["tool_name"])
            return await allow_all().evaluate_tool_call(**kwargs)

    mw, _pub = _middleware(chio_client=Recorder())
    msg = FakePubSubMessage(
        attributes={
            "X-Chio-Subject": "override:path",
            "subject": "tasks:research",
        }
    )

    async def handler(_m: Any, _r: Any) -> None:
        return None

    await mw.dispatch(msg, handler)
    # Override preserved; default prefix applied because scope_map has
    # no entry for "override:path".
    assert captured == ["events:consume:override:path"]


async def test_subject_falls_back_to_subscription_name() -> None:
    captured: list[str] = []

    class Recorder:
        async def evaluate_tool_call(self, **kwargs: Any) -> Any:
            captured.append(kwargs["tool_name"])
            return await allow_all().evaluate_tool_call(**kwargs)

    mw, _pub = _middleware(chio_client=Recorder())
    msg = FakePubSubMessage(attributes={})

    async def handler(_m: Any, _r: Any) -> None:
        return None

    await mw.dispatch(msg, handler)
    assert captured == ["events:consume:projects/p/subscriptions/agent-tasks"]


# ---------------------------------------------------------------------------
# Publisher shapes
# ---------------------------------------------------------------------------


async def test_awaitable_publisher_is_awaited() -> None:
    mw, pub = _middleware(chio_client=allow_all(), publisher=FakeAwaitablePublisher())
    msg = FakePubSubMessage(attributes={"subject": "tasks:research"})

    async def handler(_m: Any, _r: Any) -> None:
        return None

    outcome = await mw.dispatch(msg, handler)
    assert outcome.acked is True
    assert len(pub.published) == 1


# ---------------------------------------------------------------------------
# Sidecar failure
# ---------------------------------------------------------------------------


async def test_sidecar_failure_raises_without_ack() -> None:
    class FailingChio:
        async def evaluate_tool_call(self, **_kwargs: Any) -> Any:
            raise ChioConnectionError("down")

    mw, pub = _middleware(chio_client=FailingChio())
    msg = FakePubSubMessage(attributes={"subject": "tasks:research"})

    async def handler(_m: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail()

    with pytest.raises(ChioStreamingError):
        await mw.dispatch(msg, handler)
    assert msg.ack_called is False
    assert msg.nack_called is False
    assert pub.published == []


async def test_sidecar_error_can_fail_closed() -> None:
    class FailingChio:
        async def evaluate_tool_call(self, **_kwargs: Any) -> Any:
            raise ChioConnectionError("down")

    cfg = _cfg(on_sidecar_error="deny")
    mw, pub = _middleware(chio_client=FailingChio(), config=cfg)
    msg = FakePubSubMessage(attributes={"subject": "tasks:research"}, data=b"x")

    async def handler(_m: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on synthesised deny")

    outcome = await mw.dispatch(msg, handler)
    assert outcome.allowed is False
    assert outcome.receipt.decision.guard == "chio-streaming-sidecar"
    assert msg.ack_called is True
    assert len(pub.published) == 1
    assert pub.published[0]["topic"] == "projects/p/topics/chio-dlq"


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def test_config_requires_subscription() -> None:
    with pytest.raises(ChioStreamingConfigError):
        ChioPubSubConfig(
            capability_id="c",
            tool_server="t",
            subscription="",
        )


def test_config_rejects_bad_deny_strategy() -> None:
    with pytest.raises(ChioStreamingConfigError):
        ChioPubSubConfig(
            capability_id="c",
            tool_server="t",
            subscription="s",
            deny_strategy="drop",  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# Backpressure
# ---------------------------------------------------------------------------


async def test_backpressure_blocks_when_max_in_flight_reached() -> None:
    cfg = _cfg(max_in_flight=1)
    mw, _pub = _middleware(chio_client=allow_all(), config=cfg)

    release = asyncio.Event()
    started = 0
    first_started = asyncio.Event()

    async def slow_handler(_m: Any, _r: Any) -> None:
        nonlocal started
        started += 1
        if started == 1:
            first_started.set()
        await release.wait()

    msg1 = FakePubSubMessage(attributes={"subject": "tasks:research"})
    msg2 = FakePubSubMessage(attributes={"subject": "tasks:research"})

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
    pub = FakeFuturePublisher(fail_topics={"projects/p/topics/chio-dlq"})
    mw, _ = _middleware(chio_client=chio, publisher=pub)
    msg = FakePubSubMessage(attributes={"subject": "tasks:research"})

    async def handler(_m: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on deny")

    with pytest.raises(RuntimeError, match="publish failed"):
        await mw.dispatch(msg, handler)

    assert msg.ack_called is False
    assert msg.nack_called is False
    assert pub.published == []
    assert mw.in_flight == 0


async def test_receipt_publish_failure_propagates_and_does_not_ack() -> None:
    pub = FakeFuturePublisher(fail_topics={"projects/p/topics/chio-receipts"})
    mw, _ = _middleware(chio_client=allow_all(), publisher=pub)
    msg = FakePubSubMessage(attributes={"subject": "tasks:research"})

    ran: list[int] = []

    async def handler(_m: Any, _r: Any) -> None:
        ran.append(1)

    # Receipt publish is infrastructure, not handler failure. The
    # exception propagates so Pub/Sub redelivers; handler_error_strategy
    # does not reclassify it (otherwise ``handler_error_strategy="ack"``
    # would drop the source message without a receipt).
    with pytest.raises(RuntimeError, match="publish failed"):
        await mw.dispatch(msg, handler)

    assert ran == [1]
    assert msg.ack_called is False
    assert msg.nack_called is False
    assert mw.in_flight == 0


async def test_receipt_publish_failure_not_reclassified_as_handler_error_ack() -> None:
    # Regression: a failed receipt publish under ``handler_error_strategy="ack"``
    # must NOT silently acknowledge the source. The bug was a single
    # ``except Exception`` wrapping invoke_handler AND the receipt publish,
    # so a publish failure hit the handler-error branch and acked the source.
    pub = FakeFuturePublisher(fail_topics={"projects/p/topics/chio-receipts"})
    cfg = _cfg(handler_error_strategy="ack")
    mw, _ = _middleware(chio_client=allow_all(), config=cfg, publisher=pub)
    msg = FakePubSubMessage(attributes={"subject": "tasks:research"})

    async def handler(_m: Any, _r: Any) -> None:
        return None

    with pytest.raises(RuntimeError, match="publish failed"):
        await mw.dispatch(msg, handler)

    assert msg.ack_called is False
    assert msg.nack_called is False


# ---------------------------------------------------------------------------
# Receipt envelope byte-exact parity
# ---------------------------------------------------------------------------


async def test_receipt_envelope_matches_build_envelope() -> None:
    mw, pub = _middleware(chio_client=allow_all())
    msg = FakePubSubMessage(
        data=b'{"k":"v"}',
        attributes={"subject": "tasks:research"},
        message_id="mid-7",
    )

    async def handler(_m: Any, _r: Any) -> None:
        return None

    outcome = await mw.dispatch(msg, handler)
    expected = build_envelope(
        request_id=outcome.request_id,
        receipt=outcome.receipt,
        source_topic="tasks:research",
    )
    assert pub.published[0]["data"] == expected.value


async def test_request_id_is_deterministic_on_redelivery() -> None:
    # Pub/Sub redelivers the same message_id after a failed ack. The
    # middleware must produce the same request_id both times so the
    # receipt stream stays deduplicable on request_id and sidecar
    # evaluations produce byte-identical receipts.
    mw, _pub = _middleware(chio_client=allow_all())

    async def handler(_m: Any, _r: Any) -> None:
        return None

    first = await mw.dispatch(
        FakePubSubMessage(message_id="mid-stable-42", attributes={"subject": "t"}),
        handler,
    )
    second = await mw.dispatch(
        FakePubSubMessage(message_id="mid-stable-42", attributes={"subject": "t"}),
        handler,
    )
    assert first.request_id == second.request_id == "chio-pubsub-mid-stable-42"

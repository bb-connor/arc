"""Unit tests for :mod:`chio_streaming.nats`.

Covers the happy-path allow flow (receipt published, ``msg.ack`` called),
the deny flow (DLQ published, ``msg.ack``/``msg.term``), the handler-
error flow (``msg.nak`` / ``msg.term``), and sidecar failure (propagates
without ack'ing).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from chio_sdk.errors import ChioConnectionError
from chio_sdk.testing import allow_all, deny_all

from chio_streaming import RECEIPT_HEADER, VERDICT_HEADER
from chio_streaming.dlq import DLQRouter
from chio_streaming.errors import ChioStreamingConfigError, ChioStreamingError
from chio_streaming.nats import (
    ChioNatsConsumerConfig,
    ChioNatsMiddleware,
    build_nats_middleware,
)
from chio_streaming.receipt import build_envelope


class FakeNatsMsg:
    """In-memory ``nats.aio.msg.Msg`` duck.

    Tracks which ack method was called so tests can assert the
    redelivery decision.
    """

    def __init__(
        self,
        *,
        subject: str,
        data: bytes = b"",
        headers: dict[str, str] | None = None,
        reply: str | None = None,
    ) -> None:
        self._subject = subject
        self._data = data
        self._headers = headers
        self._reply = reply
        self.ack_called = False
        self.nak_called_with: float | None = None
        self.nak_no_delay = False
        self.term_called = False

    @property
    def subject(self) -> str:
        return self._subject

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def headers(self) -> dict[str, str] | None:
        return self._headers

    @property
    def reply(self) -> str | None:
        return self._reply

    async def ack(self) -> None:
        self.ack_called = True

    async def nak(self, delay: float | None = None) -> None:
        if delay is None:
            self.nak_no_delay = True
        else:
            self.nak_called_with = delay

    async def term(self) -> None:
        self.term_called = True


class FakeJetStream:
    """Records every publish call.

    ``fail_subjects`` selects subjects whose publish must raise. When
    empty, every publish succeeds. Used to exercise DLQ- and receipt-
    publish failure paths.
    """

    def __init__(self, *, fail_subjects: set[str] | None = None) -> None:
        self.published: list[dict[str, Any]] = []
        self._fail_subjects = fail_subjects or set()

    async def publish(
        self,
        subject: str,
        payload: bytes,
        headers: dict[str, str] | None = None,
    ) -> Any:
        if subject in self._fail_subjects:
            raise RuntimeError(f"publish failed for subject={subject}")
        self.published.append(
            {"subject": subject, "payload": payload, "headers": dict(headers or {})}
        )
        return {"seq": len(self.published)}


def _cfg(**overrides: Any) -> ChioNatsConsumerConfig:
    base: dict[str, Any] = dict(
        capability_id="cap-nats",
        tool_server="nats://prod",
        scope_map={"tasks.research": "events:consume:tasks.research"},
        receipt_subject="chio.receipts",
        max_in_flight=4,
    )
    base.update(overrides)
    return ChioNatsConsumerConfig(**base)


def _middleware(
    *,
    chio_client: Any,
    config: ChioNatsConsumerConfig | None = None,
    dlq_subject: str = "chio.dlq",
    js: FakeJetStream | None = None,
) -> tuple[ChioNatsMiddleware, FakeJetStream]:
    publisher = js or FakeJetStream()
    mw = build_nats_middleware(
        publisher=publisher,
        chio_client=chio_client,
        config=config or _cfg(),
        dlq_subject=dlq_subject,
    )
    return mw, publisher


# ---------------------------------------------------------------------------
# Allow
# ---------------------------------------------------------------------------


async def test_allow_publishes_receipt_and_acks() -> None:
    mw, js = _middleware(chio_client=allow_all())
    msg = FakeNatsMsg(subject="tasks.research", data=b'{"ok":true}', headers={"trace": "t"})

    called: list[str] = []

    async def handler(m: Any, _receipt: Any) -> None:
        called.append(m.subject)

    outcome = await mw.dispatch(msg, handler)

    assert outcome.allowed is True
    assert outcome.acked is True
    assert outcome.handler_error is None
    assert called == ["tasks.research"]
    assert msg.ack_called is True
    assert msg.term_called is False
    assert len(js.published) == 1
    published = js.published[0]
    assert published["subject"] == "chio.receipts"
    envelope = json.loads(published["payload"].decode("utf-8"))
    assert envelope["verdict"] == "allow"
    # Verdict header is decoded to str for NATS.
    assert published["headers"][VERDICT_HEADER] == "allow"
    assert RECEIPT_HEADER in published["headers"]


async def test_allow_without_receipt_subject_skips_publish() -> None:
    cfg = _cfg(receipt_subject=None)
    mw, js = _middleware(chio_client=allow_all(), config=cfg)
    msg = FakeNatsMsg(subject="tasks.research", data=b"x")

    async def handler(_m: Any, _r: Any) -> None:
        return None

    outcome = await mw.dispatch(msg, handler)
    assert outcome.allowed is True
    assert outcome.acked is True
    assert js.published == []
    assert msg.ack_called is True


async def test_allow_handler_error_naks_by_default() -> None:
    mw, js = _middleware(chio_client=allow_all())
    msg = FakeNatsMsg(subject="tasks.research")

    def handler(_m: Any, _r: Any) -> None:
        raise RuntimeError("boom")

    outcome = await mw.dispatch(msg, handler)
    assert outcome.allowed is True
    assert outcome.acked is False
    assert isinstance(outcome.handler_error, RuntimeError)
    # No receipt published because the handler failed.
    assert js.published == []
    # nak() was called (without an explicit delay per the default cfg).
    assert msg.nak_no_delay is True
    assert msg.ack_called is False
    assert msg.term_called is False


@pytest.mark.parametrize("shutdown_exc", [SystemExit, KeyboardInterrupt, asyncio.CancelledError])
async def test_handler_shutdown_signals_propagate(shutdown_exc: type) -> None:
    # Wave 1 replaced `except BaseException` with `except Exception` so
    # shutdown signals must surface out of dispatch unchanged.
    mw, _js = _middleware(chio_client=allow_all())
    msg = FakeNatsMsg(subject="tasks.research")

    def handler(_m: Any, _r: Any) -> None:
        raise shutdown_exc()

    with pytest.raises(shutdown_exc):
        await mw.dispatch(msg, handler)
    # No ack/nak/term ran because the exception short-circuited the path.
    assert msg.ack_called is False
    assert msg.nak_no_delay is False
    assert msg.term_called is False


async def test_allow_handler_error_terms_when_configured() -> None:
    cfg = _cfg(handler_error_strategy="term")
    mw, js = _middleware(chio_client=allow_all(), config=cfg)
    msg = FakeNatsMsg(subject="tasks.research")

    def handler(_m: Any, _r: Any) -> None:
        raise RuntimeError("boom")

    outcome = await mw.dispatch(msg, handler)
    # term() terminally settles the message — mirrors the deny-term
    # path which also reports acked=True.
    assert outcome.acked is True
    assert msg.term_called is True
    assert msg.nak_no_delay is False
    assert msg.nak_called_with is None


async def test_allow_handler_error_nak_with_delay() -> None:
    cfg = _cfg(nack_delay=2.5)
    mw, _js = _middleware(chio_client=allow_all(), config=cfg)
    msg = FakeNatsMsg(subject="tasks.research")

    def handler(_m: Any, _r: Any) -> None:
        raise RuntimeError("boom")

    await mw.dispatch(msg, handler)
    assert msg.nak_called_with == 2.5


# ---------------------------------------------------------------------------
# Deny
# ---------------------------------------------------------------------------


async def test_deny_publishes_dlq_and_acks() -> None:
    chio = deny_all("missing scope", guard="scope-guard", raise_on_deny=False)
    mw, js = _middleware(chio_client=chio)
    msg = FakeNatsMsg(subject="tasks.research", data=b'{"payload":"x"}')

    async def handler(_m: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on deny")

    outcome = await mw.dispatch(msg, handler)

    assert outcome.allowed is False
    assert outcome.acked is True
    assert msg.ack_called is True
    assert msg.term_called is False
    assert len(js.published) == 1
    dlq = js.published[0]
    assert dlq["subject"] == "chio.dlq"
    payload = json.loads(dlq["payload"].decode("utf-8"))
    assert payload["verdict"] == "deny"
    assert payload["reason"] == "missing scope"
    assert payload["source"]["topic"] == "tasks.research"


async def test_deny_can_term_when_configured() -> None:
    chio = deny_all("nope", raise_on_deny=False)
    cfg = _cfg(deny_strategy="term")
    mw, _js = _middleware(chio_client=chio, config=cfg)
    msg = FakeNatsMsg(subject="tasks.research")

    async def handler(_m: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on deny")

    outcome = await mw.dispatch(msg, handler)
    assert outcome.allowed is False
    assert outcome.acked is True
    assert msg.term_called is True
    assert msg.ack_called is False


async def test_deny_handles_sidecar_403_by_synthesising_receipt() -> None:
    chio = deny_all("forbidden", guard="kernel", raise_on_deny=True)
    mw, js = _middleware(chio_client=chio)
    msg = FakeNatsMsg(subject="tasks.research")

    async def handler(_m: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on synthesised deny")

    outcome = await mw.dispatch(msg, handler)
    assert outcome.allowed is False
    assert outcome.receipt.is_denied
    assert outcome.acked is True
    assert js.published[0]["subject"] == "chio.dlq"


# ---------------------------------------------------------------------------
# Sidecar unreachable
# ---------------------------------------------------------------------------


async def test_sidecar_unreachable_raises_without_ack() -> None:
    class FailingChio:
        async def evaluate_tool_call(self, **_kwargs: Any) -> Any:
            raise ChioConnectionError("sidecar down")

    mw, js = _middleware(chio_client=FailingChio())
    msg = FakeNatsMsg(subject="tasks.research")

    async def handler(_m: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run when sidecar is down")

    with pytest.raises(ChioStreamingError):
        await mw.dispatch(msg, handler)

    assert js.published == []
    assert msg.ack_called is False
    assert msg.nak_no_delay is False
    assert msg.term_called is False


async def test_sidecar_error_can_fail_closed() -> None:
    class FailingChio:
        async def evaluate_tool_call(self, **_kwargs: Any) -> Any:
            raise ChioConnectionError("down")

    cfg = _cfg(on_sidecar_error="deny")
    mw, js = _middleware(chio_client=FailingChio(), config=cfg)
    msg = FakeNatsMsg(subject="tasks.research", data=b"x")

    async def handler(_m: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on synthesised deny")

    outcome = await mw.dispatch(msg, handler)
    assert outcome.allowed is False
    assert outcome.receipt.decision.guard == "chio-streaming-sidecar"
    assert msg.ack_called is True
    assert len(js.published) == 1
    assert js.published[0]["subject"] == "chio.dlq"


# ---------------------------------------------------------------------------
# Config / factory
# ---------------------------------------------------------------------------


def test_config_rejects_bad_ack_strategy() -> None:
    with pytest.raises(ChioStreamingConfigError):
        ChioNatsConsumerConfig(
            capability_id="c",
            tool_server="t",
            deny_strategy="bogus",  # type: ignore[arg-type]
        )


def test_config_rejects_bad_handler_error_strategy() -> None:
    with pytest.raises(ChioStreamingConfigError):
        ChioNatsConsumerConfig(
            capability_id="c",
            tool_server="t",
            handler_error_strategy="reject",  # type: ignore[arg-type]
        )


def test_build_middleware_requires_router_or_subject() -> None:
    with pytest.raises(ChioStreamingConfigError):
        build_nats_middleware(
            publisher=FakeJetStream(),
            chio_client=allow_all(),
            config=_cfg(),
        )


def test_build_middleware_accepts_explicit_router() -> None:
    router = DLQRouter(default_topic="dlq-x")
    mw = build_nats_middleware(
        publisher=FakeJetStream(),
        chio_client=allow_all(),
        config=_cfg(),
        dlq_router=router,
    )
    assert isinstance(mw, ChioNatsMiddleware)


async def test_scope_map_fallback_uses_default_prefix() -> None:
    cfg = _cfg(scope_map={})
    captured: list[dict[str, Any]] = []

    class RecordingChio:
        async def evaluate_tool_call(self, **kwargs: Any) -> Any:
            captured.append(kwargs)
            return await allow_all().evaluate_tool_call(**kwargs)

    mw, _js = _middleware(chio_client=RecordingChio(), config=cfg)
    msg = FakeNatsMsg(subject="tasks.urgent")

    async def handler(_m: Any, _r: Any) -> None:
        return None

    await mw.dispatch(msg, handler)
    assert captured[0]["tool_name"] == "events:consume:tasks.urgent"


# ---------------------------------------------------------------------------
# Backpressure
# ---------------------------------------------------------------------------


async def test_backpressure_blocks_when_max_in_flight_reached() -> None:
    cfg = _cfg(max_in_flight=1)
    mw, _ = _middleware(chio_client=allow_all(), config=cfg)

    release = asyncio.Event()
    started = 0
    first_started = asyncio.Event()

    async def slow_handler(_m: Any, _r: Any) -> None:
        nonlocal started
        started += 1
        if started == 1:
            first_started.set()
        await release.wait()

    msg1 = FakeNatsMsg(subject="tasks.research")
    msg2 = FakeNatsMsg(subject="tasks.research")

    t1 = asyncio.create_task(mw.dispatch(msg1, slow_handler))
    await first_started.wait()
    assert mw.in_flight == 1
    assert started == 1

    t2 = asyncio.create_task(mw.dispatch(msg2, slow_handler))
    await asyncio.sleep(0.1)
    assert started == 1, "second handler ran before slot released"
    assert mw.in_flight == 1

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
    js = FakeJetStream(fail_subjects={"chio.dlq"})
    mw, _ = _middleware(chio_client=chio, js=js)
    msg = FakeNatsMsg(subject="tasks.research")

    async def handler(_m: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on deny")

    with pytest.raises(RuntimeError, match="publish failed"):
        await mw.dispatch(msg, handler)

    assert msg.ack_called is False
    assert msg.term_called is False
    assert js.published == []
    # Slot was released; another dispatch puts in_flight back to 0.
    assert mw.in_flight == 0


async def test_receipt_publish_failure_propagates_and_does_not_ack() -> None:
    js = FakeJetStream(fail_subjects={"chio.receipts"})
    mw, _ = _middleware(chio_client=allow_all(), js=js)
    msg = FakeNatsMsg(subject="tasks.research", data=b"x")

    ran: list[int] = []

    async def handler(_m: Any, _r: Any) -> None:
        ran.append(1)

    # Handler ran successfully, but the receipt publish is an
    # infrastructure failure, not a handler error. The exception
    # propagates so the caller can nak / retry; handler_error_strategy
    # does not reclassify it.
    with pytest.raises(RuntimeError, match="publish failed"):
        await mw.dispatch(msg, handler)

    assert ran == [1]
    assert msg.ack_called is False
    assert msg.nak_no_delay is False
    assert mw.in_flight == 0


async def test_receipt_publish_failure_not_reclassified_under_term_strategy() -> None:
    # Regression: a failed receipt publish must not route through
    # _negative_ack and consume the message via term(). The bug was a
    # single ``except Exception`` wrapping invoke_handler AND the receipt
    # publish; with ``handler_error_strategy="term"`` that silently
    # terminated the source on infra failures.
    js = FakeJetStream(fail_subjects={"chio.receipts"})
    cfg = _cfg(handler_error_strategy="term")
    mw, _ = _middleware(chio_client=allow_all(), js=js, config=cfg)
    msg = FakeNatsMsg(subject="tasks.research", data=b"x")

    async def handler(_m: Any, _r: Any) -> None:
        return None

    with pytest.raises(RuntimeError, match="publish failed"):
        await mw.dispatch(msg, handler)

    assert msg.ack_called is False
    assert msg.term_called is False
    assert msg.nak_no_delay is False


# ---------------------------------------------------------------------------
# Negative-ack TypeError fallback
# ---------------------------------------------------------------------------


async def test_negative_ack_falls_back_when_nak_rejects_delay_kwarg() -> None:
    # Some nats-py versions only accept nak() without kwargs. The
    # middleware must catch TypeError and retry without the delay.
    class OldNatsMsg(FakeNatsMsg):
        async def nak(self, delay: float | None = None) -> None:  # type: ignore[override]
            if delay is not None:
                raise TypeError("nak() got unexpected keyword 'delay'")
            self.nak_no_delay = True

    cfg = _cfg(nack_delay=1.0)
    mw, _ = _middleware(chio_client=allow_all(), config=cfg)
    msg = OldNatsMsg(subject="tasks.research")

    def handler(_m: Any, _r: Any) -> None:
        raise RuntimeError("boom")

    outcome = await mw.dispatch(msg, handler)
    assert outcome.acked is False
    assert msg.nak_no_delay is True


# ---------------------------------------------------------------------------
# Receipt envelope byte-exact parity
# ---------------------------------------------------------------------------


async def test_receipt_envelope_matches_build_envelope() -> None:
    mw, js = _middleware(chio_client=allow_all())
    msg = FakeNatsMsg(subject="tasks.research", data=b'{"k":"v"}')

    async def handler(_m: Any, _r: Any) -> None:
        return None

    outcome = await mw.dispatch(msg, handler)
    assert outcome.allowed is True
    expected = build_envelope(
        request_id=outcome.request_id,
        receipt=outcome.receipt,
        source_topic="tasks.research",
    )
    published = js.published[0]
    assert published["payload"] == expected.value

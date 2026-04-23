"""Unit tests for :mod:`chio_streaming.eventbridge`."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from chio_sdk.errors import ChioConnectionError
from chio_sdk.testing import allow_all, deny_all

from chio_streaming.errors import ChioStreamingConfigError
from chio_streaming.eventbridge import (
    ChioEventBridgeConfig,
    ChioEventBridgeHandler,
    build_eventbridge_handler,
)
from chio_streaming.receipt import build_envelope


class FakeEventsClient:
    """Records put_events calls.

    ``fail`` makes every put_events raise; ``fail_buses`` scopes
    failures to entries targeting specific EventBusName values (so DLQ
    and receipt failures can be isolated).
    """

    def __init__(
        self,
        *,
        fail: bool = False,
        fail_buses: set[str] | None = None,
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self._fail = fail
        self._fail_buses = fail_buses or set()

    def put_events(self, *, Entries: list[dict[str, Any]]) -> dict[str, Any]:
        if self._fail:
            raise RuntimeError("put_events failed")
        if self._fail_buses:
            for entry in Entries:
                if entry.get("EventBusName") in self._fail_buses:
                    raise RuntimeError(f"put_events failed for bus={entry.get('EventBusName')}")
        self.calls.append({"Entries": list(Entries)})
        return {"FailedEntryCount": 0, "Entries": [{"EventId": "eb-1"}]}


def _event(detail_type: str = "OrderPlaced", detail: Any = None) -> dict[str, Any]:
    return {
        "version": "0",
        "id": "evt-abc",
        "detail-type": detail_type,
        "source": "com.example.orders",
        "account": "111122223333",
        "time": "2026-04-23T00:00:00Z",
        "region": "us-east-1",
        "resources": [],
        "detail": detail if detail is not None else {"order_id": "o-1"},
    }


def _cfg(**overrides: Any) -> ChioEventBridgeConfig:
    base: dict[str, Any] = dict(
        capability_id="cap-eb",
        tool_server="aws:events://prod",
        scope_map={"OrderPlaced": "events:consume:OrderPlaced"},
        receipt_bus="chio-receipt-bus",
        dlq_bus="chio-dlq-bus",
    )
    base.update(overrides)
    return ChioEventBridgeConfig(**base)


def _handler(
    *,
    chio_client: Any,
    config: ChioEventBridgeConfig | None = None,
    events_client: FakeEventsClient | None = None,
) -> tuple[ChioEventBridgeHandler, FakeEventsClient]:
    ec = events_client or FakeEventsClient()
    h = build_eventbridge_handler(
        chio_client=chio_client,
        events_client=ec,
        config=config or _cfg(),
        dlq_fallback_topic="chio-eventbridge-dlq",
    )
    return h, ec


# ---------------------------------------------------------------------------
# Allow
# ---------------------------------------------------------------------------


async def test_allow_publishes_receipt_entry_and_runs_handler() -> None:
    h, ec = _handler(chio_client=allow_all())
    event = _event()

    seen: list[str] = []

    async def handler(evt: Any, _r: Any) -> None:
        seen.append(evt["detail-type"])

    outcome = await h.evaluate(event, handler=handler)
    assert outcome.allowed is True
    assert outcome.handler_error is None
    assert seen == ["OrderPlaced"]
    assert outcome.lambda_response()["statusCode"] == 200

    # put_events called once for the receipt entry.
    assert len(ec.calls) == 1
    entry = ec.calls[0]["Entries"][0]
    assert entry["EventBusName"] == "chio-receipt-bus"
    assert entry["Source"] == "chio.protocol.receipts"
    assert entry["DetailType"] == "ChioReceiptEmitted"
    body = json.loads(entry["Detail"])
    assert body["verdict"] == "allow"


async def test_allow_without_receipt_bus_skips_put_events() -> None:
    cfg = _cfg(receipt_bus=None)
    h, ec = _handler(chio_client=allow_all(), config=cfg)
    outcome = await h.evaluate(_event())
    assert outcome.allowed is True
    assert outcome.acked is True
    assert ec.calls == []


async def test_allow_outcome_reports_acked_true() -> None:
    # Successful evaluations must surface acked=True so broker-agnostic
    # observability code does not misclassify Lambda completions as
    # uncommitted.
    h, _ec = _handler(chio_client=allow_all())
    outcome = await h.evaluate(_event())
    assert outcome.allowed is True
    assert outcome.acked is True


async def test_deny_outcome_reports_acked_true() -> None:
    chio = deny_all("forbidden", raise_on_deny=False)
    h, _ec = _handler(chio_client=chio)
    outcome = await h.evaluate(_event())
    assert outcome.allowed is False
    assert outcome.acked is True


@pytest.mark.parametrize("shutdown_exc", [SystemExit, KeyboardInterrupt, asyncio.CancelledError])
async def test_handler_shutdown_signals_propagate(shutdown_exc: type) -> None:
    # Wave 1 replaced `except BaseException` with `except Exception` so
    # shutdown signals must surface out of evaluate() unchanged.
    h, ec = _handler(chio_client=allow_all())

    def handler(_evt: Any, _r: Any) -> None:
        raise shutdown_exc()

    with pytest.raises(shutdown_exc):
        await h.evaluate(_event(), handler=handler)
    # No put_events was attempted because the handler unwound the stack.
    assert ec.calls == []


async def test_allow_handler_error_re_raises_by_default() -> None:
    # Default handler_error_strategy="raise" so the Lambda invocation
    # errors and EventBridge retry / target DLQ fire. A strategy that
    # swallowed the exception would silently drop failed business work.
    h, ec = _handler(chio_client=allow_all())

    def handler(_evt: Any, _r: Any) -> None:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        await h.evaluate(_event(), handler=handler)
    assert ec.calls == []


async def test_allow_handler_error_return_strategy_surfaces_outcome() -> None:
    # Opt-in soft-fail mode keeps the pre-0.3 behaviour: the Lambda
    # invocation succeeds and the caller inspects outcome.handler_error.
    cfg = _cfg(handler_error_strategy="return")
    h, ec = _handler(chio_client=allow_all(), config=cfg)

    def handler(_evt: Any, _r: Any) -> None:
        raise RuntimeError("boom")

    outcome = await h.evaluate(_event(), handler=handler)
    assert outcome.allowed is True
    assert isinstance(outcome.handler_error, RuntimeError)
    assert ec.calls == []
    assert outcome.lambda_response()["statusCode"] == 500


# ---------------------------------------------------------------------------
# Deny
# ---------------------------------------------------------------------------


async def test_deny_publishes_dlq_entry() -> None:
    chio = deny_all("forbidden", guard="scope-guard", raise_on_deny=False)
    h, ec = _handler(chio_client=chio)

    outcome = await h.evaluate(_event())
    assert outcome.allowed is False
    assert outcome.dlq_record is not None
    assert outcome.dlq_put_response is not None
    assert len(ec.calls) == 1
    entry = ec.calls[0]["Entries"][0]
    assert entry["EventBusName"] == "chio-dlq-bus"
    assert entry["Source"] == "chio.protocol.dlq"
    assert entry["DetailType"] == "ChioCapabilityDenied"
    dlq_body = json.loads(entry["Detail"])
    assert dlq_body["verdict"] == "deny"
    assert dlq_body["reason"] == "forbidden"
    # EventBridge metadata threaded through.
    assert dlq_body["metadata"]["eventbridge_source"] == "com.example.orders"
    resp = outcome.lambda_response()
    assert resp["statusCode"] == 403
    assert resp["reason"] == "forbidden"


async def test_deny_without_dlq_bus_skips_put_events() -> None:
    chio = deny_all("nope", raise_on_deny=False)
    cfg = _cfg(dlq_bus=None)
    h, ec = _handler(chio_client=chio, config=cfg)
    outcome = await h.evaluate(_event())
    assert outcome.allowed is False
    assert outcome.dlq_record is not None  # still built for the caller
    assert ec.calls == []


async def test_deny_synthesises_receipt_on_sidecar_403() -> None:
    chio = deny_all("forbidden", raise_on_deny=True)
    h, ec = _handler(chio_client=chio)
    outcome = await h.evaluate(_event())
    assert outcome.receipt.is_denied
    assert len(ec.calls) == 1


# ---------------------------------------------------------------------------
# Sidecar error behaviour
# ---------------------------------------------------------------------------


async def test_sidecar_error_raises_by_default() -> None:
    class FailingChio:
        async def evaluate_tool_call(self, **_kwargs: Any) -> Any:
            raise ChioConnectionError("down")

    from chio_streaming.errors import ChioStreamingError

    h, ec = _handler(chio_client=FailingChio())
    with pytest.raises(ChioStreamingError):
        await h.evaluate(_event())
    assert ec.calls == []


async def test_sidecar_error_can_fail_closed() -> None:
    class FailingChio:
        async def evaluate_tool_call(self, **_kwargs: Any) -> Any:
            raise ChioConnectionError("down")

    cfg = _cfg(on_sidecar_error="deny")
    h, ec = _handler(chio_client=FailingChio(), config=cfg)
    outcome = await h.evaluate(_event())
    assert outcome.allowed is False
    assert outcome.receipt.decision.guard == "chio-streaming-sidecar"
    # DLQ publish should have happened since dlq_bus is set.
    assert len(ec.calls) == 1


# ---------------------------------------------------------------------------
# Detail-type resolution
# ---------------------------------------------------------------------------


async def test_camel_case_detailType_is_recognised() -> None:
    # Some producers use camelCase detailType; handler should still work.
    chio = allow_all()
    h, _ec = _handler(chio_client=chio)
    event = {
        "version": "0",
        "id": "x",
        "detailType": "IncidentDetected",
        "source": "com.x",
        "detail": {"k": 1},
    }
    outcome = await h.evaluate(event)
    assert outcome.allowed is True
    assert outcome.detail_type == "IncidentDetected"


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def test_config_rejects_bad_sidecar_error() -> None:
    with pytest.raises(ChioStreamingConfigError):
        ChioEventBridgeConfig(
            capability_id="c",
            tool_server="t",
            on_sidecar_error="bogus",  # type: ignore[arg-type]
        )


def test_handler_requires_events_client_when_dlq_bus_set() -> None:
    with pytest.raises(ChioStreamingConfigError):
        build_eventbridge_handler(
            chio_client=allow_all(),
            events_client=None,
            config=_cfg(),
        )


def test_handler_without_buses_can_omit_events_client() -> None:
    cfg = _cfg(receipt_bus=None, dlq_bus=None)
    handler = build_eventbridge_handler(
        chio_client=allow_all(),
        events_client=None,
        config=cfg,
        dlq_fallback_topic="chio-eventbridge-dlq",
    )
    assert isinstance(handler, ChioEventBridgeHandler)


# ---------------------------------------------------------------------------
# Failed-entry fail-closed semantics
# ---------------------------------------------------------------------------


class FailingEntriesClient:
    """EventBridge client that reports a per-entry failure."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def put_events(self, *, Entries: list[dict[str, Any]]) -> dict[str, Any]:
        self.calls.append({"Entries": list(Entries)})
        return {
            "FailedEntryCount": 1,
            "Entries": [
                {
                    "ErrorCode": "InternalException",
                    "ErrorMessage": "bus is sad",
                }
            ],
        }


async def test_receipt_partial_failure_raises() -> None:
    from chio_streaming.errors import ChioStreamingError

    h, _ = _handler(chio_client=allow_all(), events_client=FailingEntriesClient())
    with pytest.raises(ChioStreamingError) as excinfo:
        await h.evaluate(_event())
    assert "InternalException" in str(excinfo.value)


async def test_dlq_partial_failure_raises() -> None:
    from chio_streaming.errors import ChioStreamingError

    chio = deny_all("nope", raise_on_deny=False)
    h, _ = _handler(chio_client=chio, events_client=FailingEntriesClient())
    with pytest.raises(ChioStreamingError) as excinfo:
        await h.evaluate(_event())
    assert "InternalException" in str(excinfo.value)


async def test_fail_closed_dlq_partial_failure_still_raises() -> None:
    # on_sidecar_error="deny" routes sidecar failures through the DLQ
    # path. If the DLQ put_events response carries FailedEntryCount > 0,
    # the Lambda must see a raised ChioStreamingError rather than a
    # 403 outcome that hides the dropped entry.
    from chio_streaming.errors import ChioStreamingError

    class FailingChio:
        async def evaluate_tool_call(self, **_kwargs: Any) -> Any:
            raise ChioConnectionError("down")

    cfg = _cfg(on_sidecar_error="deny")
    h = build_eventbridge_handler(
        chio_client=FailingChio(),
        events_client=FailingEntriesClient(),
        config=cfg,
        dlq_fallback_topic="chio-eventbridge-dlq",
    )
    with pytest.raises(ChioStreamingError) as excinfo:
        await h.evaluate(_event())
    assert "InternalException" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Per-entry size limits
# ---------------------------------------------------------------------------


async def test_oversize_dlq_truncates_original_value() -> None:
    # Build a deny event whose original body is larger than the
    # EventBridge per-entry cap. The DLQ Detail must be rewritten with
    # original_value removed and a truncation marker set.
    chio = deny_all("too big", raise_on_deny=False)
    ec = FakeEventsClient()
    h = build_eventbridge_handler(
        chio_client=chio,
        events_client=ec,
        config=_cfg(),
        dlq_fallback_topic="chio-eventbridge-dlq",
    )
    huge_detail = {"blob": "x" * 260_000}
    outcome = await h.evaluate(_event(detail=huge_detail))
    assert outcome.allowed is False
    assert len(ec.calls) == 1
    dlq_detail = json.loads(ec.calls[0]["Entries"][0]["Detail"])
    assert dlq_detail.get("original_value_truncated") is True
    assert "original_value" not in dlq_detail


# ---------------------------------------------------------------------------
# Concurrent evaluate: EventBridge has no Slots because Lambda enforces
# per-function concurrency externally. This test only asserts that two
# concurrent evaluate() calls complete independently; it is the closest
# analogue to the per-broker backpressure tests.
# ---------------------------------------------------------------------------


async def test_concurrent_evaluate_calls_are_independent() -> None:
    h, ec = _handler(chio_client=allow_all())

    release = asyncio.Event()
    ran = 0

    async def slow(_evt: Any, _r: Any) -> None:
        nonlocal ran
        ran += 1
        await release.wait()

    t1 = asyncio.create_task(h.evaluate(_event(), handler=slow))
    t2 = asyncio.create_task(h.evaluate(_event(), handler=slow))
    await asyncio.sleep(0.05)
    # Both handlers enter concurrently (no Slots wrapper).
    assert ran == 2
    release.set()
    outcomes = await asyncio.wait_for(asyncio.gather(t1, t2), timeout=2.0)
    assert all(o.allowed for o in outcomes)
    assert len(ec.calls) == 2


# ---------------------------------------------------------------------------
# Publish failure paths
# ---------------------------------------------------------------------------


async def test_dlq_publish_failure_raises_and_does_not_ack() -> None:
    # EventBridge Lambda has no ack; "not acking" means re-raising so
    # Lambda retries. Asserting the DLQ put failure propagates fulfils
    # the same invariant.
    chio = deny_all("forbidden", raise_on_deny=False)
    ec = FakeEventsClient(fail_buses={"chio-dlq-bus"})
    h = build_eventbridge_handler(
        chio_client=chio,
        events_client=ec,
        config=_cfg(),
        dlq_fallback_topic="chio-eventbridge-dlq",
    )
    with pytest.raises(RuntimeError, match="put_events failed"):
        await h.evaluate(_event())
    assert ec.calls == []


async def test_receipt_publish_failure_does_not_ack() -> None:
    # On allow, a failed receipt put_events must propagate so Lambda
    # retries. Handler completed but receipt publish blows up.
    ec = FakeEventsClient(fail_buses={"chio-receipt-bus"})
    h = build_eventbridge_handler(
        chio_client=allow_all(),
        events_client=ec,
        config=_cfg(),
        dlq_fallback_topic="chio-eventbridge-dlq",
    )
    ran: list[int] = []

    async def handler(_e: Any, _r: Any) -> None:
        ran.append(1)

    with pytest.raises(RuntimeError, match="put_events failed"):
        await h.evaluate(_event(), handler=handler)
    assert ran == [1]
    assert ec.calls == []


# ---------------------------------------------------------------------------
# Receipt envelope byte-exact parity
# ---------------------------------------------------------------------------


async def test_receipt_envelope_matches_build_envelope() -> None:
    h, ec = _handler(chio_client=allow_all())

    async def handler(_e: Any, _r: Any) -> None:
        return None

    outcome = await h.evaluate(_event(), handler=handler)
    expected = build_envelope(
        request_id=outcome.request_id,
        receipt=outcome.receipt,
        source_topic="OrderPlaced",
    )
    detail_bytes = ec.calls[0]["Entries"][0]["Detail"].encode("utf-8")
    assert detail_bytes == expected.value

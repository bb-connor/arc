"""Unit tests for :mod:`chio_streaming.redis_streams`."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from chio_sdk.errors import ChioConnectionError
from chio_sdk.testing import allow_all, deny_all

from chio_streaming import VERDICT_HEADER
from chio_streaming.errors import ChioStreamingConfigError, ChioStreamingError
from chio_streaming.receipt import build_envelope
from chio_streaming.redis_streams import (
    ChioRedisStreamsConfig,
    ChioRedisStreamsMiddleware,
    build_redis_streams_middleware,
)


class FakeRedisStreams:
    """In-memory async redis-py double with XADD / XACK.

    ``fail_streams`` lets tests inject failures on specific stream
    names; ``fail`` fails every XADD. Used to exercise DLQ- and
    receipt-publish failure paths.
    """

    def __init__(
        self,
        *,
        xadd_kwargs_supported: bool = True,
        fail: bool = False,
        fail_streams: set[str] | None = None,
    ) -> None:
        self.xadded: list[dict[str, Any]] = []
        self.xacked: list[dict[str, Any]] = []
        self._xadd_kwargs_supported = xadd_kwargs_supported
        self._counter = 0
        self._fail = fail
        self._fail_streams = fail_streams or set()

    async def xadd(
        self,
        name: str,
        fields: dict[Any, Any],
        id: str | bytes = "*",
        maxlen: int | None = None,
        approximate: bool = True,
    ) -> bytes:
        if self._fail or name in self._fail_streams:
            raise RuntimeError(f"xadd failed for stream={name}")
        if not self._xadd_kwargs_supported and maxlen is not None:
            # Some older redis-py versions do not accept maxlen kwarg.
            raise TypeError("unexpected keyword 'maxlen'")
        self._counter += 1
        entry_id = f"{self._counter}-0"
        self.xadded.append(
            {
                "stream": name,
                "fields": dict(fields),
                "maxlen": maxlen,
                "approximate": approximate,
                "entry_id": entry_id,
            }
        )
        return entry_id.encode("utf-8")

    async def xack(self, name: str, groupname: str, *ids: str | bytes) -> int:
        self.xacked.append({"stream": name, "group": groupname, "ids": list(ids)})
        return len(ids)


def _cfg(**overrides: Any) -> ChioRedisStreamsConfig:
    base: dict[str, Any] = dict(
        capability_id="cap-redis",
        tool_server="redis://prod",
        group_name="agent-swarm",
        scope_map={"tasks": "events:consume:tasks"},
        receipt_stream="chio-receipts",
        receipt_maxlen=10_000,
        dlq_maxlen=10_000,
        max_in_flight=4,
    )
    base.update(overrides)
    return ChioRedisStreamsConfig(**base)


def _middleware(
    *,
    chio_client: Any,
    config: ChioRedisStreamsConfig | None = None,
    client: FakeRedisStreams | None = None,
) -> tuple[ChioRedisStreamsMiddleware, FakeRedisStreams]:
    r = client or FakeRedisStreams()
    mw = build_redis_streams_middleware(
        client=r,
        chio_client=chio_client,
        config=config or _cfg(),
        dlq_stream="chio-dlq",
    )
    return mw, r


# ---------------------------------------------------------------------------
# Allow
# ---------------------------------------------------------------------------


async def test_allow_xadds_receipt_and_xacks() -> None:
    mw, r = _middleware(chio_client=allow_all())

    seen: list[str] = []

    async def handler(entry: Any, _receipt: Any) -> None:
        seen.append(entry.entry_id)

    outcome = await mw.dispatch(
        stream="tasks",
        entry_id="100-0",
        fields={b"payload": b'{"ok":true}', b"trace": b"t"},
        handler=handler,
    )

    assert outcome.allowed is True
    assert outcome.acked is True
    assert outcome.handler_error is None
    assert seen == ["100-0"]

    # One XADD for the receipt, one XACK for the source.
    assert len(r.xadded) == 1
    receipt_xadd = r.xadded[0]
    assert receipt_xadd["stream"] == "chio-receipts"
    assert receipt_xadd["maxlen"] == 10_000
    assert receipt_xadd["approximate"] is True
    payload = json.loads(receipt_xadd["fields"]["payload"].decode("utf-8"))
    assert payload["verdict"] == "allow"
    assert receipt_xadd["fields"][VERDICT_HEADER] == b"allow"

    assert len(r.xacked) == 1
    assert r.xacked[0] == {
        "stream": "tasks",
        "group": "agent-swarm",
        "ids": ["100-0"],
    }


async def test_allow_without_receipt_stream_still_xacks() -> None:
    cfg = _cfg(receipt_stream=None)
    mw, r = _middleware(chio_client=allow_all(), config=cfg)

    async def handler(_e: Any, _r: Any) -> None:
        return None

    outcome = await mw.dispatch(
        stream="tasks", entry_id="200-0", fields={b"k": b"v"}, handler=handler
    )
    assert outcome.acked is True
    assert r.xadded == []
    assert len(r.xacked) == 1


async def test_allow_handler_error_keeps_entry_in_pel() -> None:
    mw, r = _middleware(chio_client=allow_all())

    def handler(_e: Any, _r: Any) -> None:
        raise RuntimeError("boom")

    outcome = await mw.dispatch(
        stream="tasks", entry_id="300-0", fields={b"k": b"v"}, handler=handler
    )
    assert outcome.allowed is True
    assert outcome.acked is False
    assert isinstance(outcome.handler_error, RuntimeError)
    # Handler error skips the receipt XADD AND the XACK, so the entry
    # stays in the PEL for XCLAIM / XAUTOCLAIM redelivery.
    assert r.xadded == []
    assert r.xacked == []


@pytest.mark.parametrize("shutdown_exc", [SystemExit, KeyboardInterrupt, asyncio.CancelledError])
async def test_handler_shutdown_signals_propagate(shutdown_exc: type) -> None:
    # Wave 1 replaced `except BaseException` with `except Exception` so
    # shutdown signals must surface out of dispatch unchanged.
    mw, r = _middleware(chio_client=allow_all())

    def handler(_e: Any, _r: Any) -> None:
        raise shutdown_exc()

    with pytest.raises(shutdown_exc):
        await mw.dispatch(
            stream="tasks",
            entry_id="350-0",
            fields={b"k": b"v"},
            handler=handler,
        )
    assert r.xadded == []
    assert r.xacked == []


async def test_allow_handler_error_ack_strategy_xacks() -> None:
    cfg = _cfg(handler_error_strategy="ack")
    mw, r = _middleware(chio_client=allow_all(), config=cfg)

    def handler(_e: Any, _r: Any) -> None:
        raise RuntimeError("boom")

    outcome = await mw.dispatch(
        stream="tasks", entry_id="301-0", fields={b"k": b"v"}, handler=handler
    )
    assert outcome.handler_error is not None
    # Entry XACK'd despite the failure, but "acked" still reflects
    # whether the happy-path completed.
    assert len(r.xacked) == 1
    # A handler-error receipt envelope must still be published so the
    # audit trail records the dropped entry -- otherwise "ack" strategy
    # would silently swallow the failure.
    assert len(r.xadded) == 1
    assert r.xadded[0]["stream"] == "chio-receipts"
    error_payload = json.loads(r.xadded[0]["fields"]["payload"].decode("utf-8"))
    assert error_payload["metadata"]["handler_error"] == "boom"
    assert error_payload["metadata"]["source_entry_id"] == "301-0"


async def test_ack_handler_error_strategy_requires_receipt_stream() -> None:
    # "ack" without receipt_stream would drop the entry with no audit
    # trail; the config must reject the combination up front.
    with pytest.raises(ChioStreamingConfigError):
        ChioRedisStreamsConfig(
            capability_id="c",
            tool_server="t",
            group_name="g",
            handler_error_strategy="ack",
            receipt_stream=None,
        )


# ---------------------------------------------------------------------------
# Deny
# ---------------------------------------------------------------------------


async def test_deny_xadds_dlq_and_xacks() -> None:
    chio = deny_all("missing scope", guard="scope-guard", raise_on_deny=False)
    mw, r = _middleware(chio_client=chio)

    async def handler(_e: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on deny")

    outcome = await mw.dispatch(
        stream="tasks",
        entry_id="400-0",
        fields={b"payload": b'{"evil":true}'},
        handler=handler,
    )
    assert outcome.allowed is False
    assert outcome.acked is True
    assert len(r.xadded) == 1
    dlq = r.xadded[0]
    assert dlq["stream"] == "chio-dlq"
    payload = json.loads(dlq["fields"]["payload"].decode("utf-8"))
    assert payload["verdict"] == "deny"
    assert payload["reason"] == "missing scope"
    # DLQ XADD has the entry id preserved via metadata.
    assert payload["metadata"]["redis_entry_id"] == "400-0"
    assert len(r.xacked) == 1


async def test_deny_keep_strategy_leaves_entry_pending() -> None:
    chio = deny_all("nope", raise_on_deny=False)
    cfg = _cfg(deny_strategy="keep")
    mw, r = _middleware(chio_client=chio, config=cfg)

    async def handler(_e: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on deny")

    outcome = await mw.dispatch(
        stream="tasks", entry_id="401-0", fields={b"k": b"v"}, handler=handler
    )
    assert outcome.acked is False
    # DLQ still published, but the source is NOT xacked.
    assert len(r.xadded) == 1
    assert r.xacked == []


# ---------------------------------------------------------------------------
# XACK semantics
# ---------------------------------------------------------------------------


async def test_xack_returning_zero_sets_acked_false() -> None:
    # XACK returns 0 when the entry is not in the consumer group's PEL
    # (claimed by another consumer or already acked). The outcome must
    # reflect that the ack did not take effect.
    class XackZeroClient(FakeRedisStreams):
        async def xack(self, name: str, groupname: str, *ids: str | bytes) -> int:
            self.xacked.append({"stream": name, "group": groupname, "ids": list(ids)})
            return 0

    client = XackZeroClient()
    mw, _ = _middleware(chio_client=allow_all(), client=client)

    async def handler(_e: Any, _r: Any) -> None:
        return None

    outcome = await mw.dispatch(
        stream="tasks", entry_id="1-0", fields={b"k": b"v"}, handler=handler
    )
    assert outcome.acked is False
    assert len(client.xacked) == 1


async def test_xack_returning_zero_on_deny_sets_acked_false() -> None:
    class XackZeroClient(FakeRedisStreams):
        async def xack(self, name: str, groupname: str, *ids: str | bytes) -> int:
            self.xacked.append({"stream": name, "group": groupname, "ids": list(ids)})
            return 0

    client = XackZeroClient()
    chio = deny_all("nope", raise_on_deny=False)
    mw, _ = _middleware(chio_client=chio, client=client)

    async def handler(_e: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on deny")

    outcome = await mw.dispatch(
        stream="tasks", entry_id="2-0", fields={b"k": b"v"}, handler=handler
    )
    assert outcome.allowed is False
    assert outcome.acked is False


# ---------------------------------------------------------------------------
# Client compatibility
# ---------------------------------------------------------------------------


async def test_xadd_kwargs_fallback_when_unsupported() -> None:
    client = FakeRedisStreams(xadd_kwargs_supported=False)
    mw, _r = _middleware(chio_client=allow_all(), client=client)

    async def handler(_e: Any, _r: Any) -> None:
        return None

    outcome = await mw.dispatch(
        stream="tasks", entry_id="500-0", fields={b"k": b"v"}, handler=handler
    )
    assert outcome.acked is True
    # The XADD retried without maxlen -- recorded with maxlen=None
    # since that branch does not call the kwargs version.
    assert len(client.xadded) == 1
    assert client.xadded[0]["maxlen"] is None


async def test_fields_with_str_keys_work() -> None:
    mw, r = _middleware(chio_client=allow_all())

    async def handler(entry: Any, _r: Any) -> None:
        # Fields preserved (with bytes or str keys) on the handler view.
        assert "body" in entry.fields or b"body" in entry.fields

    outcome = await mw.dispatch(
        stream="tasks",
        entry_id="600-0",
        fields={"body": "hello"},  # str keys / values
        handler=handler,
    )
    assert outcome.acked is True
    assert len(r.xadded) == 1


# ---------------------------------------------------------------------------
# Sidecar failure
# ---------------------------------------------------------------------------


async def test_sidecar_failure_raises_without_xadd_or_xack() -> None:
    class FailingChio:
        async def evaluate_tool_call(self, **_kwargs: Any) -> Any:
            raise ChioConnectionError("down")

    mw, r = _middleware(chio_client=FailingChio())

    async def handler(_e: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail()

    with pytest.raises(ChioStreamingError):
        await mw.dispatch(
            stream="tasks",
            entry_id="700-0",
            fields={b"k": b"v"},
            handler=handler,
        )
    assert r.xadded == []
    assert r.xacked == []


async def test_sidecar_error_can_fail_closed() -> None:
    class FailingChio:
        async def evaluate_tool_call(self, **_kwargs: Any) -> Any:
            raise ChioConnectionError("down")

    cfg = _cfg(on_sidecar_error="deny")
    mw, r = _middleware(chio_client=FailingChio(), config=cfg)

    async def handler(_e: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on synthesised deny")

    outcome = await mw.dispatch(
        stream="tasks",
        entry_id="701-0",
        fields={b"k": b"v"},
        handler=handler,
    )
    assert outcome.allowed is False
    assert outcome.receipt.decision.guard == "chio-streaming-sidecar"
    # DLQ XADD happened and the source entry was XACK'd.
    assert len(r.xadded) == 1
    assert r.xadded[0]["stream"] == "chio-dlq"
    assert len(r.xacked) == 1


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def test_config_requires_group_name() -> None:
    with pytest.raises(ChioStreamingConfigError):
        ChioRedisStreamsConfig(capability_id="c", tool_server="t", group_name="")


def test_config_rejects_bad_deny_strategy() -> None:
    with pytest.raises(ChioStreamingConfigError):
        ChioRedisStreamsConfig(
            capability_id="c",
            tool_server="t",
            group_name="g",
            deny_strategy="drop",  # type: ignore[arg-type]
        )


def test_build_requires_router_or_stream() -> None:
    with pytest.raises(ChioStreamingConfigError):
        build_redis_streams_middleware(
            client=FakeRedisStreams(),
            chio_client=allow_all(),
            config=_cfg(),
        )


def test_build_accepts_explicit_router() -> None:
    from chio_streaming.dlq import DLQRouter

    mw = build_redis_streams_middleware(
        client=FakeRedisStreams(),
        chio_client=allow_all(),
        config=_cfg(),
        dlq_router=DLQRouter(default_topic="dlq-x"),
    )
    assert isinstance(mw, ChioRedisStreamsMiddleware)


# ---------------------------------------------------------------------------
# Backpressure
# ---------------------------------------------------------------------------


async def test_backpressure_blocks_when_max_in_flight_reached() -> None:
    cfg = _cfg(max_in_flight=1)
    mw, _r = _middleware(chio_client=allow_all(), config=cfg)

    release = asyncio.Event()
    started = 0
    first_started = asyncio.Event()

    async def slow_handler(_e: Any, _r: Any) -> None:
        nonlocal started
        started += 1
        if started == 1:
            first_started.set()
        await release.wait()

    t1 = asyncio.create_task(
        mw.dispatch(
            stream="tasks",
            entry_id="1-0",
            fields={b"k": b"v"},
            handler=slow_handler,
        )
    )
    await first_started.wait()
    assert mw.in_flight == 1
    assert started == 1

    t2 = asyncio.create_task(
        mw.dispatch(
            stream="tasks",
            entry_id="2-0",
            fields={b"k": b"v"},
            handler=slow_handler,
        )
    )
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
    chio = deny_all("nope", raise_on_deny=False)
    client = FakeRedisStreams(fail_streams={"chio-dlq"})
    mw, _ = _middleware(chio_client=chio, client=client)

    async def handler(_e: Any, _r: Any) -> None:  # pragma: no cover
        pytest.fail("handler should not run on deny")

    with pytest.raises(RuntimeError, match="xadd failed"):
        await mw.dispatch(
            stream="tasks",
            entry_id="9-0",
            fields={b"k": b"v"},
            handler=handler,
        )

    assert client.xacked == []
    assert client.xadded == []
    assert mw.in_flight == 0


async def test_receipt_publish_failure_does_not_ack() -> None:
    client = FakeRedisStreams(fail_streams={"chio-receipts"})
    mw, _ = _middleware(chio_client=allow_all(), client=client)

    ran: list[int] = []

    async def handler(_e: Any, _r: Any) -> None:
        ran.append(1)

    outcome = await mw.dispatch(
        stream="tasks",
        entry_id="10-0",
        fields={b"k": b"v"},
        handler=handler,
    )
    assert ran == [1]
    assert outcome.allowed is True
    assert outcome.acked is False
    assert isinstance(outcome.handler_error, RuntimeError)
    assert client.xacked == []
    assert mw.in_flight == 0


# ---------------------------------------------------------------------------
# Receipt envelope byte-exact parity
# ---------------------------------------------------------------------------


async def test_receipt_envelope_matches_build_envelope() -> None:
    mw, client = _middleware(chio_client=allow_all())

    async def handler(_e: Any, _r: Any) -> None:
        return None

    outcome = await mw.dispatch(
        stream="tasks",
        entry_id="11-0",
        fields={b"k": b"v"},
        handler=handler,
    )
    expected = build_envelope(
        request_id=outcome.request_id,
        receipt=outcome.receipt,
        source_topic="tasks",
        extra_metadata={"source_entry_id": "11-0"},
    )
    receipt_xadd = client.xadded[0]
    assert receipt_xadd["stream"] == "chio-receipts"
    assert receipt_xadd["fields"]["payload"] == expected.value

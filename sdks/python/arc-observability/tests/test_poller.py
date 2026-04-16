"""Unit tests for :class:`ReceiptPoller`."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import pytest
from arc_sdk.models import ArcReceipt
from conftest import build_receipt

from arc_observability import (
    ArcObservabilityConfigError,
    ArcObservabilityError,
    ReceiptPoller,
)

# ---------------------------------------------------------------------------
# Fake bridge
# ---------------------------------------------------------------------------


@dataclass
class RecordingBridge:
    """In-memory bridge that captures every published receipt."""

    BACKEND_NAME: str = "recording"
    fail: bool = False
    published: list[ArcReceipt] = field(default_factory=list)

    def publish(
        self,
        receipt: ArcReceipt,
        *,
        tool_result: Any | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        if self.fail:
            raise RuntimeError("mock bridge failure")
        self.published.append(receipt)
        return {"ok": True}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class TestConfiguration:
    def test_non_positive_interval_rejected(self) -> None:
        with pytest.raises(ArcObservabilityConfigError):
            ReceiptPoller(source=lambda: [], bridges=[], interval_seconds=0)

    def test_non_positive_cache_rejected(self) -> None:
        with pytest.raises(ArcObservabilityConfigError):
            ReceiptPoller(
                source=lambda: [],
                bridges=[],
                interval_seconds=1.0,
                dedupe_cache_size=0,
            )

    def test_backoff_must_be_ge_interval(self) -> None:
        with pytest.raises(ArcObservabilityConfigError):
            ReceiptPoller(
                source=lambda: [],
                bridges=[],
                interval_seconds=5.0,
                max_backoff_seconds=1.0,
            )


# ---------------------------------------------------------------------------
# poll_once
# ---------------------------------------------------------------------------


class TestPollOnce:
    async def test_sync_source_forwards_receipts(self) -> None:
        bridge = RecordingBridge()
        r1 = build_receipt(receipt_id="r1")
        poller = ReceiptPoller(
            source=lambda: [r1],
            bridges=[bridge],
            interval_seconds=1.0,
        )
        new = await poller.poll_once()
        assert [r.id for r in new] == ["r1"]
        assert [r.id for r in bridge.published] == ["r1"]

    async def test_async_source_is_awaited(self) -> None:
        bridge = RecordingBridge()
        r1 = build_receipt(receipt_id="r1")

        async def source() -> list[ArcReceipt]:
            return [r1]

        poller = ReceiptPoller(
            source=source,
            bridges=[bridge],
            interval_seconds=1.0,
        )
        new = await poller.poll_once()
        assert [r.id for r in new] == ["r1"]

    async def test_duplicates_are_deduped_across_polls(self) -> None:
        bridge = RecordingBridge()
        r1 = build_receipt(receipt_id="r1")
        r2 = build_receipt(receipt_id="r2")
        batches = [[r1], [r1, r2], [r2]]

        def source() -> list[ArcReceipt]:
            return batches.pop(0)

        poller = ReceiptPoller(
            source=source,
            bridges=[bridge],
            interval_seconds=1.0,
        )
        await poller.poll_once()
        await poller.poll_once()
        await poller.poll_once()
        assert [r.id for r in bridge.published] == ["r1", "r2"]

    async def test_bridge_error_is_routed_to_on_error(self) -> None:
        bridge = RecordingBridge(fail=True)
        errors: list[tuple[BaseException, ArcReceipt | None, str | None]] = []

        def on_error(
            exc: BaseException,
            receipt: ArcReceipt | None,
            backend: str | None,
        ) -> None:
            errors.append((exc, receipt, backend))

        poller = ReceiptPoller(
            source=lambda: [build_receipt(receipt_id="r1")],
            bridges=[bridge],
            interval_seconds=1.0,
            on_error=on_error,
        )
        await poller.poll_once()
        assert len(errors) == 1
        assert errors[0][1] is not None
        assert errors[0][2] == "recording"

    async def test_source_error_wrapped(self) -> None:
        def source() -> list[ArcReceipt]:
            raise RuntimeError("source boom")

        poller = ReceiptPoller(
            source=source,
            bridges=[RecordingBridge()],
            interval_seconds=1.0,
        )
        with pytest.raises(ArcObservabilityError):
            await poller.poll_once()

    async def test_source_must_return_list(self) -> None:
        def source() -> Any:
            return {"not": "a list"}

        poller = ReceiptPoller(
            source=source,
            bridges=[RecordingBridge()],
            interval_seconds=1.0,
        )
        with pytest.raises(ArcObservabilityError):
            await poller.poll_once()

    async def test_dedupe_cache_eviction(self) -> None:
        bridge = RecordingBridge()
        receipts = [build_receipt(receipt_id=f"r{i}") for i in range(4)]
        batches = [[r] for r in receipts] + [[receipts[0]]]

        def source() -> list[ArcReceipt]:
            return batches.pop(0)

        poller = ReceiptPoller(
            source=source,
            bridges=[bridge],
            interval_seconds=1.0,
            dedupe_cache_size=2,
        )
        for _ in range(4):
            await poller.poll_once()
        # Fifth poll returns r0 again; cache has already evicted r0 so
        # it is treated as new and republished.
        await poller.poll_once()
        assert [r.id for r in bridge.published] == [
            "r0",
            "r1",
            "r2",
            "r3",
            "r0",
        ]


# ---------------------------------------------------------------------------
# start/stop
# ---------------------------------------------------------------------------


class TestLifecycle:
    async def test_start_and_stop_runs_one_iteration(self) -> None:
        bridge = RecordingBridge()
        calls = asyncio.Event()
        receipts = [build_receipt(receipt_id="r1")]

        def source() -> list[ArcReceipt]:
            calls.set()
            return receipts

        poller = ReceiptPoller(
            source=source,
            bridges=[bridge],
            interval_seconds=0.01,
        )
        await poller.start()
        await asyncio.wait_for(calls.wait(), timeout=1.0)
        await poller.stop()
        assert len(bridge.published) >= 1
        assert poller.is_running is False

    async def test_start_is_idempotent(self) -> None:
        poller = ReceiptPoller(
            source=lambda: [],
            bridges=[],
            interval_seconds=0.05,
        )
        await poller.start()
        await poller.start()
        await poller.stop()

    async def test_stop_without_start_is_noop(self) -> None:
        poller = ReceiptPoller(
            source=lambda: [],
            bridges=[],
            interval_seconds=0.05,
        )
        await poller.stop()

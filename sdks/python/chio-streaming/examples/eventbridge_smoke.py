"""End-to-end smoke test for ``ChioEventBridgeHandler``.

Wires the Lambda-style handler against a stub boto3 events client and
the ``chio_sdk.testing`` mock policy clients, then runs one allow case
and one deny case so the receipt-bus and DLQ-bus put_events paths fire
without AWS credentials.

Run:

    cd sdks/python/chio-streaming
    uv run python examples/eventbridge_smoke.py

Exits 0 on success. Output prints the request_id, decision, the
EventBridge bus the envelope landed on, and the synthesised Lambda
response status code.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

from chio_sdk.testing import allow_all, deny_all

from chio_streaming.eventbridge import (
    ChioEventBridgeConfig,
    build_eventbridge_handler,
)


class FakeEventsClient:
    """Records put_events calls (mirrors tests/test_eventbridge.py)."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def put_events(self, *, Entries: list[dict[str, Any]]) -> dict[str, Any]:
        self.calls.append({"Entries": list(Entries)})
        return {"FailedEntryCount": 0, "Entries": [{"EventId": "eb-1"}]}


def _config() -> ChioEventBridgeConfig:
    return ChioEventBridgeConfig(
        capability_id="cap-eb-smoke",
        tool_server="aws:events://smoke",
        scope_map={"OrderPlaced": "events:consume:OrderPlaced"},
        receipt_bus="chio-receipt-bus",
        dlq_bus="chio-dlq-bus",
    )


def _event(detail: Any) -> dict[str, Any]:
    return {
        "version": "0",
        "id": "evt-smoke-1",
        "detail-type": "OrderPlaced",
        "source": "com.example.orders",
        "account": "111122223333",
        "time": "2026-04-23T00:00:00Z",
        "region": "us-east-1",
        "resources": [],
        "detail": detail,
    }


async def run_allow() -> None:
    ec = FakeEventsClient()
    h = build_eventbridge_handler(
        chio_client=allow_all(),
        events_client=ec,
        config=_config(),
        dlq_fallback_topic="chio-eventbridge-dlq",
    )

    handler_ran: list[str] = []

    async def handler(evt: Any, _r: Any) -> None:
        handler_ran.append(evt["detail-type"])

    outcome = await h.evaluate(_event({"order_id": "o-1"}), handler=handler)

    assert outcome.allowed and outcome.acked
    assert handler_ran == ["OrderPlaced"]
    entry = ec.calls[0]["Entries"][0]
    body = json.loads(entry["Detail"])
    resp = outcome.lambda_response()
    print(
        f"[allow] request_id={outcome.request_id} verdict={body['verdict']} "
        f"receipt_bus={entry['EventBusName']} status={resp['statusCode']}"
    )


async def run_deny() -> None:
    ec = FakeEventsClient()
    h = build_eventbridge_handler(
        chio_client=deny_all("forbidden", guard="scope-guard", raise_on_deny=False),
        events_client=ec,
        config=_config(),
        dlq_fallback_topic="chio-eventbridge-dlq",
    )

    async def handler(_evt: Any, _r: Any) -> None:
        raise AssertionError("handler must not run on deny")

    outcome = await h.evaluate(_event({"order_id": "o-evil"}), handler=handler)

    assert not outcome.allowed and outcome.acked
    entry = ec.calls[0]["Entries"][0]
    body = json.loads(entry["Detail"])
    resp = outcome.lambda_response()
    print(
        f"[deny]  request_id={outcome.request_id} verdict={body['verdict']} "
        f"reason={body['reason']!r} dlq_bus={entry['EventBusName']} status={resp['statusCode']}"
    )


async def main() -> None:
    print("ChioEventBridgeHandler smoke test (no AWS required)")
    await run_allow()
    await run_deny()
    print("ok")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as exc:  # pragma: no cover - smoke script
        print(f"ERROR: {exc!r}", file=sys.stderr)
        sys.exit(1)

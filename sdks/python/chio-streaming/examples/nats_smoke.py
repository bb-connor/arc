"""End-to-end smoke test for ``ChioNatsMiddleware``.

Wires the middleware against an in-memory JetStream double and the
``chio_sdk.testing`` mock policy clients, then runs one allow case and
one deny case so the full envelope / DLQ paths are exercised without a
real NATS server.

Run:

    cd sdks/python/chio-streaming
    uv run python examples/nats_smoke.py

Exits 0 on success. Output prints the request_id, decision, ack state,
and the subject the receipt or DLQ envelope landed on.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

from chio_sdk.testing import allow_all, deny_all

from chio_streaming.nats import ChioNatsConsumerConfig, build_nats_middleware


class FakeNatsMsg:
    """Minimal duck of ``nats.aio.msg.Msg`` (mirrors tests/test_nats.py)."""

    def __init__(self, *, subject: str, data: bytes, headers: dict[str, str] | None = None) -> None:
        self._subject = subject
        self._data = data
        self._headers = headers
        self.ack_called = False
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
        return None

    async def ack(self) -> None:
        self.ack_called = True

    async def nak(self, delay: float | None = None) -> None:
        return None

    async def term(self) -> None:
        self.term_called = True


class FakeJetStream:
    """Records every publish; mirrors tests/test_nats.py FakeJetStream."""

    def __init__(self) -> None:
        self.published: list[dict[str, Any]] = []

    async def publish(
        self,
        subject: str,
        payload: bytes,
        headers: dict[str, str] | None = None,
    ) -> dict[str, int]:
        self.published.append({"subject": subject, "payload": payload})
        return {"seq": len(self.published)}


def _config() -> ChioNatsConsumerConfig:
    return ChioNatsConsumerConfig(
        capability_id="cap-nats-smoke",
        tool_server="nats://smoke",
        scope_map={"tasks.research": "events:consume:tasks.research"},
        receipt_subject="chio.receipts",
        max_in_flight=4,
    )


async def run_allow() -> None:
    js = FakeJetStream()
    mw = build_nats_middleware(
        publisher=js,
        chio_client=allow_all(),
        config=_config(),
        dlq_subject="chio.dlq",
    )
    msg = FakeNatsMsg(
        subject="tasks.research",
        data=b'{"task":"summarise"}',
        headers={"Nats-Msg-Id": "smoke-allow-1"},
    )

    handler_ran: list[str] = []

    async def handler(m: Any, _receipt: Any) -> None:
        handler_ran.append(m.subject)

    outcome = await mw.dispatch(msg, handler)

    assert outcome.allowed and outcome.acked and msg.ack_called
    assert handler_ran == ["tasks.research"]
    receipt = js.published[0]
    envelope = json.loads(receipt["payload"].decode("utf-8"))
    print(
        f"[allow] request_id={outcome.request_id} verdict={envelope['verdict']} "
        f"acked={outcome.acked} receipt_subject={receipt['subject']}"
    )


async def run_deny() -> None:
    js = FakeJetStream()
    mw = build_nats_middleware(
        publisher=js,
        chio_client=deny_all("missing scope", guard="scope-guard", raise_on_deny=False),
        config=_config(),
        dlq_subject="chio.dlq",
    )
    msg = FakeNatsMsg(subject="tasks.research", data=b'{"task":"exfil"}')

    async def handler(_m: Any, _r: Any) -> None:
        raise AssertionError("handler must not run on deny")

    outcome = await mw.dispatch(msg, handler)

    assert not outcome.allowed and outcome.acked and msg.ack_called
    dlq = js.published[0]
    envelope = json.loads(dlq["payload"].decode("utf-8"))
    print(
        f"[deny]  request_id={outcome.request_id} verdict={envelope['verdict']} "
        f"reason={envelope['reason']!r} dlq_subject={dlq['subject']}"
    )


async def main() -> None:
    print("ChioNatsMiddleware smoke test (no broker required)")
    await run_allow()
    await run_deny()
    print("ok")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as exc:  # pragma: no cover - smoke script
        print(f"ERROR: {exc!r}", file=sys.stderr)
        sys.exit(1)

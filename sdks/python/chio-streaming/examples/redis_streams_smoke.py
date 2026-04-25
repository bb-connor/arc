"""End-to-end smoke test for ``ChioRedisStreamsMiddleware``.

Wires the middleware against an in-memory async redis-py double and the
``chio_sdk.testing`` mock policy clients, then runs one allow case and
one deny case so the receipt XADD / DLQ XADD / XACK paths fire without
a real Redis instance.

Run:

    cd sdks/python/chio-streaming
    uv run python examples/redis_streams_smoke.py

Exits 0 on success. Output prints the request_id, decision, ack state,
and the stream the receipt or DLQ entry landed on.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

from chio_sdk.testing import allow_all, deny_all

from chio_streaming.redis_streams import (
    ChioRedisStreamsConfig,
    build_redis_streams_middleware,
)


class FakeRedisStreams:
    """Minimal async redis-py double (mirrors tests/test_redis_streams.py)."""

    def __init__(self) -> None:
        self.xadded: list[dict[str, Any]] = []
        self.xacked: list[dict[str, Any]] = []
        self._counter = 0

    async def xadd(
        self,
        name: str,
        fields: dict[Any, Any],
        id: str | bytes = "*",
        maxlen: int | None = None,
        approximate: bool = True,
    ) -> bytes:
        self._counter += 1
        entry_id = f"{self._counter}-0"
        self.xadded.append(
            {"stream": name, "fields": dict(fields), "entry_id": entry_id}
        )
        return entry_id.encode("utf-8")

    async def xack(self, name: str, groupname: str, *ids: str | bytes) -> int:
        self.xacked.append({"stream": name, "group": groupname, "ids": list(ids)})
        return len(ids)


def _config() -> ChioRedisStreamsConfig:
    return ChioRedisStreamsConfig(
        capability_id="cap-redis-smoke",
        tool_server="redis://smoke",
        group_name="agent-swarm",
        scope_map={"tasks": "events:consume:tasks"},
        receipt_stream="chio-receipts",
        receipt_maxlen=10_000,
        dlq_maxlen=10_000,
        max_in_flight=4,
    )


async def run_allow() -> None:
    client = FakeRedisStreams()
    mw = build_redis_streams_middleware(
        client=client,
        chio_client=allow_all(),
        config=_config(),
        dlq_stream="chio-dlq",
    )

    handler_ran: list[str] = []

    async def handler(entry: Any, _receipt: Any) -> None:
        handler_ran.append(entry.entry_id)

    outcome = await mw.dispatch(
        stream="tasks",
        entry_id="100-0",
        fields={b"payload": b'{"task":"summarise"}'},
        handler=handler,
    )

    assert outcome.allowed and outcome.acked
    assert handler_ran == ["100-0"]
    assert client.xacked and client.xacked[0]["stream"] == "tasks"
    receipt_xadd = client.xadded[0]
    envelope = json.loads(receipt_xadd["fields"]["payload"].decode("utf-8"))
    print(
        f"[allow] request_id={outcome.request_id} verdict={envelope['verdict']} "
        f"acked={outcome.acked} receipt_stream={receipt_xadd['stream']}"
    )


async def run_deny() -> None:
    client = FakeRedisStreams()
    mw = build_redis_streams_middleware(
        client=client,
        chio_client=deny_all("missing scope", guard="scope-guard", raise_on_deny=False),
        config=_config(),
        dlq_stream="chio-dlq",
    )

    async def handler(_e: Any, _r: Any) -> None:
        raise AssertionError("handler must not run on deny")

    outcome = await mw.dispatch(
        stream="tasks",
        entry_id="200-0",
        fields={b"payload": b'{"task":"exfil"}'},
        handler=handler,
    )

    assert not outcome.allowed and outcome.acked
    dlq = client.xadded[0]
    envelope = json.loads(dlq["fields"]["payload"].decode("utf-8"))
    print(
        f"[deny]  request_id={outcome.request_id} verdict={envelope['verdict']} "
        f"reason={envelope['reason']!r} dlq_stream={dlq['stream']}"
    )


async def main() -> None:
    print("ChioRedisStreamsMiddleware smoke test (no broker required)")
    await run_allow()
    await run_deny()
    print("ok")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as exc:  # pragma: no cover - smoke script
        print(f"ERROR: {exc!r}", file=sys.stderr)
        sys.exit(1)

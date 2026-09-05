"""Run real LangChain tools through the Chio Rust kernel, without a model key."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
from pathlib import Path

from chio_langchain.mcp import ChioMcpToolError, ChioMcpToolkit
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def run(chio: str, state: Path) -> dict:
    here = Path(__file__).resolve().parent
    journal = state / "journal.jsonl"
    parameters = StdioServerParameters(
        command=chio,
        args=[
            "--session-db",
            str(state / "session.sqlite"),
            "--receipt-db",
            str(state / "receipts.sqlite"),
            "mcp",
            "serve",
            "--policy",
            str(here / "policy.yaml"),
            "--server-id",
            "journal",
            "--",
            sys.executable,
            str(here / "tools.py"),
            str(journal),
        ],
    )
    async with (
        stdio_client(parameters) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        # This file is written by the operator-owned kernel process. Never
        # obtain a trusted signer from a tool result or an untrusted peer.
        signer = (state / "session.sqlite.kernel.pub").read_text().strip()
        toolkit = ChioMcpToolkit(session, server_id="journal", trusted_signers=[signer])
        tools = await toolkit.get_tools()
        assert len(tools) == 1, [tool.name for tool in tools]
        tool = tools[0]
        receipts = []
        for number in range(3):
            try:
                result = await tool.ainvoke(
                    {
                        "type": "tool_call",
                        "name": tool.name,
                        "id": f"note-{number}",
                        "args": {"note": f"Verified note {number + 1}: 世界"},
                    }
                )
            except ChioMcpToolError as error:
                assert number == 2, error
                assert error.output is None
                receipts.append(error.receipt)
            else:
                assert number < 2, "exhausted grant allowed another effect"
                assert result.status == "success", result
                receipts.append(result.artifact["receipt"])
        entries = [json.loads(line) for line in journal.read_text().splitlines()]
        assert len(entries) == 2, entries
        assert [receipt["decision"]["verdict"] for receipt in receipts] == [
            "allow",
            "allow",
            "deny",
        ]
        evidence = {
            "effects": entries,
            "receipts": receipts,
            "trusted_kernel_key": signer,
        }
        (state / "evidence.json").write_text(
            json.dumps(evidence, indent=2, ensure_ascii=False)
        )
        return {
            "effects": len(entries),
            "verified_receipts": len(receipts),
            "denied_before_effect": True,
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--chio", required=True, help="Path to the compiled chio binary"
    )
    parser.add_argument(
        "--state-dir", type=Path, help="New private directory for this run"
    )
    args = parser.parse_args()
    if args.state_dir:
        args.state_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        print(json.dumps(asyncio.run(run(args.chio, args.state_dir.resolve()))))
    else:
        with tempfile.TemporaryDirectory(prefix="chio-langchain-") as temporary:
            print(json.dumps(asyncio.run(run(args.chio, Path(temporary)))))


if __name__ == "__main__":
    main()

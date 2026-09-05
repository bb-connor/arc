"""Accept an imported MCP configuration against a real kernel and tool process."""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from chio.mcp import VerifiedMcpSession
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def exercise(config: dict, report: dict, note: str):
    server = config["mcpServers"]["journal"]
    entry = report["wrapped_servers"][0]
    parameters = StdioServerParameters(
        command=server["command"], args=server["args"], env=server["env"]
    )
    async with (
        stdio_client(parameters) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        signer = Path(entry["kernel_public_key_file"]).read_text().strip()
        verified = VerifiedMcpSession(
            session, server_id="journal", trusted_signers=[signer]
        )
        receipts = []
        for index in range(3):
            result = await verified.call_tool(
                "append_note", {"note": f"{note}-{index}"}
            )
            assert result.allowed == (index < 2), result
            if result.allowed:
                # Chio's MCP adapter retains the upstream JSON text content.
                # Read it from the verified output, before MCP display projection.
                body = json.loads(result.output["content"][0]["text"])
                assert body["operator_label"] == server["env"]["OPERATOR_LABEL"]
            receipts.append(result.receipt)
        return signer, receipts


def run(chio: str, state: Path) -> None:
    repo = Path(__file__).resolve().parents[2]
    journal = state / "journal.jsonl"
    original = {
        "preferences": {"theme": "dark"},
        "mcpServers": {
            "journal": {
                "command": sys.executable,
                "args": [
                    str(repo / "examples/mcp-adoption/server.py"),
                ],
                "env": {
                    "JOURNAL_PATH": str(journal),
                    "OPERATOR_LABEL": "literal value with spaces",
                },
            }
        },
    }
    original_path = state / "original.json"
    original_bytes = json.dumps(original).encode()
    original_path.write_bytes(original_bytes)
    completed = subprocess.run(
        [
            chio,
            "mcp",
            "adopt",
            "--config",
            str(original_path),
            "--policy",
            str(repo / "examples/mcp-adoption/policy.yaml"),
            "--output",
            str(state / "adopted"),
        ],
        check=True,
        capture_output=True,
    )
    report = json.loads(completed.stdout)
    assert Path(report["backup_config_path"]).read_bytes() == original_bytes
    config = json.loads(Path(report["config_path"]).read_text())
    assert original_path.read_bytes() == original_bytes
    assert config["preferences"] == original["preferences"]
    assert (
        config["mcpServers"]["journal"]["env"]
        == original["mcpServers"]["journal"]["env"]
    )
    assert not journal.exists(), "import must not launch the upstream server"
    first_key, first_receipts = asyncio.run(exercise(config, report, "first"))
    first_effects = [json.loads(line) for line in journal.read_text().splitlines()]
    assert first_effects == [{"note": "first-0"}, {"note": "first-1"}]
    # Restart creates a fresh session grant, while the kernel signer and receipt
    # history survive. This is deliberately not an aggregate lifetime quota.
    second_key, second_receipts = asyncio.run(exercise(config, report, "restart"))
    assert first_key == second_key
    effects = [json.loads(line) for line in journal.read_text().splitlines()]
    assert effects == first_effects + [{"note": "restart-0"}, {"note": "restart-1"}]
    stored = subprocess.run(
        [
            chio,
            "--receipt-db",
            report["wrapped_servers"][0]["receipt_db"],
            "receipt",
            "list",
            "--admin-all",
            "--tool-server",
            "journal",
        ],
        check=True,
        capture_output=True,
    )
    history = [json.loads(line) for line in stored.stdout.splitlines()]
    expected = first_receipts + second_receipts
    assert {receipt["id"] for receipt in expected} <= {
        receipt["id"] for receipt in history
    }
    evidence = {
        "effects": effects,
        "receipts": expected,
        "trusted_kernel_key": first_key,
    }
    (state / "evidence.json").write_text(json.dumps(evidence, indent=2))
    print(
        json.dumps(
            {
                "imported_servers": 1,
                "effects": len(effects),
                "verified_receipts": len(expected),
                "signer_survived_restart": True,
                "history_survived_restart": True,
                "original_config_unchanged": True,
            }
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--chio", required=True)
    parser.add_argument("--state-dir", type=Path)
    args = parser.parse_args()
    if args.state_dir:
        args.state_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        run(args.chio, args.state_dir.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix="chio-adoption-") as directory:
            run(args.chio, Path(directory))


if __name__ == "__main__":
    main()

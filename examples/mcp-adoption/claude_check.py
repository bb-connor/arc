"""Opt-in acceptance check using an authenticated Claude Code client."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import signal
import subprocess
import sys
from pathlib import Path

from check import inspect_status


def budget(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("budget must be a positive finite number")
    return number


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chio", required=True, type=Path)
    parser.add_argument("--claude", default="claude")
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--max-budget-usd", type=budget, default=0.5)
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("this acceptance profile requires Linux or macOS")
    os.umask(0o077)
    chio = str(args.chio.resolve(strict=True))
    here = Path(__file__).resolve().parent
    state = args.state_dir.resolve()
    state.mkdir(mode=0o700, exist_ok=False)
    version = subprocess.check_output([args.claude, "--version"], text=True).strip()
    original = state / "original.json"
    original.write_text(json.dumps({"mcpServers": {"journal": {
        "command": sys.executable,
        "args": [str(here / "server.py")],
        "env": {
            "JOURNAL_PATH": str(state / "journal.jsonl"),
            "OPERATOR_LABEL": "Claude client acceptance",
        },
    }}}))
    adopted = subprocess.run([
        chio, "mcp", "adopt", "--config", str(original),
        "--policy", str(here / "policy.yaml"), "--output", str(state / "adopted"),
    ], check=True, capture_output=True, text=True)
    report = json.loads(adopted.stdout)
    prompt = (
        "This is an MCP integration acceptance test. First use ToolSearch to discover "
        "the journal append_note tool if it is deferred. Then call append_note exactly "
        "three times, sequentially, with note values client-first, client-second, and "
        "client-third in that order. A denial on the third call is expected. Do not "
        "retry any call. Then report each outcome. Use no other tool except ToolSearch."
    )
    command = [
        args.claude, "--print", "--output-format", "stream-json", "--verbose",
        "--no-session-persistence", "--restricted", "--setting-sources", "",
        "--strict-mcp-config", "--mcp-config", report["config_path"],
        "--tools", "ToolSearch", "--allowedTools", "mcp__journal__append_note",
        "--max-budget-usd", str(args.max_budget_usd),
        "--settings", '{"disableAllHooks":true}', prompt,
    ]
    transcript = state / "client.jsonl"
    with transcript.open("w") as stdout, (state / "client.stderr.log").open("w") as stderr:
        process = subprocess.Popen(command, cwd=state, stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            code = process.wait(timeout=180)
        except BaseException as error:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            if isinstance(error, subprocess.TimeoutExpired):
                raise RuntimeError(f"Claude client exceeded 180 seconds; inspect {state}") from None
            raise
    events = [json.loads(line) for line in transcript.read_text().splitlines()]
    result = next((event for event in reversed(events) if event.get("type") == "result"), {})
    calls = [
        block
        for event in events if event.get("type") == "assistant"
        for block in event.get("message", {}).get("content", [])
        if block.get("type") == "tool_use"
    ]
    notes = ["client-first", "client-second", "client-third"]
    journal_calls = [call for call in calls if call["name"] == "mcp__journal__append_note"]
    journal_path = state / "journal.jsonl"
    effects = [json.loads(line) for line in journal_path.read_text().splitlines()] if journal_path.exists() else []
    status = inspect_status(chio, Path(report["config_path"]), state / "adopted")
    (state / "status.json").write_text(json.dumps(status, indent=2))
    evidence = status["servers"][0]["receipts"]
    # A successful client process and a plausible final answer are insufficient.
    # Require the requested calls, exact external effects, and verified decisions.
    passed = (
        code == 0 and result.get("is_error") is False
        and [call["input"] for call in journal_calls] == [{"note": note} for note in notes]
        and all(call["name"] in {"ToolSearch", "mcp__journal__append_note"} for call in calls)
        and effects == [{"note": note} for note in notes[:2]]
        and evidence.get("status") == "verified_sample" and evidence.get("verified") == 3
        and evidence.get("outcomes") == {"allow": 2, "deny": 1, "cancelled": 0, "incomplete": 0}
        and all(receipt["matches_current_policy"] for receipt in evidence.get("recent", []))
    )
    if not passed:
        raise RuntimeError(f"Claude acceptance failed; inspect transcript, journal, and status in {state}")
    with Path(chio).open("rb") as stream:
        binary_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    acceptance = {
        "kind": "chio.claude-client-acceptance.v1",
        "client_version": version, "chio_binary_sha256": binary_hash,
        "tool_attempts": len(journal_calls), "effects": len(effects),
        "verified_receipts": evidence["verified"], "outcomes": evidence["outcomes"],
        "receipt_ids": [receipt["id"] for receipt in evidence["recent"]],
        "model_cost_usd": result.get("total_cost_usd"), "release_qualified": False,
    }
    (state / "acceptance.json").write_text(json.dumps(acceptance, indent=2) + "\n")
    print(json.dumps(acceptance, indent=2))


if __name__ == "__main__":
    main()

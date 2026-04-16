"""Bundle verification for the agent-commerce-network example."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


REQUIRED = [
    "agent-output.json",
    "contracts/quote-response.json",
    "contracts/fulfillment-package.json",
    "contracts/settlement-reconciliation.json",
    "summary.json",
]


def _load(path: Path) -> Any:
    return json.loads(path.read_text())


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_bundle(bundle_path: str | Path) -> dict[str, Any]:
    d = Path(bundle_path)
    errs: list[str] = []

    for rel in REQUIRED:
        if not (d / rel).exists():
            errs.append(f"missing: {rel}")
    if errs:
        return {"bundle": str(d), "ok": False, "errors": errs}

    agent_out = _load(d / "agent-output.json")
    summary = _load(d / "summary.json")

    # Check agent produced a final status
    status = agent_out.get("final_status")
    if not status:
        errs.append("agent output missing final_status")

    # Check summary consistency
    if summary.get("final_status") != status:
        errs.append("summary/agent status mismatch")

    # Verify contracts exist and parse
    for name in ["quote-response.json", "fulfillment-package.json", "settlement-reconciliation.json"]:
        p = d / "contracts" / name
        if p.exists():
            try:
                _load(p)
            except json.JSONDecodeError:
                errs.append(f"invalid JSON: contracts/{name}")

    # Check financial data if present
    fin = d / "financial"
    if fin.exists():
        for name in ["budget-usage.json"]:
            p = fin / name
            if p.exists():
                data = _load(p)
                if data.get("configured") and data.get("usages"):
                    for u in data["usages"]:
                        if u.get("totalCostCharged", 0) < 0:
                            errs.append("negative cost in budget usage")

    return {
        "bundle": str(d), "ok": not errs,
        "agent_status": status,
        "agent_mode": agent_out.get("mode"),
        "tool_calls": len(agent_out.get("tool_calls", [])),
        "errors": errs,
    }

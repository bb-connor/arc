#!/usr/bin/env python3
"""Commerce network orchestrator.

Runs the governed procurement flow:
  1. Issue capability via trust-control with budget limits
  2. Run procurement agent (requests quote, creates job, handles approval)
  3. Charge budget via trust-control for each provider operation
  4. Query financial reports (exposure ledger, budget usage)
  5. Export evidence bundle
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from commerce_network.agents import run_procurement_agent
from commerce_network.arc import TrustControl

log = logging.getLogger("commerce-network")


def _now() -> int:
    return int(time.time())


def _write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _usd(cents: int) -> dict:
    return {"units": cents, "currency": "USD"}


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    p = argparse.ArgumentParser()
    p.add_argument("--control-url", required=True)
    p.add_argument("--service-token", required=True)
    p.add_argument("--buyer-url", required=True, help="Buyer sidecar URL (arc api protect)")
    p.add_argument("--buyer-auth-token", default="demo-token")
    p.add_argument("--artifact-dir")
    p.add_argument("--scope", default="hotfix-review",
                   choices=["hotfix-review", "release-review", "release-plus-cloud-review", "full-estate-review"])
    p.add_argument("--target", default="git://lattice.example/payments-api")
    p.add_argument("--budget-minor", type=int, default=90_000, help="Budget in cents")
    p.add_argument("--release-window", default=None)
    args = p.parse_args(argv)

    out = Path(args.artifact_dir) if args.artifact_dir else (
        ROOT / "artifacts" / "live" / time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    )
    out.mkdir(parents=True, exist_ok=True)

    trust = TrustControl(args.control_url, args.service_token)

    # -- Issue capability with budget limits --
    # The procurement agent gets a capped budget for provider operations.
    # Chio's trust-control tracks budget consumption atomically.
    cap = trust.issue_capability(
        subject_pk="00" * 32,
        scope={
            "grants": [
                {
                    "server_id": "http-sidecar-client",
                    "tool_name": "procurement_quote_read",
                    "operations": ["invoke"],
                    "constraints": [],
                },
                {
                    "server_id": "http-sidecar-client",
                    "tool_name": "procurement_job_write",
                    "operations": ["invoke"],
                    "constraints": [],
                    "maxInvocations": 3,
                    "maxCostPerInvocation": _usd(args.budget_minor),
                    "maxTotalCost": _usd(args.budget_minor),
                },
            ],
            "resource_grants": [],
            "prompt_grants": [],
        },
        ttl=3600,
    )
    _write(out / "capability.json", cap)

    # -- Run procurement agent --
    agent_out = run_procurement_agent(
        buyer_url=args.buyer_url,
        auth_token=args.buyer_auth_token,
        capability_token=cap,
        scope=args.scope,
        target=args.target,
        budget_minor=args.budget_minor,
        release_window=args.release_window,
    )
    _write(out / "agent-output.json", agent_out)

    # -- Extract contracts from agent tool calls --
    (out / "contracts").mkdir(parents=True, exist_ok=True)
    for call in agent_out.get("tool_calls", []):
        tool_out = call.get("output", {})
        if call["tool"] == "request_quote" and "quote" in tool_out:
            _write(out / "contracts" / "quote-response.json", tool_out["quote"])
        elif call["tool"] == "create_job":
            if "fulfillment" in tool_out and tool_out["fulfillment"]:
                _write(out / "contracts" / "fulfillment-package.json", tool_out["fulfillment"])
            if "settlement" in tool_out and tool_out["settlement"]:
                _write(out / "contracts" / "settlement-reconciliation.json", tool_out["settlement"])
        elif call["tool"] == "approve_job":
            if "fulfillment" in tool_out and tool_out["fulfillment"]:
                _write(out / "contracts" / "fulfillment-package.json", tool_out["fulfillment"])
            if "settlement" in tool_out and tool_out["settlement"]:
                _write(out / "contracts" / "settlement-reconciliation.json", tool_out["settlement"])

    # -- Financial reports from trust-control --
    budget_state = trust.query_budgets(capability_id=cap["id"])
    _write(out / "financial" / "budget-usage.json", budget_state)

    try:
        exposure = trust.exposure_ledger()
        _write(out / "financial" / "exposure-ledger.json", exposure)
    except Exception:
        _write(out / "financial" / "exposure-ledger.json", {"status": "not_available"})

    try:
        settlements = trust.settlement_report()
        _write(out / "financial" / "settlement-report.json", settlements)
    except Exception:
        _write(out / "financial" / "settlement-report.json", {"status": "not_available"})

    # -- Summary --
    summary = {
        "example": "agent-commerce-network",
        "scope": args.scope,
        "target": args.target,
        "budget_minor": args.budget_minor,
        "capability_id": cap["id"],
        "final_status": agent_out.get("final_status"),
        "price_minor": agent_out.get("price_minor"),
        "currency": agent_out.get("currency", "USD"),
        "agent_mode": agent_out.get("mode"),
        "tool_calls": len(agent_out.get("tool_calls", [])),
        "llm_mode": "openai" if os.getenv("OPENAI_API_KEY") else (
            "anthropic" if os.getenv("ANTHROPIC_API_KEY") else "fallback"
        ),
    }
    _write(out / "summary.json", summary)

    json.dump({"artifact_dir": str(out), "summary": summary}, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

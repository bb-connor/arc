#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


REQUIRED_TOP_LEVEL = ["README.md", "steps.md", "expected-outputs.md"]
REQUIRED_CONTRACTS = [
    "approval-ticket.json",
    "dispute-record.json",
    "federated-review-package.json",
    "fulfillment-package.json",
    "quote-request.json",
    "quote-response.json",
    "settlement-reconciliation.json",
]


def verify_bundle(
    bundle_path: str | Path,
    *,
    control_url: str | None = None,
    auth_token: str | None = None,
    capability_id: str | None = None,
) -> dict[str, Any]:
    bundle = Path(bundle_path)
    errors: list[str] = []

    for name in REQUIRED_TOP_LEVEL:
        if not (bundle / name).exists():
            errors.append(f"missing required top-level file: {name}")

    contracts_dir = bundle / "contracts"
    if not contracts_dir.exists():
        errors.append("missing contracts directory")
    else:
        for name in REQUIRED_CONTRACTS:
            if not (contracts_dir / name).exists():
                errors.append(f"missing contract artifact: {name}")

    imported_review = {}
    if (contracts_dir / "federated-review-package.json").exists():
        imported_review = json.loads((contracts_dir / "federated-review-package.json").read_text())
        if imported_review.get("import_mode") != "bounded_evidence_import":
            errors.append("federated review package must preserve bounded evidence import mode")
        if "trust_note" not in imported_review:
            errors.append("federated review package must describe trust boundaries")

    receipt_summary = None
    if control_url and auth_token and capability_id:
        query = urllib.parse.urlencode({"capabilityId": capability_id, "limit": 10})
        request = urllib.request.Request(
            f"{control_url.rstrip('/')}/v1/receipts/query?{query}",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
        receipts = payload.get("receipts", [])
        if not receipts:
            errors.append("no receipts returned for capability query")
        else:
            receipt_summary = {
                "count": len(receipts),
                "latest_receipt_id": receipts[-1]["id"],
            }

    return {
        "bundle": str(bundle),
        "ok": not errors,
        "checked_files": {
            "top_level": REQUIRED_TOP_LEVEL,
            "contracts": REQUIRED_CONTRACTS,
        },
        "imported_review": imported_review,
        "receipt_summary": receipt_summary,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify an agent-commerce-network evidence bundle.")
    parser.add_argument("bundle", help="Path to the generated bundle directory")
    parser.add_argument("--control-url", help="Optional trust-control URL for live receipt verification")
    parser.add_argument("--auth-token", help="Bearer token for the trust-control query")
    parser.add_argument("--capability-id", help="Capability id to query when live receipts are available")
    args = parser.parse_args(argv)

    result = verify_bundle(
        args.bundle,
        control_url=args.control_url,
        auth_token=args.auth_token,
        capability_id=args.capability_id,
    )
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

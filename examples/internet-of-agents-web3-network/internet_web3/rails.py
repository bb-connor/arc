"""Policy-based settlement rail selection for the web3 example."""
from __future__ import annotations

from .artifacts import ArtifactStore, Json, now_epoch


def write_rail_selection(*, store: ArtifactStore, evidence: object, order_request: Json) -> Json:
    base_available = bool(getattr(evidence, "base_smoke", None)) and evidence.base_smoke.get("status") == "pass"
    selected = {
        "rail_id": "base-sepolia-usdc" if base_available else "local-devnet-usdc",
        "kind": "web3",
        "chain_id": evidence.chain_id if base_available else "local-devnet",
        "reason": "Base Sepolia smoke evidence is attached and passing"
        if base_available else "Base Sepolia smoke absent, using local devnet qualification evidence",
        "external_execution_authoritative": base_available,
    }
    denied = [
        {
            "rail_id": "solana-memo-proof",
            "kind": "solana-memo",
            "decision": "deny",
            "reason": "alternate proof path only; no live Solana signer or settlement escrow in this smoke",
        }
    ]
    if base_available:
        denied.append({
            "rail_id": "local-devnet-usdc",
            "kind": "web3",
            "decision": "deny",
            "reason": "higher-fidelity Base Sepolia smoke is available",
        })
    else:
        denied.append({
            "rail_id": "base-sepolia-usdc",
            "kind": "web3",
            "decision": "deny",
            "reason": "Base Sepolia smoke not attached",
        })
    selection = {
        "schema": "chio.example.ioa-web3.rail-selection.v1",
        "order_id": order_request["order_id"],
        "status": "pass",
        "selected_rail": selected,
        "denied_rails": denied,
        "evaluated_at": now_epoch(),
        "mainnet_blocked": True,
    }
    store.write_json("settlement/rail-selection.json", selection)
    return selection


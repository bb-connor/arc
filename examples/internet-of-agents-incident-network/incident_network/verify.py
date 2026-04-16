"""Offline bundle verification."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from incident_network.capabilities import (
    cap_body,
    intent_hash,
    link_body,
    verify_approval,
    verify_sig,
)

REQUIRED = [
    "incident.json",
    "identities/public-identities.json",
    "capabilities/root-commander.json",
    "capabilities/triage-agent.json",
    "capabilities/change-agent.json",
    "capabilities/vendor-liaison-agent.json",
    "capabilities/provider-coordinator.json",
    "capabilities/provider-executor.json",
    "agents/triage-output.json",
    "agents/change-output.json",
    "agents/vendor-liaison-output.json",
    "agents/commander-output.json",
    "acp/task-created.json",
    "acp/task-final.json",
    "provider/process-task-response.json",
    "lineage/root-commander-chain.json",
    "lineage/triage-agent-chain.json",
    "lineage/change-agent-chain.json",
    "lineage/vendor-liaison-agent-chain.json",
    "lineage/provider-coordinator-chain.json",
    "lineage/provider-executor-chain.json",
    "summary.json",
    "bundle-manifest.json",
]


def _load(path: Path) -> Any:
    return json.loads(path.read_text())


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _check_manifest(d: Path, errs: list[str]) -> dict:
    m = _load(d / "bundle-manifest.json")
    verified = []
    for rel, expected in m.get("sha256", {}).items():
        p = d / rel
        if not p.exists():
            errs.append(f"manifest: missing {rel}")
        elif _sha256(p) != expected:
            errs.append(f"manifest: hash mismatch {rel}")
        else:
            verified.append(rel)
    return {"verified_files": verified, "manifest_entries": len(m.get("sha256", {}))}


def _check_capabilities(d: Path, errs: list[str]) -> dict:
    names = [
        "root-commander", "triage-agent", "change-agent",
        "vendor-liaison-agent", "provider-coordinator", "provider-executor",
    ]
    caps = {n: _load(d / "capabilities" / f"{n}.json") for n in names}
    by_id = {c["id"]: c for c in caps.values()}
    sigs, chains = {}, {}

    for name, cap in caps.items():
        ok = verify_sig(cap["issuer"], cap_body(cap), cap["signature"])
        sigs[name] = ok
        if not ok:
            errs.append(f"capability sig invalid: {name}")

        chain = cap.get("delegation_chain", [])
        if name == "root-commander":
            if chain:
                errs.append("root capability has delegation links")
            chains[name] = {"depth": 0, "lineage_ok": True}
            continue
        if not chain:
            errs.append(f"delegated capability missing chain: {name}")
            chains[name] = {"depth": 0, "lineage_ok": False}
            continue

        last = chain[-1]
        parent = by_id.get(last["capability_id"])
        if not parent:
            errs.append(f"parent missing from bundle: {name}")
            chains[name] = {"depth": len(chain), "lineage_ok": False}
            continue

        links_ok = all(verify_sig(lk["delegator"], link_body(lk), lk["signature"]) for lk in chain)
        if not links_ok:
            errs.append(f"delegation link sig invalid: {name}")

        lineage_ok = (
            last["delegatee"] == cap["subject"]
            and last["delegator"] == cap["issuer"]
            and chain[:-1] == parent.get("delegation_chain", [])
            and cap["expires_at"] <= parent["expires_at"]
        )
        if not lineage_ok:
            errs.append(f"lineage invalid: {name}")
        chains[name] = {"depth": len(chain), "parent_id": last["capability_id"],
                        "link_signatures_ok": links_ok, "lineage_ok": lineage_ok}

    return {"signatures": sigs, "chains": chains}


def _check_operations(d: Path, errs: list[str]) -> dict:
    commander = _load(d / "agents" / "commander-output.json")
    provider = _load(d / "provider" / "process-task-response.json")
    task_final = _load(d / "acp" / "task-final.json")
    summary = _load(d / "summary.json")
    mode = summary.get("scenario_mode", "happy-path")
    execution = provider.get("execution", {})

    if commander.get("decision") != "engage_external_provider":
        errs.append("commander did not choose external provider path")
    if summary.get("task_status") != task_final.get("status"):
        errs.append("summary/task status mismatch")

    if mode == "happy-path":
        if task_final.get("status") != "completed":
            errs.append("task not completed")
        if execution.get("verdict") != "allow":
            errs.append("execution not allowed")
    elif mode == "attenuation-deny":
        if execution.get("reason") != "attenuation_violation":
            errs.append("expected attenuation_violation")
    elif mode == "revoke-midchain":
        if execution.get("reason") != "revoked_ancestor":
            errs.append("expected revoked_ancestor")
    elif mode == "expiry-async-failure":
        if execution.get("reason") != "expired_capability":
            errs.append("expected expired_capability")
    elif mode == "approval-required":
        if execution.get("verdict") != "allow":
            errs.append("approval scenario did not allow")
        pre = _load(d / "approval" / "pre-approval-execution.json")
        req = _load(d / "approval" / "approval-request.json")
        resp = _load(d / "approval" / "approval-response.json")
        tok = _load(d / "approval" / "approval-token.json")
        if pre.get("reason") != "approval_required":
            errs.append("pre-approval should be approval_required")
        if resp.get("governed_intent_hash") != intent_hash(req["governed_intent"]):
            errs.append("intent hash mismatch")
        ok, reason = verify_approval(
            tok, subject_pk=req["subject_public_key"], request_id=req["request_id"],
            intent_hash_val=resp["governed_intent_hash"],
            now=execution.get("provider_operation", {}).get("executed_at", tok["issued_at"] + 1),
        )
        if not ok:
            errs.append(f"approval token invalid: {reason}")

    return {"scenario_mode": mode, "task_status": task_final["status"]}


def verify_bundle(bundle_path: str | Path) -> dict[str, Any]:
    d = Path(bundle_path)
    errs: list[str] = []

    for rel in REQUIRED:
        if not (d / rel).exists():
            errs.append(f"missing: {rel}")
    if errs:
        return {"bundle": str(d), "ok": False, "errors": errs}

    manifest = _check_manifest(d, errs)
    caps = _check_capabilities(d, errs)
    ops = _check_operations(d, errs)

    return {
        "bundle": str(d), "ok": not errs,
        "manifest": manifest, "capabilities": caps, "operational": ops,
        "errors": errs,
    }

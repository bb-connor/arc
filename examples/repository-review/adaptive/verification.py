"""Verify signed publication parameters before exporting a completed review."""

import hashlib
import json
import sqlite3
import subprocess

from .common import persist


def receipt_for(result, server, tool):
    matches = [
        receipt
        for entry in result["receipts"]
        if (receipt := json.loads(entry["chio"]["receipt_json"]))["tool_server"]
        == server
        and receipt["tool_name"] == tool
    ]
    if len(matches) != 1 or matches[0]["decision"]["verdict"] != "allow":
        raise ValueError("expected one verified invocation for this handoff")
    return matches[0]


def verify(config, directory, runner):
    if not runner.get("complete"):
        raise ValueError("native run is incomplete")
    results = {}
    for snapshot in runner["workers"]:
        if snapshot["state"] != "completed":
            raise ValueError("native worker did not complete")
        process = snapshot["process"]
        result = json.loads(
            (directory / "workers" / process / "result.json").read_text()
        )
        if (
            result["process"] != process
            or result["snapshot_hash"] != config["snapshot_hash"]
        ):
            raise ValueError("worker result identity mismatch")
        results[process] = result
    coordinator = results["coordinator"]
    if (
        coordinator["role"] != "coordinator"
        or results["publisher"]["role"] != "publisher"
    ):
        raise ValueError("unexpected initial worker role")
    children = coordinator["children"]
    reviews = coordinator["reviews"]
    if (
        len(reviews) != len(children)
        or len(set(children)) != len(children)
        or set(results) != {"coordinator", "publisher", *children}
    ):
        raise ValueError("completed workers differ from the delegated review plan")
    slots = sorted(results[child]["slot"] for child in children)
    if slots != list(range(1, len(reviews) + 1)):
        raise ValueError("delegated review slots are incomplete or duplicated")
    if any(results[child]["role"] != "reviewer" for child in children):
        raise ValueError("unexpected child role")
    receipts = [
        entry["chio"]["receipt_json"]
        for result in results.values()
        for entry in result["receipts"]
    ]
    if not receipts:
        raise ValueError("completed application has no receipt evidence")
    receipt_path = directory / "receipts.ndjson"
    receipt_path.write_text("".join(receipt + "\n" for receipt in receipts))
    verification = subprocess.run(
        [
            config["chio"],
            "--json",
            "receipt",
            "verify",
            "--input",
            str(receipt_path),
            "--trusted-kernel-pubkey",
            str(directory / "kernel.pub"),
        ],
        capture_output=True,
        timeout=30,
    )
    if verification.returncode:
        raise ValueError(
            "offline receipt verification failed; preserve the complete state"
        )
    handoff = receipt_for(coordinator, "chio-ipc", "send_plan")
    if handoff["action"]["parameters"] != {
        "message_key": "review-plan",
        "payload": {"reviews": reviews, "children": children},
    }:
        raise ValueError(
            "delegation metadata differs from the signed coordinator handoff"
        )
    for job, child in zip(reviews, children):
        if results[child]["slot"] != job["slot"]:
            raise ValueError("child identity does not match its assigned review slot")
        spawn = receipt_for(coordinator, "chio-process", f"spawn_review_{job['slot']}")
        if spawn["action"]["parameters"] != {
            "input": job,
            "budget_share_bps": 8000 // config["max_reviews"],
        }:
            raise ValueError("review assignment differs from its signed spawn input")
    publication = []
    for entry in results["publisher"]["receipts"]:
        receipt = json.loads(entry["chio"]["receipt_json"])
        if (
            receipt["tool_server"] == "repo"
            and receipt["tool_name"] == "publish_report"
        ):
            publication.append(
                (receipt, entry["chio"]["output"]["value"]["structuredContent"])
            )
    if len(publication) != 1:
        raise ValueError("expected one verified publication receipt")
    receipt, locator = publication[0]
    if receipt["decision"]["verdict"] != "allow":
        raise ValueError("publication receipt did not allow the invocation")
    with sqlite3.connect(
        f"file:{directory / 'publications.db'}?mode=ro", uri=True
    ) as db:
        stored = db.execute(
            "SELECT snapshot_hash,report_hash,report FROM reports WHERE id=?",
            (locator["report_id"],),
        ).fetchone()
        count = db.execute("SELECT count(*) FROM reports").fetchone()[0]
    if not stored or count != 1 or stored[0] != config["snapshot_hash"]:
        raise ValueError("expected one publication for this snapshot")
    if receipt["action"]["parameters"] != {
        "report": stored[2],
        "snapshot_hash": config["snapshot_hash"],
    }:
        raise ValueError("published text differs from the signed invocation")
    report_hash = hashlib.sha256(stored[2].encode()).hexdigest()
    if report_hash != stored[1]:
        raise ValueError("publication history checksum mismatch")
    evidence = {
        "schema": "chio.repository.adaptive-evidence.v1",
        "base": config["base"],
        "head": config["head"],
        "snapshot_hash": config["snapshot_hash"],
        "kernel_key": config["kernel_key"],
        "model_factory": config["model_factory"],
        "application_hash": config["application_hash"],
        "native_binary_sha256": config["native_binary_sha256"],
        "reviews": reviews,
        "children": children,
        "runner": runner,
        "publications": count,
        "publication": locator,
        "report_hash": report_hash,
        "receipt_verification": json.loads(verification.stdout),
        "workers": results,
    }
    # These exports are derived from already committed graph and publication state.
    (directory / "report.md").write_text(stored[2])
    persist(directory / "evidence.json", evidence)
    return {
        "complete": True,
        "reviews": len(reviews),
        "publications": count,
        "report": str(directory / "report.md"),
        "evidence": str(directory / "evidence.json"),
    }

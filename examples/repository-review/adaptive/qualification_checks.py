"""Authority and evidence corruption checks against a completed private run."""

import json
import sqlite3

from chio_process import ProcessClient
from qualify import command
from review import host

from . import verification
from .common import persist
from .qualification import run


def must_reject(function, message):
    try:
        function()
    except ValueError as error:
        assert message in str(error), str(error)
    else:
        raise AssertionError("corrupted evidence was accepted")


def corruption(config, directory, result):
    config_path = directory / "run.json"
    for key, value, message in (
        ("application_hash", "0" * 64, "application changed"),
        ("native_binary_sha256", "0" * 64, "native binary changed"),
        ("max_rounds", config["max_rounds"] + 1, "executable plan"),
    ):
        persist(config_path, {**config, key: value})
        try:
            assert message in run(directory, success=False).stderr
        finally:
            persist(config_path, config)
    path = directory / "workers/coordinator/result.json"
    original = path.read_bytes()
    changed = json.loads(original)
    changed["reviews"][0]["focus"] = "Forged assignment"
    persist(path, changed)
    try:
        must_reject(
            lambda: verification.verify(config, directory, result["runner"]),
            "signed coordinator handoff",
        )
    finally:
        path.write_bytes(original)
    with sqlite3.connect(directory / "publications.db") as db:
        original_report = db.execute("SELECT report FROM reports").fetchone()[0]
        db.execute("UPDATE reports SET report = 'Forged report'")
    try:
        must_reject(
            lambda: verification.verify(config, directory, result["runner"]),
            "signed invocation",
        )
    finally:
        with sqlite3.connect(directory / "publications.db") as db:
            db.execute("UPDATE reports SET report = ?", (original_report,))
    snapshot = directory / "snapshot.json"
    original = snapshot.read_bytes()
    changed = json.loads(original)
    changed["head"] = "0" * 40
    persist(snapshot, changed)
    try:
        assert "snapshot changed" in run(directory, success=False).stderr
    finally:
        snapshot.write_bytes(original)


def scopes(config, directory, result):
    socket = directory / "probe.sock"
    child = result["children"][0]
    clients = {}
    credentials = []
    for process in (child, "publisher"):
        destination = directory / f"probe-{process}.json"
        command(
            config["chio"],
            "process",
            "credential",
            "--state",
            directory / "host",
            "--process",
            process,
            "--socket",
            socket,
            "--out",
            destination,
        )
        descriptor = json.loads(destination.read_text())
        credentials.append(descriptor["credential"])
        clients[process] = ProcessClient(str(socket), descriptor["credential"])
        destination.unlink()
    probes = []
    with host(config, directory, socket):
        probes.append(
            clients[child].invoke(
                "scope-publish",
                "repo",
                "publish_report",
                {"report": "unauthorized", "snapshot_hash": config["snapshot_hash"]},
            )
        )
        slot = result["workers"][child]["slot"]
        other = 2 if slot == 1 else 1
        probes.append(
            clients[child].invoke(
                "scope-channel",
                "chio-ipc",
                f"send_review_{other}",
                {"message_key": "unauthorized", "payload": {}},
            )
        )
        path = result["reviews"][0]["paths"][0]
        probes.append(
            clients["publisher"].invoke(
                "scope-read",
                "repo",
                "read_file",
                {"path": path, "revision": "head"},
            )
        )
        assert all(probe["verdict"] == "deny" for probe in probes)
        escaped = clients[child].invoke(
            "scope-escape",
            "repo",
            "read_file",
            {"path": "../outside.py", "revision": "head"},
        )
        assert escaped["output"]["value"]["isError"] is True
        probes.append(escaped)
    receipts = directory / "scope-receipts.ndjson"
    receipts.write_text("".join(probe["receipt_json"] + "\n" for probe in probes))
    verified = command(
        config["chio"],
        "--json",
        "receipt",
        "verify",
        "--input",
        receipts,
        "--trusted-kernel-pubkey",
        directory / "kernel.pub",
    )
    assert json.loads(verified.stdout)["receipts_verified"] == len(probes)
    with sqlite3.connect(directory / "publications.db") as db:
        assert db.execute("SELECT count(*) FROM reports").fetchone()[0] == 1
    return credentials


def no_secrets(directory, credentials):
    with sqlite3.connect(directory / "host/process.db") as db:
        seeds = [
            row[0] for row in db.execute("SELECT seed_hex FROM process_delegation_keys")
        ]
    secrets = [secret.encode() for secret in credentials + seeds]
    paths = list((directory / "workers").rglob("*"))
    paths += list((directory / "host/run-logs").rglob("*"))
    paths += [
        directory / name for name in ("evidence.json", "report.md", "receipts.ndjson")
    ]
    for path in paths:
        if path.is_file():
            data = path.read_bytes()
            assert all(secret not in data for secret in secrets), path

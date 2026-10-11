"""Qualify the review graph under native worker restart supervision."""

import argparse
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

from qualify import command, commits

HERE = Path(__file__).resolve().parent


def exercise(binary, output, temporary):
    repo, base, head = commits(temporary)
    summary = {}
    for profile in ("inventory", "model_fixture:create"):
        name = "inventory" if profile == "inventory" else "scripted-model"
        directory = temporary / name
        command(
            sys.executable,
            HERE / "review.py",
            "prepare",
            "--repo",
            repo,
            "--base",
            base,
            "--head",
            head,
            "--run-dir",
            directory,
            "--chio",
            binary,
            "--model-factory",
            profile,
        )
        path = directory / "worker-plan.json"
        plan = json.loads(path.read_text())
        for worker in plan["workers"]:
            if worker["process"] == "changes":
                worker["input"]["crash_after_handoff"] = True
            if worker["process"] == "publisher":
                worker["input"]["crash_after_publication"] = True
        path.write_text(json.dumps(plan))
        command(
            sys.executable, HERE / "review.py", "run-native", "--run-dir", directory
        )
        evidence = json.loads((directory / "evidence.json").read_text())
        assert evidence["publications"] == 1
        assert evidence["receipt_verification"]["receipts_verified"] == (
            9 if profile == "inventory" else 13
        )
        assert evidence["runner"]["complete"]
        assert {w["process"]: w["attempts"] for w in evidence["runner"]["workers"]} == {
            "changes": 2,
            "tests": 1,
            "publisher": 2,
        }
        for role, filename in (
            ("changes", "first-handoff.json"),
            ("publisher", "first-publication.json"),
        ):
            first = json.loads((directory / role / filename).read_text())
            assert first in evidence["workers"][role]["receipts"]
            (directory / role / filename).unlink()
        with sqlite3.connect(directory / "host/mailboxes.db") as db:
            assert db.execute(
                "SELECT last_sequence,acknowledged_through FROM mailboxes"
            ).fetchall() == [(1, 1), (1, 1)]
        assert not list((directory / "connections").iterdir()), (
            "native launch must not need descriptor files"
        )
        command(
            sys.executable, HERE / "review.py", "run-native", "--run-dir", directory
        )
        repeated = json.loads((directory / "evidence.json").read_text())
        assert repeated["runner"] == evidence["runner"]
        assert repeated["workers"] == evidence["workers"]
        assert repeated["publications"] == 1
        destination = output / name
        destination.mkdir(mode=0o700)
        for filename in ("report.md", "evidence.json", "receipts.ndjson", "kernel.pub"):
            (destination / filename).write_bytes((directory / filename).read_bytes())
        summary[name] = {
            "receipts_verified": evidence["receipt_verification"]["receipts_verified"],
            "publications": 1,
            "worker_attempts": evidence["runner"]["workers"],
            "application_seconds": evidence["attempt_seconds"],
        }
    (output / "qualification.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    temporary = Path(tempfile.mkdtemp(prefix="chio-nrv-"))
    try:
        exercise(args.chio.resolve(strict=True), args.output, temporary)
    except BaseException:
        print(f"Preserved private failure state: {temporary}", file=sys.stderr)
        raise
    else:
        shutil.rmtree(temporary)


if __name__ == "__main__":
    main()

"""Bounded long-run storage comparison using real HTTP provider parsers and native processes."""

import hashlib
import json
import shutil
import sqlite3

from journal_profiles import provider, requests
from qualify import command, host_death, prepare, verify, write


def exercise_pressure(binary, destination, temporary, consumer):
    output = destination / "state-pressure"
    output.mkdir()
    profiles = {}
    for mode in (
        "pressure-inline",
        "pressure-worker-death",
        "pressure-host-death",
        "pressure-quota",
    ):
        directory = temporary / f"{consumer.name}-{mode}"
        invoke = prepare(binary, directory, consumer, mode)
        with provider(directory, consumer, mode) as endpoint:
            plan = json.loads((directory / "worker-plan.json").read_text())
            plan["workers"][0]["command"][1] = str(consumer / "pressure_worker.mjs")
            plan["workers"][0]["input"]["endpoint"] = endpoint
            write(directory / "worker-plan.json", plan)
            first = (
                host_death(invoke, directory) if mode == "pressure-host-death" else None
            )
            success = mode in ("pressure-worker-death", "pressure-host-death")
            executed = command(invoke, directory, success=success)
            if (directory / "first-result.json").exists():
                first = json.loads((directory / "first-result.json").read_text())
                (directory / "first-result.json").unlink()
            calls = requests(directory)
            result = json.loads(
                (
                    directory / ("result.json" if success else "failure-3.json")
                ).read_text()
            )
            with sqlite3.connect(directory / "publications.db") as db:
                exists = db.execute(
                    "SELECT 1 FROM sqlite_master WHERE name='reads'"
                ).fetchone()
                reads = (
                    db.execute("SELECT file_index FROM reads ORDER BY id").fetchall()
                    if exists
                    else []
                )
            assert reads == [(index,) for index in range(1, len(reads) + 1)], (
                "no duplicate or skipped native reads"
            )
            with sqlite3.connect(directory / "host/process.db") as db:
                raw = db.execute(
                    "SELECT checkpoint FROM processes WHERE id='writer'"
                ).fetchone()[0]
                chunks = db.execute(
                    "SELECT sha256,data FROM process_state_blobs WHERE process_id='writer'"
                ).fetchall()
            assert all(hashlib.sha256(data).hexdigest() == sha for sha, data in chunks)
            assert result["storage"]["process_bytes"] == sum(
                len(data) for _, data in chunks
            )
            if success:
                assert len(reads) == 32 and len(calls) == 33
                runner = json.loads(executed.stdout)
                assert runner["complete"] and runner["workers"][0]["attempts"] == 2
                assert result["receipts"][15] == first
                assert result["metrics"]["maxBytes"] < 32768
                assert result["metrics"]["writes"] == 66
                assert chunks and any(b"a" * 8192 in data for _, data in chunks)
                original = (directory / "result.json").read_bytes()
                assert json.loads(command(invoke, directory).stdout) == runner
                assert (directory / "result.json").read_bytes() == original
                assert requests(directory) == calls
            else:
                assert result["code"] == "model_outcome_unknown", result
                initial = json.loads((directory / "failure-1.json").read_text())
                assert initial["code"] == (
                    "model_journal_full"
                    if mode == "pressure-inline"
                    else "model_checkpoint_unavailable"
                )
                assert len(calls) == len(reads) + 1 and len(reads) < 32
                if mode == "pressure-quota":
                    assert not reads and not chunks
                else:
                    assert len(reads) >= 8 and not chunks
            assert "credential" not in json.dumps([item["request"] for item in calls])
            events = result["receipts"]
            verified = (
                verify(binary, directory, events)["receipts_verified"] if events else 0
            )
            case = output / mode
            case.mkdir()
            write(case / "result.json", result)
            write(case / "checkpoint.json", json.loads(raw))
            if events:
                for name in ("receipts.ndjson", "kernel.pub"):
                    shutil.copyfile(directory / name, case / name)
            profiles[mode] = {
                "completed": success,
                "reads": len(reads),
                "provider_requests": len(calls),
                "receipts_verified": verified,
                "checkpoint": result["metrics"],
                "storage": result["storage"],
            }
            print(
                json.dumps({"sdk": consumer.name, "pressure": mode, **profiles[mode]}),
                flush=True,
            )
    return profiles

"""Installed HTTP provider recovery through the native model-response checkpoint journal."""

import json
import shutil
import sqlite3
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import unquote, urlparse

from qualify import command, count, host_death, prepare, settings, verify, write


@contextmanager
def provider(directory, consumer, mode, script="model_server.py"):
    ready = directory / "provider.json"
    with (directory / "provider.log").open("wb") as log:
        process = subprocess.Popen(
            [
                sys.executable,
                str(consumer / script),
                "--database",
                str(directory / "provider.db"),
                "--ready",
                str(ready),
                "--mode",
                mode,
            ],
            stdout=log,
            stderr=log,
        )
        try:
            deadline = time.monotonic() + 20
            while not ready.exists():
                assert process.poll() is None, "HTTP provider exited before readiness"
                assert time.monotonic() < deadline, "HTTP provider did not become ready"
                time.sleep(0.02)
            yield json.loads(ready.read_text())["endpoint"]
        finally:
            process.terminate()
            process.wait(timeout=10)


def requests(directory):
    with sqlite3.connect(directory / "provider.db") as db:
        return [
            {"request": json.loads(request), "response": json.loads(response)}
            for request, response in db.execute("SELECT request,response FROM requests ORDER BY id")
        ]


def exercise_journal(binary, destination, temporary, consumer):
    output = destination / "model-journal"
    output.mkdir()
    baseline = temporary / f"{consumer.name}-http-baseline"
    data = settings(baseline, consumer, "baseline")
    with provider(baseline, consumer, "baseline") as endpoint:
        data["endpoint"] = endpoint
        write(baseline / "settings.json", data)
        invoke = ["node", consumer / "journal_worker.mjs", "--baseline", baseline / "settings.json"]
        first = command([*invoke, "1"], consumer, success=False)
        assert first.returncode == 77 and count(baseline) == 1
        (baseline / "first-result.json").unlink()
        command([*invoke, "2"], consumer)
        assert count(baseline) == 2
        responses = requests(baseline)
        assert len(responses) == 3
        ids = [
            item["response"]["choices"][0]["message"]["tool_calls"][0]["id"]
            for item in responses[:2]
        ]
        assert ids[0] != ids[1], "HTTP provider must regenerate identities in the callback baseline"
    write(output / "baseline.json", {"publications": 2, "provider_requests": responses})
    profiles = {"callback-baseline": {"completed": True, "publications": 2, "provider_requests": 3}}
    for mode in (
        "worker-death",
        "host-death",
        "model-checkpoint-death",
        "provider-death",
        "truncated-stream",
        "prompt-drift",
    ):
        directory = temporary / f"{consumer.name}-http-{mode}"
        invoke = prepare(binary, directory, consumer, mode)
        with provider(directory, consumer, mode) as endpoint:
            plan = json.loads((directory / "worker-plan.json").read_text())
            plan["workers"][0]["command"][1] = str(consumer / "journal_worker.mjs")
            plan["workers"][0]["input"].update(
                endpoint=endpoint, streaming=mode in ("host-death", "truncated-stream")
            )
            write(directory / "worker-plan.json", plan)
            first = host_death(invoke, directory) if mode == "host-death" else None
            success = mode in ("worker-death", "host-death", "model-checkpoint-death")
            executed = command(invoke, directory, success=success)
            oracle = directory / "first-result.json"
            if oracle.exists():
                first = json.loads(oracle.read_text())
                oracle.unlink()
            calls = requests(directory)
            assert len(calls) == (2 if success else 1), calls
            assert "receipt_json" not in json.dumps([call["request"] for call in calls])
            assert "credential" not in json.dumps([call["request"] for call in calls])
            expected_count = 1 if success or mode == "prompt-drift" else 0
            assert count(directory) == expected_count
            with sqlite3.connect(directory / "host/process.db") as db:
                checkpoint = json.loads(
                    db.execute("SELECT checkpoint FROM processes WHERE id='writer'").fetchone()[0]
                )
            entries = next(iter(checkpoint["chio.ai-sdk.journal.v1"]["turns"].values()))["entries"]
            assert len(entries) == (2 if success else 1)
            if success:
                runner = json.loads(executed.stdout)
                assert runner["complete"] and runner["workers"][0]["attempts"] == 2
                result = json.loads((directory / "result.json").read_text())
                events = result["receipts"]
                assert len(events) == 1 and (first is None or first == events[0])
                for url in result["modules"].values():
                    assert (
                        Path(unquote(urlparse(url).path))
                        .resolve()
                        .is_relative_to(consumer / "node_modules")
                    )
                assert all(entry["state"] == "completed" for entry in entries)
                original_id = calls[0]["response"]["choices"][0]["message"]["tool_calls"][0]["id"]
                assert entries[0]["callIds"] == [original_id]
                original = (directory / "result.json").read_bytes()
                assert json.loads(command(invoke, directory).stdout) == runner
                assert (directory / "result.json").read_bytes() == original and requests(
                    directory
                ) == calls
            else:
                with sqlite3.connect(directory / "host/runner.db") as db:
                    assert db.execute(
                        "SELECT state,attempts FROM run_workers WHERE process='writer'"
                    ).fetchone() == ("failed", 3)
                result = json.loads((directory / "failure-3.json").read_text())
                expected_code = (
                    "model_request_conflict" if mode == "prompt-drift" else "model_outcome_unknown"
                )
                assert result["code"] == expected_code, result
                assert entries[0]["state"] == ("completed" if mode == "prompt-drift" else "pending")
                events = [first] if first is not None else []
            assert not (directory / "model-plan.json").exists(), (
                "the application must not supply a saved model plan"
            )
            case = output / mode
            case.mkdir()
            write(case / "result.json", result)
            write(case / "checkpoint.json", checkpoint)
            write(case / "provider-requests.json", calls)
            verified = verify(binary, directory, events)["receipts_verified"] if events else 0
            if events:
                for name in ("receipts.ndjson", "kernel.pub"):
                    shutil.copyfile(directory / name, case / name)
            profiles[mode] = {
                "completed": success,
                "publications": expected_count,
                "provider_requests": len(calls),
                "receipts_verified": verified,
            }
            print(json.dumps({"sdk": consumer.name, "journal": mode, **profiles[mode]}), flush=True)
    return profiles

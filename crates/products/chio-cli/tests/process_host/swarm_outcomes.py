"""Supervise real retained allowed/denied calls across a shared family."""

import json
import subprocess
import sqlite3
from contextlib import closing
import sys
from pathlib import Path

import swarm_shared_family


def exercise(binary, directory):
    swarm_shared_family.exercise(binary, directory)
    state = directory / "state"
    calls = json.loads((state / "swarm-calls.json").read_text())
    worker = directory / "outcome-worker.py"
    worker.write_text('''import json,sys
from chio_process import ProcessClient
b=json.load(sys.stdin); connection=b["connection"]; call=b["input"]
assert call["process"] == connection["process_id"]
client=ProcessClient(connection["socket_path"], connection["credential"])
response=client.invoke(call["operation_key"],call["server_id"],call["tool_name"],call["arguments"],governed_intent=call["governed_intent"])
assert response["verdict"] in ["allow","deny"]
if response["verdict"] == "deny":
    assert response["output"] is None
current=client.inspect()["checkpoint"]
client.checkpoint(current["revision"], {"response":response})
print(json.dumps({"request_id":response["request_id"],"verdict":response["verdict"]}))
''')
    plan = {
        "schema": "chio.process.run.v1", "max_parallel": 4,
        "workers": [{
            "process": call["process"], "command": [sys.executable, str(worker)],
            "cwd": str(directory), "input": call, "max_attempts": 1,
            "timeout_seconds": 60,
            "resources": {"max_cpu_seconds": 20, "max_open_files": 64},
        } for call in calls["calls"]],
    }
    path = state / "outcomes-run-plan.json"
    path.write_text(json.dumps(plan))
    result = subprocess.run(
        [binary, "process", "run", "--state", str(state), "--plan", str(path)],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    report = json.loads(result.stdout)
    assert report["complete"] and len(report["workers"]) == 4, report
    with closing(sqlite3.connect(f"file:{state / 'mailboxes.db'}?mode=ro", uri=True)) as db:
        assert db.execute("SELECT count(*) FROM mailbox_messages").fetchone() == (2,)
    print(json.dumps(report))

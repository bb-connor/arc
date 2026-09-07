"""Test hooks around the installed public native entrypoint and upstream loop."""

import hashlib
import inspect
import json
import os
import signal
import sys
import time
from pathlib import Path

from chio_mini_swe.worker import build_agent, load_bootstrap, run_bootstrap
from minisweagent.agents.default import DefaultAgent

bootstrap = load_bootstrap(sys.stdin.buffer)
assert not os.environ.get("CHIO_MODEL_QUALIFICATION_SECRET")
assert not Path("/var/run/docker.sock").exists()
assert os.getuid() != 0
assert hashlib.sha256(Path(inspect.getfile(DefaultAgent)).read_bytes()).hexdigest() == (
    "e8ef8aa365942d739c2ec5cb0879f60f377d2dc2de8ec670aaedf3bafb45a4c2"
)
agent = build_agent(bootstrap)
invoke = agent.env.client.invoke


def interrupted(key, server, tool, arguments, **kwargs):
    result = invoke(key, server, tool, arguments, **kwargs)
    if bootstrap["attempt"] == 1 and server == "model":
        with Path("/work/model-returned.json").open("x") as stream:
            json.dump({"receipt_json": result["receipt_json"]}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        # The harness kills the native host here. This container must be removed
        # by native startup reconciliation before another attempt begins.
        while True:
            time.sleep(0.05)
    if bootstrap["attempt"] == 2 and "checkpoint-gap" in arguments.get("command", ""):
        print(
            json.dumps(
                {"event": "before_patch_checkpoint", "receipt_json": result["receipt_json"]}
            ),
            flush=True,
        )
        os.kill(os.getpid(), signal.SIGKILL)
    return result


agent.env.client.invoke = interrupted
result = run_bootstrap(bootstrap, agent=agent)
print(json.dumps(result), flush=True)
raise SystemExit(0 if result["exit_status"] == "Submitted" else 1)

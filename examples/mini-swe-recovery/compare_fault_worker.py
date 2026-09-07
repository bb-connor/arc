"""Inject one worker death after a real returned patch result, before checkpointing."""

import hashlib
import inspect
import json
import os
import signal
import sys
from pathlib import Path

from chio_mini_swe.worker import build_agent, load_bootstrap, run_bootstrap
from minisweagent.agents.default import DefaultAgent


def main():
    bootstrap = load_bootstrap(sys.stdin.buffer)
    agent = build_agent(bootstrap)
    invoke = agent.env.client.invoke

    def interrupted(key, server, tool, arguments, **kwargs):
        result = invoke(key, server, tool, arguments, **kwargs)
        if (
            bootstrap["attempt"] == 1
            and server == "sandbox"
            and "checkpoint-gap" in arguments.get("command", "")
        ):
            print(
                json.dumps(
                    {
                        "event": "comparison_patch_return_crash",
                        "attempt": bootstrap["attempt"],
                        "receipt_json": result["receipt_json"],
                        "upstream_agent_sha256": hashlib.sha256(
                            Path(inspect.getfile(DefaultAgent)).read_bytes()
                        ).hexdigest(),
                    }
                ),
                flush=True,
            )
            os.kill(os.getpid(), signal.SIGKILL)
        return result

    agent.env.client.invoke = interrupted
    result = run_bootstrap(bootstrap, agent=agent)
    print(json.dumps(result), flush=True)
    return 0 if result["exit_status"] == "Submitted" else 1


if __name__ == "__main__":
    raise SystemExit(main())

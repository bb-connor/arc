"""Qualification worker retaining a denial exactly as returned by the host.

The ordinary reference worker requires an allowed result. This fixture also
checks a declared denial, without retrying or turning it into execution success.
"""

import json
import os
import signal
import sys

from chio_process import ProcessClient


def main():
    bootstrap = json.load(sys.stdin)
    if bootstrap.get("schema") != "chio.process.worker-bootstrap.v1":
        raise ValueError("unsupported worker bootstrap")
    connection, call = bootstrap["connection"], bootstrap["input"]
    if call["process"] != connection["process_id"]:
        raise ValueError("planned call belongs to another worker")
    expected = call["expected_verdict"]
    if expected not in ["allow", "deny"]:
        raise ValueError("unsupported expected verdict")
    client = ProcessClient(connection["socket_path"], connection["credential"])

    def invoke(request):
        # Retain progress without logging arguments, credentials or output.
        label = request["operation_key"]
        print(f"invoke {label}: started", file=sys.stderr, flush=True)
        result = client.invoke(
            label,
            request["server_id"],
            request["tool_name"],
            request["arguments"],
            governed_intent=request["governed_intent"],
        )
        print(f"invoke {label}: {result['verdict']}", file=sys.stderr, flush=True)
        return result

    print("inspect: started", file=sys.stderr, flush=True)
    current = client.inspect()["checkpoint"]
    previous = current["value"]
    if previous is not None:
        if set(previous) != {"response", "probes"}:
            raise RuntimeError("retained observation checkpoint is malformed")
        response = previous["response"]
        observations = previous["probes"]
        print("checkpoint: recovered", file=sys.stderr, flush=True)
    else:
        observations = []
        for probe in call.get("probes", []):
            response = invoke(probe)
            if response["verdict"] != "deny" or response.get("output") is not None:
                raise RuntimeError("unauthorized probe released a result")
            observations.append({"request": probe, "response": response})
        response = invoke(call)
        if call.get("check_replay"):
            replay = invoke(call)
            if replay != response:
                raise RuntimeError("logical replay replaced the original response")
            attempt = dict(call, operation_key="reused-continuation")
            refused = invoke(attempt)
            if refused["verdict"] != "deny" or refused.get("output") is not None:
                raise RuntimeError("continuation authorized an additional result")
            observations.append({"request": attempt, "response": refused})
        print("checkpoint: started", file=sys.stderr, flush=True)
        client.checkpoint(
            current["revision"], {"response": response, "probes": observations}
        )
        print("checkpoint: retained", file=sys.stderr, flush=True)
    if call.get("crash_after_checkpoint") and bootstrap["attempt"] == 1:
        print("crash-after-checkpoint: sigkill", file=sys.stderr, flush=True)
        os.kill(os.getpid(), signal.SIGKILL)
    if response["verdict"] != expected:
        raise RuntimeError(f"expected {expected}, received {response['verdict']}")
    print(
        json.dumps(
            {"request_id": response["request_id"], "verdict": response["verdict"]}
        )
    )


if __name__ == "__main__":
    main()

"""Qualification worker retaining a denial exactly as returned by the host.

The ordinary reference worker requires an allowed result. This fixture also
checks a declared denial, without retrying or turning it into execution success.
"""

import json
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
    response = client.invoke(
        call["operation_key"],
        call["server_id"],
        call["tool_name"],
        call["arguments"],
        governed_intent=call["governed_intent"],
    )
    current = client.inspect()["checkpoint"]
    client.checkpoint(current["revision"], {"response": response})
    if response["verdict"] != expected:
        raise RuntimeError(f"expected {expected}, received {response['verdict']}")
    print(
        json.dumps(
            {"request_id": response["request_id"], "verdict": response["verdict"]}
        )
    )


if __name__ == "__main__":
    main()

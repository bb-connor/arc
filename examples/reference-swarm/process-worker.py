"""One planned call under the existing Linux process supervisor.

The host supplies the authenticated connection on stdin. Input contains the
child's entry from swarm-calls.json. A restart submits the same logical call;
the kernel decides whether its original outcome is recoverable.
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
        raise ValueError("planned call belongs to another authenticated worker")
    client = ProcessClient(connection["socket_path"], connection["credential"])
    response = client.invoke(
        call["operation_key"],
        call["server_id"],
        call["tool_name"],
        call["arguments"],
        governed_intent=call["governed_intent"],
    )
    if response["verdict"] != "allow":
        raise RuntimeError(f"task refused: {response['reason']}")
    current = client.inspect()["checkpoint"]
    value = {"operation_key": call["operation_key"], "response": response}
    if current["value"] != value:
        client.checkpoint(current["revision"], value)
    print(
        json.dumps(
            {
                "process": call["process"],
                "request_id": response["request_id"],
                "verdict": response["verdict"],
            }
        )
    )


if __name__ == "__main__":
    main()

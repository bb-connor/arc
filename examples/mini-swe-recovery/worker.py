"""Installed mini-SWE-agent loop with saved model decisions and a real crash."""

import argparse
import json
import os
import signal
from pathlib import Path

from chio_mini_swe import ChioAgent, ChioEnvironment
from chio_process import ProcessClient
from minisweagent.models.test_models import DeterministicToolcallModel, make_toolcall_output


def decisions():
    batches = [
        ["cat calculator.py; python -m unittest -v"],
        [
            "sed -i 's/return a - b/return a + b/' calculator.py; "
            "printf 'patched\\n' >> effects.txt # checkpoint-gap",
            "printf 'audit\\n' >> effects.txt",
            "printf 'audit\\n' >> effects.txt",
        ],
        [
            "python -m unittest -v > test-output.txt 2>&1 && "
            "printf 'COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT\\nAddition repaired and tests pass.\\n'"
        ],
    ]
    return [
        make_toolcall_output(
            "Repair the repository",
            [
                {
                    "id": f"call-{turn}-{index}",
                    "type": "function",
                    "function": {"name": "bash", "arguments": json.dumps({"command": command})},
                }
                for index, command in enumerate(batch)
            ],
            [
                {"command": command, "tool_call_id": f"call-{turn}-{index}"}
                for index, command in enumerate(batch)
            ],
        )
        for turn, batch in enumerate(batches)
    ]


class CrashClient(ProcessClient):
    def invoke(self, operation_key, server_id, tool_name, arguments):
        result = super().invoke(operation_key, server_id, tool_name, arguments)
        if self.crash and "checkpoint-gap" in arguments["command"] and not self.marker.exists():
            if self.emit:
                print(
                    json.dumps({"event": "before_crash", "receipt": result["receipt_json"]}),
                    flush=True,
                )
            with self.marker.open("x") as stream:
                stream.write(result["receipt_json"])
                stream.flush()
                os.fsync(stream.fileno())
            os.kill(os.getpid(), signal.SIGKILL)
        return result


class RecordedModel(DeterministicToolcallModel):
    def query(self, messages, **kwargs):
        if self.emit:
            print(json.dumps({"event": "model_query", "messages": len(messages)}), flush=True)
        with self.calls.open("a") as stream:
            stream.write(json.dumps({"messages": len(messages)}) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        return super().query(messages, **kwargs)


def main(directory, container=False, crash=False):
    connection = Path("/run/chio/connection.json") if container else directory / "connection.json"
    descriptor = json.loads(connection.read_text())
    client = CrashClient(descriptor["socket_path"], descriptor["credential"])
    client.marker = directory / "before-crash.receipt.json"
    client.emit = container
    client.crash = crash if container else True
    environment = ChioEnvironment(
        client,
        server_id="sandbox",
        tool_name="execute",
        template_vars={"cwd": "/workspace"},
    )
    model = RecordedModel(outputs=decisions())
    model.calls = directory / "provider-calls.jsonl"
    model.emit = container
    instance = ChioAgent(
        model,
        environment,
        run_id="mini-repair-qualification",
        model_id="saved-decisions-v1",
        system_template="Repair the Python repository using bash commands.",
        instance_template="{{task}}",
        step_limit=8,
        cost_limit=10,
        output_path=directory / "trajectory.json",
    )
    saved = instance.journal.read()
    # This upstream deterministic fixture has an in-memory cursor. A real
    # provider derives its next response from the restored conversation.
    if saved is not None:
        model.current_index = saved["n_calls"] - 1
    result = instance.run("Fix addition and verify the existing unit tests.")
    (directory / "result.json").write_text(json.dumps(result, indent=2))
    (directory / "receipts.ndjson").write_text("\n".join(environment.receipts) + "\n")
    if container:
        print(
            json.dumps(
                {
                    "event": "complete",
                    "result": result,
                    "trajectory": instance.serialize(),
                    "receipts": environment.receipts,
                }
            ),
            flush=True,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--container", action="store_true")
    parser.add_argument("--crash", action="store_true")
    args = parser.parse_args()
    main(args.directory, args.container, args.crash)

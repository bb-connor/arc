"""Mini's environment interface, backed exclusively by a host-selected tool."""

import json

from chio_process import ProcessClient
from minisweagent.exceptions import Submitted

from chio_mini_swe.state import digest, encode


class ChioExecutionError(RuntimeError):
    def __init__(self, reason: str, receipt_json: str | None = None):
        super().__init__(f"Chio command stopped: {reason}")
        self.receipt_json = receipt_json


class ChioEnvironment:
    """The worker gets no local execution callback or Docker handle.

    The operator binds server/tool to a sandbox. Template variables describe
    that sandbox; they do not grant authority. One ChioAgent owns this instance.
    """

    def __init__(
        self,
        client: ProcessClient,
        *,
        server_id: str,
        tool_name: str,
        template_vars: dict,
    ):
        if not server_id or not tool_name:
            raise ValueError("A host-selected server and tool are required")
        self.client = client
        self.server_id = server_id
        self.tool_name = tool_name
        self.config = json.loads(encode(template_vars))
        self.receipts: list[str] = []
        self._batch: tuple[str, int, list[dict]] | None = None
        self._index = 0

    def get_template_vars(self, **kwargs):
        return json.loads(encode(self.config)) | kwargs

    def serialize(self):
        return {"info": {"chio": {"server_id": self.server_id, "tool_name": self.tool_name}}}

    def bind(self, run_id: str, turn: int, actions: list[dict]):
        if self._batch is not None:
            raise ChioExecutionError("nested command batch")
        if any(
            not isinstance(action, dict)
            or not isinstance(action.get("command"), str)
            or not action["command"]
            for action in actions
        ):
            raise ChioExecutionError("invalid command batch")
        self._batch = (run_id, turn, json.loads(encode(actions)))
        self._index = 0

    def unbind(self):
        self._batch = None

    def execute(self, action: dict, cwd: str = "") -> dict:
        if self._batch is None or cwd:
            raise ChioExecutionError("command outside a persisted agent decision")
        run_id, turn, actions = self._batch
        index = self._index
        if index >= len(actions) or encode(action) != encode(actions[index]):
            raise ChioExecutionError("command differs from persisted decision")
        self._index += 1
        key = "mini-swe:" + digest(["chio.mini-swe.command.v1", run_id, turn, index])
        # Keep command at the top level so Chio's shell guards classify it.
        result = self.client.invoke(key, self.server_id, self.tool_name, action)
        receipt = result.get("receipt_json")
        if not isinstance(receipt, str) or not receipt:
            raise ChioExecutionError("missing receipt")
        self.receipts.append(receipt)
        if result.get("verdict") != "allow":
            raise ChioExecutionError("denied", receipt)
        if result.get("terminal_state", {}).get("state") != "completed":
            raise ChioExecutionError("unknown or incomplete outcome", receipt)
        output = result.get("output")
        if not isinstance(output, dict) or output.get("kind") != "value":
            raise ChioExecutionError("invalid output", receipt)
        value = output.get("value")
        if isinstance(value, dict) and ("content" in value or "isError" in value):
            if value.get("isError", False) is not False:
                raise ChioExecutionError("MCP execution failed", receipt)
            value = value.get("structuredContent")
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("output"), str)
            or type(value.get("returncode")) is not int
            or not isinstance(value.get("exception_info"), str)
        ):
            raise ChioExecutionError("invalid command result", receipt)
        lines = value["output"].lstrip().splitlines(keepends=True)
        if (
            value["returncode"] == 0
            and lines
            and lines[0].strip() == "COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT"
        ):
            submission = "".join(lines[1:])
            raise Submitted(
                {
                    "role": "exit",
                    "content": submission,
                    "extra": {"exit_status": "Submitted", "submission": submission},
                }
            )
        return value

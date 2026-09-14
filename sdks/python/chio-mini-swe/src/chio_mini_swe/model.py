"""mini-SWE tool-call models through a host-selected, durable Chio operation."""

import json
import math

from minisweagent.exceptions import FormatError
from minisweagent.models.utils.actions_toolcall import format_toolcall_observation_messages
from minisweagent.models.utils.openai_multimodal import expand_multimodal_content

from chio_mini_swe.state import digest, encode

QUERY_SCHEMA = "chio.mini-swe.model-query.v1"
RESULT_SCHEMA = "chio.mini-swe.model-result.v1"
MAX_QUERY_BYTES = 512 * 1024
MAX_RESULT_BYTES = 1024 * 1024
OBSERVATION = (
    "{% if output.exception_info %}<exception>{{output.exception_info}}</exception>\n{% endif %}"
    "<returncode>{{output.returncode}}</returncode>\n<output>\n{{output.output}}</output>"
)


class ChioModelError(RuntimeError):
    def __init__(self, reason, receipt_json=None):
        super().__init__(f"Chio model stopped: {reason}")
        self.receipt_json = receipt_json


def validate_result(value, model_id):
    """Validate the gateway envelope before any provider decision becomes executable."""
    try:
        size = len(encode(value))
    except (TypeError, ValueError):
        raise ChioModelError("invalid model result") from None
    if (
        size > MAX_RESULT_BYTES
        or not isinstance(value, dict)
        or value.get("schema") != RESULT_SCHEMA
        or value.get("model_id") != model_id
    ):
        raise ChioModelError("invalid model result")
    if value.get("kind") == "format_error":
        messages = value.get("messages")
        # Upstream charges the first format observation only. Accept exactly
        # one so an additional paid response cannot escape its cost accounting.
        if not isinstance(messages, list) or len(messages) != 1:
            raise ChioModelError("invalid model format error")
        for message in messages:
            if not isinstance(message, dict) or message.get("role") != "user":
                raise ChioModelError("invalid model format error")
            _cost(message)
        return value
    message = value.get("message")
    if value.get("kind") != "message" or not isinstance(message, dict):
        raise ChioModelError("invalid model message")
    _cost(message)
    actions = message["extra"].get("actions")
    calls = message.get("tool_calls")
    if (
        message.get("role") != "assistant"
        or not isinstance(actions, list)
        or not 1 <= len(actions) <= 64
        or not isinstance(calls, list)
        or len(actions) != len(calls)
    ):
        raise ChioModelError("invalid model tool-call batch")
    ids = set()
    for action, call in zip(actions, calls, strict=True):
        if not isinstance(action, dict) or not isinstance(call, dict):
            raise ChioModelError("invalid model action")
        identifier = call.get("id")
        function = call.get("function")
        if (
            not isinstance(identifier, str)
            or not identifier
            or len(identifier) > 1024
            or identifier in ids
            or call.get("type") != "function"
            or not isinstance(function, dict)
            or function.get("name") != "bash"
            or not isinstance(function.get("arguments"), str)
        ):
            raise ChioModelError("invalid model tool call")
        ids.add(identifier)
        try:
            arguments = json.loads(function["arguments"])
        except ValueError:
            raise ChioModelError("invalid model tool arguments") from None
        command = action.get("command")
        if (
            not isinstance(command, str)
            or not command
            or len(command) > 65536
            or not isinstance(arguments, dict)
            or arguments.get("command") != command
            or set(action) != {"command", "tool_call_id"}
            or action["tool_call_id"] != identifier
        ):
            raise ChioModelError("model action differs from its tool call")
    return value


def _cost(message):
    extra = message.get("extra")
    cost = extra.get("cost") if isinstance(extra, dict) else None
    if type(cost) not in (int, float) or not math.isfinite(cost) or cost < 0:
        raise ChioModelError("missing or invalid model cost")


class ChioModel:
    """No provider client, API key or network fallback is installed in this adapter.

    The host binds the selected tool to one model configuration. Each query must
    be bound by ChioAgent to its original logical turn. The request forbids
    unknown-outcome redispatch independently of the tool's read-only annotation.
    """

    def __init__(self, client, *, server_id, tool_name, model_id, observation_template=OBSERVATION):
        if any(
            not isinstance(v, str) or not v or len(v.encode()) > 1024
            for v in (server_id, tool_name, model_id)
        ):
            raise ValueError("Stable model identity and host-selected route are required")
        if not isinstance(observation_template, str) or len(observation_template) > 16384:
            raise ValueError("Invalid observation template")
        self.client = client
        self.server_id, self.tool_name, self.model_id = server_id, tool_name, model_id
        self.observation_template = observation_template
        self.receipts = []
        self._query = None

    @property
    def binding(self):
        return [
            QUERY_SCHEMA,
            self.server_id,
            self.tool_name,
            self.model_id,
            self.observation_template,
        ]

    def bind(self, run_id, turn):
        if self._query is not None or type(turn) is not int or turn < 1:
            raise ChioModelError("invalid or nested model query")
        self._query = (run_id, turn)

    def unbind(self):
        self._query = None

    def query(self, messages, **kwargs):
        if self._query is None or kwargs:
            raise ChioModelError("model query outside a persisted agent decision")
        run_id, turn = self._query
        query = {
            "schema": QUERY_SCHEMA,
            "model_id": self.model_id,
            "turn": turn,
            "messages": json.loads(encode(messages)),
        }
        if len(encode(query)) > MAX_QUERY_BYTES:
            raise ChioModelError("model request exceeds its byte limit")
        key = "mini-swe-model:" + digest([QUERY_SCHEMA, run_id, turn])
        result = self.client.invoke(
            key, self.server_id, self.tool_name, query, known_outcome_only=True
        )
        receipt = result.get("receipt_json")
        if not isinstance(receipt, str) or not receipt:
            raise ChioModelError("missing receipt")
        self.receipts.append(receipt)
        if result.get("verdict") != "allow":
            raise ChioModelError("denied", receipt)
        if result.get("terminal_state", {}).get("state") != "completed":
            raise ChioModelError("unknown or incomplete provider outcome", receipt)
        output = result.get("output")
        if not isinstance(output, dict) or output.get("kind") != "value":
            raise ChioModelError("invalid output", receipt)
        value = output.get("value")
        if isinstance(value, dict) and ("content" in value or "isError" in value):
            if value.get("isError", False) is not False:
                raise ChioModelError("model gateway failed", receipt)
            value = value.get("structuredContent")
        value = validate_result(value, self.model_id)
        if value["kind"] == "format_error":
            raise FormatError(*value["messages"])
        return value["message"]

    def format_message(self, **kwargs):
        return expand_multimodal_content(kwargs, pattern="")

    def format_observation_messages(self, message, outputs, template_vars=None):
        return format_toolcall_observation_messages(
            actions=message["extra"]["actions"],
            outputs=outputs,
            observation_template=self.observation_template,
            template_vars=template_vars,
        )

    def get_template_vars(self, **kwargs):
        return {"model_name": self.model_id, "observation_template": self.observation_template}

    def serialize(self):
        return {
            "info": {
                "chio_model": {
                    "server_id": self.server_id,
                    "tool_name": self.tool_name,
                    "model_id": self.model_id,
                    "receipts": list(self.receipts),
                }
            }
        }

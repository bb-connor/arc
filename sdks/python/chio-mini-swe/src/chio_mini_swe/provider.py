"""A pinned Chat Completions gateway with one HTTP attempt per Chio invocation."""

import argparse
import contextlib
import http.client
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

from chio_mini_swe.provider_config import (
    identity,
    read_json,
    reject_constant,
    unique_object,
    validate,
)

MAX_RESPONSE_BYTES = 512 * 1024


class ConfiguredChatModel:
    def __init__(self, config):
        self.config = validate(config)
        self.model_id = identity(self.config)

    def query(self, messages):
        # Use upstream's action parser and tool definition without initializing
        # a provider SDK or retry loop. Discovery never enters this method.
        from minisweagent.exceptions import FormatError
        from minisweagent.models.utils.actions_toolcall import BASH_TOOL, parse_toolcall_actions
        from openai.types.chat import ChatCompletion

        config = self.config
        key = os.environ.get(config["credential_env"])
        if not key or len(key) > 8192 or any(ord(c) < 32 or ord(c) > 126 for c in key):
            raise ValueError("The configured provider credential is unavailable or invalid")
        request = {
            "model": config["model"],
            "messages": [
                {key: value for key, value in message.items() if key != "extra"}
                for message in messages
            ],
            "tools": [BASH_TOOL],
            "max_completion_tokens": config["max_output_tokens"],
            "stream": False,
        }
        if "temperature" in config:
            request["temperature"] = config["temperature"]
        target = urlsplit(config["endpoint"])
        options = {"timeout": config["timeout_seconds"]}
        if target.scheme == "https":
            connection = http.client.HTTPSConnection(
                target.hostname, target.port, context=ssl.create_default_context(), **options
            )
        else:
            connection = http.client.HTTPConnection(target.hostname, target.port, **options)
        expired = threading.Event()
        active_socket = None
        response = None

        def stop_connection():
            expired.set()
            # HTTP/1.0 can transfer socket ownership to the response and clear
            # connection.sock while its body is still arriving.
            sock = active_socket or connection.sock
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            connection.close()

        deadline = threading.Timer(config["timeout_seconds"], stop_connection)
        deadline.daemon = True
        # Connect explicitly and disable http.client's implicit reconnect. A
        # timeout between connect and request must never start another socket.
        connection.auto_open = 0
        deadline.start()
        try:
            connection.connect()
            active_socket = connection.sock
            if expired.is_set():
                raise TimeoutError("Provider connection deadline elapsed")
            connection.request(
                "POST",
                target.path.rstrip("/") + "/chat/completions",
                body=json.dumps(request, allow_nan=False, ensure_ascii=False).encode(),
                headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
            )
            response = connection.getresponse()
            if response.status != 200:
                raise RuntimeError("Provider did not return a successful completion")
            payload = response.read(MAX_RESPONSE_BYTES + 1)
            if expired.is_set():
                raise TimeoutError("Provider response deadline elapsed")
            if len(payload) > MAX_RESPONSE_BYTES:
                raise RuntimeError("Provider completion exceeds its byte limit")
        finally:
            deadline.cancel()
            if response is not None:
                response.close()
            connection.close()
        raw = json.loads(payload, object_pairs_hook=unique_object, parse_constant=reject_constant)
        result = ChatCompletion.model_validate(raw)
        if len(result.choices) != 1 or result.choices[0].finish_reason not in {
            "tool_calls",
            "stop",
        }:
            raise RuntimeError("Provider did not complete one tool-call decision")
        usage = raw.get("usage")
        if not isinstance(usage, dict):
            raise ValueError("Provider usage is required for cost accounting")
        for name in ("prompt_tokens", "completion_tokens"):
            if type(usage.get(name)) is not int or not 0 <= usage[name] <= 2**31:
                raise ValueError("Invalid provider token usage")
        if usage["completion_tokens"] > config["max_output_tokens"]:
            raise ValueError("Provider exceeded its configured output token limit")
        cost = (
            usage["prompt_tokens"] * config["input_usd_per_million"]
            + usage["completion_tokens"] * config["output_usd_per_million"]
        ) / 1_000_000
        extra = {"cost": cost, "usage": usage, "timestamp": time.time()}
        message = result.choices[0].message.model_dump(exclude_none=True)
        try:
            actions = parse_toolcall_actions(
                result.choices[0].message.tool_calls or [], format_error_template="{{error}}"
            )
        except FormatError as error:
            error.messages[0].setdefault("extra", {}).update(extra)
            error.messages[0]["extra"]["response"] = raw
            raise
        message["extra"] = {"actions": actions, **extra}
        return message


def main():
    parser = argparse.ArgumentParser(description="Serve one configured coding model through Chio")
    parser.add_argument("--config", required=True)
    parser.add_argument(
        "--describe", action="store_true", help="print the identity without inference"
    )
    args = parser.parse_args()
    model = ConfiguredChatModel(read_json(args.config))
    if args.describe:
        print(json.dumps({"model_id": model.model_id, "tool_name": "model_infer"}))
        return 0
    # Keep the original stdout exclusively for MCP frames. The configured
    # gateway does not inherit upstream dotenv files or process-global budgets.
    outgoing = sys.stdout
    with tempfile.TemporaryDirectory(prefix="chio-provider-") as private:
        os.environ["MSWEA_GLOBAL_CONFIG_DIR"] = private
        os.environ["MSWEA_SILENT_STARTUP"] = "1"
        os.environ["MSWEA_GLOBAL_COST_LIMIT"] = "0"
        os.environ["MSWEA_GLOBAL_CALL_LIMIT"] = "0"
        with contextlib.redirect_stdout(sys.stderr):
            from chio_mini_swe.gateway import serve

            serve(model, model_id=model.model_id, output_stream=outgoing)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

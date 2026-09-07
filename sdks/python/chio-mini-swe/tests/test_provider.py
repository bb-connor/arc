"""The configured gateway's real HTTP boundary, identity and retry behavior."""

import contextlib
import http.client
import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time

import pytest
from chio_mini_swe.gateway import query
from chio_mini_swe.model import QUERY_SCHEMA
from chio_mini_swe.provider import ConfiguredChatModel
from chio_mini_swe.provider_config import SCHEMA, identity, validate


def config(endpoint="https://provider.example/v1"):
    return {
        "schema": SCHEMA,
        "endpoint": endpoint,
        "model": "coding-model",
        "credential_env": "CHIO_TEST_PROVIDER_KEY",
        "max_output_tokens": 1024,
        "timeout_seconds": 2,
        "input_usd_per_million": 2,
        "output_usd_per_million": 8,
    }


def completion():
    return {
        "id": "chatcmpl-fixture",
        "object": "chat.completion",
        "created": 1,
        "model": "coding-model",
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "type": "function",
                            "function": {
                                "name": "bash",
                                "arguments": json.dumps({"command": "echo hello"}),
                            },
                        }
                    ],
                },
            }
        ],
        "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120},
    }


@contextlib.contextmanager
def endpoint(payload=None, mode="success"):
    records = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            data = self.rfile.read(int(self.headers["Content-Length"]))
            records.append(
                {
                    "path": self.path,
                    "authorization": self.headers.get("Authorization"),
                    "request": json.loads(data),
                }
            )
            if mode == "disconnect":
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            body = json.dumps(completion() if payload is None else payload).encode()
            self.send_response(
                {"success": 200, "error": 500, "redirect": 307, "trickle": 200}[mode]
            )
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Location", "/different")
            self.end_headers()
            try:
                if mode == "trickle":
                    for byte in body:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(0.2)
                else:
                    self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        value = config(f"http://127.0.0.1:{server.server_port}/v1")
        value["allow_loopback_http"] = True
        yield value, records
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def request(model):
    return {
        "schema": QUERY_SCHEMA,
        "model_id": model.model_id,
        "turn": 1,
        "messages": [{"role": "user", "content": "Task", "extra": {"private": "metadata"}}],
    }


def test_real_http_uses_only_the_pinned_provider_and_accounts_explicit_usage(monkeypatch):
    monkeypatch.setenv("CHIO_TEST_PROVIDER_KEY", "fixture-key")
    monkeypatch.setenv("OPENAI_API_KEY", "wrong-ambient-key")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    with endpoint() as (value, records):
        model = ConfiguredChatModel(value)
        response = query(model, model.model_id, request(model))
    assert len(records) == 1
    assert records[0]["authorization"] == "Bearer fixture-key"
    assert records[0]["path"] == "/v1/chat/completions"
    outgoing = records[0]["request"]
    assert outgoing["model"] == "coding-model" and outgoing["max_completion_tokens"] == 1024
    assert not outgoing["stream"] and "extra" not in outgoing["messages"][0]
    assert response["message"]["extra"]["cost"] == pytest.approx(0.00036)
    assert response["message"]["extra"]["actions"] == [
        {"command": "echo hello", "tool_call_id": "call-1"}
    ]
    assert "fixture-key" not in json.dumps(response)


@pytest.mark.parametrize("mode", ["error", "redirect", "disconnect"])
def test_errors_redirects_and_lost_responses_never_add_an_http_retry(mode, monkeypatch):
    monkeypatch.setenv("CHIO_TEST_PROVIDER_KEY", "fixture-key")
    monkeypatch.setenv("MSWEA_MODEL_RETRY_STOP_AFTER_ATTEMPT", "10")
    with endpoint(mode=mode) as (value, records):
        model = ConfiguredChatModel(value)
        with pytest.raises((RuntimeError, http.client.HTTPException, OSError)):
            query(model, model.model_id, request(model))
        assert len(records) == 1


@pytest.mark.parametrize("mutation", ["usage", "boolean", "tokens", "finish", "choices"])
def test_incomplete_or_unaccounted_provider_results_stop(mutation, monkeypatch):
    monkeypatch.setenv("CHIO_TEST_PROVIDER_KEY", "fixture-key")
    payload = completion()
    if mutation == "usage":
        del payload["usage"]
    elif mutation == "boolean":
        payload["usage"]["prompt_tokens"] = True
    elif mutation == "tokens":
        payload["usage"]["completion_tokens"] = 1025
    elif mutation == "finish":
        payload["choices"][0]["finish_reason"] = "length"
    else:
        payload["choices"] *= 2
    with endpoint(payload) as (value, records):
        model = ConfiguredChatModel(value)
        with pytest.raises((ValueError, RuntimeError)):
            query(model, model.model_id, request(model))
        assert len(records) == 1


def test_every_provider_setting_participates_in_the_bound_identity():
    value = config()
    initial = identity(value)
    for key, replacement in {
        "endpoint": "https://different.example/v1",
        "model": "different",
        "credential_env": "DIFFERENT_KEY",
        "max_output_tokens": 512,
        "timeout_seconds": 3,
        "input_usd_per_million": 3,
        "output_usd_per_million": 9,
        "temperature": 0,
        "allow_loopback_http": True,
    }.items():
        assert identity(value | {key: replacement}) != initial
    assert identity(value | {"input_usd_per_million": 2.0}) == initial


def test_slow_response_cannot_reset_the_total_network_deadline(monkeypatch):
    monkeypatch.setenv("CHIO_TEST_PROVIDER_KEY", "fixture-key")
    with endpoint(mode="trickle") as (value, records):
        value["timeout_seconds"] = 1
        model = ConfiguredChatModel(value)
        started = time.monotonic()
        with pytest.raises((TimeoutError, http.client.HTTPException, OSError)):
            query(model, model.model_id, request(model))
        assert time.monotonic() - started < 2.5
        assert len(records) == 1


def test_completed_format_error_retains_its_usage_cost_and_response(monkeypatch):
    monkeypatch.setenv("CHIO_TEST_PROVIDER_KEY", "fixture-key")
    payload = completion()
    payload["choices"][0]["finish_reason"] = "stop"
    payload["choices"][0]["message"]["tool_calls"] = []
    with endpoint(payload) as (value, records):
        model = ConfiguredChatModel(value)
        response = query(model, model.model_id, request(model))
    assert response["kind"] == "format_error" and len(records) == 1
    assert response["messages"][0]["extra"]["cost"] == pytest.approx(0.00036)
    assert response["messages"][0]["extra"]["response"] == payload


def test_configuration_rejects_credentials_and_insecure_endpoint_overrides():
    for changes in [
        {"api_key": "must-not-be-accepted"},
        {"timeout_seconds": 0},
        {"endpoint": "http://provider.example/v1", "allow_loopback_http": True},
        {"endpoint": "https://user:secret@provider.example/v1"},
        {"endpoint": "https://provider.example/v1?secret=value"},
        {"input_usd_per_million": float("nan")},
        {"max_output_tokens": True},
    ]:
        with pytest.raises(ValueError):
            validate(config() | changes)


def test_console_discovery_loads_no_ambient_dotenv_or_credential(tmp_path):
    path = tmp_path / "provider.json"
    path.write_text(json.dumps(config()))
    ambient = tmp_path / "ambient"
    ambient.mkdir()
    (ambient / ".env").write_text("MSWEA_GLOBAL_COST_LIMIT=invalid-number\n")
    env = dict(os.environ, MSWEA_GLOBAL_CONFIG_DIR=str(ambient))
    env.pop("CHIO_TEST_PROVIDER_KEY", None)
    env.pop("MSWEA_SILENT_STARTUP", None)
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26"},
        },
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    result = subprocess.run(
        [sys.executable, "-m", "chio_mini_swe.provider", "--config", str(path)],
        input="\n".join(json.dumps(v) for v in messages) + "\n",
        capture_output=True,
        text=True,
        env=env,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    outputs = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(outputs) == 2
    assert outputs[1]["result"]["tools"][0]["inputSchema"]["properties"]["model_id"][
        "const"
    ] == identity(config())

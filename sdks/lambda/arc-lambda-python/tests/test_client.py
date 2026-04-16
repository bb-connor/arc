"""Unit tests for :class:`arc_lambda.ArcLambdaClient`."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from arc_lambda import ArcLambdaClient, ArcLambdaError


def _mock_transport(
    handler: Any,
) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def test_evaluate_allow_returns_verdict() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/evaluate"
        body = json.loads(request.content.decode("utf-8"))
        assert body["capability_id"] == "cap-1"
        assert body["tool_server"] == "srv"
        assert body["tool_name"] == "tool"
        return httpx.Response(
            200,
            json={
                "decision": "allow",
                "receipt_id": "rcpt-1",
                "reason": None,
                "capability_id": "cap-1",
                "tool_server": "srv",
                "tool_name": "tool",
                "timestamp": 1_700_000_000,
            },
        )

    with ArcLambdaClient(transport=_mock_transport(handler)) as client:
        verdict = client.evaluate(
            capability_id="cap-1", tool_server="srv", tool_name="tool"
        )

    assert verdict.allowed
    assert not verdict.denied
    assert verdict.receipt_id == "rcpt-1"
    assert verdict.decision == "allow"


def test_evaluate_deny_reports_reason() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "decision": "deny",
                "receipt_id": "rcpt-2",
                "reason": "missing tool_name",
                "capability_id": "cap-1",
                "tool_server": "srv",
                "tool_name": "",
                "timestamp": 1_700_000_001,
            },
        )

    with ArcLambdaClient(transport=_mock_transport(handler)) as client:
        verdict = client.evaluate(
            capability_id="cap-1", tool_server="srv", tool_name=""
        )

    assert verdict.denied
    assert verdict.reason == "missing tool_name"


def test_evaluate_forwards_scope_and_arguments() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content.decode("utf-8")))
        return httpx.Response(
            200,
            json={
                "decision": "allow",
                "receipt_id": "r",
                "reason": None,
                "capability_id": "c",
                "tool_server": "s",
                "tool_name": "t",
                "timestamp": 1,
            },
        )

    with ArcLambdaClient(transport=_mock_transport(handler)) as client:
        client.evaluate(
            capability_id="c",
            tool_server="s",
            tool_name="t",
            scope="db:read",
            arguments={"sql": "SELECT 1"},
        )

    assert captured["scope"] == "db:read"
    assert captured["arguments"] == {"sql": "SELECT 1"}


def test_evaluate_raises_on_connection_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("extension not running")

    with (
        ArcLambdaClient(transport=_mock_transport(handler)) as client,
        pytest.raises(ArcLambdaError) as exc,
    ):
        client.evaluate(capability_id="c", tool_server="s", tool_name="t")

    assert "unreachable" in str(exc.value)


def test_evaluate_raises_on_timeout() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    with (
        ArcLambdaClient(transport=_mock_transport(handler)) as client,
        pytest.raises(ArcLambdaError),
    ):
        client.evaluate(capability_id="c", tool_server="s", tool_name="t")


def test_evaluate_raises_on_5xx() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="boom")

    with (
        ArcLambdaClient(transport=_mock_transport(handler)) as client,
        pytest.raises(ArcLambdaError) as exc,
    ):
        client.evaluate(capability_id="c", tool_server="s", tool_name="t")

    assert "503" in str(exc.value)


def test_evaluate_raises_on_malformed_response() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        # Missing required "decision" field
        return httpx.Response(200, json={"not_a_decision": "oops"})

    with (
        ArcLambdaClient(transport=_mock_transport(handler)) as client,
        pytest.raises(ArcLambdaError),
    ):
        client.evaluate(capability_id="c", tool_server="s", tool_name="t")


def test_evaluate_raises_on_non_json_response() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=b"<html>not json</html>", headers={"content-type": "text/html"}
        )

    with (
        ArcLambdaClient(transport=_mock_transport(handler)) as client,
        pytest.raises(ArcLambdaError) as exc,
    ):
        client.evaluate(capability_id="c", tool_server="s", tool_name="t")

    assert "non-JSON" in str(exc.value)


def test_evaluate_unknown_decision_treated_as_deny() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "decision": "maybe",
                "receipt_id": "r",
                "reason": None,
                "capability_id": "c",
                "tool_server": "s",
                "tool_name": "t",
                "timestamp": 1,
            },
        )

    with ArcLambdaClient(transport=_mock_transport(handler)) as client:
        verdict = client.evaluate(capability_id="c", tool_server="s", tool_name="t")

    # Fail-closed: unknown decisions are treated as deny.
    assert not verdict.allowed
    assert verdict.denied


def test_health_returns_payload() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/health"
        return httpx.Response(200, json={"status": "ok", "extension": "arc"})

    with ArcLambdaClient(transport=_mock_transport(handler)) as client:
        payload = client.health()

    assert payload["status"] == "ok"

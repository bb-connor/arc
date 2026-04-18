"""Unit tests for the :func:`arc_lambda.arc_tool` decorator."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from arc_lambda import ArcLambdaClient, ArcLambdaError, arc_tool


def _client(responder: Any) -> ArcLambdaClient:
    return ArcLambdaClient(transport=httpx.MockTransport(responder))


def _allow_response(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "decision": "allow",
            "receipt_id": "r-allow",
            "reason": None,
            "capability_id": "cap-1",
            "tool_server": "srv",
            "tool_name": "tool",
            "timestamp": 1_700_000_000,
        },
    )


def _deny_response(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "decision": "deny",
            "receipt_id": "r-deny",
            "reason": "not authorized",
            "capability_id": "cap-1",
            "tool_server": "srv",
            "tool_name": "tool",
            "timestamp": 1_700_000_001,
        },
    )


def _unreachable(_request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("extension down")


def test_decorator_allows_and_calls_wrapped_function() -> None:
    client = _client(_allow_response)

    @arc_tool(scope="db:read", tool_server="srv", tool_name="tool", client=client)
    def handler(event: dict[str, Any], context: object) -> dict[str, Any]:
        return {"event": event}

    result = handler({"arc_capability_id": "cap-1", "foo": "bar"}, None)
    assert result == {"event": {"arc_capability_id": "cap-1", "foo": "bar"}}


def test_decorator_injects_capability_id_when_requested() -> None:
    client = _client(_allow_response)
    captured: dict[str, Any] = {}

    @arc_tool(scope="db:read", tool_server="srv", tool_name="tool", client=client)
    def handler(
        event: dict[str, Any], context: object, capability_id: str
    ) -> None:
        captured["capability_id"] = capability_id

    handler({"arc_capability_id": "cap-1"}, None)
    assert captured["capability_id"] == "cap-1"


def test_decorator_injects_verdict_when_requested() -> None:
    client = _client(_allow_response)
    captured: dict[str, Any] = {}

    @arc_tool(scope="db:read", tool_server="srv", tool_name="tool", client=client)
    def handler(event: dict[str, Any], context: object, verdict: Any) -> None:
        captured["verdict"] = verdict

    handler({"arc_capability_id": "cap-1"}, None)
    assert captured["verdict"].allowed is True
    assert captured["verdict"].receipt_id == "r-allow"


def test_decorator_denies_raises_and_skips_handler() -> None:
    client = _client(_deny_response)
    called = False

    @arc_tool(scope="db:read", tool_server="srv", tool_name="tool", client=client)
    def handler(event: dict[str, Any], context: object) -> None:
        nonlocal called
        called = True

    with pytest.raises(ArcLambdaError) as exc:
        handler({"arc_capability_id": "cap-1"}, None)

    assert "not authorized" in str(exc.value)
    assert called is False


def test_decorator_unreachable_fails_closed() -> None:
    client = _client(_unreachable)
    called = False

    @arc_tool(scope="db:read", tool_server="srv", tool_name="tool", client=client)
    def handler(event: dict[str, Any], context: object) -> None:
        nonlocal called
        called = True

    with pytest.raises(ArcLambdaError):
        handler({"arc_capability_id": "cap-1"}, None)

    assert called is False


def test_decorator_requires_capability_id() -> None:
    client = _client(_allow_response)

    @arc_tool(scope="db:read", tool_server="srv", tool_name="tool", client=client)
    def handler(event: dict[str, Any], context: object) -> None:
        pass

    with pytest.raises(ArcLambdaError) as exc:
        handler({}, None)

    assert "capability_id is required" in str(exc.value)


def test_decorator_capability_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client(_allow_response)
    monkeypatch.setenv("ARC_CAPABILITY_ID", "cap-env")

    @arc_tool(scope="db:read", tool_server="srv", tool_name="tool", client=client)
    def handler(event: dict[str, Any], context: object) -> str:
        return "ok"

    assert handler({}, None) == "ok"


def test_decorator_explicit_capability_id_overrides_event() -> None:
    client = _client(_allow_response)

    @arc_tool(scope="db:read", tool_server="srv", tool_name="tool", client=client)
    def handler(
        event: dict[str, Any], context: object, capability_id: str
    ) -> str:
        return capability_id

    result = handler(
        {"arc_capability_id": "cap-from-event"},
        None,
        capability_id="cap-explicit",
    )
    assert result == "cap-explicit"


def test_decorator_custom_arguments_extractor() -> None:
    captured: dict[str, Any] = {}

    def responder(request: httpx.Request) -> httpx.Response:
        import json

        body = json.loads(request.content.decode("utf-8"))
        captured["arguments"] = body.get("arguments")
        return _allow_response(request)

    client = _client(responder)

    @arc_tool(
        scope="db:read",
        tool_server="srv",
        tool_name="tool",
        client=client,
        arguments_extractor=lambda event: {"only": event.get("body")},
    )
    def handler(event: dict[str, Any], context: object) -> None:
        pass

    handler({"arc_capability_id": "cap-1", "body": "payload"}, None)
    assert captured["arguments"] == {"only": "payload"}

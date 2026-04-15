"""Tests for ARC ASGI middleware."""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable
from unittest.mock import AsyncMock, patch

import pytest

from arc_asgi.config import ArcASGIConfig
from arc_asgi.middleware import ArcASGIMiddleware, _extract_capability_token
from arc_sdk.errors import ArcConnectionError
from arc_sdk.models import EvaluateResponse, HttpReceipt, Verdict


# ---------------------------------------------------------------------------
# ASGI type helpers
# ---------------------------------------------------------------------------

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]


def _make_scope(
    method: str = "GET",
    path: str = "/test",
    headers: dict[str, str] | None = None,
    query_string: str = "",
) -> Scope:
    raw_headers: list[tuple[bytes, bytes]] = []
    if headers:
        for k, v in headers.items():
            raw_headers.append(
                (k.lower().encode("latin-1"), v.encode("latin-1"))
            )
    return {
        "type": "http",
        "method": method,
        "path": path,
        "headers": raw_headers,
        "query_string": query_string.encode("latin-1"),
    }


def _make_receive(body: bytes = b"") -> Receive:
    """Create a mock ASGI receive callable."""
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    return receive


def _make_send() -> tuple[Send, list[dict[str, Any]]]:
    """Create a mock ASGI send callable that records messages."""
    messages: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    return send, messages


def _make_receipt(
    allowed: bool = True,
    receipt_id: str = "receipt-1",
) -> HttpReceipt:
    verdict = (
        Verdict.allow()
        if allowed
        else Verdict.deny("blocked", "TestGuard", 403)
    )
    return HttpReceipt(
        id=receipt_id,
        request_id="req-1",
        route_pattern="/test",
        method="GET",
        caller_identity_hash="abc",
        verdict=verdict,
        response_status=200 if allowed else 403,
        timestamp=1700000000,
        content_hash="x",
        policy_hash="y",
        kernel_key="k",
        signature="s",
    )


def _make_evaluation(
    allowed: bool = True,
    receipt_id: str = "receipt-1",
) -> EvaluateResponse:
    receipt = _make_receipt(allowed=allowed, receipt_id=receipt_id)
    return EvaluateResponse(
        verdict=receipt.verdict,
        receipt=receipt,
        evidence=[],
    )


async def _echo_app(scope: Scope, receive: Receive, send: Send) -> None:
    """Simple ASGI app that returns 200 OK."""
    await send({
        "type": "http.response.start",
        "status": 200,
        "headers": [(b"content-type", b"text/plain")],
    })
    await send({
        "type": "http.response.body",
        "body": b"ok",
    })


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestExcludePaths:
    async def test_excluded_path_bypasses_evaluation(self) -> None:
        config = ArcASGIConfig(exclude_paths=frozenset({"/health"}))
        mw = ArcASGIMiddleware(_echo_app, config=config)

        scope = _make_scope(path="/health")
        send, messages = _make_send()
        await mw(scope, _make_receive(), send)

        assert any(m.get("status") == 200 for m in messages)


class TestExcludeMethods:
    async def test_options_excluded_by_default(self) -> None:
        mw = ArcASGIMiddleware(_echo_app)
        scope = _make_scope(method="OPTIONS")
        send, messages = _make_send()
        await mw(scope, _make_receive(), send)

        assert any(m.get("status") == 200 for m in messages)


class TestNonHttpScope:
    async def test_websocket_passthrough(self) -> None:
        called = False

        async def ws_app(scope: Scope, receive: Receive, send: Send) -> None:
            nonlocal called
            called = True

        mw = ArcASGIMiddleware(ws_app)
        scope = {"type": "websocket", "path": "/ws"}
        await mw(scope, _make_receive(), _make_send()[0])
        assert called


class TestAllowedRequest:
    async def test_forwards_on_allow(self) -> None:
        evaluation = _make_evaluation(allowed=True, receipt_id="r-allow")

        with patch(
            "arc_asgi.middleware.ArcClient", autospec=True
        ) as MockClient:
            instance = MockClient.return_value
            instance.evaluate_http_request = AsyncMock(return_value=evaluation)

            config = ArcASGIConfig(sidecar_url="http://mock:9090")
            mw = ArcASGIMiddleware(_echo_app, config=config)

            scope = _make_scope()
            send, messages = _make_send()
            await mw(scope, _make_receive(), send)

            # Should get 200 from echo app
            start_msg = next(
                m for m in messages if m.get("type") == "http.response.start"
            )
            assert start_msg["status"] == 200

            # Should include receipt header
            header_dict = dict(start_msg.get("headers", []))
            assert b"x-arc-receipt" in header_dict
            assert header_dict[b"x-arc-receipt"] == b"r-allow"


class TestDeniedRequest:
    async def test_returns_error_on_deny(self) -> None:
        evaluation = _make_evaluation(allowed=False, receipt_id="r-deny")

        with patch(
            "arc_asgi.middleware.ArcClient", autospec=True
        ) as MockClient:
            instance = MockClient.return_value
            instance.evaluate_http_request = AsyncMock(return_value=evaluation)

            config = ArcASGIConfig(sidecar_url="http://mock:9090")
            mw = ArcASGIMiddleware(_echo_app, config=config)

            scope = _make_scope()
            send, messages = _make_send()
            await mw(scope, _make_receive(), send)

            start_msg = next(
                m for m in messages if m.get("type") == "http.response.start"
            )
            assert start_msg["status"] == 403

            body_msg = next(
                m for m in messages if m.get("type") == "http.response.body"
            )
            body = json.loads(body_msg["body"])
            assert body["error"] == "TestGuard"


class TestSidecarUnavailable:
    async def test_fail_closed_by_default(self) -> None:
        with patch(
            "arc_asgi.middleware.ArcClient", autospec=True
        ) as MockClient:
            instance = MockClient.return_value
            instance.evaluate_http_request = AsyncMock(
                side_effect=ArcConnectionError("connection refused")
            )

            config = ArcASGIConfig(
                sidecar_url="http://mock:9090", fail_open=False
            )
            mw = ArcASGIMiddleware(_echo_app, config=config)

            scope = _make_scope()
            send, messages = _make_send()
            await mw(scope, _make_receive(), send)

            start_msg = next(
                m for m in messages if m.get("type") == "http.response.start"
            )
            assert start_msg["status"] == 503

    async def test_fail_open(self) -> None:
        observed_passthrough = None

        async def app_with_passthrough(scope: Scope, receive: Receive, send: Send) -> None:
            nonlocal observed_passthrough
            observed_passthrough = scope.get("state", {}).get("arc_passthrough")
            await _echo_app(scope, receive, send)

        with patch(
            "arc_asgi.middleware.ArcClient", autospec=True
        ) as MockClient:
            instance = MockClient.return_value
            instance.evaluate_http_request = AsyncMock(
                side_effect=ArcConnectionError("connection refused")
            )

            config = ArcASGIConfig(
                sidecar_url="http://mock:9090", fail_open=True
            )
            mw = ArcASGIMiddleware(app_with_passthrough, config=config)

            scope = _make_scope()
            send, messages = _make_send()
            await mw(scope, _make_receive(), send)

            start_msg = next(
                m for m in messages if m.get("type") == "http.response.start"
            )
            assert start_msg["status"] == 200
            header_dict = dict(start_msg.get("headers", []))
            assert b"x-arc-receipt" not in header_dict
            assert observed_passthrough is not None
            assert observed_passthrough.mode == "allow_without_receipt"
            assert observed_passthrough.error == "arc_sidecar_unreachable"


class TestReceiptCallback:
    async def test_on_receipt_called(self) -> None:
        evaluation = _make_evaluation(allowed=True)
        callback = AsyncMock()

        with patch(
            "arc_asgi.middleware.ArcClient", autospec=True
        ) as MockClient:
            instance = MockClient.return_value
            instance.evaluate_http_request = AsyncMock(return_value=evaluation)

            config = ArcASGIConfig(sidecar_url="http://mock:9090")
            mw = ArcASGIMiddleware(
                _echo_app, config=config, on_receipt=callback
            )

            scope = _make_scope()
            send, _ = _make_send()
            await mw(scope, _make_receive(), send)

            callback.assert_awaited_once_with(evaluation.receipt)


class TestCapabilityIdExtraction:
    def test_from_header(self) -> None:
        scope = _make_scope(headers={"x-arc-capability": "cap-123"})
        assert _extract_capability_token(scope) == "cap-123"

    def test_from_query_string(self) -> None:
        scope = _make_scope(query_string="arc_capability=cap-456&other=val")
        assert _extract_capability_token(scope) == "cap-456"

    def test_none_when_missing(self) -> None:
        scope = _make_scope()
        assert _extract_capability_token(scope) is None

    def test_header_takes_precedence(self) -> None:
        scope = _make_scope(
            headers={"x-arc-capability": "cap-header"},
            query_string="arc_capability=cap-query",
        )
        assert _extract_capability_token(scope) == "cap-header"


class TestConfig:
    def test_defaults(self) -> None:
        config = ArcASGIConfig()
        assert config.sidecar_url == "http://127.0.0.1:9090"
        assert config.fail_open is False
        assert "OPTIONS" in config.exclude_methods
        assert config.receipt_header == "X-Arc-Receipt"

    def test_custom(self) -> None:
        config = ArcASGIConfig(
            sidecar_url="http://localhost:9999",
            fail_open=True,
            exclude_paths=frozenset({"/healthz", "/ready"}),
        )
        assert config.fail_open is True
        assert "/healthz" in config.exclude_paths

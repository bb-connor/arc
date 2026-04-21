"""Tests for chio-django middleware."""

from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest
from django.test import RequestFactory, TestCase, override_settings
from django.http import HttpResponse, JsonResponse

from chio_django.middleware import ChioDjangoMiddleware, _extract_caller


class TestExtractCaller:
    def test_bearer_token(self) -> None:
        factory = RequestFactory()
        request = factory.get("/test", HTTP_AUTHORIZATION="Bearer my-token")
        caller = _extract_caller(request)
        assert caller.auth_method.method == "bearer"
        assert caller.auth_method.token_hash is not None

    def test_api_key(self) -> None:
        factory = RequestFactory()
        request = factory.get("/test", HTTP_X_API_KEY="key-123")
        caller = _extract_caller(request)
        assert caller.auth_method.method == "api_key"

    def test_session_cookie(self) -> None:
        factory = RequestFactory()
        request = factory.get("/test")
        request.COOKIES["session"] = "sess-abc"
        caller = _extract_caller(request)
        assert caller.auth_method.method == "cookie"

    def test_anonymous(self) -> None:
        factory = RequestFactory()
        request = factory.get("/test")
        caller = _extract_caller(request)
        assert caller.auth_method.method == "anonymous"
        assert caller.subject == "anonymous"


class TestMiddlewareExclusions(TestCase):
    def _get_middleware(self) -> ChioDjangoMiddleware:
        def get_response(request):
            return JsonResponse({"status": "ok"})
        return ChioDjangoMiddleware(get_response)

    def test_options_excluded(self) -> None:
        mw = self._get_middleware()
        factory = RequestFactory()
        request = factory.options("/test")
        response = mw(request)
        assert response.status_code == 200

    @override_settings(CHIO_EXCLUDE_PATHS=["/health"])
    def test_excluded_path(self) -> None:
        mw = self._get_middleware()
        factory = RequestFactory()
        request = factory.get("/health")
        response = mw(request)
        assert response.status_code == 200


class TestMiddlewareAllowed(TestCase):
    @patch("chio_django.middleware.httpx.post")
    def test_allowed_request(self, mock_post: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "verdict": {"verdict": "allow"},
            "receipt": {
                "id": "receipt-1",
                "verdict": {"verdict": "allow"},
            },
        }
        mock_post.return_value = mock_resp

        def get_response(request):
            return JsonResponse({"status": "ok"})

        mw = ChioDjangoMiddleware(get_response)
        factory = RequestFactory()
        request = factory.get("/protected")
        response = mw(request)

        assert response.status_code == 200
        assert response["X-Chio-Receipt"] == "receipt-1"


class TestMiddlewareDenied(TestCase):
    @patch("chio_django.middleware.httpx.post")
    def test_denied_request(self, mock_post: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "verdict": {
                "verdict": "deny",
                "reason": "no capability",
                "guard": "CapGuard",
                "http_status": 403,
            },
            "receipt": {
                "id": "receipt-2",
                "verdict": {
                    "verdict": "deny",
                    "reason": "no capability",
                    "guard": "CapGuard",
                    "http_status": 403,
                },
            },
        }
        mock_post.return_value = mock_resp

        def get_response(request):
            return JsonResponse({"status": "ok"})

        mw = ChioDjangoMiddleware(get_response)
        factory = RequestFactory()
        request = factory.get("/protected")
        response = mw(request)

        assert response.status_code == 403
        body = json.loads(response.content)
        assert body["error"]["code"] == "CHIO_GUARD_DENIED"


class TestMiddlewareSidecarDown(TestCase):
    @patch("chio_django.middleware.httpx.post")
    def test_fail_closed(self, mock_post: MagicMock) -> None:
        import httpx
        mock_post.side_effect = httpx.ConnectError("connection refused")

        def get_response(request):
            return JsonResponse({"status": "ok"})

        mw = ChioDjangoMiddleware(get_response)
        factory = RequestFactory()
        request = factory.get("/protected")
        response = mw(request)

        assert response.status_code == 503

    @override_settings(CHIO_FAIL_OPEN=True)
    @patch("chio_django.middleware.httpx.post")
    def test_fail_open(self, mock_post: MagicMock) -> None:
        import httpx
        mock_post.side_effect = httpx.ConnectError("connection refused")

        observed_request = None

        def get_response(request):
            nonlocal observed_request
            observed_request = request
            return JsonResponse({"status": "ok"})

        mw = ChioDjangoMiddleware(get_response)
        factory = RequestFactory()
        request = factory.get("/protected")
        response = mw(request)

        assert response.status_code == 200
        assert "X-Chio-Receipt" not in response
        assert observed_request is not None
        assert observed_request.chio_passthrough.mode == "allow_without_receipt"
        assert observed_request.chio_passthrough.error == "chio_sidecar_unreachable"


class TestMiddlewareBadSidecarResponse(TestCase):
    @patch("chio_django.middleware.httpx.post")
    def test_sidecar_500(self, mock_post: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_post.return_value = mock_resp

        def get_response(request):
            return JsonResponse({"status": "ok"})

        mw = ChioDjangoMiddleware(get_response)
        factory = RequestFactory()
        request = factory.get("/protected")
        response = mw(request)

        assert response.status_code == 502
        body = json.loads(response.content)
        assert body["error"]["code"] == "CHIO_INTERNAL_ERROR"


class TestErrors:
    def test_all_error_codes(self) -> None:
        from chio_django.errors import ChioErrorCode, chio_error_response

        for code in ChioErrorCode:
            resp = chio_error_response(400, code, "test")
            body = json.loads(resp.content)
            assert body["error"]["code"] == code.value

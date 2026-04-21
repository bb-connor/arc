"""Tests for chio-fastapi error responses."""

from __future__ import annotations

import json

from chio_fastapi.errors import ChioErrorCode, chio_error_response


class TestChioErrorResponse:
    def test_basic_error(self) -> None:
        resp = chio_error_response(
            403,
            ChioErrorCode.GUARD_DENIED,
            "ForbiddenPathGuard denied the request",
            guard="ForbiddenPathGuard",
        )
        assert resp.status_code == 403
        body = json.loads(resp.body)
        assert body["error"]["code"] == "CHIO_GUARD_DENIED"
        assert body["error"]["guard"] == "ForbiddenPathGuard"

    def test_error_with_details(self) -> None:
        resp = chio_error_response(
            403,
            ChioErrorCode.BUDGET_EXCEEDED,
            "Budget exceeded",
            details={"remaining": 0, "requested": 100},
        )
        body = json.loads(resp.body)
        assert body["error"]["details"]["remaining"] == 0

    def test_all_error_codes(self) -> None:
        codes = [
            ChioErrorCode.CAPABILITY_REQUIRED,
            ChioErrorCode.CAPABILITY_EXPIRED,
            ChioErrorCode.CAPABILITY_INSUFFICIENT,
            ChioErrorCode.GUARD_DENIED,
            ChioErrorCode.APPROVAL_REQUIRED,
            ChioErrorCode.BUDGET_EXCEEDED,
            ChioErrorCode.SIDECAR_UNAVAILABLE,
            ChioErrorCode.INTERNAL_ERROR,
        ]
        for code in codes:
            resp = chio_error_response(400, code, "test")
            body = json.loads(resp.body)
            assert body["error"]["code"] == code.value

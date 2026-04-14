"""Tests for arc-fastapi error responses."""

from __future__ import annotations

import json

from arc_fastapi.errors import ArcErrorCode, arc_error_response


class TestArcErrorResponse:
    def test_basic_error(self) -> None:
        resp = arc_error_response(
            403,
            ArcErrorCode.GUARD_DENIED,
            "ForbiddenPathGuard denied the request",
            guard="ForbiddenPathGuard",
        )
        assert resp.status_code == 403
        body = json.loads(resp.body)
        assert body["error"]["code"] == "ARC_GUARD_DENIED"
        assert body["error"]["guard"] == "ForbiddenPathGuard"

    def test_error_with_details(self) -> None:
        resp = arc_error_response(
            403,
            ArcErrorCode.BUDGET_EXCEEDED,
            "Budget exceeded",
            details={"remaining": 0, "requested": 100},
        )
        body = json.loads(resp.body)
        assert body["error"]["details"]["remaining"] == 0

    def test_all_error_codes(self) -> None:
        codes = [
            ArcErrorCode.CAPABILITY_REQUIRED,
            ArcErrorCode.CAPABILITY_EXPIRED,
            ArcErrorCode.CAPABILITY_INSUFFICIENT,
            ArcErrorCode.GUARD_DENIED,
            ArcErrorCode.APPROVAL_REQUIRED,
            ArcErrorCode.BUDGET_EXCEEDED,
            ArcErrorCode.SIDECAR_UNAVAILABLE,
            ArcErrorCode.INTERNAL_ERROR,
        ]
        for code in codes:
            resp = arc_error_response(400, code, "test")
            body = json.loads(resp.body)
            assert body["error"]["code"] == code.value

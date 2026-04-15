"""Django WSGI middleware for ARC protocol evaluation.

Intercepts incoming Django requests, extracts caller identity, and evaluates
the request against ARC policies via the sidecar. Uses synchronous httpx
since Django WSGI middleware runs synchronously.

Usage in settings.py::

    MIDDLEWARE = [
        ...
        "arc_django.ArcDjangoMiddleware",
        ...
    ]

    ARC_SIDECAR_URL = "http://127.0.0.1:9090"
    ARC_FAIL_OPEN = False
    ARC_EXCLUDE_PATHS = ["/health", "/ready"]
    ARC_EXCLUDE_METHODS = ["OPTIONS"]
    ARC_RECEIPT_HEADER = "X-Arc-Receipt"
"""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any, Callable

import httpx
from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse

from arc_sdk.models import ArcPassthrough, AuthMethod, CallerIdentity, CapabilityToken


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _capability_id_from_token(raw_token: str | None) -> str | None:
    if raw_token is None:
        return None
    try:
        return CapabilityToken.model_validate_json(raw_token).id
    except Exception:
        return None


def _extract_caller(request: HttpRequest) -> CallerIdentity:
    """Extract caller identity from a Django HttpRequest."""
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            token_hash = _sha256_hex(token)
            return CallerIdentity(
                subject=token_hash,
                auth_method=AuthMethod.bearer(token_hash=token_hash),
                verified=False,
            )

    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        key_hash = _sha256_hex(api_key)
        return CallerIdentity(
            subject=key_hash,
            auth_method=AuthMethod.api_key(key_name="x-api-key", key_hash=key_hash),
            verified=False,
        )

    session_cookie = request.COOKIES.get("session", "")
    if session_cookie:
        cookie_hash = _sha256_hex(session_cookie)
        return CallerIdentity(
            subject=cookie_hash,
            auth_method=AuthMethod.cookie(
                cookie_name="session", cookie_hash=cookie_hash
            ),
            verified=False,
        )

    return CallerIdentity.anonymous()


class ArcDjangoMiddleware:
    """Django middleware that evaluates requests through the ARC sidecar.

    Reads configuration from Django settings:

    - ``ARC_SIDECAR_URL``: sidecar base URL (default ``http://127.0.0.1:9090``)
    - ``ARC_FAIL_OPEN``: if True, allow when sidecar is down (default False)
    - ``ARC_EXCLUDE_PATHS``: list of paths to skip (default ``[]``)
    - ``ARC_EXCLUDE_METHODS``: list of methods to skip (default ``["OPTIONS"]``)
    - ``ARC_RECEIPT_HEADER``: response header for receipt ID (default ``X-Arc-Receipt``)
    - ``ARC_TIMEOUT``: request timeout in seconds (default 5)
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response
        self._sidecar_url = getattr(
            settings, "ARC_SIDECAR_URL", "http://127.0.0.1:9090"
        ).rstrip("/")
        self._fail_open = getattr(settings, "ARC_FAIL_OPEN", False)
        self._exclude_paths: set[str] = set(
            getattr(settings, "ARC_EXCLUDE_PATHS", [])
        )
        self._exclude_methods: set[str] = set(
            getattr(settings, "ARC_EXCLUDE_METHODS", ["OPTIONS"])
        )
        self._receipt_header: str = getattr(
            settings, "ARC_RECEIPT_HEADER", "X-Arc-Receipt"
        )
        self._timeout: float = getattr(settings, "ARC_TIMEOUT", 5.0)

    def __call__(self, request: HttpRequest) -> HttpResponse:
        method = request.method or "GET"

        # Bypass excluded methods and paths
        if method.upper() in self._exclude_methods:
            return self.get_response(request)
        if request.path in self._exclude_paths:
            return self.get_response(request)

        # Extract caller identity
        caller = _extract_caller(request)

        # Compute body hash
        body_hash: str | None = None
        if request.body:
            body_hash = hashlib.sha256(request.body).hexdigest()

        # Extract presented capability token
        capability_token = (
            request.headers.get("X-Arc-Capability")
            or request.GET.get("arc_capability")
        )
        capability_id = _capability_id_from_token(capability_token)

        # Evaluate via sidecar (synchronous httpx)
        request_id = str(uuid.uuid4())
        payload: dict[str, Any] = {
            "request_id": request_id,
            "method": method,
            "route_pattern": request.path,
            "path": request.path,
            "query": {
                key: request.GET.get(key, "")
                for key in request.GET.keys()
            },
            "headers": {
                key.lower(): value
                for key, value in (
                    ("content-type", request.headers.get("Content-Type")),
                    ("content-length", request.headers.get("Content-Length")),
                )
                if value is not None
            },
            "caller": caller.model_dump(exclude_none=True),
            "body_length": len(request.body),
            "timestamp": int(time.time()),
        }
        if body_hash is not None:
            payload["body_hash"] = body_hash
        if capability_id is not None:
            payload["capability_id"] = capability_id

        request_headers: dict[str, str] | None = None
        if capability_token is not None:
            request_headers = {"X-Arc-Capability": capability_token}

        try:
            resp = httpx.post(
                f"{self._sidecar_url}/arc/evaluate",
                json=payload,
                headers=request_headers,
                timeout=self._timeout,
            )
        except (httpx.ConnectError, httpx.TimeoutException):
            if self._fail_open:
                request.arc_passthrough = ArcPassthrough(  # type: ignore[attr-defined]
                    mode="allow_without_receipt",
                    error="arc_sidecar_unreachable",
                    message="ARC sidecar unavailable",
                )
                return self.get_response(request)
            return JsonResponse(
                {
                    "error": {
                        "code": "ARC_SIDECAR_UNAVAILABLE",
                        "message": "ARC sidecar is unavailable",
                    }
                },
                status=503,
            )

        if resp.status_code >= 400:
            return JsonResponse(
                {
                    "error": {
                        "code": "ARC_INTERNAL_ERROR",
                        "message": f"Sidecar returned {resp.status_code}",
                    }
                },
                status=502,
            )

        evaluation = resp.json()
        verdict = evaluation.get("verdict", {})
        receipt_data = evaluation.get("receipt", {})

        if verdict.get("verdict") == "deny":
            status = verdict.get("http_status", 403)
            return JsonResponse(
                {
                    "error": {
                        "code": "ARC_GUARD_DENIED",
                        "message": verdict.get("reason", "denied"),
                        "guard": verdict.get("guard", "ArcGuard"),
                    }
                },
                status=status,
            )

        # Store receipt data on request for downstream views
        request.arc_receipt = receipt_data  # type: ignore[attr-defined]
        request.arc_evaluation = evaluation  # type: ignore[attr-defined]

        # Forward to view and attach receipt header
        response = self.get_response(request)
        receipt_id = receipt_data.get("id", "")
        if receipt_id:
            response[self._receipt_header] = receipt_id
        return response

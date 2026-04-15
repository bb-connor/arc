"""FastAPI dependency injection helpers for ARC."""

from __future__ import annotations

import hashlib
from typing import Any

from fastapi import Depends, Request

from arc_sdk.client import ArcClient
from arc_sdk.models import ArcPassthrough, AuthMethod, CallerIdentity, HttpReceipt

# Module-level singleton. Override via ``set_arc_client`` for testing.
_arc_client: ArcClient | None = None


def set_arc_client(client: ArcClient | None) -> None:
    """Set the module-level ARC client singleton.

    Pass None to clear the singleton (the next ``get_arc_client`` call will
    create a default client).
    """
    global _arc_client
    _arc_client = client


async def get_arc_client() -> ArcClient:
    """FastAPI dependency that returns the ARC sidecar client.

    Usage::

        @app.get("/items")
        async def list_items(client: ArcClient = Depends(get_arc_client)):
            ...
    """
    global _arc_client
    if _arc_client is None:
        _arc_client = ArcClient()
    return _arc_client


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


async def get_caller_identity(request: Request) -> CallerIdentity:
    """FastAPI dependency that extracts caller identity from the request.

    Checks Authorization header (Bearer), X-API-Key header, and session cookie.
    """
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            token_hash = _sha256_hex(token)
            return CallerIdentity(
                subject=token_hash,
                auth_method=AuthMethod.bearer(token_hash=token_hash),
                verified=False,
            )

    api_key = request.headers.get("x-api-key", "")
    if api_key:
        key_hash = _sha256_hex(api_key)
        return CallerIdentity(
            subject=key_hash,
            auth_method=AuthMethod.api_key(key_name="x-api-key", key_hash=key_hash),
            verified=False,
        )

    session_cookie = request.cookies.get("session", "")
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


async def get_arc_receipt(request: Request) -> HttpReceipt | None:
    """FastAPI dependency that retrieves the ARC receipt from the request state.

    The receipt is attached by the ARC middleware or decorators. Returns None
    if no receipt is available.
    """
    return getattr(request.state, "arc_receipt", None)


async def get_arc_passthrough(request: Request) -> ArcPassthrough | None:
    """FastAPI dependency that retrieves explicit fail-open passthrough state."""

    return getattr(request.state, "arc_passthrough", None)

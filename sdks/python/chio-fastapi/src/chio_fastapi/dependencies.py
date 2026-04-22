"""FastAPI dependency injection helpers for Chio."""

from __future__ import annotations

import hashlib
from typing import Any

from fastapi import Depends, Request

from chio_sdk.client import ChioClient
from chio_sdk.models import ChioPassthrough, AuthMethod, CallerIdentity, HttpReceipt

# Module-level singleton. Override via ``set_chio_client`` for testing.
_chio_client: ChioClient | None = None


def set_chio_client(client: ChioClient | None) -> None:
    """Set the module-level Chio client singleton.

    Pass None to clear the singleton (the next ``get_chio_client`` call will
    create a default client).
    """
    global _chio_client
    _chio_client = client


async def get_chio_client() -> ChioClient:
    """FastAPI dependency that returns the Chio sidecar client.

    Usage::

        @app.get("/items")
        async def list_items(client: ChioClient = Depends(get_chio_client)):
            ...
    """
    global _chio_client
    if _chio_client is None:
        _chio_client = ChioClient()
    return _chio_client


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


async def get_chio_receipt(request: Request) -> HttpReceipt | None:
    """FastAPI dependency that retrieves the Chio receipt from the request state.

    The receipt is attached by the Chio middleware or decorators. Returns None
    if no receipt is available.
    """
    return getattr(request.state, "chio_receipt", None)


async def get_chio_passthrough(request: Request) -> ChioPassthrough | None:
    """FastAPI dependency that retrieves explicit fail-open passthrough state."""

    return getattr(request.state, "chio_passthrough", None)

"""FastAPI route decorators for ARC capability enforcement.

These decorators wrap FastAPI route handlers to evaluate ARC capabilities,
approval requirements, and budget limits via the sidecar before the handler
executes.

Usage::

    from arc_fastapi import arc_requires, arc_approval, arc_budget

    @app.post("/tools/deploy")
    @arc_requires("deploy-server", "deploy", ["Invoke"])
    async def deploy(request: Request):
        ...

    @app.post("/tools/transfer")
    @arc_approval(threshold_cents=10000)
    @arc_requires("payments", "transfer", ["Invoke"])
    async def transfer(request: Request):
        ...

    @app.post("/tools/query")
    @arc_budget(max_cost_cents=500, currency="USD")
    @arc_requires("ai", "query", ["Invoke"])
    async def query(request: Request):
        ...
"""

from __future__ import annotations

import functools
import hashlib
import uuid
from typing import Any, Callable

from fastapi import Request
from fastapi.responses import JSONResponse

from arc_sdk.client import ArcClient
from arc_sdk.errors import ArcConnectionError, ArcDeniedError, ArcError, ArcTimeoutError
from arc_sdk.models import CallerIdentity

from arc_fastapi.dependencies import get_arc_client, get_caller_identity
from arc_fastapi.errors import ArcErrorCode, arc_error_response


def arc_requires(
    server_id: str,
    tool_name: str,
    operations: list[str] | None = None,
) -> Callable[..., Any]:
    """Decorator that enforces ARC capability requirements on a FastAPI route.

    The request must carry a valid ARC capability token (via X-Arc-Capability
    header or arc_capability query parameter) that grants the specified
    server_id/tool_name/operations.

    Parameters
    ----------
    server_id:
        The ARC tool server ID required.
    tool_name:
        The tool name required.
    operations:
        List of required operations (default ``["Invoke"]``).
    """
    ops = operations or ["Invoke"]

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            request: Request | None = kwargs.get("request")
            if request is None:
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break

            if request is None:
                return arc_error_response(
                    500,
                    ArcErrorCode.INTERNAL_ERROR,
                    "Request object not found in handler arguments",
                )

            # Extract capability ID
            cap_id = (
                request.headers.get("x-arc-capability")
                or request.query_params.get("arc_capability")
            )
            if not cap_id:
                return arc_error_response(
                    401,
                    ArcErrorCode.CAPABILITY_REQUIRED,
                    f"ARC capability required for {server_id}/{tool_name}",
                )

            # Evaluate via sidecar
            try:
                client = await get_arc_client()
                caller = await get_caller_identity(request)

                body_bytes = await request.body()
                body_hash = (
                    hashlib.sha256(body_bytes).hexdigest() if body_bytes else None
                )

                receipt = await client.evaluate_http_request(
                    request_id=str(uuid.uuid4()),
                    method=request.method,
                    route_pattern=str(request.url.path),
                    path=str(request.url.path),
                    caller=caller,
                    body_hash=body_hash,
                    capability_id=cap_id,
                )
            except ArcDeniedError as exc:
                return arc_error_response(
                    403,
                    ArcErrorCode.GUARD_DENIED,
                    exc.reason or str(exc),
                    guard=exc.guard,
                )
            except (ArcConnectionError, ArcTimeoutError):
                return arc_error_response(
                    503,
                    ArcErrorCode.SIDECAR_UNAVAILABLE,
                    "ARC sidecar is unavailable",
                )
            except ArcError as exc:
                return arc_error_response(
                    502,
                    ArcErrorCode.INTERNAL_ERROR,
                    str(exc),
                )

            if receipt.is_denied:
                return arc_error_response(
                    receipt.verdict.http_status or 403,
                    ArcErrorCode.GUARD_DENIED,
                    receipt.verdict.reason or "denied",
                    guard=receipt.verdict.guard,
                )

            # Attach receipt to request state
            request.state.arc_receipt = receipt
            return await func(*args, **kwargs)

        # Store metadata for introspection
        wrapper._arc_requires = {  # type: ignore[attr-defined]
            "server_id": server_id,
            "tool_name": tool_name,
            "operations": ops,
        }
        return wrapper

    return decorator


def arc_approval(
    threshold_cents: int = 0,
    currency: str = "USD",
) -> Callable[..., Any]:
    """Decorator that requires human approval above a monetary threshold.

    Must be combined with ``@arc_requires``. If the request's cost exceeds
    ``threshold_cents``, the sidecar will require an approval token.

    Parameters
    ----------
    threshold_cents:
        Cost threshold in minor currency units above which approval is
        required. Default 0 means always require approval.
    currency:
        ISO 4217 currency code.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            request: Request | None = kwargs.get("request")
            if request is None:
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break

            if request is None:
                return arc_error_response(
                    500,
                    ArcErrorCode.INTERNAL_ERROR,
                    "Request object not found in handler arguments",
                )

            # Check for approval token
            approval_token = request.headers.get("x-arc-approval")
            if not approval_token:
                return arc_error_response(
                    403,
                    ArcErrorCode.APPROVAL_REQUIRED,
                    f"Approval required for operations above {threshold_cents} {currency}",
                    details={
                        "threshold_cents": threshold_cents,
                        "currency": currency,
                    },
                )

            # Store approval metadata for downstream handlers
            request.state.arc_approval = {
                "token": approval_token,
                "threshold_cents": threshold_cents,
                "currency": currency,
            }
            return await func(*args, **kwargs)

        wrapper._arc_approval = {  # type: ignore[attr-defined]
            "threshold_cents": threshold_cents,
            "currency": currency,
        }
        return wrapper

    return decorator


def arc_budget(
    max_cost_cents: int,
    currency: str = "USD",
) -> Callable[..., Any]:
    """Decorator that enforces a per-request budget limit.

    If the tool invocation's cost would exceed ``max_cost_cents``, the
    sidecar denies the request.

    Parameters
    ----------
    max_cost_cents:
        Maximum cost in minor currency units for this endpoint.
    currency:
        ISO 4217 currency code.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            request: Request | None = kwargs.get("request")
            if request is None:
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break

            if request is None:
                return arc_error_response(
                    500,
                    ArcErrorCode.INTERNAL_ERROR,
                    "Request object not found in handler arguments",
                )

            # Store budget metadata for the sidecar evaluation
            request.state.arc_budget = {
                "max_cost_cents": max_cost_cents,
                "currency": currency,
            }
            return await func(*args, **kwargs)

        wrapper._arc_budget = {  # type: ignore[attr-defined]
            "max_cost_cents": max_cost_cents,
            "currency": currency,
        }
        return wrapper

    return decorator

"""Configuration for the ARC ASGI middleware."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ArcASGIConfig:
    """Configuration for ArcASGIMiddleware.

    Parameters
    ----------
    sidecar_url:
        Base URL of the ARC sidecar (default ``http://127.0.0.1:9090``).
    timeout:
        Request timeout in seconds for sidecar calls (default 10).
    exclude_paths:
        Paths that bypass ARC evaluation (e.g. health checks).
    exclude_methods:
        HTTP methods that bypass ARC evaluation (default OPTIONS).
    receipt_header:
        Response header name for the ARC receipt ID (default ``X-Arc-Receipt``).
    fail_open:
        If True, allow requests when the sidecar is unreachable. Default is
        False (fail-closed).
    """

    sidecar_url: str = "http://127.0.0.1:9090"
    timeout: float = 10.0
    exclude_paths: frozenset[str] = frozenset()
    exclude_methods: frozenset[str] = frozenset({"OPTIONS"})
    receipt_header: str = "X-Arc-Receipt"
    fail_open: bool = False

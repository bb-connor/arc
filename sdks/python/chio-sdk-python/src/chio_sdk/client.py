"""Async HTTP client for the Chio sidecar kernel.

The Chio sidecar runs as a local process exposing a localhost HTTP API. This
client provides a typed Python interface over that API, handling serialization,
error mapping, and receipt verification.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

import httpx

from chio_sdk.errors import (
    ChioConnectionError,
    ChioDeniedError,
    ChioError,
    ChioTimeoutError,
    ChioValidationError,
)
from chio_sdk.models import (
    ChioHttpRequest,
    ChioReceipt,
    ChioScope,
    CallerIdentity,
    CapabilityToken,
    Decision,
    EvaluateResponse,
    GuardEvidence,
    HttpReceipt,
    Verdict,
)


def _canonical_json(obj: Any) -> bytes:
    """Produce canonical JSON (sorted keys, no extra whitespace, ensure_ascii).

    This matches the Rust kernel's canonical JSON (RFC 8785 subset) for
    deterministic hashing. Full RFC 8785 compliance (e.g. number serialization)
    is handled by the sidecar; this is a best-effort local approximation
    sufficient for content hashing.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


def _capability_id_from_token(raw_token: str | None) -> str | None:
    """Best-effort extraction of a capability token ID from its JSON payload."""
    if raw_token is None:
        return None
    try:
        return CapabilityToken.model_validate_json(raw_token).id
    except Exception:
        return None


class ChioClient:
    """Async HTTP client for the Chio sidecar.

    Parameters
    ----------
    base_url:
        Base URL of the Chio sidecar (default ``http://127.0.0.1:9090``).
    timeout:
        Request timeout in seconds (default 5).
    """

    DEFAULT_BASE_URL = "http://127.0.0.1:9090"

    def __init__(
        self,
        base_url: str | None = None,
        *,
        timeout: float = 5.0,
    ) -> None:
        self._base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self._http = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(timeout),
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._http.aclose()

    async def __aenter__(self) -> ChioClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    async def health(self) -> dict[str, Any]:
        """Check sidecar health."""
        return await self._get("/arc/health")

    # ------------------------------------------------------------------
    # Capability tokens
    # ------------------------------------------------------------------

    async def create_capability(
        self,
        *,
        subject: str,
        scope: ChioScope,
        ttl_seconds: int = 3600,
    ) -> CapabilityToken:
        """Request a new capability token from the sidecar.

        Parameters
        ----------
        subject:
            Hex-encoded Ed25519 public key of the agent the token is bound to.
        scope:
            The scope (tool/resource/prompt grants) to authorize.
        ttl_seconds:
            Token lifetime in seconds.
        """
        body = {
            "subject": subject,
            "scope": scope.model_dump(exclude_none=True),
            "ttl_seconds": ttl_seconds,
        }
        data = await self._post("/v1/capabilities", body)
        return CapabilityToken.model_validate(data)

    async def validate_capability(
        self,
        token: CapabilityToken,
    ) -> bool:
        """Ask the sidecar to validate a capability token.

        Returns True if the token is valid, False otherwise.
        """
        data = await self._post(
            "/v1/capabilities/validate",
            token.model_dump(exclude_none=True),
        )
        return bool(data.get("valid", False))

    async def attenuate_capability(
        self,
        token: CapabilityToken,
        *,
        new_scope: ChioScope,
    ) -> CapabilityToken:
        """Ask the sidecar to produce an attenuated child token.

        The new scope must be a subset of the original.
        """
        if not new_scope.is_subset_of(token.scope):
            raise ChioValidationError(
                "new_scope must be a subset of the parent token scope"
            )
        body = {
            "parent_token": token.model_dump(exclude_none=True),
            "new_scope": new_scope.model_dump(exclude_none=True),
        }
        data = await self._post("/v1/capabilities/attenuate", body)
        return CapabilityToken.model_validate(data)

    # ------------------------------------------------------------------
    # Receipt verification
    # ------------------------------------------------------------------

    async def verify_receipt(self, receipt: ChioReceipt) -> bool:
        """Ask the sidecar to verify a receipt signature.

        Returns True if the signature is valid.
        """
        data = await self._post(
            "/v1/receipts/verify",
            receipt.model_dump(exclude_none=True),
        )
        return bool(data.get("valid", False))

    async def verify_http_receipt(self, receipt: HttpReceipt) -> bool:
        """Ask the sidecar to verify an HTTP receipt signature."""
        data = await self._post(
            "/arc/verify",
            receipt.model_dump(exclude_none=True),
        )
        return bool(data.get("valid", False))

    async def verify_receipt_chain(
        self, receipts: list[ChioReceipt]
    ) -> bool:
        """Verify that a chain of receipts has contiguous content hashes.

        Each receipt's content_hash should match the SHA-256 of the canonical
        JSON of the previous receipt, forming an append-only chain.
        """
        if len(receipts) < 2:
            return True
        for i in range(1, len(receipts)):
            prev_canonical = _canonical_json(
                receipts[i - 1].model_dump(exclude_none=True)
            )
            expected_hash = _sha256_hex(prev_canonical)
            if receipts[i].content_hash != expected_hash:
                return False
        return True

    # ------------------------------------------------------------------
    # Tool evaluation (sidecar proxy)
    # ------------------------------------------------------------------

    async def evaluate_tool_call(
        self,
        *,
        capability_id: str,
        tool_server: str,
        tool_name: str,
        parameters: dict[str, Any],
    ) -> ChioReceipt:
        """Evaluate a tool call through the sidecar kernel.

        Returns the signed receipt from the kernel.
        """
        param_canonical = _canonical_json(parameters)
        param_hash = _sha256_hex(param_canonical)

        body = {
            "capability_id": capability_id,
            "tool_server": tool_server,
            "tool_name": tool_name,
            "parameters": parameters,
            "parameter_hash": param_hash,
        }
        data = await self._post("/v1/evaluate", body)
        return ChioReceipt.model_validate(data)

    async def evaluate_http_request(
        self,
        *,
        request_id: str,
        method: str,
        route_pattern: str,
        path: str,
        caller: CallerIdentity,
        query: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        body_hash: str | None = None,
        body_length: int = 0,
        session_id: str | None = None,
        capability_id: str | None = None,
        capability_token: str | None = None,
        model_metadata: dict[str, Any] | None = None,
        timestamp: int | None = None,
    ) -> EvaluateResponse:
        """Evaluate an HTTP request through the sidecar kernel."""
        resolved_capability_id = capability_id or _capability_id_from_token(
            capability_token
        )
        request_model = ChioHttpRequest(
            request_id=request_id,
            method=method,
            route_pattern=route_pattern,
            path=path,
            query=query or {},
            headers=headers or {},
            caller=caller,
            body_hash=body_hash,
            body_length=body_length,
            session_id=session_id,
            capability_id=resolved_capability_id,
            model_metadata=model_metadata,
            timestamp=timestamp or int(time.time()),
        )
        request_headers: dict[str, str] | None = None
        if capability_token is not None:
            request_headers = {"X-Chio-Capability": capability_token}
        data = await self._post(
            "/arc/evaluate",
            request_model.model_dump(exclude_none=True),
            headers=request_headers,
        )
        return EvaluateResponse.model_validate(data)

    # ------------------------------------------------------------------
    # Guard evidence helpers
    # ------------------------------------------------------------------

    @staticmethod
    def collect_evidence(
        receipts: list[ChioReceipt],
    ) -> list[GuardEvidence]:
        """Collect all guard evidence from a list of receipts."""
        evidence: list[GuardEvidence] = []
        for receipt in receipts:
            evidence.extend(receipt.evidence)
        return evidence

    # ------------------------------------------------------------------
    # Internal HTTP helpers
    # ------------------------------------------------------------------

    async def _get(self, path: str) -> dict[str, Any]:
        try:
            resp = await self._http.get(path)
        except httpx.ConnectError as exc:
            raise ChioConnectionError(
                f"Failed to connect to Chio sidecar at {self._base_url}"
            ) from exc
        except httpx.TimeoutException as exc:
            raise ChioTimeoutError(
                f"Request to {path} timed out"
            ) from exc
        return self._handle_response(resp)

    async def _post(
        self,
        path: str,
        body: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        try:
            resp = await self._http.post(path, json=body, headers=headers)
        except httpx.ConnectError as exc:
            raise ChioConnectionError(
                f"Failed to connect to Chio sidecar at {self._base_url}"
            ) from exc
        except httpx.TimeoutException as exc:
            raise ChioTimeoutError(
                f"Request to {path} timed out"
            ) from exc
        return self._handle_response(resp)

    @staticmethod
    def _handle_response(resp: httpx.Response) -> dict[str, Any]:
        if resp.status_code == 403:
            data = resp.json()
            raise ChioDeniedError(
                data.get("message", "denied"),
                guard=data.get("guard"),
                reason=data.get("reason"),
            )
        if resp.status_code >= 400:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text
            raise ChioError(
                f"Chio sidecar returned {resp.status_code}: {detail}",
                code=f"HTTP_{resp.status_code}",
            )
        return resp.json()  # type: ignore[no-any-return]

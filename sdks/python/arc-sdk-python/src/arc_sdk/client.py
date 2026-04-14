"""Async HTTP client for the ARC sidecar kernel.

The ARC sidecar runs as a local process exposing a localhost HTTP API. This
client provides a typed Python interface over that API, handling serialization,
error mapping, and receipt verification.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import httpx

from arc_sdk.errors import (
    ArcConnectionError,
    ArcDeniedError,
    ArcError,
    ArcTimeoutError,
    ArcValidationError,
)
from arc_sdk.models import (
    ArcReceipt,
    ArcScope,
    CallerIdentity,
    CapabilityToken,
    Decision,
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


class ArcClient:
    """Async HTTP client for the ARC sidecar.

    Parameters
    ----------
    base_url:
        Base URL of the ARC sidecar (default ``http://127.0.0.1:9090``).
    timeout:
        Request timeout in seconds (default 10).
    """

    DEFAULT_BASE_URL = "http://127.0.0.1:9090"

    def __init__(
        self,
        base_url: str | None = None,
        *,
        timeout: float = 10.0,
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

    async def __aenter__(self) -> ArcClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    async def health(self) -> dict[str, Any]:
        """Check sidecar health."""
        return await self._get("/health")

    # ------------------------------------------------------------------
    # Capability tokens
    # ------------------------------------------------------------------

    async def create_capability(
        self,
        *,
        subject: str,
        scope: ArcScope,
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
        new_scope: ArcScope,
    ) -> CapabilityToken:
        """Ask the sidecar to produce an attenuated child token.

        The new scope must be a subset of the original.
        """
        if not new_scope.is_subset_of(token.scope):
            raise ArcValidationError(
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

    async def verify_receipt(self, receipt: ArcReceipt) -> bool:
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
            "/v1/receipts/verify-http",
            receipt.model_dump(exclude_none=True),
        )
        return bool(data.get("valid", False))

    async def verify_receipt_chain(
        self, receipts: list[ArcReceipt]
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
    ) -> ArcReceipt:
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
        return ArcReceipt.model_validate(data)

    async def evaluate_http_request(
        self,
        *,
        request_id: str,
        method: str,
        route_pattern: str,
        path: str,
        caller: CallerIdentity,
        body_hash: str | None = None,
        capability_id: str | None = None,
    ) -> HttpReceipt:
        """Evaluate an HTTP request through the sidecar kernel."""
        payload: dict[str, Any] = {
            "request_id": request_id,
            "method": method,
            "route_pattern": route_pattern,
            "path": path,
            "caller": caller.model_dump(exclude_none=True),
        }
        if body_hash is not None:
            payload["body_hash"] = body_hash
        if capability_id is not None:
            payload["capability_id"] = capability_id
        data = await self._post("/v1/evaluate-http", payload)
        return HttpReceipt.model_validate(data)

    # ------------------------------------------------------------------
    # Guard evidence helpers
    # ------------------------------------------------------------------

    @staticmethod
    def collect_evidence(
        receipts: list[ArcReceipt],
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
            raise ArcConnectionError(
                f"Failed to connect to ARC sidecar at {self._base_url}"
            ) from exc
        except httpx.TimeoutException as exc:
            raise ArcTimeoutError(
                f"Request to {path} timed out"
            ) from exc
        return self._handle_response(resp)

    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            resp = await self._http.post(path, json=body)
        except httpx.ConnectError as exc:
            raise ArcConnectionError(
                f"Failed to connect to ARC sidecar at {self._base_url}"
            ) from exc
        except httpx.TimeoutException as exc:
            raise ArcTimeoutError(
                f"Request to {path} timed out"
            ) from exc
        return self._handle_response(resp)

    @staticmethod
    def _handle_response(resp: httpx.Response) -> dict[str, Any]:
        if resp.status_code == 403:
            data = resp.json()
            raise ArcDeniedError(
                data.get("message", "denied"),
                guard=data.get("guard"),
                reason=data.get("reason"),
            )
        if resp.status_code >= 400:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text
            raise ArcError(
                f"ARC sidecar returned {resp.status_code}: {detail}",
                code=f"HTTP_{resp.status_code}",
            )
        return resp.json()  # type: ignore[no-any-return]

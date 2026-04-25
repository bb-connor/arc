"""Chio control-plane, API sidecar, and MCP edge clients for the web3 example."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from .artifacts import Json


class ChioHttpError(RuntimeError):
    """Raised when a Chio-mediated boundary rejects a request."""

    def __init__(self, url: str, status: int, body: str) -> None:
        super().__init__(f"Chio HTTP call failed: {url}: {status}: {body}")
        self.url = url
        self.status = status
        self.body = body


def capability_header(capability: Json) -> str:
    """Serialize a capability token for `chio api protect`."""

    return json.dumps(capability, separators=(",", ":"), sort_keys=True)


def _json_request(
    method: str,
    url: str,
    *,
    payload: Json | None = None,
    headers: dict[str, str] | None = None,
    query: dict[str, Any] | None = None,
    timeout_seconds: int = 15,
) -> Json:
    request_url = url
    if query:
        request_url = f"{url}?{urllib.parse.urlencode(query)}"
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request_headers = {"Accept": "application/json", **(headers or {})}
    if body is not None:
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        request_url,
        data=body,
        headers=request_headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            raw = response.read().decode("utf-8")
            if not raw:
                return {}
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        raise ChioHttpError(request_url, exc.code, body_text) from exc


@dataclass(frozen=True)
class TrustControlClient:
    """Small HTTP client for `chio trust serve`."""

    base_url: str
    service_token: str
    timeout_seconds: int = 15

    def _url(self, path: str) -> str:
        return f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.service_token}"}

    def get(self, path: str, *, query: dict[str, Any] | None = None) -> Json:
        return _json_request(
            "GET",
            self._url(path),
            headers=self._headers(),
            query=query,
            timeout_seconds=self.timeout_seconds,
        )

    def post(self, path: str, payload: Json) -> Json:
        return _json_request(
            "POST",
            self._url(path),
            payload=payload,
            headers=self._headers(),
            timeout_seconds=self.timeout_seconds,
        )

    def issue_capability(
        self,
        subject_public_key: str,
        capability_scope: Json,
        ttl_seconds: int,
        *,
        runtime_attestation: Json | None = None,
    ) -> Json:
        payload: Json = {
            "subjectPublicKey": subject_public_key,
            "scope": capability_scope,
            "ttlSeconds": ttl_seconds,
        }
        if runtime_attestation:
            payload["runtimeAttestation"] = runtime_attestation
        return self.post("/v1/capabilities/issue", payload)["capability"]

    def record_lineage(self, capability: Json, parent_capability_id: str | None) -> Json:
        return self.post(
            "/v1/lineage",
            {"capability": capability, "parentCapabilityId": parent_capability_id},
        )

    def lineage_chain(self, capability_id: str) -> Any:
        return self.get(f"/v1/lineage/{capability_id}/chain")

    def revoke(self, capability_id: str) -> Json:
        return self.post("/v1/revocations", {"capabilityId": capability_id})

    def authorize_exposure(
        self,
        *,
        capability_id: str,
        grant_index: int,
        exposure_units: int,
        hold_id: str,
        event_id: str,
        max_invocations: int,
        max_exposure_per_invocation: int,
        max_total_exposure_units: int,
    ) -> Json:
        return self.post(
            "/v1/budgets/authorize-exposure",
            {
                "capabilityId": capability_id,
                "grantIndex": grant_index,
                "maxInvocations": max_invocations,
                "exposureUnits": exposure_units,
                "maxExposurePerInvocation": max_exposure_per_invocation,
                "maxTotalExposureUnits": max_total_exposure_units,
                "holdId": hold_id,
                "eventId": event_id,
            },
        )

    def release_exposure(
        self,
        *,
        capability_id: str,
        grant_index: int,
        reduction_units: int,
        hold_id: str,
        event_id: str,
    ) -> Json:
        return self.post(
            "/v1/budgets/release-exposure",
            {
                "capabilityId": capability_id,
                "grantIndex": grant_index,
                "reductionUnits": reduction_units,
                "holdId": hold_id,
                "eventId": event_id,
            },
        )

    def reconcile_spend(
        self,
        *,
        capability_id: str,
        grant_index: int,
        exposed_cost_units: int,
        realized_spend_units: int,
        hold_id: str,
        event_id: str,
    ) -> Json:
        return self.post(
            "/v1/budgets/reconcile-spend",
            {
                "capabilityId": capability_id,
                "grantIndex": grant_index,
                "authorizedExposureUnits": exposed_cost_units,
                "realizedSpendUnits": realized_spend_units,
                "holdId": hold_id,
                "eventId": event_id,
            },
        )


class ChioMcpClient:
    """JSON-RPC client for a `chio mcp serve-http` edge."""

    def __init__(self, base_url: str, *, auth_token: str, timeout_seconds: int = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token
        self.timeout_seconds = timeout_seconds
        self.session_id: str | None = None
        self._seq = 0

    def __enter__(self) -> "ChioMcpClient":
        self._rpc(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "ioa-web3-scenario", "version": "0.1.0"},
            },
        )
        self._notify_initialized()
        return self

    def __exit__(self, *_: Any) -> None:
        if self.session_id:
            try:
                _json_request(
                    "DELETE",
                    f"{self.base_url}/mcp",
                    headers=self._headers(),
                    timeout_seconds=5,
                )
            except (ChioHttpError, urllib.error.URLError):
                return

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.auth_token}",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        return headers

    def _request_rpc(self, message: Json) -> tuple[Json, dict[str, str]]:
        request = urllib.request.Request(
            f"{self.base_url}/mcp",
            data=json.dumps(message).encode("utf-8"),
            headers=self._headers(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                text = response.read().decode("utf-8")
                headers = {key.lower(): value for key, value in response.headers.items()}
                return self._parse_response(text, headers.get("content-type", "")), headers
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise ChioHttpError(f"{self.base_url}/mcp", exc.code, body) from exc

    def _parse_response(self, text: str, content_type: str) -> Json:
        if "text/event-stream" in content_type:
            for line in text.splitlines():
                if not line.startswith("data: "):
                    continue
                try:
                    return json.loads(line.removeprefix("data: "))
                except json.JSONDecodeError:
                    continue
            raise RuntimeError("MCP edge returned an SSE stream without a JSON-RPC payload")
        if not text:
            return {}
        return json.loads(text)

    def _rpc(self, method: str, params: Json) -> Json:
        self._seq += 1
        payload, headers = self._request_rpc(
            {"jsonrpc": "2.0", "id": self._seq, "method": method, "params": params}
        )
        session_id = headers.get("mcp-session-id")
        if session_id:
            self.session_id = session_id
        if "error" in payload:
            error = payload["error"]
            raise RuntimeError(f"MCP {method} denied: {error.get('code')}: {error.get('message')}")
        return payload.get("result", {})

    def _notify_initialized(self) -> None:
        try:
            self._request_rpc(
                {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
            )
        except ChioHttpError as exc:
            if exc.status not in {200, 202}:
                raise

    def list_tools(self) -> list[Json]:
        return self._rpc("tools/list", {}).get("tools", [])

    def call_tool(self, tool_name: str, arguments: Json | None = None) -> Json:
        result = self._rpc(
            "tools/call",
            {"name": tool_name, "arguments": arguments or {}},
        )
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            return structured
        for item in result.get("content", []):
            if not isinstance(item, dict) or item.get("type") != "text":
                continue
            text = item.get("text", "")
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed
        return {}

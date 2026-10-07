"""Thin transport for the Rust recovery host. No local authority decisions."""
from __future__ import annotations

import asyncio
import json
from urllib.parse import urlsplit
import httpx
from ._generated.recovery.command_schema import RecoveryCommandV1
from ._generated.recovery.command_result_schema import RecoveryCommandResultV1
from ._generated.recovery.command_response_schema import RecoveryCommandResponseV1
from ._generated.recovery.review_document_schema import RecoveryReviewDocumentV1
from ._generated.recovery.signed_explanation_view_schema import RecoverySignedExplanationViewV1
from ._generated.recovery.decision_report_view_schema import DecisionReportViewV1
from ._generated.recovery.policy_maintenance_view_schema import PolicyMaintenanceViewV1
from ._generated.recovery.signed_recovery_setup_probe_schema import SignedRecoverySetupProbeV1
from ._generated.recovery.signed_recovery_setup_report_schema import SignedRecoverySetupReportV1
from pydantic import BaseModel, ValidationError
from typing import TypeVar
from .recovery_errors import RecoveryError, RecoveryErrorCode, native_error
from .recovery_wire import assert_foundation_wire, read_product_view_wire, read_response_wire, retain_opaque_json

ResponseModel = TypeVar("ResponseModel", bound=BaseModel)


class RecoveryClient:
    def __init__(self, endpoint: str, *, transport: httpx.AsyncBaseTransport | None = None,
                 timeout_seconds: int | None = None):
        if timeout_seconds is not None and (type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 120):
            raise ValueError("recovery.invalid_budget")
        try:
            url = urlsplit(endpoint)
            # Accessing the port also validates a malformed authority.
            _ = url.port
        except ValueError:
            raise ValueError("recovery.invalid_endpoint") from None
        local = url.hostname in {"localhost", "127.0.0.1", "::1"}
        if not url.hostname or (url.scheme != "https" and not (url.scheme == "http" and local)) or url.username or url.password or url.query or url.fragment:
            raise ValueError("recovery.invalid_endpoint")
        # The configured service mount is a directory, including a slashless
        # base. Preserve percent-encoded segments beneath the selected origin.
        path = url.path if url.path.endswith("/") else url.path + "/"
        base = url._replace(path=path, query="", fragment="").geturl()
        self._timeout_seconds = timeout_seconds
        self._http = httpx.AsyncClient(base_url=base, transport=transport, timeout=20,
                                      follow_redirects=False, trust_env=False)

    async def aclose(self) -> None:
        await self._http.aclose()

    async def execute(self, capability: str, command: RecoveryCommandV1 | bytes) -> RecoveryCommandResultV1:
        # Callers may supply the canonical Rust-produced command bytes directly.
        if isinstance(command, bytes):
            try:
                canonical = command.decode("utf-8")
            except UnicodeError:
                raise ValueError("recovery.invalid_command") from None
        else:
            data = command.model_dump(mode="json", by_alias=True)
            # All command object keys are ASCII and numeric fields are safe
            # integers. The embedded seed/approval is an exact canonical string.
            canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        try:
            assert_foundation_wire(canonical)
        except (ValueError, UnicodeError):
            raise ValueError("recovery.invalid_command") from None
        return await self._post("commands", {"capability": capability, "command": canonical}, RecoveryCommandResultV1)

    async def review(self, capability: str, workflow_id: str) -> RecoveryReviewDocumentV1:
        return await self._post("review", {"capability": capability, "workflow_id": workflow_id}, RecoveryReviewDocumentV1)

    async def explain(self, capability: str, workflow_id: str) -> RecoverySignedExplanationViewV1:
        """Retrieve signed audience-safe advice; the host rechecks authority on resume."""
        return await self._post("explain", {"capability": capability, "workflow_id": workflow_id}, RecoverySignedExplanationViewV1)

    async def settle(self, capability: str, workflow_id: str) -> RecoveryCommandResponseV1:
        return await self._post("settle", {"capability": capability, "workflow_id": workflow_id}, RecoveryCommandResponseV1)

    async def submit_report(self, capability: str, command_id: str, report: bytes) -> DecisionReportViewV1:
        """Submit exact bounded report bytes. The host assigns classification."""
        return await self._post("reports/submit", {"capability": capability, "command_id": command_id,
                                                "report": self._opaque_payload(report)}, DecisionReportViewV1)

    async def read_report(self, capability: str, report_id: str) -> DecisionReportViewV1:
        """Every read, including replay, requires current native audience authority."""
        return await self._post("reports/read", {"capability": capability, "report_id": report_id}, DecisionReportViewV1)

    async def propose_policy(self, capability: str, proposal: bytes) -> PolicyMaintenanceViewV1:
        """Submit untrusted evidence. This method cannot install a policy."""
        return await self._post("policy/propose", {"capability": capability,
                                                "proposal": self._opaque_payload(proposal)}, PolicyMaintenanceViewV1)

    async def setup_probe(self, capability: str, workflow_id: str) -> SignedRecoverySetupProbeV1:
        """Drive the native operator-pinned self-test. Qualification requires a writer restart."""
        return await self._post("setup/probe", {"capability": capability, "workflow_id": workflow_id}, SignedRecoverySetupProbeV1)

    async def setup_qualify(self, capability: str, probe: bytes) -> SignedRecoverySetupReportV1:
        """Preserve the exact proof bytes. Only the current native writer decides readiness."""
        opaque = self._opaque_payload(probe)
        try:
            assert_foundation_wire(opaque)
            SignedRecoverySetupProbeV1.model_validate_json(probe, strict=True)
        except (ValueError, UnicodeError, ValidationError):
            raise ValueError("recovery.invalid_command") from None
        return await self._post("setup/qualify", {"capability": capability, "probe": opaque}, SignedRecoverySetupReportV1)

    @staticmethod
    def _opaque_payload(payload: bytes) -> str:
        if len(payload) > 32768:
            raise ValueError("recovery.resource_exhausted")
        try:
            return payload.decode("utf-8")
        except UnicodeError:
            raise ValueError("recovery.invalid_command") from None

    async def _post(self, path: str, envelope: dict[str, str], model: type[ResponseModel]) -> ResponseModel:
        wire = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(wire) > 65536:
            raise ValueError("recovery.resource_exhausted")
        timeout = self._timeout_seconds or (120 if path.startswith("setup/") else 20)
        try:
            # HTTPX bounds each I/O phase. This deadline also bounds the whole
            # response, including a peer that repeatedly sends tiny chunks.
            async with asyncio.timeout(timeout):
                return await self._post_bounded(path, wire, model, timeout)
        except (TimeoutError, httpx.HTTPError):
            raise RecoveryError(RecoveryErrorCode.UNAVAILABLE) from None

    async def _post_bounded(self, path: str, wire: bytes, model: type[ResponseModel],
                            timeout: int) -> ResponseModel:
        # The default HTTPX transport has no retries. Caller-provided transports
        # must retain this contract; the SDK itself never resubmits an operation.
        async with self._http.stream("POST", f"v1/recovery/{path}", content=wire,
                                     headers={"content-type": "application/json"}, timeout=timeout) as response:
            data = bytearray()
            async for chunk in response.aiter_bytes():
                if len(data) + len(chunk) > 262144:
                    raise ValueError("recovery.resource_exhausted")
                data.extend(chunk)
            if not response.is_success:
                raise native_error(response.status_code, bytes(data))
            try:
                if model in (DecisionReportViewV1, PolicyMaintenanceViewV1):
                    parsed, projection = read_product_view_wire(data)
                else:
                    parsed, projection = read_response_wire(data, opaque_result=model is RecoveryCommandResultV1)
                # JSON-specific enum/date validation sees the original metadata
                # bytes and result=null. It never converts the opaque tool value.
                validated = model.model_validate_json(projection, strict=True)
                if model is RecoveryCommandResultV1 and validated.original_response is not None:
                    validated.original_response.result = retain_opaque_json(parsed["original_response"]["result"])
                return validated
            except (ValueError, UnicodeError, ValidationError):
                raise RecoveryError(RecoveryErrorCode.INVALID_RESPONSE) from None

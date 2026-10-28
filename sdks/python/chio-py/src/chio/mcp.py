"""Verify kernel-mediated MCP tool results from a Chio MCP edge.

Every ``tools/call`` result from a Chio edge carries ``_meta.chioEvidence``
(``chio.mcp.execution-evidence.v1``). This module checks that evidence against
an operator-pinned kernel key and returns only the output the signed receipt
commits to. The rendered ``content`` and ``structuredContent`` are never
treated as signed data.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from .errors import ChioInvariantError
from .invariants.hashing import sha256_hex_utf8
from .invariants.json import canonicalize_json
from .invariants.receipt import verify_receipt
from .invariants.signing import is_valid_public_key_hex

if TYPE_CHECKING:
    from mcp import ClientSession

EXECUTION_EVIDENCE_SCHEMA = "chio.mcp.execution-evidence.v1"


class McpEvidenceError(ChioInvariantError):
    """A result has no verifiable evidence for the requested invocation."""

    def __init__(self, message: str) -> None:
        super().__init__("mcp_evidence_invalid", message)


@dataclass(frozen=True)
class VerifiedMcpResult:
    """The signed receipt and the exact output it commits to."""

    receipt: dict[str, Any]
    output: Any

    @property
    def allowed(self) -> bool:
        return self.receipt["decision"]["verdict"] == "allow"

    @property
    def tool_error(self) -> bool:
        return isinstance(self.output, dict) and self.output.get("isError") is True


def verify_mcp_result(
    result: dict[str, Any],
    *,
    trusted_signers: list[str],
    request_id: str,
    server_id: str,
    tool_name: str,
    arguments: dict[str, Any],
) -> VerifiedMcpResult:
    """Verify signer, mediation, invocation identity and output commitment.

    ``request_id`` is the ``_meta.chioRequestId`` the caller sent. Streamed
    results, pending approvals and incomplete calls fail closed.
    """
    try:
        evidence = result["_meta"]["chioEvidence"]
        if evidence["schema"] != EXECUTION_EVIDENCE_SCHEMA:
            raise McpEvidenceError("unsupported Chio MCP execution evidence")
        kind = evidence["outputKind"]
        if kind == "stream":
            raise McpEvidenceError("this client requires a complete value result")
        if kind not in {"value", "none"}:
            raise McpEvidenceError("unsupported Chio MCP output kind")
        output = evidence["output"]
        if kind == "none" and output is not None:
            raise McpEvidenceError("absent output must be null")
        receipt = evidence["receipt"]
        report = verify_receipt(receipt, trusted_signers)
        if not report["ok"]:
            raise McpEvidenceError(
                "kernel receipt failed integrity or signer verification"
            )
        if (
            receipt["receipt_kind"] != "mediated_decision"
            or receipt["boundary_class"] != "prevent"
            or receipt["trust_level"] != "mediated"
        ):
            raise McpEvidenceError("receipt does not prove kernel mediation")
        if receipt["tool_server"] != server_id or receipt["tool_name"] != tool_name:
            raise McpEvidenceError("receipt belongs to a different tool")
        signed_request_id = receipt["metadata"]["receipt_context"]["request_id"]
        if signed_request_id != request_id or evidence["requestId"] != request_id:
            raise McpEvidenceError("receipt belongs to a different invocation")
        if canonicalize_json(receipt["action"]["parameters"]) != canonicalize_json(
            arguments
        ):
            raise McpEvidenceError("receipt belongs to different arguments")
        verdict = report["decision"]
        if verdict not in {"allow", "deny"}:
            raise McpEvidenceError("tool invocation did not complete")
        if kind == "value":
            if verdict != "allow":
                raise McpEvidenceError("a denied call cannot carry a value output")
            if sha256_hex_utf8(canonicalize_json(output)) != receipt["content_hash"]:
                raise McpEvidenceError(
                    "tool output does not match its signed commitment"
                )
        return VerifiedMcpResult(receipt=receipt, output=output)
    except McpEvidenceError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, ChioInvariantError) as error:
        raise McpEvidenceError(
            "malformed or unsupported Chio MCP execution evidence"
        ) from error


class VerifiedMcpSession:
    """Call tools on an open MCP session with mandatory evidence verification.

    The session keeps its own lifetime. No retry is performed after an
    uncertain transport outcome; the caller decides whether to submit new work.
    """

    def __init__(
        self,
        session: ClientSession,
        *,
        trusted_signers: list[str],
        server_id: str,
    ) -> None:
        if not trusted_signers or not all(
            is_valid_public_key_hex(key) for key in trusted_signers
        ):
            raise ValueError("pin at least one valid kernel public key")
        if not server_id:
            raise ValueError("server_id is required")
        self.session = session
        self._trusted_signers = list(trusted_signers)
        self._server_id = server_id

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> VerifiedMcpResult:
        request_id = str(uuid4())
        # Snapshot before yielding so a caller mutating its dict mid-flight
        # cannot change what is dispatched or what the receipt is checked against.
        parameters = json.loads(canonicalize_json(arguments))
        response = await self.session.call_tool(
            name, parameters, meta={"chioRequestId": request_id}
        )
        return verify_mcp_result(
            response.model_dump(mode="json", by_alias=True, exclude_none=True),
            trusted_signers=self._trusted_signers,
            request_id=request_id,
            server_id=self._server_id,
            tool_name=name,
            arguments=parameters,
        )

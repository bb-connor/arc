"""Verify kernel-mediated MCP results without trusting projected tool content.

The MCP session is supplied by the application and retains its normal lifetime.
The operator must pin the kernel signer through a separate trusted channel.
"""

from __future__ import annotations

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


class McpReceiptError(ChioInvariantError):
    """A result has no verifiable evidence for the requested invocation."""

    def __init__(self, message: str) -> None:
        super().__init__("mcp_receipt_invalid", message)


@dataclass(frozen=True)
class VerifiedMcpResult:
    """The exact output committed by a trusted kernel receipt."""

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
    """Verify signature, request identity, arguments, and output commitment.

    Only ``_meta.chioReceipt.output`` is returned. MCP's separately projected
    ``content`` and ``structuredContent`` are never treated as signed data.
    Stream commitments and unsupported signature algorithms fail closed.
    """
    try:
        envelope = result["_meta"]["chioReceipt"]
        if type(envelope.get("version")) is not int or envelope["version"] != 1:
            raise McpReceiptError("unsupported Chio MCP receipt envelope")
        kind = envelope["output_kind"]
        if kind not in {"value", "none"}:
            raise McpReceiptError("this client requires a complete value result")
        output = envelope["output"]
        if kind == "none" and output is not None:
            raise McpReceiptError("absent output must be null")
        receipt = envelope["receipt"]
        report = verify_receipt(receipt, trusted_signers)
        if not report["ok"]:
            raise McpReceiptError(
                "kernel receipt failed integrity or signer verification"
            )
        if (
            receipt["receipt_kind"] != "mediated_decision"
            or receipt["boundary_class"] != "prevent"
            or receipt["trust_level"] != "mediated"
        ):
            raise McpReceiptError("receipt does not prove kernel mediation")
        if receipt["tool_server"] != server_id or receipt["tool_name"] != tool_name:
            raise McpReceiptError("receipt belongs to a different tool")
        if receipt["metadata"]["receipt_context"]["request_id"] != request_id:
            raise McpReceiptError("receipt belongs to a different invocation")
        expected_parameters = canonicalize_json(arguments)
        if canonicalize_json(receipt["action"]["parameters"]) != expected_parameters:
            raise McpReceiptError("receipt belongs to different arguments")
        if sha256_hex_utf8(canonicalize_json(output)) != receipt["content_hash"]:
            raise McpReceiptError("tool output does not match its signed commitment")
        if receipt["decision"]["verdict"] not in {"allow", "deny"}:
            raise McpReceiptError("tool invocation did not complete")
        return VerifiedMcpResult(receipt=receipt, output=output)
    except McpReceiptError:
        raise
    except (
        KeyError,
        TypeError,
        ValueError,
        AttributeError,
        ChioInvariantError,
    ) as error:
        raise McpReceiptError(
            "malformed or unsupported Chio MCP receipt evidence"
        ) from error


class VerifiedMcpSession:
    """Use an existing MCP session with mandatory kernel receipt verification.

    No retry is performed after an uncertain transport outcome. The caller may
    inspect the kernel receipt log before deciding whether to submit new work.
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

    async def call_tool(
        self, name: str, arguments: dict[str, Any]
    ) -> VerifiedMcpResult:
        request_id = str(uuid4())
        # Snapshot before yielding so concurrent caller mutation cannot change
        # what this invocation dispatches or what its receipt is checked against.
        import json

        parameters = json.loads(canonicalize_json(arguments))
        response = await self.session.call_tool(
            name,
            parameters,
            meta={"chioIncludeReceipt": True, "chioRequestId": request_id},
        )
        return verify_mcp_result(
            response.model_dump(mode="json", by_alias=True, exclude_none=True),
            trusted_signers=self._trusted_signers,
            request_id=request_id,
            server_id=self._server_id,
            tool_name=name,
            arguments=parameters,
        )

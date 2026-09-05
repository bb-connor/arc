"""LangChain tools that execute through Chio's MCP edge and verify receipts.

Install ``chio-langchain[mcp]``. Keep the supplied MCP session open for the
entire agent run. The id-only advisory ``ChioToolkit`` remains a separate API.
"""

from __future__ import annotations

import json
from typing import Any

from chio.mcp import VerifiedMcpSession
from langchain_core.tools import BaseTool, ToolException
from pydantic import ConfigDict, Field


class ChioMcpToolError(ToolException):
    """A verified denial or tool failure, with invocation-local evidence.

    Applications can handle this as a normal LangChain tool error. Receipt
    verification failures are a different exception and must stop the run.
    """

    def __init__(self, message: str, *, receipt: dict[str, Any], output: Any) -> None:
        super().__init__(message)
        self.receipt = receipt
        self.output = output


class ChioMcpTool(BaseTool):
    """Execute remotely and return only output covered by a trusted receipt."""

    verified_session: VerifiedMcpSession = Field(exclude=True, repr=False)
    response_format: str = "content_and_artifact"
    handle_tool_error: bool = False
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def _run(self, **kwargs: Any) -> Any:
        raise NotImplementedError("Chio MCP tools require async invocation")

    async def _arun(self, **kwargs: Any) -> tuple[str, dict[str, Any]]:
        # Integrity and transport failures propagate. They are not converted
        # into plausible model input or retried as another side effect.
        result = await self.verified_session.call_tool(self.name, kwargs)
        if not result.allowed:
            raise ChioMcpToolError(
                f"Chio denied {self.name}: "
                f"{result.receipt['decision'].get('reason', 'capability or policy denied')} "
                f"(receipt {result.receipt['id']})",
                receipt=result.receipt,
                output=result.output,
            )
        if result.tool_error:
            raise ChioMcpToolError(
                f"Tool failed: {json.dumps(result.output, ensure_ascii=False)} "
                f"(receipt {result.receipt['id']})",
                receipt=result.receipt,
                output=result.output,
            )
        return (
            json.dumps(result.output, ensure_ascii=False),
            {"receipt": result.receipt, "output": result.output},
        )


class ChioMcpToolkit:
    """Discover tools from one Chio MCP edge with operator-pinned authority."""

    def __init__(
        self, session: Any, *, server_id: str, trusted_signers: list[str]
    ) -> None:
        self._verified = VerifiedMcpSession(
            session, server_id=server_id, trusted_signers=trusted_signers
        )

    async def get_tools(self) -> list[ChioMcpTool]:
        tools: list[ChioMcpTool] = []
        seen_names: set[str] = set()
        seen_cursors: set[str] = set()
        cursor = None
        for _ in range(100):
            page = await self._verified.session.list_tools(cursor=cursor)
            for definition in page.tools:
                if definition.name in seen_names or len(tools) >= 1000:
                    raise ValueError("duplicate or excessive MCP tool definitions")
                seen_names.add(definition.name)
                tools.append(
                    ChioMcpTool(
                        name=definition.name,
                        description=definition.description or definition.name,
                        args_schema=definition.inputSchema,
                        verified_session=self._verified,
                    )
                )
            cursor = page.nextCursor
            if cursor is None:
                return tools
            if cursor in seen_cursors:
                raise ValueError("MCP discovery repeated a pagination cursor")
            seen_cursors.add(cursor)
        raise ValueError("MCP discovery exceeded 100 pages")

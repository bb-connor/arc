"""Wrap ARC tools as LangChain Tool objects.

Each ARC tool server advertises tools via a manifest. This module wraps those
tools as LangChain ``BaseTool`` instances so they can be used in LangChain
agents, chains, and pipelines. All tool invocations flow through the ARC
sidecar kernel for capability validation, guard evaluation, and receipt signing.

Usage::

    from arc_langchain import ArcToolkit

    toolkit = ArcToolkit(
        capability_id="cap-123",
        sidecar_url="http://127.0.0.1:4100",
    )
    tools = await toolkit.get_tools()
    # tools is a list of LangChain Tool objects
"""

from __future__ import annotations

import json
from typing import Any, Type

from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field, create_model

from arc_sdk.client import ArcClient
from arc_sdk.errors import ArcDeniedError, ArcError
from arc_sdk.models import ArcReceipt


class ArcTool(BaseTool):
    """A LangChain tool backed by an ARC tool server.

    Invocations are evaluated by the ARC sidecar kernel which validates
    capabilities, runs guards, and signs receipts.
    """

    name: str = ""
    description: str = ""
    server_id: str = ""
    capability_id: str = ""
    sidecar_url: str = "http://127.0.0.1:4100"

    # Store the input schema JSON from the manifest
    input_schema_def: dict[str, Any] = Field(default_factory=dict)

    # Last receipt from a tool invocation (for audit trail access)
    last_receipt: ArcReceipt | None = Field(default=None, exclude=True)

    model_config = {"arbitrary_types_allowed": True}

    def model_post_init(self, __context: Any) -> None:
        """Generate args_schema from input_schema_def after construction."""
        super().model_post_init(__context)
        schema = _build_args_schema(self.name, self.input_schema_def)
        if schema is not None:
            self.args_schema = schema  # type: ignore[assignment]

    def get_input_schema(self) -> Type[BaseModel] | None:
        """Return the dynamically generated input schema, if any."""
        return _build_args_schema(self.name, self.input_schema_def)

    def _run(self, **kwargs: Any) -> str:
        """Synchronous invocation -- raises because ARC requires async."""
        raise NotImplementedError(
            "ARC tools require async invocation. Use _arun or ainvoke."
        )

    async def _arun(self, **kwargs: Any) -> str:
        """Invoke the ARC tool through the sidecar kernel.

        Returns the tool result as a JSON string. The signed receipt is
        stored in ``self.last_receipt``.
        """
        async with ArcClient(self.sidecar_url) as client:
            try:
                receipt = await client.evaluate_tool_call(
                    capability_id=self.capability_id,
                    tool_server=self.server_id,
                    tool_name=self.name,
                    parameters=kwargs,
                )
            except ArcDeniedError as exc:
                return json.dumps({
                    "error": "denied",
                    "guard": exc.guard,
                    "reason": exc.reason or str(exc),
                })
            except ArcError as exc:
                return json.dumps({
                    "error": "arc_error",
                    "message": str(exc),
                })

        self.last_receipt = receipt

        if receipt.is_denied:
            return json.dumps({
                "error": "denied",
                "guard": receipt.decision.guard,
                "reason": receipt.decision.reason or "denied",
            })

        return json.dumps({
            "status": "allowed",
            "receipt_id": receipt.id,
            "tool_server": receipt.tool_server,
            "tool_name": receipt.tool_name,
        })


class ArcToolkit:
    """Creates LangChain tools from ARC tool server manifests.

    Parameters
    ----------
    capability_id:
        ARC capability token ID that authorizes tool invocations.
    sidecar_url:
        Base URL of the ARC sidecar (default ``http://127.0.0.1:4100``).
    """

    def __init__(
        self,
        capability_id: str,
        sidecar_url: str = "http://127.0.0.1:4100",
    ) -> None:
        self._capability_id = capability_id
        self._sidecar_url = sidecar_url

    async def get_tools(
        self,
        server_id: str | None = None,
    ) -> list[ArcTool]:
        """Fetch available tools from the sidecar and wrap them as LangChain tools.

        Parameters
        ----------
        server_id:
            If provided, only return tools from this server. Otherwise
            return tools from all servers.
        """
        async with ArcClient(self._sidecar_url) as client:
            data = await client.health()
            servers = data.get("servers", [])

        tools: list[ArcTool] = []
        for server in servers:
            sid = server.get("server_id", "")
            if server_id is not None and sid != server_id:
                continue
            for tool_def in server.get("tools", []):
                tool = ArcTool(
                    name=tool_def.get("name", ""),
                    description=tool_def.get("description", ""),
                    server_id=sid,
                    capability_id=self._capability_id,
                    sidecar_url=self._sidecar_url,
                    input_schema_def=tool_def.get("input_schema", {}),
                )
                tools.append(tool)

        return tools

    def create_tool(
        self,
        *,
        name: str,
        description: str,
        server_id: str,
        input_schema: dict[str, Any] | None = None,
    ) -> ArcTool:
        """Manually create a single ARC-backed LangChain tool.

        Use this when you know the tool definition ahead of time and do not
        need to discover it from the sidecar.
        """
        return ArcTool(
            name=name,
            description=description,
            server_id=server_id,
            capability_id=self._capability_id,
            sidecar_url=self._sidecar_url,
            input_schema_def=input_schema or {},
        )


def _build_args_schema(
    tool_name: str, input_schema_def: dict[str, Any]
) -> Type[BaseModel] | None:
    """Build a Pydantic model from a JSON Schema definition."""
    if not input_schema_def:
        return None

    properties = input_schema_def.get("properties", {})
    required = set(input_schema_def.get("required", []))

    fields: dict[str, Any] = {}
    for prop_name, prop_def in properties.items():
        field_type = _json_type_to_python(prop_def.get("type", "string"))
        description = prop_def.get("description", "")
        if prop_name in required:
            fields[prop_name] = (field_type, Field(description=description))
        else:
            fields[prop_name] = (
                field_type | None,
                Field(default=None, description=description),
            )

    if not fields:
        return None

    return create_model(f"{tool_name}Input", **fields)  # type: ignore[call-overload]


def _json_type_to_python(json_type: str) -> type:
    """Map a JSON Schema type to a Python type."""
    mapping: dict[str, type] = {
        "string": str,
        "integer": int,
        "number": float,
        "boolean": bool,
        "array": list,
        "object": dict,
    }
    return mapping.get(json_type, str)

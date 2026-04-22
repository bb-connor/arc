#!/usr/bin/env python3

import json
import os

import httpx
from chio import ChioClient, ReceiptQueryClient
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field


DEFAULT_CHIO_BASE_URL = "http://127.0.0.1:8931"
DEFAULT_CHIO_CONTROL_URL = "http://127.0.0.1:8940"
DEFAULT_CHIO_AUTH_TOKEN = "demo-token"


def session_capability_id(base_url: str, auth_token: str, session_id: str) -> str:
    response = httpx.get(
        f"{base_url}/admin/sessions/{session_id}/trust",
        headers={"Authorization": f"Bearer {auth_token}"},
        timeout=5.0,
    )
    response.raise_for_status()
    payload = response.json()
    capabilities = payload.get("capabilities") or []
    capability_id = capabilities[0].get("capabilityId") if capabilities else None
    if not isinstance(capability_id, str) or not capability_id:
        raise RuntimeError("session trust endpoint did not return an active capability id")
    return capability_id


class EchoInput(BaseModel):
    """Arguments passed through LangChain into the Chio-governed MCP tool."""

    message: str = Field(description="Message to echo through Chio")


def main() -> None:
    base_url = os.environ.get("CHIO_BASE_URL", DEFAULT_CHIO_BASE_URL)
    control_url = os.environ.get("CHIO_CONTROL_URL", DEFAULT_CHIO_CONTROL_URL)
    auth_token = os.environ.get("CHIO_AUTH_TOKEN", DEFAULT_CHIO_AUTH_TOKEN)
    client = ChioClient.with_static_bearer(base_url, auth_token)
    session = client.initialize(
        client_info={"name": "chio-langchain-example", "version": "0.2.0"}
    )
    try:
        tools_result = session.list_tools()
        tools = tools_result.get("result", {}).get("tools", [])
        capability_id = session_capability_id(base_url, auth_token, session.session_id)

        def echo_via_arc(message: str) -> str:
            """Call the Chio-governed echo_text tool and return its text payload."""

            result = session.call_tool("echo_text", {"message": message}).get("result", {})
            if result.get("structuredContent"):
                return str(result["structuredContent"].get("echo", ""))
            content = result.get("content", [])
            return "\n".join(
                item["text"] for item in content if item.get("type") == "text"
            )

        tool = StructuredTool.from_function(
            func=echo_via_arc,
            name="chio_echo_text",
            description="Invoke the Chio-governed echo_text MCP tool",
            args_schema=EchoInput,
        )

        message = os.environ.get("CHIO_MESSAGE", "hello from LangChain")
        result = tool.invoke({"message": message})
        receipts = ReceiptQueryClient(control_url, auth_token).query(
            {"capabilityId": capability_id, "limit": 10}
        )
        receipt_list = receipts.get("receipts", [])
        if not receipt_list:
            raise RuntimeError("receipt query did not return the governed tool receipt")
        receipt = receipt_list[-1]

        print(
            json.dumps(
                {
                    "sessionId": session.session_id,
                    "capabilityId": capability_id,
                    "toolNames": [tool["name"] for tool in tools],
                    "echo": result,
                    "receiptId": receipt.get("id"),
                    "receiptDecision": receipt.get("decision"),
                },
                indent=2,
            )
        )
    finally:
        session.close()


if __name__ == "__main__":
    main()

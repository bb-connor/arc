#!/usr/bin/env python3

import json
import os
from uuid import uuid4

import httpx
from chio import ChioClient, ReceiptQueryClient
from chio.mcp import verify_mcp_result
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field


DEFAULT_CHIO_BASE_URL = "http://127.0.0.1:8931"
DEFAULT_CHIO_CONTROL_URL = "http://127.0.0.1:8940"
DEFAULT_CHIO_AUTH_TOKEN = "demo-token"
DEFAULT_CHIO_ADMIN_TOKEN = "demo-admin-token"
DEFAULT_CHIO_CONTROL_TOKEN = "demo-control-token"
DEFAULT_CHIO_SERVER_ID = "wrapped-http-mock"


def session_capability_id(base_url: str, admin_token: str, session_id: str) -> str:
    response = httpx.get(
        f"{base_url}/admin/sessions/{session_id}/trust",
        headers={"Authorization": f"Bearer {admin_token}"},
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
    admin_token = os.environ.get("CHIO_ADMIN_TOKEN", DEFAULT_CHIO_ADMIN_TOKEN)
    control_token = os.environ.get("CHIO_CONTROL_TOKEN", DEFAULT_CHIO_CONTROL_TOKEN)
    server_id = os.environ.get("CHIO_SERVER_ID", DEFAULT_CHIO_SERVER_ID)
    kernel_public_key = os.environ.get("CHIO_KERNEL_PUBLIC_KEY")
    if not kernel_public_key:
        raise SystemExit(
            "set CHIO_KERNEL_PUBLIC_KEY to the edge kernel receipt signing key, "
            "obtained from the operator and not from the edge response"
        )
    client = ChioClient.with_static_bearer(base_url, auth_token)
    session = client.initialize(
        client_info={"name": "chio-langchain-example", "version": "0.2.0"}
    )
    try:
        tools_result = session.list_tools()
        tools = tools_result.get("result", {}).get("tools", [])
        capability_id = session_capability_id(base_url, admin_token, session.session_id)

        verified_receipts: list[dict] = []

        def echo_via_chio(message: str) -> str:
            """Call echo_text and return only output covered by the signed receipt."""

            arguments = {"message": message}
            request_id = str(uuid4())
            response = session.request_result(
                "tools/call",
                {
                    "name": "echo_text",
                    "arguments": arguments,
                    "_meta": {"chioRequestId": request_id},
                },
            )
            if "result" not in response:
                raise RuntimeError(f"tools/call failed: {response.get(error)}")
            verified = verify_mcp_result(
                response["result"],
                trusted_signers=[kernel_public_key],
                request_id=request_id,
                server_id=server_id,
                tool_name="echo_text",
                arguments=arguments,
            )
            if not verified.allowed or verified.tool_error:
                raise RuntimeError(
                    f"Chio did not complete echo_text (receipt {verified.receipt[id]})"
                )
            verified_receipts.append(verified.receipt)
            output = verified.output if isinstance(verified.output, dict) else {}
            if output.get("structuredContent"):
                return str(output["structuredContent"].get("echo", ""))
            content = output.get("content", [])
            return "\n".join(
                item["text"] for item in content if item.get("type") == "text"
            )

        tool = StructuredTool.from_function(
            func=echo_via_chio,
            name="chio_echo_text",
            description="Invoke the Chio-governed echo_text MCP tool",
            args_schema=EchoInput,
        )

        message = os.environ.get("CHIO_MESSAGE", "hello from LangChain")
        result = tool.invoke({"message": message})
        receipts = ReceiptQueryClient(control_url, control_token).query(
            {"capabilityId": capability_id, "limit": 10}
        )
        receipt = verified_receipts[-1]
        if not any(
            item.get("id") == receipt["id"] for item in receipts.get("receipts", [])
        ):
            raise RuntimeError("receipt query did not return the verified tool receipt")

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

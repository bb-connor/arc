#!/usr/bin/env python3

import json
import sys
import time

CLIENT_CAPABILITIES = {}

TOOLS = [
    {
        "name": "echo_text",
        "title": "Echo Text",
        "description": "Return a simple text response",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "slow_echo",
        "title": "Slow Echo",
        "description": "Sleep before returning a simple text response",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "emit_fixture_notifications",
        "title": "Emit Fixture Notifications",
        "description": "Emit resource and catalog change notifications before returning",
        "inputSchema": {
            "type": "object",
            "properties": {
                "uri": {"type": "string"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "sampled_echo",
        "title": "Sampled Echo",
        "description": "Use sampling/createMessage before returning",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "elicited_echo",
        "title": "Elicited Echo",
        "description": "Use form-mode elicitation/create before returning",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "url_elicited_echo",
        "title": "URL Elicited Echo",
        "description": "Use URL-mode elicitation/create and completion notification before returning",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "roots_echo",
        "title": "Roots Echo",
        "description": "Use roots/list before returning",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    }
]

RESOURCES = [
    {
        "uri": "fixture://docs/alpha",
        "name": "alpha-doc",
        "description": "MCP core resource fixture",
        "mimeType": "text/plain"
    }
]

PROMPTS = [
    {
        "name": "summarize_fixture",
        "description": "Summarize the fixture resource",
        "arguments": [
            {
                "name": "topic",
                "required": False,
                "description": "Optional prompt topic"
            }
        ]
    }
]
def respond(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def read_message():
    while True:
        line = sys.stdin.readline()
        if not line:
            raise EOFError("stdin closed")
        if line.strip():
            return json.loads(line)


def tool_result(request_id, text, structured_content=None, is_error=False):
    result = {
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    }
    if structured_content is not None:
        result["structuredContent"] = structured_content
    respond({"jsonrpc": "2.0", "id": request_id, "result": result})


def supports_sampling():
    return "sampling" in CLIENT_CAPABILITIES


def supports_form_elicitation():
    elicitation = CLIENT_CAPABILITIES.get("elicitation")
    return isinstance(elicitation, dict) and (not elicitation or "form" in elicitation)


def supports_url_elicitation():
    elicitation = CLIENT_CAPABILITIES.get("elicitation")
    return isinstance(elicitation, dict) and ("url" in elicitation or "openUrl" in elicitation)


def supports_roots():
    return "roots" in CLIENT_CAPABILITIES


def request_client(request_id, method, params):
    respond(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
    )
    while True:
        message = read_message()
        if message.get("id") != request_id or message.get("method"):
            continue
        return message


while True:
    try:
        message = read_message()
    except EOFError:
        break

    method = message.get("method")

    if method == "initialize":
        CLIENT_CAPABILITIES = message.get("params", {}).get("capabilities", {})
        respond(
            {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {
                        "tools": {"listChanged": True},
                        "resources": {"subscribe": True, "listChanged": True},
                        "prompts": {"listChanged": True},
                    },
                    "serverInfo": {
                        "name": "conformance-mcp-core-upstream",
                        "version": "0.1.0",
                    },
                },
            }
        )
        continue

    if method == "notifications/initialized":
        continue

    if method == "tools/list":
        respond({"jsonrpc": "2.0", "id": message["id"], "result": {"tools": TOOLS}})
        continue

    if method == "tools/call":
        arguments = message.get("params", {}).get("arguments", {})
        tool_name = message.get("params", {}).get("name")

        if tool_name == "slow_echo":
            time.sleep(1.0)
            tool_result(message["id"], arguments.get("message", "fixture-response"))
            continue

        if tool_name == "emit_fixture_notifications":
            uri = arguments.get("uri", "fixture://docs/alpha")
            respond(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/resources/updated",
                    "params": {"uri": uri},
                }
            )
            respond(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/resources/list_changed",
                }
            )
            respond(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/tools/list_changed",
                }
            )
            respond(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/prompts/list_changed",
                }
            )
            tool_result(message["id"], arguments.get("message", "fixture-response"))
            continue

        if tool_name == "sampled_echo":
            if not supports_sampling():
                tool_result(message["id"], "sampling not negotiated", is_error=True)
                continue
            sampling_id = f"sample-{message['id']}"
            sampling_response = request_client(
                sampling_id,
                "sampling/createMessage",
                {
                    "messages": [
                        {
                            "role": "user",
                            "content": {
                                "type": "text",
                                "text": arguments.get("message", "fixture sampling request"),
                            },
                        }
                    ],
                    "maxTokens": 128,
                },
            )
            if sampling_response.get("error"):
                tool_result(
                    message["id"],
                    sampling_response["error"].get("message", "sampling failed"),
                    is_error=True,
                )
                continue
            sampled = sampling_response["result"]
            tool_result(
                message["id"],
                sampled.get("content", {}).get("text", "sampled"),
                structured_content={"sampled": sampled},
            )
            continue

        if tool_name == "elicited_echo":
            if not supports_form_elicitation():
                tool_result(message["id"], "form elicitation not negotiated", is_error=True)
                continue
            elicitation_id = f"elicit-form-{message['id']}"
            elicitation_response = request_client(
                elicitation_id,
                "elicitation/create",
                {
                    "mode": "form",
                    "message": arguments.get("message", "fixture elicitation request"),
                    "requestedSchema": {
                        "type": "object",
                        "properties": {
                            "answer": {"type": "string"}
                        },
                        "required": ["answer"],
                    },
                },
            )
            if elicitation_response.get("error"):
                tool_result(
                    message["id"],
                    elicitation_response["error"].get("message", "elicitation failed"),
                    is_error=True,
                )
                continue
            elicited = elicitation_response["result"]
            tool_result(
                message["id"],
                json.dumps(elicited),
                structured_content={"elicited": elicited},
            )
            continue

        if tool_name == "url_elicited_echo":
            if not supports_url_elicitation():
                tool_result(message["id"], "url elicitation not negotiated", is_error=True)
                continue
            elicitation_id = f"elicit-url-{message['id']}"
            elicitation_response = request_client(
                elicitation_id,
                "elicitation/create",
                {
                    "mode": "url",
                    "message": arguments.get("message", "fixture url elicitation request"),
                    "url": "https://example.com/conformance/elicitation",
                    "elicitationId": elicitation_id,
                },
            )
            if elicitation_response.get("error"):
                tool_result(
                    message["id"],
                    elicitation_response["error"].get("message", "url elicitation failed"),
                    is_error=True,
                )
                continue
            elicited = elicitation_response["result"]
            if elicited.get("action") == "accept":
                respond(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/elicitation/complete",
                        "params": {"elicitationId": elicitation_id},
                    }
                )
            tool_result(
                message["id"],
                json.dumps(elicited),
                structured_content={
                    "elicited": elicited,
                    "elicitationId": elicitation_id,
                },
            )
            continue

        if tool_name == "roots_echo":
            if not supports_roots():
                tool_result(message["id"], "roots not negotiated", is_error=True)
                continue
            roots_id = f"roots-{message['id']}"
            roots_response = request_client(roots_id, "roots/list", {})
            if roots_response.get("error"):
                tool_result(
                    message["id"],
                    roots_response["error"].get("message", "roots failed"),
                    is_error=True,
                )
                continue
            roots = roots_response.get("result", {}).get("roots", [])
            tool_result(
                message["id"],
                json.dumps(roots),
                structured_content={"roots": roots},
            )
            continue

        tool_result(message["id"], arguments.get("message", "fixture-response"))
        continue

    if method == "resources/list":
        respond(
            {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {"resources": RESOURCES},
            }
        )
        continue

    if method == "prompts/list":
        respond(
            {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {"prompts": PROMPTS},
            }
        )
        continue

    respond(
        {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "error": {"code": -32601, "message": f"unknown method: {method}"},
        }
    )

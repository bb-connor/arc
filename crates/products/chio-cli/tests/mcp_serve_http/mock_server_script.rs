use super::*;

pub(crate) fn write_mock_server_script(dir: &Path) -> PathBuf {
    let script = r##"
import json
import os
import sys
import threading
import time

CLIENT_CAPABILITIES = {}
STARTUP_MARKER_PATH = os.environ.get("CHIO_MCP_STARTUP_MARKER_PATH")
WRITE_LOCK = threading.Lock()

if STARTUP_MARKER_PATH:
    with open(STARTUP_MARKER_PATH, "a", encoding="utf-8") as handle:
        handle.write(f"{os.getpid()}\n")

TOOLS = [
    {
        "name": "echo_json",
        "title": "Echo JSON",
        "description": "Return structured JSON",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"}
            }
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "echo": {"type": "string"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "sampled_echo",
        "description": "Uses sampling/createMessage before responding",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"}
            }
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "sampled": {"type": "object"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "slow_echo",
        "description": "Sleeps briefly before responding",
        "inputSchema": {"type": "object"},
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "slow_cancelable_echo",
        "description": "Sleeps longer before responding so cancellation stays in flight",
        "inputSchema": {"type": "object"},
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "emit_fixture_notifications",
        "description": "Emits resource notifications before responding",
        "inputSchema": {
            "type": "object",
            "properties": {
                "count": {"type": "integer"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "emit_late_fixture_notifications",
        "description": "Responds first and emits resource notifications later",
        "inputSchema": {
            "type": "object",
            "properties": {
                "count": {"type": "integer"},
                "delayMs": {"type": "integer"}
            }
        },
        "annotations": {
            "readOnlyHint": True
        }
    },
    {
        "name": "drop_stream_mid_call",
        "description": "Closes the wrapped MCP process before completing the tool response",
        "inputSchema": {"type": "object"},
        "annotations": {
            "readOnlyHint": True
        }
    }
]

RESOURCES = [
    {
        "uri": "fixture://docs/0",
        "name": "Fixture Doc",
        "mimeType": "text/plain"
    }
]

def respond(payload):
    with WRITE_LOCK:
        sys.stdout.write(json.dumps(payload) + "\n")
        sys.stdout.flush()

for line in sys.stdin:
    if not line.strip():
        continue

    message = json.loads(line)
    method = message.get("method")

    if method == "initialize":
        CLIENT_CAPABILITIES = message.get("params", {}).get("capabilities", {})
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "tools": {},
                    "resources": {
                        "subscribe": True,
                        "listChanged": True
                    }
                },
                "serverInfo": {
                    "name": "mock-http-upstream",
                    "version": "0.1.0"
                }
            }
        })
        continue

    if method == "notifications/initialized":
        continue

    if method == "tools/list":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"tools": TOOLS}
        })
        continue

    if method == "resources/list":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"resources": RESOURCES}
        })
        continue

    if method == "resources/templates/list":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"resourceTemplates": []}
        })
        continue

    if method == "resources/read":
        uri = message.get("params", {}).get("uri", "fixture://docs/0")
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "text/plain",
                        "text": "fixture resource"
                    }
                ]
            }
        })
        continue

    if method == "resources/subscribe" or method == "resources/unsubscribe":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {}
        })
        continue

    if method == "tools/call":
        tool_name = message["params"]["name"]
        arguments = message["params"].get("arguments", {})

        if tool_name == "echo_json":
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": "echoed"}],
                    "structuredContent": {"echo": arguments.get("message", "hello")},
                    "isError": False
                }
            })
            continue

        if tool_name == "slow_echo":
            time.sleep(1.0)
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": "slow response"}],
                    "isError": False
                }
            })
            continue

        if tool_name == "slow_cancelable_echo":
            time.sleep(3.0)
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": "slow cancellation response"}],
                    "isError": False
                }
            })
            continue

        if tool_name == "emit_fixture_notifications":
            count = max(1, int(arguments.get("count", 1)))
            for index in range(count):
                if index % 2 == 0:
                    respond({
                        "jsonrpc": "2.0",
                        "method": "notifications/resources/list_changed"
                    })
                else:
                    respond({
                        "jsonrpc": "2.0",
                        "method": "notifications/resources/updated",
                        "params": {"uri": f"fixture://docs/{index}"}
                    })
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": f"emitted {count} notifications"}],
                    "structuredContent": {"count": count},
                    "isError": False
                }
            })
            continue

        if tool_name == "emit_late_fixture_notifications":
            count = max(1, int(arguments.get("count", 1)))
            delay_ms = max(10, int(arguments.get("delayMs", 150)))

            def emit_late_notifications():
                time.sleep(delay_ms / 1000.0)
                for index in range(count):
                    if index % 2 == 0:
                        respond({
                            "jsonrpc": "2.0",
                            "method": "notifications/resources/list_changed"
                        })
                    else:
                        respond({
                            "jsonrpc": "2.0",
                            "method": "notifications/resources/updated",
                            "params": {"uri": f"fixture://docs/{index}"}
                        })

            threading.Thread(target=emit_late_notifications, daemon=True).start()
            respond({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [{"type": "text", "text": f"scheduled {count} late notifications"}],
                    "structuredContent": {"count": count, "delayMs": delay_ms},
                    "isError": False
                }
            })
            continue

        if tool_name == "drop_stream_mid_call":
            sys.stdout.flush()
            sys.exit(0)

        if tool_name == "sampled_echo":
            if "sampling" not in CLIENT_CAPABILITIES:
                respond({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [{"type": "text", "text": "sampling not negotiated"}],
                        "isError": True
                    }
                })
                continue

            sample_request_id = f"sample-{message['id']}"
            respond({
                "jsonrpc": "2.0",
                "id": sample_request_id,
                "method": "sampling/createMessage",
                "params": {
                    "messages": [
                        {
                            "role": "user",
                            "content": {
                                "type": "text",
                                "text": arguments.get("message", "sample me")
                            }
                        }
                    ],
                    "maxTokens": 128
                }
            })

            while True:
                sample_response = json.loads(sys.stdin.readline())
                if sample_response.get("id") != sample_request_id or sample_response.get("method"):
                    continue
                if sample_response.get("error"):
                    respond({
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "content": [{"type": "text", "text": sample_response["error"]["message"]}],
                            "isError": True
                        }
                    })
                    break

                sampled = sample_response["result"]
                respond({
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(sampled)}],
                        "structuredContent": {"sampled": sampled},
                        "isError": False
                    }
                })
                break
            continue

    if method == "tasks/get":
        respond({
            "jsonrpc": "2.0",
            "id": message["id"],
            "error": {
                "code": -32602,
                "message": "unknown method: tasks/get"
            }
        })
        continue

    respond({
        "jsonrpc": "2.0",
        "id": message.get("id"),
        "error": {"code": -32601, "message": f"unknown method: {method}"}
    })
"##;

    let path = dir.join("mock_http_mcp_server.py");
    fs::write(&path, script).expect("write mock server script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("secure mock MCP server permissions");
    }
    path
}

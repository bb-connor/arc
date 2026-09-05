#!/usr/bin/env python3
"""Installation-test model client. Proposes a fixed repair and never executes tools."""

import json
import sys


def main() -> None:
    request = json.load(sys.stdin)
    args = sys.argv[1:]
    for flag in ("--safe-mode", "--restricted", "--strict-mcp-config", "--no-session-persistence"):
        if flag not in args:
            raise ValueError(f"missing client restriction: {flag}")
    for flag, value in (("--tools", ""), ("--mcp-config", '{"mcpServers":{}}'),
                        ("--settings", '{"disableAllHooks":true}')):
        if args[args.index(flag) + 1] != value:
            raise ValueError(f"unexpected client setting: {flag}")
    messages = request["messages"]
    if any(message["role"] == "assistant" for message in messages):
        content = [{"type": "text", "text": "Installation-test role finished."}]
        stop = "end_turn"
    else:
        tools = {tool["name"] for tool in request["tools"]}
        calls = [("read_file", {"path": "calc.py"})]
        if "replace_text" in tools:
            calls.append(("replace_text", {"path": "calc.py", "old_text": "return a - b", "new_text": "return a + b"}))
        calls.append(("run_checks", {}))
        content = [{"type": "tool_use", "id": f"fixture-{index}", "name": name, "input": arguments}
                   for index, (name, arguments) in enumerate(calls)]
        stop = "tool_use"
    json.dump({"type": "result", "subtype": "success", "is_error": False, "permission_denials": [],
               "structured_output": {"content": content, "stop_reason": stop},
               "usage": {"input_tokens": 0, "output_tokens": 0}}, sys.stdout)


if __name__ == "__main__":
    main()

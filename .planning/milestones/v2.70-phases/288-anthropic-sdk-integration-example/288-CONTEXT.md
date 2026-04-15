# Phase 288 Context

## Goal

Provide a working example that shows Claude consuming ARC-governed tools
through the Anthropic SDK.

## Constraints

- Verification should not depend on a live Anthropic API key.
- The example still needs a real ARC/MCP tool path, not a mocked tool schema.
- Reusing the `examples/docker` upstream server keeps the integration small and
  focused on the framework seam.

## Implementation Direction

- Add a Node example that starts `arc mcp serve`.
- Use a small stdio JSON-RPC client to initialize ARC, list tools, and call
  tools directly for dry-run verification.
- When `ANTHROPIC_API_KEY` is present, use the Anthropic SDK tool-use loop to
  hand ARC tool definitions to Claude and replay `tool_result` blocks.

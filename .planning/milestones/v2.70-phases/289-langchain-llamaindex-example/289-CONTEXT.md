# Phase 289 Context

## Goal

Provide a working framework example that wraps an ARC-governed MCP tool as a
LangChain tool.

## Constraints

- The roadmap title mentions `LangChain/LlamaIndex`, but the actual shipped
  requirement `DX-04` is specifically about a LangChain tool wrapper.
- Verification should stay local and deterministic rather than depending on a
  hosted model provider.
- The example should reuse the same governed MCP surface already established in
  phases `287` and `288`.

## Implementation Direction

- Add a Python example that starts `arc mcp serve`.
- Build a tiny stdio JSON-RPC client for the ARC MCP edge.
- Wrap the governed `echo_text` tool as a LangChain `StructuredTool` and
  verify by invoking it locally.

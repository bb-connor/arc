---
phase: 310
plan: 02
created: 2026-04-13
status: complete
---

# Summary 310-02

The framework examples now use the official ARC SDKs instead of hand-rolled
stdio MCP transport.

- `examples/anthropic-sdk` imports `@arc-protocol/sdk`, initializes a hosted
  ARC session, maps the returned tool inventory into Anthropic tool
  definitions, executes tool uses back through ARC, and resolves the receipt.
- `examples/langchain` imports `arc-sdk`, wraps the governed `echo_text` call
  as a LangChain `StructuredTool`, and prints the resulting receipt metadata.
- `examples/openai-compatible` demonstrates ARC governance over Chat
  Completions function calling while allowing `OPENAI_BASE_URL` overrides for
  other compatible providers.

The new `scripts/check-framework-integration-examples.sh` script boots a trust
service plus hosted edge locally, runs all three example paths, and confirms
that each one reports a capability ID, receipt ID, and echoed governed result.

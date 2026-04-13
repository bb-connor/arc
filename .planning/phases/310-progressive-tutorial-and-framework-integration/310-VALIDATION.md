---
phase: 310-progressive-tutorial-and-framework-integration
created: 2026-04-13
status: complete
---

# Phase 310 Validation

## Required Evidence

- A tutorial document exists and covers ARC concepts, policy authoring, tool
  wrapping, governed execution, receipt lookup, and the current delegation
  workflow.
- `examples/anthropic-sdk` imports `@arc-protocol/sdk` and performs a governed
  tool call through the typed client.
- `examples/langchain` imports `arc-sdk` and performs a governed tool call
  through the typed client.
- `examples/openai-compatible` demonstrates ARC-governed function calling
  against an OpenAI-compatible Chat Completions client.

## Verification Commands

- `./scripts/check-framework-integration-examples.sh`
- `cargo check -p arc-cli`

## Regression Focus

- hosted-edge session initialization and session-to-capability lookup
- receipt query flow after governed tool execution
- local SDK installation paths for the framework examples
- OpenAI-compatible tool loop shape against the current Chat Completions
  contract

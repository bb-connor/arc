---
phase: 310-progressive-tutorial-and-framework-integration
created: 2026-04-13
status: complete
---

# Phase 310 Research

## Findings

- The TypeScript SDK already exposes the exact surface the framework examples
  need: `ArcClient.withStaticBearer(...)`, session `listTools()`, session
  `callTool(...)`, and `ReceiptQueryClient`.
- The Python SDK already exposes the equivalent `ArcClient`,
  `ArcSession.list_tools()`, `ArcSession.call_tool()`, and
  `ReceiptQueryClient` surface.
- The Docker quickstart from phase `309` already publishes stable defaults for
  tutorial consumers: hosted edge on `http://127.0.0.1:8931`, trust service on
  `http://127.0.0.1:8940`, and auth token `demo-token`.
- The concrete public delegation workflow currently documented in-repo is the
  federated continuation lane:
  `arc trust federated-delegation-policy-create` plus
  `arc trust federated-issue --upstream-capability-id ...`.
- Current OpenAI docs continue to support Chat Completions tool calling while
  recommending incremental migration toward the Responses API, so a
  Chat-Completions-based function-calling example remains valid for a simple
  governed-tool loop.

## Consequences

- The framework examples should default to the phase `309` demo endpoints so a
  developer can `docker compose up` once and then run any example without extra
  wiring.
- The tutorial should explicitly frame delegation as a continuation workflow
  rather than claiming that the local hosted-session demo directly issues child
  capabilities.
- The OpenAI-compatible example should accept `OPENAI_BASE_URL` so it works
  with OpenAI and other compatible providers that expose the same Chat
  Completions tool-calling contract.

# Example Surface Matrix

This matrix maps each example in [`examples/`](./) to the ARC surface it teaches.

Support directories such as [`_shared/`](./_shared/), [`policies/`](./policies/), and [`run-hello-smokes.sh`](./run-hello-smokes.sh) are intentionally excluded because they are scaffolding rather than teaching examples.

| Example | Kind | ARC surfaces taught | What it demonstrates | Primary run path |
| --- | --- | --- | --- | --- |
| [`agent-commerce-network/`](./agent-commerce-network/) | Flagship | `trust serve`, `api protect`, MCP edge, evidence review, federation-style artifact flow | Real multi-party economic workflow with approvals, budgets, settlement, disputes, and reviewer verification | [`README.md`](./agent-commerce-network/README.md) |
| [`internet-of-agents-incident-network/`](./internet-of-agents-incident-network/) | Flagship | recursive delegation, OpenAI SDK orchestration, MCP internal tools, ACP external jobs, offline evidence review | Cross-org incident response with a live happy path for customer-to-provider authority narrowing and “internet of agents” execution contracts | [`README.md`](./internet-of-agents-incident-network/README.md) |
| [`hello-tool/`](./hello-tool/) | Native service | Native ARC service builder, manifest signing, manifest pricing | Native ARC tool/resource/prompt registration without wrapped MCP | [`README.md`](./hello-tool/README.md) |
| [`docker/`](./docker/) | Quickstart topology | `trust serve`, hosted MCP edge, receipt dashboard | Smallest containerized governed call path with live receipt inspection | [`README.md`](./docker/README.md) |
| [`anthropic-sdk/`](./anthropic-sdk/) | Ecosystem client | Hosted ARC session, tool mapping, trust receipt lookup | Claude tool use over ARC-governed hosted tools | [`README.md`](./anthropic-sdk/README.md) |
| [`openai-compatible/`](./openai-compatible/) | Ecosystem client | Hosted ARC session, OpenAI-compatible function mapping, trust receipt lookup | OpenAI-style function calling over ARC-governed hosted tools | [`README.md`](./openai-compatible/README.md) |
| [`langchain/`](./langchain/) | Ecosystem client | Python ARC SDK, hosted HTTP edge, trust receipt lookup | LangChain `StructuredTool` execution while ARC remains in the enforcement path | [`README.md`](./langchain/README.md) |
| [`hello-trust-control/`](./hello-trust-control/) | Control-plane adjunct | Trust capability issuance, status, revocation, `arc check`, `arc evidence verify` | Direct trust-plane lifecycle plus offline receipt verification without an app surface | [`smoke.sh`](./hello-trust-control/smoke.sh) |
| [`hello-receipt-verify/`](./hello-receipt-verify/) | Control-plane adjunct | Offline evidence verification, receipt lineage inspection, tamper detection | Verify a captured evidence package locally and prove that tampering fails | [`smoke.sh`](./hello-receipt-verify/smoke.sh) |
| [`hello-openapi-sidecar/`](./hello-openapi-sidecar/) | HTTP sidecar | `arc api protect` with OpenAPI, sidecar receipts, capability-gated side effects | Governing a plain upstream app directly from an OpenAPI spec, with no framework SDK in the app | [`smoke.sh`](./hello-openapi-sidecar/smoke.sh) |
| [`hello-fastapi/`](./hello-fastapi/) | HTTP framework | `arc-asgi`, `arc-fastapi` | FastAPI-native ARC interception and receipt-bearing request handling | [`smoke.sh`](./hello-fastapi/smoke.sh) |
| [`hello-django/`](./hello-django/) | HTTP framework | `arc-django` | Django middleware-style ARC governance on safe and side-effect routes | [`smoke.sh`](./hello-django/smoke.sh) |
| [`hello-fastify/`](./hello-fastify/) | HTTP framework | `@arc-protocol/fastify` | Fastify plugin-based ARC governance with receipt-bearing routes | [`smoke.sh`](./hello-fastify/smoke.sh) |
| [`hello-elysia/`](./hello-elysia/) | HTTP framework | `@arc-protocol/elysia` | Elysia integration with ARC request governance and sidecar-backed receipts | [`smoke.sh`](./hello-elysia/smoke.sh) |
| [`hello-express/`](./hello-express/) | HTTP framework | `@arc-protocol/express` | Express middleware path for deny/allow flows with receipts | [`smoke.sh`](./hello-express/smoke.sh) |
| [`hello-chi/`](./hello-chi/) | HTTP framework | `arc-go-http` | Go `chi` integration with ARC HTTP enforcement | [`smoke.sh`](./hello-chi/smoke.sh) |
| [`hello-spring-boot/`](./hello-spring-boot/) | HTTP framework | `arc-spring-boot` | JVM/Spring Boot ARC filter chain on safe and governed routes | [`smoke.sh`](./hello-spring-boot/smoke.sh) |
| [`hello-dotnet/`](./hello-dotnet/) | HTTP framework | `ArcMiddleware` | ASP.NET ARC middleware for allow/deny and receipt-bearing responses | [`smoke.sh`](./hello-dotnet/smoke.sh) |
| [`hello-mcp/`](./hello-mcp/) | Protocol edge | MCP edge runtime | Authoritative MCP request handling over JSON-RPC with ARC semantics | [`smoke.sh`](./hello-mcp/smoke.sh) |
| [`hello-a2a/`](./hello-a2a/) | Protocol edge | A2A edge runtime | Authoritative A2A send plus deferred task lifecycle through ARC | [`smoke.sh`](./hello-a2a/smoke.sh) |
| [`hello-acp/`](./hello-acp/) | Protocol edge | ACP edge runtime | ACP invoke plus deferred stream/resume lifecycle through ARC | [`smoke.sh`](./hello-acp/smoke.sh) |
| [`guards/tool-gate/`](./guards/tool-gate/) | Guard example | `arc-guard-sdk` basic verdict logic | Tool-name-based allow/deny policy in a tiny WASM guard | [`src/lib.rs`](./guards/tool-gate/src/lib.rs) |
| [`guards/enriched-inspector/`](./guards/enriched-inspector/) | Guard example | `arc-guard-sdk` enriched fields + host functions | Enriched request inspection and host-function-based path blocking in a WASM guard | [`src/lib.rs`](./guards/enriched-inspector/src/lib.rs) |

## Suggested Learning Order

1. [`hello-openapi-sidecar/`](./hello-openapi-sidecar/) to understand the sidecar model directly.
2. One HTTP framework hello that matches your stack.
3. [`hello-trust-control/`](./hello-trust-control/) and [`hello-receipt-verify/`](./hello-receipt-verify/) for the control-plane and evidence model.
4. [`hello-mcp/`](./hello-mcp/), [`hello-a2a/`](./hello-a2a/), or [`hello-acp/`](./hello-acp/) for protocol-native surfaces.
5. [`hello-tool/`](./hello-tool/) when you want to move from wrapped adapters to a native ARC service.
6. [`agent-commerce-network/`](./agent-commerce-network/) when you want the full real-world composition.
7. [`internet-of-agents-incident-network/`](./internet-of-agents-incident-network/) when you want the full recursive delegation and cross-org “internet of agents” composition.

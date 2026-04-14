# HTTP Framework Integration Strategy

> **Status**: Strategic direction -- approved April 2026.
> This document defines how ARC extends beyond protocol adapters (MCP, A2A, ACP)
> to become the universal security kernel for any API surface.
>
> **Current-state note:** the repo does not currently ship `arc api protect`,
> `arc-openapi`, `arc-asgi`, `arc-node-http`, `arc-go-http`, or the framework
> packages named below. These names describe the proposed packaging strategy
> around the existing Rust kernel and protocol adapters.

## 1. The Problem: ARC Is Not "Just Another MCP Gateway"

ARC's current adapter surface covers three agent protocols: MCP (tool access),
A2A (agent-to-agent), and ACP (editor-to-agent). This positions ARC as a
protocol-specific security layer.

But the real surface area is much larger. Agents call APIs. They call FastAPI
endpoints, Django views, Go handlers, Elysia routes, Spring controllers. Every
HTTP API is a tool surface that agents consume. If ARC only secures the three
agent protocols, it misses a large share of the practical attack surface.

The strategic move: **one kernel, many substrates**. ARC's capability tokens,
guard pipeline, and receipt signing should work on any API -- not just MCP/A2A/ACP.

## 2. Architecture: Substrates, Not Frameworks

Instead of building N framework integrations from scratch, build a small number
of **substrate adapters** that cover families of frameworks.

```
+---------------------------------------------------------------+
|                    Framework Wrappers (thin)                   |
|  arc-fastapi  arc-django  arc-elysia  arc-fastify  arc-gin    |
+---------------------------------------------------------------+
|                    Substrate Adapters                          |
|  arc-asgi     arc-node-http     arc-go-http     arc-tower     |
+---------------------------------------------------------------+
|                    Shared Core                                 |
|  arc-http-core (request model, session, receipts, policy)     |
+---------------------------------------------------------------+
|                    ARC Kernel                                  |
|  Capabilities  |  Guards  |  Receipts  |  Budgets  |  DPoP    |
+---------------------------------------------------------------+
|                    Protocol Adapters (existing)                |
|  arc-mcp-adapter  |  arc-a2a-adapter  |  arc-acp-proxy        |
+---------------------------------------------------------------+
```

### Substrate Map

| Substrate | Covers | Package |
|-----------|--------|---------|
| ASGI (Python) | FastAPI, Starlette, Litestar, async Python | `arc-asgi` |
| WSGI/Django (Python) | Django, DRF, Flask (WSGI + ORM patterns) | `arc-django` |
| Node/Bun HTTP (JS/TS) | Fastify, Express, Nest, Hono, Elysia | `arc-node-http` |
| net/http (Go) | stdlib, Gin, Echo, Fiber, chi | `arc-go-http` |
| Servlet/WebFlux (Java) | Spring Boot, Quarkus, Micronaut | `arc-jvm` |
| ASP.NET Core (.NET) | Minimal APIs, MVC, Blazor | `arc-dotnet` |
| tower::Layer (Rust) | Axum, Tonic, any tower-based service | `arc-tower` |

### Why Substrates Work

- **ASGI** is the standard async Python interface. FastAPI and Starlette are
  ASGI apps. One ASGI middleware covers the entire async Python API ecosystem.
  Django gets its own package because WSGI, the ORM, and admin patterns are
  structurally different.

- **Node/Bun HTTP** has a common `(req, res)` or `Request -> Response` model.
  One substrate handles the core interception; thin wrappers adapt to
  framework-specific plugin APIs (Fastify plugins, Express middleware, Elysia
  lifecycle hooks).

- **net/http** in Go is the universal substrate. Gin, Echo, Fiber, and chi all
  build on or wrap `http.Handler`. One `http.Handler` middleware covers them all.

## 3. The Best Current Control Surface: OpenAPI/JSON Schema

Any HTTP API with an OpenAPI spec can be brought under baseline ARC governance.

### Auto-Discovery Pipeline

```
OpenAPI spec (YAML/JSON)
    |
    v
arc-openapi: parse routes, methods, params, response schemas, tags
    |
    v
Generate ARC ToolManifest:
    - Each route becomes a candidate ToolDefinition
    - Path params become input_schema fields
    - HTTP method provides a default side-effect hint, not the final truth
    - Tags help seed capability scopes and grouping
    - Explicit curation can suppress, merge, or relabel routes
    |
    v
Generate default policy:
    - deny-by-default for side effects unless declared safe
    - read endpoints get automatic allow with session binding
    - write endpoints require explicit capability grant
    |
    v
Developer overrides (optional):
    - annotations, decorators, or arc.yaml sections
    - only needed for exceptional cases
```

### ARC Metadata Extensions for OpenAPI

Developers add extra ARC metadata only where needed. These extend the OpenAPI
spec via `x-arc-*` fields or standalone `arc.yaml` policy:

```yaml
# In OpenAPI spec (x-arc extensions)
paths:
  /api/patients/{id}:
    get:
      x-arc-sensitivity: high
      x-arc-data-classification: phi
    delete:
      x-arc-side-effects: true
      x-arc-approval-required: true
      x-arc-cost-class: destructive
      x-arc-publish: false

  /api/deploy:
    post:
      x-arc-approval-required: true
      x-arc-budget-limit: { calls: 10, cost_usd: 500 }
      x-arc-egress-policy: internal-only
      x-arc-data-volume-limit: 50mb
```

Or equivalently in `arc.yaml`:

```yaml
routes:
  "DELETE /api/patients/{id}":
    approval_required: true
    cost_class: destructive
    publish: false

  "POST /api/deploy":
    approval_required: true
    budget: { calls: 10, cost_usd: 500 }
    egress: internal-only
```

### OpenAPI Caveats

OpenAPI is the strongest current wedge for HTTP/API governance. It is not
ground truth for all runtime behavior.

- specs can be stale, incomplete, or absent
- interface shape does not fully describe hidden side effects
- not every route should become an agent tool 1:1
- curation and override fields are first-class, not edge cases
- non-HTTP surfaces still require protocol adapters or native integrations

API-security platforms already show that spec-first governance can work in
production. ARC's differentiator would be capability-bound session control and
signed receipts, not the mere fact of reading an OpenAPI file.

## 4. Progressive Adoption Ladder

ARC adoption should not require rewriting an application. Four levels,
each adding depth without breaking the previous level.

### Level 0: Reverse Proxy / Sidecar (Zero Code)

Proposed CLI surface:

```bash
arc api protect --upstream http://localhost:8000 --spec openapi.yaml
```

What this does:
- Reads the OpenAPI spec
- Generates a default ARC manifest and policy
- Starts a reverse proxy on port 8443
- Every request gets: session binding, capability check, receipt signing
- Side-effect routes (POST/PUT/DELETE) denied by default without capability token
- GET routes allowed with session-scoped audit receipts

**Friction**: zero code changes. Deploy as a sidecar in K8s or a local proxy.

**Limitations**: best for coarse policy and fast rollout. Body inspection,
auth-context normalization, and framework-level session semantics are weaker
than native middleware unless the proxy is configured to buffer and enrich
requests explicitly.

### Level 1: Framework Middleware (One Import)

Proposed package names:

Python (FastAPI):
```python
from arc_fastapi import ArcMiddleware

app = FastAPI()
app.add_middleware(ArcMiddleware, config="arc.yaml")
```

TypeScript (Elysia):
```typescript
import { arc } from 'arc-elysia'

const app = new Elysia()
  .use(arc({ config: 'arc.yaml' }))
```

Go (net/http):
```go
import "github.com/backbay-labs/arc-go-http"

mux := http.NewServeMux()
handler := arc.Protect(mux, arc.ConfigFile("arc.yaml"))
```

What this adds over Level 0:
- Route-aware identity extraction (JWT, session cookie, API key)
- Per-route capability scoping
- Request/response body inspection for guard evaluation
- Framework-native error responses
- Receipts include authenticated caller identity

### Level 2: Annotations / Decorators (Opt-In Precision)

Proposed decorator / plugin APIs:

Python:
```python
from arc_fastapi import arc_requires, arc_approval, arc_budget

@app.delete("/api/patients/{id}")
@arc_requires(scope="patients:delete", sensitivity="high")
@arc_approval(reason="destructive operation on PHI")
async def delete_patient(id: str):
    ...

@app.post("/api/deploy")
@arc_budget(calls=10, cost_usd=500, ttl_secs=3600)
async def deploy(target: str):
    ...
```

TypeScript:
```typescript
app.delete('/api/patients/:id', {
  arc: { scope: 'patients:delete', approval: true, sensitivity: 'high' }
}, handler)
```

What this adds over Level 1:
- Per-route capability scopes declared in code
- Approval workflows for destructive actions
- Budget enforcement per route
- Data classification tags for guard evaluation
- Egress policy per route

### Level 3: Native Protocol Adapters

For agent-specific protocol surfaces:

- **MCP**: `arc-mcp-adapter` (existing) -- wraps MCP servers
- **A2A**: `arc-a2a-adapter` (existing) -- wraps A2A agents
- **ACP**: `arc-acp-proxy` (existing) -- proxies ACP sessions
- **OpenAI tool_use**: `arc-openai` (proposed) -- intercepts function calling
- **LangChain**: `arc-langchain` (proposed) -- wraps LangChain Tool interface
- **AG-UI**: `arc-ag-ui-proxy` (proposed) -- secures agent-to-user event streams

These are the deepest integrations, providing full protocol-level mediation
with streaming, nested flows, and protocol-specific guard evaluation.

## 5. Shared Core: `arc-http-core`

All substrate adapters share a common request/session/receipt model.

### Normalized Request Model

```rust
/// Protocol-agnostic representation of an HTTP request
/// that ARC needs to evaluate.
pub struct ArcHttpRequest {
    /// Unique request identifier.
    pub request_id: String,
    /// HTTP method.
    pub method: HttpMethod,
    /// Normalized path (template, not instance).
    pub route_pattern: String,
    /// Actual path with parameters resolved.
    pub path: String,
    /// Path parameters extracted by the framework.
    pub path_params: HashMap<String, String>,
    /// Query parameters.
    pub query_params: HashMap<String, String>,
    /// Request headers (sensitive values redacted in receipts).
    pub headers: HashMap<String, String>,
    /// Authenticated caller identity (extracted by substrate).
    pub caller_identity: Option<CallerIdentity>,
    /// Session context (extracted by substrate).
    pub session: Option<SessionContext>,
    /// Content-Type of request body.
    pub content_type: Option<String>,
    /// Request body hash (for receipt binding, not the full body).
    pub body_hash: Option<String>,
}

pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

pub struct CallerIdentity {
    pub agent_id: Option<String>,
    pub user_id: Option<String>,
    pub auth_method: AuthMethod,
    pub token_claims: HashMap<String, serde_json::Value>,
}

pub enum AuthMethod {
    Bearer,
    ApiKey,
    Session,
    Mtls,
    None,
}
```

### Session Model

```rust
pub struct SessionContext {
    pub session_id: String,
    pub started_at: u64,
    pub capability_token: Option<CapabilityToken>,
    pub cumulative_calls: u64,
    pub cumulative_cost_units: u64,
    pub cumulative_bytes: u64,
}
```

### Receipt Model

Every request produces a receipt, regardless of outcome:

```rust
pub struct HttpReceipt {
    pub request_id: String,
    pub route_pattern: String,
    pub method: HttpMethod,
    pub caller_identity_hash: Option<String>,
    pub session_id: Option<String>,
    pub verdict: Verdict,
    pub guard_evidence: Vec<GuardEvidence>,
    pub response_status: u16,
    pub timestamp: u64,
    pub content_hash: String,
    pub signature: Signature,
}
```

## 6. Secure Defaults (Built In, Not Documented Later)

Every substrate adapter ships with these defaults. They cannot be accidentally
disabled.

| Default | Behavior |
|---------|----------|
| **Ephemeral capabilities** | Per-session capability tokens, not static app secrets |
| **Route-scoped credentials** | Capabilities are scoped to specific routes, not the entire API |
| **Signed receipts** | Every allow/deny/cancel/incomplete produces a signed receipt |
| **Request binding** | Receipts bind to session, objective, and approval context |
| **Deny side effects** | POST/PUT/DELETE denied by default unless declared safe |
| **Budget enforcement** | Calls, bytes, cost, and time budgets enforced per session |
| **Approval hooks** | Destructive or high-risk actions require explicit approval |
| **Degraded state handling** | When evidence is incomplete, deny with clear error, never silently pass |

### Guard Classes on HTTP/API Surfaces

Not every "guard" belongs in the same operational bucket.

- **Request / response guards:** deterministic checks on a single request or
  response, such as SSRF controls, schema gating, or output sanitization
- **Session-aware deterministic guards:** deterministic checks that require a
  session journal, such as delegation depth, data-flow limits, or capability
  rotation velocity
- **Signed advisory signals:** behavioral or anomaly observations that should
  start as alerts or escalation inputs, not default hard blocks

The first two classes can fail closed. The third should usually begin as
signed evidence and operator escalation until the signal quality is proven.

## 7. Developer UX: "One Line to Start, Optional Depth Later"

### First Touch (30 seconds)

Proposed CLI / package names:

```bash
# Protect any API with an OpenAPI spec
arc api protect --upstream http://localhost:8000

# Or add one line of middleware
pip install arc-fastapi
# Then: app.add_middleware(ArcMiddleware)
```

### Auto-Discovery

- `arc api protect` reads the OpenAPI spec from `/openapi.json`, `/docs`,
  or a file path
- Generates a default manifest and policy automatically
- Developer only annotates the exceptional cases

### Local Development

- SQLite receipt store (no external dependencies)
- Dev signing keys (auto-generated, clearly marked non-production)
- Human-readable receipt log to stdout
- `arc receipts tail` for live receipt streaming

### Production Swap

- Swap SQLite for hosted receipt store (Postgres, S3, etc.)
- Swap dev keys for HSM-backed signing
- Swap local policy for control plane-managed policy
- **No application code changes required**

## 8. Build Order

The current Rust kernel is an asset. A Rust-only packaging story is an
adoption risk. The sidecar and the first three substrate families are what make
the kernel reachable for most developers.

### Phase 1: Core + Zero-Code Wedge [Shipped]

| Package | Purpose | Crate / CLI |
|---------|---------|-------------|
| `arc-http-core` | Normalized request/session/receipt model | `crates/arc-http-core` |
| `arc-openapi` | Import/generate manifests from OpenAPI specs | `crates/arc-openapi` |
| `arc api protect` | Reverse-proxy / sidecar entrypoint for any HTTP API | `crates/arc-cli` (`arc-api-protect` subcommand) |

### Phase 2: First Substrates (Python, TypeScript, Go) [Shipped]

| Package | Language | Covers | Package Name |
|---------|----------|--------|--------------|
| `arc-sdk-python` / `arc-asgi` | Python | FastAPI, Starlette, Litestar | `sdks/python/arc-sdk-python`, `sdks/python/arc-asgi` |
| `@arc-protocol/node-http` | JS/TS/Bun | Fastify, Express, Hono, Elysia | `sdks/typescript/arc-node-http` |
| `arc-go-http` | Go | net/http, Gin, Echo, Fiber, chi | `sdks/go/arc-go-http` |

### Phase 3: Framework Wrappers (Thin) [Shipped]

| Package | Wraps | Substrate | Package Name |
|---------|-------|-----------|--------------|
| `arc-fastapi` | FastAPI decorator/middleware | `arc-asgi` | `sdks/python/arc-fastapi` |
| `arc-django` | Django/DRF middleware | WSGI-specific | `sdks/python/arc-django` |
| `@arc-protocol/express` | Express middleware | `@arc-protocol/node-http` | `sdks/typescript/arc-express` |
| `@arc-protocol/fastify` | Fastify plugin | `@arc-protocol/node-http` | `sdks/typescript/arc-fastify` |
| `@arc-protocol/elysia` | Elysia lifecycle plugin | `@arc-protocol/node-http` | `sdks/typescript/arc-elysia` |

### Phase 4: Session Journal + Stateful Guards [Shipped]

| Package / Surface | Purpose | Package Name |
|-------------------|---------|--------------|
| `arc-http-session` | Multi-step journal for session-aware deterministic guards | `crates/arc-http-session` |
| v3.4 guard suite | All session-aware deterministic guards (delegation depth, data-flow limits, rotation velocity) | `crates/arc-guards` |
| signed advisory observations | Emit non-blocking behavioral/risk evidence before default hard-blocking | integrated into guard pipeline |

### Phase 5: Remaining Substrates [Shipped]

| Package | Language | Covers | Package Name |
|---------|----------|--------|--------------|
| `arc-tower` | Rust | Axum, Tonic (tower::Layer) | `crates/arc-tower` |
| `arc-spring-boot` | Java/Kotlin | Spring Boot auto-configuration, ArcFilter servlet filter | `sdks/jvm/arc-spring-boot` |
| `ArcMiddleware` | C# | ASP.NET Core middleware | `sdks/dotnet/ArcMiddleware` |

### Phase 6: Protocol Adapters and Deep Integrations (Level 3) [Shipped]

| Package | Protocol | Package Name |
|---------|----------|--------------|
| `arc-openai` | OpenAI function calling interception | `crates/arc-openai` |
| `arc-openapi-mcp-bridge` | OpenAPI-to-MCP bridging with ARC governance | `crates/arc-openapi-mcp-bridge` |
| `arc-a2a-edge` | A2A bidirectional bridging | `crates/arc-a2a-edge` |
| `arc-acp-edge` | ACP bidirectional bridging | `crates/arc-acp-edge` |

## 9. Important Constraint

"Perfectly low friction and secure" is not realistic as a single mode. The
real answer is four modes with one shared kernel:

- **Zero-code path** (reverse proxy) for fast adoption
- **Middleware path** (one import) for real coverage
- **Annotation path** (decorators/config) for least-privilege precision
- **Protocol adapter path** (MCP/A2A/ACP/OpenAI) for agent-native surfaces

All four modes share the same kernel, the same receipt format, the same
capability tokens, and the same guard pipeline. The difference is depth of
context available for policy evaluation.

## 10. How This Relates to Existing Protocol Adapters

The existing MCP, A2A, and ACP adapters are **Level 3** in this framework.
They are the deepest integrations, providing full protocol-level mediation.

The HTTP substrate adapters are **Level 1-2**. They provide the same security
guarantees (capabilities, guards, receipts) but operate at the HTTP layer
rather than the protocol layer.

Both levels feed into the same kernel. A single deployment can run:
- An MCP adapter securing agent tool calls
- An ASGI middleware securing a FastAPI backend
- A reverse proxy securing a legacy Go service

All three produce signed receipts into the same receipt store, evaluated by
the same guard pipeline, governed by the same capability authority.

This is the path that makes ARC a universal security kernel, not just an MCP
gateway.

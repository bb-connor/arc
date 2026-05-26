# AGNTCY ACP Bridge: Engineering Specification

Status: draft, May 2026. Successor (concrete) to doc 02 section 2
("AGNTCY (SLIM, OASF, ACP)"). Companion to doc 00's three-ACPs warning.

## TL;DR

AGNTCY's Agent Connect Protocol is REST/OpenAPI 3.1.1, frozen at v0.2.3
in the archived `agntcy/acp-spec` repository, with agent-as-tool
primitives (`Agent`, `Run`, optional `Thread`). Bridge it as
`chio-bridge-agntcy` (NOT `chio-acp-*`: those slots already hold Zed
Agent Client Protocol at `crates/chio-acp-edge` and
`crates/chio-acp-proxy`). Map ACP `Run` to
`ToolServerConnection::invoke` via the `/runs/wait` endpoint,
`/runs/stream` to `invoke_stream`, interrupts surface inline as a new
`KernelError::ToolInterrupted` variant. Inherit identity from the HTTP
substrate because ACP itself declares no `securitySchemes`. Introduce
`DirectoryProvider` in a new `chio-directory` crate: strictly read-only,
feeds bridge wire-up, never the hot path or capability scope. MVP is
HTTP-only, one ACP server per connection, two or three hand-allowlisted
agents.

## 1. Spec Source and Version

- OpenAPI document:
  [github.com/agntcy/acp-spec/blob/main/openapi.json](https://github.com/agntcy/acp-spec/blob/main/openapi.json),
  rendered at [spec.acp.agntcy.org](https://spec.acp.agntcy.org/).
- Version: `info.version = "0.2.3"`, `openapi = "3.1.1"`.
- Status: archived 2026-04-11. Frozen; AGNTCY's work continues under
  Linux Foundation AComp following the July 2025 donation, no announced
  v1 successor as of May 2026
  ([Zylos protocol survey](https://zylos.ai/research/2026-03-26-agent-interoperability-protocols-mcp-a2a-acp-convergence),
  [4sysops comparison](https://4sysops.com/archives/comparing-ai-protocols-mcp-a2a-agp-agntcy-ibm-acp-zed-acp/)).
  A frozen spec is a feature for a bridge: the wire surface will not
  move under us.
- Reference SDK (Python, informational only):
  [github.com/agntcy/acp-sdk](https://github.com/agntcy/acp-sdk). We
  generate or hand-write a Rust client from the OpenAPI.

## 2. Wire-Level Mapping

ACP has thirty operations across `Agents`, `Threads`, `Thread Runs`,
`Stateless Runs`. The bridge consumes a stable subset.

### 2.1 Discovery: `tool_names()`

Two-step in ACP: `POST /agents/search` returns `Agent[]` with
`agent_id` (UUID) and `metadata`; `GET /agents/{agent_id}/descriptor`
returns `AgentACPDescriptor` with `spec.input/output/interrupts/capabilities`.

`ToolServerConnection::tool_names()`
(`crates/chio-kernel/src/runtime.rs:260`) is synchronous. The bridge
builds an in-memory map at construction time from an operator
allowlist, exposing each agent under its **metadata name slug**
(kebab-case, deduped), not the UUID, to keep capability scopes
human-readable. Side map `tool_name -> agent_uuid` routes invocations.

`/agents/search` is never called on the hot path. Discovery is
operator-curated; refresh is via explicit reload. Section 5's
`DirectoryProvider` is a parallel concept (a directory of ACP
**servers**, each hosting multiple agents).

### 2.2 Invocation: `invoke()`

ACP offers three invocation shapes per run-class:

| Shape      | Stateless                | Stateful                                  |
|------------|--------------------------|-------------------------------------------|
| Async      | `POST /runs`             | `POST /threads/{tid}/runs`                |
| Block/wait | `POST /runs/wait`        | `POST /threads/{tid}/runs/wait`           |
| Stream     | `POST /runs/stream`      | `POST /threads/{tid}/runs/stream`         |

The bridge uses `POST /runs/wait` as the default. Body is
`RunCreateStateless`:

```jsonc
{
  "agent_id": "<resolved-uuid>",
  "input": <arguments verbatim>,
  "on_completion": "delete",
  "metadata": { "chio_request_id": "<RequestId>", "chio_capability_id": "<CapabilityId>" }
}
```

Server returns `Run` with terminal `status`
(`success`|`error`|`timeout`|`interrupted`) plus `RunOutput` (oneOf
`RunResult`|`RunInterrupt`|`RunError`). Mapping: `success` +
`RunResult.values` -> `Ok(values)`; `error` -> section 4; `timeout`
-> transient; `interrupted` -> 2.4. Webhook unset in MVP. Threads
unused.

### 2.3 Streaming: `invoke_stream()`

SSE on `POST /runs/stream`. `stream_mode` is `values` (full snapshot
per chunk) or `custom`. The bridge advertises `invoke_stream` only when
the descriptor declares `capabilities.streaming = true`; otherwise it
returns `Ok(None)` and the kernel falls back to `invoke()`.

Each SSE event maps to one `ToolCallChunk` in
`ToolServerStreamResult::Complete(ToolCallStream { chunks })`
(`crates/chio-kernel/src/runtime.rs:117,136`). Terminal SSE event
(`type: result|error`) closes the stream; mid-stream disconnect emits
`Incomplete { reason: "sse-disconnect" }`.

### 2.4 Events / Interrupts: `drain_events()`

ACP's `interrupted` status is MCP-elicitation-like: the agent has
paused on caller input via `RunInterrupt.interrupt` (typed against
`AgentACPDescriptor.spec.interrupts`). The bridge surfaces interrupts
inline in the invoke return as `KernelError::ToolInterrupted
{ interrupt_id, payload }` (new variant requiring kernel-team
coordination). NOT through `drain_events`: interrupts are synchronous
with a specific `run_id` and resumption requires
`POST /threads/{tid}/runs/{run_id}`.

`drain_events()` (`crates/chio-kernel/src/runtime.rs:306`) returns an
empty vec in MVP. A future revision could emit `ToolsListChanged` when
`/agents/search` diverges from cache, but only under operator opt-in
(auto-import widens trust).

### 2.5 Out of MVP Scope

Threads (`/threads/*`), background runs without wait, run search, copy,
history, delete, cancel. Threads are stateful and collide with Chio's
per-request mediation. Cancel arrives later if the bridge starts
honoring tokio cancellation tokens.

## 3. Identity Mapping

The ACP OpenAPI document declares `components.securitySchemes = {}` and
no global `security`. ACP defers authentication entirely to the
deployer, consistent with AGNTCY pairing ACP with a separate Identity
Service that issues verifiable credentials in standard HTTP headers.

The bridge therefore inherits the HTTP substrate's auth and constructs
`CallerIdentity` (`crates/chio-http-core/src/identity.rs:44`). Three
modes for MVP:

1. **Bearer** (default). Operator supplies a token source (file, env,
   `dyn TokenProvider`). Sets `Authorization: Bearer <token>`. Records
   `AuthMethod::Bearer { token_hash: sha256(token) }`.
2. **mTLS**. `reqwest` client built with client cert + key. Records
   `AuthMethod::MtlsCertificate { subject_dn, fingerprint }`.
3. **API key**. `X-API-Key: <key>`. Records
   `AuthMethod::ApiKey { key_name, key_hash: sha256(key) }`.

`verified = true` only when (a) mTLS bound the connection, or (b)
bearer was a JWT and Chio's existing JWT verifier accepted it (out of
scope for v1). `agent_id` is set to the ACP `Agent.agent_id` UUID for
provenance. `tenant` is operator-supplied.

**Canonical AGNTCY peer -> Chio caller subject rule:**

> Subject = `did:web:<acp-host>[:port]:agents:<agent-id-uuid>` when no
> AGNTCY identity credential is bound. Subject = the VC's `sub` claim
> (typically a `did:web` or `did:key`) when AGNTCY's Identity Service
> issued a credential and the kernel verifies it. The bridge never
> mints a `did:chio` for an upstream peer: `did:chio` is reserved for
> principals the local kernel attests.

## 4. Error Model

Sources of failure:

- HTTP transport (connect, TLS, timeout).
- HTTP status codes: 404, 409, 422, 5xx. Body is `ErrorResponse` which
  the spec defines as a bare `string`; bridge stores raw and does not
  parse.
- `RunStatus = error` with structured `RunError { errcode: int,
  description: string }`. `errcode` is agent-defined (not enumerated
  by ACP), treated as opaque metadata.
- `RunStatus = timeout` (terminal, retry-eligible by idempotency).
- `RunStatus = interrupted` (not an error: agent waits on input).

Mapping to `KernelError`
(`crates/chio-kernel/src/kernel/mod.rs:473`):

| ACP failure                              | Chio mapping                                                       | Retry |
|------------------------------------------|--------------------------------------------------------------------|-------|
| Transport: connect/TLS/io                | `KernelError::ToolServer { transient: true }` (wrap or new variant)| yes   |
| HTTP 5xx                                 | `KernelError::ToolServer { transient: true }`                      | yes   |
| HTTP 408, 504, `RunStatus=timeout`       | `KernelError::ToolServer { transient: true, reason: "timeout" }`   | yes   |
| HTTP 429                                 | `KernelError::ToolServer { transient: true }` + Retry-After        | yes   |
| HTTP 401, 403                            | `KernelError::ToolServerUnauthorized` (new) or `UntrustedIssuer`   | no    |
| HTTP 404 on `agent_id`                   | `KernelError::OutOfScope { tool, server }`                         | no    |
| HTTP 422 validation                      | `KernelError::InvalidConstraint(<acp-msg>)`                        | no    |
| `RunError { errcode, description }`      | `KernelError::ToolServer { transient: false, code: errcode, msg }` | no    |
| `RunInterrupt`                           | `KernelError::ToolInterrupted { interrupt_id, payload }` (new)     | n/a   |

Retry policy: exponential backoff with jitter, max 3 attempts, only on
`transient: true`. The bridge generates a `chio_request_id` UUID in
`metadata` for server-side idempotency.

## 5. `DirectoryProvider` Trait

Doc 02 introduced the sketch. Concrete shape below.

### 5.1 Crate Location

New crate `chio-directory`, distinct from `chio-federation` (which is
heavyweight: relay peering, quarantine, observability). `chio-directory`
is a leaf with no kernel dependency, depending only on
`chio-core-types` for ID/key types. AGNTCY-specific impls live in
`chio-bridge-agntcy`. NANDA impls live in a future
`chio-directory-nanda`. OASF in a future `chio-directory-oasf`.

### 5.2 Trait Surface

```rust
// crates/chio-directory/src/lib.rs
use async_trait::async_trait;

#[async_trait]
pub trait DirectoryProvider: Send + Sync {
    /// Stable name for receipts/diagnostics ("agntcy-static", "nanda-https").
    fn name(&self) -> &str;

    /// Resolve a canonical identifier. Closed-world: returns
    /// `Err(DirError::NotAllowlisted)` for ids the operator did not
    /// pin. No network call without operator consent.
    async fn lookup(&self, id: &str) -> Result<DirectoryRecord, DirError>;

    /// Enumerate the full allowlisted set. Used at bridge wire-up,
    /// never on the hot path.
    async fn allowlisted(&self) -> Result<Vec<DirectoryRecord>, DirError>;

    /// Refresh the cache. Returns wall-clock of new snapshot.
    /// Implementations with no refresh (static) return last_loaded_at.
    async fn refresh(&self) -> Result<u64, DirError>;
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DirectoryRecord {
    /// Canonical identifier. did:web, did:key, did:chio.
    pub canonical_id: String,
    pub endpoints: Vec<EndpointHint>,
    /// Advisory capabilities from the directory.
    /// Structurally separate from CapabilityToken::scope. Never widens
    /// local trust. See 5.5.
    pub advisory_capabilities: Vec<String>,
    /// Verbatim upstream-signed bytes (AGNTCY VC, NANDA AgentFacts JWS).
    pub signed_blob: Vec<u8>,
    /// Identifier of the directory that signed signed_blob.
    pub upstream_signer: String,
    pub fetched_at: u64,
    pub blob_sha256: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EndpointHint {
    pub protocol: String,            // "acp"|"mcp"|"a2a"|"https"
    pub url: String,
    pub transport: Option<String>,   // "https"|"mtls"|"slim"
}

#[derive(Debug, thiserror::Error)]
pub enum DirError {
    #[error("identifier not in operator allowlist: {0}")]
    NotAllowlisted(String),
    #[error("upstream signature invalid: {0}")]
    BadSignature(String),
    #[error("upstream io: {0}")]
    Io(String),
    #[error("upstream returned malformed record: {0}")]
    Malformed(String),
}
```

### 5.3 Signature Verification

AGNTCY uses W3C Verifiable Credentials for agent records. The provider
verifies the VC's proof at `refresh` time and rejects bad ones.
Verification keys come from the operator's trust anchor file (issuer
DIDs to public keys), never auto-resolved. Closed-world stays
closed-world.

For the AGNTCY-static MVP, `signed_blob` = canonical JSON of the
operator's pinned entry, `upstream_signer = "operator"`: no remote
signature, the operator IS the trust anchor.

### 5.4 Refresh / Caching

Default refresh interval: zero (operator triggers via control-plane
reload). Optional `AutoRefreshDirectoryProvider<P>` wraps any provider
with a tokio interval. The kernel never refreshes as a side effect of
`invoke()`.

### 5.5 Non-Goal Boundary (hard rule)

`advisory_capabilities` is purely informational. The bridge MUST NOT
pass these strings into `CapabilityToken::scope`
(`crates/chio-core-types/src/capability.rs`), into Cedar policy, into
manifest-driven scope inference, or anywhere that affects an
authorization decision. They exist for operator diagnostics and audit
comparison only. Enforce with a custom clippy lint blocking conversion
from advisory `Vec<String>` to scope types within
`chio-bridge-agntcy` and `chio-directory`.

## 6. Receipt Fields

`ChioReceiptBody` (`crates/chio-core-types/src/receipt.rs:159`) carries
`metadata: Option<serde_json::Value>`. The bridge populates a
namespaced sub-object:

```jsonc
{
  "agntcy_acp": {
    "spec_version": "0.2.3",
    "server_url_host": "agent.example.com",
    "agent_id": "<uuid>",
    "agent_name": "research-assistant",
    "run_id": "<uuid>",
    "thread_id": null,
    "run_status": "success",
    "directory_entry": {
      "provider": "agntcy-static",
      "canonical_id": "did:web:agent.example.com:agents:<uuid>",
      "blob_sha256": "<hex>",
      "upstream_signer": "operator"
    },
    "hop_count": 1
  }
}
```

Namespacing under `agntcy_acp` preserves byte-stable receipts for
non-AGNTCY callers and lets the bridge evolve its metadata without
bumping the receipt schema. `tool_server` (top-level) is the
operator-chosen ACP server ID (e.g. `agntcy:research-corp`),
`tool_name` is the agent slug. `content_hash` covers canonical JSON of
the input arguments AND the AGNTCY metadata block, so receipt
verification anchors the peer ID and directory snapshot trusted at
invoke time. `trust_level` stays `Mediated`.

## 7. MVP Scope

ACP methods: `POST /runs/wait`, `POST /runs/stream` (gated by
descriptor capability), `GET /agents/{agent_id}/descriptor` (startup).
Nothing else.

Representative agents for integration validation:

1. Research/search agent: string input, structured JSON
   `RunResult.values`; non-streaming.
2. Code-generation agent: streaming `RunResult` with incremental
   chunks; tests `invoke_stream`.
3. Workflow agent with `RunInterrupt` for human approval: tests
   `KernelError::ToolInterrupted` plumbing (MVP can surface as hard
   error; caller retries).

Stand these up from AGNTCY example agents or two LangGraph reference
agents behind ACP.

Config knobs:

```toml
[bridge.agntcy]
spec_version = "0.2.3"
server_id = "agntcy:research"
endpoint = "https://agent.example.com/acp"
auth = { kind = "bearer", token_file = "/run/secrets/acp-token" }
request_timeout_ms = 30_000
retry_max_attempts = 3
retry_backoff_ms = 250
streaming = true

[[bridge.agntcy.agents]]
agent_id = "11111111-1111-1111-1111-111111111111"
expose_as = "research-assistant"
allow_streaming = true

[bridge.agntcy.directory]
provider = "static"
```

Fail-closed: invalid config rejects at load time; unknown agents
return `KernelError::OutOfScope` without an HTTP call.

## 8. Crate Skeleton

### 8.1 Naming

`chio-bridge-agntcy`. Rejected alternatives:

- `chio-acp-bridge` / `chio-acp-client`: collides with existing
  `chio-acp-edge` / `chio-acp-proxy`, which implement Zed's Agent
  Client Protocol (verified at `crates/chio-acp-edge/src/lib.rs:1-20`).
  The `chio-acp-*` namespace is taken and means a different protocol.
- `chio-agntcy-acp`: breaks the `chio-bridge-*` prefix convention used
  by other tool-server bridges.

### 8.2 Cargo.toml

```toml
[package]
name = "chio-bridge-agntcy"
description = "Bridge that exposes AGNTCY Agent Connect Protocol agents as Chio tool servers"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
publish = false

[dependencies]
async-trait = { workspace = true }
chio-core = { package = "chio-core-types", path = "../chio-core-types" }
chio-directory = { path = "../chio-directory" }
chio-http-core = { path = "../chio-http-core" }
chio-kernel = { path = "../chio-kernel" }
eventsource-stream = "0.2"
reqwest = { workspace = true, features = ["json", "stream", "rustls-tls"] }
rustls = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
sha2 = { workspace = true }
thiserror = { workspace = true }
tokio = { workspace = true, features = ["macros", "rt"] }
tokio-stream = "0.1"
tracing = { workspace = true }
url = "2"
uuid = { version = "1", features = ["v4", "v7"] }

[lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
```

### 8.3 File Layout

```
crates/chio-bridge-agntcy/
  Cargo.toml
  src/
    lib.rs        # AgntcyAcpBridge entry, re-exports
    client.rs     # ReqwestAcpClient: HTTP client
    config.rs     # AgntcyAcpConfig, AgentBinding, AuthConfig
    connection.rs # impl ToolServerConnection
    descriptor.rs # AgentACPDescriptor + capability gating
    directory.rs  # StaticAgntcyDirectoryProvider
    error.rs      # AgntcyAcpError, KernelError mapping
    identity.rs   # peer-ID -> CallerIdentity
    receipt.rs    # build metadata.agntcy_acp block
    sse.rs        # SSE -> ToolCallChunk
  tests/
    integration_invoke.rs
    integration_stream.rs
```

### 8.4 Public API Sketch

```rust
pub use config::{AgntcyAcpConfig, AgentBinding, AuthConfig};
pub use directory::StaticAgntcyDirectoryProvider;
pub use error::AgntcyAcpError;

pub struct AgntcyAcpBridge { /* opaque */ }

impl AgntcyAcpBridge {
    /// Build from validated config. Eagerly fetches each agent's
    /// descriptor; rejects on missing/incompatible agents.
    pub async fn new(cfg: AgntcyAcpConfig) -> Result<Self, AgntcyAcpError>;

    /// Reload directory and re-fetch descriptors. Live-safe.
    pub async fn refresh(&self) -> Result<(), AgntcyAcpError>;
}

#[async_trait::async_trait]
impl chio_kernel::runtime::ToolServerConnection for AgntcyAcpBridge {
    fn server_id(&self) -> &str;
    fn tool_names(&self) -> Vec<String>;
    async fn invoke(&self, tool_name: &str, arguments: serde_json::Value,
                    bridge: Option<&mut dyn chio_kernel::runtime::NestedFlowBridge>)
        -> Result<serde_json::Value, chio_kernel::KernelError>;
    async fn invoke_stream(&self, tool_name: &str, arguments: serde_json::Value,
                           bridge: Option<&mut dyn chio_kernel::runtime::NestedFlowBridge>)
        -> Result<Option<chio_kernel::runtime::ToolServerStreamResult>,
                  chio_kernel::KernelError>;
}
```

The kernel host registers an `AgntcyAcpBridge` in its tool-server
registry like any other `ToolServerConnection`. No new kernel concept.

## 9. Risks and Watch-outs

- **Spec is frozen, but not normative for new AGNTCY work.** If LF-AComp
  produces an incompatible "ACP v2", we need a second bridge crate
  (`chio-bridge-acomp`), not an evolution of this one. `spec_version`
  is a load-time pin to make that boundary visible.
- **Empty `securitySchemes`.** Every ACP server is an auth snowflake.
  The bridge MUST refuse non-HTTPS endpoints in production builds
  (allow `http://` only behind a debug feature flag), and SHOULD warn
  when bearer is paired with non-mTLS on an external endpoint.
- **String-typed `ErrorResponse` and opaque `errcode`.** We cannot
  classify ACP errors precisely. The mapping in section 4 leans on
  HTTP status (well-defined) and treats `RunError` as permanent by
  default. False-negative retry on a transient agent fault is
  acceptable; false-positive retry on a side-effect-causing error is
  not.
- **Interrupts as a back-channel for prompt-injection.** A malicious
  agent could return `RunInterrupt` with a payload designed to elicit
  sensitive data. Bridge MUST size- and shape-check
  `RunInterrupt.interrupt` against the agent's declared
  `spec.interrupts` schema and reject payloads whose type is not
  declared.
- **`metadata` field leakage.** ACP's free-form `metadata` round-trips
  through the agent. We use it for `chio_request_id`. If the agent
  echoes metadata into `RunResult.values`, the kernel could re-ingest
  its own IDs. Treat all `RunResult.values` as untrusted input.
- **Directory entry vs capability conflation drift.** Easy footgun:
  someone adds a "convenience" helper that turns
  `DirectoryRecord.advisory_capabilities` into capability scope.
  Encode the rule via custom clippy lint and a compile-time doc-test
  asserting the conversion does not exist.
- **AGNTCY identity service stability.** Webex's production deployment
  uses AGNTCY directory and identity for MCP server registration
  ([Webex blog](https://developer.webex.com/blog/webex-leverages-agntcy-directory-and-identity-for-agentic-apps)),
  but ACP is not yet called out as in production. If AGNTCY changes
  its VC format or moves to A2A's VC profile, the identity rule
  shifts. Section 3 isolates the rule in a single function
  (`map_peer_to_caller_identity`) to limit blast radius.
- **OASF as alternative discovery.** OASF (OCI-based agent records) is
  the AGNTCY long-term directory format. MVP uses static config; a
  `chio-directory-oasf` impl is the natural next step. The trait in
  section 5 is OASF-ready (`signed_blob` accommodates an OASF JWS),
  but we do not implement OASF in v1.
- **SLIM transport not addressed.** Per doc 02 phasing, SLIM is Phase
  3. Operators wanting ACP-over-SLIM before then can deploy an
  HTTP-to-SLIM proxy in front of the bridge. The bridge does not learn
  about SLIM.

## Appendix: Citation Map

- ACP OpenAPI:
  [github.com/agntcy/acp-spec/blob/main/openapi.json](https://github.com/agntcy/acp-spec/blob/main/openapi.json),
  rendered at [spec.acp.agntcy.org](https://spec.acp.agntcy.org/).
- ACP SDK reference: [github.com/agntcy/acp-sdk](https://github.com/agntcy/acp-sdk).
- AGNTCY / AComp donation context:
  [agntcy.org](https://agntcy.org/),
  [Zylos protocol survey](https://zylos.ai/research/2026-03-26-agent-interoperability-protocols-mcp-a2a-acp-convergence),
  [4sysops comparison](https://4sysops.com/archives/comparing-ai-protocols-mcp-a2a-agp-agntcy-ibm-acp-zed-acp/).
- Webex production reference:
  [developer.webex.com blog](https://developer.webex.com/blog/webex-leverages-agntcy-directory-and-identity-for-agentic-apps).
- Chio code references:
  `crates/chio-kernel/src/runtime.rs:255` (ToolServerConnection),
  `crates/chio-kernel/src/runtime.rs:136` (ToolServerStreamResult),
  `crates/chio-kernel/src/kernel/mod.rs:473` (KernelError),
  `crates/chio-http-core/src/identity.rs:44` (CallerIdentity),
  `crates/chio-core-types/src/receipt.rs:159` (ChioReceiptBody),
  `crates/chio-acp-edge/src/lib.rs:1` (Zed ACP, namespace collision).

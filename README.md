<p align="center">
  <img src="assets/hero.png" alt="PACT" width="900" />
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/MSRV-1.93-orange?style=flat-square&logo=rust" alt="MSRV: 1.93">
  <img src="https://img.shields.io/badge/status-production--candidate-yellow?style=flat-square" alt="Status: Production candidate">
</p>

<p align="center">
  A protocol and runtime for capability-scoped agent tool access.
</p>

<h1 align="center">PACT</h1>

<p align="center">
  <strong>Provable Agent Capability Transport</strong><br/>
  <em>Capability-scoped tool access with signed receipts.</em>
</p>

<p align="center">
  Capability tokens
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  Fail-closed kernel mediation
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  Guard pipeline enforcement
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  Signed audit receipts
</p>

<p align="center">
  <a href="#the-problem">Problem</a>
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <a href="#what-pact-is-in-this-repo">What It Is</a>
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <a href="#quick-start">Quick Start</a>
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <a href="#workspace-layout">Workspace</a>
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <a href="spec/PROTOCOL.md">Protocol v2</a>
</p>

---

## The Problem

MCP gives agents broad, direct access to tool servers. That works for demos, but it leaves real security questions unanswered:

- what exactly was this agent allowed to call?
- where is the privilege boundary?
- what proves a deny or an allow actually happened?
- how do you attenuate or revoke access without relying on ambient trust?

PACT is an attempt to answer those questions with capability tokens, kernel mediation, policy guards, and signed receipts.

## What PACT Is In This Repo

PACT is a production-candidate Rust workspace for capability-based tool access
in agent systems.

The repository currently includes:

- signed capability and receipt types
- a runtime kernel that validates capabilities and evaluates guards
- a CLI for single-call checks, agent subprocess mediation, and MCP edge serving
- a library crate for adapting MCP servers into PACT tool servers and exposing a secured MCP edge
- a trust-control service for authority, revocation, receipts, budgets, federation, and certification state
- portable-trust artifacts including `did:pact`, Agent Passport, verifier policies, and federated evidence export/import
- a thin A2A v1.0.0 adapter with fail-closed auth negotiation and durable task correlation
- release-qualified TypeScript, Python, and Go SDK surfaces for the current hosted session contract
- unit, integration, end-to-end, and differential tests

## Status

This is a `v2.3` production candidate for the surface documented in
[docs/release/RELEASE_CANDIDATE.md](docs/release/RELEASE_CANDIDATE.md).

The protocol document in [spec/PROTOCOL.md](spec/PROTOCOL.md) now describes the
shipped repository profile rather than a broader aspirational draft. The README
focuses on what is implemented here today and calls out explicit boundaries
when they matter.

## What PACT Does

PACT puts a mediation layer between an agent and its tools:

1. The agent presents a signed capability token for a tool call.
2. The kernel validates scope, time bounds, and revocation state.
3. The kernel runs policy guards before the tool executes.
4. The kernel returns the tool result plus a signed receipt.

In this workspace, those pieces are implemented as Rust crates, release
scripts, and operator docs rather than a turnkey managed service.

## What Is Implemented Today

- `pact-core`: capability tokens, canonical JSON helpers, signing, hashing, Merkle helpers, receipts, and wire message types including streamed tool chunk frames
- `pact-kernel`: capability validation, guard execution, tool dispatch traits, revocation store, receipt creation, explicit terminal state tracking, and a length-prefixed stdio transport
- `pact-guards`: guard implementations for forbidden paths, shell commands, egress allowlists, path allowlists, MCP tool filtering, secret leak detection, and patch integrity checks
- `pact-cli`: `pact check`, `pact run`, `pact mcp serve`, `pact mcp serve-http`, `pact trust serve`, portable-trust commands, and certification registry administration
- `pact-manifest`: tool manifest types plus signing and verification
- `pact-mcp-adapter`: MCP wrapping, transport, and edge support for tool flows plus first-class resource and prompt session handling in the in-process edge
- `pact-a2a-adapter`: A2A v1.0.0 discovery, mediation, task follow-up, push-notification config CRUD, and fail-closed auth negotiation
- `pact-did`, `pact-credentials`, and `pact-reputation`: self-certifying identity, portable trust, verifier policy, presentation, and reputation scoring layers
- `examples/hello-tool`: maintained native-service example using `NativePactServiceBuilder` for a tool, resource, prompt, manifest signing flow, and manifest pricing metadata
- `formal/diff-tests`: differential tests for scope semantics

## What Is Not Finished Yet

- multi-region or consensus-style trust replication beyond the current deterministic HA leader/follower design
- public certification marketplace discovery
- automatic SCIM lifecycle management and broader enterprise federation workflows beyond the current provider-admin path
- synthetic cross-issuer passport trust aggregation
- broader native authoring ergonomics beyond the first `NativePactServiceBuilder` surface and maintained example
- performance-first tuning beyond the documented defaults and qualification gates
- theorem-prover completion for every protocol claim

One important detail: the guard crate contains seven guard implementations, and the current CLI YAML loader now wires all seven:

- forbidden path
- path allowlist
- shell command
- egress allowlist
- MCP tool filtering
- secret leak detection
- patch integrity

## Policy Authoring

For new policy authoring, use HushSpec.

- start with `examples/policies/canonical-hushspec.yaml`
- use `examples/policies/hushspec-guard-heavy.yaml` when you need the full shipped guard surface
- treat the legacy PACT YAML format as a compatibility input for existing setups, not the default path for new policy work

Both inputs compile into the same runtime policy materialization inside `pact-cli`; the difference is product guidance, not a split execution path.

For wrapped-MCP-to-native migration and the first higher-level native service surface, see [docs/NATIVE_ADOPTION_GUIDE.md](docs/NATIVE_ADOPTION_GUIDE.md).
For advertised tool pricing and pre-invocation budget planning, see [docs/TOOL_PRICING_GUIDE.md](docs/TOOL_PRICING_GUIDE.md).
For portable trust and federation, see [docs/AGENT_PASSPORT_GUIDE.md](docs/AGENT_PASSPORT_GUIDE.md) and [docs/IDENTITY_FEDERATION_GUIDE.md](docs/IDENTITY_FEDERATION_GUIDE.md).
For A2A mediation, see [docs/A2A_ADAPTER_GUIDE.md](docs/A2A_ADAPTER_GUIDE.md).
For certification, see [docs/PACT_CERTIFY_GUIDE.md](docs/PACT_CERTIFY_GUIDE.md).

## Release Qualification

The release-proof documents for the current production-candidate surface are:

- [docs/release/RELEASE_CANDIDATE.md](docs/release/RELEASE_CANDIDATE.md)
- [docs/release/QUALIFICATION.md](docs/release/QUALIFICATION.md)
- [docs/release/RELEASE_AUDIT.md](docs/release/RELEASE_AUDIT.md)
- [docs/release/OPERATIONS_RUNBOOK.md](docs/release/OPERATIONS_RUNBOOK.md)
- [docs/release/OBSERVABILITY.md](docs/release/OBSERVABILITY.md)
- [docs/release/GA_CHECKLIST.md](docs/release/GA_CHECKLIST.md)
- [docs/release/RISK_REGISTER.md](docs/release/RISK_REGISTER.md)

For ordinary workspace validation run:

```bash
./scripts/ci-workspace.sh
```

For release-candidate qualification run:

```bash
./scripts/qualify-release.sh
```

## Requirements

- Rust 1.93 or newer
- `node`
- `python3`
- `go`

## Quick Start

Build the workspace:

```bash
cargo build --workspace
```

Run the test suite:

```bash
cargo test --workspace
```

Try the single-shot policy checker:

```bash
cargo run -p pact-cli -- check \
  --policy examples/policies/default.yaml \
  --tool bash \
  --params '{"command":"rm -rf /"}'
```

Expected result:

```text
verdict:    DENY
tool:       bash
server:     *
```

Run the example tool server:

```bash
cargo run -p hello-tool
```

## CLI

The CLI surface is intentionally small right now.

### `pact check`

Evaluate one tool call against a policy without spawning an agent:

```bash
pact check --policy <policy.yaml> --tool <tool-name> [--server <server-id>] [--params '<json>']
```

Notes:

- exits `0` on allow
- exits `2` on deny
- exits `1` on CLI or runtime error
- `--json` prints machine-readable output
- `--receipt-db <path>` persists signed receipts
- `--revocation-db <path>` enables durable revocation enforcement for capability checks

### `pact run`

Spawn a subprocess and mediate its tool calls through the kernel:

```bash
pact run --policy <policy.yaml> <command>...
```

Important: `<command>` must be a process that speaks PACT's length-prefixed JSON message protocol over stdin/stdout. This is not a generic "run any command in a sandbox" wrapper.

At startup, the kernel issues a default capability from the policy and sends it to the child process. After that, tool requests and responses flow over the stdio transport.

The native PACT wire now supports chunked tool output for stream-capable tool servers. The agent receives one or more `tool_call_chunk` frames followed by a terminal `tool_call_response` whose status is `stream_complete`, `incomplete`, `cancelled`, or the existing single-value success/error form.

### `pact mcp serve`

Wrap an MCP server subprocess with the PACT kernel and expose a stock MCP-compatible edge over stdio:

```bash
pact mcp serve --policy <policy.yaml> --server-id <server-id> <command>...
```

This command:

- spawns the wrapped MCP server as a subprocess
- generates a synthetic PACT manifest from the server's `tools/list`
- issues the session's default capabilities from policy
- serves a stock MCP edge over stdio for tools, resources, prompts, completion, and logging

When the wrapped MCP server advertises resources and prompts, `pact mcp serve` now registers adapter-backed providers with the kernel and exposes:

- `tools/list` and `tools/call`
- `resources/list`, `resources/templates/list`, and `resources/read`
- `prompts/list` and `prompts/get`
- `completion/complete` when the wrapped server advertises completions
- `logging/setLevel` plus edge-originated `notifications/message`

When the MCP client advertises the `roots`, `sampling`, or `elicitation` capabilities, the edge now refreshes a session root snapshot after initialization and on `notifications/roots/list_changed`, and it can broker nested `roots/list`, `sampling/createMessage`, and both form-mode and URL-mode `elicitation/create` requests through the kernel with parent-child lineage and the same fail-closed policy checks used by the direct edge path.

If the MCP client includes `_meta.progressToken` on `tools/call`, the edge emits `notifications/progress` while active nested `roots/list`, `sampling/createMessage`, and `elicitation/create` work is in flight. If the client sends `notifications/cancelled` for one of those nested requests, or cancels the active parent `tools/call` while that nested work is running, the edge fails closed and returns a denied, receipted tool outcome.

Every exposed surface is filtered by the active capability set. Tool denials return MCP tool errors. Resource, prompt, and completion requests fail closed when the policy does not grant access.

When the wrapped MCP server advertises `resources.subscribe` or `resources.listChanged`, `pact mcp serve` now exposes those capability bits on the outer edge as well. Upstream `notifications/resources/updated` and `notifications/resources/list_changed` are forwarded through the kernel, and only subscribed URIs are emitted to the outer client. That now works both during active wrapped `tools/call` execution and during idle/background periods on the wrapped stdio transport.

Wrapped stdio servers can also forward `notifications/tools/list_changed` and `notifications/prompts/list_changed` during active requests and while the outer client is idle. For tool execution itself, the kernel now records explicit `Completed`, `Cancelled`, and `Incomplete` terminal states and signs matching receipts, so a wrapped server stream dropping mid-call no longer collapses into an untyped generic failure internally.

Receipts now carry a `content_hash` for every decision. When a tool returns streamed output, the receipt also records chunk-hash metadata, chunk counts, and total canonical bytes. The kernel enforces configured stream duration and total-byte limits and turns limit breaches into explicit incomplete outcomes with truncated partial output preserved in the receipt path.

Wrapped MCP `tools/call` requests can now be cancelled even when no nested `roots/list` or `sampling/createMessage` request is active. The adapter polls for top-level client cancellation while an upstream wrapped tool call is in flight, forwards `notifications/cancelled` to the wrapped server, and returns a receipted cancelled outcome immediately.

Native streamed tool output on the PACT wire now has an opt-in MCP-edge bridge. If the client negotiates `capabilities.experimental.pactToolStreaming.toolCallChunkNotifications`, the edge emits `notifications/pact/tool_call_chunk` before the final `tools/call` result. Clients that do not negotiate that extension still get a collapsed final tool result.

The MCP edge now also exposes a standard task-oriented execution slice for native PACT-backed tools. `tools/call` accepts a standard MCP `task` field, `tools/list` advertises `execution.taskSupport: "optional"`, and the edge serves `tasks/list`, `tasks/get`, `tasks/result`, and `tasks/cancel`. `tasks/result` reuses the stream bridge, so negotiated clients still receive `notifications/pact/tool_call_chunk` before the final task result when the underlying tool streams.

That task slice is now materially more mature than the first cut. Queued work no longer depends only on idle polls: both the outer edge and wrapped stdio bridge now service bounded background work on ordinary request/notification turns as well, so tasks can still complete under sustained client or upstream traffic. The edge can emit optional `notifications/tasks/status`, and task-associated nested sampling/progress/logging messages now carry standard related-task metadata. The wrapped stdio bridge now supports task-augmented `sampling/createMessage`, form-mode `elicitation/create`, and URL-mode `elicitation/create` for upstream servers. Direct tool servers can now also return standard `-32042` URL-required MCP errors and emit late async events through a kernel-drained event source instead of depending on a still-live request-local bridge.

Nested child requests are now auditable too. The kernel signs child-request receipts for `roots/list`, `sampling/createMessage`, and `elicitation/create`, recording parent lineage, operation kind, terminal state, and an outcome hash. Batching also improved: both the outer edge task runner and the wrapped nested-task runtime now advance multiple queued tasks per service pass instead of exactly one. The remaining work is broader fully concurrent ownership across transports rather than the earlier idle-only starvation problem.

Accepted URL-mode elicitations now become edge-owned pending interactions instead of request-local scratch state. Wrapped stdio servers can later send `notifications/elicitation/complete` during active work or idle periods, and the edge forwards those notifications only for elicitation IDs it actually brokered. That closes the basic URL-mode lifecycle on the wrapped stdio path and is the first real async-ownership slice beyond a single request loop.

### `pact mcp serve-http`

Expose the same kernel-backed MCP edge over Streamable HTTP:

```bash
pact mcp serve-http \
  --policy <policy.yaml> \
  --server-id <server-id> \
  --listen 127.0.0.1:8931 \
  --auth-jwt-public-key <issuer-public-key-hex> \
  --auth-jwt-issuer <issuer> \
  --auth-jwt-audience <audience> \
  --admin-token <admin-token> \
  <command>...
```

For a single hosted node, use either `--authority-db` for local persisted shared issuance state or `--authority-seed-file` for a single-node persisted issuer, not both.

For a distributed deployment, point hosted nodes at a shared trust-control service instead:

```bash
pact \
  --control-url http://127.0.0.1:8940,http://127.0.0.1:8941 \
  --control-token <control-token> \
  mcp serve-http \
  --policy <policy.yaml> \
  --server-id <server-id> \
  --listen 127.0.0.1:8931 \
  --auth-server-seed-file <auth-seed-file> \
  --auth-subject operator \
  <command>...
```

For admission, use exactly one of:

- `--auth-token` for bootstrap static bearer mode
- `--auth-jwt-public-key` for externally issued signed JWT bearer mode
- `--auth-server-seed-file` for a colocated hosted OAuth authorization server that can issue JWTs itself

This first remote slice now supports:

- authenticated session admission with either a static bearer token or an Ed25519-signed JWT bearer token
- `MCP-Session-Id` issuance and per-session edge ownership
- multiple concurrent remote sessions
- POST-based Streamable HTTP request handling with JSON request bodies and SSE responses
- remote nested `sampling/createMessage` flows over POST plus follow-up POSTed client responses
- stricter transport validation for `Accept: application/json, text/event-stream` and `Content-Type: application/json`
- session creation only after a successful `initialize` response
- normalized session auth context bound to the kernel session, separate from capability authorization
- OAuth-style session identity capture from JWT `iss` / `sub` / `aud` / scope claims when JWT mode is enabled
- follow-up requests must stay consistent with the authenticated session identity instead of presenting an unrelated bearer token
- JWT mode now serves protected-resource metadata at `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp`
- JWT-mode `401 Unauthorized` responses now advertise `resource_metadata` and challenged scopes through `WWW-Authenticate`
- when a JWT issuer is colocated with the hosted edge, the edge now serves a real hosted OAuth authorization server with `GET/POST /oauth/authorize`, `POST /oauth/token`, and `GET /oauth/jwks.json`
- the hosted auth server supports authorization code with `S256` PKCE plus `urn:ietf:params:oauth:grant-type:token-exchange`
- colocated JWT issuers now also serve OAuth authorization-server metadata at the issuer’s RFC 8414 well-known path
- operator-facing remote receipt queries at `/admin/receipts/tools` and `/admin/receipts/children` when `--receipt-db` is configured
- operator-facing remote revocation query/control at `/admin/revocations` and per-session trust administration at `/admin/sessions/{session_id}/trust` when `--revocation-db` is configured
- operator-facing remote authority status and rotation at `/admin/authority` when `--authority-seed-file` or `--authority-db` is configured
- operator-facing remote budget queries at `/admin/budgets` when `--budget-db` is configured locally or through the shared control plane
- separate admin bearer authentication via `--admin-token` when JWT admission mode is enabled
- the same hosted admin URLs now proxy to a shared trust-control service when hosted nodes are started with `--control-url` and `--control-token`

Current remote limitations:

- standalone GET `/mcp` SSE is available with bounded retained-notification replay rather than unbounded durable redelivery
- shared wrapped-host ownership is opt-in via `--shared-hosted-owner`; the conservative default remains one wrapped subprocess per session
- session lifecycle hardening now includes idle expiry, drain/delete/shutdown tombstones, and admin diagnostics; tombstones persist across restart when `serve-http` is configured with `--session-db`, and otherwise remain in memory only
- the HA control plane is a deterministic leader plus repair-sync cluster, not quorum consensus or multi-region replication
- the hosted authorization server is operator-scoped and self-hosted; dynamic user federation and richer external IdP integration are still follow-on work
- budget sharing is currently invocation-count based; richer quota dimensions and hierarchy policy are still follow-on work

On the trust plane, PACT now supports both embedded local persistence and an HA replicated distributed-control service. The local runtime still supports optional SQLite-backed `--receipt-db`, `--revocation-db`, `--authority-seed-file` or `--authority-db`, and `--budget-db`. The shared path is `pact trust serve`, which now centralizes capability issuance, authority status/rotation, revocation query/control, durable tool/child receipt ingestion/query, and shared budget accounting behind one authenticated HTTP service. In clustered mode, multiple trust-control nodes advertise themselves with `--advertise-url`, discover peers through repeated `--peer-url`, elect a deterministic write leader, forward writes there, and repair-sync authority snapshots, revocations, receipts, and budgets in the background. Hosted nodes and CLI runtime paths can use that cluster through comma-separated `--control-url` endpoints plus `--control-token`, and hosted admin APIs proxy to it when configured. Authority rotation remains intentionally future-session-only, but trusted-key history preserves already-issued capabilities while new sessions converge on the new issuer across nodes. See [docs/HA_CONTROL_AUTH_PLAN.md](docs/HA_CONTROL_AUTH_PLAN.md) for the current HA/auth rollout model and [docs/DISTRIBUTED_CONTROL_PLAN.md](docs/DISTRIBUTED_CONTROL_PLAN.md) for the earlier shared-control rewrite.

### `pact trust`

Operate on either local persisted trust state or a shared distributed control plane.

Start the shared trust-control service:

```bash
pact \
  --receipt-db <receipts.sqlite3> \
  --revocation-db <revocations.sqlite3> \
  --authority-db <authority.sqlite3> \
  --budget-db <budgets.sqlite3> \
  trust serve \
  --listen 127.0.0.1:8940 \
  --service-token <control-token> \
  --advertise-url http://127.0.0.1:8940 \
  --peer-url http://127.0.0.1:8941
```

Use `--authority-db` rather than `--authority-seed-file` when clustering trust-control nodes so authority rotation can replicate safely.

Operate on local persisted revocation state:

```bash
pact --revocation-db <revocations.sqlite3> trust revoke --capability-id <cap-id>
pact --revocation-db <revocations.sqlite3> trust status --capability-id <cap-id>
```

Operate on the shared control plane instead:

```bash
pact --control-url http://127.0.0.1:8940,http://127.0.0.1:8941 --control-token <control-token> trust revoke --capability-id <cap-id>
pact --control-url http://127.0.0.1:8940,http://127.0.0.1:8941 --control-token <control-token> trust status --capability-id <cap-id>
```

This is now a real operator-facing trust-control surface for both local and distributed deployments.

## Policy Files

The canonical new-authoring path is HushSpec:

- [examples/policies/canonical-hushspec.yaml](examples/policies/canonical-hushspec.yaml)
- [examples/policies/hushspec-guard-heavy.yaml](examples/policies/hushspec-guard-heavy.yaml)

Legacy PACT YAML remains supported as a compatibility input. The example compatibility policy lives at [examples/policies/default.yaml](examples/policies/default.yaml).

Today, the CLI understands:

- kernel delegation depth and capability TTL settings
- kernel nested-flow flags for sampling, sampling tool use, and elicitation
- guard configuration for all shipped guards:
  `forbidden_path`, `path_allowlist`, `shell_command`, `egress_allowlist`, `tool_access`, `secret_patterns`, and `patch_integrity`
- default capability grants issued at session start

Example:

```yaml
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5

guards:
  forbidden_path:
    enabled: true
    additional_patterns:
      - "/custom/secret/*"
  shell_command:
    enabled: true
  egress_allowlist:
    enabled: true
    allowed_domains:
      - "*.github.com"
      - "*.openai.com"
      - "api.anthropic.com"

capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
```

## v2.0 Agent Economy Features

v2.0 ships a first-class economic layer on top of the existing capability and receipt infrastructure.

### Monetary budget enforcement

`ToolGrant` now carries `max_cost_per_invocation` and `max_total_cost` fields, both typed as `MonetaryAmount` (minor-unit integer plus ISO 4217 currency code). The kernel enforces per-invocation and aggregate cost caps atomically via `BudgetStore::try_charge_cost`, which also increments the invocation counter in the same transaction. `ToolGrant::is_subset_of` enforces that delegated grants never exceed the parent's monetary caps. `FinancialReceiptMetadata` is embedded in the receipt `metadata` field and records `grant_index`, `cost_charged`, `currency`, `budget_remaining`, `budget_total`, `delegation_depth`, `root_budget_holder`, and `settlement_status` for every monetized invocation.

### DPoP proof-of-possession

`ToolGrant.dpop_required` enables per-grant DPoP enforcement. When set, the kernel requires a valid `pact.dpop_proof.v1` Ed25519 proof on every invocation, binding the tool call to the agent's keypair and preventing stolen-token replay. DPoP nonces are tracked in an LRU cache for the configured TTL window. See `crates/pact-kernel/src/dpop.rs`.

### Merkle-committed receipt batches

The kernel signs `pact.checkpoint_statement.v1` objects that commit a contiguous batch of receipts to a Merkle root using `MerkleTree::from_leaves`. Checkpoints record `batch_start_seq`, `batch_end_seq`, `tree_size`, and `merkle_root`. Inclusion proofs allow verifying that a specific receipt was part of a signed batch without replaying the full log. See `crates/pact-kernel/src/checkpoint.rs`.

### Velocity guard rate limiting

A `VelocityGuard` in `crates/pact-guards/src/velocity.rs` enforces token-bucket rate limits per `(capability_id, grant_index)` pair. Buckets use integer milli-token arithmetic to eliminate floating-point drift. The guard sits in the standard guard pipeline and produces a signed deny receipt on rate limit breach before any tool server call is made.

### Receipt query API

The trust-control service exposes `GET /v1/receipts/query` with eight filter dimensions (capability, tool server, tool name, outcome, since, until, min_cost, max_cost) plus cursor-based pagination and `agent_subject` filtering via capability lineage JOIN. The CLI surface is `pact receipt list` with the same filter flags. See `crates/pact-kernel/src/receipt_query.rs` and `crates/pact-cli/src/main.rs`.

### SIEM exporters

`crates/pact-siem` provides a batched async exporter pipeline with a bounded dead-letter queue. Splunk HEC and Elasticsearch bulk exporters are included. The crate is gated behind `--features siem` in `pact-cli`. Build with:

```bash
cargo build -p pact-cli --features siem
```

### Receipt dashboard SPA

A React 18 + Vite 6 single-page app lives at `crates/pact-cli/dashboard/`. It queries the trust-control API and renders receipt timelines, allow/deny breakdowns, cost summaries, and tool-level aggregates. The trust-control server serves the built SPA from `dashboard/dist/` as a catch-all route alongside the API endpoints.

Build the dashboard:

```bash
cd crates/pact-cli/dashboard && npm install && npm run build
```

### TypeScript SDK 1.0

`packages/sdk/pact-ts/` publishes `@pact-protocol/sdk` v1.0.0 (Node >= 22). It covers capability invariant verification, receipt verification, canonical JSON, Ed25519 signing, DPoP proof construction, a receipt query client, and a Streamable HTTP transport with session management.

### Compliance documents

Operator-facing compliance references ship in `docs/compliance/`:

- `docs/compliance/colorado-sb-24-205.md`: Colorado SB 24-205 (AI systems consumer protections)
- `docs/compliance/eu-ai-act-article-19.md`: EU AI Act Article 19 (logging and audit obligations)

### Capability lineage index

`crates/pact-kernel/src/capability_lineage.rs` persists `CapabilitySnapshot` records alongside the receipt store. The snapshot records `subject_key`, `issuer_key`, `issued_at`, `expires_at`, `grants_json`, `delegation_depth`, and `parent_capability_id`. The `WITH RECURSIVE` CTE in `SqliteReceiptStore` walks full delegation chains. The `GET /v1/lineage/{capability_id}/chain` endpoint on the trust-control service exposes the chain to operators. This closes the analytics join gap between receipts and agent subjects without replaying issuance logs.

### Receipt retention with time/size rotation

`RetentionConfig` on `KernelConfig` enables automatic archival: receipts older than `retention_days` (default 90) or databases larger than `max_size_bytes` (default 10 GB) are rotated into a read-only archive SQLite file. Archived receipts remain verifiable against their Merkle checkpoint roots.

---

## Workspace Layout

| Path | Purpose |
| --- | --- |
| `crates/pact-core` | Shared protocol types and cryptographic helpers |
| `crates/pact-kernel` | Kernel evaluation logic and transport |
| `crates/pact-guards` | Guard implementations |
| `crates/pact-cli` | CLI binary (`pact`) |
| `crates/pact-cli/dashboard` | Receipt dashboard SPA (React 18 + Vite 6) |
| `crates/pact-manifest` | Signed tool manifests |
| `crates/pact-mcp-adapter` | MCP compatibility layer |
| `crates/pact-siem` | SIEM exporters (Splunk HEC, Elasticsearch) -- `--features siem` |
| `examples/hello-tool` | Minimal example tool server |
| `examples/policies` | Example policy files |
| `formal/diff-tests` | Differential tests for scope behavior |
| `tests/e2e` | End-to-end integration coverage |
| `packages/sdk/pact-ts` | TypeScript SDK (`@pact-protocol/sdk`) |
| `packages/sdk/pact-py` | Python SDK |
| `packages/sdk/pact-go` | Go SDK |
| `spec/PROTOCOL.md` | Shipped `v2` protocol and artifact contract |

## Protocol And Repository Reality

The protocol document now describes the shipped repository profile rather than a
larger aspirational draft. It still calls out explicit non-goals such as
multi-region consensus, public certification discovery, and full theorem-prover
completion so release claims stay tied to what this workspace actually
qualifies.

## Verification

On this repository state, the following commands complete successfully:

```bash
./scripts/ci-workspace.sh
./scripts/qualify-release.sh
cargo run -p pact-cli -- check --policy examples/policies/default.yaml --tool bash --params '{"command":"rm -rf /"}'
cargo run -p hello-tool
```

## License

Apache-2.0. See [LICENSE](LICENSE).

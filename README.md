<p align="center">
  <img src="assets/hero.png" alt="ARC" width="900" />
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/MSRV-1.93-orange?style=flat-square&logo=rust" alt="MSRV: 1.93">
  <img src="https://img.shields.io/badge/status-production--candidate-yellow?style=flat-square" alt="Status: Production candidate">
  <img src="https://img.shields.io/badge/MCP-compatible-green?style=flat-square" alt="MCP compatible">
  <img src="https://img.shields.io/badge/A2A-interop-green?style=flat-square" alt="A2A interop">
</p>

<h1 align="center">ARC</h1>

<p align="center">
  <strong>Attested Rights Channel</strong><br/>
  <em>Economic trust infrastructure for autonomous AI systems.</em>
</p>

<p align="center">
  Fail-closed mediation
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  Capability-scoped authorization
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  Bonded execution
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  Liability coverage
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  Credit facilities
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  Exposure ledger
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  Merkle-committed receipts
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  Agent passports
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  Multi-cloud attestation
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  Lean 4 verified
</p>

<p align="center">
  <a href="#what-is-arc">What Is ARC</a>&nbsp;&nbsp;&middot;&nbsp;&nbsp;
  <a href="#why-arc">Why ARC</a>&nbsp;&nbsp;&middot;&nbsp;&nbsp;
  <a href="#how-it-works">How It Works</a>&nbsp;&nbsp;&middot;&nbsp;&nbsp;
  <a href="#quick-start">Quick Start</a>&nbsp;&nbsp;&middot;&nbsp;&nbsp;
  <a href="#cli">CLI</a>&nbsp;&nbsp;&middot;&nbsp;&nbsp;
  <a href="#sdks">SDKs</a>&nbsp;&nbsp;&middot;&nbsp;&nbsp;
  <a href="spec/PROTOCOL.md">Protocol Spec</a>
</p>

---

## What Is ARC

ARC (Attested Rights Channel) is a trust-and-economics control plane for governed agent actions. It is a Rust runtime and protocol that mediates every tool invocation an agent makes -- validating scoped capabilities, enforcing policy and spend limits, and signing a cryptographic receipt for every decision.

## Why ARC

Most of the ecosystem has focused on giving agents a clean way to reach tools. That matters, but it leaves unresolved the harder question of what it means for a machine actor to operate with bounded authority in systems where actions have financial, operational, or legal consequences.

As agents become economic actors, the relevant unit is not a model response but an authorized act: a database mutation, an infrastructure change, a purchase, a settlement-triggering API call, a delegated operation carried out across trust boundaries. Existing agent protocols mostly solve reachability. They do not solve authority. They specify how an agent invokes a tool, but not how rights are scoped, how spend is bounded, how delegation attenuates, how revocation propagates, or how a third party can later verify what actually occurred.

That gap becomes structural once agents are allowed to hold real authority. An agent that can spend, transact, modify state, or recursively delegate work is no longer just a software component. It is a machine principal participating in an economic system. At that point, permissions, budget, and accountability can no longer live in separate layers stitched together by convention. They have to be fused into the execution path itself.

ARC exists to provide that layer.

ARC inserts a fail-closed kernel between agents and tools and treats every invocation as a governed act. Capability tokens define delegated rights. Policy and constraint checks determine whether those rights are valid in context. Budget enforcement makes authority economically bounded rather than merely syntactically scoped. Signed receipts turn each decision into non-repudiable evidence rather than an ordinary log event.

The result is a stronger primitive than transport, payment, or audit alone. A capability in ARC is not just permission to call a function. It is a programmable authorization instrument. A delegation chain is not just access-control metadata. It is a cost-responsibility chain. A receipt log is not just telemetry. It has the structure of an audit trail, a billing ledger, and a compliance record at once. That is why ARC belongs above payment rails and below agent frameworks: it is the layer that can prove an agent was authorized to do something consequential, under what constraints, at what cost, and with what outcome.

## How It Works

An agent never talks to a tool directly. Every call goes through the **kernel** -- a trusted mediator that validates a signed capability token, runs the guard pipeline, checks monetary budgets, dispatches the call, and returns the result alongside a signed receipt. The receipt is the proof. It covers allows and denies, is independently verifiable, and feeds into a Merkle-committed append-only log.

The system has five pieces:

- **Agent** -- the untrusted LLM process. It holds capability tokens but has zero ambient authority.
- **Runtime Kernel** -- the TCB. Validates capabilities, enforces guards and budgets, signs every receipt. Fail-closed: if anything goes wrong, access is denied.
- **Tool Servers** -- sandboxed, isolated processes that implement tools. They never see each other or the agent directly.
- **Capability Authority** -- issues and revokes time-bounded, scope-limited, delegation-tracked tokens. Revocation cascades through the entire delegation chain.
- **Receipt Log** -- append-only, Merkle-committed. Every decision is signed and checkpointed. Inclusion proofs let you verify a single receipt without replaying the full log.

## Quick Start

**Requirements:** Rust 1.93+

```bash
# Build the workspace
cargo build --workspace

# Run the test suite
cargo test --workspace

# Try the policy checker
cargo run -p arc-cli -- check \
  --policy examples/policies/default.yaml \
  --tool bash \
  --params '{"command":"rm -rf /"}'
```

Expected output:

```
verdict:    DENY
tool:       bash
server:     *
```

```bash
# Run the example tool server
cargo run -p hello-tool
```

## CLI

The `arc` CLI is the primary interface for local development and operator workflows.

### `arc check` -- evaluate a single tool call

```bash
arc check --policy <policy.yaml> --tool <tool-name> [--params '<json>']
```

Exits `0` on allow, `2` on deny, `1` on error. Add `--json` for machine-readable output, `--receipt-db <path>` to persist signed receipts.

### `arc run` -- mediate an agent subprocess

```bash
arc run --policy <policy.yaml> <command>...
```

Spawns a subprocess that speaks ARC's length-prefixed JSON protocol over stdio. The kernel issues a default capability from the policy and mediates all tool requests. Supports chunked streaming for long-running tool output.

### `arc mcp serve` -- wrap an MCP server with ARC governance

```bash
arc mcp serve --policy <policy.yaml> --server-id <id> <command>...
```

Wraps any MCP server subprocess with ARC's kernel. The outer edge speaks stock MCP (tools, resources, prompts, completion, logging) while the kernel enforces capabilities, guards, and budgets on every call. Supports nested sampling, elicitation, progress notifications, resource subscriptions, and task-oriented execution.

### `arc mcp serve-http` -- hosted Streamable HTTP edge

```bash
arc mcp serve-http \
  --policy <policy.yaml> \
  --server-id <id> \
  --listen 127.0.0.1:8931 \
  <command>...
```

Exposes the same kernel-backed MCP edge over Streamable HTTP with session management, multiple concurrent clients, and authenticated admission (static bearer, JWT, or hosted OAuth with PKCE). Includes operator admin endpoints for receipts, revocations, authority rotation, and budget queries.

### `arc trust serve` -- distributed trust control plane

```bash
arc trust serve --listen 127.0.0.1:8940 --service-token <token> [--peer-url <peer>]
```

Runs a shared trust-control service that centralizes capability issuance, revocation, receipt ingestion, and budget accounting. Supports HA clustering with deterministic leader election and background repair-sync.

## Policy

Policies are authored in HushSpec YAML:

```yaml
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5

guards:
  forbidden_path:
    enabled: true
  shell_command:
    enabled: true
  egress_allowlist:
    enabled: true
    allowed_domains:
      - "*.github.com"
      - "api.anthropic.com"

capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
```

Seven built-in guards ship today: `forbidden_path`, `path_allowlist`, `shell_command`, `egress_allowlist`, `tool_access`, `secret_patterns`, and `patch_integrity`. A `VelocityGuard` provides token-bucket rate limiting per capability.

See [examples/policies/](examples/policies/) for starter templates.

## Agent Economy

Most agent frameworks treat authorization and payment as separate concerns -- one system decides whether a call is allowed, another tracks what it costs. ARC fuses them. A capability token is simultaneously a permission grant and a spending authorization. The delegation chain that tracks who gave an agent access is the same structure that tracks cost responsibility. The receipt log that proves what happened is already a pre-audited billing ledger.

Concretely: each `ToolGrant` carries optional `max_cost_per_invocation` and `max_total_cost` fields (minor-unit integers + ISO 4217 currency code). The kernel enforces both atomically at evaluation time and embeds financial metadata directly into the signed receipt. Delegation attenuates budgets monotonically -- a child grant can tighten a spending cap but never loosen one. DPoP proof-of-possession binds tokens to the agent's keypair, so a stolen capability is worthless without the corresponding private key.

Receipts are batched into Merkle-committed checkpoints. Inclusion proofs let you verify a single receipt against its checkpoint root without replaying the full log. The trust-control API and CLI (`arc receipt list`) expose eight-dimension filtered queries with cursor pagination. Archived receipts rotate by time and size but remain verifiable against their original checkpoint roots.

## Portable Trust and Identity

Agents operating across organizational boundaries need more than a session token. ARC provides a self-certifying identity layer (`did:arc`) and a portable credential system built on top of it.

**Agent passports** are verifiable credentials issued by operators that summarize an agent's behavioral history: reliability scores, compliance rates, scope discipline, delegation hygiene, and operational patterns. Passports are portable across trust boundaries through explicit **federation policies** -- bilateral agreements that define what evidence can be shared, under what terms, with foreign-origin marking preserved. A **reputation scoring** layer computes quantified trust from receipt history and verified credentials. An operator-administered **certification registry** manages certification state with CLI tooling.

See the [Portable Trust Profile](docs/standards/ARC_PORTABLE_TRUST_PROFILE.md) standard and the [Agent Passport Guide](docs/AGENT_PASSPORT_GUIDE.md).

## Interoperability

ARC is not a replacement for MCP or A2A -- it is a governance layer that wraps them. The **MCP adapter** takes any existing MCP server subprocess and interposes the ARC kernel, adding capability validation, guard enforcement, and receipt signing to every tool call, resource read, and prompt retrieval without modifying the server. The **A2A adapter** does the same for Google's Agent-to-Agent protocol (v1.0.0), with fail-closed auth negotiation and durable task correlation.

For observability, **SIEM exporters** provide batched async delivery to Splunk HEC and Elasticsearch (feature-gated behind `--features siem`). A **receipt dashboard** (React SPA at `crates/arc-cli/dashboard/`) renders receipt timelines, allow/deny breakdowns, cost summaries, and per-tool aggregates against the trust-control API.

## SDKs

| Language   | Package             | Path                                           |
| ---------- | ------------------- | ---------------------------------------------- |
| TypeScript | `@arc-protocol/sdk` | [`packages/sdk/arc-ts/`](packages/sdk/arc-ts/) |
| Python     | `arc-py`            | [`packages/sdk/arc-py/`](packages/sdk/arc-py/) |
| Go         | `arc-go`            | [`packages/sdk/arc-go/`](packages/sdk/arc-go/) |

All three cover capability verification, receipt verification, canonical JSON, Ed25519 signing, DPoP proof construction, receipt queries, and Streamable HTTP transport with session management.

## Workspace Layout

```
arc/
├── crates/
│   ├── arc-core             # Protocol types, signing, canonical JSON, Merkle helpers
│   ├── arc-kernel           # Capability validation, guard pipeline, receipt signing
│   ├── arc-guards           # Seven built-in guard implementations
│   ├── arc-policy           # Policy parsing and materialization
│   ├── arc-cli              # CLI binary and receipt dashboard SPA
│   ├── arc-manifest         # Signed tool manifest format
│   ├── arc-mcp-adapter      # MCP server wrapping and transport
│   ├── arc-mcp-edge         # MCP edge serving (stdio + HTTP)
│   ├── arc-hosted-mcp       # Hosted Streamable HTTP server
│   ├── arc-a2a-adapter      # A2A v1.0.0 adapter
│   ├── arc-control-plane    # Distributed trust-control service
│   ├── arc-store-sqlite     # SQLite persistence layer
│   ├── arc-did              # did:arc decentralized identity
│   ├── arc-credentials      # Verifiable credentials and passport schemas
│   ├── arc-reputation       # Reputation scoring
│   ├── arc-siem             # SIEM exporters (Splunk, Elasticsearch)
│   ├── arc-conformance      # Conformance test harness
│   └── arc-bindings-core    # FFI bindings core
├── examples/
│   ├── hello-tool/          # Minimal native tool server example
│   └── policies/            # Starter policy files
├── packages/sdk/
│   ├── arc-ts/              # TypeScript SDK
│   ├── arc-py/              # Python SDK
│   └── arc-go/              # Go SDK
├── formal/diff-tests/       # Differential tests for scope semantics
├── tests/e2e/               # End-to-end integration tests
├── docs/                    # Guides, standards, compliance, release docs
└── spec/PROTOCOL.md         # Protocol specification
```

## Documentation

| Topic                         | Link                                                                               |
| ----------------------------- | ---------------------------------------------------------------------------------- |
| Protocol specification        | [spec/PROTOCOL.md](spec/PROTOCOL.md)                                               |
| Native tool server adoption   | [docs/NATIVE_ADOPTION_GUIDE.md](docs/NATIVE_ADOPTION_GUIDE.md)                     |
| Tool pricing and budgets      | [docs/TOOL_PRICING_GUIDE.md](docs/TOOL_PRICING_GUIDE.md)                           |
| Agent passports and trust     | [docs/AGENT_PASSPORT_GUIDE.md](docs/AGENT_PASSPORT_GUIDE.md)                       |
| Identity federation           | [docs/IDENTITY_FEDERATION_GUIDE.md](docs/IDENTITY_FEDERATION_GUIDE.md)             |
| A2A adapter                   | [docs/A2A_ADAPTER_GUIDE.md](docs/A2A_ADAPTER_GUIDE.md)                             |
| ARC Certify                   | [docs/ARC_CERTIFY_GUIDE.md](docs/ARC_CERTIFY_GUIDE.md)                             |
| SIEM integration              | [docs/SIEM_INTEGRATION_GUIDE.md](docs/SIEM_INTEGRATION_GUIDE.md)                   |
| Receipt dashboard             | [docs/RECEIPT_DASHBOARD_GUIDE.md](docs/RECEIPT_DASHBOARD_GUIDE.md)                 |
| DPoP integration              | [docs/DPOP_INTEGRATION_GUIDE.md](docs/DPOP_INTEGRATION_GUIDE.md)                   |
| Monetary budgets              | [docs/MONETARY_BUDGETS_GUIDE.md](docs/MONETARY_BUDGETS_GUIDE.md)                   |
| TypeScript SDK reference      | [docs/SDK_TYPESCRIPT_REFERENCE.md](docs/SDK_TYPESCRIPT_REFERENCE.md)               |
| Operations runbook            | [docs/release/OPERATIONS_RUNBOOK.md](docs/release/OPERATIONS_RUNBOOK.md)           |
| Release candidate             | [docs/release/RELEASE_CANDIDATE.md](docs/release/RELEASE_CANDIDATE.md)             |
| EU AI Act compliance          | [docs/compliance/eu-ai-act-article-19.md](docs/compliance/eu-ai-act-article-19.md) |
| Colorado SB 24-205 compliance | [docs/compliance/colorado-sb-24-205.md](docs/compliance/colorado-sb-24-205.md)     |

## Status

Production candidate (`v2.5`). The protocol spec in [spec/PROTOCOL.md](spec/PROTOCOL.md) describes the shipped repository profile. See [docs/release/RELEASE_CANDIDATE.md](docs/release/RELEASE_CANDIDATE.md) for the full release qualification surface.

**Not yet finished:**

- Multi-region consensus replication (current HA is deterministic leader/follower)
- Public certification marketplace discovery
- Automatic SCIM lifecycle management
- Synthetic cross-issuer passport trust aggregation
- Theorem-prover completion for every protocol claim

## License

Apache-2.0. See [LICENSE](LICENSE).

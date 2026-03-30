# Architecture

**Analysis Date:** 2026-03-19

## Pattern Overview

**Overall:** Rust workspace with a security kernel, policy/guard pipeline, MCP-compatible edge adapters, and CLI-hosted trust/runtime services

**Key Characteristics:**
- Shared core types and cryptographic primitives
- Fail-closed runtime mediation around tool/resource/prompt execution
- Multiple transport paths (direct, wrapped stdio, remote HTTP) over a common session model
- Strong emphasis on receipts, revocation, and capability-scoped authorization

## Layers

**Core Model Layer:**
- Purpose: Define canonical types, signing, hashing, manifests, receipts, session messages, and capability structures
- Contains: `arc-core`, `arc-manifest`
- Depends on: Serialization and crypto dependencies
- Used by: Every other crate

**Policy and Guard Layer:**
- Purpose: Compile policy inputs and evaluate request-time guard logic
- Contains: `arc-policy`, `arc-guards`
- Depends on: Core model types
- Used by: Kernel construction and CLI policy loading

**Runtime Kernel Layer:**
- Purpose: Validate capabilities, evaluate guards, manage session operations, and persist trust state
- Contains: `arc-kernel`
- Depends on: Core model, SQLite, tracing
- Used by: CLI entrypoints and MCP adapter surfaces

**Edge and Adapter Layer:**
- Purpose: Translate between MCP-compatible transports and the kernel's session/runtime abstractions
- Contains: `arc-mcp-adapter`
- Depends on: Core model, kernel, manifest support
- Used by: `arc-cli` stdio and HTTP serving paths

**CLI and Hosted Service Layer:**
- Purpose: Provide operator-facing commands, HTTP serving, and trust-control admin/control endpoints
- Contains: `arc-cli`
- Depends on: All core runtime crates plus Axum/HTTP tooling
- Used by: Humans, harnesses, wrapped MCP clients, and remote deployments

**Verification Layer:**
- Purpose: Prove behavior across unit, integration, conformance, e2e, and formal-diff suites
- Contains: `arc-conformance`, `tests/e2e`, `formal/diff-tests`, crate integration tests
- Depends on: Runtime and edge behavior being externally observable
- Used by: CI and release qualification

## Data Flow

**CLI Policy Check:**

1. Operator invokes `arc check`
2. CLI loads policy input and default capability context
3. Kernel validates capability and evaluates guards
4. Receipt is signed and returned with allow/deny outcome

**Wrapped MCP Session:**

1. Operator invokes `arc mcp serve` or `arc mcp serve-http`
2. CLI spawns or connects to an upstream MCP server
3. Adapter exposes an MCP-compatible edge backed by kernel session state
4. Incoming tool/resource/prompt/sampling/elicitation flows are normalized into kernel operations
5. Kernel enforces capability/policy rules and emits results plus signed receipts

**Trust-Control Operation:**

1. Caller targets a trust-control endpoint locally or via cluster forwarding
2. Leader/follower routing decides where the write is handled
3. SQLite-backed authority, budget, receipt, or revocation state is updated
4. Replication and failover logic propagate or repair shared state

**State Management:**
- Session state is runtime-owned and transport-aware
- Durable trust data currently lives in SQLite stores
- Some remaining productization work is about removing timing-sensitive or edge-local ownership behavior

## Key Abstractions

**Capability / Scope:**
- Purpose: Represent what an agent may do and under what bounds
- Examples: `ArcScope`, capability tokens, grants
- Pattern: Signed, serializable security contract

**Receipt:**
- Purpose: Produce auditable evidence for allow, deny, cancel, and incomplete outcomes
- Examples: `ArcReceipt`, receipt stores, receipt signing
- Pattern: Immutable signed record

**Session Operation:**
- Purpose: Normalize active work, lineage, progress, cancellation, and terminal states
- Examples: `SessionOperation`, `ToolCallOperation`, session IDs and request IDs
- Pattern: Runtime-owned state machine

**Guard Pipeline:**
- Purpose: Apply path, shell, egress, MCP-tool, patch-integrity, and related policy checks
- Examples: `forbidden_path`, `path_allowlist`, `secret_leak`, `mcp_tool`
- Pattern: Composable policy enforcement chain

## Entry Points

**CLI Entry:**
- Location: `crates/arc-cli/src/main.rs`
- Triggers: `arc check`, `arc run`, `arc mcp serve`, `arc mcp serve-http`, `arc trust ...`
- Responsibilities: Parse flags, load policy/runtime state, host transports, route operator commands

**MCP Edge Entry:**
- Location: `crates/arc-mcp-adapter/src/edge.rs`
- Triggers: Wrapped stdio and remote HTTP MCP traffic
- Responsibilities: Translate protocol traffic into kernel/session operations

**Kernel Entry:**
- Location: `crates/arc-kernel/src/lib.rs`, `crates/arc-kernel/src/session.rs`
- Triggers: CLI and edge calls
- Responsibilities: Enforce capability and policy semantics, track session state, create receipts

## Error Handling

**Strategy:** Propagate typed errors with `Result`/`thiserror`, enforce fail-closed behavior at security boundaries, and log runtime state transitions with `tracing`

**Patterns:**
- `unwrap`/`expect` are denied in main crate code via Clippy and only relaxed in tests
- Boundary layers translate internal errors into protocol-appropriate tool/resource/prompt/task failures
- Security-relevant ambiguity is intended to deny rather than allow

## Cross-Cutting Concerns

**Logging:**
- `tracing` is the common logging surface
- Hosted and trust-control work increasingly depends on stronger observability

**Validation:**
- Policy inputs and manifests are validated before runtime use
- Session and transport inputs are normalized into internal request models

**Security:**
- Capability validation, guard evaluation, revocation, authority, and signed receipts cut across all layers
- Roots enforcement and transport-consistent long-running ownership remain active closing-cycle concerns

---
*Architecture analysis: 2026-03-19*
*Update when major patterns change*

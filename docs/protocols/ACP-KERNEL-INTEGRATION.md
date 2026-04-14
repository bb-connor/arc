# ACP Proxy Kernel Integration

Technical design specification for integrating `arc-acp-proxy` with the ARC kernel's
receipt signing and capability validation infrastructure.

**Status**: Design Proposal -- Tier 1 Priority  **Date**: 2026-04-13  **Crate**: `arc-acp-proxy`

> **Status**: Design proposal. The `ReceiptSigner` and `CapabilityChecker` traits
> described here are not yet implemented. This document specifies the target
> architecture for kernel integration.

---

## 1. Problem Statement

The ACP proxy produces **unsigned** `AcpToolCallAuditEntry` objects for tool-call events
observed in `session/update` notifications. These lack three properties that the MCP and
A2A adapters provide through kernel-mediated `ArcReceipt` objects:

1. **Non-repudiation.** No cryptographic binding to the kernel's signing key. An attacker
   with write access to the audit log can forge, reorder, or delete entries undetected.

2. **Compliance correlation.** Signed receipts carry `capability_id`, `policy_hash`, and
   `evidence` that tie decisions to the exact token and guard pipeline. Unsigned entries
   cannot be joined with MCP/A2A events in a unified compliance query.

3. **Cross-protocol audit continuity.** Unsigned entries cannot be appended to the
   kernel's `ReceiptStore` or included in Merkle checkpoint batches, breaking the
   commitment chain for organizations running ACP agents alongside MCP tool servers.

This is the single largest security gap in the ARC protocol stack.

---

## 2. Design Goals

| Goal | Constraint |
|------|-----------|
| Signed `ArcReceipt` for ACP tool-call events | Must not force proxy to implement `ToolServerConnection` |
| Capability-token validation for resource access | Preserve proxy's boundary architecture |
| Merkle receipt chain integration | Proxy must not hold private key material |
| Standalone proxy support (no kernel) | Degrade gracefully to unsigned audit entries |
| Minimal coupling | Traits in `arc-acp-proxy`; impls in `arc-kernel` or bridge crate |

Core decision: **inject the kernel as a service, not as a trait implementation.** The
proxy accepts `ReceiptSigner` and `CapabilityChecker` via constructor injection. It
never implements `ToolServerConnection` -- it is an interposition proxy, not a tool
server.

---

## 3. Proposed Architecture

### 3.1 Injection Model

Both traits are `Option`-wrapped in `MessageInterceptor`. When `None`, the proxy uses
the existing unsigned `AcpToolCallAuditEntry` path.

> **Note on imports**: Types are imported from `arc_core`, which re-exports from
> `arc_core_types`. In Cargo.toml, depend on
> `arc-core = { package = "arc-core-types", path = "../arc-core-types" }`.

```rust
pub struct MessageInterceptor {
    // ... existing fields ...
    receipt_signer: Option<Box<dyn ReceiptSigner>>,
    capability_checker: Option<Box<dyn CapabilityChecker>>,
}
```

### 3.2 Message Flow

```
Editor/IDE               ACP Proxy                         ACP Agent
    |                       |                                  |
    |-- JSON-RPC request -->|                                  |
    |                       |-- [CapabilityChecker::check] --> |
    |                       |-- [FsGuard / TerminalGuard] ---> |
    |                       |--- forward request ------------->|
    |                       |<-- session/update (tool_call) ---|
    |                       |-- [ReceiptSigner::sign] -------> |
    |<- forward + receipt --|                                  |
```

**Pre-forward:** For `fs/read_text_file`, `fs/write_text_file`, and `terminal/create`,
the interceptor consults `CapabilityChecker` (if present) before the existing guards.
Both layers must allow; either can deny (defense-in-depth).

**Post-observation:** On `session/update` with a tool-call event, the interceptor builds
an `AcpToolCallAuditEntry`, then promotes it to a signed `ArcReceipt` via
`ReceiptSigner`. On signer error, it falls back to the unsigned entry with a warning.

---

## 4. `ReceiptSigner` Trait Design

```rust
use arc_core::receipt::ArcReceipt;

/// Scope context for the resource or action being attested.
#[derive(Debug, Clone)]
pub enum AcpScopeContext {
    FilePath { path: String, operation: FileOperation },
    TerminalCommand { command: String, args: Vec<String> },
    ToolCall { tool_name: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOperation { Read, Write }

/// Parameters for signing an ACP tool-call event into an ARC receipt.
#[derive(Debug, Clone)]
pub struct AcpReceiptRequest {
    /// Unique tool call ID from the ACP protocol.
    pub tool_call_id: String,
    /// Tool name (e.g. "fs/read_text_file", "terminal/create").
    pub tool_name: String,
    /// Session ID from the ACP session/update notification.
    pub session_id: String,
    /// SHA-256 hex digest of the canonical JSON of the tool-call event.
    pub content_hash: String,
    /// Scope context for the resource being accessed.
    pub scope_context: AcpScopeContext,
    /// Server identity string (from `AcpProxyConfig::server_id`).
    pub server_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ReceiptSignError {
    #[error("signing key unavailable: {0}")]
    KeyUnavailable(String),
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("signer error: {0}")]
    Internal(String),
}

/// Signs ACP audit events into ARC receipts.
///
/// Implementations hold or delegate to the kernel's signing key.
/// The proxy never touches key material directly.
pub trait ReceiptSigner: Send + Sync {
    /// Promote an ACP tool-call event into a signed `ArcReceipt`.
    ///
    /// Responsible for: generating receipt ID (UUIDv7), populating
    /// `capability_id` and `policy_hash`, building `ArcReceiptBody`,
    /// signing with the kernel keypair, and appending to `ReceiptStore`.
    ///
    /// Errors are non-fatal -- the proxy falls back to unsigned entries.
    fn sign_acp_receipt(
        &self,
        request: &AcpReceiptRequest,
    ) -> Result<ArcReceipt, ReceiptSignError>;
}
```

---

## 5. `CapabilityChecker` Trait Design

```rust
/// Capability check verdict (local to arc-acp-proxy to avoid kernel dependency).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcpVerdict {
    Allow,
    Deny { reason: String },
}

/// A request to validate scoped access against a capability token.
#[derive(Debug, Clone)]
pub struct AcpCapabilityRequest {
    pub session_id: String,
    pub agent_id: String,
    pub access: AcpAccessRequest,
}

#[derive(Debug, Clone)]
pub enum AcpAccessRequest {
    FileRead { path: String },
    FileWrite { path: String },
    TerminalExecute { command: String, args: Vec<String> },
}

#[derive(Debug, thiserror::Error)]
pub enum CapabilityCheckError {
    #[error("no capability token bound to session: {0}")]
    NoToken(String),
    #[error("capability expired")]
    Expired,
    #[error("capability revoked: {0}")]
    Revoked(String),
    #[error("checker error: {0}")]
    Internal(String),
}

/// Validates ACP resource access against ARC capability tokens.
///
/// Implementations consult the kernel's capability authority, revocation
/// store, and budget store. The proxy calls this before forwarding
/// guarded requests (filesystem, terminal) to the agent.
pub trait CapabilityChecker: Send + Sync {
    /// Check whether the requested access is authorized.
    ///
    /// Resolves the session's capability token, verifies time bounds,
    /// revocation status, scope matching, and budget limits.
    ///
    /// Returns `Err` on internal failures -- the proxy treats errors
    /// as deny (fail-closed).
    fn check_access(
        &self,
        request: &AcpCapabilityRequest,
    ) -> Result<AcpVerdict, CapabilityCheckError>;
}
```

---

## 6. Migration Path

**Phase 1 -- Additive.** Both traits are `Option`-wrapped. Existing `AcpProxy::start`
remains unchanged. A new `AcpProxy::start_with_kernel` constructor accepts the signer
and checker. `InterceptResult` gains a new variant:

```rust
pub enum InterceptResult {
    Forward(Value),
    Block(Value),
    ForwardWithAuditEntry(Value, AcpToolCallAuditEntry),     // legacy
    ForwardWithSignedReceipt(Value, ArcReceipt),             // new
}
```

The existing `ForwardWithReceipt` is deprecated and aliased to `ForwardWithAuditEntry`.

**Phase 2 -- Dual-write.** When both signer and logger are present, the interceptor
produces both unsigned and signed artifacts. Downstream consumers migrate at their pace.

**Phase 3 -- Deprecation.** After one major release, the unsigned-only path emits a
compile-time warning. `ReceiptLogger` moves behind a `legacy-unsigned` feature flag.

---

## 7. Security Properties

**Fail-closed receipt signing.** Signer errors cause fallback to unsigned entries with
`warn`-level logging. Signing failure is an observability gap, not a safety violation --
the guards have already made the enforcement decision.

**Fail-closed capability checking.** `check_access` errors (`Err`) are treated as deny.
The proxy returns `InterceptResult::Block` and logs at `warn` level.

**Guard ordering.** When a `CapabilityChecker` is present: (1) capability check,
(2) existing guard (`FsGuard`/`TerminalGuard`), (3) forward. Both layers must allow.

**No key material in the proxy.** The `ReceiptSigner` trait is opaque. Implementations
may hold the key in-process or call out to the kernel over an authenticated channel.

**Receipt integrity.** Signed receipts carry the same properties as MCP/A2A receipts:
Ed25519 signature over canonical JSON, embedded `kernel_key`, `content_hash` from the
ACP event, `policy_hash`, and inclusion in the Merkle checkpoint chain when a
`ReceiptStore` is configured.

---

## 8. Example Usage

### 8.1 Kernel-Backed ReceiptSigner

```rust
use arc_core::crypto::Keypair;
use arc_core::receipt::{ArcReceipt, ArcReceiptBody, Decision, ToolCallAction};
use arc_core::crypto::sha256_hex;
use arc_acp_proxy::{AcpReceiptRequest, ReceiptSigner, ReceiptSignError};

pub struct KernelReceiptSigner {
    keypair: Keypair,
    policy_hash: String,
    capability_id: String,
}

impl ReceiptSigner for KernelReceiptSigner {
    fn sign_acp_receipt(
        &self,
        req: &AcpReceiptRequest,
    ) -> Result<ArcReceipt, ReceiptSignError> {
        let action = ToolCallAction {
            parameters: serde_json::json!({
                "tool_call_id": req.tool_call_id,
                "scope": format!("{:?}", req.scope_context),
            }),
            parameter_hash: sha256_hex(req.tool_call_id.as_bytes()),
        };
        let body = ArcReceiptBody {
            id: format!("rcpt-acp-{}", uuid::Uuid::now_v7()),
            timestamp: current_unix_secs(),
            capability_id: self.capability_id.clone(),
            tool_server: req.server_id.clone(),
            tool_name: req.tool_name.clone(),
            action,
            decision: Decision::Allow,
            content_hash: req.content_hash.clone(),
            policy_hash: self.policy_hash.clone(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "protocol": "acp",
                "session_id": req.session_id,
            })),
            kernel_key: self.keypair.public_key(),
        };
        ArcReceipt::sign(body, &self.keypair)
            .map_err(|e| ReceiptSignError::Internal(e.to_string()))
    }
}
```

### 8.2 Constructing the Proxy

```rust
let signer = Box::new(KernelReceiptSigner::new(keypair, policy_hash, cap_id));
let checker = Box::new(KernelCapabilityChecker::new(/* ... */));

let config = AcpProxyConfig::new("claude-code", public_key_hex)
    .with_allowed_path_prefix("/home/dev/project")
    .with_allowed_command("cargo");

// With kernel integration:
let proxy = AcpProxy::start_with_kernel(config, signer, checker)?;

// Without kernel (unchanged, unsigned audit entries only):
// let proxy = AcpProxy::start(config)?;
```

---

## Appendix: Decision Record

**Why not `ToolServerConnection`?** The proxy does not register tools, respond to
`invoke`, or produce tool outputs. Forcing it into that trait would require fabricating
`server_id`/`tool_names`/`invoke` with no meaningful semantics, polluting the kernel's
tool registry with a phantom server.

**Why `Option`-wrapped injection?** The proxy is useful standalone (path guards and
command allowlists without capability-token infrastructure). A hard kernel requirement
would eliminate that use case.

**Why define traits in `arc-acp-proxy`?** Dependency direction: the proxy should not
depend on `arc-kernel` at compile time. The kernel (or bridge crate) depends on the
proxy's trait definitions, keeping the proxy lightweight and avoiding the kernel's
dependency tree in editor integrations.

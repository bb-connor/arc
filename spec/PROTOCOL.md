# PACT: Provable Agent Capability Transport

## Protocol Design Document

**Version:** 0.1.0-draft
**Date:** 2026-03-17
**Status:** Pre-RFC
**Authors:** ClawdStrike Protocol Team

---

## Abstract

PACT (Provable Agent Capability Transport) is a protocol for secure, attested
tool access in AI agent systems. It replaces the Model Context Protocol (MCP)
with a ground-up design rooted in capability-based security, cryptographic
attestation, and privilege separation. Every tool invocation flows through a
kernel that the agent cannot address, is gated by a time-bounded capability
token the agent must present, and produces a signed receipt that forms an
immutable audit trail. Policy correctness is formally verifiable before a single
tool call is made.

PACT is not an incremental improvement to MCP. It is a new protocol designed
from ClawdStrike's first principles:

1. **Fail closed.** If something goes wrong, deny access.
2. **Sign the truth.** Every decision gets a cryptographic receipt.
3. **The enforcement layer is not in the agent's addressable universe.**
4. **Capabilities, not permissions.** Agents hold attenuated, revocable, time-bounded tokens.
5. **Prove it works.** Policy correctness is formally verified.

---

## 1. Architecture

### 1.1 Components

PACT defines five principal components. Each runs in a separate trust domain.

| Component | Role | Trust Level |
|-----------|------|-------------|
| **Agent** | LLM-powered process that consumes tools | Untrusted |
| **Runtime Kernel** (Kernel) | Mediator between agent and tools; enforces policy, validates capabilities, signs receipts | Trusted (TCB) |
| **Tool Server** | Process that implements one or more tools; executes actions on request from the Kernel | Semi-trusted (authenticated, sandboxed) |
| **Capability Authority** (CA) | Issues, attenuates, and revokes capability tokens; maintains the revocation store | Trusted (offline or isolated) |
| **Receipt Log** | Append-only, Merkle-committed log of signed receipts and attestations | Trusted (transparency log) |

Supporting components:

| Supporting Component | Role |
|---------------------|------|
| **Policy Store** | Holds verified YAML policies; serves them to the Kernel |
| **Identity Registry** | Maps agent IDs and tool server IDs to Ed25519 public keys |

### 1.2 Communication

Inter-component communication:

- **Kernel <-> Agent:** Unidirectional pipe/UDS. Agent never learns the
  Kernel's address or PID. Wire format: length-prefixed canonical JSON
  (RFC 8785).

- **Kernel <-> Tool Server:** mTLS over UDS or TCP. Mutual authentication
  via SPIFFE identity or signed manifest pinned to Ed25519 key. Wire
  format: length-prefixed canonical JSON.

- **Kernel <-> Capability Authority:** mTLS or signed envelopes over
  HTTPS. CA may be co-located or remote.

- **Kernel -> Receipt Log:** Append-only writes via Spine (signed
  envelopes over NATS JetStream or HTTPS POST). Receipts batched into
  Merkle trees with periodic witness co-signatures.

### 1.3 Serialization

All protocol messages use **canonical JSON (RFC 8785)** for deterministic
hashing and signing. Binary fields (hashes, signatures, public keys) are
hex-encoded with optional `0x` prefix. Timestamps are ISO-8601 / RFC 3339
with second or millisecond precision in UTC.

This reuses `hush-core::canonical::canonicalize` and ensures cross-language
determinism (Rust, TypeScript, Python, Go, WASM).

### 1.4 Trust Boundaries

```
 +------------------------------------------------------------------+
 |                        UNTRUSTED ZONE                             |
 |                                                                   |
 |  +-------------------+                                            |
 |  |      Agent        |  Cannot see Kernel address, PID, or keys  |
 |  |  (LLM + client)   |  Holds only: capability tokens + results  |
 |  +--------+----------+                                            |
 |           | (1) request + cap token                               |
 |           | (anonymous pipe / UDS)                                |
 +-----------|------------------------------------------------------+
             |
 ============|====== PROCESS / NAMESPACE BOUNDARY ====================
             |
 +-----------|------------------------------------------------------+
 |           v                  TRUSTED ZONE (TCB)                   |
 |  +--------+----------+                                            |
 |  |  Runtime Kernel    |  Validates caps, runs guards, signs       |
 |  |  (clawdstrike      |  receipts, mediates all I/O               |
 |  |   enforcement)     |                                           |
 |  +---+----------+----+                                            |
 |      |          |                                                 |
 |      | mTLS     | mTLS         +---------------------+            |
 |      |          |              | Capability Authority|            |
 |      |          |              | (issues + revokes   |            |
 |      |          |              |  cap tokens)        |            |
 |      |          |              +---------------------+            |
 |      |          |                                                 |
 +------|----------|------------------------------------------------+
        |          |
 =======|==========|=== PER-SERVER SANDBOX BOUNDARY ==================
        |          |
 +------v---+ +---v--------+  +------------------+
 | Tool Srv | | Tool Srv   |  |   Receipt Log    |
 | A        | | B          |  |  (Spine / NATS)  |
 | (sandbox)| | (sandbox)  |  |  append-only     |
 +-----------+ +------------+  +------------------+
```

**Key trust properties:**

- Agent never communicates with Tool Servers directly.
- Tool Servers cannot communicate with each other.
- The Kernel is the sole nexus: signing key, policy, all connections.
- The CA may be offline (pre-issued tokens) or online.

### 1.5 Trust Model Comparison with MCP

| Property | MCP | PACT |
|----------|-----|------|
| Agent <-> Server communication | Direct (stdio/HTTP) | Mediated by Kernel (never direct) |
| Server isolation | None (shared process or sibling) | Per-server sandbox (namespaces, separate user) |
| Authentication | None or bearer token | mTLS + SPIFFE / signed manifests |
| Authorization | None (all tools available) | Capability tokens per-tool |
| Attestation | None | Ed25519 signed receipts in Merkle log |
| Policy enforcement | None at protocol level | Kernel evaluates guards before forwarding |
| Tool discovery | Server advertises all tools | Capability tokens enumerate allowed tools |

---

## 2. Capability Model

### 2.1 Capability Token Structure

A PACT capability token is a signed, self-describing, attenuatable
authorization to invoke a specific set of tool operations. Inspired by
macaroons and Biscuit tokens, but uses ClawdStrike's Ed25519 + canonical
JSON signing infrastructure.

```
PactCapability {
    // Header
    capability_id:  String,          // UUIDv7 (time-ordered)
    schema:         "pact.capability.v1",
    issued_at:      DateTime<Utc>,
    expires_at:     DateTime<Utc>,
    not_before:     Option<DateTime<Utc>>,

    // Issuer chain
    issuer:         AgentId,         // CA or delegating agent
    subject:        AgentId,         // Agent authorized to use this token
    audience:       "pact:kernel",   // Expected verifier

    // Scope (what the token authorizes)
    scope: PactScope {
        tools: Vec<ToolGrant>,       // Which tools, which operations
        max_invocations: Option<u32>,// Total call count budget
        max_bytes_out:   Option<u64>,// Bandwidth ceiling
        resource_constraints: Option<ResourceConstraints>,
    },

    // Attenuation
    ceiling:        Option<PactScope>,   // Maximum privilege for re-delegation
    delegation_chain: Vec<String>,       // Parent capability IDs (append-only)
    delegation_depth: u32,               // Current depth (0 = root)
    max_delegation_depth: Option<u32>,   // Hard cap

    // Binding (prevents stolen tokens)
    proof_binding:  Option<ProofBinding>,// DPoP, mTLS thumbprint, or SPIFFE

    // Policy (what was verified at issuance)
    policy_hash:    String,          // SHA-256 of the verified policy
    attestation_level: AttestationLevel, // Logos verification depth

    // Context
    purpose:        Option<String>,
    metadata:       Option<serde_json::Value>,
}
```

A `ToolGrant` specifies access to a single tool:

```
ToolGrant {
    server_id:  String,              // Tool server identity
    tool_name:  String,              // Specific tool (or "*" for all on server)
    operations: Vec<String>,         // "invoke", "describe", "schema"
    argument_constraints: Option<ArgumentConstraints>,
    // e.g., file_patterns: ["src/**"], hosts: ["api.example.com"]
}
```

### 2.2 Token Lifecycle

```
 Capability Authority (CA)
        |
        | (1) Issue: CA signs PactCapability
        |     - Validates agent identity
        |     - Checks policy allows requested scope
        |     - Sets TTL (short: 60s-3600s)
        |     - Optionally binds to proof (DPoP key)
        v
 +------+------+
 |    Agent     |  Holds token as opaque signed blob
 +------+------+
        |
        | (2) Present: Agent sends token + tool call request
        |     to Kernel over anonymous channel
        v
 +------+------+
 |   Kernel     |  Validates:
 |              |  a. Signature (against CA public key)
 |              |  b. Time bounds (not expired, not before)
 |              |  c. Scope (requested tool in token's ToolGrant list)
 |              |  d. Revocation (check revocation store)
 |              |  e. Proof binding (if required, verify DPoP/mTLS)
 |              |  f. Invocation budget (decrement counter)
 |              |  g. Policy guards (run HushEngine)
 +------+------+
        |
        | (3) If all checks pass: forward to Tool Server
        | (4) If any check fails: deny, sign denial receipt
        v
    [Tool Server or Denial]
```

### 2.3 Capability Acquisition

An agent acquires capabilities through one of three paths:

**Path A: Direct issuance.** The deployment configuration pre-authorizes a
set of tool grants for an agent. At session start, the Kernel requests
capabilities from the CA on the agent's behalf. The agent receives tokens
through its input channel. The agent never contacts the CA.

**Path B: On-demand request.** The agent sends a `pact.request_capability`
message to the Kernel, describing the tools it needs. The Kernel validates
the request against policy, forwards it to the CA, and returns the issued
token (or a denial). The agent cannot request capabilities that exceed what
policy allows.

**Path C: Delegation.** Agent A delegates a subset of its capability to
Agent B by constructing a new PactCapability with:
- `delegation_chain` = A's chain + A's capability_id
- `scope` that is a subset of A's scope
- `expires_at` <= A's expires_at
- `ceiling` = A's effective ceiling
- Signed by A's key (not the CA)

The Kernel verifies the entire delegation chain back to a CA-issued root.

### 2.4 Attenuation

Attenuation is monotonically restrictive. A delegated capability can only
narrow, never widen:

- **Scope reduction:** Remove tools, restrict operations, tighten argument
  constraints.
- **Time reduction:** Shorter TTL (expires_at <= parent's expires_at).
- **Budget reduction:** Lower max_invocations, lower max_bytes_out.
- **Depth limits:** max_delegation_depth prevents unbounded chains.

The `ceiling` field records the maximum privileges available for further
delegation. When a token is delegated, its `cap` (granted capabilities)
must be a subset of the ceiling. The ceiling itself can only be narrowed.

Enforced via ClawdStrike's
`DelegationClaims::validate_redelegation_from`, which checks
`is_capability_subset(child.cap, parent.effective_ceiling())`.

### 2.5 Revocation

Four-layer revocation strategy:

1. **Short TTL (primary).** Default capability lifetime is 300 seconds.
   Maximum is 3600 seconds. Short-lived tokens naturally expire, limiting
   the window of misuse.

2. **Explicit revocation (supplementary).** The CA maintains a revocation
   store (in-memory or SQLite-backed, implementing ClawdStrike's
   `RevocationStore` trait). The Kernel checks revocation status on every
   capability presentation.

3. **Cascade revocation.** When a root capability is revoked, all
   capabilities in its delegation chain are implicitly revoked. The Kernel
   checks every entry in `delegation_chain` against the revocation store.
   If any ancestor is revoked, the descendant is rejected.

4. **Revocation propagation.** For distributed deployments, revocation
   events are published as Spine envelopes on a dedicated NATS subject.
   Kernels subscribe and update their local revocation caches.

### 2.6 Preventing the Confused Deputy Problem

The confused deputy problem occurs when a trusted component is tricked
into misusing its authority on behalf of an untrusted requestor. PACT
prevents this through capability designation:

- The capability token is the **sole authority** to invoke a tool. There
  is no ambient authority. The Kernel does not have a "default allow" mode.
- The token names the specific tool, operation, and argument constraints.
  The Kernel matches the actual request against the token's scope.
  A mismatch is a hard deny.
- The token is bound to a specific subject (agent identity). A different
  agent cannot use a stolen token (proof binding via DPoP or mTLS
  further strengthens this).
- The Kernel does not act on its own authority. It acts only when presented
  with a valid capability from a requestor. The Kernel is not a deputy;
  it is a validator.

### 2.7 Proof Binding (DPoP)

The `proof_binding` field in a capability token prevents a stolen token
from being used by a different agent. PACT uses Demonstration of
Proof-of-Possession (DPoP), adapted from RFC 9449 for Ed25519.

**Keypair generation.** At session start, the agent generates an
ephemeral Ed25519 keypair. The public key is sent in the `pact.hello.v1`
handshake (Section 4.0). The CA binds issued capabilities to this public
key by setting `proof_binding.subject_key` to the agent's session
public key.

```
ProofBinding {
    mode:        "dpop",
    subject_key: String,    // Hex-encoded Ed25519 public key
}
```

**Proof construction.** On every tool call, the agent signs a DPoP proof
demonstrating possession of the private key for `subject_key`:

```
proof_payload = SHA-256(
    canonical_json(tool_call_request) ||
    capability_token_id              ||
    nonce                            ||
    timestamp
)

proof_signature = Ed25519_Sign(agent_private_key, proof_payload)
```

Where:
- `canonical_json(tool_call_request)` is the RFC 8785 canonical
  serialization of the tool call request body (excluding the `proof`
  field itself).
- `capability_token_id` is the `capability_id` from the presented
  capability token, encoded as UTF-8 bytes.
- `nonce` is a monotonically increasing u64 counter, encoded as 8 bytes
  in big-endian order. The counter starts at 0 for the first message in
  the session and increments by 1 for each subsequent message.
- `timestamp` is the ISO-8601 timestamp of the proof, encoded as UTF-8
  bytes.
- `||` denotes byte concatenation.

The agent includes the proof in the tool call request:

```json
{
  "proof": {
    "mode": "dpop",
    "signature": "0x<hex-encoded Ed25519 signature>",
    "nonce": 42,
    "issued_at": "2026-03-17T12:00:05Z"
  }
}
```

**Kernel verification.** The Kernel verifies the DPoP proof by:

1. Extract `subject_key` from `proof_binding`.
2. Reconstruct `proof_payload` using the same concatenation formula.
3. Verify Ed25519 signature against `subject_key` and `proof_payload`.
4. Check `nonce` > last seen nonce (reject replays).
5. Check `issued_at` within 30s clock skew tolerance.

Any failure produces `PACT_CAP_BINDING_FAILED`.

**Nonce monotonicity.** The Kernel tracks the highest nonce per session.
Nonces must be strictly increasing; replays are rejected. Counter
initialized to -1 (first valid nonce is 0), not persisted across
sessions.

**Session binding.** The ephemeral keypair is per-session, so a token
bound to one session's public key cannot be used in another, even if
unexpired. This provides sender-constraint without requiring mTLS
between agent and Kernel (typically a pipe or UDS, not TCP).

---

## 3. Privilege Separation

### 3.1 Kernel Isolation from the Agent

The Kernel is invisible to the agent. The agent interacts only with a
file descriptor (pipe, UDS) established at process creation. It does not
know:

- The Kernel's PID, port, or socket path.
- The Kernel's signing key.
- The policy being enforced.
- What other Tool Servers exist.

Implementation strategies (in order of increasing strength):

| Level | Mechanism | What it prevents |
|-------|-----------|-----------------|
| 1: Process | Kernel in a separate process, agent's FD table restricted | Agent cannot signal/ptrace the Kernel |
| 2: Namespace | Kernel in a separate PID + network namespace | Agent cannot discover Kernel via /proc or netstat |
| 3: User | Kernel runs as a different user, agent has no sudo | Agent cannot read Kernel's memory or key material |
| 4: Sandbox | Agent runs inside a seccomp-bpf / Landlock / Sandbox-exec policy | Agent cannot make unauthorized syscalls |
| 5: VM | Kernel in a microVM (Firecracker, gVisor) | Agent cannot escape even with a kernel exploit |

The receipt's `metadata.sandbox.enforcement_level` field (from
ClawdStrike's `SignedReceipt`) records which isolation level was active,
enabling verifiers to make trust decisions based on enforcement strength.

### 3.2 Tool Server Isolation

Each Tool Server runs in its own sandbox:

- **Separate process.** No shared address space with other Tool Servers.
- **Separate filesystem namespace.** Each Tool Server sees only its own
  root filesystem plus explicitly granted mounts.
- **No shared IPC.** No Unix sockets, shared memory segments, or named
  pipes between Tool Servers.
- **Network isolation.** Tool Servers are in separate network namespaces.
  They cannot reach each other over TCP/UDP. Only the Kernel can reach
  them (via the pre-established mTLS connection).
- **Resource limits.** CPU, memory, and I/O are cgroup-bounded per server.

This prevents a compromised Tool Server A from influencing Tool Server B
through shared context, side channels, or direct communication.

### 3.3 Communication Path Enforcement

```
Agent --[pipe/UDS]--> Kernel --[mTLS/UDS]--> Tool Server A
                          |
                          +--[mTLS/UDS]--> Tool Server B
                          |
                          +--[mTLS/HTTPS]--> Capability Authority
                          |
                          +--[Spine/NATS]--> Receipt Log
```

The agent has exactly one communication path: a unidirectional channel to
the Kernel. It cannot:

- Enumerate Tool Servers (it does not know their addresses).
- Communicate with the CA (the Kernel proxies capability requests).
- Read the Receipt Log (receipts are write-only from the Kernel's perspective).
- Communicate with other agents except through explicit delegation (which
  itself requires a capability token).

### 3.4 Agent Discovery Prevention

To prevent the agent from discovering the Kernel or Tool Servers:

1. **No environment variables** expose the Kernel's address. The pipe FD is
   inherited at exec time.
2. **`/proc/self/fd`** shows only the agent's own descriptors. In a PID
   namespace, `/proc` is remounted to hide other processes.
3. **Seccomp-bpf** blocks `ptrace`, `process_vm_readv`, `mount`,
   `pivot_root`, and network-related syscalls (socket, connect, bind) that
   could probe the host.
4. **Landlock** restricts filesystem access to the agent's working directory.
5. On macOS, the **Sandbox-exec** profile (the darwin-telemetry-bridge path)
   restricts network and process operations.

---

## 4. Tool Call Flow

### 4.0 Session Handshake (Version Negotiation)

Before any tool calls, the agent and Kernel must complete a version
negotiation handshake. This is the first message exchange after the
transport connection is established.

**Agent -> Kernel:**

```json
{
  "type": "pact.hello.v1",
  "supported_versions": ["1.0", "0.1"],
  "agent_id": "agent:my-assistant",
  "proof": {
    "mode": "dpop",
    "public_key": "0x...",
    "signature": "0x...",
    "nonce": 0,
    "issued_at": "2026-03-17T12:00:00Z"
  }
}
```

`supported_versions` is ordered by preference (most preferred first).
`proof` binds the session to the agent's ephemeral keypair (Section 2.7).

**Kernel -> Agent (success):**

```json
{
  "type": "pact.hello_ack.v1",
  "selected_version": "0.1",
  "kernel_id": "kernel:prod-us-east-1",
  "session_id": "sess-UUIDv7",
  "capabilities": ["tool_call", "delegate", "request_capability", "revoke"],
  "max_message_bytes": 16777216,
  "heartbeat_interval_ms": 30000
}
```

**Kernel -> Agent (no common version):**

```json
{
  "type": "pact.hello_error.v1",
  "error_code": "PACT_VERSION_MISMATCH",
  "supported_versions": ["0.1"],
  "message": "No common protocol version"
}
```

No common version: Kernel sends `pact.hello_error.v1` and closes.

**Version compatibility rules:**

- Minor increments (0.1 to 0.2): backward compatible. Unknown fields
  ignored. New optional fields may be added.
- Major increments (0.x to 1.x): may break wire format.
- Kernel selects highest mutually supported version.
- First message must be `pact.hello.v1` or Kernel sends
  `PACT_HANDSHAKE_REQUIRED` and closes.

### 4.1 Complete Sequence

```
Agent                     Kernel                    Tool Server        Receipt Log
  |                         |                           |                  |
  |  (1) ToolCallRequest    |                           |                  |
  |  + PactCapability token |                           |                  |
  |------------------------>|                           |                  |
  |                         |                           |                  |
  |                   (2) Validate capability:          |                  |
  |                    a. Deserialize signed envelope   |                  |
  |                    b. Verify CA signature           |                  |
  |                    c. Check not expired             |                  |
  |                    d. Check not-before              |                  |
  |                    e. Verify subject matches agent  |                  |
  |                    f. Check revocation store        |                  |
  |                    g. Verify delegation chain       |                  |
  |                    h. Verify proof binding (DPoP)   |                  |
  |                    i. Check invocation budget       |                  |
  |                    j. Match tool + operation        |                  |
  |                       against scope                 |                  |
  |                         |                           |                  |
  |                   (3) Evaluate policy guards:       |                  |
  |                    - ForbiddenPathGuard             |                  |
  |                    - EgressAllowlistGuard           |                  |
  |                    - ShellCommandGuard              |                  |
  |                    - SecretLeakGuard                |                  |
  |                    - McpToolGuard                   |                  |
  |                    - PromptInjectionGuard           |                  |
  |                    - SpiderSenseGuard               |                  |
  |                    - [custom WASM guards]           |                  |
  |                    - [async guards]                 |                  |
  |                         |                           |                  |
  |                   (4) [IF DENIED at step 2 or 3]    |                  |
  |                    Build denial receipt:            |                  |
  |                    - content_hash of request        |                  |
  |                    - verdict: {passed: false}       |                  |
  |                    - provenance + violations        |                  |
  |                    Sign with Kernel key             |                  |
  |  <-----(DenialResponse + signed denial receipt)-----|                  |
  |                         |---(append denial receipt)--------------->|   |
  |                         |                           |                  |
  |                   (5) [IF ALLOWED]                  |                  |
  |                    Forward request to Tool Server:  |                  |
  |                         |                           |                  |
  |                         | ToolInvocation {          |                  |
  |                         |   invocation_id,          |                  |
  |                         |   tool_name,              |                  |
  |                         |   arguments,              |                  |
  |                         |   argument_hash,          |                  |
  |                         |   kernel_nonce,           |                  |
  |                         | }                         |                  |
  |                         |-------------------------->|                  |
  |                         |                           |                  |
  |                         |                     (6) Execute tool         |
  |                         |                      - Run in sandbox       |
  |                         |                      - Enforce resource     |
  |                         |                        limits              |
  |                         |                           |                  |
  |                         |  ToolResult {             |                  |
  |                         |    invocation_id,         |                  |
  |                         |    result_hash,           |                  |
  |                         |    result,                |                  |
  |                         |    server_signature,      |                  |
  |                         |  }                        |                  |
  |                         |<--------------------------|                  |
  |                         |                           |                  |
  |                   (7) Sign receipt:                 |                  |
  |                    Receipt {                        |                  |
  |                      version: "1.0.0",             |                  |
  |                      receipt_id,                   |                  |
  |                      timestamp,                    |                  |
  |                      content_hash: SHA256(         |                  |
  |                        canonical(request +         |                  |
  |                        result)),                   |                  |
  |                      verdict: {passed: true},      |                  |
  |                      provenance: {                 |                  |
  |                        policy_hash,                |                  |
  |                        capability_id,              |                  |
  |                        tool_server_id,             |                  |
  |                        attestation_level,          |                  |
  |                        guard_results[],            |                  |
  |                      },                            |                  |
  |                      metadata: {                   |                  |
  |                        sandbox: {                  |                  |
  |                          enforced: true,           |                  |
  |                          enforcement_level,        |                  |
  |                        },                          |                  |
  |                        invocation: {               |                  |
  |                          tool_name,                |                  |
  |                          argument_hash,            |                  |
  |                          result_hash,              |                  |
  |                          server_signature,         |                  |
  |                        },                          |                  |
  |                        delegation_chain[],         |                  |
  |                      },                            |                  |
  |                    }                               |                  |
  |                    SignedReceipt::sign(receipt, kp) |                  |
  |                         |                           |                  |
  |  <---(ToolCallResponse + signed receipt)------------|                  |
  |                         |                           |                  |
  |                   (8) Append receipt to log         |                  |
  |                         |---(Spine envelope)------------------------->|
  |                         |                           |                  |
```

### 4.2 Message Types

**Request (Agent -> Kernel):**

```json
{
  "schema": "pact.tool_call.v1",
  "request_id": "req-UUIDv7",
  "capability": "<signed-capability-envelope>",
  "tool_name": "file_read",
  "arguments": { "path": "/app/src/main.rs" },
  "proof": {
    "mode": "dpop",
    "signature": "0x...",
    "nonce": "...",
    "issued_at": "2026-03-17T12:00:00Z"
  }
}
```

**Response (Kernel -> Agent):**

```json
{
  "schema": "pact.tool_result.v1",
  "request_id": "req-UUIDv7",
  "status": "allowed",
  "result": { "content": "fn main() { ... }" },
  "receipt": "<signed-receipt-json>"
}
```

**Denial (Kernel -> Agent):**

```json
{
  "schema": "pact.tool_result.v1",
  "request_id": "req-UUIDv7",
  "status": "denied",
  "reason": "capability_expired",
  "violations": [
    { "guard": "capability_validator", "severity": "error",
      "message": "Capability expired at 2026-03-17T11:55:00Z" }
  ],
  "receipt": "<signed-denial-receipt-json>"
}
```

### 4.3 Fail-Closed Guarantees

At every decision point, the default is denial:

| Failure Mode | Behavior |
|-------------|----------|
| Capability signature invalid | Deny |
| Capability expired | Deny |
| Capability revoked (including ancestor) | Deny |
| Tool not in capability scope | Deny |
| Guard evaluation error | Deny |
| Tool Server unreachable | Deny |
| Tool Server returns error | Return error to agent, sign receipt |
| Receipt signing fails | Deny (do not return result without receipt) |
| Revocation store unreachable | Allow with warning (1s timeout, see 9.4.2) |
| Policy load fails | Deny all (sticky config error, matching HushEngine) |
| Unknown message schema | Deny |
| Invalid UTF-8 in message | Deny, close connection |
| Message exceeds size limit | Deny, discard payload |
| Receipt Log unreachable (buffer full) | Deny all tool calls until drained |
| Tool Server stream interrupted | Sign incomplete receipt |
| No version handshake | Deny, close connection |

This follows ClawdStrike's fail-closed design where
`HushEngine::config_error` causes all subsequent checks to deny. The one
exception is revocation store unreachability: because capability tokens
have short TTLs (default 300s), the Kernel allows the call with a logged
warning rather than denying. See Section 9.4.2 for the rationale and
escalation behavior.

### 4.4 Streaming Results

Tool calls that produce streaming output (long-running processes, large
file reads, SSE-backed APIs) use chunk-based forwarding with a single
receipt at stream completion.

**Flow:**

```
Agent                     Kernel                    Tool Server
  |                         |                           |
  |  (1) ToolCallRequest    |                           |
  |  (standard, per 4.1)    |                           |
  |------------------------>|                           |
  |                         |                           |
  |                   (2-3) Validate capability +       |
  |                         evaluate guards (per 4.1)   |
  |                         |                           |
  |                   (4) Forward to Tool Server        |
  |                         |-------------------------->|
  |                         |                           |
  |                         |  ToolStreamChunk {        |
  |                         |    invocation_id,         |
  |                         |    chunk_index: 0,        |
  |                         |    chunk_hash,            |
  |                         |    data,                  |
  |                         |    final: false,          |
  |                         |  }                        |
  |                         |<--------------------------|
  |                         |                           |
  |  pact.tool_call.chunk.v1|                           |
  |  { request_id,          |                           |
  |    chunk_index: 0,      |                           |
  |    data }               |                           |
  |<------------------------|                           |
  |                         |                           |
  |                         |  (more chunks...)         |
  |                         |<--------------------------|
  |  (forwarded chunks...)  |                           |
  |<------------------------|                           |
  |                         |                           |
  |                         |  ToolStreamChunk {        |
  |                         |    chunk_index: N,        |
  |                         |    chunk_hash,            |
  |                         |    data,                  |
  |                         |    final: true,           |
  |                         |    server_signature,      |
  |                         |  }                        |
  |                         |<--------------------------|
  |                         |                           |
  |                   (5) Compute stream receipt:       |
  |                    content_hash = SHA-256(          |
  |                      chunk_hash[0] ||              |
  |                      chunk_hash[1] || ... ||       |
  |                      chunk_hash[N])                |
  |                    Sign receipt                     |
  |                         |                           |
  |  pact.tool_result.v1    |                           |
  |  { status: "allowed",   |                           |
  |    stream_complete: true,|                           |
  |    total_chunks: N+1,   |                           |
  |    receipt }             |                           |
  |<------------------------|                           |
```

The Kernel buffers chunk hashes (not chunk data) as they arrive. Each
chunk is forwarded to the agent as a `pact.tool_call.chunk.v1` message
immediately upon receipt. When the stream completes (the Tool Server
sends a chunk with `final: true`), the Kernel computes the content hash
as SHA-256 over the concatenation of all chunk hashes in order and signs
a single receipt covering the entire stream.

**Chunk message (Kernel -> Agent):**

```json
{
  "schema": "pact.tool_call.chunk.v1",
  "request_id": "req-UUIDv7",
  "chunk_index": 0,
  "data": "partial output...",
  "final": false
}
```

**Interrupted streams.** If the Tool Server disconnects, times out, or
sends an error before the final chunk, the Kernel signs a partial receipt:

```json
{
  "schema": "pact.tool_result.v1",
  "request_id": "req-UUIDv7",
  "status": "incomplete",
  "chunks_received": 3,
  "reason": "PACT_SERVER_STREAM_INTERRUPTED",
  "receipt": "<signed-receipt with decision: incomplete>"
}
```

The partial receipt includes:
- `verdict.decision`: `"incomplete"`
- `content_hash`: SHA-256 over the chunk hashes received so far
- `metadata.stream.chunks_expected`: null (unknown) or the total if
  the Tool Server declared it
- `metadata.stream.chunks_received`: actual count

Partial receipts are appended to the Receipt Log like any other receipt.

**Limits.** Maximum stream duration: 300s (configurable). Maximum total
stream size: 256 MiB (configurable). Exceeding either causes the Kernel
to terminate, sign an incomplete receipt, and return
`PACT_SERVER_STREAM_LIMIT`.

---

## 5. Tool Discovery and Trust

### 5.1 Capability-Driven Discovery

MCP tool discovery passes raw server descriptions to the LLM, creating
a prompt injection vector. PACT replaces this:

1. **Capability tokens enumerate what's allowed.** `ToolGrant` entries in
   the token name specific tools. The agent inspects its tokens.

2. **Tool schemas are signed** by the Tool Server and verified by the
   Kernel. Schemas are cached in the Tool Manifest.

3. **Descriptions are sanitized before reaching the LLM.** Raw text is
   replaced with structured, length-bounded summaries. The Kernel may
   run PromptInjectionGuard and SpiderSenseGuard on descriptions at
   manifest load time.

### 5.2 Tool Manifest

Each Tool Server publishes a signed manifest at startup:

```
ToolManifest {
    schema:     "pact.manifest.v1",
    server_id:  String,
    server_key: PublicKey,          // Ed25519 public key
    spiffe_id:  Option<String>,     // SPIFFE identity
    tools: Vec<ToolDefinition>,
    signed_at:  DateTime<Utc>,
    signature:  Signature,          // Over canonical JSON of above fields
}

ToolDefinition {
    name:        String,
    version:     String,
    description: String,            // Max 500 chars, validated at manifest verify
    input_schema: serde_json::Value,// JSON Schema for arguments
    output_schema: Option<serde_json::Value>,
    capabilities_required: Vec<HostCapability>,  // fs_read, network, etc.
    estimated_latency_ms: Option<u64>,
    idempotent:  bool,
    side_effects: Vec<String>,      // ["filesystem", "network", "database"]
}
```

The Kernel verifies the manifest signature at connection time. Failure
rejects the Tool Server entirely.

### 5.3 Tool Server Authentication

Tool Servers are authenticated via one or more mechanisms:

| Mechanism | When Used |
|-----------|-----------|
| **Signed manifest** | Always. Manifest signature verified against a pinned key or the Identity Registry |
| **mTLS** | When Tool Server connects over TCP. Both sides present certificates. The Kernel verifies the Tool Server's certificate chain |
| **SPIFFE** | In Kubernetes or mesh deployments. The Kernel verifies the Tool Server's SVID against the trust domain |
| **Process attestation** | When Tool Server is a local process. The Kernel verifies the binary hash matches a pinned value |

ClawdStrike's `TrustBundle` (Spine crate) configures which mechanisms
are required for a given deployment.

---

## 6. Multi-Agent Delegation

### 6.1 Delegation Model

PACT's delegation model extends ClawdStrike's `hush-multi-agent` crate.
When Agent A wants Agent B to have access to a subset of its tools:

```
Agent A (delegator)           Kernel              Agent B (delegatee)
    |                           |                       |
    | (1) DelegationRequest {   |                       |
    |   parent_capability,      |                       |
    |   subject: B,             |                       |
    |   scope: <subset>,        |                       |
    |   expires_at: <shorter>,  |                       |
    | }                         |                       |
    |-------------------------->|                       |
    |                           |                       |
    |                     (2) Kernel validates:         |
    |                      - A's parent cap is valid    |
    |                      - Requested scope is subset  |
    |                      - expires_at <= parent's     |
    |                      - delegation_depth < max     |
    |                      - Policy allows delegation   |
    |                           |                       |
    |                     (3) Kernel constructs child   |
    |                        PactCapability:            |
    |                      - issuer = A                 |
    |                      - subject = B               |
    |                      - scope = requested subset   |
    |                      - chain = A's chain + A's ID |
    |                      - ceiling = A's ceiling      |
    |                           |                       |
    |                     (4) A signs the child cap     |
    |  <----(sign challenge)----|                       |
    |  ----(signature)--------->|                       |
    |                           |                       |
    |                     (5) Kernel delivers to B      |
    |                           |----(child cap)------->|
    |                           |                       |
    |                     (6) Sign delegation receipt   |
    |                           |                       |
```

### 6.2 Receipt Chain

When Agent B uses a delegated capability, the receipt includes the full
provenance:

```json
{
  "receipt": {
    "provenance": {
      "delegation_chain": [
        { "capability_id": "cap-root-123", "issuer": "ca:authority", "subject": "agent:A" },
        { "capability_id": "cap-del-456",  "issuer": "agent:A",     "subject": "agent:B" }
      ],
      "delegation_depth": 1,
      "root_capability_id": "cap-root-123"
    }
  }
}
```

This creates an unbroken chain from B's action back through A's delegation
to the CA's original issuance. Auditors can trace any tool invocation to
the human or system that authorized it.

### 6.3 Revocation Cascade

Revoking any capability in a delegation chain revokes all descendants:

```
CA revokes cap-root-123
  -> Kernel checks B's cap-del-456
  -> delegation_chain contains "cap-root-123"
  -> Kernel queries revocation store for "cap-root-123"
  -> Found: revoked
  -> cap-del-456 is rejected
```

This reuses ClawdStrike's chain validation in
`SignedDelegationToken::verify_redelegated_from`, which verifies the parent
token before accepting the child.

### 6.4 Cross-Agent Audit

Every delegation and every delegated invocation produces a receipt. The
Receipt Log's Merkle tree includes both delegation receipts and invocation
receipts, enabling:

- **Delegation graph reconstruction:** Given any receipt, walk the
  delegation_chain to reconstruct who delegated what to whom.
- **Blast radius analysis:** Given a revoked capability, query the Receipt
  Log for all receipts referencing it in their delegation_chain.
- **Temporal analysis:** UUIDv7 capability IDs are time-ordered, so the
  delegation graph has a natural temporal ordering.

---

## 7. Formal Verification Surface

### 7.1 What Can Be Verified

PACT's core safety properties are mechanically verifiable. The
verification surface spans three layers, matching ClawdStrike's Logos
attestation levels:

| Property | Layer | Tool | Status |
|----------|-------|------|--------|
| **Capability monotonicity** | Token logic | Lean 4 | Provable |
| **Revocation completeness** | Token logic | Lean 4 | Provable |
| **Fail-closed guarantee** | Kernel state machine | Lean 4 + Logos | Provable |
| **Policy consistency** | Policy logic | Logos / Z3 | Existing |
| **Policy completeness** | Policy logic | Logos / Z3 | Existing |
| **Deny monotonicity (inheritance)** | Policy logic | Logos / Z3 | Existing |
| **Receipt chain integrity** | Cryptographic | Lean 4 | Provable |
| **Delegation graph acyclicity** | Token logic | Lean 4 | Provable |
| **Scope subsumption** | Token logic | Lean 4 | Provable |
| **Implementation correctness** | Rust code | Aeneas | Future |

### 7.2 Formal Properties

**Property 1: Capability Monotonicity.**
For any delegation chain C0 -> C1 -> ... -> Cn, for all i:
scope(C_{i+1}) is a subset of scope(C_i). Equivalently: delegation
can only attenuate, never amplify.

```lean
theorem capability_monotonicity (chain : DelegationChain) :
  ∀ i, i + 1 < chain.length →
    scope_subset (chain.get (i + 1)).scope (chain.get i).effective_ceiling = true
```

**Property 2: Revocation Completeness.**
If capability C is revoked at time t, then for all capabilities D
where C is in D.delegation_chain, and for all times t' >= t, the
Kernel rejects D at time t'.

```lean
theorem revocation_completeness (C D : Capability) (t t' : Timestamp)
  (h_revoked : revoked C t)
  (h_ancestor : C.id ∈ D.delegation_chain)
  (h_time : t' ≥ t) :
  kernel_rejects D t' = true
```

**Property 3: Fail-Closed.**
For any Kernel state s and any request r, if any validation step
returns an error, the Kernel produces a denial.

```lean
theorem fail_closed (s : KernelState) (r : Request) :
  (∃ step, step_fails s r step) →
    kernel_decision s r = Decision.Deny
```

**Property 4: Receipt Chain Integrity.**
For any receipt R in the Receipt Log, the content_hash in R equals
SHA256(canonical_json(request, result)), and the signature is valid
under the Kernel's public key.

```lean
theorem receipt_integrity (R : SignedReceipt) (kp : PublicKey) :
  R.verify kp →
    R.receipt.content_hash = sha256 (canonical_json R.receipt.content) ∧
    valid_signature kp (canonical_json R.receipt) R.signatures.signer
```

**Property 5: Delegation Graph Acyclicity.**
The delegation graph is a DAG. No capability can appear in its own
delegation chain.

```lean
theorem delegation_acyclicity (C : Capability) :
  C.id ∉ C.delegation_chain
```

### 7.3 Connection to ClawdStrike Verification

PACT extends ClawdStrike's verification stack:

- **Logos Layer 3 (normative):** The `clawdstrike-logos` crate compiles
  policies into Logos formulas and verifies consistency, completeness,
  and inheritance. PACT adds capability scope as a new atom domain: tool
  grants become permission atoms, capability ceilings become obligation
  atoms.

- **Z3 backend:** The `logos-z3` crate provides SMT-backed verification.
  PACT capability constraints (subset checking, time bound ordering) are
  expressible as Z3 assertions.

- **Attestation levels:** The 5-level attestation hierarchy (Heuristic ->
  Formula-Verified -> Z3-Verified -> Lean-Proved -> Implementation-Verified)
  carries into PACT. Capability tokens include their `attestation_level`,
  telling the verifier how deeply the issuing policy was checked.

- **Receipt metadata:** PACT receipts use `Receipt::merge_metadata` to
  embed verification reports via the
  `VerificationReport::to_receipt_metadata()` pattern.

---

## 8. Migration Path from MCP

### 8.1 MCP Adapter Architecture

Existing MCP servers can be wrapped in a PACT-compatible adapter without
modifying the server code:

```
                    PACT World                          MCP World

Agent --[PACT]--> Kernel --[mTLS]--> MCP Adapter --[stdio/HTTP]--> MCP Server
                                     (Tool Server)
```

The **MCP Adapter** is a PACT Tool Server that:

1. Connects to the MCP server via standard transport (stdio or SSE).
2. Translates `tools/list` into a signed PACT ToolManifest.
3. Translates `ToolInvocation` into MCP `tools/call`, forwards, returns.
4. Runs PromptInjectionGuard on tool descriptions before manifest inclusion.
5. Enforces argument size limits and output sanitization.

The MCP server runs inside the adapter's sandbox. It has no direct
communication channel to the agent or the Kernel. From the MCP server's
perspective, it is being called normally; from PACT's perspective, it is
a sandboxed tool implementation.

### 8.2 Adapter Configuration

```yaml
# pact-mcp-adapter.yaml
server_id: "mcp-adapter:github-tools"
upstream:
  transport: stdio
  command: ["npx", "-y", "@modelcontextprotocol/server-github"]
  env:
    GITHUB_TOKEN: "${GITHUB_TOKEN}"

security:
  # Scan MCP tool descriptions for prompt injection
  scan_descriptions: true
  injection_threshold: 0.7

  # Argument size limits
  max_argument_bytes: 65536

  # Output sanitization
  sanitize_output: true

  # Only expose these tools from the MCP server
  tool_allowlist:
    - "search_repositories"
    - "get_file_contents"
    - "create_pull_request"
```

### 8.3 MCP Client Migration

For MCP clients that want to speak PACT natively, the migration is
incremental:

**Level 1: Wrap.** Run the existing MCP client behind the MCP Adapter.
Zero code changes. The client gets capability-gated access to all its
existing MCP servers.

**Level 2: Add capability handling.** The client adds a
`pact.request_capability` call before each tool invocation. This requires
adding the PACT client library and changing the tool call flow from:
```
client -> mcp_server.tool_call(name, args)
```
to:
```
cap = kernel.request_capability(tool_name)
result = kernel.tool_call(cap, tool_name, args)
```

**Level 3: Native PACT.** The client drops MCP entirely and uses the PACT
client SDK. Tool Servers are native PACT servers with signed manifests.

### 8.4 SDK Support

PACT provides client SDKs in the same languages as ClawdStrike:

| Language | Package | Status |
|----------|---------|--------|
| Rust | `pact-client` | Core implementation |
| TypeScript | `@clawdstrike/pact` | Wraps WASM + native bindings |
| Python | `clawdstrike-pact` | Pure Python + native extension |
| Go | `clawdstrike-pact-go` | Pure Go |

Each SDK provides:
- Capability request/presentation
- Tool call marshaling
- Receipt verification
- Delegation helpers
- MCP adapter bindings

### 8.5 Framework Adapters

PACT provides framework adapters following ClawdStrike's adapter pattern:

| Framework | Adapter | Migration Path |
|-----------|---------|---------------|
| OpenAI SDK | `pact-openai` | Replace MCP server config with PACT Kernel config |
| Vercel AI SDK | `pact-vercel-ai` | Drop `experimental_toToolResultContent`, use PACT tool provider |
| LangChain | `pact-langchain` | Replace `Tool` base class with `PactTool` |
| Claude Code | `pact-claude` | Native integration via ClawdStrike adapter |

---

## 9. Wire Protocol Specification

### 9.1 Message Framing

All PACT messages are framed as:

```
[4 bytes: message length (big-endian u32)] [message bytes (canonical JSON)]
```

Maximum message size: 16 MiB (configurable). Messages exceeding the limit
are rejected and a denial receipt is generated.

### 9.2 Message Types

| Schema | Direction | Purpose |
|--------|-----------|---------|
| `pact.hello.v1` | Agent -> Kernel | Version negotiation, session start (Section 4.0) |
| `pact.hello_ack.v1` | Kernel -> Agent | Selected version, session parameters |
| `pact.hello_error.v1` | Kernel -> Agent | Version mismatch or handshake failure |
| `pact.request_capability.v1` | Agent -> Kernel | Request a new capability token |
| `pact.capability_response.v1` | Kernel -> Agent | Issued capability or denial |
| `pact.tool_call.v1` | Agent -> Kernel | Invoke a tool with capability |
| `pact.tool_call.chunk.v1` | Kernel -> Agent | Streaming result chunk (Section 4.4) |
| `pact.tool_result.v1` | Kernel -> Agent | Tool result, denial, or stream completion |
| `pact.delegate.v1` | Agent -> Kernel | Delegate capability to another agent |
| `pact.delegate_response.v1` | Kernel -> Agent | Delegation result |
| `pact.revoke.v1` | Agent -> Kernel | Request revocation of own capability |
| `pact.heartbeat.v1` | Kernel <-> Agent | Liveness check |
| `pact.tool_invocation.v1` | Kernel -> Tool Server | Execute a tool |
| `pact.tool_response.v1` | Tool Server -> Kernel | Tool execution result |
| `pact.manifest.v1` | Tool Server -> Kernel | Signed tool manifest |

All messages include a `request_id` (UUIDv7) for correlation and a
`timestamp` (RFC 3339) for ordering.

### 9.3 Error Codes

PACT errors use a hierarchical code taxonomy:

```
PACT_CAP_EXPIRED          - Capability has expired
PACT_CAP_REVOKED          - Capability has been revoked
PACT_CAP_SCOPE_MISMATCH   - Requested tool not in capability scope
PACT_CAP_SIGNATURE_INVALID - Capability signature verification failed
PACT_CAP_CHAIN_BROKEN     - Delegation chain verification failed
PACT_CAP_BUDGET_EXHAUSTED - Invocation budget exceeded
PACT_CAP_BINDING_FAILED   - Proof binding verification failed
PACT_GUARD_DENIED         - Policy guard denied the action
PACT_GUARD_ERROR          - Policy guard evaluation error (fail-closed)
PACT_SERVER_UNREACHABLE   - Tool server not available
PACT_SERVER_ERROR         - Tool server returned an error
PACT_SERVER_TIMEOUT       - Tool server did not respond in time
PACT_SCHEMA_UNKNOWN       - Unknown message schema version
PACT_POLICY_INVALID       - Policy failed to load
PACT_RECEIPT_SIGN_FAILED  - Receipt signing failed
PACT_VERSION_MISMATCH     - No common protocol version
PACT_HANDSHAKE_REQUIRED   - First message must be pact.hello.v1
PACT_MESSAGE_INVALID_UTF8 - Message contains invalid UTF-8
PACT_MESSAGE_TOO_LARGE    - Message exceeds maximum size limit
PACT_RECEIPT_LOG_FULL     - Receipt buffer full, cannot accept tool calls
PACT_SERVER_STREAM_INTERRUPTED - Tool server stream ended unexpectedly
PACT_SERVER_STREAM_LIMIT  - Stream exceeded duration or size limit
PACT_MTLS_TIMEOUT         - mTLS handshake with tool server timed out
```

### 9.4 Error Handling

Specifies the Kernel's behavior for each error scenario, including
timeouts, retry policy, and what the agent observes. Guiding principle:
fail-closed. Ambiguous or unexpected states result in denial.

**9.4.1 Timeouts**

| Operation | Default Timeout | Configurable | Notes |
|-----------|----------------|--------------|-------|
| mTLS handshake (Kernel to Tool Server) | 5s | Yes | Includes certificate exchange and verification |
| Revocation store check | 1s | Yes | Per-check, not cumulative |
| CA reachability (capability issuance) | 5s | Yes | Kernel retries once before failing |
| Tool Server response (request-response) | 30s | Yes | Per-deployment, per-tool override supported |
| Tool Server stream duration | 300s | Yes | Total wall-clock time for streaming results |
| Version handshake (`pact.hello.v1`) | 10s | No | Agent must complete handshake within this window |
| Heartbeat response | 30s | No | Matches heartbeat_interval_ms from hello_ack |

Timeouts measure from send to complete response. Streaming results are
the exception: each chunk resets a per-chunk inactivity timer (default
30s, configurable).

**9.4.2 Error Scenarios**

**Tool Server returns an error after capability check passes.**
The Kernel wraps it in `pact.tool_result.v1` with `status: "error"` and
`PACT_SERVER_ERROR`. Signs a receipt with `verdict.passed: false`,
`verdict.reason: "server_error"`. The server's error message goes in the
receipt's provenance for audit but is not forwarded to the agent. No
retry.

```json
{
  "schema": "pact.tool_result.v1",
  "request_id": "req-UUIDv7",
  "status": "error",
  "error_code": "PACT_SERVER_ERROR",
  "error_category": "tool_execution",
  "message": "Tool server returned an error during execution",
  "receipt": "<signed-receipt-json>"
}
```

**Receipt Log unreachable.**
The Kernel buffers receipts in memory (up to 1000) when the Receipt Log
is unreachable, flushing on a 5s interval. Tool calls continue during
buffering. At capacity, the Kernel denies all tool calls with
`PACT_RECEIPT_LOG_FULL` until drained, preserving the invariant that
every call has a corresponding receipt. Buffered receipts flush in order
on reconnect.

**CA unreachable during revocation check.**
If the revocation store is unreachable within the 1s timeout, the Kernel
treats the capability as **not revoked** and proceeds. This exception to
fail-closed is justified by short token TTLs (default 300s). The Kernel
logs `warn` and includes `revocation_check: "skipped"` in receipt
provenance. After 60 consecutive seconds unreachable, escalates to
`error` severity and may optionally switch to fail-closed revocation
per deployment configuration.

**Invalid UTF-8 in message.**
If any message contains bytes that are not valid UTF-8, the Kernel
rejects with `PACT_MESSAGE_INVALID_UTF8`, signs a denial receipt, and
closes the connection. The agent must establish a new session.

**Message exceeds size limit.**
If a message exceeds the maximum size (default 16 MiB, communicated in
`pact.hello_ack.v1` as `max_message_bytes`), the Kernel rejects it
with error code `PACT_MESSAGE_TOO_LARGE`, signs a denial receipt, and
discards the oversized payload. The connection remains open. The Kernel
reads and discards the remaining bytes of the framed message (as
indicated by the 4-byte length prefix) before accepting the next
message.

**Tool Server timeout.**
If the Tool Server does not respond within the configured timeout
(default 30s), the Kernel denies with `PACT_SERVER_TIMEOUT` and signs a
denial receipt. No retry. The mTLS connection is reset. Late responses
are discarded and logged.

**mTLS handshake timeout.**
If the mTLS handshake does not complete within 5s, the Kernel denies
with `PACT_MTLS_TIMEOUT`. No retry for the current request. Subsequent
requests to the same Tool Server attempt a fresh handshake.

**9.4.3 Agent-Visible Error Format**

Errors returned to the agent follow a consistent structure. Internal
details (stack traces, server-side error messages, internal IPs) are
never exposed. The agent sees:

- `error_code`: One of the `PACT_*` codes (Section 9.3).
- `error_category`: One of `capability`, `policy`, `tool_execution`,
  `transport`, `protocol`.
- `message`: Static description. No request-specific details.
- `receipt`: Signed denial receipt (for auditors, not agent debugging).

The receipt contains full diagnostic detail (guard violations, server
error messages, timeout durations) in its provenance and metadata fields,
intended for operators and auditors, not the agent.

---

## 10. Security Analysis

### 10.1 Threat Model

| Threat | MCP Vulnerable? | PACT Mitigation |
|--------|----------------|-----------------|
| Malicious agent calls privileged tool | Yes (all tools available) | Capability scope restricts to granted tools |
| Stolen tool credentials | Yes (server holds secrets) | Broker pattern: secrets never touch agent or tool server |
| Prompt injection via tool descriptions | Yes (raw text to LLM) | Descriptions signed, sanitized, injection-scanned |
| Compromised server A attacks server B | Yes (shared context) | Server isolation (namespaces, no IPC) |
| Agent discovers enforcement layer | Yes (sibling process) | Kernel in separate namespace, no discoverable address |
| Replay attack (reuse old tool call) | Yes (no nonces) | Capability TTL + nonce in proof binding |
| Capability escalation | N/A (no capabilities) | Monotonic attenuation, formal proof |
| Unaudited tool calls | Yes (no logging) | Every call produces a signed receipt in Merkle log |
| Policy bypass | Yes (no policy) | Guards run before every tool call, fail-closed |
| Man-in-the-middle | Yes (stdio, no auth) | mTLS between Kernel and Tool Servers |

### 10.2 Residual Risks

- **Side channels:** CPU cache timing between Kernel and Agent processes
  on the same host. Mitigated by VM isolation (Level 5).
- **Kernel compromise:** If the Kernel is compromised, all security
  guarantees are lost. Mitigated by minimal TCB, formal verification of
  Kernel logic, and hardware attestation (TPM-backed signing keys).
- **CA compromise:** A compromised CA can issue arbitrary capabilities.
  Mitigated by short TTLs, offline CA mode, and transparency logging of
  all issued capabilities.
- **Clock skew:** Capability time bounds depend on synchronized clocks.
  Mitigated by requiring NTP and including clock-skew tolerance in the
  Kernel's validation (configurable, default 30s).

---

## 11. Deployment Modes

### 11.1 Local Development

```
Agent process
  |
  +-- embedded Kernel (same process, library mode)
       |
       +-- Tool Servers as child processes (stdio)
       +-- In-memory CA (auto-issues capabilities)
       +-- In-memory Receipt Log
```

No isolation, but receipts are still generated and can be verified
offline.

### 11.2 Production (Single Host)

```
Agent (sandboxed, user: agent)
  |-- pipe
  v
Kernel (user: kernel, PID namespace)
  |-- UDS
  +-- Tool Server A (user: tool-a, namespace A)
  +-- Tool Server B (user: tool-b, namespace B)
  +-- CA (user: ca, co-located)
  +-- Receipt Log (NATS on localhost or remote)
```

### 11.3 Production (Distributed)

```
Agent (VM A)
  |-- TLS
  v
Kernel (VM B, Kubernetes pod)
  |-- mTLS
  +-- Tool Server A (Pod C, SPIFFE identity)
  +-- Tool Server B (Pod D, SPIFFE identity)
  +-- CA (Service E, HSM-backed signing)
  +-- Receipt Log (NATS cluster, Spine protocol)
```

---

## 12. Comparison Summary

| Dimension | MCP | PACT |
|-----------|-----|------|
| Trust model | Binary (installed = trusted) | Capability-based (token = authority) |
| Authorization | None | Per-tool, time-bounded, attenuatable tokens |
| Authentication | None or bearer | mTLS, SPIFFE, signed manifests |
| Isolation | None | Process, namespace, VM |
| Attestation | None | Ed25519 signed receipts, Merkle log |
| Policy enforcement | None | Guard pipeline, fail-closed |
| Formal verification | None | Logos + Z3 + Lean 4 |
| Tool discovery | Server advertisement | Capability enumeration |
| Description safety | Raw text to LLM | Signed, sanitized, injection-scanned |
| Multi-agent | Not supported | Delegation with monotonic attenuation |
| Revocation | Not supported | Short TTL + explicit revocation + cascade |
| Audit | Not supported | Receipt chain with Merkle proofs |
| Transport | stdio / HTTP SSE | Length-prefixed canonical JSON over pipe/mTLS |
| Migration from MCP | N/A | Adapter wraps existing MCP servers |

---

## Appendix A: Cryptographic Primitives

PACT reuses ClawdStrike's `hush-core` primitives:

| Primitive | Algorithm | Usage |
|-----------|-----------|-------|
| Signing | Ed25519 (ed25519-dalek) | Capabilities, receipts, manifests, envelopes |
| Hashing | SHA-256 | Content hashes, capability hashes, Merkle trees |
| Hashing | Keccak-256 | Ethereum attestation anchoring (optional) |
| Canonical serialization | RFC 8785 (JCS) | Deterministic JSON for cross-language signing |
| Merkle tree | RFC 6962 (CT) | Receipt log integrity, inclusion proofs |
| Key zeroization | ZeroizeOnDrop | Private key material cleared on drop |
| TPM binding | tpm2-tss | Hardware-backed signing keys (optional) |

## Appendix B: Relationship to ClawdStrike Crates

| PACT Component | ClawdStrike Crate | Relationship |
|----------------|-------------------|-------------|
| Capability tokens | `clawdstrike-broker-protocol` | Extends `BrokerCapability` with tool scope |
| Delegation | `hush-multi-agent` | Reuses `DelegationClaims`, `RevocationStore` |
| Receipt signing | `hush-core` | Reuses `Receipt`, `SignedReceipt`, `Keypair` |
| Guard pipeline | `clawdstrike` (engine) | Reuses `HushEngine`, all 13 built-in guards |
| Formal verification | `clawdstrike-logos`, `logos-ffi`, `logos-z3` | Extends with capability scope atoms |
| Audit log | `spine` | Reuses signed envelopes, checkpoints, NATS transport |
| Trust bundles | `spine::trust` | Reuses `TrustBundle` for Tool Server authentication |
| WASM guards | `clawdstrike-guard-sdk` | Plugin guards run inside Kernel's WASM sandbox |
| Tool manifests | New | New crate: `pact-manifest` |
| Kernel | New | New crate: `pact-kernel` (orchestrates the above) |
| MCP adapter | New | New crate: `pact-mcp-adapter` |

## Appendix C: Open Questions

1. **Capability token format:** Should PACT use its own signed JSON format
   (consistent with ClawdStrike) or adopt Biscuit tokens (which have
   built-in attenuation semantics and a Datalog authorization language)?
   The current design favors consistency with ClawdStrike's canonical JSON
   + Ed25519 stack, but Biscuit's offline attenuation is compelling.

2. **Bidirectional tool communication:** Some tools need to ask the agent
   for clarification mid-execution (MCP's "sampling" capability). PACT
   could support this via a `pact.tool_callback.v1` message, but this
   creates a re-entrant control flow that complicates the Kernel's state
   machine. This needs careful design.

3. **Capability caching:** Should the Kernel cache validated capabilities
   to avoid re-verifying on every call? Cache invalidation must respect
   revocation (TTL on cache entries <= revocation propagation latency).

4. **Multi-Kernel coordination:** In distributed deployments with multiple
   Kernels, how are invocation budgets (max_invocations) enforced across
   Kernels? Options: (a) partitioned budgets at issuance, (b) distributed
   counter via the CA, (c) approximate enforcement with reconciliation.

5. **Backward compatibility window:** How long should the MCP adapter be
   supported as a first-class migration path? Proposal: 18 months from
   PACT 1.0 GA.

---

## Appendix D: Receipt Financial Metadata (v2.0)

### D.1 FinancialReceiptMetadata Structure

When a tool invocation is governed by a `ToolGrant` that carries monetary
budget fields (`max_cost_per_invocation` or `max_total_cost`), the Kernel
attaches financial accounting data to the receipt under the `"financial"` key
inside `PactReceipt::metadata`.

```
FinancialReceiptMetadata {
    grant_index:         u32,              // Index of the matching grant in the capability scope
    cost_charged:        u64,              // Cost charged for this invocation (minor units)
    currency:            String,           // ISO 4217 code, e.g. "USD"
    budget_remaining:    u64,              // Remaining budget after this charge (minor units)
    budget_total:        u64,              // Total budget for this grant (minor units)
    delegation_depth:    u32,              // Depth of delegation chain at time of invocation
    root_budget_holder:  String,           // Agent ID of the root budget holder
    payment_reference:   Option<String>,   // Opaque reference for external settlement systems
    settlement_status:   String,           // "pending", "settled", or "failed"
    cost_breakdown:      Option<Value>,    // Optional itemized breakdown for audit
    attempted_cost:      Option<u64>,      // Populated only on denial receipts (budget exhausted)
}
```

The struct is serialized as the value under the `"financial"` key:

```json
{
  "financial": {
    "grant_index": 0,
    "cost_charged": 150,
    "currency": "USD",
    "budget_remaining": 850,
    "budget_total": 1000,
    "delegation_depth": 1,
    "root_budget_holder": "agent-root-001",
    "settlement_status": "pending"
  }
}
```

### D.2 Field Semantics

**`cost_charged` and `currency`.** All monetary values are expressed in the
smallest denomination of the currency (minor units). For USD, 1 dollar = 100
units (cents). For JPY, 1 yen = 1 unit. The `currency` field carries the ISO
4217 code. All monetary values within a single grant use the same currency;
mixing currencies within a grant is not permitted.

**`budget_remaining`.** Records the post-charge balance as seen by the Kernel
node that produced the receipt. In HA deployments, this is a best-effort
snapshot: if two nodes are briefly split-brain, each may independently approve
one invocation at up to `max_cost_per_invocation` before the LWW merge
propagates. Consumers must treat `budget_remaining` as advisory, not as a
strict balance guarantee.

**`settlement_status`.** Tracks external settlement state. Valid values are:
- `"pending"` -- charge recorded; external settlement has not yet confirmed.
- `"settled"` -- external settlement system confirmed the charge.
- `"failed"` -- settlement system reported a failure; charge may be reversed.

**`attempted_cost` (denial receipts).** When the Kernel denies an invocation
because it would exceed a budget limit, the receipt carries
`Decision::Deny` and `cost_charged` is 0. The `attempted_cost` field holds
the cost that would have been charged. This allows auditors to distinguish
budget-denial receipts from other denial reasons.

### D.3 When Financial Metadata Is Present vs Absent

Financial metadata is present when **all** of the following hold:

1. The matched `ToolGrant` in the capability has at least one of
   `max_cost_per_invocation` or `max_total_cost` set.
2. The tool call was evaluated against a monetary budget (either allowed or
   denied due to budget exhaustion).

Financial metadata is absent when:

- The matched `ToolGrant` has no monetary budget fields set.
- The receipt type is `ChildRequestReceipt` (child receipts do not carry
  financial metadata directly; costs are tracked at the parent tool-call level).
- The invocation was denied before reaching the budget-check step (e.g., due
  to a signature failure or revocation check).

---

## Appendix E: Receipt Query API (v2.0)

### E.1 Endpoint

```
GET /v1/receipts/query
Authorization: Bearer <service-token>
```

Returns a filtered, paginated list of tool receipts from the Kernel's receipt
store. All filter parameters are optional; omitting them returns all receipts.

### E.2 Query Parameters

All parameters use `camelCase` in the HTTP query string.

| Parameter      | Type    | Description |
|----------------|---------|-------------|
| `capabilityId` | string  | Filter by exact capability ID. |
| `toolServer`   | string  | Filter by exact tool server name. |
| `toolName`     | string  | Filter by exact tool name. |
| `outcome`      | string  | Filter by decision: `"allow"`, `"deny"`, `"cancelled"`, `"incomplete"`. |
| `since`        | u64     | Include only receipts with `timestamp >= since` (Unix seconds, inclusive). |
| `until`        | u64     | Include only receipts with `timestamp <= until` (Unix seconds, inclusive). |
| `minCost`      | u64     | Include only receipts with financial `cost_charged >= minCost`. Receipts without financial metadata are excluded when this filter is set. |
| `maxCost`      | u64     | Include only receipts with financial `cost_charged <= maxCost`. Receipts without financial metadata are excluded when this filter is set. |
| `agentSubject` | string  | Filter by agent subject public key (hex-encoded Ed25519). Resolved through capability lineage JOIN. |
| `cursor`       | u64     | Pagination cursor: return only receipts with `seq > cursor` (exclusive). |
| `limit`        | usize   | Maximum receipts per page. Capped at 200. Defaults to 50. |

All filters are applied with AND semantics. The `agentSubject` filter does not
replay issuance logs; it queries a precomputed capability lineage table.

### E.3 Response Format

```json
{
  "totalCount": 42,
  "nextCursor": 137,
  "receipts": [ ... ]
}
```

- `totalCount` -- total number of receipts matching the filters across all
  pages (independent of `limit` and `cursor`).
- `nextCursor` -- seq of the last receipt in this page, present when more
  results exist; absent on the last page. Pass this value as `cursor` to
  fetch the next page.
- `receipts` -- array of serialized `PactReceipt` objects for this page,
  ordered by `seq` ascending.

### E.4 Pagination Pattern

```
# Page 1 (no cursor)
GET /v1/receipts/query?limit=50

# Subsequent pages: pass nextCursor from previous response
GET /v1/receipts/query?limit=50&cursor=137
```

Pagination is forward-only. There is no backward cursor. The cursor is stable
as long as no receipts are deleted (the receipt store is append-only, so
cursors never become invalid).

---

## Appendix F: Receipt Checkpointing (v2.0)

### F.1 Purpose

Receipt checkpoints commit a batch of receipts to a Merkle tree and produce a
signed statement that can be used to prove inclusion of any receipt in the
batch without replaying the full log.

### F.2 KernelCheckpoint Format

```
KernelCheckpoint {
    body: KernelCheckpointBody {
        schema:           "pact.checkpoint_statement.v1",
        checkpoint_seq:   u64,    // Monotonic checkpoint counter
        batch_start_seq:  u64,    // First receipt seq in this batch
        batch_end_seq:    u64,    // Last receipt seq in this batch
        tree_size:        usize,  // Number of leaves in the Merkle tree
        merkle_root:      Hash,   // Root from MerkleTree::from_leaves
        issued_at:        u64,    // Unix seconds when checkpoint was issued
        kernel_key:       PublicKey, // Kernel's Ed25519 public key
    },
    signature: Signature,         // Ed25519 over canonical JSON of body
}
```

The `schema` field is a forward-compatibility guard. Verifiers must reject
checkpoints with unknown schema identifiers.

### F.3 Batch Trigger Conditions

Checkpoints are triggered by receipt count, not by time. A new checkpoint is
issued whenever the number of uncommitted receipts since the last checkpoint
reaches the configured `batch_size`. There is no time-based trigger. The
`batch_size` is configurable per Kernel deployment; the default is 100.

Implication: a low-traffic deployment that never accumulates `batch_size`
receipts will not emit checkpoints. This is intentional; an empty checkpoint
(with `tree_size = 0`) is not valid.

### F.4 Merkle Root Computation

Leaves are the canonical JSON bytes of each `PactReceipt` in the batch,
ordered by `seq` ascending. The tree is a standard binary Merkle tree using
SHA-256 at each node. The `merkle_root` in `KernelCheckpointBody` is the root
of this tree.

### F.5 Inclusion Proof Verification

A `ReceiptInclusionProof` establishes that a specific receipt was part of a
specific checkpoint batch:

```
ReceiptInclusionProof {
    checkpoint_seq:  u64,       // Which checkpoint this proof covers
    receipt_seq:     u64,       // Seq of the receipt being proved
    leaf_index:      usize,     // Index of this receipt in the Merkle leaf array
    merkle_root:     Hash,      // The root this proof is against
    proof:           MerkleProof, // Audit path
}
```

Verification procedure:

1. Fetch the `KernelCheckpoint` for `checkpoint_seq`.
2. Verify the checkpoint signature against `body.kernel_key`.
3. Confirm `proof.merkle_root == body.merkle_root`.
4. Call `proof.verify(canonical_json_bytes(receipt), expected_root)`.
5. All four steps must pass.

A verifier that trusts the Kernel's public key can confirm that a receipt is
authentic and was not added or removed from the log after the checkpoint was
issued.

---

## Appendix G: Nested Flow Receipts (v2.0)

### G.1 Overview

When an agent operation spawns sub-operations (for example, a sampling
operation or a resource fetch triggered inside a tool call), the Kernel
produces a `ChildRequestReceipt` for each nested operation in addition to the
top-level `PactReceipt`.

### G.2 ChildRequestReceipt Structure

```
ChildRequestReceipt {
    id:                 String,                  // UUIDv7 receipt ID
    timestamp:          u64,                     // Unix seconds
    session_id:         SessionId,               // Session that owns this flow
    parent_request_id:  RequestId,               // Request ID of the parent operation
    request_id:         RequestId,               // Request ID of this child operation
    operation_kind:     OperationKind,           // e.g. CreateMessage, GetPrompt, ReadResource
    terminal_state:     OperationTerminalState,  // Completed, Cancelled, or Incomplete
    outcome_hash:       String,                  // SHA-256 of canonical JSON of the outcome
    policy_hash:        String,                  // SHA-256 of the policy applied
    metadata:           Option<Value>,           // Optional audit metadata
    kernel_key:         PublicKey,               // Kernel's signing key
    signature:          Signature,               // Ed25519 over canonical JSON of all above
}
```

### G.3 Session, Parent, and Child Relationships

All receipts for a single agent session share the same `session_id`. The
`parent_request_id` links a child receipt to its parent operation. The
`request_id` is unique per child operation within the session.

A top-level `PactReceipt` does not carry a `parent_request_id`; it is the
root of the tree. `ChildRequestReceipt` always has a `parent_request_id`
pointing to an operation that exists in the same session.

The complete invocation tree for a session can be reconstructed by:

1. Starting from the `PactReceipt` for the top-level tool call.
2. Querying `GET /v1/receipts/children?sessionId=<id>` for all child receipts
   in the session.
3. Joining child receipts to parents via `parent_request_id`.

### G.4 Terminal States

`OperationTerminalState` has three values:

| State        | Meaning |
|--------------|---------|
| `Completed`  | The operation reached a successful final state. |
| `Cancelled`  | The operation was explicitly cancelled before completion. |
| `Incomplete` | The operation did not reach a terminal state (e.g., stream ended early). |

A child receipt is always written when an operation reaches a terminal state.
The Kernel never leaves an in-flight nested operation without a terminal
receipt; if the operation is interrupted, it receives `Incomplete`.

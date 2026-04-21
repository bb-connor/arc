# Chio Runtime Boundaries

This document records the ownership seams introduced in phase `180` so later
runtime work has a stable place to land and the largest entrypoints do not
quietly collapse back into monolithic shells.

## Ownership Map

| Surface | Runtime shell responsibility | Extracted boundary |
| --- | --- | --- |
| `crates/chio-cli/src/remote_mcp.rs` | hosted MCP session lifecycle, auth, edge routing, and transport orchestration | `crates/chio-cli/src/remote_mcp/admin.rs` owns remote admin routes, admin-only storage access, and session trust control handlers |
| `crates/chio-cli/src/trust_control.rs` | trust-service routing, issuance, registry operations, remote client entrypoints, and cluster coordination | `crates/chio-cli/src/trust_control/health.rs` owns health-report composition and cluster health projection; `crates/chio-cli/src/federation_policy.rs` owns the bounded federation-policy model; `crates/chio-cli/src/scim_lifecycle.rs` owns the bounded SCIM lifecycle model |
| `crates/chio-mcp-edge/src/runtime.rs` | `ChioMcpEdge` state machine, task orchestration, runtime event forwarding, and inbound loop control | `crates/chio-mcp-edge/src/runtime/protocol.rs` owns JSON-RPC shaping, task/result metadata, transport glue, pagination, and capability selection helpers |
| `crates/chio-kernel/src/lib.rs` | kernel policy flow, dispatch, receipt persistence, checkpoint triggering, and public crate surface | `crates/chio-kernel/src/receipt_support.rs` owns receipt hashing and metadata helpers; `crates/chio-kernel/src/request_matching.rs` owns session request tracking plus capability and constraint matching |

## Layering Rules

- `chio-cli` stays a shell. `crates/chio-cli/src/main.rs` re-exports runtime
  surfaces from `chio-hosted-mcp` and `chio-control-plane` instead of inlining
  additional giant modules.
- `chio-hosted-mcp` remains the owner of the remote MCP HTTP edge via
  `#[path = "../../chio-cli/src/remote_mcp.rs"]`.
- `chio-control-plane` remains the owner of the trust-control service via
  `#[path = "../../chio-cli/src/trust_control.rs"]`.
- `chio-mcp-edge` keeps protocol glue separate from the runtime loop so JSON-RPC
  behavior can change without widening the edge state machine.
- `chio-kernel` keeps receipt construction and request matching separate from
  the main kernel flow so policy and dispatch changes do not hide low-level
  security drift.

## Verified Core Boundary

The current bounded verified-core contract is defined machine-readably in
`formal/proof-manifest.toml`. It is intentionally narrower than the full Chio
runtime and names exactly which pure symbols can participate in the current
formal-evidence story.

### Covered Pure Core

| Rust surface | Why it is inside the current boundary |
| --- | --- |
| `chio_kernel_core::capability_verify::{verify_capability, verify_capability_with_trusted}` | pure issuer-trust, signature, and time-window checks over one in-memory capability |
| `chio_kernel_core::scope::{resolve_matching_grants, resolve_capability_grants}` | fail-closed portable scope matching over request arguments only |
| `chio_kernel_core::evaluate::evaluate` | pure authorization path that composes capability verification, subject binding, scope match, and sync guards |
| `chio_kernel_core::receipts::sign_receipt` | pure receipt-signing step over an already-constructed receipt body |

### Covered Shell Entry Points

| Shell surface | Covered part |
| --- | --- |
| `chio_kernel::ChioKernel::evaluate_portable_verdict` | direct delegation into `chio_kernel_core::evaluate` with trusted issuer and portable guard wiring |
| `chio_kernel::ChioKernel::build_and_sign_receipt` | direct delegation into `chio_kernel_core::sign_receipt` after the shell has assembled the receipt body |

### Explicit Exclusions

The current verified-core boundary does **not** cover:

- revocation-store lookups or receipt-store lineage joins
- budget mutation, payment authorization, or any metering state transition
- DPoP verification, nonce replay caches, or hosted/session transport admission
- governed transaction policy, approval-token flow, or runtime-attestation enforcement
- tool dispatch, subprocess effects, network effects, or remote MCP orchestration
- receipt persistence, checkpoint publication, trust-control clustering, or settlement rails

Those surfaces stay in the operational shell until a later formal phase names a
smaller normalized model and a corresponding refinement story.

## Regression Guard

`crates/chio-control-plane/tests/runtime_boundaries.rs` is the source-shape
guard for this boundary. It verifies:

- the extracted ownership files exist
- the main CLI entrypoint still re-exports hosted/control-plane crates
- the runtime shells stay below the line-count ceilings captured in phase `180`
- this document remains present as the human-readable ownership map

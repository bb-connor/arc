# Unsafe inventory

Lexical measurement of `unsafe` across the workspace's library crates, for the
owners who add `#![forbid(unsafe_code)]` and `// SAFETY:` comments. Measured on
2026-09-26 at integration `07e963e8f5` by blanking comments and string
literals, then matching `unsafe {`, `unsafe impl` and `unsafe fn` in every
tracked `.rs` and `.inc` file of each crate (fuzz sub-workspaces excluded). A
block or impl counts as documented when a line within the four above it, or the
same line before the keyword, contains `SAFETY:` in any case, which is what
`clippy::undocumented_unsafe_blocks` accepts; a comment placed further above a
multi-line statement is missed here and found by the lint, so the missing list
is an upper bound. `cargo clippy --workspace --all-targets -W
clippy::undocumented_unsafe_blocks` is the authoritative count.

## Library roots with no `unsafe` and no `#![forbid(unsafe_code)]` (41)

Each takes `#![forbid(unsafe_code)]` at the root; `forbid` so no inner `#[allow]` reopens it.

- `examples/bilateral-invocation/src/lib.rs:1` (bilateral-invocation)
- `crates/platform/chio-agent-web-interop/src/lib.rs:1` (chio-agent-web-interop)
- `crates/sdk/chio-binding-helpers/src/lib.rs:1` (chio-binding-helpers)
- `crates/core/chio-bounded/src/lib.rs:1` (chio-bounded)
- `crates/platform/chio-commerce-order/src/lib.rs:1` (chio-commerce-order)
- `crates/tooling/chio-conformance/src/lib.rs:1` (chio-conformance)
- `crates/core/chio-core-types/src/lib.rs:1` (chio-core-types)
- `crates/guards/chio-data-guards/redactors/default/src/lib.rs:1` (chio-data-guards-redactors-default)
- `crates/trust/chio-disclosure-lineage/src/lib.rs:1` (chio-disclosure-lineage)
- `tests/e2e/src/lib.rs:1` (chio-e2e)
- `crates/platform/chio-enterprise-export/src/lib.rs:1` (chio-enterprise-export)
- `examples/guards/enriched-inspector/src/lib.rs:1` (chio-example-enriched-inspector)
- `examples/guards/tool-gate/src/lib.rs:1` (chio-example-tool-gate)
- `crates/trust/chio-federation-transport-iroh/src/lib.rs:1` (chio-federation-transport-iroh)
- `crates/platform/chio-finding-market-store-postgres/src/lib.rs:1` (chio-finding-market-store-postgres)
- `crates/platform/chio-finding-worker/src/lib.rs:1` (chio-finding-worker)
- `crates/security/chio-flow/src/lib.rs:1` (chio-flow)
- `formal/diff-tests/src/lib.rs:1` (chio-formal-diff-tests)
- `crates/products/chio-mercury-core/src/lib.rs:1` (chio-mercury-core)
- `crates/products/chio-proof-room/src/lib.rs:1` (chio-proof-room)
- `crates/security/chio-quarantine/src/lib.rs:1` (chio-quarantine)
- `crates/tooling/chio-reference-tools/src/lib.rs:1` (chio-reference-tools)
- `crates/platform/chio-risk-comptroller/src/lib.rs:1` (chio-risk-comptroller)
- `crates/security/chio-security-types/src/lib.rs:1` (chio-security-types)
- `crates/trust/chio-signing-remote/src/lib.rs:1` (chio-signing-remote)
- `crates/core/chio-supervisor/src/lib.rs:1` (chio-supervisor)
- `crates/kernel/chio-swarm-authority/src/lib.rs:1` (chio-swarm-authority)
- `examples/chio-3vendor/src/lib.rs:1` (chio-three-vendor-example)
- `crates/tooling/chio-trace-validate/src/lib.rs:1` (chio-trace-validate)
- `crates/platform/chio-transaction-passport/src/lib.rs:1` (chio-transaction-passport)
- `crates/platform/chio-trust-market-context/src/lib.rs:1` (chio-trust-market-context)
- `crates/tooling/chio-conformance/verdict_matrix/drivers/lambda/src/lib.rs:1` (chio-verdict-matrix-driver-lambda)
- `crates/guards/chio-wasm-guards/src/lib.rs:1` (chio-wasm-guards)
- `crates/economy/chio-web3-bindings/src/lib.rs:1` (chio-web3-bindings)
- `crates/platform/chio-workflow-preflight/src/lib.rs:1` (chio-workflow-preflight)
- `examples/cross-provider-policy/src/lib.rs:1` (cross-provider-policy)
- `examples/hello-a2a/src/lib.rs:1` (hello-a2a)
- `examples/hello-acp/src/lib.rs:1` (hello-acp)
- `examples/hello-mcp/src/lib.rs:1` (hello-mcp)
- `examples/hello-tool/src/lib.rs:1` (hello-tool)
- `integrations/editors/zed-chio/src/lib.rs:1` (zed-chio)

### Roots that `deny` rather than `forbid` (2)

- `crates/kernel/chio-kernel-browser/src/lib.rs:1` (chio-kernel-browser): `deny` can be reopened by an inner `#[allow]`; use `forbid`
- `crates/kernel/chio-kernel-core/src/lib.rs:1` (chio-kernel-core): `deny` can be reopened by an inner `#[allow]`; use `forbid`

## Crates with `unsafe` (16)

These are the crates the Miri list classifies (docs/security/toolchain/miri-crates.md). Blocks, impls and `unsafe fn` items, and the blocks or impls with no `SAFETY:` comment within reach.

| Crate | Blocks | Impls | `unsafe fn` | Missing `SAFETY:` |
| --- | --- | --- | --- | --- |
| `chio-active-response-authority` | 3 | 0 | 0 | 0 |
| `chio-attest-verify` | 0 | 1 | 0 | 1 |
| `chio-bindings-ffi` | 4 | 0 | 0 | 0 |
| `chio-cage` | 110 | 0 | 0 | 0 |
| `chio-control-plane` | 8 | 0 | 0 | 0 |
| `chio-cpp-kernel-ffi` | 3 | 0 | 0 | 0 |
| `chio-guard-sdk` | 8 | 0 | 1 | 5 |
| `chio-guard-sdk-macros` | 1 | 0 | 0 | 1 |
| `chio-hosted-mcp` | 4 | 0 | 0 | 0 |
| `chio-kernel` | 6 | 0 | 0 | 5 |
| `chio-kernel-mobile` | 1 | 0 | 0 | 0 |
| `chio-keyring` | 6 | 0 | 0 | 1 |
| `chio-mcp-edge` | 0 | 1 | 0 | 0 |
| `chio-secret-broker` | 15 | 0 | 3 | 0 |
| `chio-secure-ipc` | 6 | 0 | 1 | 0 |
| `chio-sqlite-file-identity` | 5 | 0 | 0 | 0 |

## Blocks and impls without a `SAFETY:` comment (13: 7 in production files, 6 in test files)

Each line is one comment to write, stating the invariant that makes the block sound, not the mechanism. Under `-D warnings` with the lint at `deny`, every one of these fails the build.

### chio-attest-verify (1)

- `crates/trust/chio-attest-verify/tests/policy_loader.rs:57` unsafe impl (test scope)

### chio-guard-sdk (5)

- `crates/sdk/chio-guard-sdk/src/glue.rs:280` unsafe block
- `crates/sdk/chio-guard-sdk/src/glue.rs:289` unsafe block
- `crates/sdk/chio-guard-sdk/src/glue.rs:294` unsafe block
- `crates/sdk/chio-guard-sdk/src/host.rs:112` unsafe block
- `crates/sdk/chio-guard-sdk/src/host.rs:168` unsafe block

### chio-guard-sdk-macros (1)

- `crates/sdk/chio-guard-sdk-macros/src/lib.rs:194` unsafe block

### chio-kernel (5)

- `crates/kernel/chio-kernel/tests/loom_concurrency.rs:1043` unsafe block (test scope)
- `crates/kernel/chio-kernel/tests/loom_concurrency.rs:1052` unsafe block (test scope)
- `crates/kernel/chio-kernel/tests/loom_concurrency.rs:1053` unsafe block (test scope)
- `crates/kernel/chio-kernel/tests/loom_concurrency.rs:1057` unsafe block (test scope)
- `crates/kernel/chio-kernel/tests/loom_concurrency.rs:1058` unsafe block (test scope)

### chio-keyring (1)

- `crates/security/chio-keyring/src/lib.rs:623` unsafe block

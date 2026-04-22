# AGENTS.md

## What is Chio?

Chio (Chio) is a protocol for secure, attested tool access in AI agent systems. It replaces MCP with a ground-up design built on capability-based security, cryptographic attestation, and privilege separation.

Chio is the protocol layer. ClawdStrike is the policy engine that plugs into the Chio kernel as the guard evaluation backend.

## Five Components

1. **Agent** -- untrusted LLM-powered process that consumes tools
2. **Runtime Kernel** -- trusted mediator (TCB) that validates capabilities, runs guards, signs receipts
3. **Tool Servers** -- sandboxed processes that implement tools, isolated from each other
4. **Capability Authority** -- issues and revokes time-bounded capability tokens
5. **Receipt Log** -- append-only Merkle-committed log of signed attestations

## Crate Map

| Crate | Purpose |
|-------|---------|
| `chio-core` | Shared types: capabilities, scopes, grants, receipts, canonical JSON, signing |
| `chio-kernel` | Runtime kernel: capability validation, guard pipeline, receipt signing |
| `chio-manifest` | Tool server manifest format: tool definitions, signing, verification |
| `chio-mcp-adapter` | Wraps existing MCP servers as Chio tool servers |
| `hello-tool` | Example tool server (in `examples/`) |

## Build and Test

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

## Conventions

- **Fail-closed**: errors during evaluation deny access. Invalid policies reject at load time.
- **Clippy**: `unwrap_used = "deny"`, `expect_used = "deny"` in all crates.
- **Serialization**: canonical JSON (RFC 8785) for all signed payloads.
- **Commit messages**: conventional commits (`feat:`, `fix:`, `docs:`, `test:`, etc.).
- **No em dashes** in code comments or documentation.

## Key Files

- Protocol spec: `spec/PROTOCOL.md`
- Core types: `crates/chio-core/src/lib.rs`
- Kernel: `crates/chio-kernel/src/lib.rs`
- Manifest: `crates/chio-manifest/src/lib.rs`
- MCP adapter: `crates/chio-mcp-adapter/src/lib.rs`

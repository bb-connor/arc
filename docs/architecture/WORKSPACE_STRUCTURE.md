# Workspace Structure

`v2.4` leaves the workspace flat, but the layers are no longer meant to be
flat in responsibility.

## Intended Layers

### Domain and protocol core

- `pact-core`
- `pact-manifest`
- `pact-did`
- `pact-guards`
- `pact-policy`
- `pact-reputation`
- `pact-credentials`

These crates should stay free of CLI/server-framework concerns. They can depend
on protocol, crypto, serde, and other pure libraries, but they should not
depend on `pact-cli`, `pact-control-plane`, `pact-hosted-mcp`, or direct
transport/server libraries such as `clap`, `axum`, or `reqwest`.

### Enforcement and persistence

- `pact-kernel`
- `pact-store-sqlite`

`pact-kernel` owns enforcement contracts and runtime behavior. Concrete SQLite
storage belongs in `pact-store-sqlite`, not back in the kernel or the CLI.

### Adapter and edge layer

- `pact-mcp-edge`
- `pact-mcp-adapter`
- `pact-a2a-adapter`

These crates translate external protocols into the PACT runtime surface. They
can depend on runtime and transport libraries, but they should not pull CLI
command parsing inward.

### Service and operator layer

- `pact-control-plane`
- `pact-hosted-mcp`
- `pact-cli`

These crates own HTTP services, admin/runtime orchestration, and command
surfaces. They are allowed to depend on the lower layers; the reverse should
not happen.

## Guardrail

`./scripts/check-workspace-layering.sh` enforces the most important negative
dependency rules for the domain layer and is part of the workspace
qualification path.

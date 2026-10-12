# chio-a2a-adapter architecture

## Responsibility and boundary

Discovers A2A agent cards and exposes advertised skills as Chio tool-server calls.
It connects outbound JSON-RPC and HTTP+JSON requests to kernel dispatch.

Implemented outbound adapter with authentication, SSE handling, task operations,
and optional file-backed task tracking. Kernel admission, guards, and receipts
require mediated invocation through the kernel.

## Structure

`config.rs` defines configuration and credential builders.

`invoke.rs` implements `A2aAdapter` and `ToolServerConnection`.

`protocol.rs`, `mapping.rs`, and `discovery.rs` decode cards and map skills.

`auth.rs` and `transport.rs` own TLS, HTTP, redirect, and response handling.

`task_registry.rs` and its persistence module track task bindings.

`clock.rs`, `oauth_cache.rs`, `partner_policy.rs`, and `loaded_weights`
  support authority deadlines, token reuse, and partner restrictions.

## Data and control flow

Discovery validates configuration, fetches a card, selects an interface,
then constructs a validated manifest from projectable skills.

Invocation resolves authentication for the selected skill and builds an A2A
message. JSON-RPC and HTTP+JSON paths use the selected interface URL.

Streaming decodes SSE events into kernel chunks and updates task activity.
Optional task persistence records bindings needed for later task operations.

## Trust and invariants

HTTP helpers require egress authority for discovery, invocation, and token
exchange. The resolver checks addresses used by the connection; redirects
are manually checked before following. Body-bearing cross-origin redirects deny.

Response readers apply declared response ceilings. SSE parsing also has line
and event bounds. Credentials are filtered when redirects cross origins.

Agent-card fields and configuration keys do not establish remote signing
identity. Partner-policy checks apply only when a policy is configured.
The kernel remains responsible for capability checks and signed receipts.

## Dependencies

`chio-egress-contract` provides URL and response policy. `ureq`, `url`,
and TLS roots implement transport. `chio-manifest` validates projected tools;
`chio-kernel` supplies dispatch traits. Security clock types bound token reuse.

## Verification

Unit tests cover discovery, authentication, protocol boundaries, task lifecycle,
and kernel receipts. `tests/integration_smoke.rs` runs fake loopback A2A servers;
its helper can skip when loopback sockets are unavailable.

Run the focused crate suite from the workspace root:

```bash
cargo test -p chio-a2a-adapter
```

See the [README](README.md) for a minimal public API example and requirements.

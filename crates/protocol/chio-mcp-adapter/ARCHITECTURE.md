# Architecture

## Responsibility and boundary

`McpAdapter` owns an MCP transport and the server identity assigned by its host.
It translates tool discovery into a Chio manifest and maps invocation results.
`AdaptedMcpServer` implements the kernel's `ToolServerConnection` contract.
Resource and prompt providers connect the corresponding MCP operations to Chio.
The adapter also reexports shared edge APIs through its `edge` module.

Calling `McpAdapter::invoke` directly delegates to the transport.
Capability validation, guard evaluation, and receipt signing require the host
kernel's dispatch path. `McpAdapter::new` accepts custom transports without
establishing native launch evidence or authenticating discovered metadata.

## Structure

- `adapter` implements adapter configuration and shared transport serialization.
- `server` implements kernel registration, invocation, and cost metadata lookup.
- `manifest` projects tools and compares discovery with admitted manifests.
- `transport` implements stdio, writer ownership, deadlines, and nested flows.
- `native` builds in-process tools, resources, and prompts with handlers.
- `resources` and `prompts` implement kernel-facing provider adapters.
- `loaded_weights` reports that native loaded model bytes are unavailable.
- `result_mapping`, `errors`, and `url_elicitation` translate protocol outcomes.
- `framing` supplies test/fuzz decoding; `fuzz` is feature gated.

## Data and control flow

A subprocess host supplies `CageRequiredLaunch` to `McpAdapter::from_command`.
The timeout-aware constructor checks the launch server ID, spawns the transport,
and requires fully enforced evidence and a persisted enforcement receipt.
Transport startup performs the MCP initialize handshake.
A caller-provided transport can instead be passed to `McpAdapter::new`.

`generate_manifest` lists upstream tools, projects schemas and safety hints,
and calls `chio_manifest::validate_manifest`.
`AdaptedMcpServer::new` retains this discovery-derived manifest.
`new_with_manifest_registry` matches that surface against an admitted manifest
and retains the publisher's security sidecars for kernel use.
Construction failures shut down the adapter and retain shutdown failures.

Kernel invocation enters `AdaptedMcpServer`, which forwards dispatch identity
through `invoke_in_context` and maps MCP content and structured content.
The default `McpTransport::call_tool_in_context` falls back to plain invocation;
custom transports must implement contextual delivery when it is required.
`SerializedMcpTransport` gates upstream calls for shared owners.
Shutdown bypasses that gate so the underlying transport can cancel active work.

## Trust and invariants

Projection requires input and optional output schemas to be JSON objects.
Missing read-only hints, malformed booleans, and destructive hints produce
side-effecting tools requiring approval in the generated manifest.
Discovery matching checks schema, server identity, display metadata, key,
tool count, descriptions, schemas, and projected safety annotations.
The matcher requires admitted `server_tools` to be empty.
It does not verify a signature itself; registry admission owns that check.

Native constructors require cage authorization and terminal evidence custody.
Stdio transport owns bounded frames, buffered-message accounting, request
deadlines, cancellation, and removal of Chio credential environment variables.
Those guarantees apply to the supplied stdio implementation.
The public transport trait permits other implementations with different I/O.
Notification-drain gate failures are logged and return an empty list.

## Dependencies

`chio-mcp-edge` supplies transport types and edge contracts.
`chio-manifest` validates surfaces and retains admitted security metadata.
`chio-kernel` supplies invocation and provider interfaces.
`chio-cage` supplies native launch enforcement; core and security types carry
identities, receipts, and clocks. Tokio supports transport execution, while
Serde, JSON, URL, Chrono, and tracing support protocol data and diagnostics.

## Verification

Run `cargo test -p chio-mcp-adapter` for unit and integration tests.
`src/tests.rs` checks safety hints, schema shape, manifest projection, and results.
`src/manifest.rs` tests discovery matching and admitted-sidecar handling.
Transport tests cover frame bounds, nested callbacks, deadlines, and writer races.
`tests/integration_smoke.rs` uses an in-memory edge as an MCP peer and exercises
manifest discovery plus a tool call through real JSON-RPC envelopes.
These tests establish the exercised adapter paths and controlled peer behavior.
The deployment host must validate its cage, policy, stores, and upstream peer.

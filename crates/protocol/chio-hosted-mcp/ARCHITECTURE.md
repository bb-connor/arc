# Architecture

## Responsibility and boundary

`chio-hosted-mcp` is a public facade for hosted MCP runtime setup.
It reexports control-plane helpers and the remote HTTP service entrypoint.
Its public surface is defined by `src/lib.rs`; there are no private service
modules, transport implementations, or session state machines in this crate.
The facade allows downstream hosts to import setup and serving APIs together.

`serve_http` and `RemoteServeHttpConfig` come from `chio-mcp-remote`.
`CliError` comes from `chio-control-plane`.
Authority, policy, storage, federation, and trust-control helpers also come
from the control-plane dependency. Their implementations own their checks.

## Structure

The library contains two explicit reexport groups.
The control-plane group includes kernel construction, authority-key loading
and rotation, capability issuance, budget/receipt/revocation store setup,
enterprise federation, policy, and trust-control modules.
The remote group includes the blocking server function and configuration type.

The Cargo manifest declares only these two normal dependencies.
There are no declared Cargo features or facade-specific default feature effects.
`tests/facade.rs` checks that the normal dependency list retains this boundary.
The crate forbids unsafe code and uses the workspace lint configuration.

## Data and control flow

A downstream host loads its policy and configures kernel/store authority using
reexported control-plane APIs where those helpers fit its setup.
It constructs `RemoteServeHttpConfig` with listener transport, authentication,
publisher-signed manifest admission, and native launch authority.
Calling `serve_http` enters the remote crate's implementation directly.
The facade does not intercept the configuration or construct a default one.

The remote implementation prepares listener transport, validates auth modes,
loads its admitted manifest, creates session ownership, and restores configured
persisted sessions before serving the installed HTTP routes.
It owns POST initialization, GET/SSE notification replay, DELETE closure,
and remote administrative routing.
Tool dispatch uses remote session workers and kernel-backed MCP edges.
Termination and shared-owner cleanup also remain in the remote implementation.

## Trust and invariants

This facade adds no validation or authority issuance of its own.
The control-plane functions enforce their documented file custody, policy,
store, key, and capability constraints at their own entrypoints.
The remote runtime enforces its transport, auth, manifest, launch, and session
checks when `serve_http` receives a fully configured service.
Callers must supply every required configuration field and independent keys.

A facade import does not establish a verified manifest or running kernel.
Persistent receipt, revocation, budget, and session behavior depends on the
configuration and successful setup in the owning implementations.
Durable remote resume requires the remote runtime's dedicated HMAC keyring.
Local authorization route code belongs to the remote implementation; the
protocol retains a distinct acceptance boundary for an authorization-server product.
The host owns operational credential custody and deployment acceptance.

## Dependencies

`chio-control-plane` supplies policy loading, kernel construction, capability
authority, persistent-store setup, enterprise identity, and trust-control APIs.
`chio-mcp-remote` supplies listener setup, HTTP routes, bearer verification,
session workers, notification replay, and remote lifecycle persistence.
The facade has no direct dependency on an HTTP framework, cryptographic
implementation, database engine, or subprocess transport.
Those dependencies remain behind the owning crate's public interfaces.

## Verification

Run `cargo test -p chio-hosted-mcp` for the facade dependency assertion.
`hosted_mcp_normal_dependencies_are_reexport_boundary_only` reads Cargo metadata
and checks the exact normal dependency names and order.
Run `cargo test -p chio-mcp-remote` to exercise the reexported service behavior.
Run the relevant control-plane tests when validating its setup helpers.
The facade test verifies dependency scope; it does not start an HTTP listener,
exercise authentication, sign receipts, or establish store durability.
The README wrapper compiles the public call pattern without starting services.

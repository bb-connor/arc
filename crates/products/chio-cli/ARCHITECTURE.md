# chio-cli architecture

## Responsibility and boundary

The public surface is the `chio` command tree. `Cli`, `Commands`, `CheckMode`,
and the dispatch functions are crate-private implementation details. This
binary owns argument parsing, command-specific input handling, local process
or service orchestration, output rendering, and operator-selected persistence.
`chio-kernel` owns admission and evaluation; `chio-control-plane` loads policy
and constructs/configures kernels. Specialized crates own domain verification.
Some verification adapters, archive checks, and process-host orchestration are
implemented directly in this binary.

The package has `autobins = false` and one declared binary. It is a public
entrypoint with publishing disabled. Commands can operate entirely offline,
start long-running services, or contact configured remote endpoints. The
command and its flags determine those effects.

## Structure

| Source | Role |
|---|---|
| `src/main.rs` | Binary root: shared imports/re-exports, explicit module mounts, and `main`. |
| `src/cli/types.rs`, `src/cli/types/*.rs` | Clap arguments, global state paths, command enum, and nested command families. |
| `src/cli/chio/types.rs`, `src/cli/chio/types/` | Federation, runtime, authority, treaty, and pheromone argument trees. |
| `src/cli/dispatch/mod.rs`, `src/cli/dispatch/*.rs` | Central dispatch, tracing initialization, family routing, error rendering. |
| `src/cli/runtime.rs`, `src/cli/runtime/` | Agent sessions, fixture checks, MCP/HTTP edge setup, stores, and authority wiring. |
| `src/cli/session/` | Agent-message normalization, capability selection, response mapping, and statistics. |
| `src/cli/mcp/` | Manifest-gated wrapper, nonce mediation, IDE configuration, signed launch inputs, and provisioning. |
| `src/cli/trust/`, `src/admin.rs`, `src/passport.rs` | Trust issuance/query adapters and local or remote administrative operations. |
| `src/cli/trust/receipt/`, `src/cli/receipt_verify.rs` | Store queries/maintenance and separate offline receipt verification. |
| `src/cli/dispatch/proof/`, `src/cli/dispatch/finding/` | Proof collection/verification/serving and finding ingress, challenge, and status handling. |
| `src/cli/chio/dispatch/` | Runtime, federation, buyer, and pheromone implementation trees. |
| `src/cli/process_host/` | Private host state, process admission, native brokerage, worker journals, and diagnostics. |
| `src/cli/input.rs`, `src/archive.rs` | Bounded original-document decoding and constrained archive codecs. |
| `src/guard/`, `src/commands/`, `src/guards/` | Guard lifecycle, model-card binding, blocklists, and signing helpers. |
| `src/cert/`, `src/cert.rs` | Session receipt coverage, compliance profiles, certificate generation/verification. |
| `src/doctor/`, `src/scaffold.rs`, `templates/init/` | Environment probes and embedded project templates. |

`build.rs` includes `../proof_fixture_build.rs` to prepare proof
fixture support. Command-specific tests are compiled into the binary through
`main_tests_*.rs`; black-box tests invoke the `chio` executable from `tests/`.

## Data and control flow

`main` calls `dispatch_cli::run`. On Windows it first creates an 8 MiB-stack
worker for the large generated clap parser. Dispatch parses `Cli`, extracts
store/control settings and output mode, then initializes redacted tracing.
A match over `Commands` routes the command to its implementation.

The common terminal error path renders `CliError::report()` through
`write_cli_error`, writes stderr, and exits 1. Human error fields pass through
`terminal_safe`; JSON errors use structured serialization. Individual commands
have additional exit meanings. `check` uses 2 for deny and 3 for pending
approval; policy analysis uses 1 for findings at the selected threshold and
2 for analysis failure. Automation must use the selected command's contract.

For `check`, `cmd_check` loads policy and calls `validate_check_mode` before
opening admission state. It builds/configures a kernel, registers a
`CheckToolServer`, parses arguments, generates an agent key, and issues the
policy's default capabilities. If no capability matches, it issues an empty
scope that leaves rejection to kernel evaluation. Where required, it signs a
DPoP proof bound to the capability, server, tool, canonical argument hash,
nonce, time, generated agent key, and configured activated replay authority.

The command opens and activates a session, constructs a `ToolCallOperation`,
and calls `evaluate_session_operation`. It drains and closes the session
before rendering the verdict, reason, receipt ID, policy hashes, and check
mode. Preflight uses a synthetic probe result; full mode supplies the decoded
output fixture through the same tool-server connection. Neither mode launches
an external tool implementation.

`run` instead starts the selected agent with stdio pipes and mediates its
messages through the session handler. MCP service commands construct adapted
servers and governed edges. `mcp wrap` uses a name allowlist for ordinary
forwarding; its strict mode constructs a local kernel with execution nonces
and the default runtime guard profile. Wrapper receipt state remains ephemeral.

## Trust, validation, and persistence

`input::read_regular` reads at most the configured bound plus one byte and
requires a regular file. On Unix it adds `O_NOFOLLOW` and `O_NONBLOCK`.
The general document bound is 16 MiB. `input::decode` uses
`UntrustedJsonText::decode_signed` for duplicate-aware original JSON decoding;
`input::canonical_ijson` additionally checks canonical and typed preservation.
These helpers provide decoding boundaries; each command supplies its own
signature, identity, and business validation.

`cmd_receipt_verify` limits each NDJSON line to 8 MiB, total input to 64 MiB,
and receipts to 10,000. It refuses empty input. `verify_original_receipt`
canonicalizes the original document, checks the typed supported schema,
and invokes replay verification with the external kernel pin. Acceptance
requires the signature, signer identity, and recomputed action hash. This
operation does not reconstruct policy execution or prove log completeness.

`open_cli_durable_admission_runtime` validates participant paths and, when
applicable, distinct database paths before opening local or remote admission
state. `CHIO_DPOP_REPLAY_AUTHORITY_FILE` is the one DPoP authority
configuration point for `run`, `check`, `mcp serve`, `mcp serve-http`, `api
protect` and the process host. The loader bounds a regular input to 4096 bytes
and rejects duplicate fields. A policy whose default grants require DPoP
refuses startup when the file is unset.
Attachment verifies the selected descriptor against the active durable store.
A configured descriptor with admission disabled refuses startup.
A remote runtime requires a control token. The default admission mode
is `SideEffecting`; enabled modes require a session/admission database path. `run` and
`check` call `opt_in_ephemeral_revocation_for_local_session` only when they
have no durable admission runtime; it opts in when no durable revocation
backend or remote control service is selected.

`require_durable_or_ephemeral_optin` is the sidecar startup boundary used by
`start` and `api protect`. Missing receipt storage or an SQLite in-memory
sentinel requires explicit ephemeral opt-in. A filesystem receipt store
requires an existing private authority seed; the helper validates custody
before startup. These rules belong to these launchers and do not describe
every command's persistence behavior.

Trust issuance has an explicit owner initialization step:
`provision_local_issuance_authority` accepts a seed file, a `credential:`
reference or private SQLite authority, validates existing custody, or
initializes a missing seed file. A credential reference is only loaded, never
initialized, and `CHIO_KEY_CUSTODY=required` refuses a seed file before
staging one.
`StagedLocalIssuanceSeed::publish` uses non-overwriting publication and reads
back the retained owner. Later business refusal can leave initialized custody.
Receipt preflight can also leave an initialized store. Read/report paths use
existing custody loaders for signed exports/reports; operators must preserve
keys alongside stored state.

Local receipt list/explain reads require a tenant or explicit administrative
scope through `local_receipt_read_context`. Remote reads reject these local
scope flags and rely on the authenticated service. Local operator maintenance
commands reject a remote control URL. A global option's syntactic availability
does not imply every command consumes it: process-host dispatch rejects global
store/control overrides, and MCP wrap rejects receipt storage before startup.

`init_redacted_tracing` installs the redaction layer and preregisters known
metric labels. A redaction construction error terminates startup.
`format_redacted_event_line` control-encodes field names and values, preventing
fields from introducing extra physical stderr log lines. The default filter
is `warn,chio.guard=info`; `RUST_LOG` can select another filter.

## Process and feature boundaries

The experimental process host binds its databases and retained identity to
`--state`. Unix modules own private custody, provision/serve operations, and
inspection. Linux enables the worker runner and call/outcome/run attestation.
`runner::run` loads and validates a plan, acquires `Host`, opens a journal,
starts a worker socket, and reconciles retained container ownership. Unresolved
container custody blocks replacement. Completion incorporates journal state,
cleanup, credential revocation, and publication checks.

Diagnostics read the retained snapshot and logs without opening a kernel or
reconciling admissions. Snapshot worker states are the last observation; a
crash can leave a recorded running attempt. The journal supplies recovery state.
The [host guide](PROCESS_HOST.md) and [container guide](PROCESS_CONTAINERS.md)
describe operator requirements for those execution profiles.

No CLI features are enabled by default. `real-linux-enforcement` forwards to
`chio-cage` and enables feature-required native integration tests.
`tee-quotes` enables the runtime-quote verification backend; its disabled
implementation returns an explicit feature error. `iroh` links the optional
transport and enables the pheromone relay lane; requesting that lane without
the feature is rejected. Dependency-level Wasmtime, marketplace, worker,
BBS, and native MCP support are enabled independently in the manifest.

## Dependencies

`chio-core` and `chio-core-types` supply signed artifacts, sessions, canonical
JSON, and keys; `chio-kernel` evaluates operations; `chio-control-plane` supplies
policy loading, kernel configuration, trust services, and domain adapters.
`chio-mcp-adapter`/`chio-mcp-remote` implement MCP transport edges, and
`chio-api-protect` supplies the HTTP sidecar. `chio-store-sqlite` and `rusqlite`
supply durable stores and operator queries; `chio-process` supplies persistent
process admission and worker services.

`chio-proof-room`, `chio-commerce-order`, `chio-finding-verifier`, and
`chio-acp-proxy` provide proof, commerce, finding, and compliance verification.
`chio-guard-registry` and `chio-wasm-guards` back registry and WASM operations.
Federation/runtime/pheromone crates supply their respective state machines.
Clap parses arguments; Tokio/Axum drive asynchronous services;
Reqwest/Ureq provide HTTP clients; `chio-log-redact` handles tracing redaction.
The economy dependencies support specific artifacts and configured adapters;
a CLI command or dependency alone establishes no deployed settlement service.

## Verification

`cargo test --locked -p chio-cli` exercises parsing and command integration.
`tests/code_agent_preset.rs` covers preflight refusal and fixture-backed output
guards; `tests/receipt_verify.rs` checks signer pins, tampered actions, schema
changes, empty input, and line limits. `tests/receipt_list_tenant_scope.rs`
checks local query scope; `tests/mcp_startup_security.rs` checks early rejection
and store acquisition ordering. `tests/session_certificate.rs` covers complete
session receipt verification and incomplete input refusal.

`tests/process_state.rs` checks administrative reads without authority or
launch side effects. Feature-required `enforced_discovery` and
`process_host_native` need `real-linux-enforcement`; native execution also
requires its platform prerequisites. The README sample evaluates a synthetic
call using a conformance policy and temporary private admission database.
These checks establish the
exercised command behavior; credentials, retained custody, server operation,
and deployment acceptance require operator validation.

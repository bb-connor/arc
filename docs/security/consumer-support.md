# Consumer boundary support ledger

This is the M4 worklist, not a release qualification. Source discovery and a
passing component test do not establish a supported deployment profile. Rows
remain open until their construction, authenticated input, effect and recovery
boundaries have the acceptance evidence required by
[M4](m4-consumer-qualification.md). The complete M3 native caller host contract
remains required. The M1 Linux x86_64 confinement deferral is unchanged.

Intentional source/wire changes and parser limitations are documented in the
[M4 migration contract](m4-consumer-migration.md). The tables classify source
roles; final gate results are recorded separately rather than inferred from a
constructor count.

## Profile vocabulary

- **Trusted native host:** operator-supplied live security context, verified
  manifest registry, tenant policy/topology, installed flow/guard pipeline and
  durable capture/release participants. Ordinary, nested and authenticated
  caller execution have distinct public entrypoints, not interchangeable rights.
- **Mediated protocol:** authenticated Chio authorization is retained through the
  protocol envelope and checked by the configured kernel. External discovery,
  headers and provider descriptions cannot create authority. MCP, A2A and ACP
  require positive negotiated cases, not only unsupported-profile denials.
- **Ordinary kernel host:** the factory does not install active defense. It must
  reject a selected flow-required profile before acquiring effect-capable launch
  authority. This does not declare the whole underlying protocol unsupported.
- **Caller transport:** carries reservations, signed starts and signed reports to
  the trusted Rust host. It is not an execution authorizer, native custody owner
  or SDK-local budget authority. Reservation is not permission to execute.
- **Portable verification:** no native process or durable release authority.
  Unsupported negotiated or multi-hop witness profiles reject explicitly.
- **Harness:** synthetic/local connector with no advertised production authority.
  A harness pass is not confinement, hosted production or hardware evidence.

Unless a row names another owner, recovery belongs to the kernel's durable
admission/outcome stores and the M3 executor ledger, not the transport. All
production rows require trusted key/policy selection and their profile's stores;
no request-controlled identity or silent ephemeral replacement is permitted.

## Direct Rust construction and factory sites

Paths are relative to the repository. The physical-source audit found the 29
sites below. This includes constructor wrappers, not just direct `new` calls.
Included test fragments are retained visibly rather than misclassified as
production. The same physical-source gate now pins 86 dispatch/caller references
(D001-D086) as well as these 29 construction references. This is an exact source
inventory, not Rust macro expansion or a semantic proof of all network effects.

| ID | Exact path and symbol | Role / selected profile | Acceptance owner and current state |
| --- | --- | --- | --- |
| C01 | `crates/platform/chio-control-plane/src/lib.rs::build_kernel` | Ordinary host factory | `build_kernel_registers_default_guard_profile`, `build_kernel_registers_post_invocation_pipeline`; flow gate owns missing-port negatives |
| C02 | same file, `build_kernel_components` | Private composition for C01/C03 | C01 tests plus `security/active_defense_host_tests.rs` and flow installation-order gate |
| C03 | same file, `build_kernel_with_active_defense` | Trusted native host factory | `ensure_ready`, pre/post guards, dispatch and issuance installation; M3 dependency gate required |
| C04 | `crates/protocol/chio-mcp-remote/src/remote_mcp/session_core/factory.rs::RemoteSessionFactory::spawn_session` | Ordinary remote MCP host | Remote `tests::session_runtime`, 59 library cases and exact early-startup rejection; P02 owns hosted role separation |
| C05 | same file, `RemoteSessionFactory::restore_session` | Restarted ordinary remote MCP host | Remote session runtime/restoration tests and exact MCP retained-profile test; no profile upgrade on restart |
| C06 | `crates/platform/chio-http-core/src/authority.rs::HttpAuthority::assemble` | HTTP authorization, not native executor | `authority/tests.rs`: final receipt/kernel linkage, revoked-capability denial and path-identity binding; `tests/execution_nonce.rs` real nonce/replay cases |
| C07 | same file, `HttpAuthorityBuilder::build` | Configured HTTP authorization | Same C06 public-authority suite; request hints cannot replace configured issuer/policy or parsed route identity |
| C08 | `crates/products/chio-api-protect/src/proxy/mediated.rs::build_mediation_kernel` | Caller reservation and configured mediated execution | Exact M3 caller/store and executor-ledger gates; no native custody asserted by this transport constructor |
| C09 | `crates/products/chio-cli/src/cli/runtime.rs::build_mcp_edge_kernel` | Ordinary MCP host factory | C10 startup/stdio tests plus CLI durable/ephemeral store unit tests; the public startup owns early flow rejection |
| C10 | same file, `cmd_mcp_serve` | Executable stdio MCP host | Counterexample reproduced and repaired before store/launch authority; startup regression and all 21 stdio integration tests passed |
| C11 | same file, `cmd_run` | One-shot ordinary agent-protocol host | Fresh agent/session/capabilities; explicitly ephemeral local fallback only when no durable backend is configured. Agent subprocess is not a confined tool server. Control-plane/CLI suites own policy, stores and session behavior; no M5 profile claim |
| C12 | same file, `cmd_check` | Policy-check local probe | Local `CheckToolServer` only; check-mode validation and CLI policy/receipt suites, not external tool execution |
| C13 | `crates/products/chio-cli/src/cli/mcp/wrap.rs::KernelMediatedMcpTransport::new` | Ordinary MCP wrapping | `require_unprotected_wrap_compatible` before launch; flow gate and `mcp_wrap_e2e` counted verdict/strict-nonce cases |
| C14 | `crates/products/chio-cli/src/cli/mcp/governed_sim.rs::cmd_mcp_governed_sim` | Simulation harness | Local `SimFlatCostServer`, no provider/native authority; CLI simulation suite is behavior evidence, not deployment qualification |
| C15 | `crates/products/chio-cli/src/cli/replay/execute.rs::run_traffic_replay` | Replay harness | Local `ReplayProbeToolServer`, isolated partition; `replay_traffic` clean-match, verdict/signature/schema/redaction drift cases |
| C16 | `crates/kernel/chio-runtime-harness/src/kernel.rs::execute_runtime_loopback_step` | Deterministic local connector | Durable proof/outcome identities; 22 harness and 147 CLI proof tests passed after fixture repair |
| C17 | `crates/platform/chio-control-plane/src/trust_control/finding_operator_purchase.rs::FindingOperatorPurchaseExecutor::build_kernel` | Bounded single-operator purchase host | `finding_wedge_purchase_e2e_tests`: configured independent listing/buyer pins, reserved-restart recovery, expired/pre-dispatch rejection and durable finalization. Not generalized native flow or public hosted production |
| C18 | `examples/hello-mcp/src/lib.rs::build_demo_state` | Ordinary executable MCP example | Local echo server; `mcp_lifecycle_direct_jsonrpc_lists_and_calls_tool`, receipt projection and unknown-tool denial tests |
| C19 | `examples/hello-a2a/src/lib.rs::build_demo_state` | Ordinary executable A2A example | Local echo server; `direct_jsonrpc_send_stream_and_task_get_carry_receipts` and unknown-tool denial tests |
| C20 | `examples/hello-acp/src/lib.rs::build_demo_state` | Ordinary executable ACP example | Local echo server; `direct_jsonrpc_invoke_stream_and_resume_carry_receipts` and unknown-tool denial tests |
| C21 | `crates/tooling/chio-conformance/src/native_suite.rs::capture_runtime_revocation_trace_with_store` | Conformance harness | Native conformance revocation traces, supplied store and local connector; no independent production authority |
| C22 | `crates/tooling/chio-conformance/verdict_matrix/src/driver.rs::evaluate_scenario` | Verdict conformance harness | Verdict-matrix schema/scenario suite; fixed projections and local connector, not deployment authority |
| C23 | `crates/kernel/chio-runtime-core/benches/fixtures/treaty_admission_fixture.rs::TreatyPredispatchDenyFixture::new` | Benchmark harness | Predispatch denial cost, not execution qualification |
| C24 | `crates/kernel/chio-kernel/benches/fixtures/dispatch_request_fixture.rs::DispatchAllowFixture::new` | Benchmark harness | Local allow-path cost, not deployment qualification |
| C25 | `bench/chio-loadgen/src/stack.rs::StackHarness::boot_inner` | Load harness | Configured benchmark stack, not production authority |
| C26 | `crates/protocol/chio-mcp-edge/src/fuzz.rs::make_kernel` | Fuzz harness | Adversarial parser/edge input; not production authority |
| C27 | `crates/protocol/chio-acp-edge/src/fuzz.rs::make_kernel` | Fuzz harness | Adversarial parser/edge input; not production authority |
| C28 | `crates/platform/chio-control-plane/src/security/adapters/native_flow_test_support.rs::open_kernel` | Included test fixture | Included by native-flow tests under `cfg(test)`; M3 native host acceptance fixture |
| C29 | `crates/platform/chio-control-plane/src/security/event_consumer_parts/part_06.inc::build_real_adapter_runtime` | Included test fixture | Event-consumer test composition; not a separate public factory |

Remote construction is gated by the public factory's
`RemoteSessionFactory::new`, before C04/C05. Its new
`remote_session_factory_rejects_flow_before_launch_authority_or_store_acquisition`
test first failed because the unsupported profile was accepted. The fix rejects
from the verified registry before launch preparation or store acquisition. The
same test requires a valid unconstrained factory and nonzero launch preparation.
All 59 remote-MCP library tests passed in
`/tmp/chio-m4-remote-startup-fixed.log`. This is local component evidence, not
exact-candidate hosted qualification.

## Other required consumer boundaries

These roots extend the direct-construction worklist. The D inventory below pins
physical native dispatch references; the following public profile mapping also
covers portable evaluators, declarative translators and effect-only connectors.
Qualification is still pending where the owner gate has not completed.

| ID | Source roots | Required boundary / evidence owner |
| --- | --- | --- |
| P01 | `chio-kernel` public ordinary, nested and caller APIs; `chio-runtime`, `chio-runtime-core` | Original authorization and operation identity, installed ports, one physical capture, output release and recovery |
| P02 | `chio-mcp-edge/src/runtime/tool_calls.rs`, `chio-mcp-remote`, `chio-hosted-mcp` | Negotiated metadata, session identity, role-separated control credentials, replay and durable session restoration |
| P03 | `chio-a2a-edge`, `chio-a2a-adapter` | Negotiated complete authorization, authenticated sidecar and counted mediated connector |
| P04 | `chio-acp-edge`, `chio-acp-proxy`, ACP client routes | Same guarantees through ACP ingress/transport, compatibility surface explicitly separate |
| P05 | `chio-cross-protocol`, `chio-openapi`, `chio-openapi-mcp-bridge` | Registry-bound flow sidecar and canonical projection; dropped/substituted metadata must deny |
| P06 | Provider adapter crates and `chio-tower` | Complete approval/proposal/DPoP/intent/opaque extension projection, no direct-provider fallback after denial, streaming release boundary |
| P07 | `chio-api-protect/src/proxy/mediated/authenticated.rs`, caller control routes | Reserved/start/report lifecycle, configured executor pin, signed delivery and durable ledger replay |
| P08 | `chio-kernel-core`, browser/mobile kernels, `chio-bindings-ffi`, `chio-cpp-kernel-ffi` | Portable schema/negotiation and request preservation; unsupported authenticated witness contracts deny |
| P09 | `chio-manifest`, core `ToolDefinition`, verified manifest registry | One v2 latency field, signed flow, v1 migration is unsigned and requires re-signing; runtime/schema parity |
| P10 | Remaining product dispatch/network roots and executable integrations | Discovery must establish reachability and selected authority profile, not infer support from crate names |

### Public profile mapping

Default Cargo features are the supported host profile unless a row names a
different feature/target. `compatibility-surface` is an explicit unmediated API,
not a fallback available to an enforced invocation. Ordinary hosts do not acquire
native caller custody by enabling a negotiation flag.

| Row | Entrypoint and physical implementation | Profile and trust/recovery boundary | Required owner gate |
| --- | --- | --- | --- |
| P01 | `ChioKernel::evaluate_tool_call*` in `kernel/evaluation/evaluation_entry.rs` and `sync_evaluation_wrapper.rs`; nested APIs in `kernel/session_ops/nested_tool_call.rs`; caller APIs in `kernel/evaluation/caller_execution.rs` | Native host supplies installed ports, authenticated context and verified registry. Ordinary, nested and caller starts converge on retained admission but do not exchange rights. Kernel/store own capture and release recovery. | Exact M3 61 cases passed on the changed closure; full control-plane/default-stack and flow gate remain final dependencies. |
| P02 | `ChioMcpEdge::handle_jsonrpc*` via `handle_initialize`, `handle_tools_call*`, `handle_tasks_result*`, `process_background_tasks*`; `RemoteSessionFactory::{new,spawn_session,restore_session}` | MCP negotiation is session-retained. Task execution reuses the prepared operation. Remote/stdio ordinary factories reject required flow before launch/store acquisition. Hosted control credentials remain separate from session credentials. | MCP 113 library cases, remote 59 cases, exact peer/profile restoration, live MCP restart, stdio and hosted auth suites. |
| P03 | `ChioA2aEdge::{new_with_registry,handle_send_message_with_request_id,handle_stream_message_with_request_id,handle_jsonrpc}` in `chio-a2a-edge/src/edge.rs` | One host-established peer profile per edge; registry-bound sidecar and authenticated context retained through the native target. Unsupported stream/batch authority does not become a direct connector retry. | A2A 97 library cases, exact peer cases and two live restart scenarios. |
| P04 | `ChioAcpEdge::{new_with_registry,invoke_with_request_id,invoke_with_mcp_target,handle_jsonrpc,start_stream_with_request_id}` in `chio-acp-edge/src/edge.rs` | The roadmap's ACP-Client mediated route is this ACP tool-invocation edge. `chio-acp-proxy::AcpProxy` instead supervises an agent protocol and issues observation attestations; it is not a native tool executor or custody owner. Compatibility passthrough is separately feature-gated. | ACP 93 library cases, exact peer cases, two live restart scenarios, ACP proxy and compatibility-source gates. |
| P05 | `CrossProtocolOrchestrator::execute`; `evaluate_bound_kernel_request`; `chio_openapi::tools_from_spec`; `OpenApiMcpBridge::{registry_bound_mcp_tools,as_tool_server}` | Declarative OpenAPI translation is not authority. Live HTTP dispatch is an effect connector installed behind the kernel. Plain export of remote tools rejects; verified canonical manifest identity, effective egress and sidecar coordinates must match. | Cross-protocol library, live native restart and OpenAPI signed-flow / substitution tests. |
| P06 | `ChioOpenAiAdapter::{new,with_peer_capabilities,execute_tool_call,execute_tool_calls}`; `KernelService::{new,with_peer_capabilities}` and its `Service::call`; `HttpAuthority::{builder,evaluate,prepare}` via `authorize_via_kernel` | Ordinary host wrappers preserve typed requests and reject unnegotiated extensions before admission. OpenAI's unsigned-manifest constructor rejects flow-required tools; the verified cross-protocol host owns that profile. Provider `ProviderAdapter` implementations translate dialects, and registered tool-server implementations perform effects; neither independently grants Chio admission. The separate HTTP middleware's explicit fail-open option is unenforced operation and excluded from this profile. | OpenAI 46 and Tower 56 library cases passed, including counted-effect/receipt controls. HTTP, provider projection, batch/stream and M3 gates remain required. |
| P07 | API-protect `proxy/mediated/authenticated.rs::{start,report}` and caller routes in `proxy/mediated.rs`; native Rust `start_caller_execution_blocking_with_security_context` | Trusted executor pin and durable ledger, original nonce/credentials and exact signed delivery. Reservation alone never permits execution. Native release/declassification remain Rust-host-owned, not transport-local. | Exact M3: 33 caller/store, 9 executor-ledger and 19 native-custody cases passed. Python client and hosted role-separation suites remain required. |
| P08 | Browser `evaluate_pure` / wasm facade; mobile `evaluate`; C ABI `chio_kernel_evaluate_json` / `chio_kernel_verify_capability_with_context_json`; `chio-bindings-ffi` invariant exports | Portable verification, not native dispatch. Unsupported approval/proposal/intent extensions and unauthenticated witness profiles reject. Browser wasm and mobile FFI packaging are distinct from native unit execution. | Exact portable denials; browser 27, mobile 31 and C++ FFI 23 component tests passed. External C/C++ gates remain required. |
| P09 | `VerifiedManifestRegistry`, `migrate_legacy_manifest_v1`, `ToolDefinition`, `NetworkDestination::new` | v2 uses only `latency_hint`; v1 migration returns an unsigned result and requires trusted re-signing. Registry identity, host-selected policy/topology and nonzero destination ports remain authoritative. | Exact signed manifest corpus, all four wire lanes and the flow registry gate. |
| P10 | D001-D009, D045-D058 and D076-D079 plus C11-C25 | Arena/load/proof/replay/example hosts are explicit harness or ordinary profiles. Operator purchase execution uses configured signer/buyer pins and durable domain storage. Pure policy probes have no connector effect. These rows do not claim M5 swarm confinement, M6 enterprise topology, M9 packages or M11 public hosted production. | Workspace component suites plus their domain/proof gates; no new production deployment claim. |

Raw `ToolServerConnection` / `HttpDispatcher` implementations are effect ports,
not secure invocation APIs for agents. A trusted host can call its own network or
process primitives directly; Chio's supported host contract requires attaching
them to the kernel. M4 checks that an enforced adapter does not select such a port
after denial. Native process confinement remains under the explicit M1 boundary.

The provider-fabric `ToolInvocation` vocabulary has no negotiated complete proof
envelope. Its `build_tool_call_request` lowering therefore rejects aggregate or
cumulative extensions before yielding a kernel request. Ordinary capabilities
retain their canonical bytes. Full authorization artifacts use the native or
mediated protocol APIs; provider provenance fields do not substitute for them.

## SDK roles and parity lanes

SDK wire models and transport helpers do not inherit cryptographic verification
or native custody claims from a different package in the same language.

| ID | Package / source | Actual role and required lane |
| --- | --- | --- |
| S01 | Python `sdks/python/chio-sdk-python` | Current generated Pydantic wire validators and authenticated caller HTTP client; full 193 tests and exact 15-case current-wire gate passed, separate from `check-chio-py.sh` |
| S02 | Python `sdks/python/chio-py` | Invariant/signature and canonical helpers; manifest helper currently recognizes v1 only, so its legacy vectors are not v2 runtime evidence |
| S03 | Python `sdks/python/chio-adapter-base` and affected users | Transport/receipt/security field preservation; no unsigned reserve/execute shortcut; all 199 adapter-base cases passed |
| S04 | TypeScript `sdks/typescript/packages/node-http` and private `packages/conformance` | Public `node-http` wire validator is exercised through its freshly built package export; generated types/shared corpus remain in the private conformance package. Type compilation alone is insufficient |
| S05 | TypeScript `sdks/typescript/chio-ts` | Public clients and canonical/signature helpers; current manifest invariant helper is v1-only, distinct from S04 |
| S06 | Go `sdks/go/chio-go-http` | Generated current-wire types and public transactional security decoders, raw duplicate/size/depth/integer bounds; full suite and exact shared corpus passed. Bounded validation, not a complete JSON Schema or signature verifier |
| S07 | Go `sdks/go/chio-go` | Canonical/signature invariants and clients; manifest v1 helper is not current-v2 validation |
| S08 | Rust `crates/sdk/chio-binding-helpers` | Normative current manifest verifier and canonical codec; verify current vectors and registered signer separately from schema acceptance |
| S09 | C++ `sdks/cpp/chio-cpp`, `chio-cpp-kernel`, `chio-drogon` | Affected pure SDK, Rust-backed portable evaluator and HTTP middleware behavioral gates; no hardware/confinement claim |

M4 must link each required current-wire positive/negative vector to the actual
runtime lane and exact canonical bytes/hash. Legacy-only helper support can
remain explicitly versioned; it cannot be reported as current-v2 verification.

## Executable gates

- `check-protocol-peer-negotiation.sh`: 12 named native/MCP/A2A/ACP and portable
  cases. Now uses the shared exact listed/executed inventory checker. Its wrapper
  calibration rejects missing, renamed, ignored and zero-match tests. Real Rust
  cases passed in `/tmp/chio-m4-peer-gate-complete.log`.
- `check-authenticated-caller-delivery.sh`: all 61 M3 cases remain required for
  the changed dependency closure, including native release/declassification.
- `check-flow-security.sh`: registry, policy/topology, flow, constructor and
  installation cases remain required; no broad unsupported-profile waiver.
- `check-adapter-no-bypass.sh`: existing physical-source mediation contracts,
  including the new remote/stdio startup guard calls. It supplements behavioral
  tests and is not proof that every consumer has been inventoried.

The physical constructor portion now runs in the existing adapter source gate.
It pins all 29 exact path/symbol/reference-count entries, including function
pointer references. Constructor aliases and macro-hidden references require
explicit checker support instead of silently escaping coverage. This is not a
Rust type-system proof. The D inventory below extends this to 86 physical
dispatch references. Unit calibration adds/removes constructors and dispatch
references in isolated source trees and removes each required mediation call.

The first real run of the stricter peer gate failed because
`tests::cross_protocol_kernel_request_preserves_complete_authorization_context`
does not exist in the current source. The restored historical wrapper listed
acceptance names not backed by this candidate. Existing A2A/ACP projection tests
do preserve approval sets and opaque extensions, but they do not establish all
the wrapper's advertised negotiated end-to-end scenarios. Reconcile the whole
12-case contract before changing its acceptance claims or calling the gate green.
All 12 missing/current identities have since been implemented and passed. This
historical failure is retained as calibration, not the candidate's current state.

The native orchestrator and public MCP/OpenAI target executors now use one
manifest- and host-context-preserving kernel projection. Direct MCP target calls
reject a substituted sidecar or unbound authenticated session before effects or
receipt mutation; the valid control still invokes once. Cross-protocol target
execution carries the host-established negotiation profile. A2A/ACP hosts bind
that profile in edge configuration (one authenticated peer profile per edge),
not message metadata. The baseline profile has all new extensions disabled.

MCP computes its intersection from `capabilities.experimental.chioAuthorization`
during initialization and stores it with the authenticated session. Malformed
profiles reject before session acquisition. Legacy retained sessions have no
authorization profile and gain no new extension support on restore. The
`opaque_supplemental_authorization` flag means carriage to an installed verifier,
not caller-created quota authority. The bridge-only MCP Rust request now carries
DPoP explicitly and shares one sync/async request projection.

Component reruns passed 97 A2A, 93 ACP, 35 cross-protocol and 112 MCP tests
(`/tmp/chio-m4-peer-boundaries-fixed.log`). The added preservation cases compare
all signed fields using typed wire fixtures. They are not live admission of
those fixtures. Ordinary positive invocations plus missing-feature denials prove
the pre-dispatch boundary. Full negotiated admission, restart calibration,
portable cases and the exact peer gate remain separate required evidence.

The active-response schema incorrectly used `chio.governed-response-plan.v1`
while the native validator uses `chio.response-plan.v1`. The schema and shared
vectors now use the native identifier and independently computed domain-separated
plan-body hash. All four languages were regenerated successfully. Current Python,
Go and TypeScript public-parser gates passed; the final Rust/composed gate remains
required after the expanded corpus and later consumer changes.

The current-manifest shared corpus has 14 cases in
`tests/bindings/fixtures/manifest-v2-consumers.json`. Python initially accepted
explicit-null flow/latency aliases and numeric booleans; Go accepted 12 invalid
security-object cases through ordinary `json.Unmarshal`. Python now obtains
non-nullable object validation and strict booleans/integers through xtask-generated
model composition. Go now enforces required/unknown/duplicate/non-null security
properties before committing a decoded generated value. These remain wire
validators, not publisher signature verifiers or permission authorities.

Rust also accepted destination port zero through derived deserialization despite
rejecting it in `NetworkDestination::new`. The private field is now `NonZeroU16`,
with unchanged wire/accessor shape. All 24 manifest tests pass, including both
nonzero port boundaries, the corpus and the independent registered signer check.
The valid existing cage vector's canonical SHA-256 is identical across Rust,
Python, TypeScript and Go. Python's full SDK suite passed 193 tests; TypeScript's
manifest lane passed 15 tests; Go's HTTP SDK suite passed. These are bounded
manifest results, not blanket parity for every security schema or numeric domain.

## Current M4 acceptance and remaining qualification

Eight live tests in `chio-conformance --test consumer_boundary` passed through
native, MCP, A2A and ACP public ingress. Each protocol has an aggregate-budget
case and a threshold-approval case. They use real SQLite admission/outcome,
budget/revocation and receipt stores, registered signed manifests, counted local
connectors and verified kernel receipts. Threshold cases consume an actual signed
pending proposal and two signed approvals before execution. Restart replays the
original receipt without another connector effect. Aggregate and cumulative
profiles remain separate; unsupported joint roots still reject.

Evidence: `/tmp/chio-m4-consumer-durable-e2e-supported.log`, 8 passed. MCP now
returns the actual signed receipt in `_meta.chio` and a valid pending proposal in
`structuredContent`. A2A pending approval remains `working`, with a proposal data
message. ACP uses the same pending-result wire shape. Connector-supplied metadata
cannot replace the kernel receipt namespace. These response additions are
intentional public contract changes.

`scripts/check-consumer-boundaries.sh` pins the eight live cases, early factory
rejections, profile restoration, Rust/schema vectors and Tower/OpenAI ingress
denials, then runs the 12-case peer gate and source contracts. It is wired into
the existing PR and enterprise lanes. `scripts/check-consumer-sdk-parity.sh`
separately checks exact Python, Go and TypeScript terminal identities and all
14 manifest / 35 protocol vectors. Missing, renamed, ignored, duplicated and
zero-match SDK reports fail calibration. No hosted run is claimed by this wiring.

The expanded public SDK gate passed with all 35 protocol and 14 manifest vectors
(`/tmp/chio-m4-sdk35-final.log`). It verifies 15 Python, seven Go top-level and
19 TypeScript terminal test identities, plus every Go corpus subcase. Python's
full SDK suite passed 193 tests after caller-artifact and optional-DPoP hardening
(`/tmp/chio-m4-python-full-caller-final.log`). The authenticated caller HTTP test
sends generated models and preserves required null output and cost fields. Go's
ordinary public JSON decoders now reject duplicate, unknown, missing and malformed
security fields before replacing the destination value, including aggregate raw
unions and signed caller report cost objects. Required explicit null report output
and cost remain intact. Opaque JSON numbers use `json.Number`; typed integers reject values outside
the generated signed-64-bit domain. This is bounded structural/domain validation,
not a claim that every Go generated shape implements the complete JSON Schema.

TypeScript's public `@chio-protocol/node-http` package exposes
`createWireSchemaValidator` over operator-selected authoritative schemas. The
corpus gate rebuilds and imports that package export, not a private test wrapper.
All 73 existing Node HTTP tests also passed. The validator compiles at setup and
accepts synchronous validation only. Its parsed-
JSON profile rejects unsafe integer values, non-JSON values and excessive nesting.
Already-parsed JavaScript and Python dictionaries cannot recover duplicate raw
keys; duplicate-rejecting raw ingress remains a host responsibility. Go's raw
security-artifact profile rejects duplicate keys, more than 64 nesting levels and
artifacts above one MiB. These limits do not create a portable custody authority.

The constructor/dispatch profile table is classified and the optional-DPoP and
caller wire regressions pass the public SDK gate. The remaining external C++/FFI,
exact M3 dependency and final composed qualification are still required.
The C++ kernel/FFI gate passed locally;
Drogon's strict library/example/live smoke and the other final gates are still
running. M4 is not yet complete.

## Physical dispatch reference classification

Exact path, symbol, callee and count for each D ID are recorded in
`formal/adapter-source-inventory.toml`. The existing source checker scans Rust
files and include fragments across crates, examples, integrations, benchmarks and
SDKs. It records function-pointer references and rejects newly introduced aliases
or macro-hidden construction/dispatch identifiers without explicit checker support.
A new or removed physical reference fails the inventory. Similar policy-only
method names are classified below instead of silently excluded. The default
workspace build and applicable explicit compatibility/portable gates remain
separate requirements; this table alone does not qualify a deployment.

| IDs | Exact physical source | Classification | Acceptance owner |
| --- | --- | --- | --- |
| D001-D002 | `bench/chio-loadgen/src/stack.rs` | Benchmark harness, not deployment authority | C23-C25 |
| D003 | `crates/core/chio-arena/src/link/multiplex.rs` | Adversarial arena harness | P10, workspace arena tests |
| D004-D005 | `crates/core/chio-arena/src/runtime.rs` | Adversarial arena harness | P10, workspace arena tests |
| D006-D007 | `crates/guards/chio-policy/src/evaluate/engine.rs` | Pure policy evaluation, no connector dispatch | P01, policy tests |
| D008-D009 | `crates/kernel/chio-kernel/benches/fixtures/dispatch_request_fixture.rs` | Benchmark harness, not deployment authority | C23-C25 |
| D010-D015 | `crates/kernel/chio-kernel/src/kernel/evaluation/caller_execution.rs` | Caller reservation/start/report kernel owner | P01, M1-M3 and flow gates |
| D016-D022 | `crates/kernel/chio-kernel/src/kernel/evaluation/evaluation_entry.rs` | Ordinary kernel entry/facade | P01, M1-M3 and flow gates |
| D023-D024 | `crates/kernel/chio-kernel/src/kernel/evaluation/nested_flow_evaluation.rs` | Nested/session kernel owner | P01, M1-M3 and flow gates |
| D025-D035 | `crates/kernel/chio-kernel/src/kernel/evaluation/sync_evaluation_wrapper.rs` | Ordinary kernel entry/facade | P01, M1-M3 and flow gates |
| D036-D037 | `crates/kernel/chio-kernel/src/kernel/evaluator.rs` | Ordinary kernel entry/facade | P01, M1-M3 and flow gates |
| D038 | `crates/kernel/chio-kernel/src/kernel/session_ops.rs` | Nested/session kernel owner | P01, M1-M3 and flow gates |
| D039-D042 | `crates/kernel/chio-kernel/src/kernel/session_ops/nested_tool_call.rs` | Nested/session kernel owner | P01, M1-M3 and flow gates |
| D043-D044 | `crates/kernel/chio-kernel/src/provider_verdict.rs` | Provider mediated verdict boundary | P01, M1-M3 and flow gates |
| D045 | `crates/kernel/chio-runtime-core/benches/fixtures/treaty_admission_fixture.rs` | Benchmark harness, not deployment authority | C23-C25 |
| D046 | `crates/kernel/chio-runtime-harness/src/kernel.rs` | Deterministic loopback proof harness | C16, harness and proof CLI |
| D047 | `crates/platform/chio-control-plane/src/security/adapters/native_flow_process_races.rs` | Included native host acceptance fixture | P01/P07, exact M3 native custody |
| D048 | `crates/platform/chio-control-plane/src/security/adapters/native_flow_process_recovery.rs` | Included native host acceptance fixture | P01/P07, exact M3 native custody |
| D049-D050 | `crates/platform/chio-control-plane/src/security/adapters/native_flow_process_restart.rs` | Included native host acceptance fixture | P01/P07, exact M3 native custody |
| D051-D052 | `crates/platform/chio-control-plane/src/security/adapters/native_flow_test_support.rs` | Included native host acceptance fixture | P01/P07, exact M3 native custody |
| D053 | `crates/platform/chio-control-plane/src/trust_control/finding_operator_purchase.rs` | Configured operator purchase host | C17/P10, domain authority and recovery tests |
| D054 | `crates/platform/chio-http-core/src/authority.rs` | HTTP authorization kernel host | C06-C07/P06, HTTP authority tests |
| D055 | `crates/products/chio-api-protect/src/proxy/mediated.rs` | Authenticated caller control and retained report | P07, exact M3 dependency gate |
| D056 | `crates/products/chio-api-protect/src/proxy/mediated/authenticated.rs` | Authenticated caller control and retained report | P07, exact M3 dependency gate |
| D057 | `crates/products/chio-cli/src/cli/mcp/governed_sim.rs` | Simulation harness, no provider authority | C14 |
| D058 | `crates/products/chio-cli/src/cli/mcp/wrap.rs` | Ordinary MCP wrap, constrained profiles reject | C13, wrap compatibility gate |
| D059-D061 | `crates/protocol/chio-cross-protocol/src/execution.rs` | Verified registry and host-context mediated projection | P03-P06, live consumer and sidecar negatives |
| D062-D066 | `crates/protocol/chio-mcp-edge/src/runtime/tasks.rs` | MCP task continuation through the retained prepared operation | P02, MCP library and live consumer gates |
| D067-D073 | `crates/protocol/chio-mcp-edge/src/runtime/tool_calls.rs` | MCP mediated direct/nested/bridge entry | P02, MCP library and live consumer gates |
| D074 | `crates/protocol/chio-openai-adapter/src/lib.rs` | Ordinary OpenAI host, peer preflight and flow rejection | P06, OpenAI exact cases |
| D075 | `crates/protocol/chio-tower/src/kernel_service.rs` | Ordinary Tower host, peer preflight; no native custody API | P06, Tower exact case |
| D076 | `crates/tooling/chio-conformance/src/native_suite.rs` | Conformance harness, no deployment authority | C21-C22 |
| D077-D078 | `crates/tooling/chio-conformance/verdict_matrix/src/driver.rs` | Conformance harness, no deployment authority | C21-C22 |
| D079 | `examples/hello-mcp/src/lib.rs` | Ordinary executable example, local echo connector | C18-C20, example tests |
| D080-D082 | `crates/kernel/chio-kernel/src/kernel/evaluation/caller_execution.rs` | Caller reservation, including host security context and strict nonce preflight | P01/P07, exact M3 dependency gate |
| D083-D084 | `crates/kernel/chio-kernel/src/provider_verdict.rs` | Provider verdict APIs retain verified registry and optional host security context | P06, provider lowering and missing/forged-sidecar cases |
| D085-D086 | `crates/products/chio-api-protect/src/proxy/mediated.rs` | Mediated reservation endpoint, never execution permission | P07, API-protect caller and M3 dependency gates |

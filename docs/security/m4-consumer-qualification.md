# M4 execution plan: consumer-boundary qualification

Status: M4 implementation and focused acceptance are in progress on 2026-09-13.
The baseline repairs, physical consumer inventory, negotiated mediation and
public parser changes are implemented. Final M4.8 composed qualification is
still running; unchecked acceptance items are not waived by this status.
This document does not yet qualify the milestone.
Current command results and remaining gates are recorded in the
[local acceptance report](m4-local-acceptance.md).
This expands [M4 in the accepted execution plan](launch-execution-plan.md#m4-close-constructor-protocol-and-sdk-bypasses);
it does not replace that plan or narrow its requirements.

Planning baseline: `/tmp/arc-security-launch`, branch
`security/launch-integration`, HEAD
`3d0f5a0685a84907366705e4b040b47a605f1888`. M3 implementation is
`90a77c37e50419cdba91b2898213c26d3ea5ae21`. Preserve the separate
`/home/connor/backbay` worktrees. This planning change does not authorize merge,
publication, operator migrations, deployment, workflow repins or new manual
hosted qualification jobs.

## Outcome and scope

A consumer using a supported Chio entrypoint must reach the same authenticated
admission, guarded execution and receipt boundary as the qualified kernel path.
No constructor, adapter, SDK, fallback or compatibility route may silently discard
required authority or turn a reservation into execution permission.

Native caller release-owner and declassification custody remain required. They
are supported through the trusted Rust host contract established in M3, not
through request-supplied security identities. Four-language wire parity does not
mean four independent native executors or four new durable custody authorities.

| Existing requirement | Execution checkpoints |
| --- | --- |
| Original M4 requirement 1: all constructors and caller/remote entrypoints classified | M4.1, M4.2, M4.5 |
| Original M4 requirement 2: actual production consumer closure, not a blanket adapter rewrite | M4.1, M4.4, M4.7 |
| Original M4 requirement 3: authenticated semantic preservation | M4.3, M4.4, M4.5 |
| Original M4 requirement 4: four-language schemas/vectors and affected FFI/C++ gates | M4.6, M4.8 |
| Original M4 requirement 5: no enforced-to-legacy, direct-provider or ephemeral fallback | M4.2, M4.4, M4.5, M4.7 |
| Protocol primitives Task 3: feature negotiation | M4.3, M4.6 |
| Protocol primitives Tasks 12 and 13: schemas and adapter preservation | M4.3-M4.7 |
| Active-defense Phase 2: authenticated manifests and bridges | M4.3, M4.4, M4.6 |
| Active-defense Phase 5: installation and hook composition | M4.2, M4.4, M4.7 |

The [original protocol tasks](../superpowers/plans/2026-07-09-protocol-primitives.md)
and [active-defense phases](../superpowers/plans/2026-07-09-security-active-defense.md)
remain normative. In particular, native, MCP, A2A and ACP-Client require their
promised end-to-end cases; an unsupported extension is handled only as permitted
by its contract, not by silently dropping the whole consumer.

M5 owns the bound/confined reference swarm, M6 the integrated enterprise topology,
M7 the full active-response composition, M8 retention/scale/operator recovery,
M9 package publication closure, and M10 exact-candidate release qualification.
M4 preserves those interfaces and fixes demonstrated boundary regressions; it
does not implement those milestones early. M1's confinement deferral remains
explicit and does not become portable or confined-process evidence for M4.

## Fresh baseline: broad regression results now available

The M3 exact gate passed 61 tests. Its kernel/API library runs and strict
workspace/all-target Clippy also passed. Subsequently, the normal workspace
build completed successfully, but `cargo test --workspace --no-fail-fast` exited
101 with 11 failed targets. These results were still pending at M3 closeout.

Evidence: `/tmp/chio-m3-final-workspace-tests-resumed.log` and
`/tmp/chio-m3-final-workspace-build-qualified.log`. The following are observed
failure signatures, not six proven root causes:

| Observed failure | Affected targets | First investigation / acceptance |
| --- | --- | --- |
| Default test-thread stack overflow in `native_nonce_supports_public_nested_sync_and_async_dispatch` | `chio-control-plane --lib` | Reproduce the workspace feature configuration and exact nested path; repair ownership/stack composition, then pass at the default stack size |
| Runtime proof package and verifier-report hash mismatch | `chio-runtime-harness --lib`; `chio-cli --test proof_cli_contract` | Trace canonical inputs and deterministic regeneration; retain the tamper-negative test and independent expected hashes |
| Static-bearer hosted MCP startup requires a separate `--admin-token`; later fixture locks poison | `chio-hosted-mcp --test auth_flows`, `cross_crate_pipeline`, `error_contract`, `session_isolation`, `session_lifecycle` | Provision distinct trusted admin/session credentials in positive fixtures if appropriate; retain the production denial and verify neither credential crosses roles |
| `canonical_json` emits insertion order instead of canonical order | `chio-reference-tools --test tools` | The digest tool currently uses `Value::to_string`; use the established canonical codec and verify bytes/hash with workspace feature unification |
| Public runtime hook type-name expectation fails | `chio-runtime --test runtime_boundary` | Determine whether ownership/API exposure regressed or only an internal module path changed; verify the public facade without deleting the ownership contract |
| Caller-security negative expects an older denial reason | `chio-security-kernel --test adapters` | Reach the intended unsupported-custody check and assert no hook acquisition/effect; a different earlier rejection must not accidentally satisfy the test |

No failing target is waived as flaky, harmless, or a fixture-only problem without
reproduction. The stack overflow is a new demonstrated composed regression and
therefore qualifies for narrowly reopening that M1-M3 path. It does not justify
another unrestricted lifecycle refactor or replacement of the passing M3 gate.

## Execution order and stopping rules

Execute M4.0 through M4.8 in order. Inventory work can inform diagnosis, but the
new nested crash is the first implementation priority. Each checkpoint must
produce a consumer-visible acceptance result, the smallest cohesive fix and
recorded evidence before the next checkpoint becomes the primary task.

- Keep one authoritative support ledger, linked from launch status. Record exact
  paths and symbols, not only crate names or historical constructor counts.
- Reuse existing installation, canonical codecs, verified manifest registry,
  request builders, admission ports and the M3 executor ledger. No new policy
  engine, dispatch framework, parallel verifier or SDK-local quota authority.
- Preserve private validated authority, original operation identity, checked
  arithmetic, explicit state transitions and the existing dependency direction.
  Do not box or split code indiscriminately; justify layout changes with the
  reproduced failure or ownership boundary.
- A negative needs a valid positive control and evidence of the intended denial
  boundary. A successful HTTP response or a nonzero test count is insufficient.
- Do not enlarge stack limits, extend security deadlines, ignore cases, weaken
  assertion precision, widen lint exceptions or switch Enforce to Disabled to
  obtain a green result.
- After two checkpoints without advancing a named acceptance scenario, stop
  broadening the work and report the exact blocker. New features require an
  existing requirement or a demonstrated security defect.

## M4.0. Restore the composed baseline

Owners: the six failure groups above, including control-plane native nested
tests, runtime harness proof construction, hosted-MCP fixture setup, reference
tools, the runtime facade and security-kernel caller callbacks.

- [x] Preserve the terminal logs, source revision, toolchain, target, environment
  and commands. Capture the workspace-resolved Cargo features as well as the
  package-only feature set; a package-only pass cannot dismiss a workspace failure.
- [x] Reproduce the nested-nonce crash first. Identify the repeated frame or
  oversized state/future and repair its actual ownership boundary. Verify both
  public synchronous and asynchronous nested entrypoints at normal stack limits.
- [x] Diagnose and repair each remaining signature with a focused regression.
  Regenerate proof fixtures only after establishing the intended canonical
  contract; never bless mismatches or remove the tampered-report control.
- [x] For hosted MCP, distinguish the first startup failure from subsequent
  poisoned-fixture failures. Restore the intended positive sessions without
  removing the separate admin-token requirement.
- [x] Rerun all 11 affected targets under the failing feature configuration.
  Rerun the exact M3 gate if its dependency closure changes; retain the ordinary
  and nested M1/M2 cases affected by the stack repair.

Exit: all observed failures are resolved with intended invariants intact. Record
whether each correction was production code, fixture setup, API assertion or
canonical evidence. Full-workspace qualification is repeated at M4.8, not after
every small fix.

### M4.0 implementation and composed baseline evidence

The earlier-source full workspace run passed on 2026-09-14 UTC: 17,178 passed, zero failed,
48 existing ignores. All 11 original failed targets passed, including the full
1,134-case control-plane target at the default stack limit. The final exact M3
gate also passed all 61 cases. No Rust ignore was added relative to the planning
baseline. The [acceptance report](m4-local-acceptance.md) retains original failures,
corrections and command evidence. Final review then reproduced receipt-origin
schema/SDK drift and a stale retained attachment capacity limit. Their repaired
source requires refreshed M4.8 qualification, including the full workspace gate.

The original default-stack crash was reproduced in the workspace-built test
executable under GDB. The retained-request decode was reached through legitimate
output, dispatch, egress and history verification, not infinite recursion.
Large request values accumulated across these frames. The private retained wire
and decoded tool request are now heap-owned; canonical serialization and every
authority check remain unchanged. A handle-size regression accompanies the
existing original-capability round-trip test. Do not raise `RUST_MIN_STACK` to
qualify this repair.

The focused nested public sync/async nonce test passed at the default stack
size (one test, 228.91 seconds). The original workspace feature configuration
also passed the exact test (240.68 seconds), recorded in
`/tmp/chio-m4-workspace-nested-regression.log`. Filtered zero-test results from
other workspace libraries are not acceptance evidence. The full rebuilt
control-plane target passed all 1,134 tests in 5,599.87 seconds at the default
stack size (`/tmp/chio-m4-control-plane-workspace-full.log`). This is the original
workspace feature configuration. It qualifies the stack repair, not the later
protocol and SDK changes; final composed qualification is still required.

The reference digest tool now uses the shared RFC 8785 codec rather than JSON
display serialization. Its regression includes ordering, negative zero and an
integral floating-point number. The runtime-facade assertion permits a private
module move while retaining Chio ownership. The caller negative now requires the
M3 custody-specific denial and still proves the acquisition hook was not called.
These focused suites passed 6, 14 and 34 tests respectively before the final
composed rerun (`/tmp/chio-m4-baseline-focused.log`).

Hosted-MCP static-bearer fixtures now carry distinct session/admin credentials,
including in their administrative request helpers. The auth test requires both
the positive admin route and denial of each credential in the other role.
Production authentication is unchanged. All five hosted targets passed (3 auth,
2 cross-crate pipeline, 5 error-contract, 5 isolation and 2 lifecycle tests) in
`/tmp/chio-m4-proof-hosted-regressions.log`.

Proof fixture drift was traced to the retained raw-outcome schema
`chio.raw-invocation-outcome-with-signing-identity.v1`: federation context and
receipt-signing identity now participate in the outcome blob hash. Recomputing
all three old outcome identities using only the previous schema and omitting
those two fields reproduces the old fixture IDs exactly. The regenerated proof
verifier accepted the new evidence; the changes cascade through receipt IDs,
signatures, workflow commitments and selective-disclosure proof. The built-in
and example baseline use clock `1766000001000`; the recursive-swarm CLI template
uses `1800000001000`. The admission windows also differ: the harness regression
uses `1700000000000..1900000000000`, whereas the CLI retains the original
`1800000000000..1800003600000` window. The first CLI refresh incorrectly reused
the harness window and was rejected by exact parity. The corrected CLI fixture
was regenerated with its original window, not by broadening the authorization.
Both baseline profiles were independently verified. All 22 runtime-harness tests
passed, followed by all 147 CLI proof-contract tests with the corrected profile
(`/tmp/chio-m4-cli-proof-correct-profile.log`), including the tampered-report
negative. Exact package/report parity remains unchanged.

### Historical consumer findings from source discovery

These findings drove the implemented consumer ledger, exact source gate, public
parser repairs and migration contract. They are retained as discovery history,
not new milestone requirements or qualification waivers. Current results and
remaining final gates are in the acceptance report.

- The direct Rust construction/factory audit found 29 physical sites across
  crates, examples and benchmarks after excluding inline test modules. Two
  included test fragments require caller-context classification; fuzz and
  benchmark harnesses are separate from production authorities. This count does
  not cover all portable verifiers, SDKs, dispatch roots or macro-generated code.
- Python `chio-py`, TypeScript `chio-ts` and Go `chio-go` manifest invariant
  helpers still recognize only v1. Their v1 corpus is not v2 consumer evidence.
  The generated-schema lanes also live in different packages: Python
  `chio-sdk-python`, TypeScript `packages/conformance`, and Go `chio-go-http`.
  Baselines passed 179 Python tests, the TypeScript shared-corpus test and the Go
  HTTP suite. The subsequent shared 35-protocol/14-manifest corpus and actual
  public parser lanes now pass; the legacy helper version limits remain explicit.
- V2's schema rejected `annotations.estimated_duration_ms` while Rust accepted
  it. Adding a runtime assertion reproduced the mismatch (22 manifest-v2 tests
  passed, one failed). The public normative annotation field and its constructor
  literals have now been removed; only the private v1 migration parser retains
  it and converts it into `latency_hint`. This is an intentional Rust source
  break aligned with the existing v2 wire schema, not a second latency authority.
  The focused core, forward-compatibility and manifest suites passed 29, 7, 389,
  32 and 23 tests in `/tmp/chio-m4-manifest-single-latency.log`. Broad compilation,
  codegen and current-manifest parity subsequently passed. Final milestone
  qualification remains governed by M4.8.

## M4.1. Establish the complete consumer and support inventory

The worklist is maintained in [the consumer support ledger](consumer-support.md).
The existing adapter source gate now checks 29 construction and 86 dispatch
references. The ledger separately maps public protocol, caller, portable and SDK
roles to their owner tests, including effect-only connectors and non-production
harnesses. Source classification does not substitute for the pending final gates.

Owner: existing `formal/adapter-source-inventory.toml`,
`xtask/src/adapter_no_bypass.rs` and `xtask/src/adapter_no_bypass/source.rs`, with
a human-readable consumer table in the launch documentation. Extend the existing
inventory mechanism where practical, rather than creating a second broad scanner.

- [x] Enumerate non-test kernel construction, wrappers/factories, portable
  verification, tool discovery/import/export, dispatch and caller-control paths.
  Include `include!` fragments, aliases, macros, feature-gated code, binaries,
  integrations and executable examples. Inspect network/effect sites as well as
  `ChioKernel::new`; the existing adapter-name markers alone are not exhaustive.
- [x] Give every row a stable ID, exact path/symbol, public entrypoint, build
  features, role, reachable effect, trusted configuration source, installer or
  rejection point, authority/store requirements, wire transformations, recovery
  owner, positive/negative tests and evidence state.
- [x] Classify each entrypoint/profile pair as required-supported,
  explicitly-unsupported, or not an execution/authority boundary with a reason.
  Track planned, implemented and locally verified separately. Unknown rows block
  M4; a generic unsupported label cannot close a promised positive path.
- [x] Map the original requirements to rows and tests. Review advertised examples
  and SDK documentation so their claims do not exceed those rows.

Minimum seed inventory, to be expanded from source discovery:

| Surface | Existing source anchors / coverage |
| --- | --- |
| Central native construction | `chio-control-plane/src/lib.rs::{build_kernel, build_kernel_with_active_defense}` and `src/security.rs::ActiveDefenseRuntime` |
| Public Rust execution and custody | `chio-kernel` ordinary/nested/caller APIs, `chio-runtime` facade and `chio-runtime-core` admission hooks |
| Harness and CLI | `chio-runtime-harness/src/kernel.rs`; `chio-cli/src/cli/mcp/wrap.rs`; runtime/sidecar/remote startup reached by production CLI commands |
| HTTP authority and sidecar | `chio-http-core/src/authority.rs`; `chio-api-protect/src/evaluator.rs`, `src/proxy/mediated.rs` and `src/proxy/mediated/authenticated.rs` |
| MCP ingress and remote delivery | `chio-mcp-edge/src/runtime/tool_calls.rs`; `chio-mcp-remote/src/remote_mcp/session_core/authority_mode.rs`; hosted-MCP and transport/stdio launch paths |
| Other protocol ingress and providers | A2A, ACP-Client/edge/proxy, Tower, OpenAI, Anthropic and remaining provider adapter request/dispatch builders |
| Manifest and bridge transformations | `chio-core-types/src/manifest.rs`, `chio-manifest`, OpenAPI generator/bridge and `chio-cross-protocol` |
| Portable Rust/FFI | `chio-kernel-core`, browser/mobile kernels, `chio-bindings-ffi`, `chio-cpp-kernel-ffi`, binding helpers and their public request/verification models |
| Language consumers | Python `chio-sdk-python`, `chio-py` and relevant `chio-adapter-base` users; TypeScript `chio-ts`; Go `chio-go`; affected C++ consumers |
| Alternate products and examples | Remaining workspace constructors, direct network/tool effects and executable examples; classify actual reachability rather than rebuilding unrelated products |

Exit: every discovered boundary is accounted for and every required positive
profile has an owner and an acceptance case. The inventory is a finite worklist,
not a count copied from the old 62-constructor snapshot.

## M4.2. Close construction, activation and trusted-context gaps

Owners: central control-plane installation, runtime/harness, HTTP authority,
CLI wrapping and API-protect construction paths identified by M4.1.

- [ ] Route enforcement-capable constructors through the established installation
  contract. Where layering precludes a control-plane dependency, keep neutral
  kernel ports and reject unsupported opted-in profiles before effect-capable
  launch or authority acquisition. Do not add a kernel-to-policy/flow dependency.
- [ ] Validate the full selected authority profile: durable budget/admission,
  receipt and revocation state; required runtime, approval and DPoP participants;
  native flow/release/declassification custody; verified manifests; tenant policy;
  topology and trusted security-context source; executor pin for caller execution.
  Configured authority selection and request-triggered credential use are distinct.
- [ ] Refuse missing, ephemeral, mismatched, inactive or unreadable required stores
  without silently constructing replacements. Verify explicit legacy/ephemeral
  constructors cannot advertise the enforced or durable profile.
- [ ] Bind tenant/session/subject/epoch/lineage/generation to the trusted host or
  authenticated session. Headers, request bodies and discovery objects cannot
  select authority identities or upgrade historical context into live authority.
- [ ] Verify the exact installed guard/hook order, including existing restrictive
  overlays. Tripwire/containment and flow precede ordinary guards; raw-output
  tripwire precedes sanitization; final flow checks follow sanitization. Preserve
  existing added restrictions rather than reducing installation to an old list.
- [ ] Test Disabled compatibility, Shadow observation and Enforce denial/allow
  behavior at each applicable public factory. Shadow must not grant permission
  to bypass authentication or other independently enforced policy.

Acceptance: required native and mediated positive paths execute once through
production constructors and yield verified receipts. Missing context or any
required authority denies at the intended boundary with zero external effects;
output blocks expose no raw output. Unsupported CLI/portable profiles reject
explicitly. Existing guard-order tests remain green.

## M4.3. Qualify feature negotiation and authenticated manifests

Owners: core capability feature/signing/attenuation types, portable verifiers,
capability issuance/session negotiation, manifest parsing/registry and federation
handshake consumers. Preserve the existing implementation unless a test exposes
a gap.

- [ ] Exercise negotiated aggregate and cumulative approval semantics from
  advertisement/intersection through issuance, verification and dispatch. Legacy
  default features remain disabled as specified. Unknown or unnegotiated required
  semantics reject; a request field cannot select a rollout profile.
- [ ] Preserve exact signed aggregate/cumulative root bindings through delegation
  and lineage. Test omission, substitution and mixed-version peers. Apply the
  established portable multi-hop rejection until its authenticated witness
  contract exists; do not invent new portable delegation support in M4.
- [ ] Verify one normative public `ToolDefinition`, explicit v1 parsing/migration,
  v2 re-signing requirements, strict nested fields and unambiguous latency and
  side-effect annotations. Discovery data never substitutes for a verified v2
  registry entry.
- [ ] Test publisher flow declarations against tenant/data-owner policy and
  mandatory runtime egress. A publisher cannot widen clearance, erase an output
  floor, invent declassification purposes or label a remote boundary local.
- [ ] Preserve the legacy per-request approval constraint distinctly from
  cumulative approval. Test complete threshold sets, typed intents and negotiated
  bindings without widening M3's explicitly unsupported combined profiles.

Acceptance: mixed-version and field-mutation cases deny before dispatch; supported
negotiated calls preserve the original signed bytes and accounting owner. Positive
manifest verification and negative publisher-widening cases use the actual
registry and policy/topology resolution path.

## M4.4. Close protocol transformations and dispatch fallbacks

Owners: the M4.1 affected MCP, A2A, ACP-Client, provider, Tower, OpenAPI and
cross-protocol routes, reusing existing request builders and
`BridgeSecurityMetadata`.

- [ ] For each transformation, record input/output representation and preserve
  canonical authenticated semantics: flow declaration, root bindings, full
  approval set/proposal, governed intent, DPoP binding, context references,
  supplemental extension, operation ID and combined capture metadata.
- [ ] Carry constrained metadata in the authenticated Chio envelope or retained
  registry-bound sidecar when the external protocol lacks fields. Removing the
  sidecar, changing registry coordinates or exporting/importing without required
  authentication must reject. Human-readable descriptions are never authority.
- [ ] Keep supplemental authorization opaque for the installed verifier. Never
  deserialize it into a caller-selected quota claim or silently drop it to make
  an unsupported caller profile run. Preserve operation IDs in supported
  downstream idempotency metadata without claiming provider deduplication where
  none exists.
- [ ] Exercise synchronous, asynchronous, nested, batch and streaming variants
  where exposed. Check incremental output, cancellation, error translation and
  fallback paths for pre-release data leakage or unmediated retry. Reuse existing
  kernel handling and truthful unsupported-streaming denials where required.
- [ ] Test native, MCP, A2A and ACP-Client promised positives through public
  ingress, actual kernel admission and a counted local connector. Add provider
  projection round trips and explicit extension denials where support is not
  promised. No external provider account or live production effect is needed.

Acceptance: canonical flow bytes survive OpenAPI and applicable protocol round
trips; dropped/substituted authority is caught by the intended check. No adapter
selects only the first approval, retries an uncertain effect, or routes directly
to a provider after mediated denial. Each supported path produces the original
operation/capture/receipt binding and one effect.

## M4.5. Qualify caller-control and native-host consumers

Owners: API-protect authenticated mediation/control routes, remote session
authority and Rust caller entrypoints, Python sidecar transport helpers and
other advertised callers. Reuse [M3's contract](authenticated-caller-delivery.md).

- [ ] Verify reservation responses remain `reserved`, not executable permission.
  Start requires trusted configured authorizer/executor identity, exact original
  nonce/arguments/credentials and physical capture before signed authorization.
- [ ] Exercise trusted native host preflight, refreshed flow generation,
  reservation, start and report through public Rust APIs, including release-owner
  and declassification custody with combined runtime/DPoP/approval participants.
  Request-supplied context cannot replace that host authority.
- [ ] Keep admin/control tokens, executor signing keys and raw reports out of
  untrusted-agent APIs, diagnostics, exceptions and receipts. Test bearer/admin
  role separation, wrong executor/epoch, wrong request and unsigned report denial.
- [ ] Test lost start replies, exact start retry, report replay, late original
  delivery and changed delivery across the consumer boundary. Invoke the durable
  executor ledger rather than a fixture-only callback map. Recovery never renews
  the original execution interval or repeats an uncertain effect.
- [ ] Retain early rejection of deprecated unsigned reconciliation and direct
  reserve/execute integrations. Distinguish transport helpers from signature
  verification and custody ownership in SDK docs and tests.
- [ ] Keep supplemental and combined threshold-approval/credit-exposure caller
  profiles explicitly fail closed. Native caller custody is not on that list.

Acceptance: a complete consumer-level native caller invocation and restart/replay
returns only kernel-approved output and the original verified receipt, with one
effect and one declassification use where required. An untrusted session cannot
use control routes or manufacture custody. M3's exact 61-case gate stays required
for changes to its dependency closure.

## M4.6. Close four-language wire and affected FFI parity

Owners: `spec/PROTOCOL.md`, authoritative/embedded schemas and registry, xtask
generation, existing conformance/bindings vectors and actual SDK parse/send paths.

- [ ] Audit duplicated capability, request, result and feature shapes, not just
  newly added files. Include aggregate/cumulative bindings, bounded approval
  arrays, flow/declassification, DPoP, combined capture, pending approval, execution
  nonce versions and authenticated caller authorization/report schemas.
- [ ] Extend the existing shared positive/negative fixture corpus. Verify canonical
  decode/re-encode bytes and hashes in Rust, Python, TypeScript and Go. Use valid
  signatures and independently known bindings where authenticity is tested;
  schema acceptance is not signature verification.
- [ ] Test unknown nested fields, missing/extra authority, wrong schema domain,
  invalid IDs, boundary integers and bounded collections. Test duplicate map keys
  at supported raw-parser boundaries, recording parser limitations explicitly.
  Reject unrepresentable signed numeric values instead of rounding them.
- [ ] Verify actual runtime validators and client serialization. TypeScript
  compilation alone is insufficient; default Go unmarshalling or generated types
  alone must not silently erase security fields. Distinguish signature verifiers
  from schema/transport-only consumers in the support ledger.
- [ ] Regenerate all four languages through xtask, update authoritative schema
  hashes and registry, and run `make codegen-check`. No hand-edited generated
  models. Document intentional source/wire breaks and migration requirements.
- [ ] Cover both Python packages: the existing `check-chio-py.sh` lane exercises
  `chio-py`, not the M3 `chio-sdk-python` caller client. Run that client's tests
  separately, plus affected adapter-base integrations.
- [ ] Qualify browser/mobile/FFI negotiation and request preservation where shared
  shapes changed; run affected C++ consumer and kernel-FFI gates. Compilation is
  not mobile hardware qualification or native confinement evidence.

Acceptance: each required fixture has the same accept/reject and canonical-byte
outcome in all four languages. Every advertised sender preserves all required
fields into the kernel or rejects before sending. Shared FFI/C++ changes have
their existing behavioral gates, not only generated-header diffs.

## M4.7. Make consumer coverage executable

Owners: existing adapter source contracts, binding matrix, exact test-inventory
runner and relevant CI/test entrypoints. Add only the missing enforcement of the
M4 ledger, not a general new qualification framework.

- [ ] Link each required inventory row to its positive and negative tests. Extend
  existing source discovery to fail on new unclassified constructors/dispatch
  roots and stale classifications. Exemptions must name a narrow non-effect role,
  never a whole security-capable crate.
- [ ] Calibrate the guard with deliberate mutations: remove an installer call,
  erase an approval member/root binding, drop a constrained bridge sidecar,
  replace trusted context, omit caller start, and substitute direct-provider
  fallback. The responsible structural or behavioral check must fail. Restore
  calibration inputs without modifying the candidate under test.
- [ ] Add a bounded `scripts/check-consumer-boundaries.sh` milestone runner
  (proposed new file) using `run-exact-cargo-test-inventory.sh` for Rust cases and
  explicit SDK fixture counts. Missing, renamed, ignored, zero-match or skipped
  required tests fail. Populate counts from the final discovered cases, not a
  speculative target count in this plan.
- [ ] Test the runner/inventory failure modes. Reuse existing adapter and flow
  gates; source matching supplements behavior and is not proof of no bypass.
- [ ] Wire the runner into the appropriate existing local/CI lane with affected
  source selection. CI configuration changes do not authorize manual dispatch,
  changes to protected controller pins or bypassing repository policy.

Exit: adding a new unclassified boundary or deleting a named security test makes
the gate red, and the unmodified production candidate passes. Required checks
cannot silently disappear behind a feature flag or unavailable language tool.

## M4.8. Final qualification, documentation and handoff

- [ ] Run all affected full crate/integration suites and supported feature
  profiles after the exact M4 gate. Retain the workspace feature-unification
  configuration that exposed M4.0, plus portable/production variants selected by
  the inventory. Do not use an invalid blanket `--all-features` combination.
- [ ] Complete the four-language gates, required C++/FFI gates, codegen/schema
  checks, adapter contracts, security dependency checks and affected source/formal
  bindings. Review changed formal anchors before updating them; matching hashes
  do not prove new adapter or caller semantics.
- [ ] Run normal workspace build, full workspace tests, strict all-target Clippy,
  formatting and file hygiene on the final source. Record existing non-M4 ignored
  tests separately. No required M4 test may be ignored and no observed failing
  target may be silently excluded. Missing prerequisites mean incomplete evidence.
- [ ] Update launch status, consumer support rows, SDK/constructor migration notes
  and examples. Replace only current claims; preserve historical evidence and the
  explicit M1 confinement/hosted/operational boundaries.
- [ ] Record exact commit, clean-tree state, target/tool versions, Cargo features,
  command exits, test inventories and artifact locations. Keep implementation,
  local qualification, hosted CI and release authorization as separate states.
  Commit/push under existing PR-maintenance authority when execution is requested;
  do not merge or publish as part of M4.

Final exit: no unclassified consumer, every promised positive profile exercised,
every permitted unsupported profile rejected before its forbidden action, no
silent authority loss, final required local gates green, and a reproducible
consumer-boundary report. M5 can then use the supported constructors/adapters
without inventing new admission wiring. M6/M7 receive the same support ledger.

## Verification recipes and evidence discipline

Start with `umask 022`, disabled core dumps for deliberate abort tests, the pinned
Rust 1.94.1 toolchain and required WASM/SDK/C++ prerequisites. Use one Cargo
compilation owner and an explicit build-job limit appropriate to host memory/disk.
Use `--locked`; use cached/offline resolution when available, never alter lockfiles
merely to work around a missing tool. Isolated stores and single test-thread
diagnostics must be followed by the intended final gate, not substituted for it.

Existing core commands, to select at the checkpoint named above:

```bash
cargo xtask check adapter-no-bypass
bash scripts/tests/check-adapter-no-bypass.test.sh
bash scripts/check-security-dependencies.sh
bash scripts/check-authenticated-caller-delivery.sh
make codegen-check
bash scripts/check-chio-schema-registry.sh
cargo test --locked -p chio-conformance --test vectors_schema_pair
cargo test --locked -p chio-conformance --test protocol_primitives_authority_bindings
cargo test --locked -p chio-cross-protocol -p chio-provider-conformance
bash scripts/check-bindings-parity.sh
bash scripts/check-sdk-parity.sh
cargo build --workspace --locked
cargo test --workspace --locked --no-fail-fast
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
git diff --check
```

The parity scripts overlap; schedule their underlying lanes once while preserving
coverage and record that choice. Add `chio-sdk-python` pytest, affected adapter
tests, C++ kernel-FFI checks and feature-specific portable builds explicitly from
the inventory. A cached generated-file check is not a live protocol test. Do not
invoke package publication or external-consumer release jobs to qualify M4.

Suggested reviewable implementation slices: composed baseline repairs;
inventory/constructor enforcement; negotiation and bridge preservation; caller
consumers; shared wire/SDK parity; calibrated gate and closeout. Keep cross-layer
security fixes together when splitting would make an intermediate commit unsafe.
Do not create layered PRs merely to meet this suggested slice count.

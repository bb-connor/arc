# Work Protocol and Developer Surface Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax. Consume the agreed W1/W2 interfaces and the recovery lane's host negotiation contract.

**Goal:** Make two different agent applications use the same work abstraction through supported protocols and installed SDKs.
**Architecture:** Extend existing cross-protocol fidelity/lifecycle contracts and process clients. The owner service remains the single work adapter over native authority.
**Tech Stack:** Rust, existing protocol adapters, Python chio-process, TypeScript @chio-protocol/process, CLI and conformance fixtures.
**Spec:** [developer surface](../specs/2026-10-03-work-developer-surface-design.md).

## Global Constraints

- Adapters translate envelopes and return bounded projections; they do not implement their own allocation, authorization, recovery or financial reducer.
- Keep the original route and request fixed after sealing.
- Work command frames are at most 2 MiB; work view frames are at most 8 MiB.
- A work handle and every transported commitment are evidence or references. They never mint live authority or install trust.
- Apply all [parent constraints](../specs/2026-10-03-agentic-work-kernel-design.md#global-constraints).

## Review Focus

- A bridge strips an allocation, approval or route binding: refuse before execution (W3.1).
- An old SDK silently treats an unknown work operation as ordinary invoke: explicit unsupported protocol (W3.2).
- Timeout causes the SDK to generate a fresh command ID or repeat a provider effect: preserve original reference, no automatic fresh call (W3.2).
- A retained result is leaked through an error, stream, export or status path: recovery release checks apply to all enabled channels (W3.1/W3.3).
- The second application contains hidden custom authority/recovery glue: public-interface dependency audit and source review (W3.3/W3.4).

LC01 through LC06 in the [developer specification](../specs/2026-10-03-work-developer-surface-design.md#required-composition-cases) are mandatory acceptance cases across the same two applications. W1.3/W1.5 add the profile and acceptance/join contracts; W2 owns actual peer and recovery composition.

## W3.1: Shared work profile and protocol conformance

**Files:**

- Modify: crates/protocol/chio-cross-protocol/src/lifecycle.rs, semantic_hints.rs.
- Create: crates/protocol/chio-cross-protocol/src/work_profile.rs.
- Modify: crates/protocol/chio-cross-protocol/src/lib.rs.
- Create: fixtures/work-contract/accepted.json, substitutions.json, unsupported.json.
- Test: crates/protocol/chio-cross-protocol/tests/work_contract.rs.
- Extend owning tests in crates/protocol/chio-mcp-edge, chio-a2a-edge, chio-acp-edge and crates/products/chio-api-protect.
- Update: docs/standards/CHIO_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json; reconcile its relationship to CHIO_UNIVERSAL_CONTROL_PLANE_QUALIFICATION_MATRIX.json.

**Interfaces:**

- WorkProfileSupportV1 contains schema/version and admission, dispatch, execution-observation, release, recovery, work-transport and funding dimensions, plus resolved_profiles, acceptance_evidence and all_success_join support. It describes mediation support, distinct from W1 WorkProfileV1's resolved working terms.
- validate_work_projection(required: &WorkProfileSupportV1, offered: &WorkProfileSupportV1) -> Result<(), BridgeError>.
- Each supported bridge carries the W1 commitment binding through the existing OrchestratedToolCall path without changing signed bytes.
- Unsupported profiles return a named error and no kernel dispatch.

- [ ] Add shared vectors for accepted bindings, changed capability/request/route/receiver, consumed continuation, unsupported release profile and unknown version. Include positive cases for each supported protocol, not negative-only conformance.
- [ ] Add profile-generation/account substitution, wrong artifact/evaluator, a join draft presented as authority, dependency category changed in transit, and unauthorized recovery-link vectors. Assert exact retained terms and evidence survive each supported path; unsupported composition dimensions refuse explicitly.
- [ ] Run cargo test --locked -p chio-cross-protocol --test work_contract. Expect missing profile/validation.
- [ ] Extend existing lifecycle/fidelity negotiation. Map each adapter's actual boundary. Do not mark Envoy admission or provider trace observation as full work execution.
- [ ] Run the same semantic vectors through the four named live adapter paths. Assert owning kernel receipts and actual tool effects. Replaying through a different route is rejected; creating a fresh separately bound call through another protocol is supported only when advertised.
- [ ] Add malformed-body and output/error/stream canaries using the security/recovery suites rather than adapter-local bypasses.
- [ ] Run focused adapter tests and cargo clippy --locked -p chio-cross-protocol --all-targets -- -D warnings.
- [ ] Commit: feat(protocol): expose the common work contract with explicit fidelity.

Acceptance: AW11/AW15/AW26/AW28 at protocol boundaries. The matrix distinguishes implemented, locally qualified, hosted-qualified and unsupported surfaces.

## W3.2: Installed Python and TypeScript work clients

**Files:**

- Modify: crates/kernel/chio-process/src/worker.rs and its worker-server composition, in coordination with recovery P6.
- Create: crates/kernel/chio-process/src/worker/work_transport.rs.
- Create: crates/platform/chio-control-plane/src/work/worker_service.rs.
- Create: sdks/python/chio-process/src/chio_process/work.py and tests/test_work.py.
- Modify: sdks/python/chio-process/src/chio_process/__init__.py.
- Create: sdks/typescript/packages/process/work.mjs, work.d.ts and test/work.test.mjs.
- Modify: sdks/typescript/packages/process/package.json exports/files.
- Test: crates/kernel/chio-process/tests/work_transport.rs.

**Interfaces:**

- WorkCommandService is the narrow bounded-byte extension needed beyond existing InvocationPreparer. Reuse WorkerService authentication, credentials, limits and connection lifecycle; do not add a second worker listener/credential store. It receives verified process context and cannot issue native execution ownership.
- The control-plane adapter decodes and authorizes chio.work.v1 using W1/W2 types. Keep chio-process independent of runtime-core and control-plane.
- Python WorkClient.prepare(proposal), submit(command), query(query), and inspect(handle) as a query convenience; TypeScript exposes the same operations and closed outcomes. Original-ID query works before a handle exists. collect helpers submit Reconcile; result access uses the recovery lane's existing release client.
- Catalog/Profile use query; Join uses prepare and the existing Extend command. Views expose WorkAcceptanceV1 and WorkRecoveryLinkV1 separately. Recovery links enter the already implemented recovery client operations with their original scope, workflow and revision; the work SDK does not introduce its own resume/approve state.
- The private worker connection descriptor declares negotiated protocols. chio.process.v1 retains its current behavior.

- [ ] Add shared client fixtures for preparation, success, Pending, denied result release, unsupported profile, cross-process handle and lost response. Assert the transmitted command ID is exactly caller-supplied, signed material comes from the owning service, and no hidden second submission occurs.
- [ ] Add catalog pagination/reload, acceptance versus payment, unsigned Join draft, stale recovery offer and caller-revoked-after-response-loss fixtures. Assert zero automatic offer selection/approval/resume and no leakage of private policy or artifact bytes into SDK errors. Use the native recovery client for the positive LC03 path.
- [ ] Run Python unittest discovery and node --test test/work.test.mjs in the process package; run cargo test --locked -p chio-process --features worker-server --test work_transport. Expect missing client/extension before implementation.
- [ ] Implement transport and client wrappers using existing deadline/frame/secret handling and the same versioned schema/vectors. Preserve lossless wide-integer/digest representations in Python/TypeScript; do not reserialize signed records through JavaScript Number. Do not make signing or policy decisions in SDK code.
- [ ] Add nested duplicate/unknown-variant, maximum/one-over, metadata/error-canary and stalled-session vectors. Assert original preparation/command lookup, bounded buffers and no raw retained output through query/reconcile.
- [ ] Test old process clients against the extended host and new work clients against an old-profile host. Unknown work protocol is a clear error, never a fallback to raw invoke.
- [ ] Re-run installed-package tests, not only source imports: extend scripts/qualify-process-packages.py to install the wheel/tarball and assert module origins and declared work exports.
- [ ] Commit: feat(sdk): expose work commands through process clients.

Acceptance: AW12/AW29. Language choice does not change authority, acceptance, retry, release or settlement semantics.

## W3.3: CLI and two applications using only the public contract

**Files:**

- Create: crates/products/chio-cli/src/cli/work.rs and cli/types/work.rs.
- Modify: crates/products/chio-cli/src/cli/types.rs, cli/dispatch/mod.rs and src/main.rs for the existing path-based module registration.
- Extend: examples/owner-work/ from W2.5.
- Refactor: examples/federated-work/src/funded_work/evolving.rs and graph helpers into public-client workload code.
- Add: examples/owner-work/api_review.py, support_disclosure.mjs, scenarios.json.
- Create: sdks/python/chio-langgraph/src/chio_langgraph/work.py and tests/test_work_node.py; extend its __init__.py exports and README.md using the existing optional process dependency.
- Add: examples/owner-work/api_review_langgraph.py as an entrypoint for application A's same domain functions, not a third application.
- Extend: scripts/qualify-process-packages.py and examples/reference-swarm's existing qualification entrypoints.
- Update: docs/reference/WORK_PROGRAMMING.md and WORK_OWNERS.md.

**Interfaces:**

- chio work init/serve/submit/inspect/collect/export use the existing private-directory, host profile and W2 service.
- init is a local owner operation; serve requires actual qualified authority activation.
- scenarios.json names each application's owner profiles, inputs, acceptance checks, requested fault cutpoints and expected effect/state observations. It does not contain private keys.
- Application A uses the API-review workload; B consumes the recovery lane's support-disclosure implementation.
- scenarios.json includes LC01-LC06, each with original request/owner/profile-generation references, actual effect observer, positive/negative expectations and evidence paths. Shared fixtures may cover multiple cases; a local one-administrator result retains that scope.
- ChioWorkNode(client: WorkClient, *, request_key: str = "work_request", response_key: str = "work_response") is a LangGraph Runnable over persisted state. Its request is a closed Prepare/Submit/Query work envelope from the shared SDK, with explicit stable command/preparation IDs where applicable. It writes bounded authorized observations under response_key, never model-message content or raw artifact bytes. Follow the existing ChioProcessToolNode checkpoint-before-dispatch discipline; leave planning/checkpoint ownership with LangGraph and propagate uncertainty without a new ID or local fallback.

- [ ] Write CLI tests for missing/invalid profile, changed store identity, unsupported work protocol and a successful installed-client run.
- [ ] Implement CLI adapters with no separate scheduler, retry logic or authority state. Reuse existing process-host startup and source activation. inspect supports original command/preparation IDs; collect performs historical reconciliation only. Protected result reads use existing recovery release commands.
- [ ] Run application A across owner services, with plan growth and intermediary loss. Confirm the child's original accepted claim remains collectible and the parent unknown effect is retained.
- [ ] Run application B with owner-approved disclosure, a distinct authorized continuation, protected artifact release and process loss. Confirm exactly one permitted publication and no unauthorized output channels.
- [ ] Execute LC01-LC04 through the installed shared clients. Include unused approved provider selection, exact acceptance plus all_success join, scoped recovery navigation, policy reload at the named cutpoints and a separately authorized workflow progressing beside unknown work. Assert the negative controls in the spec at real native boundaries.
- [ ] Execute LC05 with the same consumer domain-function source hash against direct and internally delegated implementations satisfying the same external requirements. Permit configuration/new commitment changes; reject added effects/readers or substituted acceptance terms without renewed admission. Record any changed application authority glue as a failure of this case.
- [ ] Execute LC06 in single-owner unpaid, enrolled cross-owner unpaid and qualified funded profiles. Assert unpaid execution makes no funding calls. Extend the package qualifier to install the existing LangGraph adapter/process SDK plus ChioWorkNode and run application A with durable checkpoints and a deterministic planner. Assert actual installed module origins, unchanged IDs after worker loss, changed-body conflict, honest pending/refused outcomes and no local callback execution or checkpointed credentials.
- [ ] Switch the client host/language and one supported protocol for newly created commitments, leaving application task logic intact. A sealed route remains immutable.
- [ ] Audit application imports and host glue: no example-private modules, runtime-core, direct native-store writes, raw ToolCallRequest credential containers, custom signature verification, payment state machine or provider retry loop. Necessary policy, checker and task logic remain explicit.
- [ ] Run cargo test --locked -p chio-cli with the owning CLI filters and the extended installed-package qualification. Retain the actual enforced platform/profile.
- [ ] Run python -m pytest sdks/python/chio-langgraph/tests/test_work_node.py in its locked adapter environment, then the extended scripts/qualify-process-packages.py scenario. Source-only tests do not establish the installed-harness result.
- [ ] Commit: feat(cli): run reusable work programs from installed clients.

Acceptance: AW13/AW27/AW28/AW29/AW30/AW31 and LC01-LC06. Both applications work through the same documented interface with actual effects and authority checks. Missing required recovery/native/harness evidence is pending or unavailable, not passed.

## W3.4: Demonstrate the systems contribution and stop

**Files:**

- Create: docs/research/work-abstraction/EVALUATION.md, results.json, responsibility-map.json.
- Extend the existing qualified workload harness rather than adding a new benchmark runtime.
- Preserve: existing SQL/escrow comparison artifacts and their original source pins.

**Interfaces:** Responsibility rows identify owner (Chio/common baseline/application), implementation path, exercised scenario, source revision and observed outcome. results.json records LC01-LC06 source/profile/effect/evidence references and terminal status independently; no aggregate success flag hides a failed case.

- [ ] Inventory the existing comparator's actual coverage and record a matched comparison contract for any quantitative claim retained in the paper: equivalent keys, funds, trust, confinement, outputs and fault rules. Default to no quantitative superiority claim; do not make a new full comparator implementation a beta prerequisite.
- [ ] Record developer setup, application-specific coordination code, configuration/dependencies, task outcomes, actual effects and resource/capital/checker costs. Separate cold setup from reuse by application B.
- [ ] Record the unchanged consumer logic and exact permitted configuration/binding changes for LC05, plus the adoption stages and installed LangGraph package hashes for LC06. Retain limits: configured substitution is not a general equivalence proof, and a catalog-selected peer is not permissionless discovery.
- [ ] Count only actual measured implementation effort; code size is a descriptive metric, not proof of engineering effort. If a quantitative superiority claim is retained, execute its matched comparison and publish any tie/loss. Otherwise record that claim as unestablished and complete the mandatory two-application responsibility/cost report.
- [ ] Verify the evaluation can be reproduced from the installed package and report exact source/artifact identities.
- [ ] Review whether the paper's reusable-abstraction claim is supported by both applications. If not, fix the shared interface once; do not invent a third application or another novelty hypothesis.
- [ ] Commit: docs(work): evaluate reusable cross-owner programming.

Acceptance: AW14/AW31. The evidence addresses a systems abstraction; no claim that conventional components cannot reproduce a particular outcome.

Stop condition: working reuse, bounded compatibility and honest comparative reporting. Extra protocol families, a marketplace and arbitrary graph editing are separate future work.

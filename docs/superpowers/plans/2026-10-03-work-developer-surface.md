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

- WorkProfileSupportV1 contains schema/version and admission, dispatch, execution-observation, release, recovery, work-transport and funding dimensions.
- validate_work_projection(required: &WorkProfileSupportV1, offered: &WorkProfileSupportV1) -> Result<(), BridgeError>.
- Each supported bridge carries the W1 commitment binding through the existing OrchestratedToolCall path without changing signed bytes.
- Unsupported profiles return a named error and no kernel dispatch.

- [ ] Add shared vectors for accepted bindings, changed capability/request/route/receiver, consumed continuation, unsupported release profile and unknown version. Include positive cases for each supported protocol, not negative-only conformance.
- [ ] Run cargo test --locked -p chio-cross-protocol --test work_contract. Expect missing profile/validation.
- [ ] Extend existing lifecycle/fidelity negotiation. Map each adapter's actual boundary. Do not mark Envoy admission or provider trace observation as full work execution.
- [ ] Run the same semantic vectors through the four named live adapter paths. Assert owning kernel receipts and actual tool effects. Replaying through a different route is rejected; creating a fresh separately bound call through another protocol is supported only when advertised.
- [ ] Add malformed-body and output/error/stream canaries using the security/recovery suites rather than adapter-local bypasses.
- [ ] Run focused adapter tests and cargo clippy --locked -p chio-cross-protocol --all-targets -- -D warnings.
- [ ] Commit: feat(protocol): expose the common work contract with explicit fidelity.

Acceptance: AW11/AW15. The matrix distinguishes implemented, locally qualified, hosted-qualified and unsupported surfaces.

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
- The private worker connection descriptor declares negotiated protocols. chio.process.v1 retains its current behavior.

- [ ] Add shared client fixtures for preparation, success, Pending, denied result release, unsupported profile, cross-process handle and lost response. Assert the transmitted command ID is exactly caller-supplied, signed material comes from the owning service, and no hidden second submission occurs.
- [ ] Run Python unittest discovery and node --test test/work.test.mjs in the process package; run cargo test --locked -p chio-process --features worker-server --test work_transport. Expect missing client/extension before implementation.
- [ ] Implement transport and client wrappers using existing deadline/frame/secret handling and the same versioned schema/vectors. Preserve lossless wide-integer/digest representations in Python/TypeScript; do not reserialize signed records through JavaScript Number. Do not make signing or policy decisions in SDK code.
- [ ] Add nested duplicate/unknown-variant, maximum/one-over, metadata/error-canary and stalled-session vectors. Assert original preparation/command lookup, bounded buffers and no raw retained output through query/reconcile.
- [ ] Test old process clients against the extended host and new work clients against an old-profile host. Unknown work protocol is a clear error, never a fallback to raw invoke.
- [ ] Re-run installed-package tests, not only source imports: extend scripts/qualify-process-packages.py to install the wheel/tarball and assert module origins and declared work exports.
- [ ] Commit: feat(sdk): expose work commands through process clients.

Acceptance: AW12. Language choice does not change authority, retry, release or settlement semantics.

## W3.3: CLI and two applications using only the public contract

**Files:**

- Create: crates/products/chio-cli/src/cli/work.rs and cli/types/work.rs.
- Modify: crates/products/chio-cli/src/cli/types.rs, cli/dispatch/mod.rs and src/main.rs for the existing path-based module registration.
- Extend: examples/owner-work/ from W2.5.
- Refactor: examples/federated-work/src/funded_work/evolving.rs and graph helpers into public-client workload code.
- Add: examples/owner-work/api_review.py, support_disclosure.mjs, scenarios.json.
- Extend: scripts/qualify-process-packages.py and examples/reference-swarm's existing qualification entrypoints.
- Update: docs/reference/WORK_PROGRAMMING.md and WORK_OWNERS.md.

**Interfaces:**

- chio work init/serve/submit/inspect/collect/export use the existing private-directory, host profile and W2 service.
- init is a local owner operation; serve requires actual qualified authority activation.
- scenarios.json names each application's owner profiles, inputs, acceptance checks, requested fault cutpoints and expected effect/state observations. It does not contain private keys.
- Application A uses the API-review workload; B consumes the recovery lane's support-disclosure implementation.

- [ ] Write CLI tests for missing/invalid profile, changed store identity, unsupported work protocol and a successful installed-client run.
- [ ] Implement CLI adapters with no separate scheduler, retry logic or authority state. Reuse existing process-host startup and source activation. inspect supports original command/preparation IDs; collect performs historical reconciliation only. Protected result reads use existing recovery release commands.
- [ ] Run application A across owner services, with plan growth and intermediary loss. Confirm the child's original accepted claim remains collectible and the parent unknown effect is retained.
- [ ] Run application B with owner-approved disclosure, a distinct authorized continuation, protected artifact release and process loss. Confirm exactly one permitted publication and no unauthorized output channels.
- [ ] Switch the client host/language and one supported protocol for newly created commitments, leaving application task logic intact. A sealed route remains immutable.
- [ ] Audit application imports and host glue: no example-private modules, runtime-core, direct native-store writes, raw ToolCallRequest credential containers, custom signature verification, payment state machine or provider retry loop. Necessary policy, checker and task logic remain explicit.
- [ ] Run cargo test --locked -p chio-cli with the owning CLI filters and the extended installed-package qualification. Retain the actual enforced platform/profile.
- [ ] Commit: feat(cli): run reusable work programs from installed clients.

Acceptance: AW13. Both applications work through the same documented interface with actual effects and authority checks.

## W3.4: Demonstrate the systems contribution and stop

**Files:**

- Create: docs/research/work-abstraction/EVALUATION.md, results.json, responsibility-map.json.
- Extend the existing qualified workload harness rather than adding a new benchmark runtime.
- Preserve: existing SQL/escrow comparison artifacts and their original source pins.

**Interfaces:** Responsibility rows identify owner (Chio/common baseline/application), implementation path, exercised scenario, source revision and observed outcome.

- [ ] Inventory the existing comparator's actual coverage and record a matched comparison contract for any quantitative claim retained in the paper: equivalent keys, funds, trust, confinement, outputs and fault rules. Default to no quantitative superiority claim; do not make a new full comparator implementation a beta prerequisite.
- [ ] Record developer setup, application-specific coordination code, configuration/dependencies, task outcomes, actual effects and resource/capital/checker costs. Separate cold setup from reuse by application B.
- [ ] Count only actual measured implementation effort; code size is a descriptive metric, not proof of engineering effort. If a quantitative superiority claim is retained, execute its matched comparison and publish any tie/loss. Otherwise record that claim as unestablished and complete the mandatory two-application responsibility/cost report.
- [ ] Verify the evaluation can be reproduced from the installed package and report exact source/artifact identities.
- [ ] Review whether the paper's reusable-abstraction claim is supported by both applications. If not, fix the shared interface once; do not invent a third application or another novelty hypothesis.
- [ ] Commit: docs(work): evaluate reusable cross-owner programming.

Acceptance: AW14. The evidence addresses a systems abstraction; no claim that conventional components cannot reproduce a particular outcome.

Stop condition: working reuse, bounded compatibility and honest comparative reporting. Extra protocol families, a marketplace and arbitrary graph editing are separate future work.

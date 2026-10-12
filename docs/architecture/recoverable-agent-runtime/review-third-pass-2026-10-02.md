# Third-pass Rust and architecture review

Date: October 2, 2026. Input: architecture revision 2. Result: revision 3, still proposed. Confidence: high in the source findings and identified contract ambiguities; moderate in integration effort until the native implementation and cutpoint corpus exist.

The architecture should retain its existing kernel authority and two small pure crates. This pass found six corrections worth making. The largest was compatibility with strict nonce preflight: a frozen process request and an execution request carrying the original native nonce are distinct representations of the same operation. Revision 2 did not describe that boundary precisely enough.

These findings concern the proposed integration contract. They are not assertions that the existing runtime contains six exploitable vulnerabilities. Source pins remain the retained security/process research candidate; this pass did not rebase or claim a freshly fetched remote head. The [input inventory](review-third-pass-inputs.json) preserves hashes of the complete revision-2 package. The [previous review](review-2026-10-02.md) remains a historical record.

## Corrections

| Finding | Risk in the earlier specification | Revision 3 decision and acceptance |
|---|---|---|
| THIRD-01: Distinct request bindings | Generic request-hash wording could conflate canonical arguments, frozen process input and native immutable material, or drop semantic authorization fields | Give each digest its own type and owning derivation. Exhaustive Rust field projection must account for governed intent, model constraints, federation identity and every extension. Preserve v1 hash meanings. RUST-11, REC-21. |
| THIRD-02: Native nonce preflight | An implementation could persist intent too late, rewrite the process hash after attaching a nonce, or renew issuance after losing its acknowledgement | Persist intent before preflight. Read back and attach the exact original native issuance, preserve phase-specific deadlines and include every participant in closure. REC-24. |
| THIRD-03: Exact signed-envelope custody | A process digest and credential-free historical request cannot reconstruct the original signed caller envelope after restart | Retain bounded protected exact request/authorization custody before process finalization; preserve the existing native historical record's exclusions. Lost bytes cannot justify fresh signatures. REC-23. |
| THIRD-04: Composite approval semantics | All-required coverage lacked a complete acyclic binding order and a precise rule against mixed-context attestations, duplicate principals or different target powers | Review unsigned authorization requirements first; bind every contributing approval to the same action, requirements, source and challenge. Compose disclosure coverage into one native-verified grant under the explicitly scoped aggregate issuer. Integrity endorsement has its own typed artifact and participant. REC-22. |
| THIRD-05: Recovery after revocation | Reusing ordinary invoke could strand native work after process cancellation or capability expiry; swapping in maintenance credentials could overauthorize it | Extend the existing fenced recovery owner with narrow historical settlement scope. Current provider lookup and recipient-release authority remain separate. OPS-13. |
| THIRD-06: Planner versus driver API | One result enum mixed advisory search, exact offers, runtime progress and operation recovery | Separate `PlanDecision` from pure `WorkflowDirective`; materialization and signing stay in the host, execution stays in native capture. Neither enum confers authority. RUST-11. |

Detailed contracts are in [Rust structure](02-rust-design.md), [recovery protocol](03-recovery-protocol.md), [operations](08-protocol-operations.md) and the [binding catalog](11-contract-catalog.md). The [delivery sequence](10-delivery-decisions.md) now includes these boundaries in P0/P1, with three additional architectural decisions. There are 111 requirements, 21 ADRs and 15 mapped functionality groups. All original capability groups remain covered; this pass introduces no additional runtime, policy language or execution coordinator.

## Source evidence

The [source inventory](source-map.json) now verifies 57 development-source inputs and 22 findings. Four new findings distinguish payload/process/native digests, operation-owned nonce issuance and preflight knowledge, existing startup settlement, and single-grant native consumption. In particular:

- `ProcessRuntime::invoke_with_recovery` freezes the caller-supplied request before attaching retained native nonce material.
- Native `RetainedToolAdmissionRequestV1` explicitly strips DPoP, nonce, approval, supplemental and declassification credentials; it cannot substitute for exact process-envelope custody.
- Native nonce routing compares the presented issuance with the retained original operation. Its expiry behavior depends on native phase, rather than imposing a fresh-issuance test on all historical work.
- Native startup reconciliation owns operations through serving fences and recovery leases. New process invocation still checks that the process is running and restores/verifies capability ancestry.

These are inspected implementation facts, with precise files in the [source crosswalk](source-map.md). V2 approval composition, the recovery envelope and new host ports remain proposed changes.

## Verification performed

The [model runner](model/run.py) compiled all three architecture programs using Rust 1.94.1, Rust 2021 and denied warnings, after checking formatting. Existing ownership and revision-2 baselines still passed with their 12 expected mutation failures.

The new [nonce model](model/third_nonce.rs) explored 133 states and 252 transitions. Useful completion is reachable after a crash loses the native issuance acknowledgement. It rejects five deliberate faults, including requiring live initiating authority for already-owned internal settlement. That last property establishes a locally available transition under the model's recovery-authority assumption, not eventual fairness.

The [coverage corpus](model/third_contracts.rs) checked 3,844 symbolic cases and rejected three deliberate faults: accepting partial coverage, mixing approval contexts, and counting principal aliases twice. This is not real signature or label-algebra testing. The [retained output](model/third-results.txt) and [source-bound model evidence](model/evidence.json) state the assumptions and exclusions. All 20 mutations across the package fail for their expected reasons; their counts are not production security assurance.

The existing foundation command `cargo test --locked -p chio-process --test nonce_recovery` passed: three top-level tests, zero failures. This includes one subprocess helper and two behavior tests covering one execution across reopen and retained original nonce/custody after abrupt process death with an unknown effect. The [test record](foundation-tests-third-pass.json) includes command, toolchain and selected source hashes. It is a tool-observed summary, not a retained full build transcript. These tests do not exercise proposed recovery-v2 code.

The architecture checker verifies requirement/table equality, owner/test/phase mappings, local links, source hashes, model source/output evidence, unchanged root build inputs and documentation formatting. Negative checks on temporary package copies confirmed that it rejects modified model source, modified retained output and a changed foundation-test count; the positive control passed. Prior review records and the four existing model sources/results remain byte-identical to revision 2. The final [validation record](validation.json) reports its exact scope. No production implementation was changed by this review. Existing research prototypes and the original dirty checkout were preserved; no commit, push or deployment was performed.

## Principal-engineering judgment

The design is ready to move from architecture review to a small native implementation slice. The next useful evidence is exact-envelope finalization plus strict-nonce preflight/readback through the actual two stores, followed by one reviewed disclosure and real crash cutpoints. More prose cannot establish transaction composition, latency or operational recovery. Keep the remaining functionality behind the stated dependency phases and qualify each enabled native participant combination explicitly.

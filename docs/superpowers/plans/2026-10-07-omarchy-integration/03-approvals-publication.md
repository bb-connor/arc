# Exact Approvals and Reviewed Publication Implementation Plan

| Boundary scope | `boundary_class` | `planning_status` | Decision and execution gate |
| --- | --- | --- | --- |
| `approval_and_publication` | `prevent` | `blocked_by_adr` | Owner decisions F1/F2/F3 on product, operator ABI and native contract; then completed P2, native-approval-decision-binding.json and exact enrolled destination/recovery. |
| `review_guidance` | `advisory_only` | `blocked_by_adr` | Owner decisions F1/F2 on task/review model; displayed proposal text conveys no grant and cannot replace the native decision. |
| `outcome_observation` | `detect_only` | `ready_after_adr` | Accepted ADR-0011 permits independent receipt/destination probes; observed output cannot authorize an effect or manufacture original-operation recovery. |

Metadata follows [ADR-0011](../../../adr/ADR-0011-boundary-taxonomy-product-wording.md) and the [plan-set inheritance and owner-decision gate](README.md#boundary-metadata-and-inheritance). Classes describe proposed boundaries, not delivered qualification.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable one exact native operator decision and reviewed delivery of the admitted project artifact to its fixed private local review destination.

**Architecture:** The native approval owner creates, verifies, retains and consumes decisions. The desktop opens a trusted bounded review and submits an opaque native decision handle; the coding resource owns immutable artifact publication and original-result recovery.

**Tech Stack:** Proposed Rust desktop adapter/controller modules, installed native bridge operator, existing Chio approval verification, pinned coding-resource participant, Python fault harness and native reviewer UI.

---

Status: Proposed. Confidence: high in the blocking decision-binding defect and required boundary, moderate in delivery until the replacement utility is qualified. All implementation/test commands are future execution instructions, not claims that their files exist or tests have run. Preserve unrelated work and use an isolated execution worktree.

Prerequisites: complete P2 `project-v1`; `native-approval-decision-binding.json` produced by a replacement native operator; exact source/test/artifact and destination bindings. Read [authority](../../specs/2026-10-07-omarchy-integration/06-authority-approvals.md), [operator protocol](../../specs/2026-10-07-omarchy-integration/05-operator-protocol.md), [project resource](../../specs/2026-10-07-omarchy-integration/09-project-resource.md) and [hosts](../../specs/2026-10-07-omarchy-integration/07-host-provider-adapters.md).

Publication here means reviewed delivery to the private local `review` artifact store. It does not add Git push, pull-request creation, deployment, checkout writeback or arbitrary destinations. Those require separate resource/effect contracts and qualification.

## Files and ownership

| Proposed or existing target | Responsibility |
| --- | --- |
| `crates/products/chio-desktop/src/adapter/approval.rs` | Pinned native proposal/decision adapter, no independent signer |
| `crates/products/chio-desktop/src/controller/review.rs` | Exact revision/proposal review state and opaque decision submission |
| `crates/products/chio-desktop/src/contracts/review.rs` | Bounded escaped projection of native bindings |
| `crates/products/chio-desktop/tests/approval.rs` | Native-unavailable, mismatch, expiry, replay and cancellation tests |
| `integrations/omarchy/qualification/approvals.py` | Real decision-before-retention and publication cutpoints |
| `integrations/omarchy/tests/test_approvals.py` | Harness false-green and missing-original regressions |
| `integrations/omarchy/fixtures/approvals/` | Synthetic hostile review text, expired/substituted proposal and destination fixtures |
| Separate bridge source `src/gateway-operator.ts` and proposed `test/gateway-operator-decision.test.mjs` | Native decision-before-retention fix and regression, maintained in its owning package |
| Separate public Pi package `src/operator-cli.ts`, `src/operator.ts`, `test/operator.test.mjs` | Remove the current refusal only after the replacement artifact is pinned and proven |

The inspected vendored bridge source map identifies `src/gateway-operator.ts`; the installed binary is `dist/gateway-operator.js`. Do not patch vendored generated JavaScript in place or assume another archive with version 0.3.0 is the same code. Native fix delivery is an explicit upstream handoff and archive update.

### Task 1: Reproduce and close the native decision-retention mismatch

- [ ] Retain current unavailable behavior in the desktop capability gate. Write the first controller test with a current-artifact descriptor and both choices `approved`/`denied`; assert the result is `prerequisite_unavailable`, native child/admin traffic counters are zero and no approval file appears. Run `cargo test -p chio-desktop --test approval frozen_operator_decision_is_unavailable`; expected red before the guard and green after adding it.
- [ ] In the bridge owner's isolated checkout, add a native utility regression using an actual signed token returned by the controlled native approval fixture: requested denial, returned approved token for the exact request. Also test requested approval with denied token, wrong approval ID, wrong subject/request/arguments and expired token. Assert before/after native retained credential inventories and actual gateway resume effect counter.

```python
assert observed["requested_decision"] == "denied"
assert observed["returned_signed_decision"] == "approved"
assert observed["retained_credentials_after"] == observed["retained_credentials_before"]
assert observed["resource_dispatches_after_resume_attempt"] == 0
assert observed["original_proposal_id_after"] == observed["original_proposal_id_before"]
```

These are required assertions in `qualification/approvals.py`; observations come from independent native store/resource readers, not the utility's console text.
- [ ] Add the proposed bridge regression file `test/gateway-operator-decision.test.mjs` using Node's built-in test runner, invoking the installed `dist/gateway-operator.js` through literal argv against the controlled native fixture. Run `node --test test/gateway-operator-decision.test.mjs`. Record that command and source/archive hashes in `native-approval-decision-binding.json`. Expected red on the frozen archive: the signed approved credential can be retained after requested denial in the component reproduction.
- [ ] Change native `src/gateway-operator.ts` so signature verification, original request/authority binding, requested decision, approval ID, expiry and retained proposal equality all pass before any usable credential retention. Use the native token parser/verifier. A post-write check, alternate token format or controller-only check is insufficient. Run the full native mismatch matrix for green, then actual kernel deny/approve/resume with separate resource observation.
- [ ] Publish only the newly built artifact into the qualified local bundle through its owner workflow, update Pi's pinned archive/integrity and consumer lock, and retain the old refusal unless the exact replacement code hash is admitted. Commit each owning package separately with `fix: bind native approval decisions before retention`; P0 compatibility must be refreshed before desktop activation. This plan does not authorize registry publication.

### Task 2: Render native proposals with exact review bindings

- [ ] Define `contracts/review.rs` as a projection containing task/native-operation/proposal references, expected task revision, exact native argument/source/test/recipe/destination/policy/limits digests, native validity interval, safe text and `truncated`. Native canonical proposal bytes remain with the owner; this projection cannot be signed into authority by the controller.
- [ ] Write tests using synthetic malicious review text containing `<script>`, ANSI escape, bidi controls, a long diff and hidden-secret placeholder. Assert plain escaped rendering, exact untouched binding digests, visible truncation and refusal to produce a consequential decision handle until the full authoritative proposal is available. Run `cargo test -p chio-desktop --test approval review_projection_is_not_authority`; expected red before the bounded projector, green after it.
- [ ] Implement `controller/review.rs` so `review.open` resolves the retained native original and returns only a trusted review locator. A stale task revision requires refresh. A model-provided URL/path/proposal body cannot select review authority. Missing native verification yields explicit unavailable or invalid evidence, not a preapproved view.
- [ ] Test `approval.submit` requests against the existing operator schemas: boolean `approved:true`, arbitrary decision body, foreign opaque handle, changed original operation and changed expected revision must all refuse. Only the qualified reviewer/native operator can produce a handle with exact retained decision binding. Run the focused Rust suite and raw protocol fixture tests for green.
- [ ] Commit with `feat: present exact native approval reviews`. Coordinate the separate QML reviewer changes with the UI owner; lock-screen notifications never carry approval actions or private task text.

### Task 3: Consume one original and publish only the fixed review artifact

- [ ] Add a table-driven test over mutations to `proposal_id`, original native ID, canonical arguments digest, source generation, retained test operation/result, recipe digest, destination, authority, policy version and expiry. Each mutation must refuse before native consume/resource publication. Expected test shape:

```python
for changed_field in MUTATED_BINDINGS:
    case = run_native_case("changed-binding", changed_field=changed_field)
    assert case["new_resource_effects"] == 0
    assert case["native_original_ids_after"] == case["native_original_ids_before"]
    assert case["approval_consumed"] is False
```

Define `MUTATED_BINDINGS` to the eleven named fields and `run_native_case` in `approvals.py` as the real-case runner using P0's installed artifact/fixture descriptors. It must obtain original IDs from native admission and independently read effect/consume observations; it cannot supply a fake signing implementation.
- [ ] Run `python3 -m unittest discover -s integrations/omarchy/tests -p test_approvals.py -v` red before the case runner/validation, then implement closed observation validation and rerun green. Run `cargo test -p chio-desktop --test approval` while the native integration cases remain explicitly gated by prerequisite availability.
- [ ] Wire `adapter/approval.rs` to the qualified native decision/consume path using literal argv or its delivered typed API. Retain original IDs before submission and query that original after response loss. The adapter must not accept an approval precheck then call `publish_artifact` locally; native admission owns effect authorization.
- [ ] Run actual concurrent consume, replay, expiry/revocation/cancel after review-open, stale source/test and destination-conflict cases. The valid approved operation produces exactly its retained local review artifact; denied/expired/invalidated cases produce no new publication. Existing P2 review artifacts remain immutable. Unknown post-effect outcomes retain the original fence.
- [ ] Commit with `feat: consume exact native publication decisions`. No change adds shell, raw Git, remote destination or a broad remembered approval.

### Task 4: Qualify interruption, evidence and P3 availability

- [ ] Add deterministic cutpoints before native decision retention, after retention before controller reply, before consumption, after resource artifact commit before response, after history delivery and before/after ACK. `approvals.py` must retain original proposal/operation/receipt IDs, private credential inventory digests, publication count and independently read artifact hashes.
- [ ] Run `python3 integrations/omarchy/qualify.py --phase P3 --profile reviewed-publish-v1 --bundle /absolute/private/selected-bundle.json --output /absolute/private/new-p3-evidence`. Expected unavailable until replacement approval artifact and complete P2 tuple are present. No current frozen-utility test can promote P3.
- [ ] After native delivery passes, rerun with a new evidence directory. Expected green: correct deny retains no approved credential; correct approve consumes once; concurrent/replayed submissions reconcile the same original; cancelled/expired/substituted proposals refuse; lost post-effect response yields original recovery with no duplicate artifact; every visible outcome follows native evidence.
- [ ] Independently verify AT-AUT-004 through AT-AUT-009, AT-HST-011/015 and publication-related AT-RES-010/011/013/015. Include safe rendered review captures and signature/result/delivery verification; raw model text and unsigned review bundle alone cannot pass.
- [ ] Commit harness and redacted evidence references with `test: qualify native reviewed publication`. Activate only `reviewed-publish-v1` in its exact bundle. Hand P4/P5/P6 the qualified decision owner artifact and original-operation contract, not a general-purpose desktop approve API.

## Exit criteria

The exact requested decision is verified before native retention; exact original consumption survives races and interruption; local review publication has current test/source/destination lineage and independent effect evidence. Every unsupported decision path remains unavailable. No public/external publication or registry release follows from this phase without its separately authorized workflow.

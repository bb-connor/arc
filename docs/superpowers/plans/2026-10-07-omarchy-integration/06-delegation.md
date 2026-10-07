# Native Delegated Workers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a small confined worker tree under one Chio authority, with durable child admission, aggregate limits and original-operation recovery.

**Architecture:** The existing native process registry/host owns attenuation, child signing custody, admission and recovery. The desktop stores only task-to-native references and presents child settlement; optional remote workers or stopped-state relocation require additional qualified native custody contracts.

**Tech Stack:** Native Rust process runtime/host, proposed Rust desktop adapter/controller modules, pinned Pi native child facade, Linux confinement and Python fault-injection qualification harness.

---

Status: Proposed P6 plan. Confidence: high in required authority boundaries, moderate in local integration; remote delivery remains unknown until its native prerequisites exist. Commands are future execution instructions. Current scope is documentation only, not runtime implementation. Execute later in an isolated worktree and preserve all unrelated edits.

Prerequisites: completed P3 exact native approvals; P0 compatible native process/cage/Pi tuple; `native-delegation-profile.json`. Read [delegation](../../specs/2026-10-07-omarchy-integration/13-delegation-multihost.md), [hosts](../../specs/2026-10-07-omarchy-integration/07-host-provider-adapters.md), [state](../../specs/2026-10-07-omarchy-integration/14-state-evidence-data.md) and [readiness](../../specs/2026-10-07-omarchy-integration/research/chio-readiness.md). P4/P5 desktop/config capabilities are not automatically inherited by workers.

## Files and responsibilities

| Proposed file or candidate source map | Responsibility |
| --- | --- |
| `crates/products/chio-desktop/src/adapter/delegation.rs` | Bind selected native child facade and retain original child references |
| `crates/products/chio-desktop/src/controller/children.rs` | Bounded child views, wait/settle projection and explicit cancel/resume controls |
| `crates/products/chio-desktop/src/contracts/children.rs` | Closed safe child status and exact native binding references |
| `crates/products/chio-desktop/tests/delegation.rs` | Unavailable facade, attenuation, duplicate and settlement regressions |
| `integrations/omarchy/fixtures/delegation/templates.json` | Operator-selected immutable reader/checker template inventory |
| `integrations/omarchy/qualification/delegation.py` | Actual local/remote/relocation cases and outside observers |
| `integrations/omarchy/tests/test_delegation.py` | Harness identity/evidence/limit validation tests |
| `integrations/omarchy/qualification/custody.py` | Observe native owner/lease/handoff contracts; no desktop lease authority |
| NQ-01 through NQ-03 | Native process runtime, registry and lifecycle source locations in the readiness crosswalk |
| Public Pi `src/delegation.ts`, `src/governance.ts`, `test/delegation.test.mjs` | Owning package's installed native child composition and stock-host tests |

If candidate-only native files are absent from the selected source, stop dependent native implementation and hand off the missing artifact. A new desktop registry, signing key or SQLite effect ledger is not a replacement. Shared task/store/supervision files already delivered by P1/P2 must be extended without changing settled semantics.

### Task 1: Keep the child surface unavailable until native delivery

- [ ] Add the first Rust regression `callback_shape_cannot_enable_children` in `tests/delegation.rs`. Supply a descriptor claiming complete callbacks but no exact native child evidence; assert no capability issue, child launch or model request occurs. Run `cargo test -p chio-desktop --test delegation callback_shape_cannot_enable_children`; expected red until the P0 gate is applied, green after it.
- [ ] Define the installed facade observation consumed by `adapter/delegation.rs`: exact native ABI/store/runtime identity, `submit/reconcile/cancel/wait` availability, selected template digests, qualified signer-custody reference and profile evidence. A successful callback return or process-local set does not establish durable admission.
- [ ] Verify delivered source symbols from NQ-01/02/03: `ProcessRuntime::open/create_root/spawn/invoke/cancel`, `ProcessRegistry::submit_child/provision_signers`, active-run `spawn_<template>/wait_children/settle_children`. Retain actual artifact hashes and native tests for one signed hop, narrowed scope/expiry, same issuer/budget family, durable admission `all` and serving-only refusal. Do not invent a new HTTP child endpoint.
- [ ] In the separate Pi checkout run the existing `npm run build` then `node --test test/delegation.test.mjs test/governance.test.mjs`; these are stock-host/component checks only. If a real native facade is missing, retain `native_prerequisite_unavailable` and its handoff record while independent UI/negative tests proceed.
- [ ] Commit desktop gating with `feat: gate delegated workers on native child authority`. Do not enable delegated-v1 yet.

### Task 2: Admit fixed children with atomic identity and constrained budgets

- [ ] Create a two-template fixture: `project-reader` may call status/read/context tools; `project-checker` may call the pinned fixed test recipe. The catalog binds template/runtime/registry/confinement/provider digests and permits no executable, argv, env, package, path or socket fields in model input. Set the proposed limits to eight total processes, depth two, two active children, 64 tree calls and TTL at most 15 minutes/parent expiry.
- [ ] Add `tests/delegation.rs` cases for widened scope, changed issuer/parent/account, extended expiry, unsupported template, injected launch selectors and sibling share overflow. Add a duplicate-admission assertion:

```python
assert first["native_child_id"] == replay["native_child_id"]
assert first["native_submission_id"] == replay["native_submission_id"]
assert observations["issued_child_capabilities"] == 1
assert observations["launched_child_instances"] <= 1
assert changed_input["code"] == "binding_conflict"
```

The first/replay records come from the native fixture; `observations` comes from independent registry/launch inspection. Define these case outputs in `qualification/delegation.py` and test the validator with synthetic data before real execution.
- [ ] Run `cargo test -p chio-desktop --test delegation` and `python3 -m unittest discover -s integrations/omarchy/tests -p test_delegation.py -v`; expected red before binding/observation implementation. Implement the adapter forwarding and desktop mapping only after native transactional child admission is available. Persist its original submission ID before the owner call and reconcile equal duplicates; changed data conflicts.
- [ ] Add concurrent sibling/grandchild budget tests, cancellation-without-share-refund, tree logical-call replay and per-child model-reservation persistence. Require either qualified native tree reservations or conservative non-overlapping preallocation; never give each child a fresh full Pi run budget. Parent requirements for hard tokens/spend refuse providers whose bound is unavailable. Run the suites for green and separately inspect actual native budget tables.
- [ ] Commit with `feat: retain bounded native child admission`. Map to AT-DLG-002 through AT-DLG-005; counterfeit callback evidence cannot close native acceptance.

### Task 3: Preserve original operations through child/parent interruption

- [ ] Add deterministic cuts: child admitted before launch; launch before owner reply; worker killed before dispatch; effect before retained outcome; completion before native history; ACK observer paused during close; parent killed before checkpoint. Define report assertions:

```python
assert case["native_original_ids_before"] == case["native_original_ids_after"]
assert case["completed_receipt_hash_before"] == case["completed_receipt_hash_after"]
assert case["unexpected_redispatches"] == 0
assert case["root_succeeded_with_unknown_child"] is False
assert case["new_budget_allowance_after_restart"] == 0
```

For a deliberately unknown original, completion hashes may both be null; require `blocked_unknown` and an unchanged independent effect count.
- [ ] Run the Rust and Python delegation tests red, implement `controller/children.rs` projection from native child/process originals and the native host observer, then rerun green. Do not create a replayable desktop effect request from a child message. Only native verifier/results may permit parent ingestion and delivery ACK.
- [ ] Add dependency-cycle and unauthorized sibling-wait cases, hung/failed required child and optional child with unknown effect. Use the native active-run graph and bounded wait/settle contracts. A known optional failure can be visible under explicit policy; an unknown effect cannot be hidden as an optional skip.
- [ ] Add expiry/revocation/cancel races and qualified cgroup teardown. Assert native admissions stop at their transaction boundary, previous effects remain recorded, actual guest absence is observed and unresolved effects keep `blocked_unknown`. A process signal alone cannot declare native revocation or rollback. Verify no custody release while callbacks/private writes/ACK observers remain active.
- [ ] Commit with `feat: reconcile original delegated work through interruption`. Map evidence to AT-DLG-006/007/012/013 and relevant host/state cases.

### Task 4: Gate and specify optional remote custody without emulation

- [ ] Add `test_delegation.py` mutations for missing remote lease evidence, wrong authority/host/worker, reused generation, expired lease, clock uncertainty and incomplete relocation inventory. Expected case result is unavailable/refused, zero new native effects and preserved original identity. Run the unittest command red, then implement only evidence validation/closed projections in `custody.py` for green.
- [ ] Hand off the native remote profile to the process/authority owner: one selected authority, authenticated host/worker routes, native-issued fenced lease/generation, exact original request custody and current revocation/expiry. Proposed timings are 30-second lease, renewal no more often than 10 seconds and no more than 2 seconds accepted clock uncertainty. No available native contract means remote execution remains disabled; controller heartbeats cannot implement it.
- [ ] For a delivered remote-worker profile, add actual two-host cases: partition renewals while effect is in flight, keep old worker alive while requesting takeover, wrong host credentials, delayed old-generation message, namespace/PID reuse and replayed child result. New admission must refuse for stale/unknown ownership; retained unknown effects must not be given fresh identities.
- [ ] For a delivered stopped-relocation profile, use the native host's actual export/import commands from its pinned CLI help. Retain those literal commands in the evidence manifest. Require stopped services/guests, source retirement, complete native state plus Pi mappings/model reservations/history and resource generations, content/ABI validation and interrupted-import reconciliation. Missing custody or a receipt-only copy refuses. Never promote this to live migration.
- [ ] Commit harness/projection changes with `test: gate remote workers on native custody and fencing`. Keep local, remote-worker and stopped-relocation capability cells separate within the exact delegated-v1 bundle; unsupported cells are disabled, not skipped required tests.

### Task 5: Qualify the exact delegated profile

- [ ] Extend the shared harness with P6 cases `local-tree`, `attenuation`, `duplicate-admission`, `aggregate-budget`, `cancel-expiry`, `child-crash`, `parent-crash`, `child-delivery`, `settlement`, and optional selected cells `remote-partition`/`stopped-relocation`. Every enabled cell maps to its complete AT-DLG set and actual native evidence.
- [ ] Run `python3 integrations/omarchy/qualify.py --phase P6 --profile delegated-v1 --bundle /absolute/private/selected-bundle.json --output /absolute/private/new-p6-evidence`. Expected unavailable until P3, the native child facade, tree model limits and exact child confinement are qualified. A source-only or callback-only bundle must exit nonzero.
- [ ] Once delivered, rerun with fresh output. Expected green for the selected local cell: valid attenuated reader/checker children complete, independent recipe/result verification succeeds, all widening/limit/expired/cancelled requests refuse, concurrent original admission retains one identity, and child/parent crash tests preserve receipts/unknown fences without duplicate effects.
- [ ] If remote/relocation is advertised, require two real independently observed hosts and the additional AT-DLG-008 through AT-DLG-011 cases. A remote HTTP timeout cannot prove no effect. Record the selected provider's actual idempotency/lookup guarantee rather than a general exactly-once claim. An incomplete remote cell cannot block local qualification only when remote capability is absent from the release/runtime selection.
- [ ] Independently review all fourteen delegation acceptance cases and their applicability, exact public deliverables, skipped/open records and clean installation prerequisites. Commit harness and safe evidence references with `test: qualify bounded native delegated workers`. Hand P7 the exact enabled capability cells; P6 completion does not publish a release.

## Exit criteria

The selected delegated-v1 installation uses one native authority, attenuated child grants, durable original admission, aggregate budgets, qualified confinement and truthful parent settlement. Optional cross-host behavior remains unavailable unless its own custody/lease/transfer tests pass. No native authority, signer, recovery coordinator, remote scheduler or general-purpose shell runner is implemented inside the desktop controller.

# Confined Project Task Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete one Pi task over an immutable imported project, run a fixed independent recipe and deliver a verifiable private review artifact without modifying the original checkout.

**Architecture:** The controller retains preparation intent and native references, while the existing coding resource owns project effects and the existing authority owns dispatch/recovery. A qualified Pi SDK/print adapter receives private task input and operates only through the exact declared native registry.

**Tech Stack:** Proposed Rust `chio-desktop` modules, pinned Pi 1.0.2/coding resource, native Chio authority, Linux x86_64 confinement, Python qualification harness.

---

Status: Proposed. Confidence: moderate until P0's exact native/kernel/Pi/x64 prerequisites pass. Implementation commands are future commands and must run in an isolated execution worktree. This planning work does not implement or qualify them. Preserve other agents' changes and original user repositories.

Required inputs: completed P0 compatibility for `project-v1`, P1 controller/client scaffolding, enrolled project/profile, qualified private-input transport and a current actual-native coding fixture. Read [project resource](../../specs/2026-10-07-omarchy-integration/09-project-resource.md), [hosts](../../specs/2026-10-07-omarchy-integration/07-host-provider-adapters.md), [controller](../../specs/2026-10-07-omarchy-integration/04-controller-architecture.md), [state](../../specs/2026-10-07-omarchy-integration/14-state-evidence-data.md) and [Linux](../../specs/2026-10-07-omarchy-integration/08-linux-confinement.md).

## Files and boundaries

| Proposed file | Responsibility |
| --- | --- |
| `crates/products/chio-desktop/src/adapter/project_import.rs` | Descriptor-relative selected-input import and provenance |
| `crates/products/chio-desktop/src/adapter/pi.rs` | Pinned host descriptor, private input, explicit registry and native references |
| `crates/products/chio-desktop/src/controller/task.rs` | Four preparation stages and completion predicate |
| `crates/products/chio-desktop/src/store/task_intents.rs` | Idempotent desktop intent/outbox mapping, not native effects |
| `crates/products/chio-desktop/src/supervision/guest.rs` | Qualified launch/process/cgroup lifecycle observations |
| `crates/products/chio-desktop/tests/{project_import,pi_host,task_recovery}.rs` | Focused component regressions |
| `integrations/omarchy/fixtures/project-v1/{source/add.js,acceptance/check.mjs,selection.json}` | Small task plus immutable independent acceptance program |
| `integrations/omarchy/qualification/project_task.py` | Real workflow and deterministic interruption cases |
| `integrations/omarchy/tests/test_project_task.py` | Qualification harness self-tests and false-success rejection |

Reuse the shared `qualify.py` and bundle evaluator from P0. The public Pi coding-resource implementation remains its owning package; do not copy its ledger into the controller. Any required package repair belongs in that package with a new pinned artifact and renewed P0 evidence.

### Task 1: Define the task and independent acceptance fixture

- [ ] Create the source fixture and independent test program, with the latter outside the model-editable resource:

```javascript
// fixtures/project-v1/source/add.js
export function add(a, b) { return a - b; }
```

```javascript
// fixtures/project-v1/acceptance/check.mjs
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";
const { add } = await import(pathToFileURL(process.argv[2]).href);
assert.equal(add(2, 3), 5);
assert.equal(add(-2, 3), 1);
assert.equal(add(0, 0), 0);
```

The test argv is operator-pinned to the admitted immutable generation; the model cannot choose `process.argv[2]`. Its source and executable hash are part of the recipe.
- [ ] Run the fixture with a qualified pinned Node: `node integrations/omarchy/fixtures/project-v1/acceptance/check.mjs integrations/omarchy/fixtures/project-v1/source/add.js`. Expected red: `-1 !== 5`. Retain this failing baseline as the useful-work oracle, not as an implementation failure.
- [ ] Add a separate harness-only expected output with `return a + b;` and run the same test over it. Expected green. Keep original broken input unchanged; the actual P2 model task must produce its own admitted patch.
- [ ] Write `test_project_task.py` to reject a task report when independent recipe digest, source digest, native test operation, result digest or immutable artifact digest is absent/mismatched, even if host exit is zero. Implement the report validator in `project_task.py`; run `python3 -m unittest discover -s integrations/omarchy/tests -p test_project_task.py -v` red then green.
- [ ] Commit fixture/validator changes with `test: define independently checked project task`.

### Task 2: Import selected dirty input without touching originals

- [ ] Add `tests/project_import.rs` fixtures for differing HEAD/index/worktree content, selected untracked input, ignored credential canary, symlink/hardlink/FIFO, submodule gitlink, source/index changes during intake and one-byte-over-limit selection. Define `ImportObservation` in `project_import.rs` with `source_digest`, `manifest_digest`, `selected_paths`, `excluded_paths` and retained original provenance; actual bytes remain in the private resource staging root.
- [ ] The component test must assert the independent pre/post original inventory, not just the importer's return value:

```rust
assert_eq!(before.original_bytes, after.original_bytes);
assert_eq!(before.index_digest, after.index_digest);
assert_eq!(before.modes_and_links, after.modes_and_links);
assert_eq!(imported.selected_worktree_digest, expected_dirty_digest);
assert!(!imported.selected_paths.iter().any(|p| p == ".env"));
```

Define the fixture observer in this test file to independently hash regular files, index and link metadata before and after intake. Do not use the production import helper as the test oracle.
- [ ] Run `cargo test -p chio-desktop --test project_import`. Expected red while importer is absent/unsafe. Implement registered-root lookup, explicit selection, no-follow descriptor traversal, qualified nonexecuting Git metadata access, bounded copy to newly created private inodes and pre/post validation inside a P0-qualified immutable snapshot or enforceable writer-exclusion interval. Without that mechanism, refuse project admission; endpoint hash equality alone is not coherent capture. Add ABA edits restoring endpoint hashes and a missing-mechanism negative. Publish only one immutable manifest after all checks succeed; return `source_changed` on mutation and never chmod/reset originals.
- [ ] Repeat the command for green, then run adversarial rename/symlink/index races under the external qualification driver. Require zero credential-canary reads and no admitted mixed generation. The metadata reader must be explicitly selected and verified; a shell `git` fallback is unavailable until its nonexecution contract passes.
- [ ] Commit with `feat: import stable selected project generations` and map evidence to AT-RES-001 through AT-RES-004/012. Do not add checkout export or Git execution tools.

### Task 3: Wire the qualified Pi adapter and private input

- [ ] Add `tests/pi_host.rs` first. For each invalid descriptor (Pi version, registry digest, provider/account, native signer, runtime hash, required governance unavailable), assert `credential_reads == 0`, `provider_requests == 0`, `guest_launches == 0` for preflight-detectable mismatches. Actual credential account mismatches are checked privately after acquisition but before provider egress.
- [ ] Run `cargo test -p chio-desktop --test pi_host`; expected red. Implement `adapter/pi.rs` using the P0 pinned adapter contract, literal executable argv, a bounded private stdin/FD input channel and the installed Pi SDK/print entrypoint. No `--prompt` content, API-key env, normal user profile, shell interpolation or unqualified native facade may be introduced.
- [ ] Add positive fixture checks for exactly the nine project tools, original argument equality and sequential execution. Run tests red when one extra local tool is installed, then preserve/revalidate registry restrictions after reload/resume until green. API-only mock success remains a component result; current native/kernel acceptance is separate.
- [ ] Add provider count/deadline-resume tests and real credential-canary process sampling. Confirm Codex hard-token fields remain null, no model/provider fallback occurs, and storage failure stops provider submission. Run `cargo test -p chio-desktop --test pi_host` for green before native qualification.
- [ ] Commit with `feat: launch pinned protected Pi tasks with private input`. If the installed package lacks private input or exact native compatibility, retain the explicit refusal and hand the package fix to its owner; do not bypass confinement with ordinary SDK execution.

### Task 4: Persist preparation and reconcile original operations

- [ ] Add reviewed-scope race tests before task admission: fetch scope.get, mutate project selection/provider/recipe/limits, then submit the old scope_revision/reviewed_scope_digest. Require revision_conflict and zero guest/provider effects. Compare and bind the exact commitment atomically with reservation and revalidate before provisioning.
- [ ] Add enrollment-epoch replay tests: require the hello epoch on each mutation, retire only settled enrollment, close old connections, then replay the old request after a new handshake. It must remain refused. Preserve native IDs through owner-bound operation_ref, including resource SHA-256 and native approval UUIDv7/string identities.

- [ ] Implement tests around the stages `reserved`, `resource_ready`, `authority_ready`, `guest_started`. For each stage, terminate after the external owner action and before local acknowledgement, then restart. The test report must expose these independently observed fields:

```python
assert report["resource_import_count"] == 1
assert report["native_grant_count"] == 1
assert report["guest_launch_count"] <= 1
assert report["native_original_ids_before"] == report["native_original_ids_after"]
assert report["original_checkout_before"] == report["original_checkout_after"]
```

`project_task.py` collects counts from resource/native/OS observers outside the controller. The reports do not create native IDs.
- [ ] Run `cargo test -p chio-desktop --test task_recovery`. Expected red before durable mappings. Extend `store/task_intents.rs` and `controller/task.rs` with one transaction per local intent/revision/event transition, persisted native request IDs before submission and idempotent owner reconciliation. New controller mutation keys cannot replace unknown native originals.
- [ ] Add post-effect response loss, history substitution, lost ACK response, cancelled guest, failed recipe, model success prose and exit-zero cases. Require native completion/result verification and host-history delivery before ACK. After lost cancellation, assert independent stop_status fields survive reconnect: confirmed guest exit cannot turn unknown admission stop into confirmed stop. Unknown originals map to `blocked_unknown`; failed checks with accounted effects map to `failed`; success requires sealed review artifact and unchanged original checkout.
- [ ] Add capacity/full-disk tests: no new admission, retained inspection/cancel/recovery remains reachable when reserved control capacity exists, unresolved records never deleted. Re-run the Rust test command and Python report tests for green. Confirm no controller code signs receipts or directly edits the resource ledger.
- [ ] Commit with `feat: retain project task originals through interruption`.

### Task 5: Real confined workflow and P2 handoff

- [ ] Extend `project_task.py` with named cases `useful-task`, `inventory-reload`, `private-input`, `import-race`, `after-resource-effect`, `before-native-ack`, `after-native-ack`, `cancel-before-dispatch`, `cancel-after-effect`, `storage-failure`, `provider-failure` and `deadline-resume`. Each case writes native IDs, outside effect counts, protected filesystem digests, process/cgroup census and evidence classifications.
- [ ] Run `python3 integrations/omarchy/qualify.py --phase P2 --profile project-v1 --bundle /absolute/private/selected-bundle.json --output /absolute/private/new-p2-evidence`. Expected red/refusal until actual x64 confinement and all native prerequisite artifacts exist. The driver must not turn an unavailable case into a skip/pass.
- [ ] After the exact prerequisites pass, run the same command with a fresh output directory. Expected green: native admitted edit repairs `add`, independently pinned recipe passes, exact review bundle is retained and delivered, source checkout is byte/mode/index unchanged, forbidden guest paths fail with positive controls, every required interruption reconciles its original or remains explicitly unresolved as prescribed by the case.
- [ ] Independently inspect the evidence index and every AT-HST/AT-RES/AT-LNX case applicable to project-v1. A deliberate unknown fixture passes only when it remains correctly fenced; it does not make that fixture task successful. Record actual provider, architecture and observed confinement rather than copying prior arm64/component evidence.
- [ ] Commit harness/source and approved synthetic or redacted evidence references with `test: qualify recoverable confined project tasks`. Hand P3 the immutable source/test/artifact/native-operation bindings. No checkout writeback, push, pull request, deployment or external publication is part of P2.

## Exit criteria

P2 delivers one qualified `project-v1` profile with exact P0 tuple, fixed provider/disclosure scope, independent passing recipe, original-operation recovery and private local review artifact. Qualification covers host inventory/delivery/errors/lifecycle, selected resource import/CAS/recipe/artifact cases and all applicable Linux boundaries. Native approvals remain unavailable until P3. The existing package's historical Pi 0.85.1 qualification cannot satisfy this plan's Pi 1.0.2 runtime gates.

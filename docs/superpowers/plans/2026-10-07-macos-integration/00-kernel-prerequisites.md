# Mac Kernel Prerequisites Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a reproducible current-source inventory and closed native prerequisite gate, then obtain native-owner acceptance evidence before enabling Mac mutations.

**Architecture:** Existing native admission and SQLite authority owners retain all authority. The new Mac qualification code inventories, checks applicability and explains unavailable gates; it cannot sign approvals, issue capabilities, implement crossing semantics or turn a schema-valid report into authorization. Missing north-star contracts are delivered by their native owners and accepted through this program before the shared controller binds them.

**Tech Stack:** Existing Rust workspace, Python 3 standard-library qualification tests, immutable source/blob identities, native kernel/store test harnesses, profile-specific installed evidence.

---

Status: proposed plan. Commands and proposed files below are for future execution; no product implementation or runtime qualification is performed by this document. Confidence: high in the baseline/source gaps, moderate in integration until native owners deliver the required contracts. Execute in a fresh isolated worktree, preserve other workers' edits and commit only task-owned files. M1 read-only UX can proceed; M2 mutation wiring waits for M0. M6 closure precedes execution profiles.

Read [kernel contracts](../../specs/2026-10-07-macos-integration/03-kernel-contracts.md), [authority/integrity](../../specs/2026-10-07-macos-integration/04-authority-integrity.md), [recovery](../../specs/2026-10-07-macos-integration/11-state-recovery.md), [readiness](../../specs/2026-10-07-macos-integration/research/chio-readiness.md) and [qualification](../../specs/2026-10-07-macos-integration/17-qualification.md).

## File and owner map

| Path | Status / responsibility |
| --- | --- |
| `integrations/macos/qualification/source_probe.py` | New, source-only symbol/blob inventory |
| `integrations/macos/qualification/prerequisites.py` | New, closed gate dependency and evidence applicability checks; never cryptographic authority |
| `integrations/macos/qualification/native-handoffs.json` | New, native gate owner, delivered artifact, required case and actual status |
| `integrations/macos/tests/test_source_probe.py` | New, source absence and blob identity tests |
| `integrations/macos/tests/test_prerequisites.py` | New, evidence-class, mismatch and missing-gate tests |
| `integrations/macos/qualification/fixtures/native-cut-cases.json` | New synthetic fault-schedule input, never a passing runtime record |
| `crates/kernel/chio-kernel/src/admission_operation/{identity,state,store,sequencer}.rs` | Existing native operation identity, legality, claims and sequencing; native owner preserves contracts |
| `crates/kernel/chio-kernel/src/kernel/{admission_coordinator.rs,dispatch.rs,construction.rs}` | Existing native drivers and current in-memory stop; native owner migration sites |
| `crates/platform/chio-store-sqlite/src/serving_owner.rs`, `serving_owner/{global_commit_chain,rollback_anchor,lease_history}.rs` | Existing serving owner, chain, anchor and lease integration |
| `crates/platform/chio-store-sqlite/src/admission_operation_store/{store,schema}.rs` | Existing operation transactions and schema gates |
| `crates/kernel/chio-kernel-core/src/admission_machine.rs`, `abi.rs` | New native-owner modules proposed by NK-01/NK-03, not desktop facades |
| `crates/kernel/chio-kernel/src/crossing.rs`, `stop_epoch.rs` | New native-owner contract modules, coordinated with north-star implementation |
| `crates/platform/chio-store-sqlite/src/admission_operation_store/crossing.rs`, `stop_epoch.rs` | New native-owner writer implementations; no second SQLite connection owning approval/stop |

The native program may split its proposed modules while implementing the pinned design. If it does, update the inventory and handoff with actual delivered paths before acceptance; do not pretend a planned path already exists. The controller scaffold and shared wire types belong to M2. The Mac qualification directory must extend that shared harness when another plan has created it.

### Task 1: Freeze source evidence without inferring availability

- [ ] Record the selected commit and present tracked paths using these actual commands:

```bash
git rev-parse HEAD
git ls-files crates/kernel/chio-kernel/src/admission_operation crates/platform/chio-store-sqlite/src/serving_owner.rs
rg -n 'struct AdmissionState|enum KernelOp|enum CrossingKind|struct StopEpochV1|RequiredIntegrity|struct InfluenceStateV1|struct ProcessRuntime|trait CausalLineageStore' crates
```

Expected at the inspected baseline: SHA `6573b8980a1e5331028b7e688169f033a39d0384`, existing operation/owner files, and no matches for the proposed contracts. A later execution records the actual SHA and reviews every changed disposition rather than forcing these historical expectations.

- [ ] Create `test_source_probe.py` with a complete source-only regression:

```python
import importlib.util
from pathlib import Path
import tempfile
import unittest

MODULE = Path(__file__).parents[1] / "qualification/source_probe.py"

class SourceProbeTests(unittest.TestCase):
    def test_absence_and_content_are_not_runtime_evidence(self):
        spec = importlib.util.spec_from_file_location("source_probe", MODULE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "owner.rs"
            target.write_text("pub struct Owner;\n")
            first = module.observe(root, "owner.rs", "pub struct Owner")
            self.assertEqual(first["classification"], "source")
            self.assertTrue(first["symbol_present"])
            self.assertEqual(len(first["sha256"]), 64)
            target.write_text("pub struct Different;\n")
            second = module.observe(root, "owner.rs", "pub struct Owner")
            self.assertNotEqual(first["sha256"], second["sha256"])
            self.assertFalse(second["symbol_present"])
            self.assertFalse(module.observe(root, "absent.rs", "Owner")["present"])

if __name__ == "__main__":
    unittest.main()
```

- [ ] Run `python3 -m unittest discover -s integrations/macos/tests -p test_source_probe.py -v`. Expected red: module file absent.
- [ ] Create `source_probe.py` with this complete bounded observer:

```python
import hashlib
from pathlib import Path

def observe(root, relative, symbol):
    root = Path(root).resolve(strict=True)
    candidate = root / relative
    if not candidate.exists():
        return {"path": relative, "classification": "source", "present": False,
                "symbol_present": False, "sha256": None}
    path = candidate.resolve(strict=True)
    path.relative_to(root)
    content = path.read_bytes()
    return {"path": relative, "classification": "source", "present": True,
            "symbol_present": symbol.encode("utf-8") in content,
            "sha256": hashlib.sha256(content).hexdigest()}
```

- [ ] Rerun the same test. Expected green, with no launch/key/capability operations. Record the CK/NK path table from readiness in the source artifact. Commit only the two new files with `git add integrations/macos/qualification/source_probe.py integrations/macos/tests/test_source_probe.py` and `git commit -m "test: inventory Mac native prerequisites as source evidence"`.

### Task 2: Add a closed prerequisite dependency graph

- [ ] Create `test_prerequisites.py` using this complete diagnostic-gate test. It intentionally never asserts runtime qualification:

```python
import importlib.util
from pathlib import Path
import unittest

MODULE = Path(__file__).parents[1] / "qualification/prerequisites.py"
spec = importlib.util.spec_from_file_location("prerequisites", MODULE)
gates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gates)

class PrerequisiteTests(unittest.TestCase):
    def test_no_source_report_opens_execution(self):
        expected = {"kernel": "a" * 64, "platform": "macos-arm64"}
        result = gates.evaluate("vm-project-v1", expected, [])
        self.assertFalse(result["complete_for_native_verification"])
        reports = [{"gate": gate, "classification": "source",
                    "tuple": expected, "result": "pass", "synthetic": False}
                   for gate in gates.required("vm-project-v1")]
        self.assertFalse(gates.evaluate("vm-project-v1", expected, reports)
                         ["complete_for_native_verification"])

    def test_exact_tuple_and_no_synthetic_reports(self):
        expected = {"kernel": "a" * 64, "platform": "macos-arm64"}
        reports = [{"gate": gate, "classification": "installed-runtime",
                    "tuple": expected, "result": "pass", "synthetic": False}
                   for gate in gates.required("brokered-v1")]
        self.assertTrue(gates.evaluate("brokered-v1", expected, reports)
                        ["complete_for_native_verification"])
        for field, value in (("synthetic", True), ("result", "skipped"),
                             ("tuple", {"kernel": "b" * 64})):
            changed = [dict(row) for row in reports]
            changed[0][field] = value
            self.assertFalse(gates.evaluate("brokered-v1", expected, changed)
                             ["complete_for_native_verification"])
        with self.assertRaises(ValueError):
            gates.required("automatic-fallback")

if __name__ == "__main__":
    unittest.main()
```

- [ ] Run `python3 -m unittest discover -s integrations/macos/tests -p test_prerequisites.py -v`. Expected red before module creation.
- [ ] Create `prerequisites.py` with the following complete initial gate logic:

```python
COMMON = frozenset({"compatibility", "closed-abi", "pure-admission", "crossing",
                    "durable-stop", "integrity", "native-custody", "recovery"})
PROFILES = {
    "observe-v1": frozenset({"compatibility", "read-boundary"}),
    "brokered-v1": COMMON | {"typed-broker"},
    "vm-project-v1": COMMON | {"typed-broker", "vm-boundary", "project-resource"},
    "remote-project-v1": COMMON | {"remote-binding", "remote-finality", "project-resource"},
    "native-descendant-v1": COMMON | {"typed-broker", "native-descendant-boundary"},
    "managed-endpoint-v1": COMMON | {"managed-boundary", "multi-user-boundary"},
}

def required(profile, publication=False):
    if profile not in PROFILES:
        raise ValueError("unknown execution profile")
    extra = {"exact-publication", "resource-generation"} if publication else set()
    return PROFILES[profile] | extra

def evaluate(profile, expected_tuple, reports, publication=False):
    required_gates = required(profile, publication)
    valid = set()
    duplicates = set()
    seen = set()
    for row in reports:
        gate = row.get("gate")
        if not isinstance(gate, str):
            continue
        if gate in seen:
            duplicates.add(gate)
        seen.add(gate)
        if (gate in required_gates and row.get("classification") == "installed-runtime"
            and row.get("tuple") == expected_tuple and bool(expected_tuple)
            and row.get("result") == "pass" and row.get("synthetic") is False):
            valid.add(gate)
    valid -= duplicates
    missing = sorted(required_gates - valid)
    return {"complete_for_native_verification": not missing, "missing": missing,
            "duplicates": sorted(duplicates), "authority_granted": False}
```

These strings are proposed qualification gate IDs, not native API names or new execution profiles. The complete expected tuple comes from the shared compatibility contract and includes actual OS/architecture, binaries, ABI/store, policy and adapter identities. A positive diagnostic result means only that all applicability records are present. Before profile activation, M8 verifies their evidence and the installed native owner independently advertises supported authority. A caller can forge this Python input, so the controller must never accept it as authority.

- [ ] Rerun the test green. Add negative rows for a duplicate gate, wrong architecture, empty tuple and publication missing either extra gate. Use `evaluate` directly and assert `authority_granted is False` in every case. Commit only gate/tests with `git commit -m "feat: report closed Mac prerequisite dependencies"` after file-scoped `git add`.

### Task 3: Issue precise native-owner handoffs

- [ ] Create `native-handoffs.json` as an array of records with this concrete initial record and the remaining rows below. `status` begins `unavailable`; no source inspection changes it to qualified.

```json
{
  "gate": "crossing",
  "status": "unavailable",
  "source_id": "CHIO-MAIN",
  "owner": "native admission and SQLite serving-owner maintainer",
  "current_files": [
    "crates/kernel/chio-kernel/src/admission_operation/store.rs",
    "crates/platform/chio-store-sqlite/src/serving_owner.rs",
    "crates/platform/chio-store-sqlite/src/admission_operation_store/store.rs"
  ],
  "design_source": "CHIO-NORTHSTAR:docs/superpowers/specs/2026-10-04-crossing-primitive-design.md",
  "delivered_artifact": "native-crossing-acceptance.json",
  "required_cases": ["join-before-intent", "stop-before-intent", "anchor-outcome-unknown", "participant-refusal", "original-operation-replay"]
}
```

| Gate / owner | Concrete delivery contract and current change sites | Required native acceptance artifact |
| --- | --- | --- |
| `pure-admission` / kernel-core + kernel driver maintainers | New `AdmissionState`, `AdmissionEvent`, `Transition`, `EffectList`; total projection of existing `AdmissionOperationV1` and tool-outcome state; startup/dispatch/recovery drivers consume one transition. Current `admission_operation/state.rs`, `kernel/admission_coordinator.rs`, `tool_outcome/post_return.rs` | `native-admission-machine-acceptance.json`: persisted round-trip, deterministic event trace, old/new predicate differential, named expected disagreements |
| `closed-abi` / kernel API maintainer | New `KernelOp` and version registry in `chio-kernel-core/src/abi.rs`; generated inventory over live kernel methods, core exports, FFI, wire and sidecar routes. Existing `kernel/evaluation/evaluation_entry.rs`, `kernel/session_ops.rs`, `kernel/construction.rs` | `native-abi-census.json`: one classification per entry; layer descent; deny/allow stopped coverage; unmapped addition fails |
| `durable-stop` / native owner maintainer | `StopEpochId` includes chain generation/epoch; native journal, signed records and anchored heads; current `kernel/construction.rs` in-memory stop migrates under shared owner, not alongside it | `native-stop-acceptance.json`: durable/latch/process cuts, restart, stale resume, pending multi-scope intents, anchor failure |
| `integrity` / native knowledge + approval maintainers | Native observation journal and `RequiredIntegrity`; same-writer verified endorsement adapters, selector and current roster; current `authority.rs::ensure_capability_issuance_supported` must reject unsupported enforcement | `native-integrity-acceptance.json`: bootstrap and migration, join race, domain mismatch, stale roster/action, exact single consume |
| `native-custody` / native process + key maintainer | Deliver missing process/child owner with signer custody, conservative influence inheritance, parent cut and ancestor budget; receipt-lineage snapshots and `BudgetTree` alone cannot satisfy | `native-custody-acceptance.json`: key export rejection, child attenuation, orphan admission race, unknown commitment retention |
| `recovery` / native recovery maintainer | Original operation lookup and typed finality; restore generations and external floor for selected restoration feature; current qualified claim/store/tool-outcome owners remain canonical | `native-recovery-acceptance.json`: all M6 cuts, no blind retry, no restored spent authority |
| `typed-broker` under NK-03/NK-05 / native resource intake + knowledge maintainers | Deliver registered authenticated native intake for bounded selected handles and task-input bytes; native capture seals immutable workspace and input resources, retains influence and returns distinct verified references before `task.create`. No current Mac intake API exists; resource implementation belongs to the native owner and M4 Task 1 | `native-resource-intake-acceptance.json`: unauthenticated peer, substituted handle, unsealed input, wrong user/generation and lost reply refuse or reconcile; valid intake yields native `resource_ref` and `input_ref` before any task/model launch |
| `exact-publication` under NK-03/NK-05 / native resource + approval maintainers | Deliver typed preparation accepting sealed artifact reference, enrolled destination identity/generation, exact filename bytes, expected-absent target, current policy/influence and authenticated scope; return the original native operation reference for `review.open`/`approval.submit`, without executing publication. Resource effect adapter remains M4 Task 6 | `native-publication-preparation-acceptance.json`: exact original binding, absence condition, current influence/policy, stable retry, bridge authentication and closed census; preparation has zero filesystem publication effects; missing interface keeps `publication-v1` unavailable |

- [ ] For each record, include exact proposed type signatures from its pinned NK design in the handoff attachment, retaining that design's ownership and domain-separated vocabulary. Do not implement replacements under `integrations/macos/` or `chio-desktop`. The Mac acceptance owner reviews delivered actual symbols and patches the handoff's `current_files` to match before testing.
- [ ] Add the two resource records to the existing `typed-broker` and `exact-publication` gate handoffs, requiring both NK-03 census registration and NK-05 influence/current-review binding. The native resource owner publishes the actual typed interface and bridge authentication/authorization rules; M2 transports its verified references and M4 implements selected-resource preparation/effect adapters. Do not add a public operator method, raw path/bookmark fields to `task.create`, or arbitrary artifact delivery to `evidence.export`. Until the native owner delivers the interface, report the exact unavailable prerequisite and perform zero task/model launch or publication effects.
- [ ] Extend the new native M0 test target with `mac_contract_resource_intake_` and `mac_contract_publication_prepare_` cases driven by these additional concrete fixture rows:

```json
[
  {"case":"resource-intake-before-task","schedule":["authenticate-bridge","verify-selected-handle","seal-workspace-and-input","join-bootstrap-influence","return-native-resource-refs","task-create"],"oracle":{"native_resource_refs_distinct":true,"bootstrap_bound_before_agent_ready":true}},
  {"case":"publication-preparation-original","schedule":["authenticate-bridge","verify-sealed-artifact","verify-enrolled-destination","bind-absent-target-policy-influence","prepare-native-operation","drop-reply","retry-same-intent","review-open-original"],"oracle":{"native_operations":1,"publication_effects":0,"original_ref_replayed":true}},
  {"case":"publication-preparation-substitution","schedule":["prepare-native-operation","change-destination-or-filename-or-artifact-or-policy-or-influence","approval-submit-original"],"oracle":{"publication_effects":0,"stale_binding_refused":true}},
  {"case":"unregistered-resource-bridge","schedule":["unregistered-or-unauthenticated-bridge-call"],"oracle":{"native_operations":0,"native_resource_refs":0,"publication_effects":0}}
]
```

- [ ] Run `cargo test -p chio-kernel --test macos_contract_prerequisites mac_contract_resource_intake_ -- --nocapture` and `cargo test -p chio-kernel --test macos_contract_prerequisites mac_contract_publication_prepare_ -- --nocapture` after the native owner delivers the new cases. Expected initial red/unavailable before delivery; acceptance requires nonzero case counts, real native reference verification, original-operation readback and an independent destination observer proving preparation caused no publication. M4 Task 6 separately proves approved exact no-replace installation and original-effect recovery. Hand its actual native interface/acceptance artifact to [M4](04-resources-publication.md), without implementing a shim in this plan.
- [ ] Validate JSON with `python3 -m json.tool integrations/macos/qualification/native-handoffs.json > /dev/null`; inspect every artifact record against the gate table. Expected: syntactically valid and all undelivered gates still unavailable. Commit only the handoff file with `docs: assign Mac native contract prerequisite owners`.

### Task 4: Establish current native regression controls

- [ ] Run the existing focused source regressions and retain exact command, exit status and source revision in a fresh private execution record:

```bash
cargo test -p chio-store-sqlite --lib recovery_claims_
cargo test -p chio-store-sqlite --lib serving_owner::tests
cargo test -p chio-kernel --lib emergency_
cargo test -p chio-kernel --test durable_admission_sqlite
```

Expected: selected current native tests pass, or an explicit toolchain/test failure is recorded. Zero selected tests is not success; inspect the reported count. These controls establish existing recovery claims, owner fencing and in-memory emergency behavior only. They do not close a proposed native gate.
- [ ] Compare changed native-owner code against `admission_operation_store_tests/recovery.rs`, `serving_owner/tests.rs`, `kernel/tests/emergency.rs` and `tests/durable_admission_sqlite.rs`. Preserve pre-existing coverage for bounded claims, historical lease verification, wrong owner/epoch, atomic ancestor revocation, rollback anchor and canonical terminal replay.
- [ ] Record any failed baseline as a separate prerequisite defect with exact failing command and source file; native owner fixes it before running acceptance of its new contract. Commit source fixes only in that owner's change, with its own regression, never as a Mac bypass.

### Task 5: Drive native race and failure acceptance

- [ ] Create `native-cut-cases.json` with this complete initial fixture array. The native-owner test adapter consumes these schedules; this file is test input, not proof of the expected result.

```json
[
  {"case":"join-before-intent","schedule":["guard-read","join-commit","intent-attempt"],"oracle":{"effects":0,"result":"insufficient-integrity"}},
  {"case":"stop-before-intent","schedule":["stop-anchor","intent-attempt"],"oracle":{"effects":0,"result":"stopped"}},
  {"case":"intent-before-stop","schedule":["intent-anchor","stop-anchor","effect","release-attempt"],"oracle":{"effects":1,"release":"withheld"}},
  {"case":"anchor-outcome-unknown","schedule":["intent-commit","anchor-io-failure","restart","lookup-original"],"oracle":{"new_intents":0,"owner":"poisoned-before-reconcile"}},
  {"case":"participant-refusal","schedule":["reserve","participant-refuse","rollback-savepoint"],"oracle":{"effects":0,"consumption":0}},
  {"case":"original-operation-replay","schedule":["intent-anchor","effect","terminal-commit","drop-reply","retry-same-intent"],"oracle":{"effects":1,"native_operations":1}}
]
```

- [ ] Native owners implement barriers/fault ports in their owning test modules, using injected authority time, commit, anchor, transport and participant results. They expose test cases named `mac_contract_` in new `crates/kernel/chio-kernel/tests/macos_contract_prerequisites.rs` and SQLite unit modules as appropriate. This is a newly introduced test surface; it is not present on CHIO-MAIN. A source-only table or a mock controller cannot close its gate.
- [ ] Run `cargo test -p chio-kernel --test macos_contract_prerequisites mac_contract_ -- --nocapture` after delivery. Expected initial red while the contract is missing; green requires assertions over real native writer state and an independent sink counter. Run native store tests for the same races with a process kill around COMMIT/anchor and an on-disk reopen. Record exact runtime case count and no skipped required cases.
- [ ] Expand native cases to cover ABI variant addition, check-only rejection for tracked read, all crossing sinks, child/parent budget race, cross-store `early_only`, unknown finality, selector input replay and stopped historical export. Each case names its exact requirement oracle from the three owned specs; update fixture/test names together.
- [ ] Commit fixture and native tests under their owners with `test: verify Mac native prerequisite cutpoints`. Do not mark any profile runtime-qualified from unit tests alone.

### Task 6: Accept delivered contracts and hand M2 a truthful boundary

- [ ] Inventory actual delivered artifacts and symbols again with Task 1. Compare expected versus delivered ABI, store schema, signer/authority binding and native operation-reference contract. The native maintainer supplies the adapter implementing those actual interfaces; an absent method remains unavailable.
- [ ] Verify every required native artifact on an installed exact tuple, with independent file/network/resource observers outside the worker/controller. Retain original operation records, resource results, receipt verification and stop history. `observe-v1` needs only its read gate; each execution profile follows its own dependency set; `publication-v1` is an additional gated feature.
- [ ] Run both Python test commands, relevant delivered native tests, `cargo fmt --all -- --check` and `git diff --check`. Expected: all applicable checks pass; native/runtime unavailable statuses remain explicit. Re-run only checks affected by fixes.
- [ ] Hand M2 a source/API crosswalk, installed binding contract, per-profile missing list and verified evidence references. M2 refuses unsupported mutations before touching credentials or launchers. M6 receives exact original-operation and stop-reconciliation contracts. Record M0 complete only for the selected gate scope; missing optional profiles remain unavailable.

## Coverage and exit

Task 1 covers source identity and evidence classes. Task 2 covers profile/feature dependency and refusal. Task 3 assigns all NK-01 through NK-09 consequences, including notification ownership through M2. Tasks 4 and 5 preserve current behavior and test kernel, integrity, budget/custody and stop races. Task 6 establishes exact installed applicability. The acceptance scope is AT-MAC-KER-001 through AT-MAC-KER-016 and native prerequisites for AT-MAC-AUT-001 through AT-MAC-AUT-016 and AT-MAC-REC-002 through AT-MAC-REC-010. M6 and the platform/resource plans supply composed host evidence; M8 separately decides release qualification.

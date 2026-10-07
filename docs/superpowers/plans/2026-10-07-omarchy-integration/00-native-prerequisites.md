# Native Prerequisites Implementation Plan

| Boundary scope | `boundary_class` | `planning_status` | Decision and execution gate |
| --- | --- | --- | --- |
| `capability_admission` | `prevent` | `blocked_by_adr` | Owner decisions F1/F3 on product/profile and native contract selection; then P0-NATIVE-BUNDLE, P0-OPERATOR-FACADE and exact per-profile artifacts. |
| `native_observation` | `detect_only` | `ready_after_adr` | Accepted ADR-0011 permits independent probe/evidence planning; unavailable native contracts remain named blockers, and observations grant no authority. |
| `source_inventory` | `advisory_only` | `ready_after_adr` | Accepted ADR-0011 permits operator-pinned source research; source presence cannot qualify or enable a profile. |

Metadata follows [ADR-0011](../../../adr/ADR-0011-boundary-taxonomy-product-wording.md) and the [plan-set inheritance and owner-decision gate](README.md#boundary-metadata-and-inheritance). Classes describe proposed boundaries, not delivered qualification.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce an independently checked compatibility bundle that can truthfully admit one Omarchy profile or report its exact unavailable prerequisite.

**Architecture:** Reuse Chio's native authority, admission, process and resource owners. Add only compatibility observation and admission gating in the proposed desktop adapter; package a source map and qualification evidence without introducing another issuer or recovery engine.

**Tech Stack:** Rust workspace, proposed `chio-desktop` crate, Python standard-library qualification harness, exact Pi 1.0.2 and selected native Chio artifacts, non-root x86_64 Omarchy.

---

Status: Proposed execution plan. Confidence: high for missing prerequisites, moderate for integration until their delivered artifacts qualify. This document authorizes no runtime implementation now. Commands below are future execution commands; proposed files do not yet exist. Execute in a fresh isolated worktree, preserve concurrent changes and use file-scoped commits. Do not commit machine credentials, private state or raw confidential evidence.

Read [readiness](../../specs/2026-10-07-omarchy-integration/research/chio-readiness.md), [controller](../../specs/2026-10-07-omarchy-integration/04-controller-architecture.md), [hosts](../../specs/2026-10-07-omarchy-integration/07-host-provider-adapters.md), [confinement](../../specs/2026-10-07-omarchy-integration/08-linux-confinement.md) and [verification](../../specs/2026-10-07-omarchy-integration/15-verification-release.md). P0 must finish before P2 native execution. Independent read-only P1 work can continue against explicit unavailable features.

## Files and ownership

| Proposed path | Responsibility |
| --- | --- |
| `integrations/omarchy/contracts/compatibility-bundle.schema.json` | Qualification package wrapper referencing the existing spec `contracts/compatibility.schema.json` and `release-evidence.schema.json`; no competing wire tuple |
| `integrations/omarchy/qualification/bundle.py` | Strict bundle loading and evidence applicability, never receipt signing |
| `integrations/omarchy/qualify.py` | Shared future qualification entrypoint with phase/case selection |
| `integrations/omarchy/tests/test_bundle.py` | Missing/stale/misclassified evidence regression cases |
| `integrations/omarchy/tests/test_native_probe.py`, `test_platform_probe.py` | Native capability refusals and platform eligibility probes |
| `integrations/omarchy/fixtures/compatibility/source-only.json` | Synthetic negative fixture, explicitly unable to qualify runtime |
| `integrations/omarchy/fixtures/compatibility/synthetic-matching-tuple.json` | Synthetic validator control with matching fields, always refused by the synthetic gate |
| `integrations/omarchy/fixtures/compatibility/profile-requirements.json` | Per-profile required native artifacts and applicable acceptance IDs |
| `crates/products/chio-desktop/src/adapter/capabilities.rs` | Translate a verified installation observation into available/refused desktop features |
| `crates/products/chio-desktop/tests/prerequisites.rs` | No-credential/no-launch prerequisite tests |
| `integrations/omarchy/qualification/native_probe.py` | Run installed native diagnostics with literal argv and bounded private output |
| `integrations/omarchy/qualification/platform_probe.py` | Record the real architecture/kernel/runtime/confinement tuple |
| `integrations/omarchy/qualification/observations.py` | Keep component and independent native observations distinct |

The crate scaffold and shared protocol types are coordinated with P1. Extend those files rather than creating a second crate or overwriting another plan's modules. Native process/cage/credential sources absent from main are external prerequisites, not permission to invent similarly named controller APIs.

### Task 1: Freeze the prerequisite inventory and source availability

- [ ] Record the public Chio and Pi refs from the readiness crosswalk and refresh them through `gh api repos/backbay-labs/chio/commits/main` and `gh api repos/backbay-labs/chio-pi-plugin/commits/main`. Retain the returned identities; do not silently switch the selected tuple to a newer main.
- [ ] Create `profile-requirements.json` with these complete proposed gate sets. Each array is already expanded, including inherited artifacts:

```json
{
  "observe-v1": ["native-compatibility-manifest.json"],
  "project-v1": ["native-compatibility-manifest.json", "omarchy-x64-confinement.json", "pi-current-native-workflow.json", "pi-private-input-transport.json", "provider-limits-profile.json"],
  "reviewed-publish-v1": ["native-compatibility-manifest.json", "omarchy-x64-confinement.json", "pi-current-native-workflow.json", "pi-private-input-transport.json", "provider-limits-profile.json", "native-approval-decision-binding.json"],
  "desktop-v1": ["native-compatibility-manifest.json", "omarchy-x64-confinement.json", "pi-current-native-workflow.json", "pi-private-input-transport.json", "provider-limits-profile.json", "native-approval-decision-binding.json", "desktop-compositor-profile.json"],
  "repair-v1": ["native-compatibility-manifest.json", "omarchy-x64-confinement.json", "pi-current-native-workflow.json", "pi-private-input-transport.json", "provider-limits-profile.json", "native-approval-decision-binding.json", "desktop-compositor-profile.json", "native-host-file-replacement-profile.json", "configuration-reload-profile.json"],
  "delegated-v1": ["native-compatibility-manifest.json", "omarchy-x64-confinement.json", "pi-current-native-workflow.json", "pi-private-input-transport.json", "provider-limits-profile.json", "native-approval-decision-binding.json", "native-delegation-profile.json"]
}
```

The dependency graph is `observe-v1 -> project-v1 -> reviewed-publish-v1`, then `reviewed-publish-v1 -> desktop-v1 -> repair-v1` and separately `reviewed-publish-v1 -> delegated-v1`. Delegation inherits no desktop/repair authority. Optional remote cells additionally require `cross-host-custody-profile.json` within the selected delegated-v1 tuple. Required governance adds `native-model-release-profile.json` to every selected profile. These conditional requirements come from the independently selected tuple, never from a mutable bundle field.

The three additional artifact names are proposed prerequisite records owned by the native/resource maintainers, implementing the [prerequisite register](../../specs/2026-10-07-omarchy-integration/16-roadmap-decisions.md#prerequisite-register):

| Artifact | Required prerequisite contents and independent evidence |
| --- | --- |
| `desktop-compositor-profile.json` | P4-COMPOSITOR: exact Omarchy/Hyprland binaries and IPC grammar, enrolled session/peer identity, protected socket custody, bounded resource calls and outside compositor observer. P5 additionally requires the completed P4 acceptance for that exact session/resource tuple. |
| `native-host-file-replacement-profile.json` | P5-WRITER-EXCLUSION: native host-file participant, enforceable writer exclusion/conditional replacement, no-follow identity and metadata checks, durable original-operation stages, verified backup/readback and restore representability under concurrent-writer and crash tests. |
| `configuration-reload-profile.json` | P5-RELOAD-CLOSURE: exact enrolled live dependency graph and confined validator, bounded effects, automatic-reload coordination or a proved equivalent sequence, one normal reload, independent live-value/error observation and restoration evidence. |

Record unavailable native component contracts by name; missing writer exclusion or reload closure keeps repair apply unavailable. Each resource owner produces its record from independently observed native/resource preflight before the composed P4 or P5 acceptance run, without requiring that run's final qualified index. Completed P4 acceptance is an entry gate for P5 only. These records cannot replace complete `AT-DSK`/`AT-FIX` coverage. The reviewed applicability matrix and completed predecessor-phase evidence remain separate necessary conditions for profile qualification, as required by the [shared harness contract](README.md#proposed-qualification-harness-abi). P0 delivers the inventory and records missing later prerequisites without requiring optional P4/P5/P6 closure for an earlier profile.

- [ ] Define `evaluate_bundle` in `qualification/bundle.py` to return `{"qualified": bool, "missing": list[str], "invalid": list[str]}`; it is a diagnostic evaluator of independently verified inputs, not an authority verifier. Reject unknown profile IDs before examining their artifacts with exactly `{"qualified": false, "missing": [], "invalid": ["unknown_profile"]}`. Never default an unknown profile to an empty gate set. At load time, reject an inventory whose keys differ from the six supported profile IDs in `release-evidence.schema.json`, including a missing or extra mapping.
- [ ] Write `test_bundle.py` first using `unittest`. Call the helper below from a test method, loading the proposed inventory and supplying `complete_fixture(profile)`, which constructs an explicitly synthetic, internally matching control for each independently selected profile. Fixture artifacts are keyed by their required filenames; removing one must identify precisely that prerequisite:

```python
import copy

def assert_profile_inventory(test, requirements, evaluate_bundle, complete_fixture):
    observe = {"native-compatibility-manifest.json"}
    project = observe | {
        "omarchy-x64-confinement.json", "pi-current-native-workflow.json",
        "pi-private-input-transport.json", "provider-limits-profile.json",
    }
    publication = project | {"native-approval-decision-binding.json"}
    desktop = publication | {"desktop-compositor-profile.json"}
    expected = {
        "observe-v1": observe,
        "project-v1": project,
        "reviewed-publish-v1": publication,
        "desktop-v1": desktop,
        "repair-v1": desktop | {
            "native-host-file-replacement-profile.json",
            "configuration-reload-profile.json",
        },
        "delegated-v1": publication | {"native-delegation-profile.json"},
    }
    test.assertEqual(set(requirements), set(expected))
    for profile, artifacts in expected.items():
        with test.subTest(profile=profile):
            test.assertCountEqual(requirements[profile], artifacts)
            control = complete_fixture(profile)
            test.assertIs(control["synthetic"], True)
            test.assertEqual(evaluate_bundle(profile, control), {
                "qualified": False, "missing": [], "invalid": ["synthetic_bundle"],
            })
            for artifact in sorted(artifacts):
                with test.subTest(artifact=artifact):
                    mutant = copy.deepcopy(control)
                    del mutant["artifacts"][artifact]
                    result = evaluate_bundle(profile, mutant)
                    test.assertFalse(result["qualified"])
                    test.assertEqual(result["missing"], [artifact])
                    test.assertEqual(result["invalid"], ["synthetic_bundle"])
    for unknown in ("", "unknown-v1", "desktop-v2", "Project-v1"):
        with test.subTest(profile=unknown):
            test.assertEqual(evaluate_bundle(unknown, complete_fixture("project-v1")), {
                "qualified": False, "missing": [], "invalid": ["unknown_profile"],
            })
```

- [ ] Also assert the inventory keys exactly match the release schema enum and every `--profile` value in plans 01 through 06. Delete each profile mapping and add an unknown mapping in loader tests; each must reject the inventory. Repeat artifact-removal tests with required governance for all six profiles and remote delegated mode, asserting the exact additional missing filename. Keep governance and remote selection in trusted test setup.
- [ ] Run `python3 -m unittest discover -s integrations/omarchy/tests -p test_bundle.py -v`. Expected red: missing `qualification.bundle`, incomplete mapping, accepted unknown profile or failed missing-artifact assertion. Implement strict inventory loading, full-set lookup and conditional requirement unions, then rerun. Expected green: all six profile controls remain synthetic/unqualified, every removal identifies the missing artifact and every unknown profile is refused.
- [ ] Commit only the inventory, loader and tests with `test: define Omarchy prerequisite inventory`. Evidence: source availability comparison and fixture result; no runtime gate closes.

### Task 2: Reject source-only, stale and substituted evidence

- [ ] Extend the bundle schema to require exact profile, artifact SHA-256, installed-file inventory digest, public source refs, native ABI/store identity, bridge/operator hashes, Pi peer and consumer-lock digest, runtime/architecture, provider profile/account binding reference, resource/policy/recipe hashes, governance mode and per-case evidence class/result. Secrets, absolute credential paths and undeclared fields are forbidden.
- [ ] Add this helper to `test_bundle.py` and call it from a test method. `base` is the new `synthetic-matching-tuple.json` control, not the source-only negative fixture. Trusted test setup independently selects the exact project tuple with x86_64, Pi 1.0.2 and governance not required; all required artifacts/cases match that selection. The control's first evidence record has a stable `acceptance_id` and expected `classification` of `independent_integration`. These are fabricated validator inputs under `synthetic: true`, never actual integration evidence. The evaluator must continue collecting diagnostic defects after the synthetic refusal, using the stable codes below:

```python
import copy

def assert_tuple_and_evidence_refusals(test, evaluate_bundle, base):
    test.assertIs(base["synthetic"], True)
    control = evaluate_bundle("project-v1", base)
    test.assertEqual(control, {
        "qualified": False, "missing": [], "invalid": ["synthetic_bundle"],
    })

    def assert_exact_defect(mutant, code):
        test.assertIs(mutant["synthetic"], True)
        result = evaluate_bundle("project-v1", mutant)
        test.assertFalse(result["qualified"])
        test.assertEqual(result["missing"], [])
        test.assertCountEqual(result["invalid"], ["synthetic_bundle", code])

    for field, replacement in (
        ("architecture", "arm64"),
        ("pi_version", "0.85.1"),
        ("governance", "required"),
    ):
        with test.subTest(field=field):
            mutant = copy.deepcopy(base)
            mutant["installed"][field] = replacement
            assert_exact_defect(mutant, f"tuple_mismatch:{field}")
    acceptance_id = base["evidence"][0]["acceptance_id"]
    for classification in ("source", "document", "component", "skipped", "unknown"):
        with test.subTest(classification=classification):
            mutant = copy.deepcopy(base)
            mutant["evidence"][0]["classification"] = classification
            assert_exact_defect(mutant, f"evidence_class:{acceptance_id}:{classification}")
```

- [ ] Run the Task 1 unittest command. Expected red before classification/tuple checks because the exact defect code is absent, even though `qualified` is already false. Prove that removing each field/classification check makes its corresponding test fail; an evaluator returning only `synthetic_bundle` must fail these tests. Implement equality against the independently selected tuple and refuse any missing/failed/skipped required case. A synthetic fixture can exercise validator branches but must never produce a runtime-qualified bundle. Re-run for green; the internally matching control remains false solely because it is synthetic, and each mutant adds exactly its own defect code.
- [ ] Implement `capabilities.rs` as a closed observer over the verified bundle: `unavailable`, `source_supported_unqualified`, `qualified_for_profile`. Add Rust test `source_evidence_cannot_enable_project` in `tests/prerequisites.rs`, checking unavailable mutations and zero credential-reader/launcher calls. Run `cargo test -p chio-desktop --test prerequisites source_evidence_cannot_enable_project`. Expected red before adapter gate, green after exact-match gating. The Rust test uses counters in test-only callbacks, not fake native grants.
- [ ] Commit schema/gating changes with `feat: gate desktop profiles on exact qualification evidence`. Keep the installed native verifier responsible for signatures and retained authority.

### Task 3: Probe actual native contracts and hand off missing source

- [ ] Create `native_probe.py` with one closed observation contract:

```python
REQUIRED_OBSERVATIONS = (
    "installed_binary_hash", "native_abi", "authority_store_identity",
    "operator_code_hash", "original_lookup", "exact_completion_verification",
    "delivery_ack", "approval_decision_binding", "child_admission",
)
```

Each value records `available`, evidence path and artifact digest, or `unavailable` with a safe reason. A listening port or semver alone supplies none of these observations.
- [ ] Write tests that select the current Pi operator and require `approval_decision_binding == "unavailable"`, native child admission unavailable without a delivered facade, and required governance unavailable before credentials. Run `python3 -m unittest discover -s integrations/omarchy/tests -p test_native_probe.py -v`. Expected red if a utility name/version promotes availability; implement explicit artifact/contract checks and rerun for green.
- [ ] Invoke only installed supported commands for the selected artifact, beginning with `chio-pi doctor --config /absolute/private/prepared.json` and `chio-pi inspect --config /absolute/private/prepared.json --request ORIGINAL_REQUEST_ID --json`. `ORIGINAL_REQUEST_ID` comes from the native fixture, never from the test runner's invented effect identity. Store redacted results and independently verify the completion using the selected native verifier.
- [ ] Produce a handoff record for every absent native function: owner role, source-map ID, exact required input/output and fault case, selected archive/binary hash and missing evidence. In particular, hand off approval decision-before-retention, exact Pi 1.0.2 coding compatibility, private prompt transport and process-child facade. Do not add `/v1/knowledge`, `/v1/semantic`, child or recovery routes to the desktop to simulate them.
- [ ] Commit only source/probe code and synthetic fixtures with `feat: report native desktop prerequisites without fallback`. Runtime observations stay in a new private evidence directory until redacted/approved for source retention.

### Task 4: Establish x64 and actual native workflow evidence

- [ ] Define `platform_probe.py` output fields for architecture, boot ID, kernel, Landlock ABI, user namespaces, cgroup controllers, bubblewrap binary hash/version, Node/runtime closure, seccomp profile, Omarchy/Hyprland/Quickshell/systemd versions and actual service UID. Test missing features as refusals using `test_platform_probe.py`; run its unittest command red, implement bounded probes, then green.
- [ ] Extend future `qualify.py` with required `--phase`, `--profile`, `--bundle`, `--output` and optional `--case`; output directory must be new and private. Exit 0 only when every selected applicable case passes; exit 2 for unavailable prerequisites; exit 1 for failed observations. Preserve partial evidence on every failure. Add tests that an existing output directory and a skipped required case cannot succeed.
- [ ] On the actual selected non-root Omarchy x64 installation run `python3 integrations/omarchy/qualify.py --phase P0 --profile project-v1 --bundle /absolute/private/selected-bundle.json --output /absolute/private/new-p0-evidence`. Expected initial refusal until all delivered native prerequisites exist. Never use the arm64 privileged-container record to fill this cell.
- [ ] Once delivered, record the native positive control and forbidden guest routes, exact signed result/history/ACK and original recovery. Independent resource/listener/process observers must run outside guest/controller; each negative needs a working outside-boundary positive control. Run the independently observed native coding control directly through the installed protected Pi and resource packages, without a desktop controller, and bind its exact source/test/receipt/history/ACK/recovery results as `pi-current-native-workflow.json`. Extend the P0 case driver with `native-coding-control`; keep fabricated metadata and scripted native services classified as component evidence. P2 subsequently tests the complete desktop composition, so P0 closure does not depend on a P2 controller build.
- [ ] Commit probe/harness changes with `test: qualify exact Omarchy native prerequisites`. A failed or unavailable native artifact remains an explicit P0/P2 blocker; source and fixture tests may pass independently.

## Exit and handoff

P0 hands P1/P2 a verified exact tuple, source/API crosswalk, available feature descriptor, named missing-artifact report and immutable evidence index. No current installer claim follows from a source ref. P2 native execution remains unavailable unless its complete tuple passes; P3/P4/P5/P6 remain unavailable until their inherited and added gates pass. Required governance is separately selected. This plan does not authorize release publication.

Coverage: host prerequisites AT-HST-001/003/005/006/008/016, source/candidate distinctions, platform prerequisites and AT-VER-001/004. Actual useful workflow, approval consume and child launch live in the dependent plans, not in callback fixtures here.

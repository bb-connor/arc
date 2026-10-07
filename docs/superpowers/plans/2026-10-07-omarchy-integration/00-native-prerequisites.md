# Native Prerequisites Implementation Plan

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
| `integrations/omarchy/fixtures/compatibility/profile-requirements.json` | Per-profile required native artifacts and applicable acceptance IDs |
| `crates/products/chio-desktop/src/adapter/capabilities.rs` | Translate a verified installation observation into available/refused desktop features |
| `crates/products/chio-desktop/tests/prerequisites.rs` | No-credential/no-launch prerequisite tests |
| `integrations/omarchy/qualification/native_probe.py` | Run installed native diagnostics with literal argv and bounded private output |
| `integrations/omarchy/qualification/platform_probe.py` | Record the real architecture/kernel/runtime/confinement tuple |
| `integrations/omarchy/qualification/observations.py` | Keep component and independent native observations distinct |

The crate scaffold and shared protocol types are coordinated with P1. Extend those files rather than creating a second crate or overwriting another plan's modules. Native process/cage/credential sources absent from main are external prerequisites, not permission to invent similarly named controller APIs.

### Task 1: Freeze the prerequisite inventory and source availability

- [ ] Record the public Chio and Pi refs from the readiness crosswalk and refresh them through `gh api repos/backbay-labs/chio/commits/main` and `gh api repos/backbay-labs/chio-pi-plugin/commits/main`. Retain the returned identities; do not silently switch the selected tuple to a newer main.
- [ ] Create `profile-requirements.json` with exact proposed gate sets:

```json
{
  "observe-v1": ["native-compatibility-manifest.json"],
  "project-v1": ["native-compatibility-manifest.json", "omarchy-x64-confinement.json", "pi-current-native-workflow.json", "pi-private-input-transport.json", "provider-limits-profile.json"],
  "reviewed-publish-v1": ["native-approval-decision-binding.json"],
  "delegated-v1": ["native-delegation-profile.json"]
}
```

These arrays are incremental dependencies: reviewed publication includes project-v1, delegated-v1 includes reviewed-publish-v1, optional remote cells additionally require `cross-host-custody-profile.json` within the selected delegated-v1 tuple. Required governance adds `native-model-release-profile.json` to any selected profile.
- [ ] Write `test_bundle.py` first using `unittest`: load the profile requirements, remove each required artifact in turn and assert its exact filename appears in `evaluate_bundle(profile, bundle)["missing"]`. Define `evaluate_bundle` in `qualification/bundle.py` to return `{"qualified": bool, "missing": list[str], "invalid": list[str]}`; it is a diagnostic evaluator of independently verified inputs, not an authority verifier.
- [ ] Run `python3 -m unittest discover -s integrations/omarchy/tests -p test_bundle.py -v`. Expected red: missing `qualification.bundle` or failed missing-artifact assertion. Add the incremental dependency expansion and required-governance union, then rerun. Expected green: all removal cases identify the missing artifact; source-only never qualifies.
- [ ] Commit only the inventory, loader and tests with `test: define Omarchy prerequisite inventory`. Evidence: source availability comparison and fixture result; no runtime gate closes.

### Task 2: Reject source-only, stale and substituted evidence

- [ ] Extend the bundle schema to require exact profile, artifact SHA-256, installed-file inventory digest, public source refs, native ABI/store identity, bridge/operator hashes, Pi peer and consumer-lock digest, runtime/architecture, provider profile/account binding reference, resource/policy/recipe hashes, governance mode and per-case evidence class/result. Secrets, absolute credential paths and undeclared fields are forbidden.
- [ ] Add this test logic to `test_bundle.py`; `base` is the checked-in synthetic observation fixture loaded by the test, and its `synthetic` field must remain true:

```python
for field, replacement in (
    ("architecture", "arm64"),
    ("pi_version", "0.85.1"),
    ("governance", "required"),
):
    mutant = copy.deepcopy(base)
    mutant["installed"][field] = replacement
    self.assertFalse(evaluate_bundle("project-v1", mutant)["qualified"])
for classification in ("source", "component", "skipped", "unknown"):
    mutant = copy.deepcopy(base)
    mutant["evidence"][0]["classification"] = classification
    self.assertFalse(evaluate_bundle("project-v1", mutant)["qualified"])
```

- [ ] Run the Task 1 unittest command. Expected red before classification/tuple checks. Implement equality against the independently selected tuple and refuse any missing/failed/skipped required case. A synthetic fixture can exercise validator branches but must never produce a runtime-qualified bundle. Re-run for green; include one fixture whose internal match succeeds but final qualification remains false because it is synthetic.
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

P0 hands P1/P2 a verified exact tuple, source/API crosswalk, available feature descriptor, named missing-artifact report and immutable evidence index. No current installer claim follows from a source ref. P2 native execution remains unavailable unless its complete tuple passes; P3 and P6 remain unavailable until their added gates pass. Required governance is separately selected. This plan does not authorize release publication.

Coverage: host prerequisites AT-HST-001/003/005/006/008/016, source/candidate distinctions, platform prerequisites and AT-VER-001/004. Actual useful workflow, approval consume and child launch live in the dependent plans, not in callback fixtures here.

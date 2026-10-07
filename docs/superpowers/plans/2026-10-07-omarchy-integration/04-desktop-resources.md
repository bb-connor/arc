# Bounded Desktop Resources Implementation Plan

| Boundary scope | `boundary_class` | `planning_status` | Decision and execution gate |
| --- | --- | --- | --- |
| `desktop_admission` | `prevent` | `blocked_by_adr` | Owner decision F5 must retain or remove P4; if retained, P3 exact approval, pinned compositor, enrolled session and protected socket custody remain execution gates. |
| `compositor_observation` | `detect_only` | `ready_after_adr` | Accepted ADR-0011 permits bounded independent compositor observations; postconditions and dispatch counters do not themselves authorize workspace mutation. |
| `reserved_window_actions` | `prevent` | `deferred` | Window focus/move/close are excluded from desktop-v1. Any future profile needs an owner-approved scope and atomic generation-bound compositor effect contract. |

Metadata follows [ADR-0011](../../../adr/ADR-0011-boundary-taxonomy-product-wording.md) and the [plan-set inheritance and owner-decision gate](README.md#boundary-metadata-and-inheritance). Classes describe proposed boundaries, not delivered qualification.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the P4 resource profile with four bounded metadata reads and an exactly approved numeric workspace selection, with independently observed outcomes and explicit refusal for unqualified effects.

**Architecture:** A protected Rust resource participant owns the enrolled compositor connection and accepts only native kernel-admitted calls. The desktop controller projects native operation state and opens evidence artifacts; it implements no second approval or recovery engine. Address-targeted windows and capture remain unavailable.

**Tech Stack:** Rust, native Chio resource participant transport, AF_UNIX Hyprland IPC, pinned serde/serde_json from the qualified Rust dependency graph, Python standard-library qualification harness, actual Omarchy x86-64 session.

---

Status: Proposed plan only. All `integrations/omarchy/` files and commands below are proposed unless created by earlier phase plans. Code blocks are focused implementation/test sketches; complete production behavior is governed by the linked specification, not by omission from a sketch. No command below has been executed as runtime qualification during specification drafting.

Read [desktop contract](../../specs/2026-10-07-omarchy-integration/10-desktop-tools.md) and [source comparison](../../specs/2026-10-07-omarchy-integration/research/desktop-ecosystem.md) before execution. Preserve unrelated checkout changes. At execution, create an isolated worktree using the required worktree skill. Do not install or execute a community server to obtain a broader fallback.

## Prerequisites and stop conditions

P0 must supply exact Omarchy/Hyprland binary identities and current grammar; P3 must supply tested native approval decisions, caller binding, durable original-operation identity and reconciliation. A missing native approval gate permits read-only adapter development and tests but blocks the workspace mutation gate. A JSON fixture saying `approved: true` cannot close it. Raw socket access must be absent from the actual Pi guest before any desktop capability is enrolled.

The stable compositor target primitive is absent from the inspected source contract. No task below implements window focus/move/close or tries to emulate atomic identity checking with repeated address reads. P4 can complete its explicitly named metadata-and-workspace profile without claiming those features.

Use the proposed qualification CLI consistently:

```sh
python3 integrations/omarchy/qualify.py --phase P4 --profile desktop-v1 --bundle /absolute/qualified-bundle.json --output /absolute/new-evidence-dir
```

The qualified bundle supplies independently verified native prerequisites; it is not a local approval flag. The output path must be a new private directory. Expected before prerequisites: nonzero exit with named missing gates and zero desktop mutation. Expected after completion: exit 0 only when every `AT-DSK` case for the named profile has independent evidence. Earlier plans own the shared CLI entrypoint; add P4 registration without replacing other phases.

## File ownership map

| Proposed path | Responsibility |
| --- | --- |
| `integrations/omarchy/resources/desktop/Cargo.toml`, `src/lib.rs` | Resource build surface; integrate with the qualified parent dependency/build scheme, not a parallel kernel. |
| `integrations/omarchy/resources/desktop/src/schema.rs` | Closed request inventory and argument validation. |
| `integrations/omarchy/resources/desktop/src/session.rs` | Trusted enrollment and compositor epoch/peer validation. |
| `integrations/omarchy/resources/desktop/src/ipc.rs` | Fixed requests, bounded synchronous socket lifetime and event resync. |
| `integrations/omarchy/resources/desktop/src/projection.rs` | Private bounded metadata snapshots and pagination. |
| `integrations/omarchy/resources/desktop/src/participant.rs` | Native admitted-call binding, one dispatch and retained resource observations. |
| `integrations/omarchy/resources/desktop/tests/contract.rs` | Focused schema, epoch, bounds and state-transition regressions. |
| `integrations/omarchy/fixtures/desktop/` | Recorded schema/IPC fixtures and redacted version-bound descriptors. |
| `integrations/omarchy/tests/test_desktop_evidence.py` | Independent evidence assertions and deliberate false-green rejection. |
| `integrations/omarchy/tests/desktop_observer.py` | Separate host observer for socket/process/window/session effects. |
| `integrations/omarchy/qualify.py` | Register P4 cases using the earlier phase's common evidence validation. |

## Task 1: Freeze the inventory and refused interfaces

**Files:** Create the desktop crate/build entry under the parent build scheme, `src/schema.rs`, `tests/contract.rs`; create `fixtures/desktop/inventory.json`. Covers OM-DSK-001, 004, 012, 013.

- [ ] Write a failing inventory test before exporting any tool:

```rust
#[test]
fn inventory_is_closed() {
    assert_eq!(desktop_resource::schema::TOOL_NAMES, [
        "desktop_session", "desktop_windows", "desktop_workspaces",
        "desktop_monitors", "desktop_workspace_select",
    ]);
}
```

- [ ] Run `cargo test --manifest-path integrations/omarchy/resources/desktop/Cargo.toml inventory_is_closed`. Expected red: missing module/constant, never an accidental pass because no tests were selected.
- [ ] Add the constant below as the known inventory, and closed serde types for the five exact schemas from the specification. Deny additional fields; validate UUID/digest representation using the already qualified native parsers. Schema inventory hashes must be included in the resource manifest. Runtime advertisement filters this known inventory by actual capability/native-gate availability, so unavailable workspace mutation is not advertised. Set the crate library name to `desktop_resource` for the test imports shown here.

```rust
pub const TOOL_NAMES: [&str; 5] = [
    "desktop_session", "desktop_windows", "desktop_workspaces",
    "desktop_monitors", "desktop_workspace_select",
];
pub fn workspace_slot(value: &serde_json::Value) -> Result<u8, &'static str> {
    match value.as_u64() {
        Some(n @ 1..=10) => Ok(n as u8),
        _ => Err("workspace_slot_out_of_scope"),
    }
}
```

- [ ] Add parameterized tests for `0`, `11`, `-1`, `1.5`, `"+1"`, `"special"`, `null`, extra properties and raw command/Lua/path fields; test every excluded tool name. Run the crate's `contract` test target. Expected green: valid absolute slots only; rejected cases reach no dispatch spy.
- [ ] Commit only these paths with `git commit -m "feat(omarchy): define closed desktop resource inventory"` after staging the exact files. Do not mark P4 enabled.

## Task 2: Enroll and validate the real session boundary

**Files:** Create `src/session.rs`; extend `tests/contract.rs`, `fixtures/desktop/session-identities.json`, `tests/desktop_observer.py`. Covers OM-DSK-002, 003.

- [ ] Write the epoch regression using a value object whose fields are explicitly defined here:

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionIdentity {
    pub boot_id: String,
    pub uid: u32,
    pub session_id: String,
    pub compositor_start: u64,
    pub instance_signature: String,
    pub socket_inode: u64,
}
pub fn same_session(expected: &SessionIdentity, actual: &SessionIdentity)
    -> Result<(), &'static str>
{
    if expected == actual { Ok(()) } else { Err("session_epoch_changed") }
}
```

In the test, construct an enrolled identity, clone it, increment `compositor_start`, and assert `same_session` returns `session_epoch_changed`. Also assert changing any one other field refuses. Write tests first, before adding the function implementation.
- [ ] Run `cargo test --manifest-path integrations/omarchy/resources/desktop/Cargo.toml session_epoch`. Expected red before `session.rs` exists; green only after all changed-field cases refuse.
- [ ] Implement trusted enrollment from the operator-owned session descriptor, no-follow socket metadata and connected peer credentials. Use fixed permitted runtime paths derived from enrollment; reject inherited guest environment, ambiguous/missing lock state and changed compositor peer. Add a constructor reachable only from the native trusted transport, not JSON-supplied session objects.

```rust
pub fn permit_mutation(locked: Option<bool>, identity_matches: bool)
    -> Result<(), &'static str>
{
    match (locked, identity_matches) {
        (Some(false), true) => Ok(()),
        _ => Err("session_not_available_for_mutation"),
    }
}
```

- [ ] Run the actual guest socket-probe portion of AT-DSK-002 and session-restart/lock cases from AT-DSK-003 through the P4 harness. Expected green only with OS denial and a positive admitted read; a mock `same_session` test alone leaves these gates open.
- [ ] Commit exact session/observer/test files with `git commit -m "feat(omarchy): bind desktop resource to enrolled session"`.

## Task 3: Bound request sockets, events and projections

**Files:** Create `src/ipc.rs`, `src/projection.rs`; extend `tests/contract.rs`; create `fixtures/desktop/oversized-event.json`, `fixtures/desktop/private-windows.json`. Covers OM-DSK-005, 009, 014.

- [ ] Write tests for a 65,537-byte raw response, 8,193-byte event line, 257 queued events, expired pagination, titles containing credentials and terminal escapes. Assert response refusal/invalidation rather than silent success. A useful independent byte-bound test is:

```rust
#[test]
fn wire_bound_counts_json_escaping() -> Result<(), Box<dyn std::error::Error>> {
    let payload = serde_json::json!({"value": "\u{0000}".repeat(4096)});
    let bytes = serde_json::to_vec(&payload)?;
    assert!(bytes.len() > 16 * 1024);
    assert_eq!(desktop_resource::projection::fit(bytes.len()), Err("result_bound"));
    Ok(())
}
```

- [ ] Run `cargo test --manifest-path integrations/omarchy/resources/desktop/Cargo.toml --test contract`. Expected red for absent projection/overflow behavior.
- [ ] Implement fixed IPC commands selected from an enum, one request in flight, eight queued calls, one-second read/write deadlines and immediate socket closure. Never keep an idle request socket open. Implement event overflow as snapshot invalidation followed by one bounded resync. Redact titles/initial titles/paths before serialization, and use content digests separate from observation timestamps.

```rust
pub fn fit(encoded_bytes: usize) -> Result<(), &'static str> {
    if encoded_bytes <= 16 * 1024 { Ok(()) } else { Err("result_bound") }
}
#[derive(Debug, PartialEq, Eq)]
pub enum SnapshotState { Fresh, NeedsResync }
pub fn after_event_loss() -> SnapshotState { SnapshotState::NeedsResync }
```

- [ ] Repeat the test target, then run actual AT-DSK-005/009/014 through the qualification harness. Expected green: bounded encoded outputs, no leaked canaries, no stale snapshot and no adapter-held request connection above 1.1 seconds in the measured lane. Preserve scheduler/platform measurement in the report.
- [ ] Commit exact IPC/projection/fixture/test files with `git commit -m "feat(omarchy): bound desktop IPC and private projections"`.

## Task 4: Connect one exact native workspace operation

**Files:** Create `src/participant.rs`; extend native resource manifest registration in the parent integration and `tests/contract.rs`; create `fixtures/desktop/approval-substitution.json`. Covers OM-DSK-006, 007, 008.

- [ ] Write the failing native-boundary test: original approved slot 3 cannot be substituted with slot 4, stale session/snapshot, changed task revision or expired authority. The test observer counts real dispatches separately from return values:

```python
import unittest

class ApprovalEvidence(unittest.TestCase):
    def test_substitution_has_no_effect(self):
        import json
        from pathlib import Path
        evidence = json.loads(Path("/absolute/new-evidence-dir/AT-DSK-006.json").read_text())
        self.assertEqual(evidence["substituted_dispatch_count"], 0)
        self.assertEqual(evidence["accepted_exact_dispatch_count"], 1)
        self.assertTrue(evidence["native_signature_verified"])
```

- [ ] Run the P4 qualifier while the native decision gate is unavailable. Expected red: a named `native_approval_unavailable` prerequisite and zero workspace dispatch. Do not change the test to accept local approval booleans.
- [ ] After P3 supplies the real admitted-call API, wire its immutable operation/tool/argument/session bindings to the resource. Freshly compare the relevant state digest, send exactly one fixed absolute-slot dispatcher request and observe the postcondition. No local approval verifier, signing key, generic dispatcher or fallback is created.

```rust
#[derive(Debug, PartialEq, Eq)]
pub enum EffectDetail {
    NotDispatched,
    DispatchedObserved,
    DispatchedPostconditionFailed,
    DispatchOutcomeUnknown,
}
pub fn observed_result(sent: bool, retained_reply: bool, postcondition: Option<bool>)
    -> EffectDetail
{
    match (sent, retained_reply, postcondition) {
        (false, _, _) => EffectDetail::NotDispatched,
        (true, false, _) | (true, true, None) => EffectDetail::DispatchOutcomeUnknown,
        (true, true, Some(true)) => EffectDetail::DispatchedObserved,
        (true, true, Some(false)) => EffectDetail::DispatchedPostconditionFailed,
    }
}
```

This helper classifies observations; native durable completion remains a separate necessary condition for task success.
- [ ] Run AT-DSK-006/007/008 with the independent compositor observer. Expected green: one exact approved selection, zero substituted/window-targeted dispatch and honest postcondition failure when command acknowledgement lacks effect. Any native prerequisite still missing keeps the task incomplete.
- [ ] Commit exact participant/manifest/test files with `git commit -m "feat(omarchy): mediate exact workspace selection"` only after the enabled behavior matches the available native contract.

## Task 5: Preserve stop, lost response and original identity

**Files:** Extend `src/participant.rs`, `tests/contract.rs`, `tests/desktop_observer.py`; create `fixtures/desktop/crash-points.json`. Covers OM-DSK-010, 011.

- [ ] Add failing crash/cancel cases at queue, final admission, socket write, observation and native result delivery. The response-loss test must assert one original operation ID and one compositor request after restart:

```python
def assert_original_only(test, evidence):
    test.assertEqual(len(set(evidence["operation_ids"])), 1)
    test.assertEqual(evidence["compositor_dispatch_count"], 1)
    if evidence["retained_native_outcome"] is None:
        test.assertEqual(evidence["task_state"], "blocked_unknown")
```

- [ ] Run `python3 -m unittest discover -s integrations/omarchy/tests -p 'test_desktop_evidence.py' -v` against deliberate bad evidence (second dispatch or unknown reported success). Expected red assertions, proving the oracle rejects false completion.
- [ ] Wire queue cancellation and final native admission checks; retain dispatch phase and observations through the native resource original-outcome contract. Reconciliation must inspect the original native operation; do not infer success from the currently active workspace.

```rust
pub fn should_redispatch(has_original_intent: bool) -> bool {
    !has_original_intent
}
```

Use this invariant only at the admission boundary: an original intent always chooses native inspection/recovery rather than a fresh dispatch. A completed replay returns its retained result.
- [ ] Run AT-DSK-010/011 against actual response loss and controller/resource restart. Expected green: queued denial has zero requests, dispatched unknown stays fenced, exact completed replay never changes the user's later workspace.
- [ ] Commit exact recovery/test files with `git commit -m "fix(omarchy): retain desktop operation truth across restart"`.

## Task 6: Integrate independent qualification and profile enablement

**Files:** Extend `integrations/omarchy/qualify.py`; complete `tests/test_desktop_evidence.py`, `tests/desktop_observer.py`; create `fixtures/desktop/profile-manifest.json`; update the installed-profile documentation produced by P0. Covers OM-DSK-015 and closes all prior evidence cases.

- [ ] Add evidence rejection tests for missing native signatures, stale binary hashes, wrong architecture, fixture-only observers, absent positive controls and a missing acceptance case. Use a closed expected set:

```python
EXPECTED = {f"AT-DSK-{n:03d}" for n in range(1, 16)}
def missing_cases(records):
    return EXPECTED - {record["acceptance_id"] for record in records
                       if record["passed"] and record["independent_oracle"]}
```

- [ ] Run the evidence tests with one record removed. Expected red: precisely that acceptance ID is missing; a top-level `passed: true` does not override it.
- [ ] Register the actual-machine runner for each case; require machine/session/binary/schema/policy identities, native verification and independent observer artifact hashes. Add profile invalidation on any qualified identity drift. Preserve full capture/clipboard/window/privilege exclusions even if an optional community plugin is installed.
- [ ] Run the exact P4 qualifier command above plus `cargo test --manifest-path integrations/omarchy/resources/desktop/Cargo.toml`. Expected green only for the named actual-machine profile; all unavailable gates remain listed and yield nonzero. Do not generalize to other compositors, architectures or privileged-container evidence.
- [ ] Commit exact harness/evidence-schema/docs changes with `git commit -m "test(omarchy): qualify bounded desktop resource profile"`. Store generated private evidence outside Git; commit only sanitized version manifests and reproducible assertions authorized by the release plan.

## Coverage and handoff

| Requirements | Tasks |
| --- | --- |
| OM-DSK-001, OM-DSK-004, OM-DSK-012, OM-DSK-013 | 1, 6 |
| OM-DSK-002, OM-DSK-003 | 2, 6 |
| OM-DSK-005, OM-DSK-009, OM-DSK-014 | 3, 6 |
| OM-DSK-006, OM-DSK-007, OM-DSK-008 | 4, 6 |
| OM-DSK-010, OM-DSK-011 | 5, 6 |
| OM-DSK-015 | 6 |

Report adapter/unit checks, actual native acceptance, installed desktop qualification and release publication as separate outcomes. An unresolved native approval or custody gate ends with read-only development artifacts and an explicit blocked mutation profile. This plan does not authorize implementing an unreviewed window-target primitive or broadening the allowlist.

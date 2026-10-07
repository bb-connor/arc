# Reviewed Configuration Repair Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver P5 diagnosis and exact review for one Hyprland appearance file, enabling apply only after native approval, safe writer exclusion, backup and bounded reload qualification exist.

**Architecture:** A protected Rust configuration participant snapshots and validates private copied inputs, then uses native authority and the qualified host-file effect contract for any live replacement. The native operation retains each file/reload stage; the controller displays exact plans and evidence without signing approvals or inventing recovery. A restricted literal grammar and one-file profile constrain the initial domain.

**Tech Stack:** Rust, native Chio resource/approval/recovery interfaces, a dedicated restricted Lua parser, confined Linux validator, AF_UNIX desktop observation from P4, Python standard-library acceptance harness.

---

Status: Proposed plan only. Paths, APIs and commands below are proposed unless delivered by earlier plans. Implementation snippets establish narrow interfaces and test expectations; the full [repair contract](../../specs/2026-10-07-omarchy-integration/11-configuration-repair.md) remains normative. Read [desktop contract](../../specs/2026-10-07-omarchy-integration/10-desktop-tools.md) and [ecosystem sources](../../specs/2026-10-07-omarchy-integration/research/desktop-ecosystem.md) before execution. No runtime repair is authorized by running a documentation validator.

## Prerequisites and stop conditions

P4 must qualify the exact session/observer. P3 must supply working exact native approval and original-operation reconciliation. Native host-file integration must supply a tested writer-exclusion/replacement contract; a hash check followed by rename is not sufficient. Reload coordination must either suppress automatic reload safely or supply a separately proved equivalent sequence, and the complete live dependency graph must have a qualified effect profile. Missing any one keeps apply unavailable while diagnosis/preview development continues.

The first profile rejects multi-file repair, arbitrary Lua, symlinked dotfiles, privileged operations and unsupported metadata. A future broader profile needs another reviewed specification; implementation may not promote a partially working two-file transaction into the default.

The shared proposed harness command is:

```sh
python3 integrations/omarchy/qualify.py --phase P5 --profile repair-v1 --bundle /absolute/qualified-bundle.json --output /absolute/new-evidence-dir
```

The bundle path identifies independently qualified native component evidence, not a writable local `approved` switch. The output directory must be new and private. Before prerequisites, expected result is nonzero with named blockers and zero host writes/reloads. A fixture or privileged-container success is insufficient to enable `repair-v1`.

## File ownership map

| Proposed path | Responsibility |
| --- | --- |
| `integrations/omarchy/resources/configuration/Cargo.toml`, `src/lib.rs` | Focused resource build entry in the qualified dependency scheme. |
| `integrations/omarchy/resources/configuration/src/domain.rs` | Exact target and allowed scalar grammar/values. |
| `integrations/omarchy/resources/configuration/src/parser.rs` | Non-executing lexer/parser and deterministic emitter. |
| `integrations/omarchy/resources/configuration/src/diagnosis.rs` | Bounded incident/source metadata projection. |
| `integrations/omarchy/resources/configuration/src/snapshot.rs` | No-follow config/dependency snapshot and exact preview. |
| `integrations/omarchy/resources/configuration/src/validator.rs` | Sealed input manifest and confined validator lifecycle. |
| `integrations/omarchy/resources/configuration/src/backup.rs` | Private durable backup/readback/restore-representability verification. |
| `integrations/omarchy/resources/configuration/src/participant.rs` | Native admission, writer lease, file effect and durable stage integration. |
| `integrations/omarchy/resources/configuration/src/reload.rs` | Exact graph/session reload and postcondition observation via P4. |
| `integrations/omarchy/resources/configuration/tests/contract.rs` | Domain, snapshot, privacy, backup and recovery regressions. |
| `integrations/omarchy/fixtures/repair/` | Restricted/hostile Lua, concurrent-writer and crash fixtures. |
| `integrations/omarchy/tests/repair_observer.py` | Separate file/metadata/process/reload evidence collector. |
| `integrations/omarchy/tests/test_repair_evidence.py` | Independent acceptance and false-green rejection. |
| `integrations/omarchy/qualify.py` | Register P5 without modifying the earlier phases' semantics. |

## Task 1: Implement the closed appearance grammar

**Files:** Create the resource crate/build entry, `src/domain.rs`, `src/parser.rs`, `tests/contract.rs`; create `fixtures/repair/allowed.lua`, `fixtures/repair/hostile.lua`. Covers OM-FIX-001 and the syntax portion of 004.

- [ ] Write failing tests that accept comments plus literal `hl.config` tables and reject `os.execute`, indirect function calls, `require`, duplicate/conflicting keys, expressions, floats, strings as commands and unsupported keys. Keep the domain representation small:

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scalar { Integer(i64), Boolean(bool) }
pub fn allowed(key: &str, value: &Scalar) -> bool {
    match (key, value) {
        ("general.gaps_in" | "general.gaps_out" | "decoration.rounding", Scalar::Integer(n)) => (0..=32).contains(n),
        ("general.border_size", Scalar::Integer(n)) => (0..=8).contains(n),
        ("animations.enabled", Scalar::Boolean(_)) => true,
        _ => false,
    }
}
```

Write tests against `allowed` before adding that function; also test the actual parser with the hostile fixture, not only manually constructed scalar values.
- [ ] Run `cargo test --manifest-path integrations/omarchy/resources/configuration/Cargo.toml --test contract`. Expected red before the module exists and for every still-accepted hostile syntax form.
- [ ] Implement a dedicated lexer and recursive parser for the complete grammar below, with a maximum input size of 65,536 bytes, bounded nesting of four table levels, and token-count bound. Preserve comments/whitespace spans when replacing allowed scalar tokens. Reject duplicate keys and any token after the last permitted statement.

```text
file      = (whitespace | comment | statement)* EOF
statement = "hl" "." "config" "(" table ")" [";"]
table     = "{" [entry ("," entry)* [","]] "}"
entry     = identifier "=" (table | integer | "true" | "false")
comment   = Lua single-line comment only
integer   = optional-minus followed by decimal digits, no exponent or suffix
```

Flatten parsed table keys and pass every leaf through `allowed`; refuse empty/unknown subtrees that could hide extra behavior. The emitter must never copy unparsed executable text into a valid output. Do not evaluate Lua or remove suspicious words with regex.
- [ ] Run the contract tests; expected green includes parse/emit/parse scalar equivalence, exact unaffected comment bytes, rejection of malformed Unicode and a bounded failure for deep nesting/input flood. Confirm generated output contains only the supported grammar.
- [ ] Commit the exact parser/domain/test files with `git commit -m "feat(omarchy): restrict repair to appearance scalar grammar"`.

## Task 2: Snapshot exact inputs and project bounded diagnosis

**Files:** Create `src/diagnosis.rs`, `src/snapshot.rs`; extend `tests/contract.rs`; create `fixtures/repair/incident.json`, `fixtures/repair/dirty-source.lua`. Covers OM-FIX-002, 003, 013.

- [ ] Write a failing test with reused incident PID, differing boot identity, changed input during read and secret-bearing config comments. Assert incident mismatch is unavailable rather than a fabricated cause, changed input is refused and secret comments are not provider context. Independent evidence shape:

```python
def check_snapshot(test, record):
    test.assertEqual(record["before_original_sha256"], record["after_original_sha256"])
    test.assertEqual(record["preview_original_sha256"], record["selected_snapshot_sha256"])
    test.assertEqual(record["provider_secret_canary_count"], 0)
    test.assertFalse(record["core_memory_collected"])
```

- [ ] Run `cargo test --manifest-path integrations/omarchy/resources/configuration/Cargo.toml snapshot` and the new diagnosis tests. Expected red until exact file/incident matching is enforced.
- [ ] Implement no-follow directory-relative snapshotting of the enrolled regular, single-link file with supported owner/mode/metadata; refuse symlinked dotfiles and unsupported ACL/xattrs/flags. Record full byte hashes, file identity and sealed dependency identities. Build a preview containing text diff and scalar before/after, separate from model-selected diagnostic excerpts.

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncidentIdentity {
    pub boot_id: String,
    pub process_start: u64,
    pub executable_build_id: String,
    pub recorded_timestamp: String,
}
pub fn incident_matches(selected: &IncidentIdentity, observed: &IncidentIdentity) -> bool {
    selected == observed
}
```

Use the same complete identity in metadata collection; PID-only lookup cannot satisfy it. Bound incident reads to 64 KiB and preserve unavailable/truncation fields.
- [ ] Run AT-FIX-002/003/013 in the harness using independent source hashing and captured provider context. Expected green: exact selected incident, unchanged originals, no core/environment dump and no canary leakage.
- [ ] Commit exact snapshot/diagnosis/fixture/test files with `git commit -m "feat(omarchy): prepare exact private repair previews"`.

## Task 3: Validate copied configuration without host effects

**Files:** Create `src/validator.rs`; extend `tests/contract.rs`; create `fixtures/repair/validator-manifest.json`, `fixtures/repair/dependency-hook.lua`; extend `tests/repair_observer.py`. Covers OM-FIX-004 and dependency prerequisites of 009.

- [ ] Add failing cases for a copied dependency invoking network/process/host-file effects, infinite loop, 16-KiB-plus output and changed validator/runtime hash. The independent observer must detect zero host effects, not trust a sandbox return label:

```python
def check_validator(test, evidence):
    test.assertEqual(evidence["host_process_launches"], 0)
    test.assertEqual(evidence["host_canary_after"], evidence["host_canary_before"])
    test.assertEqual(evidence["external_socket_connects"], 0)
    test.assertLessEqual(evidence["returned_output_bytes"], 16384)
```

- [ ] Run the validator test selection before the confinement adapter exists. Expected red: `validator_unavailable`, never fallback to live `hyprctl reload`, `lua` or `luac` as an effect-safety proof.
- [ ] Implement manifest construction and invoke only a P0-qualified Linux confined validator through its fixed template. Inputs are copied/read-only; no home/session/authority sockets; 32 MiB scratch, 10-second deadline and 16 KiB output. Pin binary, runtime closure, option schema and all input hashes. Do not invent an upstream offline flag: select a proved offline parser or separately qualified isolated headless compositor.

```rust
pub fn validate_manifest_match(expected: &[u8; 32], actual: &[u8; 32])
    -> Result<(), &'static str>
{
    if expected == actual { Ok(()) } else { Err("validator_input_changed") }
}
```

The manifest equality helper is necessary but not sufficient: record actual OS confinement and attempted effects in the validator result. Unsupported native confinement remains unavailable.
- [ ] Run the actual AT-FIX-004 fixture with process/network/file observers. Expected green: hostile validation confined/refused, ordinary scalar candidate validated and its exact dependency/runtime hashes retained. A mock-only pass leaves P5 blocked.
- [ ] Commit exact validator/observer/test files with `git commit -m "feat(omarchy): validate repair candidates in confinement"`.

## Task 4: Add verified backups and a refusing writer-exclusion facade

**Files:** Create `src/backup.rs`, initial `src/participant.rs`; extend `tests/contract.rs`; create `fixtures/repair/backup-faults.json`, `fixtures/repair/writer-races.json`. Covers OM-FIX-006, 007, 014.

- [ ] Write failing backup cases for disk-full, fsync error, readback corruption, unsupported metadata and a Snapper-only recovery claim. Write a host-file race case with a concurrent editor holding an open writable descriptor; apply must be unavailable without proved exclusion.

```rust
#[derive(Debug, PartialEq, Eq)]
pub enum ApplyAvailability { Available, MissingBackup, MissingWriterExclusion }
pub fn availability(backup_verified: bool, exclusive_native_lease: bool) -> ApplyAvailability {
    if !backup_verified { ApplyAvailability::MissingBackup }
    else if !exclusive_native_lease { ApplyAvailability::MissingWriterExclusion }
    else { ApplyAvailability::Available }
}
```

These booleans are internal test inputs for classification only. Production values must come from verified backup readback and an unforgeable native lease object; neither field is accepted over the guest API.
- [ ] Run `cargo test --manifest-path integrations/omarchy/resources/configuration/Cargo.toml backup` and `writer_exclusion` selections. Expected red before durable readback and the refusing facade; no fake lease is added to make actual-machine gates pass.
- [ ] Implement private backup write/fsync/parent-fsync/readback and restore into a separate test directory. Record supported metadata and retention pins. Integrate the native writer lease only if its accepted contract covers parent replacement, open writers and stale-byte races; otherwise return `MissingWriterExclusion` and keep apply disabled. No hash-then-rename fallback or sudo/polkit helper is permitted.
- [ ] Run AT-FIX-006/007/014. Expected green for backup/exclusion refusal with zero host effect; enabling mutation still requires the actual native CAS lane. Independent restore bytes/metadata must equal the original; `~/.config` is not treated as covered by root snapshots.
- [ ] Commit exact backup/facade/test files with `git commit -m "feat(omarchy): require verified backups and native writer exclusion"`.

## Task 5: Bind exact native approval and reload effects

**Files:** Extend `src/participant.rs`; create `src/reload.rs`; extend `tests/contract.rs`; create `fixtures/repair/approval-substitution.json`, `fixtures/repair/reload-graph.json`. Covers OM-FIX-005, 009, 010.

- [ ] Write the failing approval test matrix for changed file bytes, backup digest, validator/dependency graph, schema, task revision, compositor epoch and expiry. Add accepted reload with wrong live value/config error and unrelated `configreloaded` event. Assert zero native effects for substituted approvals and no success from acknowledgement alone.

```python
def check_success(test, record):
    if record["reported_succeeded"]:
        test.assertTrue(record["native_completion_verified"])
        test.assertEqual(record["observed_file_sha256"], record["approved_after_sha256"])
        test.assertEqual(record["relevant_config_errors"], [])
        test.assertEqual(record["live_scalars"], record["approved_scalars"])
```

- [ ] Run P5 qualification with missing native approval/reload prerequisites. Expected nonzero with exact named blockers and zero writes/reloads. Do not accept the controller's review state as an approval substitute.
- [ ] After native prerequisites exist, consume the one-use admitted effect plan. Acquire the native writer exclusion, coordinate auto-reload, recheck all file/dependency/session bindings, durably install the approved file and issue one normal reload through the fixed protected session adapter. Return exact errors if any enrolled hook has changed or cannot be bounded. The only reload operation in this profile is the enum below:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReloadAction { NormalReload }
pub fn reload_argv(action: ReloadAction) -> [&'static str; 1] {
    match action { ReloadAction::NormalReload => ["reload"] }
}
```

Use this only inside the protected P4 session adapter with fixed binary identity; no caller argv, `full-reset`, service restart or arbitrary eval is admitted. Restore the prior automatic-reload setting and record failure if restoration cannot be verified.
- [ ] Run AT-FIX-005/009/010 on the selected real session. Expected green: exact approved effect, clean relevant parse errors and observed scalar values within three seconds; dependency hook attempts and stale bindings produce zero effects. Missing proof keeps apply unavailable.
- [ ] Commit exact participant/reload/test files with `git commit -m "feat(omarchy): apply exact approved appearance repair"` only for behavior the native prerequisites actually support.

## Task 6: Preserve stages, partial truth and conditional restoration

**Files:** Extend `src/participant.rs`, `src/backup.rs`, `src/reload.rs`, `tests/contract.rs`; create `fixtures/repair/crash-points.json`; extend `tests/repair_observer.py`. Covers OM-FIX-008, 011, 012.

- [ ] Write crash tests after durable intent, after file replacement, after reload send and before/after native result delivery. Refuse a two-file plan before any writes. Add failed postcheck followed by a new user edit, corrupted backup and failed restore reload.

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairStage {
    Prepared, BackupVerified, IntentDurable, FileInstalled,
    ReloadSent, PostcheckObserved,
}
pub fn default_file_count_allowed(count: usize) -> bool { count == 1 }
pub fn restore_precondition(current: &[u8; 32], proposed: &[u8; 32]) -> bool {
    current == proposed
}
```

Test functions independently with altered current bytes; the production restore requires the original exact native approval or a new native restore approval in addition to this hash precondition.
- [ ] Run the contract tests and deliberately false evidence through `python3 -m unittest discover -s integrations/omarchy/tests -p 'test_repair_evidence.py' -v`. Expected red for unknown reported succeeded, a second reload after response loss, multi-file default writes or overwritten user edits.
- [ ] Retain each effect stage through the native resource outcome contract, preserving the original operation identity and failure. Restore only the exact backup under declared compensation authority and unchanged current/dependency/session preconditions. If file restore works but reload fails, report partial recovery. Never claim that restored bytes reverse external hook effects.

```python
def check_recovery(test, record):
    test.assertEqual(len(set(record["original_operation_ids"])), 1)
    if record["outcome_unknown"]:
        test.assertEqual(record["task_state"], "blocked_unknown")
        test.assertEqual(record["automatic_redispatches"], 0)
    if record["new_user_edit"]:
        test.assertEqual(record["user_bytes_after"], record["user_bytes_before_restore"])
```

- [ ] Run actual AT-FIX-008/011/012 with an external crash supervisor and file/reload observer. Expected green only when known files/stages, recovery and unknown states match physical effects. A future multi-file branch must remain rejected by the default profile; no new two-file runtime feature is added here.
- [ ] Commit exact recovery/test files with `git commit -m "fix(omarchy): retain repair and restoration outcome truth"`.

## Task 7: Qualify the named actual-machine profile

**Files:** Extend `integrations/omarchy/qualify.py`; complete `tests/test_repair_evidence.py`, `tests/repair_observer.py`; create `fixtures/repair/profile-manifest.json`; update P0's installed-profile documentation. Covers OM-FIX-015 and closes the previous gates.

- [ ] Add the closed evidence set and reject missing signatures, missing independent observations, drifted source/binary/parser identities, wrong architecture and fixture-only acceptance:

```python
EXPECTED = {f"AT-FIX-{n:03d}" for n in range(1, 16)}
def incomplete(records):
    accepted = {r["acceptance_id"] for r in records
                if r["passed"] and r["independent_oracle"]}
    return EXPECTED - accepted
```

- [ ] Remove AT-FIX-007 from a fixture report and run the evidence tests. Expected red even if all other cases and the top-level report say passed. Repeat with actual CAS evidence replaced by a mock observer report.
- [ ] Register actual-machine cases and bind accepted evidence to exact Omarchy/compositor/parser/validator/native bundle hashes, writer model, reload graph profile and restoration observations. An identity change disables apply while retaining diagnosis/preview and recovery access. Keep private raw evidence outside committed source.
- [ ] Run the exact P5 command above and `cargo test --manifest-path integrations/omarchy/resources/configuration/Cargo.toml`. Expected green only when all fifteen cases and prerequisites pass on the named actual Omarchy profile. Any blocker yields nonzero with its owner and evidence requirement, not a skipped green case.
- [ ] Commit sanitized harness/profile/docs changes with `git commit -m "test(omarchy): qualify reviewed configuration repair"`. Report validation, installed profile enablement and release publication separately.

## Coverage and handoff

| Requirements | Tasks |
| --- | --- |
| OM-FIX-001 | 1, 6 |
| OM-FIX-002, OM-FIX-003, OM-FIX-013 | 2, 7 |
| OM-FIX-004 | 1, 3 |
| OM-FIX-005 | 5 |
| OM-FIX-006, OM-FIX-007, OM-FIX-014 | 4, 7 |
| OM-FIX-008, OM-FIX-011, OM-FIX-012 | 6 |
| OM-FIX-009, OM-FIX-010 | 3, 5 |
| OM-FIX-015 | 7 |

The execution handoff must name whether P5 remains preview-only, which native gate is missing, and whether live file/reload/restoration evidence exists. A source patch, parser unit test or system snapshot does not establish a safe repair. This plan creates no privileged default profile and no general configuration editor.

# Mac Recovery and Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make controller restart, stop, crash recovery and evidence export preserve native truth and block unsupported authority restoration before any execution profile launches.

**Architecture:** The desktop persists retry correlation and display projections, while native owners retain original operation, approval, budget, influence and stop state. Recovery reads and reconciles original native references through the M2 adapter; it does not create a parallel authority engine. Independent resource/process observers verify the outcomes, and whole-snapshot authority restore stays closed without qualified external freshness evidence.

**Tech Stack:** Proposed shared Rust `chio-desktop` controller, existing native admission/SQLite/receipt owners, Python qualification harness, signed canonical native evidence, macOS supervisor and profile-specific independent observers.

---

Status: proposed implementation plan; commands below are future execution commands. Confidence: high in recovery invariants; unknown in installed closure until acceptance. M0 native gates and M2 controller contract are prerequisites. M6 precedes M3 VM execution, M4 publication, M5 native enforcement and M7 delegation for the applicable selected profile. Run in an isolated worktree and preserve other authors' files.

Read [state recovery](../../specs/2026-10-07-macos-integration/11-state-recovery.md), [kernel contracts](../../specs/2026-10-07-macos-integration/03-kernel-contracts.md), [authority/integrity](../../specs/2026-10-07-macos-integration/04-authority-integrity.md), [operator protocol](../../specs/2026-10-07-macos-integration/06-operator-protocol.md), and the delivered M0 native API manifest. There is no assumed current `ProcessRuntime` or desktop recovery service on CHIO-MAIN.

## File and owner map

| Path | Responsibility |
| --- | --- |
| `crates/products/chio-desktop/src/recovery/projection.rs` | New pure display projection; never authority |
| `crates/products/chio-desktop/src/recovery/mod.rs` | New module integration into M2's scaffold |
| `crates/products/chio-desktop/src/recovery/retry_store.rs` | New controller-only stable-intent correlation, canonical request digest and retained native reference |
| `crates/products/chio-desktop/src/recovery/reconcile.rs` | New orchestration using delivered native read/reconcile adapter; no duplicate classifier |
| `crates/products/chio-desktop/src/evidence/manifest.rs` | New export composition preserving native artifacts and gaps |
| `crates/products/chio-desktop/tests/recovery_projection.rs`, `recovery_retry.rs`, `evidence_export.rs` | New controller component regressions |
| `integrations/macos/qualification/recovery_cases.py`, `evidence_index.py` | New deterministic schedule/oracle and artifact applicability checks |
| `integrations/macos/tests/test_recovery_cases.py`, `test_evidence_index.py` | New pure harness regressions; always component evidence |
| `integrations/macos/qualification/fixtures/recovery-cuts.json` | New synthetic schedules, expected independent observations |
| `crates/platform/chio-store-sqlite/src/admission_operation_store_tests/recovery.rs` | Existing native recovery-lease regressions; native owner extends |
| `crates/platform/chio-store-sqlite/src/serving_owner/tests.rs` | Existing native rollback, path and owner regressions; native owner extends |
| `crates/kernel/chio-kernel/src/kernel/admission_coordinator.rs`, `tool_outcome/post_return.rs` | Existing native original-operation and retained-return recovery owners |
| `crates/kernel/chio-kernel/src/evidence_export.rs`, `checkpoint.rs`; SQLite `evidence_export.rs` | Existing receipt export/verifier foundation, not a complete Mac evidence bundle |

Files under `chio-desktop` are proposed. M2 owns the scaffold, adapter and shared protocol models; import its actual symbols instead of inventing similarly named native APIs. Keep wire fields solely in the shared operator contract. Recovery projection types below are internal, not another wire schema.

### Task 1: Implement a truth-preserving internal projection

- [ ] Add this complete failing test to `tests/recovery_projection.rs` after M2 creates the crate:

```rust
use chio_desktop::recovery::projection::{project, Facts, Finality, Phase};

#[test]
fn worker_exit_does_not_close_unknown_effect() {
    let facts = Facts {
        admission_fenced: Some(true),
        worker_absent: Some(true),
        restrictions_converged: Some(true),
        finality: Finality::Unknown,
        output_released: Some(false),
        review_pending: false,
        unavailable: false,
    };
    let view = project(facts);
    assert_eq!(view.phase, Phase::BlockedUnknown);
    assert!(view.execution_stopped);
    assert!(view.external_outcome_unresolved);
}

#[test]
fn unconfirmed_stop_is_not_stopped() {
    let view = project(Facts {
        admission_fenced: None,
        worker_absent: Some(true),
        restrictions_converged: Some(true),
        finality: Finality::Closed,
        output_released: Some(false),
        review_pending: false,
        unavailable: false,
    });
    assert!(!view.execution_stopped);
    assert_eq!(view.phase, Phase::BlockedUnknown);
}
```

- [ ] Run `cargo test -p chio-desktop --test recovery_projection`. Expected red: module or types absent, after the scaffold itself builds.
- [ ] Create `src/recovery/projection.rs` with this complete pure projection and expose it with `pub mod projection;` from `src/recovery/mod.rs`. Add `pub mod recovery;` to M2's existing `src/lib.rs` without replacing other modules.

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finality { NoEffect, Closed, Unknown }

#[derive(Clone, Copy, Debug)]
pub struct Facts {
    pub admission_fenced: Option<bool>,
    pub worker_absent: Option<bool>,
    pub restrictions_converged: Option<bool>,
    pub finality: Finality,
    pub output_released: Option<bool>,
    pub review_pending: bool,
    pub unavailable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase { Unavailable, BlockedUnknown, Stopped, Completed, ReviewRequired, Running }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Projection {
    pub phase: Phase,
    pub execution_stopped: bool,
    pub external_outcome_unresolved: bool,
}

pub fn project(facts: Facts) -> Projection {
    let execution_stopped = facts.admission_fenced == Some(true)
        && facts.worker_absent == Some(true)
        && facts.restrictions_converged == Some(true);
    let external_outcome_unresolved = facts.finality == Finality::Unknown;
    let incomplete = facts.admission_fenced.is_none() || facts.worker_absent.is_none()
        || facts.restrictions_converged.is_none() || facts.output_released.is_none();
    let phase = if facts.unavailable {
        Phase::Unavailable
    } else if external_outcome_unresolved || incomplete {
        Phase::BlockedUnknown
    } else if execution_stopped {
        Phase::Stopped
    } else if facts.finality == Finality::Closed && facts.output_released == Some(true)
        && facts.worker_absent == Some(true) {
        Phase::Completed
    } else if facts.review_pending {
        Phase::ReviewRequired
    } else {
        Phase::Running
    };
    Projection { phase, execution_stopped, external_outcome_unresolved }
}
```

For profiles without a provider restriction component, its adapter supplies `Some(true)` only after checking that restriction is explicitly inapplicable in the qualified profile. `None` means unknown, not inapplicable. `Closed` means all applicable native outcomes accounted for; it cannot be set from exit status alone. Wire/UI mapping into the full shared task state is M2's projection adapter.

- [ ] Rerun the test green. Extend it to enumerate all `None/false/true` fact combinations and assert stopped requires all three exact facts; an unresolved effect always keeps its explicit unresolved field. Commit only recovery projection/module/tests with `feat: preserve independent Mac recovery facts`.

### Task 2: Bind retries to original native operations

- [ ] Add controller store tests in `tests/recovery_retry.rs` for the exact authenticated principal/method/intent retry scope: same principal, method, intent and canonical parameters return the retained original reference; the same key with different parameters conflicts; the same principal/intent used for two different mutating methods addresses two distinct native mappings; a request whose method differs from the selected cache key refuses before native adapter invocation. Also cover native commit plus lost response and a corrupt local row. Use M2's actual native-ref type, closed method enum and canonicalization code, not a second wire definition.
- [ ] Introduce this controller-only SQL in `src/recovery/retry_store.rs`, adapting M2's existing database transaction helper. This SQL stores correlation, not authority or native decisions:

```sql
CREATE TABLE desktop_retry_intents (
    owner_binding_digest TEXT NOT NULL,
    authenticated_principal_digest TEXT NOT NULL,
    method TEXT NOT NULL CHECK (method IN (
        'task.create', 'task.stop', 'approval.submit', 'evidence.export'
    )),
    client_intent_id TEXT NOT NULL,
    canonical_parameter_commitment TEXT NOT NULL,
    canonical_request_digest TEXT NOT NULL,
    native_operation_ref BLOB,
    transport_state TEXT NOT NULL CHECK (transport_state IN ('pending','bound','unknown')),
    PRIMARY KEY (owner_binding_digest, authenticated_principal_digest, method, client_intent_id)
);
```

Generate/check the SQL method allowlist against M2's closed mutating method catalog; adding a method requires an explicit schema/contract change. Derive the principal digest from authenticated native identity, and derive the method from the validated request enum. Neither comes from a caller-selected cache key. The cache owner binding includes native authority identity and generation but does not encode or replace method identity.

Use one transaction to insert if absent and read by the entire four-column primary key. Compare both canonical parameter commitment and canonical request digest before returning or updating a row. The parameter commitment is computed by M2's shared canonical parameter contract. The controller-only request digest is SHA-256 of the RFC 8785 canonical record with `domain` equal to `chio.desktop.retry-cache.v1` and fields `version`, `authenticated_principal_digest`, `method`, `intent_id` and `parameter_commitment` populated from that validated request and authenticated owner. It excludes transport request ID/session, so an equal retry after reconnect is stable. This local digest is a corruption/correlation check, never a native authority artifact or a replacement for the native owner's parameter commitment.

On cache read and response binding, check request method equals key method equals row method; recompute the complete request commitment and verify that the authenticated native result matches the original principal/method/intent/parameter tuple. Set `native_operation_ref` only from that verified result. Never return or rewrite a reference selected under another method or intent. A legacy cache row whose method/principal is missing cannot be migrated by guessing: retain it as untrusted diagnostic data and reconcile through authenticated native original lookup before caching a new complete row.
- [ ] Add these explicit table-driven cases to the Rust controller tests. The two native references in the cross-method case must be supplied by the native test adapter's separately verified mappings, not manufactured by the cache:

| Test case | Requests / selected cache key | Expected controller and native behavior |
| --- | --- | --- |
| `same_method_equal_retry_returns_original` | Principal A, `task.create`, intent I, parameters P, then the same tuple after reconnect | Same original native reference; one native operation/effect; changed transport request ID has no effect |
| `same_method_changed_parameters_conflicts` | Principal A, `task.create`, intent I, parameters P then Q | Conflict before repeated dispatch; original native mapping unchanged |
| `same_intent_different_methods_are_distinct` | Principal A, intent I first with `task.create`, then `task.stop`, each with valid method-specific parameters | Two method-scoped rows and distinct original native mappings; each equal retry returns its own result, with no create-result replay for stop |
| `method_substitution_for_selected_key_refuses` | Valid `task.stop` envelope paired with a cache lookup/result keyed as `task.create` for the same A/I | Refuse before native adapter invocation; zero reference returned or overwritten; neither tuple is reinterpreted |
| `principal_substitution_for_selected_key_refuses` | Principal B envelope paired with principal A's otherwise matching cache key | Refuse without disclosing A's native reference |
| `lost_reply_uses_original_method_lookup` | Native `approval.submit` for A/I/P commits; reply lost; same request retried | Lookup includes A, `approval.submit`, I and P commitment; one native approval consumption, never a new operation |

- [ ] Implement the reconciliation control flow in `reconcile.rs` using the exact native adapter delivered by M0/M2. Its exhaustive result table is the implementation contract:

| Native original lookup | Controller action | Mutation permission |
| --- | --- | --- |
| Verified existing operation for exact principal/method/intent/parameter tuple, terminal or pending | Bind original reference to the same complete cache key and refresh projection | Only native original reconciliation, if authorized |
| Verified absent principal/method/intent mapping in the original native namespace | Send the original method-specific request once through native idempotent begin | Native owner may create that mapping; lost reply returns to the same tuple lookup |
| Parameter commitment conflict or method/principal substitution | Retain local record, return conflict/refusal without exposing another tuple's reference | None |
| Unknown, expired lookup authority, disconnected or corrupt binding | Mark transport unknown and report native availability | None |
| Native owner generation changed | Re-authenticate, locate original under delivered recovery contract | Never regenerate operation identity from transport ID |

No new native function signature is assumed: the adapter acceptance record must identify how the installed owner provides authoritative original lookup and idempotent begin scoped to authenticated principal, closed method, stable intent and canonical parameter commitment. An owner-generation change may partition or invalidate this cache but cannot make the original native tuple absent or authorize allocation of a replacement. If that lookup contract is unavailable, this task delivers the refusal branch and leaves execution unavailable. A local absence check is not authoritative absence; distinct local rows do not allocate distinct native operations.
- [ ] Run `cargo test -p chio-desktop --test recovery_retry`. Expected red before storage/reconciliation, green after the five result branches are covered. Native integration control must drop the actual post-commit reply and verify one external effect using a resource counter outside the controller. Commit file-scoped changes with `feat: reconcile Mac retries through original native operations`.

### Task 3: Encode crash schedules and independent outcome oracles

- [ ] Create `qualification/fixtures/recovery-cuts.json` with concrete cases and expected observations:

```json
[
  {"case":"prepared-crash","cut":"before-dispatch-commit","expected":{"effects":0,"new_intents":0,"known_finality":true}},
  {"case":"dispatch-crash","cut":"after-dispatch-before-return","expected":{"effects_max":1,"new_intents":0,"allow_unknown":true}},
  {"case":"return-crash","cut":"after-return-before-outcome","expected":{"effects":1,"new_intents":0,"return_reused":true}},
  {"case":"receipt-projection-crash","cut":"after-terminal-before-receipt-append","expected":{"effects":1,"canonical_receipts":1}},
  {"case":"approval-reply-loss","cut":"after-consume-before-reply","expected":{"consumptions":1,"native_operations":1}},
  {"case":"stop-journal-crash","cut":"after-intent-fsync-before-stop-anchor","expected":{"new_effects_after_restart":0,"pending_intent_honored":true}},
  {"case":"stop-retire-crash","cut":"after-stop-anchor-before-intent-retire","expected":{"exact_satisfaction_checked":true,"stale_resume_refused":true}}
]
```

- [ ] Add a complete generic oracle helper and test before wiring the native driver. `recovery_cases.py` contains:

```python
def compare_observations(expected, observed):
    failures = []
    for key, value in expected.items():
        if key == "allow_unknown":
            if type(observed.get("unknown")) is not bool:
                failures.append("missing-unknown-status")
            elif observed["unknown"] is True and value is not True:
                failures.append("unexpected-unknown")
        elif key.endswith("_max"):
            actual = observed.get(key[:-4])
            if type(actual) is not int or actual < 0 or actual > value:
                failures.append(key)
        elif key not in observed or type(observed[key]) is not type(value) or observed[key] != value:
            failures.append(key)
    return failures
```

Create `test_recovery_cases.py` with this complete regression:

```python
import importlib.util
from pathlib import Path
import unittest

MODULE = Path(__file__).parents[1] / "qualification/recovery_cases.py"
spec = importlib.util.spec_from_file_location("recovery_cases", MODULE)
cases = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cases)

class RecoveryOracleTests(unittest.TestCase):
    def test_missing_or_wrong_observation_refuses(self):
        compare = cases.compare_observations
        self.assertEqual(compare({"effects_max": 1}, {"effects": 1}), [])
        self.assertEqual(compare({"effects": 0}, {}), ["effects"])
        self.assertEqual(compare({"effects_max": 1}, {"effects": 2}), ["effects_max"])
        self.assertEqual(compare({"effects": 1}, {"effects": True}), ["effects"])
        self.assertEqual(compare({"new_intents": 0}, {"new_intents": 1}), ["new_intents"])
        self.assertEqual(compare({"allow_unknown": True}, {}), ["missing-unknown-status"])

if __name__ == "__main__":
    unittest.main()
```

- [ ] Run `python3 -m unittest discover -s integrations/macos/tests -p test_recovery_cases.py -v` red before helper creation and green after. This tests comparison only; it cannot assert native failure injection occurred.
- [ ] Native owner extends its new M0 test target `macos_contract_prerequisites.rs` with `mac_recovery_` barrier cases; reuse actual claim/store and tool-outcome owners. On-disk tests kill a child process at each named native cut, reopen under a fresh serving fence and reconcile through the native machine. Read effect count from a separately running resource process. Every observation records producing component, native operation reference and artifact hash.
- [ ] Run `cargo test -p chio-kernel --test macos_contract_prerequisites mac_recovery_ -- --nocapture` and `cargo test -p chio-store-sqlite --lib recovery_claims_`. Expected all selected cases pass with nonzero count. Unknown without qualified finality passes only the explicit unknown oracle; it never becomes a failed-to-execute assertion. Commit fixture/harness and native owner tests separately by ownership.

### Task 4: Integrate durable stop and lifecycle revalidation

- [ ] Add native cases for two pending scopes, a narrowed containment intent, journal-full/write-failed, anchor-unknown, stale resume, rollover generation and crash after satisfaction/before retirement. Implement them in the NK-04 owner delivered at M0; exact native types remain there. Expected predicates are:

```text
durable_stop_ack => anchored_exact_stop_record
pending_intent(scope) => no_resume_or_relax(scope)
retire(intent) => matching_id_and_generation_in_anchored_ancestry
old_resume.expected_head != current_head => refuse_without_mutation
offline_helper_exited => reported_durability != process_only
```

- [ ] Wire controller stop reconciliation to native stop evidence and separate supervisor/provider observations. The M2 adapter maps typed native response facts without assigning durable status from IPC success. Add component tests that `process_only` cannot become durable when persisted in `desktop_retry_intents`, and that a stopped worker plus unknown publication retains the unresolved fact.
- [ ] Inject macOS lifecycle events through the existing M1/M2 platform adapter: sleep beyond capability expiry, wake with provider disconnected, logout/fast user switch, helper restart and host reboot. Each event blocks affected mutation until native binding/time/restriction readiness is refreshed. The lifecycle callback carries an observation and invokes reconciliation; it has no resume/approval authority.
- [ ] Run `cargo test -p chio-desktop --test recovery_projection`, `cargo test -p chio-desktop --test recovery_retry` and the delivered `mac_recovery_` native tests. On a selected installation, repeat stop-before-intent, intent-before-stop and release-after-stop with independent sink barriers. Expected ordering is native crossing order, not event timestamps. Commit `feat: reconcile Mac stop and lifecycle without implicit resume` using only changed owned paths.

### Task 5: Keep restore closed until independent freshness is proven

- [ ] Extend native M0 acceptance with four restore experiments: database-only rollback; database and local anchor rollback; whole-volume/VM snapshot replay; same-position chain fork. Use the current native test helpers in `serving_owner/tests.rs` for database cutpoints and a separate test environment for complete snapshot replay. Never restore the developer's working Mac.
- [ ] Require the selected native restore contract to produce these verified facts before any restored authority is ready:

```text
external_floor.authority == native_authority
external_floor.store == selected_store
local_ancestry.contains(external_floor.position, external_floor.digest)
all_pending_restrictions_recovered
new_restore_generation > prior_accepted_restore_generation
old_launch_handles_and_nonces_rejected
unresolved_original_operations_retained
```

The external floor must be outside the restored snapshot and authenticated under pinned trust. Its absent/unreachable/invalid result is unavailable, not a reason to trust local age or a numeric head alone. A local Keychain item or APFS volume name does not automatically meet the independent snapshot-domain requirement.
- [ ] Add controller restore tests that allow rebuilding labels/receipt views but refuse launch, approval consume and publication until the native restore contract succeeds. Restored guest disks enter only as data under a fresh launch; stale worker descriptors, credentials and operation namespaces must fail native generation checks. No controller-generated epoch satisfies this test.
- [ ] Run the delivered native `mac_recovery_restore_` cases in `macos_contract_prerequisites`, followed by `cargo test -p chio-desktop --test recovery_retry`. Expected: supported fresh restore passes exact native proof; every unsupported restore remains inspection-only with original unknown effects retained. Commit `test: refuse unsafe Mac authority restoration` under the native and controller owners separately.

### Task 6: Compose export without fabricating evidence

- [ ] Add `tests/evidence_export.rs` cases for another user's read boundary, omitted tenant, tampered native receipt, missing checkpoint coverage, wrong runtime tuple, gap ranges, retained unknown operation, and redaction of a signed original. Use native `EvidenceExportQuery::tenant_scoped` only when the authenticated owner supplies that tenant; never call `admin_all` because a field was absent.
- [ ] Implement `evidence/manifest.rs` as a composition of immutable native artifact files and separate host observations. Reuse the existing native `EvidenceExportBundle` and shared M8 evidence schema; do not redefine their signed body or wire fields. Required composition entries are:

```text
native: canonical receipts, original operation state, stop/closure chain,
        checkpoint/inclusion records, authority public trust roots
host: exact installed tuple, worker incarnation/absence, resource observation,
      ES/NE coverage and loss ranges, selected execution profile
limits: missing artifacts, retention omissions, uncheckpointed receipts,
        unresolved external finality, synthetic/component classifications
privacy: authenticated read boundary, separate redaction manifest,
         digest of each retained original and each redacted derivative
```

- [ ] Create `evidence_index.py` with this complete descriptor-relative file integrity helper. It checks package shape/content hashes only; native cryptographic and effect verifiers remain mandatory. The authenticated artifact owner supplies a held root-directory descriptor and its separately pinned `(st_dev, st_ino)` identity from trusted enrollment. Keep that descriptor alive for the whole validation; neither the bundle nor a newly resolved pathname chooses the identity. Reject unavailable no-follow/descriptor-relative primitives rather than weakening traversal.

The caller owns a private, immutable local artifact store with no untrusted writers, writable aliases, hard-link ingress or mount substitution. If this custody cannot be established, refuse verification. The helper duplicates the enrolled descriptor, opens every path component relative to a held descriptor without following symlinks, refuses other filesystems and non-regular leaves, and hashes the same bounded opened leaf. Renaming an already opened directory preserves its object identity; it does not enroll a replacement at the old pathname. Metadata rechecks detect ordinary mutation but do not prove a coherent snapshot of maliciously mutable files. Qualification must retain the artifact-store custody evidence separately. `read_verified_file` returns those exact verified bytes or `None`; M8 must parse the returned bytes, never verify then reopen a pathname. `verify_file` is only its Boolean convenience wrapper.

```python
import hashlib
import os
import stat
from contextlib import ExitStack

_REQUIRED_FLAGS = ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")
_SUPPORTED = (all(hasattr(os, flag) for flag in _REQUIRED_FLAGS)
              and os.open in os.supports_dir_fd)

def read_verified_file(root_fd, root_identity, relative, expected_digest, max_bytes):
    if (not _SUPPORTED or type(root_fd) is not int or root_fd < 0
            or type(max_bytes) is not int or max_bytes < 1
            or type(root_identity) is not tuple or len(root_identity) != 2
            or any(type(part) is not int or part < 0 for part in root_identity)
            or type(relative) is not str or "\0" in relative
            or type(expected_digest) is not str or len(expected_digest) != 64
            or any(char not in "0123456789abcdef" for char in expected_digest)):
        return None
    parts = relative.split("/")
    if len(parts) > 32 or any(part in ("", ".", "..") for part in parts):
        return None
    try:
        if len(relative.encode("utf-8")) > 4096:
            return None
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        with ExitStack() as opened:
            # Borrow caller-held custody; never reopen a root pathname.
            directory_fd = os.dup(root_fd)
            opened.callback(os.close, directory_fd)
            root_stat = os.fstat(directory_fd)
            if (not stat.S_ISDIR(root_stat.st_mode)
                    or (root_stat.st_dev, root_stat.st_ino) != root_identity):
                return None
            for part in parts[:-1]:
                directory_fd = os.open(part, flags | os.O_DIRECTORY,
                                       dir_fd=directory_fd)
                opened.callback(os.close, directory_fd)
                directory_stat = os.fstat(directory_fd)
                if (not stat.S_ISDIR(directory_stat.st_mode)
                        or directory_stat.st_dev != root_identity[0]):
                    return None
            artifact_fd = os.open(parts[-1], flags, dir_fd=directory_fd)
            opened.callback(os.close, artifact_fd)
            before = os.fstat(artifact_fd)
            if (not stat.S_ISREG(before.st_mode)
                    or before.st_dev != root_identity[0]
                    or before.st_size < 0 or before.st_size > max_bytes):
                return None
            hasher = hashlib.sha256()
            size = 0
            chunks = []
            while True:
                chunk = os.read(artifact_fd, min(65536, max_bytes - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    return None
                hasher.update(chunk)
                chunks.append(chunk)
            after = os.fstat(artifact_fd)
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if (size != before.st_size
                    or any(getattr(before, field) != getattr(after, field)
                           for field in fields)):
                return None
            if hasher.hexdigest() != expected_digest:
                return None
            return b"".join(chunks)
    except (OSError, ValueError, UnicodeError):
        return None

def verify_file(root_fd, root_identity, relative, expected_digest, max_bytes):
    return read_verified_file(root_fd, root_identity, relative,
                              expected_digest, max_bytes) is not None
```

- [ ] Create `test_evidence_index.py` with these complete regressions. The production `max_bytes` is the selected M8/privacy artifact bound; tests use 32 bytes. Inject actual final/directory swaps at open/read boundaries, retain an outside-file identity guard at the read syscall, substitute a FIFO with no writer, reject `/dev/null` before any read, and replace the root pathname while retaining its original descriptor. A separately opened replacement root must fail even if its regular-file bytes match.

```python
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).parents[1] / "qualification/evidence_index.py"
spec = importlib.util.spec_from_file_location("evidence_index", MODULE)
index = importlib.util.module_from_spec(spec)
spec.loader.exec_module(index)

def identity(fd):
    value = os.fstat(fd)
    return value.st_dev, value.st_ino

class EvidenceIndexTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "root"
        self.root.mkdir()
        self.content = b"native-original"
        self.digest = hashlib.sha256(self.content).hexdigest()
        self.original = self.root / "receipt.json"
        self.original.write_bytes(self.content)
        self.outside = self.base / "outside"
        self.outside.mkdir()
        self.canary = self.outside / "receipt.json"
        self.canary.write_bytes(b"outside-canary-secret")
        canary_stat = self.canary.stat()
        self.canary_identity = canary_stat.st_dev, canary_stat.st_ino
        self.root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY
                               | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.addCleanup(os.close, self.root_fd)
        self.root_identity = identity(self.root_fd)
        self.read_bytes = 0
        actual_read = os.read
        def guarded_read(fd, count):
            self.assertNotEqual(identity(fd), self.canary_identity,
                                "outside canary reached the read syscall")
            result = actual_read(fd, count)
            self.read_bytes += len(result)
            return result
        guard = patch.object(index.os, "read", side_effect=guarded_read)
        guard.start()
        self.addCleanup(guard.stop)

    def verify(self, relative="receipt.json", digest=None):
        return index.verify_file(self.root_fd, self.root_identity, relative,
                                 self.digest if digest is None else digest, 32)

    def test_original_tamper_path_and_bound(self):
        self.assertTrue(self.verify())
        self.assertEqual(index.read_verified_file(self.root_fd, self.root_identity,
                         "receipt.json", self.digest, 32), self.content)
        (self.root / "empty.json").write_bytes(b"")
        self.assertEqual(index.read_verified_file(self.root_fd, self.root_identity,
                         "empty.json", hashlib.sha256(b"").hexdigest(), 32), b"")
        (self.root / "nested").mkdir()
        (self.root / "nested/receipt.json").write_bytes(self.content)
        self.assertTrue(self.verify("nested/receipt.json"))
        for relative in ("", "/receipt.json", "../outside/receipt.json",
                         "nested/../receipt.json", "nested//receipt.json",
                         "./receipt.json", "receipt.json\0"):
            self.assertFalse(self.verify(relative))
        self.original.write_bytes(b"changed")
        self.assertFalse(self.verify())
        self.original.write_bytes(b"x" * 33)
        self.read_bytes = 0
        self.assertFalse(self.verify(digest=hashlib.sha256(b"x" * 33).hexdigest()))
        self.assertEqual(self.read_bytes, 0)
        self.assertFalse(index.verify_file(self.root_fd, self.root_identity,
                                          "receipt.json", self.digest, True))

    def test_final_component_swap_before_open_refuses_without_canary_read(self):
        actual_open = os.open
        def racing_open(name, flags, *args, **kwargs):
            if name == "receipt.json":
                self.original.unlink()
                self.original.symlink_to(self.canary)
            return actual_open(name, flags, *args, **kwargs)
        with patch.object(index.os, "open", side_effect=racing_open):
            self.assertFalse(self.verify())
        self.assertEqual(self.read_bytes, 0)

    def test_directory_swap_before_open_refuses_without_canary_read(self):
        nested = self.root / "nested"
        nested.mkdir()
        (nested / "receipt.json").write_bytes(self.content)
        actual_open = os.open
        def racing_open(name, flags, *args, **kwargs):
            if name == "nested":
                nested.rename(self.root / "retained")
                nested.symlink_to(self.outside, target_is_directory=True)
            return actual_open(name, flags, *args, **kwargs)
        with patch.object(index.os, "open", side_effect=racing_open):
            self.assertFalse(self.verify("nested/receipt.json"))
        self.assertEqual(self.read_bytes, 0)

    def test_directory_swap_after_open_retains_pinned_directory(self):
        nested = self.root / "nested"
        nested.mkdir()
        (nested / "receipt.json").write_bytes(self.content)
        actual_open = os.open
        def racing_open(name, flags, *args, **kwargs):
            fd = actual_open(name, flags, *args, **kwargs)
            if name == "nested":
                nested.rename(self.root / "retained")
                nested.symlink_to(self.outside, target_is_directory=True)
            return fd
        with patch.object(index.os, "open", side_effect=racing_open):
            self.assertTrue(self.verify("nested/receipt.json"))
        self.assertEqual(self.read_bytes, len(self.content))

    def test_final_swap_after_open_never_reopens_path(self):
        guarded_read = index.os.read
        swapped = False
        def racing_read(fd, count):
            nonlocal swapped
            if not swapped:
                swapped = True
                self.original.unlink()
                self.original.symlink_to(self.canary)
            return guarded_read(fd, count)
        canary_digest = hashlib.sha256(b"outside-canary-secret").hexdigest()
        with patch.object(index.os, "read", side_effect=racing_read):
            self.assertFalse(self.verify(digest=canary_digest))
        self.assertTrue(swapped)
        self.assertEqual(self.read_bytes, len(self.content))

    def test_fifo_swap_before_open_never_blocks_or_reads(self):
        actual_open = os.open
        def racing_open(name, flags, *args, **kwargs):
            if name == "receipt.json":
                self.original.unlink()
                os.mkfifo(self.original)
            return actual_open(name, flags, *args, **kwargs)
        with patch.object(index.os, "open", side_effect=racing_open):
            self.assertFalse(self.verify())
        self.assertEqual(self.read_bytes, 0)

    def test_device_refuses_before_read(self):
        fd = os.open("/dev", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            with patch.object(index.os, "read",
                              side_effect=AssertionError("device was read")):
                self.assertFalse(index.verify_file(fd, identity(fd), "null",
                                                  hashlib.sha256(b"").hexdigest(), 32))
        finally:
            os.close(fd)

    def test_root_path_swap_cannot_change_authenticated_descriptor(self):
        self.root.rename(self.base / "retained-root")
        self.root.mkdir()
        (self.root / "receipt.json").symlink_to(self.canary)
        self.assertTrue(self.verify())
        (self.root / "receipt.json").unlink()
        (self.root / "receipt.json").write_bytes(self.content)
        replacement = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            self.assertFalse(index.verify_file(replacement, self.root_identity,
                                              "receipt.json", self.digest, 32))
        finally:
            os.close(replacement)
        self.assertEqual(self.read_bytes, len(self.content))

    def test_growth_during_read_is_bounded(self):
        guarded_read = index.os.read
        changed = False
        def racing_read(fd, count):
            nonlocal changed
            if not changed:
                changed = True
                with self.original.open("ab") as writer:
                    writer.write(b"x" * 64)
            return guarded_read(fd, count)
        with patch.object(index.os, "read", side_effect=racing_read):
            self.assertFalse(self.verify())
        self.assertEqual(self.read_bytes, 33)

if __name__ == "__main__":
    unittest.main()
```

- [ ] Run the following supervised command red before helper creation then green after creation. Expected: all nine tests run, exact retained bytes accept within the bound, outside-canary reads never occur, and tamper/escape/symlink/oversize/FIFO/device/root-substitution inputs refuse. The supervising process requires exactly nine tests with no skips, kills a hung FIFO case after 10 seconds and exits unsuccessfully; empty discovery or a hang cannot count as a completed test.

```bash
python3 - <<'PY'
import subprocess
import sys
runner = """import unittest
suite = unittest.defaultTestLoader.discover(
    "integrations/macos/tests", pattern="test_evidence_index.py")
if suite.countTestCases() != 9:
    raise SystemExit("expected exactly nine evidence-index regressions")
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() and not result.skipped else 1)
"""
result = subprocess.run([sys.executable, "-c", runner], timeout=10, check=False)
raise SystemExit(result.returncode)
PY
```

- [ ] Prove the race controls are meaningful in disposable copies: remove `O_NOFOLLOW` only from the helper's open flags and require a failing outside-canary read assertion; remove `O_NONBLOCK` and require the supervised FIFO case to time out unsuccessfully; remove the root identity comparison and require the byte-identical replacement-root case to fail; remove the leaf regular-file predicate and require the device-read assertion to fail. Restore the helper and rerun green. These are component regressions, not native receipt/effect verification. The descriptor APIs and flag behavior are documented by [Python `os.open`](https://docs.python.org/3/library/os.html#os.open) and [Apple `open(2)`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/open.2.html).
- [ ] Run the actual native receipt/checkpoint verifier selected in M0 on exported originals, and the independent resource-finality verifier for external effects. The invocation and executable hash come from the delivered native manifest; if no verifier exists for a required claim, export it as unverified and keep qualification open. A schema-valid manifest never substitutes.
- [ ] Run `cargo test -p chio-desktop --test evidence_export`. Expected: own-scope exports preserve signed bytes, named missing evidence and unresolved effects; tampered/foreign-scope inputs fail. Commit only export implementation/tests with `feat: preserve native evidence and explicit Mac observation gaps`.

### Task 7: Saturation, retention and installed closure

- [ ] Configure test quotas below the selected production bounds so a small fixture reaches ordinary capacity, reserved recovery capacity and actual filesystem ENOSPC. Add fault injection for failed fsync and bounded event-queue overflow. Observe new admission refusal, actual stop durability and missing sensor ranges independently; do not infer a successful durable stop from a UI button.
- [ ] Rebase event transport while an end acknowledgement is pending. Use M2's stable subscription identity and native session-record owner; attempt stale candidate publication and wrong-session acknowledgement. Expected: no resurrected marker and no sensor gap erased by transport reconnection.
- [ ] On the exact installed selected profile, run the full recovery-cuts fixture plus lifecycle, restore, privacy/export and saturation cases. The qualification driver records command, artifacts, case count, observed cutpoint and runtime tuple. Required cases cannot be skipped; source/component/installed-runtime evidence remain separate until M8 verification.
- [ ] Run `python3 -m unittest discover -s integrations/macos/tests -p 'test_*recovery*.py' -v`, the evidence-index test, all three controller test targets, relevant native acceptance target, `cargo fmt --all -- --check` and `git diff --check`. Expected all applicable checks pass with no fabricated closure; any native/environment gate remains explicitly unavailable.
- [ ] Hand M3/M4/M5/M7 a verified recovery compatibility reference, original-operation/stop adapter contract, evidence export verifier references and the exact accepted scope. A successful M6 brokered profile does not qualify VM, native descendant or managed endpoint behavior; their independent worker/provider evidence still must pass.

## Coverage and exit

Task 1 covers fact projection; Task 2 original intent/replay; Task 3 native crash classification and canonical projection repair; Task 4 durable stop and lifecycle; Task 5 restore/upgrade generation safety; Task 6 evidence, independent verification and privacy; Task 7 event gaps and exhaustion. Together they cover AT-MAC-REC-001 through AT-MAC-REC-016. Kernel crossing, exact endorsement, budget and custody claims retain their M0 native gates. The delivered package states which profile and restore mode were actually exercised; M8 release acceptance is separate.

use std::{
    cell::Cell,
    sync::{Arc, Barrier},
};

use chio_kernel::{admission_operation::AdmissionIdentifier, GovernedApprovalReplayStore};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

thread_local! { static FAIL_AFTER: Cell<u8> = const { Cell::new(0) }; }

pub(super) fn seal_cutpoint(stage: u8) -> Result<(), Error> {
    if FAIL_AFTER.get() == stage {
        return Err(invalid("injected seal cutpoint"));
    }
    Ok(())
}

struct ResetCutpoint;
impl Drop for ResetCutpoint {
    fn drop(&mut self) {
        FAIL_AFTER.set(0);
    }
}

fn binding() -> Result<
    GovernedApprovalReplaySourceBinding,
    chio_kernel::admission_operation::AdmissionOperationError,
> {
    Ok(GovernedApprovalReplaySourceBinding {
        source_id: AdmissionIdentifier::try_new("source", "approval-replay-source")?,
        approval_authority_id: AdmissionIdentifier::try_new("authority", "governed-authority")?,
        destination_authority_id: AdmissionIdentifier::try_new(
            "destination",
            "operation-authority",
        )?,
    })
}

fn reserve(
    store: &SqliteGovernedApprovalReplayStore,
    request: &str,
) -> Result<bool, chio_kernel::KernelError> {
    store.reserve_for_dispatch(
        "subject",
        request,
        "intent",
        u64::try_from(super::super::now_secs()).unwrap_or(0) + 3600,
        "private-owner",
    )
}

fn read_value(
    snapshot: &GovernedApprovalReplaySourceSnapshot,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&snapshot.canonical_bytes()?)?)
}

#[test]
fn seals_complete_inventory_and_reopens_without_pruning_or_reconfiguration() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("approval.db");
    let store = SqliteGovernedApprovalReplayStore::open_with_capacity(&path, 8)?;
    assert!(reserve(&store, "reserved")?);
    assert!(reserve(&store, "committed")?);
    assert!(store.commit_dispatch_reservation(
        "subject",
        "committed",
        "intent",
        "private-owner"
    )?);
    let legacy = Connection::open(&path)?;
    // Sealing inventories physical rows without pruning or rewriting them.
    legacy.execute("INSERT INTO chio_governed_approval_replay_entries VALUES (?1, 'unscoped', 'intent', 1, 'historical-owner')",
        params![super::super::LEGACY_UNSCOPED_SUBJECT_ID])?;
    let expected = store.preview_legacy_replay_source(&binding()?)?;
    assert_eq!(expected.marker_count(), 3);
    assert_eq!(
        GovernedApprovalReplaySourceSnapshot::from_canonical_bytes(&expected.canonical_bytes()?)?,
        expected
    );
    let value = read_value(&expected)?;
    let inventory = &value["body"]["inventory"];
    assert_eq!(inventory["capacity"], "8");
    assert_eq!(
        inventory["markers"][0]["subject_id"],
        super::super::LEGACY_UNSCOPED_SUBJECT_ID
    );
    assert_eq!(inventory["markers"][0]["expires_at"], "1");
    assert!(inventory["markers"][1]["dispatch_reservation_id"].is_null());
    assert_eq!(
        inventory["markers"][2]["dispatch_reservation_id"],
        "private-owner"
    );
    let seal = store.seal_expected_legacy_replay_source(&expected)?;
    assert_eq!(seal.snapshot(), &expected);
    assert_eq!(store.seal_expected_legacy_replay_source(&expected)?, seal);
    assert!(!format!("{seal:?}").contains("private-owner"));
    assert!(!format!("{seal:?}").contains("historical-owner"));
    drop(store);
    // Sealed sources ignore requested capacity; they cannot resume service.
    let reopened = SqliteGovernedApprovalReplayStore::open_with_capacity(&path, 1)?;
    assert_eq!(
        reopened.load_legacy_replay_source_seal(&binding()?)?,
        Some(seal)
    );
    reopened.verify_legacy_replay_source_seal(&expected)?;
    assert!(reserve(&reopened, "new").is_err());
    Ok(())
}

#[test]
fn old_connections_and_typed_noops_cannot_mutate_a_sealed_source() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("approval.db");
    let store = SqliteGovernedApprovalReplayStore::open(&path)?;
    let old = SqliteGovernedApprovalReplayStore::open(&path)?;
    let connection = Connection::open(&path)?;
    assert!(reserve(&store, "reserved")?);
    let expected = store.preview_legacy_replay_source(&binding()?)?;
    store.seal_expected_legacy_replay_source(&expected)?;
    for store in [&store, &old] {
        assert!(reserve(store, "new").is_err());
        assert!(store
            .reserve_for_dispatch("subject", "expired", "intent", 1, "owner")
            .is_err());
        for request in ["reserved", "missing"] {
            assert!(store
                .commit_dispatch_reservation("subject", request, "intent", "private-owner")
                .is_err());
            assert!(store
                .rollback_dispatch_reservation("subject", request, "intent", "private-owner")
                .is_err());
        }
    }
    for table in ["entries", "clock", "limits", "source_seal"] {
        let table = format!("chio_governed_approval_replay_{table}");
        assert!(connection
            .execute(&format!("DELETE FROM {table}"), [])
            .is_err());
        assert!(connection
            .execute(
                &format!("INSERT OR REPLACE INTO {table} SELECT * FROM {table}"),
                []
            )
            .is_err());
    }
    for sql in [
        "UPDATE chio_governed_approval_replay_entries SET dispatch_reservation_id = NULL",
        "UPDATE chio_governed_approval_replay_clock SET wall_clock_high_water = wall_clock_high_water + 1",
        "UPDATE chio_governed_approval_replay_limits SET capacity = capacity + 1",
        "UPDATE chio_governed_approval_replay_source_seal SET canonical_bytes = canonical_bytes",
    ] { assert!(connection.execute(sql, []).is_err(), "{sql}"); }
    let now = super::super::now_secs();
    let recovery = SqliteGovernedApprovalReplayStore::recover_clock_high_water(&path, now + 1, now);
    assert!(recovery
        .err()
        .is_some_and(|error| error.to_string().contains("sealed")));
    store.verify_legacy_replay_source_seal(&expected)?;
    Ok(())
}

#[test]
fn changed_candidate_remains_unsealed_and_exact_binding_is_required() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("approval.db");
    let store = SqliteGovernedApprovalReplayStore::open(&path)?;
    let stale = store.preview_legacy_replay_source(&binding()?)?;
    assert!(reserve(&store, "new")?);
    assert!(store.seal_expected_legacy_replay_source(&stale).is_err());
    assert!(store.load_legacy_replay_source_seal(&binding()?)?.is_none());
    let expected = store.preview_legacy_replay_source(&binding()?)?;
    store.seal_expected_legacy_replay_source(&expected)?;
    let mut wrong_binding = binding()?;
    wrong_binding.destination_authority_id =
        AdmissionIdentifier::try_new("destination", "other-authority")?;
    assert!(store
        .load_legacy_replay_source_seal(&wrong_binding)
        .is_err());
    assert!(store.preview_legacy_replay_source(&wrong_binding).is_err());
    assert!(store.seal_expected_legacy_replay_source(&stale).is_err());
    Ok(())
}

#[test]
fn sql_cutpoints_roll_back_all_evidence_and_allow_exact_retry() -> TestResult {
    let _reset = ResetCutpoint;
    for stage in 1..=4 {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("approval.db");
        let store = SqliteGovernedApprovalReplayStore::open(&path)?;
        assert!(reserve(&store, "reserved")?);
        let expected = store.preview_legacy_replay_source(&binding()?)?;
        FAIL_AFTER.set(stage);
        let result = store.seal_expected_legacy_replay_source(&expected);
        FAIL_AFTER.set(0);
        assert!(result
            .err()
            .is_some_and(|error| error.to_string().contains("injected seal cutpoint")));
        assert!(store.load_legacy_replay_source_seal(&binding()?)?.is_none());
        assert!(!schema::has_evidence(&Connection::open(&path)?)?);
        assert_eq!(store.preview_legacy_replay_source(&binding()?)?, expected);
        store.seal_expected_legacy_replay_source(&expected)?;
        store.verify_legacy_replay_source_seal(&expected)?;
    }
    Ok(())
}

#[test]
fn lost_seal_acknowledgement_is_resolved_by_reopen_and_exact_readback() -> TestResult {
    let _reset = ResetCutpoint;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("approval.db");
    let store = SqliteGovernedApprovalReplayStore::open(&path)?;
    assert!(reserve(&store, "reserved")?);
    let expected = store.preview_legacy_replay_source(&binding()?)?;
    FAIL_AFTER.set(5);
    let result = store.seal_expected_legacy_replay_source(&expected);
    FAIL_AFTER.set(0);
    assert!(result
        .err()
        .is_some_and(|error| error.to_string().contains("injected seal cutpoint")));
    assert!(reserve(&store, "new").is_err());
    drop(store);
    let reopened = SqliteGovernedApprovalReplayStore::open(&path)?;
    reopened.verify_legacy_replay_source_seal(&expected)?;
    assert_eq!(
        reopened
            .seal_expected_legacy_replay_source(&expected)?
            .snapshot(),
        &expected
    );
    Ok(())
}

#[test]
fn racing_legacy_reservation_and_seal_have_one_serialized_outcome() -> TestResult {
    for _ in 0..8 {
        let directory = tempfile::tempdir()?;
        let store = SqliteGovernedApprovalReplayStore::open(directory.path().join("approval.db"))?;
        let expected = store.preview_legacy_replay_source(&binding()?)?;
        let barrier = Arc::new(Barrier::new(2));
        std::thread::scope(|scope| -> TestResult {
            let reserve_barrier = Arc::clone(&barrier);
            let store_ref = &store;
            let writer = scope.spawn(move || {
                reserve_barrier.wait();
                reserve(store_ref, "racer")
            });
            barrier.wait();
            let sealed = store.seal_expected_legacy_replay_source(&expected);
            let reserved = writer.join().map_err(|_| "reservation thread panicked")?;
            match (sealed, reserved) {
                (Ok(_), Err(_)) => store.verify_legacy_replay_source_seal(&expected)?,
                (Err(_), Ok(true)) => {
                    assert!(store.load_legacy_replay_source_seal(&binding()?)?.is_none());
                    assert_eq!(
                        store
                            .preview_legacy_replay_source(&binding()?)?
                            .marker_count(),
                        1
                    );
                }
                _ => return Err("seal and reservation were not serialized".into()),
            }
            Ok(())
        })?;
    }
    Ok(())
}

#[path = "tests/bounds.rs"]
mod bounds;
#[path = "tests/tamper.rs"]
mod tamper;

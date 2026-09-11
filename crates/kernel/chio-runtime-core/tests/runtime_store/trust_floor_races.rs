use std::sync::Barrier;

use chio_runtime_core::{
    ChioRuntimeError, InMemoryRuntimeAdmissionStore, JsonRuntimeAdmissionStore,
    JsonRuntimeTrustFloorStateStore, RuntimeTrustFloorEntry, RuntimeTrustFloorStore,
    SqliteRuntimeOrchestrationStore,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CONTENDERS: usize = 4;
const ROUNDS: u64 = 8;

fn assert_rejected(result: Result<(), ChioRuntimeError>, expected: &str) {
    match result {
        Err(ChioRuntimeError::Rejected { code, .. }) => assert_eq!(code, expected),
        other => panic!("expected {expected}, got {other:?}"),
    }
}

fn assert_round(
    stores: &[&dyn RuntimeTrustFloorStore],
    round: u64,
) -> TestResult<RuntimeTrustFloorEntry> {
    assert_eq!(stores.len(), CONTENDERS);
    let first = stores.first().ok_or("missing race store")?;
    let seed = RuntimeTrustFloorEntry {
        verifier_id: format!("verifier-trust-floor-race-{round}"),
        key_id: "key-trust-floor-race".to_owned(),
        highest_version: 1,
        latest_bundle_sha256: "1".repeat(64),
        latest_revocation_checkpoint_sha256: "2".repeat(64),
    };
    RuntimeTrustFloorStore::validate_and_record_runtime_trust_floor(*first, seed.clone(), None)?;

    let start = Barrier::new(stores.len() + 1);
    let outcomes = std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for (index, store) in stores.iter().copied().enumerate() {
            let start = &start;
            let previous_hash = seed.latest_bundle_sha256.clone();
            let mut candidate = seed.clone();
            candidate.highest_version = 2;
            candidate.latest_bundle_sha256 = format!("{:064x}", 0x100 + index);
            candidate.latest_revocation_checkpoint_sha256 = format!("{:064x}", 0x200 + index);
            workers.push(scope.spawn(move || {
                start.wait();
                let result = RuntimeTrustFloorStore::validate_and_record_runtime_trust_floor(
                    store,
                    candidate.clone(),
                    Some(&previous_hash),
                );
                (candidate, result)
            }));
        }
        start.wait();
        workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .map_err(|_| std::io::Error::other("trust-floor race worker panicked"))
            })
            .collect::<Result<Vec<_>, _>>()
    })?;

    let mut winner = None;
    for (candidate, result) in outcomes {
        match result {
            Ok(()) => assert!(
                winner.replace(candidate).is_none(),
                "multiple conflicting version-two transitions won round {round}"
            ),
            failure => assert_rejected(failure, "runtime_trust_same_version_mismatch"),
        }
    }
    let winner = winner.ok_or("no trust-floor transition won")?;
    for store in stores.iter().copied() {
        assert_eq!(
            RuntimeTrustFloorStore::runtime_trust_floor(store, &seed.verifier_id, &seed.key_id)?,
            Some(winner.clone()),
            "a racing handle did not observe the exact acknowledged winner"
        );
        RuntimeTrustFloorStore::validate_and_record_runtime_trust_floor(
            store,
            winner.clone(),
            Some(&seed.latest_bundle_sha256),
        )?;
        assert_rejected(
            RuntimeTrustFloorStore::validate_and_record_runtime_trust_floor(
                store,
                seed.clone(),
                None,
            ),
            "runtime_trust_rollback",
        );
        let mut wrong_previous = winner.clone();
        wrong_previous.highest_version = 3;
        wrong_previous.latest_bundle_sha256 = "f".repeat(64);
        assert_rejected(
            RuntimeTrustFloorStore::validate_and_record_runtime_trust_floor(
                store,
                wrong_previous,
                Some(&seed.latest_bundle_sha256),
            ),
            "runtime_trust_previous_hash_mismatch",
        );
        assert_eq!(
            RuntimeTrustFloorStore::runtime_trust_floor(store, &seed.verifier_id, &seed.key_id)?,
            Some(winner.clone()),
            "idempotent retry or rejected transitions changed the committed floor"
        );
    }
    Ok(winner)
}

fn assert_rounds(
    stores: &[&dyn RuntimeTrustFloorStore],
) -> TestResult<Vec<RuntimeTrustFloorEntry>> {
    (0..ROUNDS)
        .map(|round| assert_round(stores, round))
        .collect()
}

fn assert_persisted_winners(
    store: &dyn RuntimeTrustFloorStore,
    winners: &[RuntimeTrustFloorEntry],
) -> TestResult {
    for winner in winners {
        assert_eq!(
            RuntimeTrustFloorStore::runtime_trust_floor(
                store,
                &winner.verifier_id,
                &winner.key_id
            )?,
            Some(winner.clone())
        );
    }
    Ok(())
}

#[test]
fn memory_clones_linearize_conflicting_trust_floor_transitions() -> TestResult {
    let shared = InMemoryRuntimeAdmissionStore::new();
    let handles: Vec<_> = (0..CONTENDERS).map(|_| shared.clone()).collect();
    let stores: Vec<&dyn RuntimeTrustFloorStore> = handles
        .iter()
        .map(|store| store as &dyn RuntimeTrustFloorStore)
        .collect();
    assert_rounds(&stores)?;
    Ok(())
}

#[test]
fn shared_json_admission_store_linearizes_conflicting_trust_floor_transitions() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("shared-runtime-admission.json");
    let shared = JsonRuntimeAdmissionStore::open(&path)?;
    // Sharing one opened JSON state coordinates its writers. Separately opened
    // JSON handles do not share that mutex.
    let stores = vec![&shared as &dyn RuntimeTrustFloorStore; CONTENDERS];
    let winners = assert_rounds(&stores)?;
    assert_persisted_winners(&JsonRuntimeAdmissionStore::open(&path)?, &winners)
}

#[test]
fn shared_json_floor_store_linearizes_conflicting_trust_floor_transitions() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("shared-runtime-trust-floor.json");
    let shared = JsonRuntimeTrustFloorStateStore::open(&path)?;
    let stores = vec![&shared as &dyn RuntimeTrustFloorStore; CONTENDERS];
    let winners = assert_rounds(&stores)?;
    assert_persisted_winners(&JsonRuntimeTrustFloorStateStore::open(&path)?, &winners)
}

#[test]
fn independent_sqlite_handles_linearize_conflicting_trust_floor_transitions() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory
        .path()
        .join("independent-runtime-trust-floor.sqlite3");
    let handles = (0..CONTENDERS)
        .map(|_| SqliteRuntimeOrchestrationStore::open(&path))
        .collect::<Result<Vec<_>, _>>()?;
    let stores: Vec<&dyn RuntimeTrustFloorStore> = handles
        .iter()
        .map(|store| store as &dyn RuntimeTrustFloorStore)
        .collect();
    let winners = assert_rounds(&stores)?;
    assert_persisted_winners(&SqliteRuntimeOrchestrationStore::open(&path)?, &winners)
}

use chio_federation::verifier_ledger::oid4vp_requests::{
    Oid4vpRequestHash, Oid4vpRequestId, Oid4vpRequestLedger, Oid4vpRequestRecord,
};
use chio_federation::verifier_ledger::presentation_challenges::{
    ChallengeHash, ChallengeTransition, PresentationChallengeId, PresentationChallengeLedger,
    PresentationChallengeRecord, PresentationHash,
};
use chio_test_support::prelude::*;
use tempfile::TempDir;

use super::*;

const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct Fixture {
    _temp: TempDir,
    store: SqlitePassportVerifierStore,
    _clock: chio_test_support::clock::ClockScope,
}

fn fixture() -> Fixture {
    let clock = chio_test_support::clock::scope_unix_secs(1_710_000_000);
    let temp = tempfile::tempdir().test_unwrap();
    let path = temp.path().join("verifier.sqlite3");
    let store = SqlitePassportVerifierStore::open(&path).test_unwrap();
    Fixture {
        _temp: temp,
        store,
        _clock: clock,
    }
}

fn challenge_id(id: &str) -> PresentationChallengeId {
    PresentationChallengeId::parse(id).test_unwrap()
}

fn request_id(id: &str) -> Oid4vpRequestId {
    Oid4vpRequestId::parse(id).test_unwrap()
}

fn challenge_entry(id: &str) -> PresentationChallengeRecord {
    PresentationChallengeRecord {
        challenge_id: challenge_id(id),
        challenge_hash: ChallengeHash::parse(HASH_A).test_unwrap(),
        challenge_json: "{}".to_owned(),
        issued_at: 100,
        expires_at: 400,
    }
}

fn request_entry(id: &str) -> Oid4vpRequestRecord {
    Oid4vpRequestRecord {
        request_id: request_id(id),
        request_hash: Oid4vpRequestHash::parse(HASH_B).test_unwrap(),
        request_json: "{}".to_owned(),
        request_jwt: "request.jwt".to_owned(),
        issued_at: 100,
        expires_at: 400,
    }
}

#[test]
fn incoherent_status_rows_are_refused() {
    let fixture = fixture();
    let store = &fixture.store;
    let challenge = challenge_id("challenge-1");
    PresentationChallengeLedger::insert(store, &challenge_entry("challenge-1")).test_unwrap();
    let presented = PresentationHash::parse(HASH_B).test_unwrap();
    assert!(PresentationChallengeLedger::consume(
        store,
        &challenge,
        ChallengeTransition::Verify,
        150,
        &presented
    )
    .test_unwrap());
    let request = request_id("request-1");
    Oid4vpRequestLedger::insert(store, &request_entry("request-1")).test_unwrap();
    assert!(Oid4vpRequestLedger::consume(store, &request, 150).test_unwrap());
    for (sql, id) in [
        (
            "UPDATE passport_verifier_challenges SET presentation_hash = NULL WHERE challenge_id = ?1",
            challenge.as_str(),
        ),
        (
            "UPDATE passport_oid4vp_transactions SET consumed_at = NULL WHERE request_id = ?1",
            request.as_str(),
        ),
    ] {
        let incoherent = store.transact(|transaction| Ok(transaction.execute(sql, [id])?));
        assert!(matches!(incoherent, Err(PassportVerifierStoreError::Sqlite(_))));
    }
}

#[test]
fn duplicate_and_out_of_range_rows_are_refused() {
    let fixture = fixture();
    let store = &fixture.store;
    PresentationChallengeLedger::insert(store, &challenge_entry("challenge-1")).test_unwrap();
    assert_eq!(
        PresentationChallengeLedger::insert(store, &challenge_entry("challenge-1")),
        Err(LedgerFault::Duplicate)
    );
    Oid4vpRequestLedger::insert(store, &request_entry("request-1")).test_unwrap();
    assert_eq!(
        Oid4vpRequestLedger::insert(store, &request_entry("request-1")),
        Err(LedgerFault::Duplicate)
    );
    let mut far = challenge_entry("challenge-far");
    far.expires_at = u64::MAX;
    assert_eq!(
        PresentationChallengeLedger::insert(store, &far),
        Err(LedgerFault::Unrepresentable)
    );
}

#[test]
fn store_errors_reach_the_port_as_closed_faults() {
    let corrupt = rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CORRUPT),
        None,
    );
    let not_a_database = rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_NOTADB),
        None,
    );
    let busy =
        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY), None);
    for (error, fault) in [
        (
            PassportVerifierStoreError::Duplicate("challenge-1".into()),
            LedgerFault::Duplicate,
        ),
        (
            PassportVerifierStoreError::InvalidRow,
            LedgerFault::IntegrityFailure,
        ),
        (
            PassportVerifierStoreError::InvalidField(LedgerFieldError::Digest("request_hash")),
            LedgerFault::IntegrityFailure,
        ),
        (
            PassportVerifierStoreError::Sqlite(corrupt),
            LedgerFault::IntegrityFailure,
        ),
        (
            PassportVerifierStoreError::Sqlite(not_a_database),
            LedgerFault::IntegrityFailure,
        ),
        (
            PassportVerifierStoreError::Sqlite(busy),
            LedgerFault::Unavailable,
        ),
        (
            PassportVerifierStoreError::Unavailable("fenced".into()),
            LedgerFault::Unavailable,
        ),
        (
            PassportVerifierStoreError::Io(std::io::Error::from(std::io::ErrorKind::Other)),
            LedgerFault::Unavailable,
        ),
    ] {
        assert_eq!(ledger_fault(error), fault);
    }
}

#[test]
fn foreign_and_in_memory_databases_are_refused() {
    for path in [":memory:", "file:verifier?mode=memory", ""] {
        assert!(matches!(
            SqlitePassportVerifierStore::open(path),
            Err(PassportVerifierStoreError::InvalidPath)
        ));
    }
    let temp = tempfile::tempdir().test_unwrap();
    let path = temp.path().join("unstamped.sqlite3");
    Connection::open(&path)
        .test_unwrap()
        .execute_batch("CREATE TABLE passport_verifier_challenges (challenge_id TEXT PRIMARY KEY);")
        .test_unwrap();
    assert!(matches!(
        SqlitePassportVerifierStore::open(&path),
        Err(PassportVerifierStoreError::Schema(
            SchemaVersionError::ForeignDatabase { .. }
        ))
    ));
}

#[test]
fn ledger_statements_seek_the_primary_key() {
    let fixture = fixture();
    let statements = [
        (super::challenges::SELECT, 1),
        (super::challenges::EXPIRE, 2),
        (super::challenges::CONSUME, 5),
        (super::oid4vp_requests::SELECT, 1),
        (super::oid4vp_requests::EXPIRE, 1),
        (super::oid4vp_requests::CONSUME, 2),
    ];
    let plans = fixture
        .store
        .read(|connection| {
            statements
                .iter()
                .map(|(sql, arity)| {
                    let nulls = std::iter::repeat_n(rusqlite::types::Null, *arity);
                    let mut statement = connection.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
                    let details = statement
                        .query_map(rusqlite::params_from_iter(nulls), |row| {
                            row.get::<_, String>(3)
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    Ok(details)
                })
                .collect::<Result<Vec<_>>>()
        })
        .test_unwrap();
    for plan in plans {
        assert!(!plan.is_empty(), "{plan:?}");
        assert!(
            plan.iter().all(|detail| detail.starts_with("SEARCH")),
            "{plan:?}"
        );
    }
}

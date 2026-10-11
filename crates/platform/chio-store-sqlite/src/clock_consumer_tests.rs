//! Owner-level controls for the shared SQLite clock contract.

use std::sync::{Arc, Mutex};

use chio_kernel::payment::{PaymentAdapter, PaymentAuthorizeRequest};
use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};

use crate::encrypted_blob::{SqliteEncryptedBlobStore, TenantId, TenantKey};
use crate::finding_operator_bundle_store::SqliteFindingOperatorBundleStore;
use crate::finding_operator_payment::SqliteFindingOperatorPaymentAdapter;
use crate::finding_payload_store::SqliteFindingPayloadStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const EPOCH: u64 = 42_000;

pub(crate) struct TestClock(Mutex<Result<ClockReading, ClockError>>);

impl TestClock {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(Ok(Self::reading(EPOCH, 100)))))
    }

    pub(crate) fn reading(unix_ms: u64, monotonic: u64) -> ClockReading {
        ClockReading::new(
            UnixMillis::new(unix_ms),
            MonotonicInstant::from_nanos(monotonic),
        )
    }

    pub(crate) fn set(&self, reading: Result<ClockReading, ClockError>) -> TestResult {
        *self.0.lock().map_err(|_| "fixture clock poisoned")? = reading;
        Ok(())
    }
}

impl Clock for TestClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        *self.0.lock().map_err(|_| ClockError::Unavailable)?
    }
}

fn faults() -> [Result<ClockReading, ClockError>; 4] {
    [
        Err(ClockError::Unavailable),
        Err(ClockError::Overflow),
        Ok(TestClock::reading(EPOCH - 1, 100)),
        Ok(TestClock::reading(EPOCH, 99)),
    ]
}

#[test]
fn sqlite_injected_blob_clock_stamps_and_refuses_before_mutation() -> TestResult {
    for fault in faults() {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("blobs.db");
        let clock = TestClock::new();
        let store = SqliteEncryptedBlobStore::open_with_clock(&path, clock.clone())?;
        let tenant = TenantId::new("clock-tenant");
        let key = TenantKey::from_bytes([7; 32]);
        store.write_encrypted_blob(&tenant, &key, b"retained")?;
        let connection = rusqlite::Connection::open(&path)?;
        let created_at: i64 =
            connection.query_row("SELECT created_at FROM chio_encrypted_blobs", [], |row| {
                row.get(0)
            })?;
        assert_eq!(created_at, 42);
        let before = crate::tests::authority_snapshot(&connection)?;
        clock.set(fault)?;
        assert!(store
            .write_encrypted_blob(&tenant, &key, b"refused")
            .is_err());
        assert_eq!(crate::tests::authority_snapshot(&connection)?, before);
    }
    Ok(())
}

#[test]
fn sqlite_injected_payload_clock_denies_exact_replay_without_writes() -> TestResult {
    for fault in faults() {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("payload.db");
        let clock = TestClock::new();
        let store = SqliteFindingPayloadStore::open_with_clock(&path, clock.clone())?;
        let tenant = TenantId::new("clock-tenant");
        let key = TenantKey::from_bytes([7; 32]);
        let payload = b"retained payload";
        let digest = chio_finding::finding_payload_sha256("text/plain", payload)?;
        store.put(
            &tenant,
            &key,
            "finding-clock",
            "text/plain",
            &digest,
            payload,
        )?;
        let connection = rusqlite::Connection::open(&path)?;
        let created_at: i64 =
            connection.query_row("SELECT created_at FROM chio_finding_payloads", [], |row| {
                row.get(0)
            })?;
        assert_eq!(created_at, 42);
        let before = crate::tests::authority_snapshot(&connection)?;
        clock.set(fault)?;
        assert!(store
            .put(
                &tenant,
                &key,
                "finding-clock",
                "text/plain",
                &digest,
                payload
            )
            .is_err());
        assert_eq!(crate::tests::authority_snapshot(&connection)?, before);
    }
    Ok(())
}

#[test]
fn sqlite_injected_payment_clock_denies_replay_and_capture_without_writes() -> TestResult {
    for fault in faults() {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("payment.db");
        let clock = TestClock::new();
        let store = SqliteFindingOperatorPaymentAdapter::open_with_clock(&path, clock.clone())?;
        let request = PaymentAuthorizeRequest {
            amount_units: 25,
            currency: "USD".to_owned(),
            payer: "buyer-clock".to_owned(),
            payee: "seller-clock".to_owned(),
            reference: "purchase-clock".to_owned(),
            governed: None,
            commerce: None,
        };
        let held = store.authorize(&request)?;
        let connection = rusqlite::Connection::open(&path)?;
        let created_at: i64 = connection.query_row(
            "SELECT created_at FROM chio_finding_operator_payments",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(created_at, 42);
        let before = crate::tests::authority_snapshot(&connection)?;
        clock.set(fault)?;
        assert!(store.authorize(&request).is_err());
        assert!(store
            .capture(&held.authorization_id, 25, "USD", &request.reference)
            .is_err());
        assert_eq!(crate::tests::authority_snapshot(&connection)?, before);
    }
    Ok(())
}

#[test]
fn sqlite_injected_bundle_clock_denies_replay_and_capacity_release() -> TestResult {
    for fault in faults() {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("bundle.db");
        let clock = TestClock::new();
        let store = SqliteFindingOperatorBundleStore::open_with_clock(&path, clock.clone())?;
        let request = "a".repeat(64);
        let digest = "b".repeat(64);
        store.reserve_terminal_capacity(&request, "principal-clock", &digest)?;
        let connection = rusqlite::Connection::open(&path)?;
        let created_at: i64 = connection.query_row(
            "SELECT created_at FROM chio_finding_operator_terminal_capacity",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(created_at, 42);
        let before = crate::tests::authority_snapshot(&connection)?;
        clock.set(fault)?;
        assert!(store
            .reserve_terminal_capacity(&request, "principal-clock", &digest)
            .is_err());
        assert!(store
            .release_terminal_capacity(&request, "principal-clock", &digest)
            .is_err());
        assert_eq!(crate::tests::authority_snapshot(&connection)?, before);
    }
    Ok(())
}

#[test]
fn sqlite_injected_relocation_clock_refuses_before_export_or_import_mutation() -> TestResult {
    let dir = tempfile::tempdir()?;
    crate::test_authority::secure_directory(dir.path());
    let database = dir.path().join("authority.db");
    let locks = dir.path().join("locks");
    std::fs::create_dir(&locks)?;
    crate::test_authority::secure_directory(&locks);
    crate::SqliteAuthorityStore::provision(&database, &locks)?;
    let clock = TestClock::new();
    let before = std::fs::read(&database)?;
    clock.set(Err(ClockError::Unavailable))?;
    assert!(
        crate::SqliteAuthorityStore::export_for_relocation_with_clock(
            &database,
            &locks,
            clock.clone()
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&database)?, before);
    clock.set(Ok(TestClock::reading(EPOCH, 100)))?;
    let seal = crate::SqliteAuthorityStore::export_for_relocation_with_clock(
        &database,
        &locks,
        clock.clone(),
    )?;
    assert_eq!(seal.exported_at_ms, EPOCH);
    let before = std::fs::read(&database)?;
    clock.set(Ok(TestClock::reading(EPOCH - 1, 100)))?;
    assert!(crate::SqliteAuthorityStore::import_relocated_with_clock(
        &database,
        &locks,
        clock.clone()
    )
    .is_err());
    assert_eq!(std::fs::read(&database)?, before);
    clock.set(Ok(TestClock::reading(EPOCH + 1_000, 200)))?;
    crate::SqliteAuthorityStore::import_relocated_with_clock(&database, &locks, clock)?;
    let connection = rusqlite::Connection::open(&database)?;
    let imported_at: i64 = connection.query_row(
        "SELECT imported_at_ms FROM chio_serving_relocation",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(imported_at, 43_000);
    Ok(())
}

#[test]
fn sqlite_injected_relocation_callback_clock_fault_preserves_lock_artifacts() -> TestResult {
    let dir = tempfile::tempdir()?;
    crate::test_authority::secure_directory(dir.path());
    let database = dir.path().join("authority.db");
    let locks = dir.path().join("locks");
    std::fs::create_dir(&locks)?;
    crate::test_authority::secure_directory(&locks);
    crate::SqliteAuthorityStore::provision(&database, &locks)?;
    let clock = TestClock::new();
    let seal = crate::SqliteAuthorityStore::export_for_relocation_with_clock(
        &database,
        &locks,
        clock.clone(),
    )?;
    let lock_path = locks.join(format!("{}.lock", seal.store_uuid));
    let before_database = std::fs::read(&database)?;
    let before_lock = std::fs::read(&lock_path)?;
    assert!(
        crate::SqliteAuthorityStore::import_relocated_checked_with_clock(
            &database,
            &locks,
            &seal,
            || clock
                .set(Err(ClockError::Unavailable))
                .map_err(|error| crate::SqliteServingOwnerError::Invalid(error.to_string())),
            clock.clone(),
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&database)?, before_database);
    assert_eq!(std::fs::read(&lock_path)?, before_lock);
    Ok(())
}

#[test]
fn sqlite_injected_revocation_replication_clock_denies_replay_and_delta() -> TestResult {
    for fault in faults() {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("revocations.db");
        let clock = TestClock::new();
        let store = crate::SqliteRevocationStore::open_with_clock(&path, clock.clone())?;
        chio_kernel::RevocationStore::revoke(&store, "local-clock")?;
        let retained = chio_kernel::RevocationRecord {
            capability_id: "replicated-clock".to_owned(),
            revoked_at: 7,
        };
        assert!(store.upsert_revocation_if_newer(&retained)?);
        assert_eq!(
            store
                .list_revocations(10, Some("replicated-clock"))?
                .first()
                .ok_or("missing replicated revocation")?
                .revoked_at,
            7
        );
        let connection = rusqlite::Connection::open(&path)?;
        let before = crate::tests::authority_snapshot(&connection)?;
        clock.set(fault)?;
        assert!(store.upsert_revocation_if_newer(&retained).is_err());
        let advanced = chio_kernel::RevocationRecord {
            revoked_at: 8,
            ..retained
        };
        assert!(store.upsert_revocation_if_newer(&advanced).is_err());
        assert_eq!(crate::tests::authority_snapshot(&connection)?, before);
    }
    Ok(())
}

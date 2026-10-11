//! Real Prepare/Execute containment distinguishes corrupt parents from absence.
use super::*;

fn fault(fixture: &Fixture, sql: &str) {
    let independent = rusqlite::Connection::open(&fixture.secret_path)
        .test_expect("own temporary secret database");
    independent
        .execute_batch("PRAGMA foreign_keys = OFF;")
        .test_expect("disable FK only on fault connection");
    assert_eq!(
        independent
            .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
            .test_expect("fault connection FK flag"),
        0
    );
    independent
        .execute_batch(sql)
        .test_expect("actual corrupt parent fixture");
}

fn assert_native_integrity_source(error: &BrokerError) {
    assert!(
        matches!(error, BrokerError::CredentialStorage(_)),
        "corrupt parent lost fatal credential storage ownership: {error:?}"
    );
    assert!(
        error.is_service_fault(),
        "shared broker fatal predicate was weakened"
    );
    assert_eq!(error.diagnostic_code(), "storage");
    let mut cause = std::error::Error::source(error);
    let mut found = false;
    for _ in 0..8 {
        match cause {
            Some(source) => {
                if matches!(
                    source.downcast_ref::<chio_store_sqlite::BlobStoreError>(),
                    Some(chio_store_sqlite::BlobStoreError::InvalidReference)
                ) {
                    found = true;
                    break;
                }
                cause = source.source();
            }
            None => break,
        }
    }
    assert!(
        found,
        "original native invalid-reference category was discarded"
    );
}

fn prepare_fault(sql: &str, suffix: &str) {
    let fixture = Fixture::new();
    let credential = Fixture::credential(1);
    assert!(
        fixture
            .rpc(&fixture.mutation(CredentialMutationKind::Provision, &credential, suffix))
            .test_expect("valid governed provision")
            .accepted
    );
    let (registration, execute) = fixture.execution(credential, suffix);
    assert!(
        fixture
            .rpc(&fixture.attempt_request(&registration, &execute, RegisterAttemptAction::Register))
            .test_expect("signed registration while reference is valid")
            .accepted
    );
    fault(&fixture, sql);
    let error = fixture
        .rpc(&fixture.attempt_request(&registration, &execute, RegisterAttemptAction::Prepare))
        .test_expect_err("corrupt parent must remain fatal at real Prepare endpoint");
    assert_native_integrity_source(&error);
    assert_public_error_is_private(&error, &fixture);
    let redacted = error.redacted();
    assert_native_integrity_source(&redacted);
    assert_public_error_is_private(&redacted, &fixture);
    let attempt = fixture
        .attempts
        .load_attempt(&registration.ids.attempt_id)
        .test_expect("attempt after Prepare refusal")
        .test_expect("registered attempt remains");
    assert_eq!(attempt.state, AttemptState::Registered);
    assert!(attempt.dispatch_claim_id.is_none());
    assert_eq!(fixture.dispatch_calls.load(Ordering::SeqCst), 0);
    assert!(fixture
        .observed_authorization
        .lock()
        .test_expect("secret observer")
        .is_none());
    assert!(fixture
        .service
        .replay_failure(&execute, 100)
        .test_expect("no Execute terminal fabricated by Prepare")
        .is_none());
}

#[test]
fn f011_reference_integrity_missing_parent_prepare_remains_fatal() {
    prepare_fault("DELETE FROM chio_encrypted_blobs;", "orphan-prepare");
}

#[test]
fn f011_reference_integrity_wrong_tenant_prepare_remains_fatal() {
    prepare_fault(
        "UPDATE chio_encrypted_blobs SET tenant_id = 'foreign-resolver-tenant';",
        "wrong-tenant-prepare",
    );
}

fn execute_fault(sql: &str, suffix: &str, sqlite: bool) {
    let fixture = Fixture::new();
    let (registration, execute) = provision_and_prepare(&fixture, 1, suffix);
    fault(&fixture, sql);
    let error = fixture
        .rpc(&execute_request(&execute))
        .test_expect_err("corrupt parent must reach fatal real Execute IPC consumer");
    if sqlite {
        assert!(matches!(&error, BrokerError::CredentialStorage(_)));
        assert!(error.is_service_fault());
        assert_eq!(error.diagnostic_code(), "storage");
        assert_native_store_source(&error, true);
    } else {
        assert_native_integrity_source(&error);
    }
    assert_public_error_is_private(&error, &fixture);
    let redacted = error.redacted();
    if sqlite {
        assert_native_store_source(&redacted, true);
    } else {
        assert_native_integrity_source(&redacted);
    }
    assert_public_error_is_private(&redacted, &fixture);
    let failure = assert_terminal_failure(
        &fixture,
        &registration,
        &execute,
        "chio.broker.storage",
        BrokerFailureOutcome::Failed,
    );
    assert_exact_denial_replay(&fixture, &execute, &failure);
}

#[test]
fn f011_reference_integrity_missing_parent_execute_remains_fatal_after_signed_projection() {
    execute_fault("DELETE FROM chio_encrypted_blobs;", "orphan-execute", false);
}

#[test]
fn f011_reference_integrity_wrong_tenant_execute_remains_fatal_after_signed_projection() {
    execute_fault(
        "UPDATE chio_encrypted_blobs SET tenant_id = 'foreign-resolver-tenant';",
        "wrong-tenant-execute",
        false,
    );
}

#[test]
fn f011_reference_integrity_missing_parent_table_execute_retains_native_sqlite() {
    execute_fault(
        "DROP TABLE chio_encrypted_blobs;",
        "missing-parent-table-execute",
        true,
    );
}

#[test]
fn f011_reference_integrity_healthy_execute_is_exactly_once() {
    let fixture = Fixture::new();
    assert_healthy_execute_once(&fixture, "resolver-healthy-execute");
}

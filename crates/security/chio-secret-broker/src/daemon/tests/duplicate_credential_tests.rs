//! Governed writes onto an existing credential version through the real endpoint.
use super::*;

fn assert_conflict(response: &IpcResponse) {
    assert!(!response.accepted);
    assert!(response.response.is_empty());
    assert_eq!(response.error_code.as_deref(), Some("conflict"));
}

fn encrypted_blob_rows(fixture: &Fixture) -> i64 {
    rusqlite::Connection::open(&fixture.secret_path)
        .test_expect("own temporary database")
        .query_row("SELECT COUNT(*) FROM chio_encrypted_blobs", [], |row| {
            row.get(0)
        })
        .test_expect("encrypted blob rows")
}

fn existing_version_write_is_contained(kind: CredentialMutationKind, disable_first: bool) {
    let fixture = Fixture::new();
    let credential = Fixture::credential(1);
    assert!(
        fixture
            .rpc(&fixture.mutation(CredentialMutationKind::Provision, &credential, "initial"))
            .test_expect("provision")
            .accepted
    );
    if disable_first {
        assert!(
            fixture
                .rpc(&fixture.mutation(CredentialMutationKind::Disable, &credential, "disable"))
                .test_expect("disable")
                .accepted
        );
    }
    let request = fixture.mutation(kind, &credential, "existing-version");
    assert_conflict(
        &fixture
            .rpc(&request)
            .test_expect("existing version write is a nonfatal conflict"),
    );
    assert_conflict(
        &fixture
            .rpc(&request)
            .test_expect("same approval repeat remains a conflict"),
    );
    assert_eq!(encrypted_blob_rows(&fixture), 1);
    fixture.healthy_next("healthy-after-existing-version");
}

#[test]
fn a_duplicate_provision_is_a_contained_conflict() {
    existing_version_write_is_contained(CredentialMutationKind::Provision, false);
}

#[test]
fn a_rotation_onto_an_existing_version_is_a_contained_conflict() {
    existing_version_write_is_contained(CredentialMutationKind::Rotate, false);
}

#[test]
fn reprovisioning_a_disabled_version_is_a_contained_conflict() {
    existing_version_write_is_contained(CredentialMutationKind::Provision, true);
}

fn native_store_cause(error: &BrokerError) -> Option<&chio_store_sqlite::BlobStoreError> {
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        if let Some(store) = cause.downcast_ref::<chio_store_sqlite::BlobStoreError>() {
            return Some(store);
        }
        source = cause.source();
    }
    None
}

fn assert_fatal_credential_storage(
    error: &BrokerError,
    expected: fn(&chio_store_sqlite::BlobStoreError) -> bool,
) {
    assert!(matches!(error, BrokerError::CredentialStorage(_)));
    assert_eq!(error.diagnostic_code(), "storage");
    assert!(
        native_store_cause(error).is_some_and(expected),
        "real native storage source was discarded or reclassified"
    );
}

#[test]
fn a_reference_store_fault_during_provision_remains_fatal_with_native_cause() {
    let fixture = Fixture::new();
    assert!(
        fixture
            .rpc(&fixture.mutation(
                CredentialMutationKind::Provision,
                &Fixture::credential(1),
                "initial"
            ))
            .test_expect("provision")
            .accepted
    );
    rusqlite::Connection::open(&fixture.secret_path)
        .test_expect("own temporary database")
        .execute_batch("DROP TABLE chio_encrypted_blob_references;")
        .test_expect("actual durable schema fault");
    let error = fixture
        .rpc(&fixture.mutation(
            CredentialMutationKind::Provision,
            &Fixture::credential(2),
            "corrupt-store",
        ))
        .test_expect_err("real storage fault remains fatal");
    assert_fatal_credential_storage(&error, |cause| {
        matches!(cause, chio_store_sqlite::BlobStoreError::Sqlite(_))
    });
}

fn existing_version_with_broken_binding_is_fatal(
    kind: CredentialMutationKind,
    fault: &str,
    expected: fn(&chio_store_sqlite::BlobStoreError) -> bool,
) {
    let fixture = Fixture::new();
    let credential = Fixture::credential(1);
    assert!(
        fixture
            .rpc(&fixture.mutation(CredentialMutationKind::Provision, &credential, "initial"))
            .test_expect("provision")
            .accepted
    );
    rusqlite::Connection::open(&fixture.secret_path)
        .test_expect("own temporary database")
        .execute_batch(fault)
        .test_expect("actual durable integrity fault");
    let error = match fixture.rpc(&fixture.mutation(kind, &credential, "broken-binding")) {
        Err(error) => error,
        Ok(response) => {
            panic!("a broken existing binding must end the endpoint, answered {response:?}")
        }
    };
    assert_fatal_credential_storage(&error, expected);
}

#[test]
fn a_duplicate_provision_over_a_missing_blob_table_remains_fatal() {
    existing_version_with_broken_binding_is_fatal(
        CredentialMutationKind::Provision,
        "PRAGMA foreign_keys = OFF; DROP TABLE chio_encrypted_blobs;",
        |cause| matches!(cause, chio_store_sqlite::BlobStoreError::Sqlite(_)),
    );
}

#[test]
fn a_rotation_onto_a_version_over_a_missing_blob_table_remains_fatal() {
    existing_version_with_broken_binding_is_fatal(
        CredentialMutationKind::Rotate,
        "PRAGMA foreign_keys = OFF; DROP TABLE chio_encrypted_blobs;",
        |cause| matches!(cause, chio_store_sqlite::BlobStoreError::Sqlite(_)),
    );
}

#[test]
fn a_duplicate_provision_of_a_version_without_its_blob_row_remains_fatal() {
    existing_version_with_broken_binding_is_fatal(
        CredentialMutationKind::Provision,
        "PRAGMA foreign_keys = OFF; DELETE FROM chio_encrypted_blobs;",
        |cause| matches!(cause, chio_store_sqlite::BlobStoreError::InvalidReference),
    );
}

use super::*;

#[test]
fn historical_suspension_discovery_refuses_one_past_its_supported_bound() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("suspension-history-bound.db");
    let store =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("open store: {error}"));
    let mut external = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("open history connection: {error}"));
    let transaction = external
        .transaction()
        .unwrap_or_else(|error| panic!("transaction: {error}"));
    for index in 1_u64..=1024 {
        let mut hash = [0_u8; 32];
        hash[..8].copy_from_slice(&index.to_be_bytes());
        transaction
            .execute(
                "INSERT INTO security_capability_set_suspension_state VALUES (?1, ?2, 1, 1)",
                rusqlite::params![tenant().as_str(), hash.as_slice()],
            )
            .unwrap_or_else(|error| panic!("seed history: {error}"));
    }
    transaction
        .commit()
        .unwrap_or_else(|error| panic!("commit history: {error}"));
    let query = CapabilitySuspensionQuery {
        tenant_id: tenant(),
        capability_id: record("unrelated"),
    };
    assert!(
        !store
            .evaluate_capability_suspension(&query)
            .unwrap_or_else(|error| panic!("exact-bound history: {error}"))
            .denied
    );
    external
        .execute(
            "INSERT INTO security_capability_set_suspension_state VALUES (?1, ?2, 1, 1)",
            rusqlite::params![tenant().as_str(), [255_u8; 32].as_slice()],
        )
        .unwrap_or_else(|error| panic!("seed one-over history: {error}"));
    let refusal = require_error(store.evaluate_capability_suspension(&query));
    assert_eq!(refusal.kind(), PortErrorKind::Unavailable);
    assert_eq!(
        refusal.code().as_str(),
        "store.suspension_lookup_budget_exhausted"
    );
    // A refusal must clear the progress callback and release its snapshot.
    external
        .execute(
            "DELETE FROM security_capability_set_suspension_state WHERE affected_set_hash = ?1",
            [[255_u8; 32].as_slice()],
        )
        .unwrap_or_else(|error| panic!("remove one-over history: {error}"));
    assert!(
        !store
            .evaluate_capability_suspension(&query)
            .unwrap_or_else(|error| panic!("bounded retry: {error}"))
            .denied
    );
}

#[test]
fn oversized_suspension_body_refuses_before_decoding() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("suspension-body-bound.db");
    let store =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("open store: {error}"));
    let external =
        rusqlite::Connection::open(&path).unwrap_or_else(|error| panic!("open mutation: {error}"));
    external
        .execute_batch("PRAGMA ignore_check_constraints=ON")
        .unwrap_or_else(|error| panic!("fault controls: {error}"));
    external
        .execute(
            "INSERT INTO security_capability_set_suspension_state VALUES (?1, ?2, 1, 1)",
            rusqlite::params![tenant().as_str(), [1_u8; 32].as_slice()],
        )
        .unwrap_or_else(|error| panic!("seed state: {error}"));
    external.execute("INSERT INTO security_capability_set_suspension_effects VALUES (?1, ?2, 'action-large', 'effect-large', zeroblob(2097152), ?2, 1, 1)", rusqlite::params![tenant().as_str(), [1_u8; 32].as_slice()])
        .unwrap_or_else(|error| panic!("seed oversized body: {error}"));
    let refusal = require_error(
        store.evaluate_capability_suspension(&CapabilitySuspensionQuery {
            tenant_id: tenant(),
            capability_id: record("unrelated"),
        }),
    );
    assert_eq!(refusal.kind(), PortErrorKind::Unavailable);
    assert_eq!(
        refusal.code().as_str(),
        "store.suspension_lookup_budget_exhausted"
    );
}

use super::*;

fn projection_fixture() -> Result<Connection, rusqlite::Error> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(
        r#"
            CREATE TABLE budget_mutation_events (event_id TEXT PRIMARY KEY);
            CREATE TABLE channel_lifecycle_records (channel_id TEXT PRIMARY KEY);
            CREATE TABLE channel_prepared_admission_plans (operation_id TEXT PRIMARY KEY);
            CREATE TABLE frost_nonce_commitments (nonce_id TEXT PRIMARY KEY);
            CREATE TABLE payment_journal (operation_id TEXT PRIMARY KEY);
            CREATE TABLE payment_release_evidence (evidence_id TEXT PRIMARY KEY);
            "#,
    )?;
    Ok(connection)
}

fn factor_projection_fixture() -> Result<Connection, rusqlite::Error> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(
        r#"
        CREATE TABLE admission_operation_commits (
            operation_id TEXT NOT NULL,
            commit_sequence INTEGER NOT NULL
        );
        CREATE TABLE budget_mutation_events (
            event_id TEXT NOT NULL,
            event_seq INTEGER NOT NULL
        );
        CREATE TABLE admission_authority_commits (
            kind TEXT NOT NULL,
            capability_id TEXT NOT NULL,
            commit_index INTEGER NOT NULL
        );
        CREATE TABLE frost_projection_commits (
            projection_key TEXT NOT NULL,
            projection_sequence INTEGER NOT NULL
        );
        CREATE TABLE payment_journal (
            operation_id TEXT NOT NULL,
            journal_version INTEGER NOT NULL
        );
        CREATE TABLE economic_state_stage_commits (
            batch_id TEXT NOT NULL,
            stage_version INTEGER NOT NULL
        );
        CREATE TABLE chio_channel_release_publications (
            channel_id TEXT NOT NULL,
            record_version INTEGER NOT NULL
        );
        CREATE TABLE factor_assignment_authority_sets (
            generation INTEGER NOT NULL PRIMARY KEY,
            active_set_digest TEXT NOT NULL,
            previous_active_set_digest TEXT,
            activated_at_unix_ms INTEGER NOT NULL,
            store_uuid TEXT NOT NULL,
            store_lease_id TEXT NOT NULL,
            store_owner_epoch INTEGER NOT NULL
        );
        CREATE TABLE fiscal_projection_commits (
            projection_key TEXT NOT NULL,
            projection_sequence INTEGER NOT NULL,
            commit_digest TEXT NOT NULL
        );
        CREATE TABLE authority_global_commits (
            projection_kind TEXT NOT NULL,
            projection_key TEXT NOT NULL,
            projection_sequence INTEGER NOT NULL
        );
        INSERT INTO factor_assignment_authority_sets (
            generation, active_set_digest, previous_active_set_digest,
            activated_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch
        ) VALUES (
            1,
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            NULL,
            1000,
            'store-1',
            'lease-1',
            1
        );
        "#,
    )?;
    Ok(connection)
}

fn factor_commit(reference_digest: String) -> CommitRow {
    CommitRow {
        sequence: 2,
        mutation_kind: "factor_assignment_authority_set".to_string(),
        projection_kind: "factor_assignment_authority_set".to_string(),
        projection_key: "active".to_string(),
        projection_sequence: 1,
        projection_reference_digest: reference_digest,
        authority_projection_digest: GLOBAL_GENESIS_DIGEST.to_string(),
        previous_chain_digest: GLOBAL_GENESIS_DIGEST.to_string(),
        chain_digest: GLOBAL_GENESIS_DIGEST.to_string(),
        store_uuid: "store-1".to_string(),
        store_lease_id: Some("lease-1".to_string()),
        store_owner_epoch: 1,
    }
}

fn insert_factor_global_commit(
    connection: &Connection,
    key: &str,
    generation: i64,
) -> Result<(), rusqlite::Error> {
    connection.execute(
        r#"
        INSERT INTO authority_global_commits (
            projection_kind, projection_key, projection_sequence
        ) VALUES ('factor_assignment_authority_set', ?1, ?2)
        "#,
        params![key, generation],
    )?;
    Ok(())
}

#[test]
fn authority_snapshot_includes_payment_projection() -> Result<(), Box<dyn std::error::Error>> {
    let connection = projection_fixture()?;

    assert_eq!(
        table_names(&connection, false)?,
        vec![
            "budget_mutation_events",
            "channel_lifecycle_records",
            "channel_prepared_admission_plans",
            "frost_nonce_commitments",
            "payment_journal",
            "payment_release_evidence",
        ]
    );
    assert_ne!(
        baseline_projection_digest(&connection)?,
        pre_payment_baseline_projection_digest(&connection)?
    );
    Ok(())
}

#[test]
fn pre_payment_compatibility_requires_empty_payment_projection(
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = projection_fixture()?;
    assert!(payment_projection_is_empty(&connection)?);

    connection.execute(
        "INSERT INTO payment_journal (operation_id) VALUES ('operation-1')",
        [],
    )?;

    assert!(!payment_projection_is_empty(&connection)?);
    Ok(())
}

#[test]
fn pre_channel_compatibility_requires_every_channel_table_to_be_empty(
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = projection_fixture()?;
    assert!(projection_is_empty(&connection, "channel_")?);

    connection.execute(
        "INSERT INTO channel_prepared_admission_plans (operation_id) VALUES ('operation-1')",
        [],
    )?;

    assert!(!projection_is_empty(&connection, "channel_")?);
    Ok(())
}

#[test]
fn pre_factor_assignment_compatibility_requires_empty_projection(
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    connection.execute(
        "CREATE TABLE factor_assignment_authority_sets (generation INTEGER PRIMARY KEY)",
        [],
    )?;

    assert!(factor_assignment_projection_is_empty(&connection)?);
    assert_ne!(
        baseline_projection_digest(&connection)?,
        pre_factor_assignment_baseline_projection_digest(&connection)?
    );

    connection.execute(
        "INSERT INTO factor_assignment_authority_sets (generation) VALUES (1)",
        [],
    )?;

    assert!(!factor_assignment_projection_is_empty(&connection)?);
    Ok(())
}

#[test]
fn factor_assignment_authority_reference_is_exact() -> Result<(), Box<dyn std::error::Error>> {
    let connection = factor_projection_fixture()?;
    let reference =
        projection_reference_digest(&connection, "factor_assignment_authority_set", "active", 1)?;
    assert_eq!(
        reference,
        "65555c1ac79c44d41687384af06f00a441f0a1fd738d1415e74bdf136651f429"
    );
    let commit = factor_commit(reference);

    assert!(verify_projection_reference(&connection, &commit).is_ok());

    connection.execute(
        r#"
        UPDATE factor_assignment_authority_sets
        SET active_set_digest =
            'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
        WHERE generation = 1
        "#,
        [],
    )?;

    assert!(verify_projection_reference(&connection, &commit).is_err());
    Ok(())
}

#[test]
fn factor_assignment_authority_coverage_is_exact_and_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = factor_projection_fixture()?;
    assert!(verify_global_projection_coverage(&connection).is_err());

    for (key, generation, exact) in [
        ("active", 1, true),
        ("retained", 1, false),
        ("active", 2, false),
    ] {
        let connection = factor_projection_fixture()?;
        insert_factor_global_commit(&connection, key, generation)?;
        assert_eq!(
            verify_global_projection_coverage(&connection).is_ok(),
            exact
        );
    }
    Ok(())
}

#[test]
fn channel_release_projection_references_are_exact_and_unknown_kinds_stay_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(
        r#"
        CREATE TABLE chio_channel_release_publications (
            channel_id TEXT PRIMARY KEY,
            record_version INTEGER NOT NULL,
            publication_binding_digest TEXT NOT NULL,
            status TEXT NOT NULL
        );
        CREATE TABLE authority_global_commits (
            projection_kind TEXT NOT NULL,
            projection_key TEXT NOT NULL,
            projection_sequence INTEGER NOT NULL
        );
        INSERT INTO chio_channel_release_publications
            (channel_id, record_version, publication_binding_digest, status)
        VALUES ('channel-1', 1, 'binding-1', 'dispatch_committed');
        INSERT INTO authority_global_commits
            (projection_kind, projection_key, projection_sequence)
        VALUES ('channel_release_publication', 'channel-1', 1);
        "#,
    )?;

    assert!(projection_reference_digest(
        &connection,
        "channel_release_publication",
        "channel-1",
        1,
    )
    .is_ok());
    assert!(projection_reference_digest(
        &connection,
        "channel_release_publication",
        "channel-1",
        2,
    )
    .is_err());
    assert!(projection_reference_digest(&connection, "unknown", "channel-1", 1).is_err());
    assert!(verify_channel_release_projection_coverage(&connection).is_ok());

    connection.execute_batch(
        r#"
        UPDATE chio_channel_release_publications SET record_version = 3;
        INSERT INTO authority_global_commits
            (projection_kind, projection_key, projection_sequence)
        VALUES
            ('channel_release_publication', 'channel-1', 1),
            ('channel_release_publication', 'channel-1', 3);
        "#,
    )?;
    assert!(verify_channel_release_projection_coverage(&connection).is_err());
    Ok(())
}

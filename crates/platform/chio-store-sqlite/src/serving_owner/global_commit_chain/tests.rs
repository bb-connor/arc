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
        CREATE TABLE revocation_entries (
            entry_id TEXT NOT NULL,
            entry_seq INTEGER NOT NULL
        );
        CREATE TABLE authority_global_commits (
            commit_sequence INTEGER,
            mutation_kind TEXT,
            projection_kind TEXT NOT NULL,
            projection_key TEXT NOT NULL,
            projection_sequence INTEGER NOT NULL,
            projection_reference_digest TEXT
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
    connection.execute_batch(include_str!("../../admission_operation_runtime_source.sql"))?;
    connection.execute_batch(include_str!("../../admission_operation_recovery.sql"))?;
    connection.execute_batch(include_str!("../../delegation_store.sql"))?;
    connection.execute_batch(include_str!("../../work_graph_store.sql"))?;
    connection.execute_batch(include_str!("../../root_exchange_store.sql"))?;
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

#[test]
fn baseline_requires_the_complete_declared_projection_even_when_empty(
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(
        "CREATE TABLE factor_assignment_authority_sets (generation INTEGER PRIMARY KEY);
         CREATE TABLE authority_global_commits (
             commit_sequence INTEGER, projection_kind TEXT, projection_reference_digest TEXT
         );",
    )?;
    let incomplete = baseline_projection_digest_for_tables(&connection, Vec::new())?;
    connection.execute(
        "INSERT INTO authority_global_commits VALUES(1, 'baseline', ?1)",
        [&incomplete],
    )?;
    assert!(matches!(
        verify_live_baseline_projection(&connection),
        Err(SqliteServingOwnerError::Invalid(message))
            if message == "global authority baseline does not match its live projection"
    ));
    assert_eq!(
        connection.query_row(
            "SELECT projection_reference_digest FROM authority_global_commits",
            [],
            |row| row.get::<_, String>(0),
        )?,
        incomplete
    );
    Ok(())
}

#[test]
fn revocation_entry_coverage_is_exact_and_closed() -> Result<(), Box<dyn std::error::Error>> {
    for (commits, exact) in [
        (&[("rev_a", 1)][..], true),
        (&[][..], false),
        (&[("rev_a", 1), ("rev_a", 1)][..], false),
        (&[("rev_a", 1), ("rev_b", 2)][..], false),
        (&[("rev_a", 2)][..], false),
    ] {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            r#"
            CREATE TABLE revocation_entries (
                entry_id TEXT NOT NULL,
                entry_seq INTEGER NOT NULL
            );
            CREATE TABLE authority_global_commits (
                projection_kind TEXT NOT NULL,
                projection_key TEXT NOT NULL,
                projection_sequence INTEGER NOT NULL
            );
            INSERT INTO revocation_entries (entry_id, entry_seq) VALUES ('rev_a', 1);
            "#,
        )?;
        for (key, sequence) in commits {
            connection.execute(
                r#"
                INSERT INTO authority_global_commits
                    (projection_kind, projection_key, projection_sequence)
                VALUES ('revocation_entry', ?1, ?2)
                "#,
                params![key, sequence],
            )?;
        }
        let result = revocation_entry::verify_coverage(&connection);
        if exact {
            result?;
        } else {
            assert!(
                matches!(
                    &result,
                    Err(SqliteServingOwnerError::Invalid(detail))
                        if detail == "revocation entry projection coverage is not exact"
                ),
                "{commits:?}: {result:?}"
            );
        }
    }
    Ok(())
}

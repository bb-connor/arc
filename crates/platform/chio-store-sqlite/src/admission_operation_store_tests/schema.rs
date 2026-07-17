use super::*;

#[test]
fn fresh_provision_creates_the_operation_schema_after_serving_lease_schema() {
    let fixture = fixture();
    let connection = fixture.store.connection().expect("connection");
    let (version, head, high_water, lease_table): (i64, i64, i64, bool) = connection
        .query_row(
            r#"
            SELECT
                (SELECT version FROM chio_store_schema_versions
                 WHERE store_key = 'admission_operation'),
                (SELECT head_sequence FROM admission_operation_commit_meta
                 WHERE singleton = 1),
                (SELECT trusted_time_high_water_unix_ms
                 FROM admission_operation_commit_meta WHERE singleton = 1),
                EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table' AND name = 'chio_serving_leases'
                )
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("schema projection");
    assert_eq!(
        version,
        i64::from(ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)
    );
    assert_eq!(head, 0);
    assert_eq!(high_water, 0);
    assert!(lease_table);
    verify_admission_operation_invariants(&connection).expect("fresh invariants");
}

#[test]
fn provision_migrates_v1_operation_state_without_losing_replay_identity() {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-v1-migration",
        "capability-v1-migration",
    );
    fixture
        .store
        .begin(&operation, &fixture.fence, now_ms())
        .expect("persist v1 operation");

    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);

    let connection = Connection::open(&database).expect("open offline database");
    connection
        .execute_batch(
            r#"
            DROP TABLE obligation_disposition_records;
            DROP TABLE obligation_atoms;
            DROP TABLE admission_operation_observer_attempts;
            DROP TABLE admission_operation_authorization_consumptions;
            DROP TABLE admission_operation_terminal_records;
            DROP TABLE admission_operation_terminal_projections;
            UPDATE chio_store_schema_versions
            SET version = 1
            WHERE store_key = 'admission_operation';
            "#,
        )
        .expect("shape database as v1");
    drop(connection);

    SqliteAuthorityStore::provision(&database, &lock_root).expect("migrate v1 authority");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open migrated authority");
    let store = authority.admission_operation_store();
    assert_eq!(
        store
            .load_by_operation_id(operation.binding().operation_id())
            .expect("load preserved operation"),
        Some(operation)
    );
    let connection = store.connection().expect("migrated connection");
    verify_admission_operation_invariants(&connection).expect("migrated invariants");
    drop(_temp);
}

#[test]
fn provision_migrates_v2_commit_chain_across_closed_serving_epochs() {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-v2-chain-migration",
        "capability-v2-chain-migration",
    );
    fixture
        .store
        .begin(&operation, &fixture.fence, now_ms())
        .expect("persist v2 operation");
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);

    let replacement =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("rotate serving owner");
    drop(replacement);

    let connection = Connection::open(&database).expect("open offline database");
    let closed_epochs: i64 = connection
        .query_row(
            r#"
            SELECT COUNT(*)
            FROM admission_operation_commits AS commits
            JOIN chio_serving_leases AS leases
              ON leases.store_uuid = commits.store_uuid
             AND leases.owner_epoch = commits.store_owner_epoch
            WHERE leases.end_head_index IS NOT NULL
            "#,
            [],
            |row| row.get(0),
        )
        .expect("closed commit epochs");
    assert!(closed_epochs > 0);
    connection
        .execute_batch(
            r#"
            DROP TRIGGER admission_operation_commits_exact_lease;
            DROP TRIGGER admission_operation_commits_immutable;
            DROP TRIGGER admission_operation_commits_no_delete;
            DROP INDEX admission_operation_commits_operation;
            ALTER TABLE admission_operation_commits
                RENAME TO admission_operation_commits_v3;

            CREATE TABLE admission_operation_commits (
                commit_sequence INTEGER PRIMARY KEY CHECK (commit_sequence > 0),
                operation_id TEXT NOT NULL,
                operation_version INTEGER NOT NULL CHECK (operation_version > 0),
                mutation_kind TEXT NOT NULL CHECK (
                    mutation_kind IN ('begin', 'compare_and_swap', 'recovery_claim')
                ),
                operation_digest TEXT NOT NULL CHECK (
                    length(operation_digest) = 64
                    AND operation_digest NOT GLOB '*[^0-9a-f]*'
                ),
                recovery_claim_digest TEXT CHECK (
                    recovery_claim_digest IS NULL
                    OR (length(recovery_claim_digest) = 64
                        AND recovery_claim_digest NOT GLOB '*[^0-9a-f]*')
                ),
                previous_chain_digest TEXT NOT NULL CHECK (
                    length(previous_chain_digest) = 64
                    AND previous_chain_digest NOT GLOB '*[^0-9a-f]*'
                ),
                chain_digest TEXT NOT NULL CHECK (
                    length(chain_digest) = 64
                    AND chain_digest NOT GLOB '*[^0-9a-f]*'
                ),
                store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
                store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
                store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
                recorded_at_unix_ms INTEGER NOT NULL CHECK (recorded_at_unix_ms > 0),
                FOREIGN KEY (operation_id) REFERENCES admission_operations(operation_id),
                FOREIGN KEY (store_uuid, store_owner_epoch)
                    REFERENCES chio_serving_leases(store_uuid, owner_epoch),
                CHECK (
                    (mutation_kind = 'begin' AND recovery_claim_digest IS NULL)
                    OR (mutation_kind IN ('compare_and_swap', 'recovery_claim')
                        AND recovery_claim_digest IS NOT NULL)
                )
            );
            INSERT INTO admission_operation_commits (
                commit_sequence, operation_id, operation_version, mutation_kind,
                operation_digest, recovery_claim_digest, previous_chain_digest,
                chain_digest, store_uuid, store_lease_id, store_owner_epoch,
                recorded_at_unix_ms
            )
            SELECT commit_sequence, operation_id, operation_version, mutation_kind,
                   operation_digest, recovery_claim_digest, previous_chain_digest,
                   chain_digest, store_uuid, store_lease_id, store_owner_epoch,
                   recorded_at_unix_ms
            FROM admission_operation_commits_v3;
            DROP TABLE admission_operation_commits_v3;
            CREATE INDEX admission_operation_commits_operation
                ON admission_operation_commits(operation_id, commit_sequence);
            CREATE TRIGGER admission_operation_commits_exact_lease
            BEFORE INSERT ON admission_operation_commits
            WHEN NOT EXISTS (
                SELECT 1 FROM chio_serving_leases
                WHERE store_uuid = NEW.store_uuid
                  AND owner_epoch = NEW.store_owner_epoch
                  AND lease_id = NEW.store_lease_id
                  AND end_head_index IS NULL
            )
            BEGIN
                SELECT RAISE(ABORT, 'admission operation commit has no exact serving lease');
            END;
            CREATE TRIGGER admission_operation_commits_immutable
            BEFORE UPDATE ON admission_operation_commits
            BEGIN
                SELECT RAISE(ABORT, 'admission operation commit is immutable');
            END;
            CREATE TRIGGER admission_operation_commits_no_delete
            BEFORE DELETE ON admission_operation_commits
            BEGIN
                SELECT RAISE(ABORT, 'admission operation commit is immutable');
            END;
            UPDATE chio_store_schema_versions
            SET version = 2
            WHERE store_key = 'admission_operation';
            "#,
        )
        .expect("shape database as v2");
    drop(connection);

    SqliteAuthorityStore::provision(&database, &lock_root).expect("migrate v2 authority");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open migrated authority");
    let store = authority.admission_operation_store();
    assert_eq!(
        store
            .load_by_operation_id(operation.binding().operation_id())
            .expect("load preserved operation"),
        Some(operation)
    );
    let connection = store.connection().expect("migrated connection");
    let (version, null_participants): (i64, i64) = connection
        .query_row(
            r#"
            SELECT
                (SELECT version FROM chio_store_schema_versions
                 WHERE store_key = 'admission_operation'),
                (SELECT COUNT(*) FROM admission_operation_commits
                 WHERE participant_digest IS NULL)
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("migrated commit schema");
    assert_eq!(
        version,
        i64::from(ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)
    );
    assert!(null_participants > 0);
    verify_admission_operation_invariants(&connection).expect("migrated invariants");
    drop(_temp);
}

#[test]
fn provision_migrates_v4_channel_commit_kind_without_changing_history() -> AnchoredTestResult {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-v4-channel-commit-migration",
        "capability-v4-channel-commit-migration",
    );
    let begun_at = now_ms();
    fixture.store.begin(&operation, &fixture.fence, begun_at)?;
    let recovery = claim(&fixture, &operation, "v4-channel-migration", begun_at + 1);
    let participant_digest = economic_digest("v4-channel-participant");
    {
        let mut connection = fixture.store.connection()?;
        let transaction = fixture
            .store
            .begin_write(&mut connection, Some(&fixture.fence))?;
        append_participant_update_tx(
            &transaction,
            &fixture.store.serving_owner,
            &operation,
            &recovery,
            &participant_digest,
            begun_at + 2,
        )?;
        fixture.store.commit_write(transaction)?;
        fixture.store.sync_after_write(&connection)?;
    }
    let before = {
        let connection = fixture.store.connection()?;
        admission_commit_rows(&connection)?
    };

    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);

    let connection = Connection::open(&database)?;
    connection.execute_batch(
        r#"
        DROP TRIGGER admission_operation_commits_exact_lease;
        DROP TRIGGER admission_operation_commits_immutable;
        DROP TRIGGER admission_operation_commits_no_delete;
        DROP INDEX admission_operation_commits_operation;
        ALTER TABLE admission_operation_commits
            RENAME TO admission_operation_commits_v4;

        CREATE TABLE admission_operation_commits (
            commit_sequence INTEGER PRIMARY KEY CHECK (commit_sequence > 0),
            operation_id TEXT NOT NULL,
            operation_version INTEGER NOT NULL CHECK (operation_version > 0),
            mutation_kind TEXT NOT NULL CHECK (
                mutation_kind IN (
                    'begin', 'compare_and_swap', 'recovery_claim', 'participant_update'
                )
            ),
            operation_digest TEXT NOT NULL CHECK (
                length(operation_digest) = 64
                AND operation_digest NOT GLOB '*[^0-9a-f]*'
            ),
            recovery_claim_digest TEXT CHECK (
                recovery_claim_digest IS NULL
                OR (length(recovery_claim_digest) = 64
                    AND recovery_claim_digest NOT GLOB '*[^0-9a-f]*')
            ),
            participant_digest TEXT CHECK (
                participant_digest IS NULL
                OR (length(participant_digest) = 64
                    AND participant_digest NOT GLOB '*[^0-9a-f]*')
            ),
            previous_chain_digest TEXT NOT NULL CHECK (
                length(previous_chain_digest) = 64
                AND previous_chain_digest NOT GLOB '*[^0-9a-f]*'
            ),
            chain_digest TEXT NOT NULL CHECK (
                length(chain_digest) = 64
                AND chain_digest NOT GLOB '*[^0-9a-f]*'
            ),
            store_uuid TEXT NOT NULL CHECK (store_uuid <> ''),
            store_lease_id TEXT NOT NULL CHECK (store_lease_id <> ''),
            store_owner_epoch INTEGER NOT NULL CHECK (store_owner_epoch > 0),
            recorded_at_unix_ms INTEGER NOT NULL CHECK (recorded_at_unix_ms > 0),
            FOREIGN KEY (operation_id) REFERENCES admission_operations(operation_id),
            FOREIGN KEY (store_uuid, store_owner_epoch)
                REFERENCES chio_serving_leases(store_uuid, owner_epoch),
            CHECK (
                (mutation_kind = 'begin'
                 AND recovery_claim_digest IS NULL
                 AND participant_digest IS NULL)
                OR (mutation_kind = 'recovery_claim'
                    AND recovery_claim_digest IS NOT NULL
                    AND participant_digest IS NULL)
                OR (mutation_kind = 'compare_and_swap'
                    AND recovery_claim_digest IS NOT NULL)
                OR (mutation_kind = 'participant_update'
                    AND recovery_claim_digest IS NOT NULL
                    AND participant_digest IS NOT NULL)
            )
        );
        INSERT INTO admission_operation_commits (
            commit_sequence, operation_id, operation_version, mutation_kind,
            operation_digest, recovery_claim_digest, participant_digest,
            previous_chain_digest, chain_digest,
            store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
        )
        SELECT commit_sequence, operation_id, operation_version, mutation_kind,
               operation_digest, recovery_claim_digest, participant_digest,
               previous_chain_digest, chain_digest,
               store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
        FROM admission_operation_commits_v4
        ORDER BY commit_sequence;
        DROP TABLE admission_operation_commits_v4;
        CREATE INDEX admission_operation_commits_operation
            ON admission_operation_commits(operation_id, commit_sequence);
        CREATE TRIGGER admission_operation_commits_exact_lease
        BEFORE INSERT ON admission_operation_commits
        WHEN NOT EXISTS (
            SELECT 1 FROM chio_serving_leases
            WHERE store_uuid = NEW.store_uuid
              AND owner_epoch = NEW.store_owner_epoch
              AND lease_id = NEW.store_lease_id
              AND end_head_index IS NULL
        )
        BEGIN
            SELECT RAISE(ABORT, 'admission operation commit has no exact serving lease');
        END;
        CREATE TRIGGER admission_operation_commits_immutable
        BEFORE UPDATE ON admission_operation_commits
        BEGIN
            SELECT RAISE(ABORT, 'admission operation commit is immutable');
        END;
        CREATE TRIGGER admission_operation_commits_no_delete
        BEFORE DELETE ON admission_operation_commits
        BEGIN
            SELECT RAISE(ABORT, 'admission operation commit is immutable');
        END;
        UPDATE chio_store_schema_versions
        SET version = 4
        WHERE store_key = 'admission_operation';
        "#,
    )?;
    drop(connection);

    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fence = authority.mutation_fence();
    let store = authority.admission_operation_store();
    let mut connection = store.connection()?;
    assert_eq!(before, admission_commit_rows(&connection)?);
    let version: i64 = connection.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = 'admission_operation'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        version,
        i64::from(ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)
    );
    verify_admission_operation_invariants(&connection)?;

    let transaction = store.begin_write(&mut connection, Some(&fence))?;
    let next_sequence: i64 = transaction.query_row(
        "SELECT MAX(commit_sequence) + 1 FROM admission_operation_commits",
        [],
        |row| row.get(0),
    )?;
    let inserted = transaction.execute(
        r#"
        INSERT INTO admission_operation_commits (
            commit_sequence, operation_id, operation_version, mutation_kind,
            operation_digest, recovery_claim_digest, participant_digest,
            previous_chain_digest, chain_digest,
            store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
        )
        SELECT ?1, operation_id, 2, 'channel_reservation_finalized',
               operation_digest, ?2, ?3, chain_digest, ?4, ?5, ?6, ?7, ?8
        FROM admission_operation_commits
        WHERE commit_sequence = 1
        "#,
        params![
            next_sequence,
            economic_digest("v5-channel-recovery-claim"),
            economic_digest("v5-channel-participant"),
            economic_digest("v5-channel-probe-chain"),
            &fence.store_uuid,
            &fence.lease_id,
            i64::try_from(fence.owner_epoch)?,
            i64::try_from(now_ms())?,
        ],
    )?;
    assert_eq!(inserted, 1);
    transaction.rollback()?;
    drop(_temp);
    Ok(())
}

#[test]
fn canonical_schema_rejects_a_same_name_no_op_trigger() {
    let fixture = fixture();
    let connection = fixture.store.connection().expect("connection");
    connection
        .execute_batch(
            r#"
            DROP TRIGGER admission_operations_no_delete;
            CREATE TRIGGER admission_operations_no_delete
            BEFORE DELETE ON admission_operations
            BEGIN
                SELECT 1;
            END;
            "#,
        )
        .expect("replace trigger");

    assert!(matches!(
        verify_admission_operation_invariants(&connection),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
}

#[test]
fn canonical_schema_rejects_an_unexpected_trigger_with_an_unrelated_name() {
    let fixture = fixture();
    let connection = fixture.store.connection().expect("connection");
    connection
        .execute_batch(
            r#"
            CREATE TRIGGER unexpected_delete_hook
            BEFORE DELETE ON admission_operations
            BEGIN
                SELECT 1;
            END;
            "#,
        )
        .expect("add trigger");

    assert!(matches!(
        verify_admission_operation_invariants(&connection),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
}

#[test]
fn canonical_schema_rejects_a_weakened_table_definition() {
    let fixture = fixture();
    let connection = fixture.store.connection().expect("connection");
    connection
        .execute_batch("PRAGMA writable_schema = ON")
        .expect("enable schema repair mode");
    let changed = connection
        .execute(
            r#"
            UPDATE sqlite_schema
            SET sql = 'CREATE TABLE admission_operations (operation_id TEXT PRIMARY KEY)'
            WHERE type = 'table' AND name = 'admission_operations'
            "#,
            [],
        )
        .expect("weaken table definition");
    connection
        .execute_batch("PRAGMA writable_schema = OFF")
        .expect("disable schema repair mode");
    assert_eq!(changed, 1);

    assert!(matches!(
        verify_admission_operation_invariants(&connection),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
}

#[test]
fn persisted_operations_use_rfc_8785_bytes() {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-canonical-雪",
        "capability-canonical",
    );
    fixture
        .store
        .begin(&operation, &fixture.fence, now_ms())
        .expect("begin operation");

    let stored = fixture
        .store
        .connection()
        .expect("connection")
        .query_row(
            "SELECT operation_json FROM admission_operations WHERE operation_id = ?1",
            [operation.binding().operation_id().as_str()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .expect("stored operation bytes");
    let expected = canonical_json_bytes(&operation.to_persisted()).expect("canonical operation");
    let serde_order = serde_json::to_vec(&operation.to_persisted()).expect("serde operation");

    assert_eq!(stored, expected);
    assert_ne!(stored, serde_order);
    assert!(std::str::from_utf8(&stored)
        .expect("UTF-8 operation")
        .contains('雪'));
}

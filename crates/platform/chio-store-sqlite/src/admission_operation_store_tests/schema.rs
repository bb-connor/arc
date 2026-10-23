use super::*;

struct SqlObligationHead {
    obligation_id: String,
    atom_digest: String,
    settlement_digest: String,
    head_digest: String,
}

struct SqlAssignmentParticipant {
    operation_id: String,
    participant_digest: String,
    commit_sequence: i64,
    committed_at_unix_ms: u64,
}

fn seed_sql_obligation_head(
    fixture: &Fixture,
    suffix: &str,
    committed_at_unix_ms: u64,
) -> AnchoredTestResult<SqlObligationHead> {
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        &format!("assignment-source-{suffix}"),
        &format!("assignment-source-capability-{suffix}"),
    );
    fixture
        .store
        .begin(&operation, &fixture.fence, committed_at_unix_ms)?;
    let operation_id = operation.binding().operation_id().as_str();
    let obligation_id = economic_digest(&format!("assignment-obligation-{suffix}"));
    let atom_digest = economic_digest(&format!("assignment-atom-{suffix}"));
    let disposition_digest = economic_digest(&format!("assignment-disposition-{suffix}-1"));
    let settlement_digest = economic_digest(&format!("assignment-settlement-{suffix}-1"));
    let head_digest = economic_digest(&format!("assignment-head-{suffix}-1"));
    let mut connection = fixture.store.connection()?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    transaction.execute(
        r#"
        INSERT INTO admission_operation_terminal_projections (
            operation_id, source_operation_version, terminal_operation_version,
            terminal_state, projection_body_digest, projection_digest,
            projection_json, manifest_json, record_count, committed_at_unix_ms,
            store_uuid, store_lease_id, store_owner_epoch
        ) VALUES (?1, 1, 2, 'completed', ?2, ?3, X'01', X'01', 1, ?4, ?5, ?6, ?7)
        "#,
        params![
            operation_id,
            economic_digest(&format!("assignment-projection-body-{suffix}")),
            economic_digest(&format!("assignment-projection-{suffix}")),
            i64::try_from(committed_at_unix_ms)?,
            &fixture.fence.store_uuid,
            &fixture.fence.lease_id,
            i64::try_from(fixture.fence.owner_epoch)?,
        ],
    )?;
    transaction.execute(
        r#"
        INSERT INTO obligation_atoms (
            obligation_id, operation_id, atom_digest, source_receipt_id,
            source_receipt_digest, atom_json, committed_at_unix_ms,
            store_uuid, store_lease_id, store_owner_epoch
        ) VALUES (?1, ?2, ?3, ?4, ?5, X'01', ?6, ?7, ?8, ?9)
        "#,
        params![
            &obligation_id,
            operation_id,
            &atom_digest,
            format!("assignment-receipt-{suffix}"),
            economic_digest(&format!("assignment-receipt-{suffix}")),
            i64::try_from(committed_at_unix_ms)?,
            &fixture.fence.store_uuid,
            &fixture.fence.lease_id,
            i64::try_from(fixture.fence.owner_epoch)?,
        ],
    )?;
    transaction.execute(
        r#"
        INSERT INTO obligation_disposition_records (
            obligation_id, version, lifecycle_fence, atom_digest,
            disposition_digest, operation_id, record_json, committed_at_unix_ms,
            store_uuid, store_lease_id, store_owner_epoch
        ) VALUES (?1, 1, 1, ?2, ?3, ?4, X'01', ?5, ?6, ?7, ?8)
        "#,
        params![
            &obligation_id,
            &atom_digest,
            &disposition_digest,
            operation_id,
            i64::try_from(committed_at_unix_ms)?,
            &fixture.fence.store_uuid,
            &fixture.fence.lease_id,
            i64::try_from(fixture.fence.owner_epoch)?,
        ],
    )?;
    transaction.execute(
        r#"
        INSERT INTO obligation_settlement_lifecycle_records (
            obligation_id, version, lifecycle_fence, atom_digest,
            lifecycle_digest, operation_id, record_json, committed_at_unix_ms,
            store_uuid, store_lease_id, store_owner_epoch
        ) VALUES (?1, 1, 1, ?2, ?3, ?4, X'01', ?5, ?6, ?7, ?8)
        "#,
        params![
            &obligation_id,
            &atom_digest,
            &settlement_digest,
            operation_id,
            i64::try_from(committed_at_unix_ms)?,
            &fixture.fence.store_uuid,
            &fixture.fence.lease_id,
            i64::try_from(fixture.fence.owner_epoch)?,
        ],
    )?;
    transaction.execute(
        r#"
        INSERT INTO obligation_head_commits (
            obligation_id, head_sequence, previous_head_digest, head_digest,
            atom_digest, disposition_version, disposition_lifecycle_fence,
            disposition_digest, settlement_version, settlement_lifecycle_fence,
            settlement_lifecycle_digest, snapshot_version, resource_fence,
            source_kind, source_operation_id, participant_digest,
            participant_commit_sequence, committed_at_unix_ms,
            store_uuid, store_lease_id, store_owner_epoch
        ) VALUES (
            ?1, 1, ?2, ?3, ?4, 1, 1, ?5, 1, 1, ?6, 1, 1,
            'initial_projection', ?7, NULL, NULL, ?8, ?9, ?10, ?11
        )
        "#,
        params![
            &obligation_id,
            GENESIS_CHAIN_DIGEST,
            &head_digest,
            &atom_digest,
            &disposition_digest,
            &settlement_digest,
            operation_id,
            i64::try_from(committed_at_unix_ms)?,
            &fixture.fence.store_uuid,
            &fixture.fence.lease_id,
            i64::try_from(fixture.fence.owner_epoch)?,
        ],
    )?;
    transaction.execute(
        r#"
        INSERT INTO obligation_heads (
            obligation_id, head_sequence, head_digest, atom_digest,
            disposition_version, disposition_lifecycle_fence,
            settlement_version, settlement_lifecycle_fence,
            snapshot_version, resource_fence, updated_at_unix_ms,
            store_uuid, store_lease_id, store_owner_epoch
        ) VALUES (?1, 1, ?2, ?3, 1, 1, 1, 1, 1, 1, ?4, ?5, ?6, ?7)
        "#,
        params![
            &obligation_id,
            &head_digest,
            &atom_digest,
            i64::try_from(committed_at_unix_ms)?,
            &fixture.fence.store_uuid,
            &fixture.fence.lease_id,
            i64::try_from(fixture.fence.owner_epoch)?,
        ],
    )?;
    fixture.store.commit_write(transaction)?;
    fixture.store.sync_after_write(&connection)?;
    Ok(SqlObligationHead {
        obligation_id,
        atom_digest,
        settlement_digest,
        head_digest,
    })
}

fn seed_sql_assignment_participant(
    fixture: &Fixture,
    suffix: &str,
    begun_at_unix_ms: u64,
) -> AnchoredTestResult<SqlAssignmentParticipant> {
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::GovernedEconomicMutation,
        &format!("assignment-request-{suffix}"),
        &format!("assignment-capability-{suffix}"),
    );
    fixture
        .store
        .begin(&operation, &fixture.fence, begun_at_unix_ms)?;
    let recovery = claim(
        fixture,
        &operation,
        &format!("assignment-worker-{suffix}"),
        begun_at_unix_ms + 1,
    );
    let participant_digest = economic_digest(&format!("assignment-participant-{suffix}"));
    let committed_at_unix_ms = begun_at_unix_ms + 2;
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
        committed_at_unix_ms,
    )?;
    let commit_sequence = transaction.query_row(
        r#"
        SELECT commit_sequence
        FROM admission_operation_commits
        WHERE operation_id = ?1
          AND mutation_kind = 'participant_update'
          AND participant_digest = ?2
        "#,
        params![
            operation.binding().operation_id().as_str(),
            &participant_digest
        ],
        |row| row.get(0),
    )?;
    fixture.store.commit_write(transaction)?;
    fixture.store.sync_after_write(&connection)?;
    Ok(SqlAssignmentParticipant {
        operation_id: operation.binding().operation_id().as_str().to_owned(),
        participant_digest,
        commit_sequence,
        committed_at_unix_ms,
    })
}

fn advance_sql_obligation_head(
    fixture: &Fixture,
    head: &SqlObligationHead,
    participant: &SqlAssignmentParticipant,
) -> AnchoredTestResult<String> {
    let resulting_disposition_digest =
        economic_digest(&format!("{}-disposition-2", participant.operation_id));
    let resulting_head_digest = economic_digest(&format!("{}-head-2", participant.operation_id));
    let mut connection = fixture.store.connection()?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    transaction.execute(
        r#"
        INSERT INTO obligation_disposition_records (
            obligation_id, version, lifecycle_fence, atom_digest,
            disposition_digest, operation_id, record_json, committed_at_unix_ms,
            store_uuid, store_lease_id, store_owner_epoch
        ) VALUES (?1, 2, 2, ?2, ?3, ?4, X'02', ?5, ?6, ?7, ?8)
        "#,
        params![
            &head.obligation_id,
            &head.atom_digest,
            &resulting_disposition_digest,
            &participant.operation_id,
            i64::try_from(participant.committed_at_unix_ms)?,
            &fixture.fence.store_uuid,
            &fixture.fence.lease_id,
            i64::try_from(fixture.fence.owner_epoch)?,
        ],
    )?;
    transaction.execute(
        r#"
        INSERT INTO obligation_head_commits (
            obligation_id, head_sequence, previous_head_digest, head_digest,
            atom_digest, disposition_version, disposition_lifecycle_fence,
            disposition_digest, settlement_version, settlement_lifecycle_fence,
            settlement_lifecycle_digest, snapshot_version, resource_fence,
            source_kind, source_operation_id, participant_digest,
            participant_commit_sequence, committed_at_unix_ms,
            store_uuid, store_lease_id, store_owner_epoch
        ) VALUES (
            ?1, 2, ?2, ?3, ?4, 2, 2, ?5, 1, 1, ?6, 2, 2,
            'disposition_transition', ?7, ?8, ?9, ?10, ?11, ?12, ?13
        )
        "#,
        params![
            &head.obligation_id,
            &head.head_digest,
            &resulting_head_digest,
            &head.atom_digest,
            &resulting_disposition_digest,
            &head.settlement_digest,
            &participant.operation_id,
            &participant.participant_digest,
            participant.commit_sequence,
            i64::try_from(participant.committed_at_unix_ms)?,
            &fixture.fence.store_uuid,
            &fixture.fence.lease_id,
            i64::try_from(fixture.fence.owner_epoch)?,
        ],
    )?;
    transaction.execute(
        r#"
        UPDATE obligation_heads
        SET head_sequence = 2, head_digest = ?1,
            disposition_version = 2, disposition_lifecycle_fence = 2,
            snapshot_version = 2, resource_fence = 2,
            updated_at_unix_ms = ?2,
            store_uuid = ?3, store_lease_id = ?4, store_owner_epoch = ?5
        WHERE obligation_id = ?6
        "#,
        params![
            &resulting_head_digest,
            i64::try_from(participant.committed_at_unix_ms)?,
            &fixture.fence.store_uuid,
            &fixture.fence.lease_id,
            i64::try_from(fixture.fence.owner_epoch)?,
            &head.obligation_id,
        ],
    )?;
    fixture.store.commit_write(transaction)?;
    fixture.store.sync_after_write(&connection)?;
    Ok(resulting_head_digest)
}

fn insert_sql_assignment_result(
    connection: &Connection,
    fixture: &Fixture,
    head: &SqlObligationHead,
    participant: &SqlAssignmentParticipant,
    outcome: &str,
    resulting_head_sequence: i64,
    resulting_head_digest: &str,
) -> rusqlite::Result<usize> {
    let authority_set_digest = economic_digest("schema-factor-authority-set");
    connection.execute(
        r#"
        INSERT INTO factor_assignment_authority_sets (
            generation, active_set_digest, previous_active_set_digest,
            activated_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch
        )
        SELECT 1, ?1, NULL, ?2, ?3, ?4, ?5
        WHERE NOT EXISTS (SELECT 1 FROM factor_assignment_authority_sets)
        "#,
        params![
            &authority_set_digest,
            i64::try_from(participant.committed_at_unix_ms)
                .map_err(|error| { rusqlite::Error::ToSqlConversionFailure(Box::new(error)) })?,
            &fixture.fence.store_uuid,
            &fixture.fence.lease_id,
            i64::try_from(fixture.fence.owner_epoch)
                .map_err(|error| { rusqlite::Error::ToSqlConversionFailure(Box::new(error)) })?,
        ],
    )?;
    connection.execute(
        r#"
        INSERT INTO obligation_assignment_results (
            operation_id, obligation_id, obligation_atom_digest, outcome,
            authority_set_generation, authority_set_digest,
            authority_configuration_digest,
            normalized_request_digest, normalized_request_json,
            claim_digest, claim_json, receipt_digest, receipt_json,
            iou_digest, iou_json, offer_digest, offer_json,
            bind_authorization_body_digest, bind_authorization_envelope_digest,
            bind_authorization_json, agreement_body_digest,
            agreement_artifact_digest, agreement_seller_signature_digest,
            agreement_buyer_signature_digest, agreement_json,
            assignment_authorization_set_digest, status_proof_body_digest,
            status_proof_envelope_digest, status_proof_json,
            result_id, result_body_digest, result_envelope_digest,
            result_signature_digest, result_json,
            observed_head_sequence, observed_head_digest,
            resulting_head_sequence, resulting_head_digest,
            participant_digest, participant_commit_sequence,
            store_uuid, store_lease_id, store_owner_epoch
        ) VALUES (
            ?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, X'01', ?8, X'02',
            ?9, X'08', ?10, X'09', ?11, X'03', ?12, ?13, X'04',
            ?14, ?15, ?16, ?17, X'05', ?18, ?19, ?20, X'06',
            ?21, ?22, ?23, ?24, X'07', 1, ?25, ?26, ?27, ?28,
            ?29, ?30, ?31, ?32
        )
        "#,
        params![
            &participant.operation_id,
            &head.obligation_id,
            &head.atom_digest,
            outcome,
            &authority_set_digest,
            economic_digest(&format!("{}-authority-config", participant.operation_id)),
            economic_digest(&format!("{}-request", participant.operation_id)),
            economic_digest(&format!("{}-claim", participant.operation_id)),
            economic_digest(&format!("{}-receipt", participant.operation_id)),
            economic_digest(&format!("{}-iou", participant.operation_id)),
            economic_digest(&format!("{}-offer", participant.operation_id)),
            economic_digest(&format!("{}-bind-body", participant.operation_id)),
            economic_digest(&format!("{}-bind-envelope", participant.operation_id)),
            economic_digest(&format!("{}-agreement-body", participant.operation_id)),
            economic_digest(&format!("{}-agreement", participant.operation_id)),
            economic_digest(&format!("{}-seller-signature", participant.operation_id)),
            economic_digest(&format!("{}-buyer-signature", participant.operation_id)),
            economic_digest(&format!("{}-authorization-set", participant.operation_id)),
            economic_digest(&format!("{}-status-body", participant.operation_id)),
            economic_digest(&format!("{}-status-envelope", participant.operation_id)),
            economic_digest(&format!("{}-result-id", participant.operation_id)),
            economic_digest(&format!("{}-result-body", participant.operation_id)),
            economic_digest(&format!("{}-result-envelope", participant.operation_id)),
            economic_digest(&format!("{}-result-signature", participant.operation_id)),
            &head.head_digest,
            resulting_head_sequence,
            resulting_head_digest,
            &participant.participant_digest,
            participant.commit_sequence,
            &fixture.fence.store_uuid,
            &fixture.fence.lease_id,
            i64::try_from(fixture.fence.owner_epoch)
                .map_err(|error| { rusqlite::Error::ToSqlConversionFailure(Box::new(error)) })?,
        ],
    )
}

#[test]
#[allow(
    clippy::type_complexity,
    reason = "The tuple preserves the complete typed database row at this existing storage boundary."
)]
fn fresh_provision_creates_the_operation_schema_after_serving_lease_schema() {
    let fixture = fixture();
    let connection = fixture.store.connection().expect("connection");
    let (
        version,
        head,
        high_water,
        lease_table,
        lifecycle_table,
        obligation_head_commit_table,
        obligation_head_table,
        obligation_assignment_result_table,
        assignment_evidence_columns,
        assignment_result_triggers,
        assignment_participant_fk,
        assignment_participant_unique,
        disposition_fk,
    ): (
        i64,
        i64,
        i64,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
    ) = connection
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
                ),
                EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table'
                      AND name = 'obligation_settlement_lifecycle_records'
                ),
                EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table' AND name = 'obligation_head_commits'
                ),
                EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table' AND name = 'obligation_heads'
                ),
                EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table'
                      AND name = 'obligation_assignment_results'
                ),
                (SELECT COUNT(*) = 5
                 FROM pragma_table_info('obligation_assignment_results')
                 WHERE name IN (
                    'authority_configuration_digest', 'receipt_digest',
                    'receipt_json', 'iou_digest', 'iou_json'
                 )),
                (SELECT COUNT(*) = 6 FROM sqlite_master
                 WHERE type = 'trigger'
                   AND tbl_name = 'obligation_assignment_results'),
                EXISTS(
                    SELECT 1
                    FROM pragma_foreign_key_list('obligation_assignment_results')
                    WHERE "table" = 'admission_operation_commits'
                      AND "from" = 'participant_commit_sequence'
                ),
                EXISTS(
                    SELECT 1
                    FROM pragma_index_list('obligation_assignment_results')
                    WHERE "unique" = 1 AND origin = 'u'
                ),
                EXISTS(
                    SELECT 1
                    FROM pragma_foreign_key_list('obligation_disposition_records')
                    WHERE "table" = 'admission_operations'
                )
            "#,
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                ))
            },
        )
        .expect("schema projection");
    assert_eq!(
        version,
        i64::from(ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)
    );
    assert_eq!(head, 0);
    assert_eq!(high_water, 0);
    assert!(lease_table);
    assert!(lifecycle_table);
    assert!(obligation_head_commit_table);
    assert!(obligation_head_table);
    assert!(obligation_assignment_result_table);
    assert!(assignment_evidence_columns);
    assert!(assignment_result_triggers);
    assert!(assignment_participant_fk);
    assert!(assignment_participant_unique);
    assert!(disposition_fk);
    verify_admission_operation_invariants(&connection).expect("fresh invariants");
}

#[test]
fn current_schema_reopen_rejects_assignment_results_without_evidence_columns() -> AnchoredTestResult
{
    let fixture = fixture();
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
        DROP TRIGGER obligation_assignment_results_fence_later_head;
        DROP TABLE obligation_assignment_results;
        CREATE TABLE obligation_assignment_results (
            operation_id TEXT NOT NULL PRIMARY KEY,
            claim_digest TEXT NOT NULL,
            claim_json BLOB NOT NULL
        );
        "#,
    )?;
    drop(connection);
    let error = match crate::test_authority::open_serving(&database, &lock_root) {
        Ok(_) => return Err("incomplete current assignment schema was accepted".into()),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("schema differs from the canonical definition"));
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

#[test]
#[allow(
    clippy::type_complexity,
    reason = "The tuple preserves the complete typed database row at this existing storage boundary."
)]
fn not_applied_assignment_result_retains_exact_artifacts_and_head() -> AnchoredTestResult {
    let fixture = fixture();
    let at = now_ms();
    let head = seed_sql_obligation_head(&fixture, "not-applied", at)?;
    let participant = seed_sql_assignment_participant(&fixture, "not-applied", at + 10)?;
    let connection = fixture.store.connection()?;

    assert_eq!(
        insert_sql_assignment_result(
            &connection,
            &fixture,
            &head,
            &participant,
            "not_applied",
            1,
            &head.head_digest,
        )?,
        1
    );
    let artifacts: (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) = connection.query_row(
        r#"
        SELECT normalized_request_json, claim_json, receipt_json, iou_json, offer_json,
               bind_authorization_json, agreement_json, status_proof_json,
               result_json
        FROM obligation_assignment_results
        WHERE operation_id = ?1
        "#,
        [&participant.operation_id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
            ))
        },
    )?;
    assert_eq!(
        artifacts,
        (
            vec![1],
            vec![2],
            vec![8],
            vec![9],
            vec![3],
            vec![4],
            vec![5],
            vec![6],
            vec![7],
        )
    );
    assert!(connection
        .execute(
            "UPDATE obligation_assignment_results SET result_json = X'08' WHERE operation_id = ?1",
            [&participant.operation_id],
        )
        .is_err());
    assert!(connection
        .execute(
            "DELETE FROM obligation_assignment_results WHERE operation_id = ?1",
            [&participant.operation_id],
        )
        .is_err());
    drop(connection);

    let error = advance_sql_obligation_head(&fixture, &head, &participant)
        .expect_err("not-applied operation must not advance an obligation head");
    assert!(error
        .to_string()
        .contains("not-applied assignment operation"));

    let contender = seed_sql_assignment_participant(&fixture, "wrong-head", at + 20)?;
    let connection = fixture.store.connection()?;
    assert!(insert_sql_assignment_result(
        &connection,
        &fixture,
        &head,
        &contender,
        "applied",
        2,
        &economic_digest("missing-resulting-head"),
    )
    .is_err());
    let wrong_participant = SqlAssignmentParticipant {
        operation_id: contender.operation_id.clone(),
        participant_digest: economic_digest("wrong-participant-digest"),
        commit_sequence: contender.commit_sequence,
        committed_at_unix_ms: contender.committed_at_unix_ms,
    };
    assert!(insert_sql_assignment_result(
        &connection,
        &fixture,
        &head,
        &wrong_participant,
        "not_applied",
        1,
        &head.head_digest,
    )
    .is_err());
    drop(connection);

    let fenced = seed_sql_assignment_participant(&fixture, "closed-lease", at + 30)?;
    let connection = fixture.store.connection()?;
    connection.execute(
        r#"
        UPDATE chio_serving_leases
        SET end_head_index = start_head_index
        WHERE store_uuid = ?1 AND owner_epoch = ?2
        "#,
        params![
            &fixture.fence.store_uuid,
            i64::try_from(fixture.fence.owner_epoch)?,
        ],
    )?;
    let error = insert_sql_assignment_result(
        &connection,
        &fixture,
        &head,
        &fenced,
        "not_applied",
        1,
        &head.head_digest,
    )
    .expect_err("closed serving lease must fence assignment result");
    assert!(error.to_string().contains("exact serving lease"));
    Ok(())
}

#[test]
fn applied_assignment_result_requires_the_exact_participant_head() -> AnchoredTestResult {
    let fixture = fixture();
    let at = now_ms();
    let head = seed_sql_obligation_head(&fixture, "applied", at)?;
    let participant = seed_sql_assignment_participant(&fixture, "applied", at + 10)?;
    let resulting_head_digest = advance_sql_obligation_head(&fixture, &head, &participant)?;
    let connection = fixture.store.connection()?;

    assert_eq!(
        insert_sql_assignment_result(
            &connection,
            &fixture,
            &head,
            &participant,
            "applied",
            2,
            &resulting_head_digest,
        )?,
        1
    );
    let stored: (String, i64, String, i64) = connection.query_row(
        r#"
        SELECT outcome, resulting_head_sequence, resulting_head_digest,
               participant_commit_sequence
        FROM obligation_assignment_results
        WHERE operation_id = ?1
        "#,
        [&participant.operation_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(
        stored,
        (
            "applied".to_owned(),
            2,
            resulting_head_digest.clone(),
            participant.commit_sequence,
        )
    );
    drop(connection);

    let contender = seed_sql_assignment_participant(&fixture, "applied-contender", at + 20)?;
    let connection = fixture.store.connection()?;
    assert!(insert_sql_assignment_result(
        &connection,
        &fixture,
        &head,
        &contender,
        "applied",
        2,
        &resulting_head_digest,
    )
    .is_err());
    Ok(())
}

#[test]
fn admission_schema_other_than_current_is_refused() -> AnchoredTestResult {
    for stamped in [0, 2, 38] {
        let fixture = fixture();
        let mut connection = fixture.store.connection()?;
        crate::test_schema::write_version(&connection, "admission_operation", stamped)?;
        let error = crate::test_schema::apply(
            &mut connection,
            crate::serving_owner::SERVING_NAMESPACES,
            initialize_admission_operation_schema,
            |error| invariant(error.to_string()),
        )
        .err()
        .ok_or("stale admission schema opened")?;
        assert_eq!(
            error.to_string(),
            format!(
                "admission operation invariant failed: database schema version {stamped} is not the current schema version 1; refusing to open"
            )
        );
    }
    Ok(())
}

#[test]
fn unstamped_provisioned_admission_store_is_refused() -> AnchoredTestResult {
    let fixture = fixture();
    let mut connection = fixture.store.connection()?;
    connection.execute(
        "DELETE FROM chio_store_schema_versions WHERE store_key = 'admission_operation'",
        [],
    )?;
    let error = crate::test_schema::apply(
        &mut connection,
        crate::serving_owner::SERVING_NAMESPACES,
        initialize_admission_operation_schema,
        |error| invariant(error.to_string()),
    )
    .err()
    .ok_or("unstamped admission schema opened")?;
    assert_eq!(
        error.to_string(),
        "admission operation invariant failed: schema namespace admission_operation is missing"
    );
    Ok(())
}

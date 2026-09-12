use super::*;

mod clock;
mod migration_v17;
mod migration_v19;
mod migration_v20;
mod migration_v21;
mod migration_v22;
mod migration_v23;
mod migration_v24;
mod migration_v25;
mod migration_v26;
mod migration_v27;
mod migration_v28;
mod migration_v29;
mod migration_v30;
mod migration_v31;
mod migration_v32;
mod migration_v33;

#[cfg(test)]
pub(crate) fn pre_dpop_claim_schema_fixture() -> String {
    migration_v26::predecessor_admission_schema()
}

#[cfg(test)]
pub(super) fn pre_dpop_activation_schema_fixture() -> String {
    migration_v25::predecessor_schema()
}

#[cfg(test)]
pub(super) fn pre_approval_claim_schema_fixture() -> String {
    migration_v23::predecessor_admission_schema()
}

#[cfg(test)]
pub(super) fn pre_approval_activation_schema_fixture() -> String {
    migration_v23::predecessor_approval_schema()
}
pub(crate) use clock::verify_trusted_time;
pub(super) use clock::{authority_validation_time, observe_authority_time};

#[cfg(test)]
pub(super) fn pre_runtime_claim_schema_fixture() -> String {
    migration_v20::predecessor_schema()
}

#[cfg(test)]
pub(super) fn pre_runtime_activation_schema_fixture() -> String {
    migration_v21::predecessor_schema()
}

pub(crate) fn initialize_admission_operation_schema(
    connection: &mut Connection,
) -> Result<(), AdmissionOperationStoreError> {
    crate::security_state::deny_native_mutations(connection).map_err(sqlite_error)?;
    let on_disk = crate::check_schema_version(
        connection,
        ADMISSION_OPERATION_SCHEMA_KEY,
        ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION,
        ADMISSION_OPERATION_SCHEMA_ANCHORS,
    )
    .map_err(|error| invariant(error.to_string()))?;
    if on_disk == ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION {
        return verify_admission_operation_invariants(connection);
    }
    migration_v17::preserving_parent_names(connection, |connection| {
        migrate_schema(connection, on_disk)
    })
}

fn migrate_schema(
    connection: &mut Connection,
    on_disk: i32,
) -> Result<(), AdmissionOperationStoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error)?;
    if on_disk < 19 {
        migration_v19::verify_pre_migration_schema(&transaction, on_disk)?;
    }
    if on_disk < 20 {
        migration_v20::verify_pre_migration_schema(&transaction, on_disk)?;
    }
    if on_disk < 21 {
        migration_v21::verify_pre_migration_schema(&transaction, on_disk)?;
    }
    if on_disk < 22 {
        migration_v22::verify_pre_migration_schema(&transaction, on_disk)?;
    }
    if on_disk < 23 {
        migration_v23::verify_pre_migration_schema(&transaction, on_disk)?;
    }
    if on_disk < 24 {
        migration_v24::verify_pre_migration_schema(&transaction, on_disk)?;
    }
    if on_disk < 25 {
        migration_v25::verify_pre_migration_schema(&transaction, on_disk)?;
    }
    if on_disk < 26 {
        migration_v26::verify_pre_migration_schema(&transaction, on_disk)?;
    }
    if on_disk < 27 {
        migration_v27::verify_pre_migration_schema(&transaction, on_disk)?;
    }
    if on_disk < 28 {
        migration_v28::verify_pre_migration_schema(&transaction, on_disk)?;
    }
    if on_disk < 29 {
        migration_v29::verify_pre_migration_schema(&transaction, on_disk)?;
    }
    if on_disk < 30 {
        migration_v30::verify_pre_migration_schema(&transaction, on_disk)?;
    }
    if on_disk < 31 {
        migration_v31::verify_pre_migration_schema(&transaction, on_disk)?;
    }
    if on_disk < 32 {
        migration_v32::verify_pre_migration_schema(&transaction, on_disk)?;
    }
    migration_v33::verify_pre_migration_schema(&transaction, on_disk)?;
    if on_disk < 18 && table_exists(&transaction, "admission_operations")? {
        // The legacy report-after-effect contract could refund an executed
        // caller as pre-dispatch compensation. A refunded terminal is not
        // authoritative evidence that the external executor never acted.
        let ambiguous_callers: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM admission_operations AS operation,
                json_each(operation.operation_json, '$.attachments') AS attachment
             WHERE (operation.terminal = 0 OR operation.state IN (
                    'compensated_before_dispatch', 'not_accepted_after_dispatch_commit',
                    'denied_after_delivery'))
               AND json_extract(attachment.value, '$.BrokerAttempt.transport_id') LIKE 'caller-report:%')",
            [], |row| row.get(0),
        ).map_err(sqlite_error)?;
        if ambiguous_callers {
            return Err(invariant("legacy caller reservations require authoritative external-effect reconciliation before schema migration"));
        }
    }
    if on_disk < 9 && table_exists(&transaction, "threshold_approval_tokens")? {
        migrate_threshold_approval_token_scope(&transaction)?;
    }
    if obligation_disposition_references_terminal_projection(&transaction)? {
        migrate_obligation_lifecycle_foundation(&transaction)?;
    }
    if on_disk == 2 {
        migrate_admission_commit_participant_digest(&transaction)?;
    }
    if on_disk == 3 {
        migrate_admission_commit_begin_participant_digest(&transaction)?;
    }
    if matches!(on_disk, 1 | 4) {
        migrate_admission_commit_channel_reservation_kind(&transaction)?;
    }
    if matches!(on_disk, 2 | 3) {
        migrate_terminal_record_kinds(&transaction)?;
    }
    migration_v17::migrate_commit_observation_clock(&transaction)?;
    migration_v20::migrate_commit_kinds(&transaction)?;
    if on_disk < 21 {
        migration_v21::migrate_activation_event(&transaction)?;
    }
    if on_disk < 23 {
        migration_v23::migrate(&transaction)?;
    }
    if on_disk < 25 {
        migration_v25::migrate(&transaction)?;
    }
    if on_disk < 26 {
        migration_v26::migrate(&transaction)?;
    }
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(include_str!("../admission_operation_nonce.sql"))
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(include_str!("../admission_operation_nonce_preflight.sql"))
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(RUNTIME_REPLAY_MIGRATION_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(RUNTIME_PARTICIPANT_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(GOVERNED_APPROVAL_REPLAY_MIGRATION_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(GOVERNED_APPROVAL_CLAIM_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(DPOP_REPLAY_MIGRATION_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(DPOP_AUTHORITY_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(DPOP_CLAIM_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(SECURITY_PARTICIPANT_MIGRATION_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(&super::security_participant_state::schema::sql()?)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(super::security_participant_state::egress::sql())
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(super::security_participant_state::dispatch_ledger::sql())
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(super::security_participant_state::output::sql())
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(super::security_participant_state::nonce_preflight::sql())
        .map_err(sqlite_error)?;
    crate::stamp_schema_version(
        &transaction,
        ADMISSION_OPERATION_SCHEMA_KEY,
        ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION,
    )
    .map_err(|error| invariant(error.to_string()))?;
    verify_admission_operation_invariants(&transaction)?;
    let foreign_key_violation: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if foreign_key_violation {
        return Err(invariant("admission schema migration broke a foreign key"));
    }
    transaction.commit().map_err(sqlite_error)
}

fn table_exists(
    transaction: &Transaction<'_>,
    table_name: &str,
) -> Result<bool, AdmissionOperationStoreError> {
    transaction
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = ?1
            )
            "#,
            [table_name],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn migrate_threshold_approval_token_scope(
    transaction: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    transaction
        .execute_batch(
            r#"
            DROP TRIGGER IF EXISTS threshold_approval_tokens_immutable;
            DROP TRIGGER IF EXISTS threshold_approval_tokens_no_delete;
            ALTER TABLE threshold_approval_tokens
                RENAME TO threshold_approval_tokens_v8;
            CREATE TABLE threshold_approval_tokens (
                proposal_id TEXT NOT NULL,
                token_id TEXT NOT NULL
                    CHECK (length(token_id) BETWEEN 1 AND 512),
                approver_fingerprint TEXT NOT NULL
                    CHECK (approver_fingerprint <> ''),
                canonical_token_digest TEXT NOT NULL UNIQUE CHECK (
                    length(canonical_token_digest) = 64
                    AND canonical_token_digest NOT GLOB '*[^0-9a-f]*'
                ),
                token_json BLOB NOT NULL
                    CHECK (length(token_json) BETWEEN 1 AND 262144),
                PRIMARY KEY (proposal_id, token_id),
                UNIQUE (proposal_id, approver_fingerprint),
                UNIQUE (proposal_id, canonical_token_digest),
                FOREIGN KEY (proposal_id)
                    REFERENCES threshold_approval_proposals(proposal_id)
            );
            INSERT INTO threshold_approval_tokens (
                proposal_id, token_id, approver_fingerprint,
                canonical_token_digest, token_json
            )
            SELECT proposal_id, token_id, approver_fingerprint,
                   canonical_token_digest, token_json
            FROM threshold_approval_tokens_v8;
            DROP TABLE threshold_approval_tokens_v8;
            "#,
        )
        .map_err(sqlite_error)
}

fn obligation_disposition_references_terminal_projection(
    transaction: &Transaction<'_>,
) -> Result<bool, AdmissionOperationStoreError> {
    transaction
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM pragma_foreign_key_list('obligation_disposition_records')
                WHERE "table" = 'admission_operation_terminal_projections'
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn migrate_obligation_lifecycle_foundation(
    transaction: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    let obligation_count: i64 = transaction
        .query_row("SELECT COUNT(*) FROM obligation_atoms", [], |row| {
            row.get(0)
        })
        .map_err(sqlite_error)?;
    if obligation_count != 0 {
        return Err(invariant(
            "populated admission schema v5 requires offline authoritative settlement reconciliation",
        ));
    }
    transaction
        .execute_batch(
            r#"
            DROP TRIGGER obligation_disposition_records_exact_lease;
            DROP TRIGGER obligation_disposition_records_immutable;
            DROP TRIGGER obligation_disposition_records_no_delete;
            DROP INDEX obligation_disposition_records_operation;
            ALTER TABLE obligation_disposition_records
                RENAME TO obligation_disposition_records_v5;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(
            r#"
            DROP TRIGGER obligation_settlement_lifecycle_records_exact_lease;
            DROP TRIGGER obligation_heads_exact_lease_insert;
            DROP TRIGGER obligation_heads_exact_lease_update;
            DROP TRIGGER obligation_disposition_records_exact_lease;
            INSERT INTO obligation_disposition_records (
                obligation_id, version, lifecycle_fence, atom_digest,
                disposition_digest, operation_id, record_json, committed_at_unix_ms,
                store_uuid, store_lease_id, store_owner_epoch
            )
            SELECT obligation_id, version, lifecycle_fence, atom_digest,
                   disposition_digest, operation_id, record_json, committed_at_unix_ms,
                   store_uuid, store_lease_id, store_owner_epoch
            FROM obligation_disposition_records_v5
            ORDER BY obligation_id, version;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(
            r#"
            DROP TABLE obligation_disposition_records_v5;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)
}

fn migrate_terminal_record_kinds(
    transaction: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    transaction
        .execute_batch(
            r#"
            DROP TRIGGER IF EXISTS admission_operation_terminal_records_immutable;
            DROP TRIGGER IF EXISTS admission_operation_terminal_records_no_delete;
            DROP INDEX IF EXISTS admission_operation_terminal_records_kind;
            ALTER TABLE admission_operation_terminal_records
                RENAME TO admission_operation_terminal_records_v3;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(
            r#"
            INSERT INTO admission_operation_terminal_records (
                operation_id, record_kind, record_id, record_digest, record_json
            )
            SELECT operation_id, record_kind, record_id, record_digest, record_json
            FROM admission_operation_terminal_records_v3;
            DROP TABLE admission_operation_terminal_records_v3;
            "#,
        )
        .map_err(sqlite_error)
}

fn migrate_admission_commit_participant_digest(
    transaction: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    transaction
        .execute_batch(
            r#"
            DROP TRIGGER admission_operation_commits_exact_lease;
            DROP TRIGGER admission_operation_commits_immutable;
            DROP TRIGGER admission_operation_commits_no_delete;
            DROP INDEX admission_operation_commits_operation;
            ALTER TABLE admission_operation_commits
                RENAME TO admission_operation_commits_v2;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch("DROP TRIGGER admission_operation_commits_exact_lease;")
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(
            r#"
            INSERT INTO admission_operation_commits (
                commit_sequence, operation_id, operation_version, mutation_kind,
                operation_digest, recovery_claim_digest, participant_digest,
                previous_chain_digest, chain_digest,
                store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
            )
            SELECT commit_sequence, operation_id, operation_version, mutation_kind,
                   operation_digest, recovery_claim_digest, NULL,
                   previous_chain_digest, chain_digest,
                   store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
            FROM admission_operation_commits_v2
            ORDER BY commit_sequence;
            DROP TABLE admission_operation_commits_v2;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)
}

fn migrate_admission_commit_begin_participant_digest(
    transaction: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    transaction
        .execute_batch(
            r#"
            DROP TRIGGER admission_operation_commits_exact_lease;
            DROP TRIGGER admission_operation_commits_immutable;
            DROP TRIGGER admission_operation_commits_no_delete;
            DROP INDEX admission_operation_commits_operation;
            ALTER TABLE admission_operation_commits
                RENAME TO admission_operation_commits_v3;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch("DROP TRIGGER admission_operation_commits_exact_lease;")
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(
            r#"
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
            FROM admission_operation_commits_v3
            ORDER BY commit_sequence;
            DROP TABLE admission_operation_commits_v3;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)
}

fn migrate_admission_commit_channel_reservation_kind(
    transaction: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    transaction
        .execute_batch(
            r#"
            DROP TRIGGER admission_operation_commits_exact_lease;
            DROP TRIGGER admission_operation_commits_immutable;
            DROP TRIGGER admission_operation_commits_no_delete;
            DROP INDEX admission_operation_commits_operation;
            ALTER TABLE admission_operation_commits
                RENAME TO admission_operation_commits_v4;
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch("DROP TRIGGER admission_operation_commits_exact_lease;")
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(
            r#"
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
            "#,
        )
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)
}

pub(crate) fn verify_admission_operation_invariants(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    verify_admission_operation_schema(connection, ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)?;

    verify_admission_operation_data_invariants(connection)?;
    super::runtime_participant::verify_all(connection)?;
    super::governed_approval_claim::verify_all(connection)?;
    super::dpop_claim::verify_all(connection)?;
    super::governed_approval_replay::verify_all_records(connection)
        .map(|_| ())
        .map_err(invariant)?;
    super::dpop_replay::verify_all_records(connection)
        .map(|_| ())
        .map_err(invariant)?;
    super::security_participant_migration::verify_all(connection)?;
    super::security_participant_state::egress::verify_catalog(connection)?;
    super::security_participant_state::output::verify_catalog(connection)?;
    super::security_participant_state::nonce_preflight::verify_catalog(connection)?;
    super::security_participant_state::dispatch_ledger::verify_all(connection)?;
    super::security_participant_state::verify_all(connection).map(|_| ())
}

fn verify_admission_operation_schema(
    connection: &Connection,
    version: i32,
) -> Result<(), AdmissionOperationStoreError> {
    let expected = Connection::open_in_memory().map_err(sqlite_error)?;
    expected
        .execute_batch(&if version < 20 {
            migration_v20::predecessor_schema()
        } else if version < 23 {
            migration_v23::predecessor_admission_schema()
        } else if version < 26 {
            migration_v26::predecessor_admission_schema()
        } else {
            ADMISSION_OPERATION_SCHEMA.to_owned()
        })
        .map_err(sqlite_error)?;
    if version >= 19 {
        expected
            .execute_batch(&if version < 21 {
                migration_v21::predecessor_schema()
            } else {
                RUNTIME_REPLAY_MIGRATION_SCHEMA.to_owned()
            })
            .map_err(sqlite_error)?;
    }
    if version >= 20 {
        expected
            .execute_batch(RUNTIME_PARTICIPANT_SCHEMA)
            .map_err(sqlite_error)?;
    }
    if version >= 22 {
        expected
            .execute_batch(&if version < 23 {
                migration_v23::predecessor_approval_schema()
            } else {
                GOVERNED_APPROVAL_REPLAY_MIGRATION_SCHEMA.to_owned()
            })
            .map_err(sqlite_error)?;
    }
    if version >= 23 {
        expected
            .execute_batch(GOVERNED_APPROVAL_CLAIM_SCHEMA)
            .map_err(sqlite_error)?;
    }
    if version >= 24 {
        expected
            .execute_batch(&if version < 25 {
                migration_v25::predecessor_schema()
            } else {
                DPOP_REPLAY_MIGRATION_SCHEMA.to_owned()
            })
            .map_err(sqlite_error)?;
    }
    if version >= 25 {
        expected
            .execute_batch(DPOP_AUTHORITY_SCHEMA)
            .map_err(sqlite_error)?;
    }
    if version >= 26 {
        expected
            .execute_batch(DPOP_CLAIM_SCHEMA)
            .map_err(sqlite_error)?;
    }
    if version >= 27 {
        expected
            .execute_batch(SECURITY_PARTICIPANT_MIGRATION_SCHEMA)
            .map_err(sqlite_error)?;
    }
    if version >= 28 {
        expected
            .execute_batch(&if version == 28 {
                super::security_participant_state::schema::predecessor_sql()
            } else {
                super::security_participant_state::schema::sql()?
            })
            .map_err(sqlite_error)?;
    }
    if version >= 30 {
        expected
            .execute_batch(super::security_participant_state::egress::sql())
            .map_err(sqlite_error)?;
    }
    if version >= 31 {
        expected
            .execute_batch(super::security_participant_state::dispatch_ledger::sql())
            .map_err(sqlite_error)?;
    }
    if version >= 32 {
        expected
            .execute_batch(super::security_participant_state::output::sql())
            .map_err(sqlite_error)?;
    }
    if version >= 33 {
        expected
            .execute_batch(super::security_participant_state::nonce_preflight::sql())
            .map_err(sqlite_error)?;
    }
    if admission_operation_schema_catalog(connection)?
        != admission_operation_schema_catalog(&expected)?
    {
        return Err(invariant(
            "admission operation schema differs from the canonical definition",
        ));
    }
    Ok(())
}

fn verify_admission_operation_data_invariants(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let (head, high_water, commit_count, max_commit, max_observed_at): (i64, i64, i64, i64, i64) =
        connection
            .query_row(
                r#"
            SELECT
                (SELECT head_sequence FROM admission_operation_commit_meta
                 WHERE singleton = 1),
                (SELECT trusted_time_high_water_unix_ms
                 FROM admission_operation_commit_meta WHERE singleton = 1),
                (SELECT COUNT(*) FROM admission_operation_commits),
                (SELECT COALESCE(MAX(commit_sequence), 0)
                 FROM admission_operation_commits),
                (SELECT COALESCE(MAX(COALESCE(observed_at_unix_ms, recorded_at_unix_ms)), 0)
                 FROM admission_operation_commits)
            "#,
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .map_err(sqlite_error)?;
    let serving_leases_exist: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'chio_serving_leases'
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let invalid_lease = if serving_leases_exist {
        connection
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1 FROM admission_operation_commits AS committed
                    WHERE NOT EXISTS (
                        SELECT 1 FROM chio_serving_leases AS lease
                        WHERE lease.store_uuid = committed.store_uuid
                          AND lease.owner_epoch = committed.store_owner_epoch
                          AND lease.lease_id = committed.store_lease_id
                    )
                )
                "#,
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(sqlite_error)?
    } else {
        commit_count != 0
    };
    if head < 0
        || high_water < 0
        || u64::try_from(high_water).map_or(true, |value| value > MAX_TRUSTED_UNIX_MS)
        || high_water != max_observed_at
        || (head == 0) != (high_water == 0)
        || commit_count != head
        || max_commit != head
        || invalid_lease
    {
        return Err(invariant(
            "admission operation commit log is not a dense fenced sequence",
        ));
    }
    let invalid_commit_order: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM (
                    SELECT mutation_kind, operation_version, recorded_at_unix_ms,
                           LAG(operation_version) OVER (
                               PARTITION BY operation_id ORDER BY commit_sequence
                           ) AS previous_version,
                           LAG(recorded_at_unix_ms) OVER (
                               PARTITION BY operation_id ORDER BY commit_sequence
                           ) AS previous_time
                    FROM admission_operation_commits
                )
                WHERE (previous_version IS NULL
                       AND (mutation_kind <> 'begin' OR operation_version <> 1))
                   OR (previous_version IS NOT NULL
                       AND (mutation_kind = 'begin'
                            OR (mutation_kind = 'recovery_claim'
                                AND operation_version <> previous_version)
                            OR (mutation_kind = 'participant_update'
                                AND operation_version <> previous_version)
                            OR (mutation_kind IN ('runtime_participant_release', 'governed_approval_release', 'dpop_replay_release')
                                AND operation_version <> previous_version)
                            OR (mutation_kind IN ('runtime_participant_claim', 'governed_approval_claim', 'dpop_replay_claim')
                                AND operation_version NOT IN (previous_version, previous_version + 1))
                            OR (mutation_kind = 'compare_and_swap'
                                AND operation_version <> previous_version + 1)
                            OR (mutation_kind = 'channel_reservation_finalized'
                                AND operation_version <> previous_version + 1)
                            OR recorded_at_unix_ms < previous_time))
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if invalid_commit_order {
        return Err(invariant(
            "admission operation commits regress version or trusted time",
        ));
    }
    let global_time_regression: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM (
                    SELECT COALESCE(observed_at_unix_ms, recorded_at_unix_ms) AS authority_time,
                           LAG(COALESCE(observed_at_unix_ms, recorded_at_unix_ms)) OVER (
                               ORDER BY commit_sequence
                           ) AS previous_time
                    FROM admission_operation_commits
                )
                WHERE previous_time IS NOT NULL
                  AND authority_time < previous_time
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if global_time_regression {
        return Err(invariant(
            "admission authority time regresses across commits",
        ));
    }
    verify_admission_commit_chain(connection)?;

    let mut statement = connection
        .prepare(
            r#"
            SELECT operation_id, request_namespace_digest, request_id,
                   operation_json, state, terminal, coordinator_lease_epoch,
                   version, created_at_unix_ms, updated_at_unix_ms,
                   recovery_claimant_id, recovery_coordinator_lease_id,
                   recovery_coordinator_lease_epoch, recovery_claimed_version,
                   recovery_expires_at_unix_ms, recovery_store_uuid,
                   recovery_store_lease_id, recovery_store_owner_epoch
            FROM admission_operations
            "#,
        )
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let stored = decode_row(read_raw_row(row).map_err(sqlite_error)?)?;
        verify_latest_commit(connection, &stored)?;
        super::execution_nonce::verify_reservation(connection, &stored.operation)?;
        super::retained_request::load_retained_request_tx(connection, &stored.operation)?;
        super::caller_dispatch_context::load(connection, &stored.operation)?;
        super::security_participant_state::dispatch_ledger::verify_capture_attachment(
            connection,
            &stored.operation,
        )?;
        verify_stored_terminal_projection(connection, &stored)?;
    }
    drop(rows);
    drop(statement);
    super::retained_request::verify_retained_request_ownership(connection)?;
    super::caller_dispatch_context::verify_ownership(connection)?;
    super::execution_nonce::verify_ownership(connection)?;
    super::credit_exposure::verify_credit_exposure_account_invariants(connection)
}

pub(crate) fn validate_trusted_time(
    value: u64,
    field: &'static str,
) -> Result<(), AdmissionOperationStoreError> {
    if value == 0 || value > MAX_TRUSTED_UNIX_MS {
        return Err(invariant(format!(
            "{field} is outside the persisted trusted-time range"
        )));
    }
    Ok(())
}

pub(super) fn verify_latest_commit(
    connection: &Connection,
    stored: &StoredOperation,
) -> Result<(), AdmissionOperationStoreError> {
    let latest = connection
        .query_row(
            r#"
            SELECT operation_version, operation_digest, recovery_claim_digest,
                   recorded_at_unix_ms
            FROM admission_operation_commits
            WHERE operation_id = ?1
            ORDER BY commit_sequence DESC
            LIMIT 1
            "#,
            [stored.operation.binding().operation_id().as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| invariant("admission operation has no commit record"))?;
    let encoded = encode_operation(&stored.operation)?;
    let claim_digest = stored
        .recovery_claim
        .as_ref()
        .map(recovery_claim_digest)
        .transpose()?;
    if stored_u64(latest.0, "commit operation_version")? != stored.operation.version()
        || latest.1 != sha256_hex(&encoded)
        || latest.2 != claim_digest
        || stored_u64(latest.3, "commit recorded_at_unix_ms")? != stored.updated_at_unix_ms
    {
        return Err(invariant(
            "latest admission operation commit does not match its projection",
        ));
    }
    Ok(())
}

type SchemaCatalogEntry = (String, String, String, Option<String>);

fn admission_operation_schema_catalog(
    connection: &Connection,
) -> Result<Vec<SchemaCatalogEntry>, AdmissionOperationStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT type, name, tbl_name, sql
            FROM sqlite_schema
            WHERE name GLOB 'admission_operation*'
               OR tbl_name GLOB 'admission_operation*'
               OR name GLOB 'obligation_*'
               OR tbl_name GLOB 'obligation_*'
               OR name GLOB 'credit_exposure_*'
               OR tbl_name GLOB 'credit_exposure_*'
               OR lower(name) GLOB 'runtime_replay_*'
               OR lower(tbl_name) GLOB 'runtime_replay_*'
               OR lower(name) GLOB 'governed_approval_replay_*'
               OR lower(tbl_name) GLOB 'governed_approval_replay_*'
               OR lower(name) GLOB 'dpop_replay_*'
               OR lower(tbl_name) GLOB 'dpop_replay_*'
               OR lower(name) GLOB 'security_participant_migration*'
               OR lower(tbl_name) GLOB 'security_participant_migration*'
               OR lower(name) GLOB 'security_participant_state*'
               OR lower(tbl_name) GLOB 'security_participant_state*'
               OR lower(name) GLOB 'security_participant_egress*'
               OR lower(tbl_name) GLOB 'security_participant_egress*'
               OR lower(name) GLOB 'security_participant_nonce_preflight*'
               OR lower(tbl_name) GLOB 'security_participant_nonce_preflight*'
               OR lower(name) GLOB 'security_participant_output*'
               OR lower(tbl_name) GLOB 'security_participant_output*'
               OR lower(name) GLOB 'admission_operation_native_dispatch*'
               OR lower(tbl_name) GLOB 'admission_operation_native_dispatch*'
            ORDER BY type, name, tbl_name
            "#,
        )
        .map_err(sqlite_error)?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(entries)
}

pub(super) fn recovery_claim_digest(
    claim: &UntrustedAdmissionRecoveryClaim,
) -> Result<String, AdmissionOperationStoreError> {
    #[derive(Serialize)]
    struct ClaimDigestBody<'a> {
        operation_id: &'a str,
        claimant_id: &'a str,
        coordinator_lease_id: &'a str,
        coordinator_lease_epoch: u64,
        claimed_version: u64,
        expires_at_unix_ms: u64,
        store_uuid: &'a str,
        store_lease_id: &'a str,
        store_owner_epoch: u64,
    }

    let body = ClaimDigestBody {
        operation_id: claim.operation_id().as_str(),
        claimant_id: claim.claimant_id().as_str(),
        coordinator_lease_id: claim.coordinator_lease_id().as_str(),
        coordinator_lease_epoch: claim.coordinator_lease_epoch(),
        claimed_version: claim.claimed_version(),
        expires_at_unix_ms: claim.expires_at_unix_ms(),
        store_uuid: &claim.store_fence().store_uuid,
        store_lease_id: &claim.store_fence().lease_id,
        store_owner_epoch: claim.store_fence().owner_epoch,
    };
    let canonical = canonical_json_bytes(&body)
        .map_err(|error| invariant(format!("recovery claim encoding failed: {error}")))?;
    Ok(sha256_hex(&canonical))
}

pub(crate) fn verify_active_owner(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    requested: Option<&StoreMutationFence>,
) -> Result<(), AdmissionOperationStoreError> {
    crate::serving_owner::verify_budget_fence(transaction, Some(owner)).map_err(|error| {
        if matches!(error, chio_kernel::BudgetStoreError::Fenced { .. }) {
            AdmissionOperationStoreError::Fenced
        } else {
            AdmissionOperationStoreError::Unavailable(error.to_string())
        }
    })?;
    if requested.is_some_and(|fence| fence != &owner.fence) {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    let active_lease: i64 = transaction
        .query_row(
            r#"
            SELECT COUNT(*) FROM chio_serving_leases
            WHERE store_uuid = ?1 AND owner_epoch = ?2 AND lease_id = ?3
              AND end_head_index IS NULL
            "#,
            params![
                &owner.fence.store_uuid,
                sqlite_i64(owner.fence.owner_epoch, "store_owner_epoch")?,
                &owner.fence.lease_id,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if active_lease != 1 {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    Ok(())
}

pub(super) fn coordinator_lease_id_for_epoch(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    coordinator_lease_epoch: u64,
) -> Result<AdmissionIdentifier, AdmissionOperationStoreError> {
    let lease_id = transaction
        .query_row(
            r#"
            SELECT lease_id
            FROM chio_serving_leases
            WHERE store_uuid = ?1 AND owner_epoch = ?2
            "#,
            params![
                &owner.fence.store_uuid,
                sqlite_i64(coordinator_lease_epoch, "coordinator_lease_epoch")?,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| invariant("operation coordinator lease is absent from lease history"))?;
    AdmissionIdentifier::try_new("coordinator_lease_id", lease_id).map_err(Into::into)
}

use super::*;

mod clock;

pub(super) use clock::authority_validation_time;
pub(crate) use clock::{observe_authority_time, verify_trusted_time};

/// The admission v1 schema: every table family, in creation order. A store is
/// created from exactly this list and every open is verified against it.
pub(crate) fn admission_operation_schema_sql() -> Result<String, AdmissionOperationStoreError> {
    let schema_v1 = [
        ADMISSION_OPERATION_SCHEMA,
        super::recovery::SCHEMA,
        include_str!("../admission_operation_recovery.sql"),
        include_str!("../admission_operation_nonce.sql"),
        include_str!("../admission_operation_nonce_preflight.sql"),
        RUNTIME_SOURCE_SCHEMA,
        RUNTIME_PARTICIPANT_SCHEMA,
        GOVERNED_APPROVAL_AUTHORITY_SCHEMA,
        GOVERNED_APPROVAL_CLAIM_SCHEMA,
        DPOP_REPLAY_MIGRATION_SCHEMA,
        DPOP_AUTHORITY_SCHEMA,
        DPOP_CLAIM_SCHEMA,
        SECURITY_PARTICIPANT_MIGRATION_SCHEMA,
        &super::security_participant_state::schema::sql()?,
        super::security_participant_state::egress::sql(),
        super::security_participant_state::dispatch_ledger::sql(),
        super::security_participant_state::output::sql(),
        super::security_participant_state::nonce_preflight::sql(),
        super::security_participant_state::checkpoint::sql(),
        super::caller_budget::SCHEMA,
        super::stop_epoch::SCHEMA,
    ];
    Ok(schema_v1.join("\n"))
}

pub(crate) fn initialize_admission_operation_schema(
    schema: &crate::schema_version::SchemaTransaction<'_>,
) -> std::result::Result<(), AdmissionOperationStoreError> {
    let transaction = schema.connection();
    crate::security_state::deny_native_mutations(transaction).map_err(sqlite_error)?;
    if schema.is_fresh() {
        transaction
            .execute_batch(&admission_operation_schema_sql()?)
            .map_err(sqlite_error)?;

        schema
            .stamp(ADMISSION_OPERATION_SCHEMA_KEY)
            .map_err(|error| invariant(error.to_string()))?;
    }
    verify_admission_operation_invariants(transaction)
}

fn table_exists(
    transaction: &Connection,
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

pub(crate) fn verify_admission_operation_invariants(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    verify_admission_operation_schema(connection)?;
    super::recovery_records::verify_local_history(connection)?;
    super::recovery_deployment::verify_planning_allocations(connection)?;

    verify_operation_data(connection)?;
    super::caller_budget::verify_ownership(connection)?;
    super::runtime_participant::verify_all(connection)?;
    super::governed_approval_claim::verify_all(connection)?;
    super::dpop_claim::verify_all(connection)?;
    super::governed_approval_authority::verify_all_records(connection)
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
    super::recovery::verify_all(connection)?;
    super::security_participant_state::checkpoint::verify_catalog(connection)?;
    super::security_participant_state::checkpoint::verify_all(connection)?;
    if table_exists(connection, "authority_global_commits")? {
        super::security_participant_state::verify_archive_coverage(connection)
            .map_err(map_owner_error)?;
    }
    super::security_participant_state::verify_all(connection).map(|_| ())
}

fn verify_admission_operation_schema(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let expected = Connection::open_in_memory().map_err(sqlite_error)?;
    expected
        .execute_batch(&admission_operation_schema_sql()?)
        .map_err(sqlite_error)?;
    if admission_operation_schema_catalog(connection)?
        != admission_operation_schema_catalog(&expected)?
    {
        return Err(invariant(
            "admission operation schema differs from the canonical definition",
        ));
    }
    Ok(())
}

pub(super) fn verify_admission_commit_chronology(
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
                (SELECT COALESCE(MAX(observed_at_unix_ms), 0)
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
                            OR (mutation_kind IN ('recovery_deferred', 'recovery_deferral_cleared')
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
                    SELECT observed_at_unix_ms AS authority_time,
                           LAG(observed_at_unix_ms) OVER (
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
    Ok(())
}

fn verify_operation_data(connection: &Connection) -> Result<(), AdmissionOperationStoreError> {
    verify_admission_commit_chronology(connection)?;
    let history = CheckedHistoryScope::from_verified_chain(
        connection,
        verify_admission_commit_chain(connection)?,
    );

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
        let retained =
            super::retained_request::load_retained_request_tx(connection, &stored.operation)?;
        super::caller_budget::verify_indexed(connection, &stored.operation, retained.as_ref())?;
        super::caller_dispatch_context::load(connection, &stored.operation)?;
        super::security_participant_state::dispatch_ledger::verify_capture_attachment(
            connection,
            &stored.operation,
        )?;
        super::projection::verify_stored_terminal_projection_with_history(
            connection, &stored, &history,
        )?;
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
               OR lower(name) GLOB 'admission_execution_nonce_*'
               OR lower(tbl_name) GLOB 'admission_execution_nonce_*'
               OR name GLOB 'obligation_*'
               OR tbl_name GLOB 'obligation_*'
               OR name GLOB 'credit_exposure_*'
               OR tbl_name GLOB 'credit_exposure_*'
               OR lower(name) GLOB 'runtime_source_*'
               OR lower(tbl_name) GLOB 'runtime_source_*'
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
               OR lower(name) GLOB 'security_participant_checkpoint*'
               OR lower(tbl_name) GLOB 'security_participant_checkpoint*'
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

#[cfg(test)]
mod tests;

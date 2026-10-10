//! Ordinary owning geometry observations are not native financing authority.
use super::*;
use chio_kernel::tool_outcome::{CanonicalInvocationBlobV1, ToolOutcomeRecordV1};

pub(crate) fn seven_metadata_command_wal_price(
    connection: &Connection,
) -> Result<u64, AdmissionOperationStoreError> {
    for (kind, name, table, compiled, stored) in
        schema::command_catalog_difference_for_test(connection)?
    {
        println!(
            "Raw static catalog difference: kind={kind}, name={name}, table={table}, compiled_sql_sha256={compiled:?}, stored_sql_sha256={stored:?}",
        );
    }
    let scope = "e".repeat(64);
    let mut plan = recovery::resources::ProtectedCommandLiabilityPlan::new();
    for ordinal in 0..7 {
        plan.add_new_command(
            connection,
            &format!("native-influence-phase:{scope}:raw-price-control:{ordinal}"),
            &scope,
            16_384,
        )?;
    }
    Ok(recovery::resources::price_protected_command_liability(connection, &plan)?.wal_bytes())
}

pub(crate) fn main_wal_frontier(
    connection: &Connection,
) -> Result<(u64, u64, u64), AdmissionOperationStoreError> {
    let (busy, log, checkpointed): (i64, i64, i64) = connection
        .query_row("PRAGMA main.wal_checkpoint(NOOP)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(sqlite_error)?;
    if busy != 0 || log < 0 || checkpointed < 0 || checkpointed > log {
        return Err(invariant("owning Raw WAL observation refused"));
    }
    let page_size: i64 = connection
        .query_row("PRAGMA main.page_size", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    let page_size = stored_u64(page_size, "owning Raw page size")?;
    let frame_bytes = page_size
        .checked_add(24)
        .ok_or_else(|| invariant("owning Raw WAL observation overflowed"))?;
    Ok((
        stored_u64(log, "owning Raw WAL log frontier")?,
        stored_u64(checkpointed, "owning Raw WAL checkpoint frontier")?,
        frame_bytes,
    ))
}

/// Observe the source-owned whole transaction price before the actual owning
/// producer. Only primitive bytes leave this cfg(test) bridge, never a loan.
pub(crate) fn whole_raw_custody_wal_price_before_write(
    store: &SqliteAdmissionOperationStore,
    operation: &AdmissionOperationV1,
    blob: &CanonicalInvocationBlobV1,
    record: &ToolOutcomeRecordV1,
    claim: &RecoveryClaimRequest<'_>,
    trusted_now_unix_ms: u64,
) -> Result<u64, AdmissionOperationStoreError> {
    let mut connection = store.connection()?;
    let tx = store.begin_write(&mut connection, Some(claim.fence))?;
    let origin = store
        .serving_owner
        .prepare_native_source_transaction(&tx)
        .map_err(map_owner_error)?;
    let source = raw_custody_liability::prepare_raw_custody_write_liability(
        &tx,
        (&store.serving_owner, &origin),
        raw_custody_liability::RawCustodyWriteRequest {
            operation,
            blob,
            outcome: record,
            claim: *claim,
            trusted_now_unix_ms,
        },
    )?;
    let price = recovery::resources::price_raw_custody_liability(
        &tx,
        (&store.serving_owner, &origin),
        &source,
    )?;
    let result = price.wal_bytes();
    drop(source);
    tx.rollback().map_err(sqlite_error)?;
    Ok(result)
}

#[derive(Clone, Copy)]
pub(crate) enum RawLiabilitySourceControl {
    OriginalChanged,
    ClaimChanged,
    DifferentTransaction,
    ExtraIndex,
    TemporaryCallback,
}

/// Actual owning source controls expose only the refusal observation. No
/// source, physical amount, arbitrary SQL or writer permission escapes.
pub(crate) fn raw_source_refuses_after_control(
    store: &SqliteAdmissionOperationStore,
    operation: &AdmissionOperationV1,
    blob: &CanonicalInvocationBlobV1,
    record: &ToolOutcomeRecordV1,
    claim: &RecoveryClaimRequest<'_>,
    trusted_now_unix_ms: u64,
    control: RawLiabilitySourceControl,
) -> Result<bool, AdmissionOperationStoreError> {
    let request = raw_custody_liability::RawCustodyWriteRequest {
        operation,
        blob,
        outcome: record,
        claim: *claim,
        trusted_now_unix_ms,
    };
    let mut connection = store.connection()?;
    let tx = store.begin_write(&mut connection, Some(request.claim.fence))?;
    let origin = store
        .serving_owner
        .prepare_native_source_transaction(&tx)
        .map_err(map_owner_error)?;
    let source = raw_custody_liability::prepare_raw_custody_write_liability(
        &tx,
        (&store.serving_owner, &origin),
        request,
    )?;
    // The real profile/source/price must succeed before every negative control.
    let baseline = recovery::resources::price_raw_custody_liability(
        &tx,
        (&store.serving_owner, &origin),
        &source,
    )?;
    if baseline.wal_bytes() == 0 {
        return Err(invariant(
            "Raw source control baseline did not price its producer",
        ));
    }
    let refused = match control {
        RawLiabilitySourceControl::DifferentTransaction => {
            let path = tx
                .path()
                .ok_or_else(|| invariant("Raw control lost its path"))?;
            let mut other =
                Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                    .map_err(sqlite_error)?;
            let other_tx = other
                .transaction_with_behavior(TransactionBehavior::Deferred)
                .map_err(sqlite_error)?;
            source
                .verify_before(&other_tx, (&store.serving_owner, &origin))
                .is_err()
        }
        RawLiabilitySourceControl::OriginalChanged => {
            tx.execute(
                "UPDATE main.admission_operations SET updated_at_unix_ms=updated_at_unix_ms+1
                        WHERE operation_id=?1",
                [source.operation_id_for_test()],
            )
            .map_err(sqlite_error)?;
            source
                .verify_before(&tx, (&store.serving_owner, &origin))
                .is_err()
        }
        RawLiabilitySourceControl::ClaimChanged => {
            let changed = tx
                .execute(
                    "UPDATE main.admission_operations
                        SET recovery_expires_at_unix_ms=recovery_expires_at_unix_ms+1
                        WHERE operation_id=?1 AND recovery_expires_at_unix_ms IS NOT NULL",
                    [source.operation_id_for_test()],
                )
                .map_err(sqlite_error)?;
            if changed != 1 {
                return Err(invariant(
                    "Raw control did not change its actual original claim",
                ));
            }
            source
                .verify_before(&tx, (&store.serving_owner, &origin))
                .is_err()
        }
        RawLiabilitySourceControl::ExtraIndex => {
            tx.execute_batch("CREATE INDEX main.raw_unpriced_index ON tool_outcomes(request_id)")
                .map_err(sqlite_error)?;
            source
                .verify_before(&tx, (&store.serving_owner, &origin))
                .is_err()
        }
        RawLiabilitySourceControl::TemporaryCallback => {
            tx.execute_batch("CREATE TEMP TABLE unrelated_raw_census(value INTEGER)")
                .map_err(sqlite_error)?;
            source.verify_before(&tx, (&store.serving_owner, &origin))?;
            tx.execute_batch(
                "CREATE TEMP TRIGGER raw_unpriced_callback
                AFTER INSERT ON main.tool_outcome_blobs
                BEGIN INSERT INTO unrelated_raw_census VALUES(1); END",
            )
            .map_err(sqlite_error)?;
            source
                .verify_before(&tx, (&store.serving_owner, &origin))
                .is_err()
        }
    };
    drop(source);
    tx.rollback().map_err(sqlite_error)?;
    Ok(refused)
}

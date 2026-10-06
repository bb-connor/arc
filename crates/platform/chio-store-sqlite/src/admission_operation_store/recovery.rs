//! Fenced recovery status, separate from operation and financial completion.

use super::*;
use chio_kernel::admission_operation::{
    AdmissionRecoveryDeferralClear, AdmissionRecoveryDeferralWrite, AdmissionRecoveryPageQuery,
    AdmissionRecoveryPageV1, AdmissionRecoveryStatusV1,
};

mod page;
mod status;

pub(super) const SCHEMA: &str = include_str!("recovery/schema.sql");

impl SqliteAdmissionOperationStore {
    pub(super) fn read_recovery_status(
        &self,
        operation_id: &AdmissionOperationId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<AdmissionRecoveryStatusV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        verify_active_owner(&transaction, &self.serving_owner, Some(fence))?;
        schema::authority_validation_time(&transaction, now, &self.serving_owner)?;
        let stored = load_by_operation_id_tx(&transaction, operation_id)?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        verify_latest_commit(&transaction, &stored)?;
        let status = status::load(&transaction, &stored.operation)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(status)
    }

    pub(super) fn persist_recovery_deferral(
        &self,
        request: AdmissionRecoveryDeferralWrite<'_>,
    ) -> Result<AdmissionRecoveryStatusV1, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(request.fence))?;
        let stored = verify_snapshot(
            &transaction,
            &self.serving_owner,
            request.operation,
            Some(request.lease),
            request.fence,
            request.trusted_now_unix_ms,
        )?;
        if stored.operation.state().is_terminal() {
            return Err(invariant("a terminal operation cannot be quarantined"));
        }
        request.deferral.validate_for(&stored.operation)?;
        if request.deferral.operation_version != stored.operation.version()
            || request.deferral.last_failure_unix_ms != request.trusted_now_unix_ms
        {
            return Err(invariant(
                "recovery deferral does not describe the current attempt",
            ));
        }
        let current = status::load(&transaction, &stored.operation)?;
        let desired = AdmissionRecoveryStatusV1 {
            quarantined: true,
            deferral: request.deferral.clone(),
        };
        if current.as_ref() == Some(&desired) {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(desired);
        }
        if current.as_ref() != request.expected
            || current.as_ref().map_or(1, |current| {
                current.deferral.attempt_count.saturating_add(1)
            }) != desired.deferral.attempt_count
        {
            return Err(invariant("recovery deferral compare-and-set conflicted"));
        }
        status::persist(
            &transaction,
            &stored,
            &desired,
            "recovery_deferred",
            &self.serving_owner,
            request.trusted_now_unix_ms,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(desired)
    }

    pub(super) fn persist_recovery_deferral_clear(
        &self,
        request: AdmissionRecoveryDeferralClear<'_>,
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(request.fence))?;
        let stored = verify_snapshot(
            &transaction,
            &self.serving_owner,
            request.operation,
            request.lease,
            request.fence,
            request.trusted_now_unix_ms,
        )?;
        let current = status::load(&transaction, &stored.operation)?
            .ok_or_else(|| invariant("recovery deferral disappeared before clearing"))?;
        let desired = AdmissionRecoveryStatusV1 {
            quarantined: false,
            deferral: request.expected.deferral.clone(),
        };
        if current == desired {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        }
        if &current != request.expected {
            return Err(invariant(
                "recovery deferral clearing compare-and-set conflicted",
            ));
        }
        status::persist(
            &transaction,
            &stored,
            &desired,
            "recovery_deferral_cleared",
            &self.serving_owner,
            request.trusted_now_unix_ms,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)
    }

    pub(super) fn read_recovery_page(
        &self,
        query: AdmissionRecoveryPageQuery<'_>,
    ) -> Result<AdmissionRecoveryPageV1, AdmissionOperationStoreError> {
        page::read(self, query)
    }
}

fn verify_snapshot(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    operation: &AdmissionOperationV1,
    lease: Option<&AdmissionRecoveryLease>,
    fence: &StoreMutationFence,
    now: u64,
) -> Result<StoredOperation, AdmissionOperationStoreError> {
    schema::authority_validation_time(transaction, now, owner)?;
    let stored = load_by_operation_id_tx(transaction, operation.binding().operation_id())?
        .ok_or(AdmissionOperationStoreError::NotFound)?;
    verify_latest_commit(transaction, &stored)?;
    if &stored.operation != operation {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    match lease {
        Some(lease) => verify_stored_recovery_claim(
            transaction,
            owner,
            &stored,
            lease.untrusted_claim(),
            now,
            fence,
        )?,
        None if operation.state().is_terminal() => {}
        None => {
            return Err(invariant(
                "nonterminal recovery status mutation requires its original operation lease",
            ))
        }
    }
    Ok(stored)
}

pub(super) fn verify_all(connection: &Connection) -> Result<(), AdmissionOperationStoreError> {
    let mut statement = connection.prepare(
        "SELECT o.operation_id, o.request_namespace_digest, o.request_id,
         o.operation_json, o.state, o.terminal, o.coordinator_lease_epoch,
         o.version, o.created_at_unix_ms, o.updated_at_unix_ms,
         o.recovery_claimant_id, o.recovery_coordinator_lease_id,
         o.recovery_coordinator_lease_epoch, o.recovery_claimed_version,
         o.recovery_expires_at_unix_ms, o.recovery_store_uuid,
         o.recovery_store_lease_id, o.recovery_store_owner_epoch
         FROM admission_operations o JOIN admission_operation_recovery_deferrals d USING(operation_id)
         ORDER BY o.operation_id").map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let stored = decode_row(read_raw_row(row).map_err(sqlite_error)?)?;
        verify_latest_commit(connection, &stored)?;
        status::load(connection, &stored.operation)?;
    }
    let missing: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM admission_operation_commits c JOIN admission_operations o USING(operation_id)
         WHERE c.mutation_kind IN ('recovery_deferred','recovery_deferral_cleared')
           AND NOT EXISTS(SELECT 1 FROM admission_operation_recovery_deferrals d WHERE d.operation_id=c.operation_id))",
        [], |row| row.get(0)).map_err(sqlite_error)?;
    if missing {
        return Err(invariant(
            "recovery deferral history lost its retained status",
        ));
    }
    Ok(())
}

// The caller holds its owner-verified admission/outcome transaction. This
// bounded component check does not replace chain/owner/anchor verification.
pub(crate) fn verify_outcome_recovery_status(
    connection: &Connection,
    operation: &AdmissionOperationV1,
) -> Result<(), AdmissionOperationStoreError> {
    status::load(connection, operation).map(|_| ())
}

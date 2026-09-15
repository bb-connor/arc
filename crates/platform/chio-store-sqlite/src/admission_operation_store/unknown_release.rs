//! Fenced append-only monetary successors to historical unknown admissions.

use super::*;
use chio_kernel::budget_store::{BudgetEventAuthority, BudgetReconcileHoldRequest};
use chio_kernel::payment::{
    unknown_release_digest, CoSignedUnknownPaymentReleaseV1, QualifiedUnknownPaymentReleaseStore,
    UnknownPaymentReleaseError, UnknownPaymentReleasePolicyV1, UnknownPaymentReleaseRecordV1,
};

fn error(value: impl std::fmt::Display) -> UnknownPaymentReleaseError {
    UnknownPaymentReleaseError(value.to_string())
}

fn source(
    connection: &Connection,
    id: &str,
) -> Result<(AdmissionOperationV1, PaymentJournalRecord), UnknownPaymentReleaseError> {
    let id = AdmissionOperationId::from_persisted(id).map_err(error)?;
    let operation = load_by_operation_id_tx(connection, &id)
        .map_err(error)?
        .ok_or_else(|| error("unknown admission is absent"))?
        .operation;
    let journal = crate::budget_store::load_original_payment_journal(connection, id.as_str())
        .map_err(error)?
        .ok_or_else(|| error("original payment authorization is absent"))?;
    if operation.state() != AdmissionOperationState::OutcomeUnknownAfterDispatch {
        return Err(error("release source is not a historical unknown"));
    }
    Ok((operation, journal))
}

fn load_record(
    connection: &Connection,
    id: &str,
) -> Result<Option<UnknownPaymentReleaseRecordV1>, UnknownPaymentReleaseError> {
    let mut statement = connection.prepare("SELECT sequence,request_digest,record_json,record_digest FROM unknown_payment_release_records WHERE operation_id=? ORDER BY sequence LIMIT 3").map_err(error)?;
    let rows = statement
        .query_map([id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(error)?;
    if rows.is_empty() {
        return Ok(None);
    }
    if rows.len() > 2 {
        return Err(error("release history exceeds its two transitions"));
    }
    let (operation, original) = source(connection, id)?;
    let mut previous: Option<UnknownPaymentReleaseRecordV1> = None;
    for (index, (sequence, request_digest, bytes, record_digest)) in rows.into_iter().enumerate() {
        if bytes.is_empty() || bytes.len() > 1024 * 1024 {
            return Err(error("release record exceeds bounds"));
        }
        let record: UnknownPaymentReleaseRecordV1 =
            serde_json::from_slice(&bytes).map_err(error)?;
        record.validate()?;
        let accepted = record.accepted_fence();
        let fence = record.completion().map_or(accepted, |(_, _, fence)| fence);
        let covered: i64 = connection.query_row(
            "SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind='payment_resolution' AND mutation_kind='unknown_payment_release' AND projection_key=?1 AND projection_sequence=?2 AND projection_reference_digest=?3 AND store_uuid=?4 AND store_lease_id=?5 AND store_owner_epoch=?6",
            params![id, sequence, &record_digest, &fence.store_uuid, &fence.lease_id, i64::try_from(fence.owner_epoch).map_err(error)?],
            |row| row.get(0)).map_err(error)?;
        let hold = original
            .hold_id
            .as_deref()
            .ok_or_else(|| error("release has no original hold"))?;
        let budget_matches: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM budget_mutation_events WHERE event_id=?1 AND hold_id=?2 AND capability_id=?3 AND grant_index=?4 AND kind='reconcile_spend' AND exposure_units=?5 AND realized_spend_units=0 AND authority_id=?6 AND lease_id=?7 AND lease_epoch=?8)",
            params![format!("{hold}:reconcile"), hold, &original.capability_id, original.grant_index,
                i64::try_from(original.amount_units).map_err(error)?, &accepted.store_uuid, &accepted.lease_id,
                i64::try_from(accepted.owner_epoch).map_err(error)?], |row| row.get(0)).map_err(error)?;
        if covered != 1 || !budget_matches {
            return Err(error(
                "release lost its exact fenced authority or budget reconciliation",
            ));
        }
        if sequence != i64::try_from(index + 1).map_err(error)?
            || record.sequence() != u64::try_from(sequence).map_err(error)?
            || record.operation_id() != id
            || record.original_operation() != &operation.to_persisted()
            || unknown_release_digest(record.original_journal())?
                != unknown_release_digest(&original)?
            || request_digest != unknown_release_digest(record.request())?
            || sha256_hex(&bytes) != record_digest
            || canonical_json_bytes(&record).map_err(error)? != bytes
        {
            return Err(error(
                "release history is not bound to its original authorization",
            ));
        }
        if let Some(prior) = previous {
            let (transaction_id, at, fence) = record
                .completion()
                .ok_or_else(|| error("second release record is not completed"))?;
            let expected = prior.complete(transaction_id.into(), at, fence.clone())?;
            if unknown_release_digest(&expected)? != record_digest {
                return Err(error("release completion changed its accepted intent"));
            }
        }
        previous = Some(record);
    }
    Ok(previous)
}

pub(crate) fn load_effective_journal(
    connection: &Connection,
    original: &PaymentJournalRecord,
) -> Result<Option<PaymentJournalRecord>, UnknownPaymentReleaseError> {
    // Standalone budget stores do not contain the admission resolution schema.
    let exists: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='unknown_payment_release_records')", [], |r| r.get(0)).map_err(error)?;
    if !exists {
        return Ok(None);
    }
    load_record(connection, &original.operation_id)?
        .map(|record| record.current_journal())
        .transpose()
}

fn append_record(
    store: &SqliteAdmissionOperationStore,
    transaction: &Transaction<'_>,
    record: &UnknownPaymentReleaseRecordV1,
) -> Result<(), UnknownPaymentReleaseError> {
    record.validate()?;
    let bytes = canonical_json_bytes(record).map_err(error)?;
    transaction.execute("INSERT INTO unknown_payment_release_records(operation_id,sequence,request_digest,record_json,record_digest) VALUES(?,?,?,?,?)",
        params![record.operation_id(), i64::try_from(record.sequence()).map_err(error)?,
            unknown_release_digest(record.request())?, &bytes, sha256_hex(&bytes)]).map_err(error)?;
    store
        .serving_owner
        .append_global_commit(
            transaction,
            "unknown_payment_release",
            "payment_resolution",
            record.operation_id(),
            record.sequence(),
        )
        .map_err(error)?;
    Ok(())
}

impl QualifiedUnknownPaymentReleaseStore for SqliteAdmissionOperationStore {
    fn unknown_release_source(
        &self,
        operation_id: &str,
        fence: &StoreMutationFence,
    ) -> Result<(AdmissionOperationV1, PaymentJournalRecord), UnknownPaymentReleaseError> {
        if fence != &self.serving_owner.fence {
            return Err(error("release read was fenced"));
        }
        let mut connection = self.connection().map_err(error)?;
        let transaction = self.begin_read(&mut connection).map_err(error)?;
        source(&transaction, operation_id)
    }

    fn load_unknown_release(
        &self,
        operation_id: &str,
        fence: &StoreMutationFence,
    ) -> Result<Option<UnknownPaymentReleaseRecordV1>, UnknownPaymentReleaseError> {
        if fence != &self.serving_owner.fence {
            return Err(error("release read was fenced"));
        }
        let mut connection = self.connection().map_err(error)?;
        let transaction = self.begin_read(&mut connection).map_err(error)?;
        load_record(&transaction, operation_id)
    }

    fn begin_unknown_release(
        &self,
        policy: &UnknownPaymentReleasePolicyV1,
        request: &CoSignedUnknownPaymentReleaseV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<UnknownPaymentReleaseRecordV1, UnknownPaymentReleaseError> {
        let mut connection = self.connection().map_err(error)?;
        let transaction = self
            .begin_write(&mut connection, Some(fence))
            .map_err(error)?;
        verify_trusted_time(&transaction, trusted_now_unix_ms).map_err(error)?;
        let id = &request.proposal.body.operation_id;
        if let Some(existing) = load_record(&transaction, id)? {
            if unknown_release_digest(existing.request())? != unknown_release_digest(request)?
                || unknown_release_digest(policy)? != unknown_release_digest(existing.policy())?
            {
                return Err(error("unknown hold already binds another release intent"));
            }
            // Accepted consent remains executable after its original admission
            // window closes. Validation uses the retained acceptance time.
            return Ok(existing);
        }
        let (operation, original) = source(&transaction, id)?;
        let verified = request.qualify(policy, &operation, &original, trusted_now_unix_ms)?;
        let record = UnknownPaymentReleaseRecordV1::accepted(verified, fence.clone())?;
        let hold = original
            .hold_id
            .as_deref()
            .ok_or_else(|| error("release has no budget hold"))?;
        let budget = crate::budget_store::SqliteBudgetStore::open_alongside(
            self.connection.clone(),
            self.serving_owner.clone(),
        );
        let (_, changed) = budget
            .reconcile_composite_hold_in_transaction(
                &transaction,
                &BudgetReconcileHoldRequest {
                    capability_id: original.capability_id.clone(),
                    grant_index: usize::try_from(original.grant_index).map_err(error)?,
                    exposed_cost_units: original.amount_units,
                    realized_spend_units: 0,
                    hold_id: Some(hold.into()),
                    event_id: Some(format!("{hold}:reconcile")),
                    authority: Some(BudgetEventAuthority {
                        authority_id: fence.store_uuid.clone(),
                        lease_id: fence.lease_id.clone(),
                        lease_epoch: fence.owner_epoch,
                    }),
                },
            )
            .map_err(error)?;
        if !changed {
            return Err(error(
                "unknown hold was reconciled without this release intent",
            ));
        }
        append_record(self, &transaction, &record)?;
        self.commit_write(transaction).map_err(error)?;
        self.sync_after_write(&connection).map_err(error)?;
        Ok(record)
    }

    fn complete_unknown_release(
        &self,
        operation_id: &str,
        request_digest: &str,
        transaction_id: &str,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<UnknownPaymentReleaseRecordV1, UnknownPaymentReleaseError> {
        let mut connection = self.connection().map_err(error)?;
        let transaction = self
            .begin_write(&mut connection, Some(fence))
            .map_err(error)?;
        verify_trusted_time(&transaction, trusted_now_unix_ms).map_err(error)?;
        let current = load_record(&transaction, operation_id)?
            .ok_or_else(|| error("release intent is absent"))?;
        if unknown_release_digest(current.request())? != request_digest {
            return Err(error("release completion changes the accepted intent"));
        }
        if let Some((id, _, _)) = current.completion() {
            if id != transaction_id {
                return Err(error("rail changed its completed release reference"));
            }
            return Ok(current);
        }
        let completed =
            current.complete(transaction_id.into(), trusted_now_unix_ms, fence.clone())?;
        append_record(self, &transaction, &completed)?;
        self.commit_write(transaction).map_err(error)?;
        self.sync_after_write(&connection).map_err(error)?;
        Ok(completed)
    }

    fn list_pending_unknown_releases(
        &self,
        fence: &StoreMutationFence,
        limit: usize,
    ) -> Result<Vec<UnknownPaymentReleaseRecordV1>, UnknownPaymentReleaseError> {
        if fence != &self.serving_owner.fence || limit == 0 || limit > 256 {
            return Err(error("release recovery read was fenced or unbounded"));
        }
        let mut connection = self.connection().map_err(error)?;
        let transaction = self.begin_read(&mut connection).map_err(error)?;
        let mut statement = transaction.prepare("SELECT r.operation_id FROM unknown_payment_release_records r WHERE r.sequence=1 AND NOT EXISTS(SELECT 1 FROM unknown_payment_release_records completed WHERE completed.operation_id=r.operation_id AND completed.sequence=2) ORDER BY r.operation_id LIMIT ?").map_err(error)?;
        let ids = statement
            .query_map([i64::try_from(limit).map_err(error)?], |r| {
                r.get::<_, String>(0)
            })
            .map_err(error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(error)?;
        ids.into_iter()
            .map(|id| {
                load_record(&transaction, &id)?.ok_or_else(|| error("pending release disappeared"))
            })
            .collect()
    }
}

pub(crate) fn verify_invariants(connection: &Connection) -> Result<(), UnknownPaymentReleaseError> {
    let mut statement = connection.prepare("SELECT DISTINCT operation_id FROM unknown_payment_release_records ORDER BY operation_id").map_err(error)?;
    let ids = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(error)?;
    for id in ids {
        load_record(connection, &id)?.ok_or_else(|| error("release history disappeared"))?;
    }
    Ok(())
}

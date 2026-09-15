//! Authoritative source validation for append-only capture waiver history.
use super::*;
use chio_kernel::payment::*;
fn error(e: impl std::fmt::Display) -> CaptureWaiverError {
    CaptureWaiverError(e.to_string())
}
pub(super) fn source(
    connection: &Connection,
    id: &str,
) -> Result<CaptureWaiverSourceV1, CaptureWaiverError> {
    // Payment terminal validation loads its monetary successor. Avoid recursion
    // through that projection while retaining all source and commit checks.
    let operation = load_by_operation_id_without_terminal_projection_tx(
        connection,
        &AdmissionOperationId::from_persisted(id).map_err(error)?,
    )
    .map_err(error)?
    .ok_or_else(|| error("waiver operation absent"))?
    .operation;
    let journal = crate::budget_store::load_original_payment_journal(connection, id)
        .map_err(error)?
        .ok_or_else(|| error("original capture absent"))?;
    let retained = retained_request::load_retained_request_tx(connection, &operation)
        .map_err(error)?
        .ok_or_else(|| error("original request absent"))?;
    let request = retained.request_for_revalidation();
    let (raw_output_digest, encoded): (String, Vec<u8>) = connection
        .query_row(
            "SELECT raw_output_digest,outcome_json FROM tool_outcomes WHERE operation_id=?",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(error)?;
    let persisted: chio_kernel::tool_outcome::PersistedToolOutcomeRecordV1 =
        serde_json::from_slice(&encoded).map_err(error)?;
    let outcome =
        chio_kernel::tool_outcome::ToolOutcomeRecordV1::from_persisted(persisted).map_err(error)?;
    outcome.validate_against(&operation).map_err(error)?;
    if outcome.raw_output_digest().as_str() != raw_output_digest {
        return Err(error("raw outcome source differs"));
    }

    let retained_terms_digest = request
        .arguments
        .get(CAPTURE_WAIVER_TERMS_ARGUMENT)
        .and_then(|v| v.as_str())
        .ok_or_else(|| error("original request did not authorize capture waiver"))?
        .to_owned();
    Ok(CaptureWaiverSourceV1 {
        operation,
        journal,
        raw_output_digest,
        retained_terms_digest,
        issuer: request.capability.issuer.clone(),
        subject: request.capability.subject.clone(),
    })
}
pub(super) fn validate_budget(
    connection: &Connection,
    j: &PaymentJournalRecord,
) -> Result<(), CaptureWaiverError> {
    let hold = j
        .hold_id
        .as_deref()
        .ok_or_else(|| error("capture hold absent"))?;
    let valid: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(SELECT 1
            FROM budget_mutation_events e
            JOIN authority_global_commits g ON g.projection_kind='budget'
            AND g.projection_key=e.event_id
            AND g.store_uuid=e.authority_id
            AND g.store_lease_id=e.lease_id
            AND g.store_owner_epoch=e.lease_epoch
            WHERE e.event_id=?1
            AND e.hold_id=?2
            AND e.capability_id=?3
            AND e.grant_index=?4
            AND e.kind='reconcile_spend'
            AND e.exposure_units=?5
            AND e.realized_spend_units=?6)
            "#,
            params![
                format!("{hold}:reconcile"),
                hold,
                j.capability_id,
                j.grant_index,
                i64::try_from(j.amount_units).map_err(error)?,
                i64::try_from(
                    j.settle_amount_units
                        .ok_or_else(|| error("positive capture absent"))?
                )
                .map_err(error)?
            ],
            |r| r.get(0),
        )
        .map_err(error)?;
    if !valid {
        return Err(error("waiver lost exact positive budget source"));
    }
    Ok(())
}
pub(super) fn load_record(
    connection: &Connection,
    id: &str,
) -> Result<Option<ContractualCaptureWaiverRecordV1>, CaptureWaiverError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT sequence,request_digest,record_json,record_digest
            FROM capture_waiver_records
            WHERE operation_id=?
            ORDER BY sequence
            LIMIT 3
            "#,
        )
        .map_err(error)?;
    let rows = statement
        .query_map([id], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, String>(3)?,
            ))
        })
        .map_err(error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(error)?;
    if rows.is_empty() {
        return Ok(None);
    }
    if rows.len() > 2 {
        return Err(error("invalid waiver history length"));
    }
    let actual = source(connection, id)?;
    validate_budget(connection, &actual.journal)?;
    let mut prior: Option<ContractualCaptureWaiverRecordV1> = None;
    for (index, (seq, request_digest, bytes, digest)) in rows.into_iter().enumerate() {
        if bytes.is_empty() || bytes.len() > 1024 * 1024 {
            return Err(error("waiver history bounds"));
        }
        let record: ContractualCaptureWaiverRecordV1 =
            serde_json::from_slice(&bytes).map_err(error)?;
        record.validate()?;
        let original = AdmissionOperationV1::from_persisted(record.original_operation().clone())
            .map_err(error)?;
        // Admission lifecycle may advance after completion; immutable binding and raw outcome cannot.
        if original.binding() != actual.operation.binding()
            || original.tool_outcome_id() != actual.operation.tool_outcome_id()
            || record.original_journal() != &actual.journal
            || record.request().observation.body.raw_output_digest != actual.raw_output_digest
            || capture_waiver_digest(&record.request().terms)? != actual.retained_terms_digest
            || record.policy().receiver_key != actual.issuer
            || record.policy().counterparty_key != actual.subject
            || seq != i64::try_from(index + 1).map_err(error)?
            || record.sequence() != u64::try_from(seq).map_err(error)?
            || record.operation_id() != id
            || request_digest != capture_waiver_digest(record.request())?
            || sha256_hex(&bytes) != digest
            || canonical_json_bytes(&record).map_err(error)? != bytes
        {
            return Err(error("waiver lost original authoritative sources"));
        }
        let fence = record
            .completion()
            .map_or(record.accepted_fence(), |(_, f)| f);
        let covered: i64 = connection
            .query_row(
                r#"
            SELECT COUNT(*)
            FROM authority_global_commits
            WHERE projection_kind='payment_resolution'
            AND mutation_kind='capture_waiver'
            AND projection_key=?1
            AND projection_sequence=?2
            AND projection_reference_digest=?3
            AND store_uuid=?4
            AND store_lease_id=?5
            AND store_owner_epoch=?6
            "#,
                params![
                    format!("capture-waiver:{id}"),
                    seq,
                    digest,
                    fence.store_uuid,
                    fence.lease_id,
                    i64::try_from(fence.owner_epoch).map_err(error)?
                ],
                |r| r.get(0),
            )
            .map_err(error)?;
        if covered != 1 {
            return Err(error("waiver global coverage absent"));
        }
        if let Some(previous) = prior {
            let (at, f) = record
                .completion()
                .ok_or_else(|| error("waiver completion absent"))?;
            if capture_waiver_digest(&previous.complete(at, f.clone())?)? != digest {
                return Err(error("waiver completion changed accepted authority"));
            }
        }
        prior = Some(record);
    }
    Ok(prior)
}
pub(crate) fn load_effective_journal(
    connection: &Connection,
    original: &PaymentJournalRecord,
) -> Result<Option<PaymentJournalRecord>, CaptureWaiverError> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='capture_waiver_records' AND type='table')",
        [],
        |row| row.get(0),
    ).map_err(error)?;
    if !exists {
        return Ok(None);
    }
    load_record(connection, &original.operation_id)?
        .map(|r| r.current_journal())
        .transpose()
}
pub(crate) fn verify_invariants(connection: &Connection) -> Result<(), CaptureWaiverError> {
    let mut stmt = connection
        .prepare("SELECT DISTINCT operation_id FROM capture_waiver_records")
        .map_err(error)?;
    let ids = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(error)?;
    for id in ids {
        load_record(connection, &id)?.ok_or_else(|| error("waiver vanished"))?;
    }
    Ok(())
}

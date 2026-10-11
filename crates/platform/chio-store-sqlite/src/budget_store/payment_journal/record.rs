//! Decode retained debit and authorization custody without guessing legacy facts.
use super::*;

pub(super) fn payment_journal_from_row(
    row: &rusqlite::Row<'_>,
) -> Result<PaymentJournalRecord, rusqlite::Error> {
    let release_kind = row
        .get::<_, Option<String>>(13)?
        .map(|value| payment_release_authority_kind(&value))
        .transpose()?;
    let release_evidence_id = row.get::<_, Option<String>>(14)?;
    let release_evidence_digest = row.get::<_, Option<String>>(15)?;
    let release_operation_version = row
        .get::<_, Option<i64>>(16)?
        .map(|value| payment_u64_from_i64(value, "release operation_version"))
        .transpose()?;
    let release_authority = match (
        release_kind,
        release_evidence_id,
        release_evidence_digest,
        release_operation_version,
    ) {
        (Some(kind), Some(evidence_id), Some(evidence_digest), Some(operation_version)) => {
            Some(PaymentReleaseAuthorityBinding {
                kind,
                operation_id: row.get(0)?,
                operation_version,
                evidence_id,
                evidence_digest,
            })
        }
        (None, None, None, None) => None,
        _ => {
            return Err(invalid_payment_column(
                "incomplete release authority binding",
            ))
        }
    };
    let grant_index =
        u32::try_from(row.get::<_, i64>(4)?).map_err(|_| invalid_payment_column("grant_index"))?;
    let record = PaymentJournalRecord {
        operation_id: row.get(0)?,
        journal_version: payment_u64_from_i64(row.get(20)?, "journal_version")?,
        request_namespace_digest: row.get(1)?,
        request_id: row.get(2)?,
        capability_id: row.get(3)?,
        grant_index,
        hold_id: Some(row.get(5)?),
        rail: row.get(6)?,
        rail_mode: payment_rail_mode(&row.get::<_, String>(7)?)?,
        authorization_id: row.get(8)?,
        transaction_id: row.get(9)?,
        amount_units: payment_u64_from_i64(row.get(10)?, "amount_units")?,
        authorized_amount_units: row
            .get::<_, Option<i64>>(21)?
            .map(|value| payment_u64_from_i64(value, "authorized_amount_units"))
            .transpose()?,
        authorization_attempt: row
            .get::<_, Option<String>>(22)?
            .map(|value| payment_authorization_attempt(&value))
            .transpose()?,
        settle_action: row
            .get::<_, Option<String>>(11)?
            .map(|value| payment_settle_action(&value))
            .transpose()?,
        settle_amount_units: row
            .get::<_, Option<i64>>(12)?
            .map(|value| payment_u64_from_i64(value, "settle_amount_units"))
            .transpose()?,
        release_authority,
        currency: row.get(17)?,
        state: payment_journal_state(&row.get::<_, String>(18)?)?,
        created_at_unix_ms: payment_u64_from_i64(row.get(19)?, "created_at_unix_ms")?,
    };
    record
        .validate()
        .map_err(|_| invalid_payment_column("invalid payment journal record"))?;
    Ok(record)
}

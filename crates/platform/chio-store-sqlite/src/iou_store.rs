//! SQLite-backed persistence for IOU envelopes.
//!
//! The `iou_envelope` table is keyed by `receipt_id` so a finalized
//! receipt maps to exactly one row. Re-processing the same finalized
//! receipt is idempotent: a byte-identical envelope returns `Ok(false)`;
//! a different envelope returns [`IouEnvelopeStoreError::Conflict`].
//!
//! The migration is `CREATE TABLE IF NOT EXISTS` plus
//! `CREATE INDEX IF NOT EXISTS`, so it can run repeatedly against a
//! receipt-store database that already holds other tables.

use std::sync::Arc;

use chio_core::canonical::canonical_json_bytes;
use chio_credit::{IouEnvelope, IouEnvelopeStore, IouEnvelopeStoreError, IOU_ENVELOPE_SCHEMA};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::dead_letters::{
    receipt_connection_checkout, sqlite_connection_checkout, SqliteConnectionCheckout,
};

pub(crate) const MAX_IOU_CANONICAL_BYTES: usize = 65_536;
const MAX_IOU_ID_BYTES: usize = 512;
const MAX_IOU_TEXT_BYTES: usize = 512;

/// SQL migration applied by [`SqliteIouEnvelopeStore::open_with_pool`]
/// to create the `iou_envelope` table.
pub const IOU_ENVELOPE_MIGRATION: &str = r#"
CREATE TABLE IF NOT EXISTS iou_envelope (
    receipt_id TEXT PRIMARY KEY,
    iou_id TEXT NOT NULL,
    receipt_timestamp INTEGER NOT NULL,
    tenant_id TEXT,
    amount_units INTEGER NOT NULL,
    currency TEXT NOT NULL,
    issuer_key TEXT NOT NULL,
    canonical_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_iou_envelope_receipt_timestamp
    ON iou_envelope(receipt_timestamp);
CREATE INDEX IF NOT EXISTS idx_iou_envelope_tenant
    ON iou_envelope(tenant_id);
"#;

const IOU_ENVELOPE_LIVE_RECEIPT_TRIGGER: &str = r#"
CREATE TRIGGER IF NOT EXISTS iou_envelope_require_live_receipt_insert
BEFORE INSERT ON iou_envelope
WHEN NOT EXISTS (
    SELECT 1 FROM chio_tool_receipts AS receipt
    WHERE receipt.receipt_id = NEW.receipt_id
      AND receipt.timestamp = NEW.receipt_timestamp
)
BEGIN
    SELECT RAISE(ABORT, 'IOU envelope requires exact authoritative live receipt');
END;
"#;

const IOU_ENVELOPE_REJECT_UPDATE_TRIGGER: &str = r#"
CREATE TRIGGER IF NOT EXISTS iou_envelope_reject_update
BEFORE UPDATE ON iou_envelope
BEGIN
    SELECT RAISE(ABORT, 'IOU envelopes are immutable');
END;
"#;

const IOU_ENVELOPE_REJECT_DELETE_TRIGGER: &str = r#"
CREATE TRIGGER IF NOT EXISTS iou_envelope_reject_delete
BEFORE DELETE ON iou_envelope
BEGIN
    SELECT RAISE(ABORT, 'IOU envelopes are immutable');
END;
"#;

/// SQLite-backed [`IouEnvelopeStore`] implementation. Wraps an
/// existing connection pool from [`crate::SqliteReceiptStore`] so
/// IOU writes share the same SQLite database and journal mode.
pub struct SqliteIouEnvelopeStore {
    connection_checkout: SqliteConnectionCheckout,
    /// Present when opened alongside a receipt store: all writes are
    /// serialized through the receipt store's single writer connection.
    /// `None` only for the standalone `open_with_pool` path.
    writer: Option<crate::receipt_store::WriterHandle>,
}

impl SqliteIouEnvelopeStore {
    /// Open a store backed by the same pool as a sibling receipt
    /// store. Runs the additive migration if the table is absent.
    pub fn open_with_pool(
        pool: Pool<SqliteConnectionManager>,
    ) -> Result<Self, IouEnvelopeStoreError> {
        let connection_checkout = sqlite_connection_checkout(pool);
        let mut connection = connection_checkout().map_err(IouEnvelopeStoreError::Backend)?;
        let transaction = connection
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| IouEnvelopeStoreError::Backend(error.to_string()))?;
        transaction
            .execute_batch(IOU_ENVELOPE_MIGRATION)
            .map_err(|err| IouEnvelopeStoreError::Backend(err.to_string()))?;
        ensure_iou_immutability_schema(&transaction)?;
        transaction
            .commit()
            .map_err(|error| IouEnvelopeStoreError::Backend(error.to_string()))?;
        Ok(Self {
            connection_checkout,
            writer: None,
        })
    }

    /// Construct the store sharing the connection pool of an
    /// existing [`crate::SqliteReceiptStore`]. The receipt store has
    /// already configured WAL / synchronous=FULL on every connection
    /// out of the pool, so no additional connection setup is needed.
    /// Writes are routed through the receipt store's writer handle so
    /// they serialize with receipt commits on the single writer
    /// connection; reads keep using the reader pool.
    pub fn open_alongside(
        store: &crate::SqliteReceiptStore,
    ) -> Result<Self, IouEnvelopeStoreError> {
        let writer = store.writer_handle();
        // Run the additive migration on the writer connection so the reader
        // pool never executes DDL.
        writer
            .run_write(|connection| {
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(chio_kernel::ReceiptStoreError::from)?;
                transaction
                    .execute_batch(IOU_ENVELOPE_MIGRATION)
                    .map_err(chio_kernel::ReceiptStoreError::from)?;
                ensure_alongside_receipt_ownership_schema(&transaction)
                    .map_err(iou_to_receipt_error)?;
                transaction
                    .commit()
                    .map_err(chio_kernel::ReceiptStoreError::from)
            })
            .map_err(receipt_to_iou_error)?;
        Ok(Self {
            connection_checkout: receipt_connection_checkout(store),
            writer: Some(writer),
        })
    }
}

fn encode_envelope(envelope: &IouEnvelope) -> Result<Arc<[u8]>, IouEnvelopeStoreError> {
    let canonical = canonical_json_bytes(envelope)
        .map_err(|err| IouEnvelopeStoreError::Backend(err.to_string()))?;
    Ok(Arc::from(canonical.into_boxed_slice()))
}

fn decode_envelope(canonical: &str) -> Result<IouEnvelope, IouEnvelopeStoreError> {
    let envelope: IouEnvelope = serde_json::from_str(canonical)
        .map_err(|error| conflict(format!("persisted IOU envelope is malformed: {error}")))?;
    require_coherent_embedded_signature(&envelope)?;
    Ok(envelope)
}

fn conflict(message: impl Into<String>) -> IouEnvelopeStoreError {
    IouEnvelopeStoreError::Conflict(message.into())
}

fn require_coherent_embedded_signature(
    envelope: &IouEnvelope,
) -> Result<(), IouEnvelopeStoreError> {
    if !envelope
        .verify_signature()
        .map_err(|error| conflict(format!("IOU signature verification failed: {error}")))?
    {
        return Err(conflict("IOU envelope signature is invalid"));
    }
    Ok(())
}

fn iou_to_receipt_error(error: IouEnvelopeStoreError) -> chio_kernel::ReceiptStoreError {
    match error {
        IouEnvelopeStoreError::Conflict(message) => {
            chio_kernel::ReceiptStoreError::Conflict(message)
        }
        IouEnvelopeStoreError::Backend(message) => {
            chio_kernel::ReceiptStoreError::Canonical(message)
        }
    }
}

fn receipt_to_iou_error(error: chio_kernel::ReceiptStoreError) -> IouEnvelopeStoreError {
    match error {
        chio_kernel::ReceiptStoreError::Conflict(message) => {
            IouEnvelopeStoreError::Conflict(message)
        }
        chio_kernel::ReceiptStoreError::Canonical(message) => {
            IouEnvelopeStoreError::Backend(message)
        }
        other => IouEnvelopeStoreError::Backend(other.to_string()),
    }
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches(';')
        .to_string()
}

pub(crate) fn ensure_alongside_receipt_ownership_schema(
    connection: &rusqlite::Connection,
) -> Result<(), IouEnvelopeStoreError> {
    ensure_iou_immutability_schema(connection)?;
    ensure_iou_integrity_triggers(
        connection,
        &[(
            "iou_envelope_require_live_receipt_insert",
            IOU_ENVELOPE_LIVE_RECEIPT_TRIGGER,
        )],
    )?;
    let orphaned = connection
        .query_row(
            "SELECT envelope.receipt_id FROM iou_envelope AS envelope \
             WHERE NOT EXISTS ( \
                 SELECT 1 FROM chio_tool_receipts AS receipt \
                 WHERE receipt.receipt_id = envelope.receipt_id \
                   AND receipt.timestamp = envelope.receipt_timestamp \
             ) LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| IouEnvelopeStoreError::Backend(error.to_string()))?;
    if orphaned.is_some() {
        return Err(conflict(
            "IOU envelope exists without its exact authoritative live receipt",
        ));
    }
    Ok(())
}

pub(crate) fn ensure_iou_immutability_schema(
    connection: &rusqlite::Connection,
) -> Result<(), IouEnvelopeStoreError> {
    ensure_iou_integrity_triggers(
        connection,
        &[
            (
                "iou_envelope_reject_update",
                IOU_ENVELOPE_REJECT_UPDATE_TRIGGER,
            ),
            (
                "iou_envelope_reject_delete",
                IOU_ENVELOPE_REJECT_DELETE_TRIGGER,
            ),
        ],
    )
}

fn ensure_iou_integrity_triggers(
    connection: &rusqlite::Connection,
    triggers: &[(&str, &str)],
) -> Result<(), IouEnvelopeStoreError> {
    for &(name, expected) in triggers {
        connection
            .execute_batch(expected)
            .map_err(|error| IouEnvelopeStoreError::Backend(error.to_string()))?;
        let trigger_sql = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' \
                 AND name = ?1 AND tbl_name = 'iou_envelope'",
                params![name],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| IouEnvelopeStoreError::Backend(error.to_string()))?
            .ok_or_else(|| conflict(format!("IOU integrity trigger {name} is missing")))?;
        let expected = expected.replacen("CREATE TRIGGER IF NOT EXISTS", "CREATE TRIGGER", 1);
        if normalize_schema_sql(&trigger_sql) != normalize_schema_sql(&expected) {
            return Err(conflict(format!("IOU integrity trigger {name} is invalid")));
        }
    }
    Ok(())
}

fn require_authoritative_live_receipt(
    connection: &rusqlite::Connection,
    receipt_id: &str,
    receipt_timestamp: i64,
) -> Result<(), IouEnvelopeStoreError> {
    let live_timestamp = connection
        .query_row(
            "SELECT timestamp FROM chio_tool_receipts WHERE receipt_id = ?1",
            params![receipt_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|error| IouEnvelopeStoreError::Backend(error.to_string()))?;
    match live_timestamp {
        Some(timestamp) if timestamp == receipt_timestamp => Ok(()),
        Some(_) => Err(conflict(
            "IOU receipt timestamp diverges from the authoritative live receipt",
        )),
        None => Err(conflict(
            "IOU receipt is absent from authoritative live storage",
        )),
    }
}

fn validate_text(value: &str, field: &str) -> Result<(), IouEnvelopeStoreError> {
    if value.trim().is_empty() || value.len() > MAX_IOU_TEXT_BYTES {
        return Err(conflict(format!(
            "IOU {field} must be nonblank and at most {MAX_IOU_TEXT_BYTES} bytes"
        )));
    }
    Ok(())
}

pub(crate) fn validate_settlement_envelope(
    envelope: &IouEnvelope,
    trusted_iou_issuers: &[chio_core::PublicKey],
    trusted_kernel_keys: &[chio_core::PublicKey],
) -> Result<(), IouEnvelopeStoreError> {
    const MAX_TRUST_ROOTS: usize = 256;
    if trusted_iou_issuers.is_empty() {
        return Err(conflict("IOU issuer trust set must not be empty"));
    }
    if trusted_kernel_keys.is_empty() {
        return Err(conflict("kernel trust set must not be empty"));
    }
    if trusted_iou_issuers.len() > MAX_TRUST_ROOTS || trusted_kernel_keys.len() > MAX_TRUST_ROOTS {
        return Err(conflict(format!(
            "settlement trust domains are limited to {MAX_TRUST_ROOTS} keys each"
        )));
    }
    let distinct_iou_issuers = trusted_iou_issuers
        .iter()
        .map(chio_core::PublicKey::to_hex)
        .collect::<std::collections::BTreeSet<_>>();
    let distinct_kernel_keys = trusted_kernel_keys
        .iter()
        .map(chio_core::PublicKey::to_hex)
        .collect::<std::collections::BTreeSet<_>>();
    if distinct_iou_issuers.len() != trusted_iou_issuers.len()
        || distinct_kernel_keys.len() != trusted_kernel_keys.len()
    {
        return Err(conflict("settlement trust roots must be unique"));
    }
    if trusted_iou_issuers
        .iter()
        .any(|issuer| trusted_kernel_keys.contains(issuer))
    {
        return Err(conflict(
            "IOU issuer and kernel receipt signer trust domains must be disjoint",
        ));
    }
    if envelope.body.schema != IOU_ENVELOPE_SCHEMA {
        return Err(conflict("IOU envelope schema is invalid"));
    }
    if envelope.body.iou_id.trim().is_empty() || envelope.body.iou_id.len() > MAX_IOU_ID_BYTES {
        return Err(conflict(format!(
            "IOU id must be nonblank and at most {MAX_IOU_ID_BYTES} bytes"
        )));
    }
    validate_text(&envelope.body.receipt_id, "receipt id")?;
    validate_text(&envelope.body.tool_server, "tool server")?;
    validate_text(&envelope.body.tool_name, "tool name")?;
    validate_text(&envelope.body.capability_id, "capability id")?;
    validate_text(&envelope.body.currency, "currency")?;
    if envelope
        .body
        .tenant_id
        .as_ref()
        .is_some_and(|tenant| tenant.trim().is_empty() || tenant.len() > MAX_IOU_TEXT_BYTES)
    {
        return Err(conflict(format!(
            "IOU tenant id must be absent, nonblank, and at most {MAX_IOU_TEXT_BYTES} bytes"
        )));
    }
    if envelope.body.amount_units == 0 {
        return Err(conflict("IOU amount must be positive"));
    }
    let _ = i64::try_from(envelope.body.amount_units)
        .map_err(|_| conflict("IOU amount exceeds SQLite INTEGER range"))?;
    let _ = i64::try_from(envelope.body.receipt_timestamp)
        .map_err(|_| conflict("IOU receipt timestamp exceeds SQLite INTEGER range"))?;
    if !trusted_iou_issuers.contains(&envelope.body.issuer_key) {
        return Err(conflict("IOU envelope issuer is not trusted"));
    }
    if !envelope
        .verify_signature()
        .map_err(|error| conflict(format!("IOU signature verification failed: {error}")))?
    {
        return Err(conflict("IOU envelope signature is invalid"));
    }
    let canonical = canonical_json_bytes(envelope)
        .map_err(|error| conflict(format!("IOU canonical encoding failed: {error}")))?;
    if canonical.len() > MAX_IOU_CANONICAL_BYTES {
        return Err(conflict(format!(
            "IOU canonical envelope exceeds {MAX_IOU_CANONICAL_BYTES} bytes"
        )));
    }
    Ok(())
}

fn same_settlement_obligation(existing: &IouEnvelope, expected: &IouEnvelope) -> bool {
    existing.body.schema == expected.body.schema
        && existing.body.iou_id == expected.body.iou_id
        && existing.body.receipt_id == expected.body.receipt_id
        && existing.body.receipt_timestamp == expected.body.receipt_timestamp
        && existing.body.tenant_id == expected.body.tenant_id
        && existing.body.tool_server == expected.body.tool_server
        && existing.body.tool_name == expected.body.tool_name
        && existing.body.capability_id == expected.body.capability_id
        && existing.body.amount_units == expected.body.amount_units
        && existing.body.currency == expected.body.currency
}

/// Insert the expected settlement IOU, or accept a previously committed IOU
/// issued by another independently trusted issuer. Existing bytes are never
/// rewritten. The caller must hold the settlement lease transaction fence.
pub(crate) fn insert_or_validate_settlement_envelope_on_connection(
    connection: &rusqlite::Connection,
    expected: &IouEnvelope,
    trusted_iou_issuers: &[chio_core::PublicKey],
    trusted_kernel_keys: &[chio_core::PublicKey],
) -> Result<bool, IouEnvelopeStoreError> {
    let canonical_bytes = encode_envelope(expected)?;
    let canonical_str = std::str::from_utf8(&canonical_bytes)
        .map_err(|error| IouEnvelopeStoreError::Backend(error.to_string()))?;
    let issuer_key_str = serde_json::to_string(&expected.body.issuer_key)
        .map_err(|error| IouEnvelopeStoreError::Backend(error.to_string()))?;
    let receipt_timestamp = i64::try_from(expected.body.receipt_timestamp)
        .map_err(|error| IouEnvelopeStoreError::Backend(error.to_string()))?;
    let amount_units = i64::try_from(expected.body.amount_units)
        .map_err(|error| IouEnvelopeStoreError::Backend(error.to_string()))?;

    let existing_size = connection
        .query_row(
            "SELECT length(CAST(canonical_json AS BLOB)) FROM iou_envelope WHERE receipt_id = ?1",
            params![expected.body.receipt_id.as_str()],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|error| IouEnvelopeStoreError::Backend(error.to_string()))?;
    let Some(existing_size) = existing_size else {
        return insert_envelope_on_connection(
            connection,
            expected.body.receipt_id.as_str(),
            expected.body.iou_id.as_str(),
            receipt_timestamp,
            expected.body.tenant_id.as_deref(),
            amount_units,
            expected.body.currency.as_str(),
            issuer_key_str.as_str(),
            canonical_str,
        );
    };
    let existing_size = usize::try_from(existing_size)
        .map_err(|_| conflict("persisted IOU canonical envelope has an invalid size"))?;
    if existing_size > MAX_IOU_CANONICAL_BYTES {
        return Err(conflict(format!(
            "persisted IOU canonical envelope exceeds {MAX_IOU_CANONICAL_BYTES} bytes"
        )));
    }

    let existing_row = connection
        .query_row(
            "SELECT iou_id, receipt_timestamp, tenant_id, amount_units, currency, issuer_key, canonical_json \
             FROM iou_envelope WHERE receipt_id = ?1",
            params![expected.body.receipt_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .map_err(|error| IouEnvelopeStoreError::Backend(error.to_string()))?;
    let (iou_id, receipt_ts, tenant_id, amount, currency, issuer_key, canonical) = existing_row;
    let existing = decode_envelope(&canonical)?;
    let recanonical = encode_envelope(&existing)?;
    if recanonical.as_ref() != canonical.as_bytes() {
        return Err(conflict("persisted IOU envelope is not canonical JSON"));
    }
    validate_settlement_envelope(&existing, trusted_iou_issuers, trusted_kernel_keys)?;
    let stored_issuer = serde_json::to_string(&existing.body.issuer_key)
        .map_err(|error| IouEnvelopeStoreError::Backend(error.to_string()))?;
    let existing_receipt_ts = i64::try_from(existing.body.receipt_timestamp)
        .map_err(|_| conflict("persisted IOU receipt timestamp exceeds SQLite INTEGER range"))?;
    let existing_amount = i64::try_from(existing.body.amount_units)
        .map_err(|_| conflict("persisted IOU amount exceeds SQLite INTEGER range"))?;
    if iou_id != existing.body.iou_id
        || receipt_ts != existing_receipt_ts
        || tenant_id != existing.body.tenant_id
        || amount != existing_amount
        || currency != existing.body.currency
        || issuer_key != stored_issuer
    {
        return Err(conflict(
            "persisted IOU projections do not match canonical bytes",
        ));
    }
    if !same_settlement_obligation(&existing, expected) {
        return Err(conflict(format!(
            "IOU row for receipt_id={} has divergent settlement terms",
            expected.body.receipt_id
        )));
    }
    Ok(false)
}

#[allow(clippy::too_many_arguments)]
fn insert_envelope_on_connection(
    connection: &rusqlite::Connection,
    receipt_id: &str,
    iou_id: &str,
    receipt_ts: i64,
    tenant_id: Option<&str>,
    amount: i64,
    currency: &str,
    issuer_key_str: &str,
    canonical_str: &str,
) -> Result<bool, IouEnvelopeStoreError> {
    let inserted = connection
        .execute(
            r#"
            INSERT INTO iou_envelope (
                receipt_id,
                iou_id,
                receipt_timestamp,
                tenant_id,
                amount_units,
                currency,
                issuer_key,
                canonical_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(receipt_id) DO NOTHING
            "#,
            params![
                receipt_id,
                iou_id,
                receipt_ts,
                tenant_id,
                amount,
                currency,
                issuer_key_str,
                canonical_str,
            ],
        )
        .map_err(|err| IouEnvelopeStoreError::Backend(err.to_string()))?;
    if inserted == 1 {
        return Ok(true);
    }

    let existing = connection
        .query_row(
            "SELECT canonical_json FROM iou_envelope WHERE receipt_id = ?1",
            params![receipt_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|err| IouEnvelopeStoreError::Backend(err.to_string()))?;
    match existing {
        Some(existing_canonical) if existing_canonical == canonical_str => Ok(false),
        Some(_) => Err(IouEnvelopeStoreError::Conflict(format!(
            "iou_envelope row for receipt_id={receipt_id} already exists with different bytes"
        ))),
        None => Err(IouEnvelopeStoreError::Backend(format!(
            "iou_envelope conflict for receipt_id={receipt_id} but no row was readable"
        ))),
    }
}

impl IouEnvelopeStore for SqliteIouEnvelopeStore {
    fn insert(&self, envelope: &IouEnvelope) -> Result<bool, IouEnvelopeStoreError> {
        require_coherent_embedded_signature(envelope)?;
        let canonical_bytes = encode_envelope(envelope)?;
        let canonical_str = std::str::from_utf8(&canonical_bytes)
            .map_err(|err| IouEnvelopeStoreError::Backend(err.to_string()))?;
        let issuer_key_str = serde_json::to_string(&envelope.body.issuer_key)
            .map_err(|err| IouEnvelopeStoreError::Backend(err.to_string()))?;
        let amount: i64 =
            envelope
                .body
                .amount_units
                .try_into()
                .map_err(|err: std::num::TryFromIntError| {
                    IouEnvelopeStoreError::Backend(err.to_string())
                })?;
        let receipt_ts: i64 = envelope.body.receipt_timestamp.try_into().map_err(
            |err: std::num::TryFromIntError| IouEnvelopeStoreError::Backend(err.to_string()),
        )?;

        match &self.writer {
            Some(writer) => {
                let receipt_id = envelope.body.receipt_id.clone();
                let iou_id = envelope.body.iou_id.clone();
                let tenant_id = envelope.body.tenant_id.clone();
                let currency = envelope.body.currency.clone();
                let issuer_key = issuer_key_str.clone();
                let canonical = canonical_str.to_string();
                writer
                    .run_write(move |connection| {
                        let transaction = connection
                            .transaction_with_behavior(TransactionBehavior::Immediate)
                            .map_err(chio_kernel::ReceiptStoreError::from)?;
                        require_authoritative_live_receipt(&transaction, &receipt_id, receipt_ts)
                            .map_err(iou_to_receipt_error)?;
                        let inserted = insert_envelope_on_connection(
                            &transaction,
                            &receipt_id,
                            &iou_id,
                            receipt_ts,
                            tenant_id.as_deref(),
                            amount,
                            &currency,
                            &issuer_key,
                            &canonical,
                        )
                        .map_err(iou_to_receipt_error)?;
                        transaction
                            .commit()
                            .map_err(chio_kernel::ReceiptStoreError::from)?;
                        Ok(inserted)
                    })
                    .map_err(receipt_to_iou_error)
            }
            None => {
                let connection =
                    (self.connection_checkout)().map_err(IouEnvelopeStoreError::Backend)?;
                insert_envelope_on_connection(
                    connection.connection(),
                    envelope.body.receipt_id.as_str(),
                    envelope.body.iou_id.as_str(),
                    receipt_ts,
                    envelope.body.tenant_id.as_deref(),
                    amount,
                    envelope.body.currency.as_str(),
                    issuer_key_str.as_str(),
                    canonical_str,
                )
            }
        }
    }

    fn get_by_receipt_id(
        &self,
        receipt_id: &str,
    ) -> Result<Option<IouEnvelope>, IouEnvelopeStoreError> {
        let connection = (self.connection_checkout)().map_err(IouEnvelopeStoreError::Backend)?;
        let row = connection
            .connection()
            .query_row(
                "SELECT canonical_json FROM iou_envelope WHERE receipt_id = ?1",
                params![receipt_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|err| IouEnvelopeStoreError::Backend(err.to_string()))?;
        match row {
            Some(canonical) => Ok(Some(decode_envelope(&canonical)?)),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_core::crypto::{sha256_hex, Ed25519Backend, Keypair, SigningAlgorithm};
    use chio_core::receipt::{
        body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
        economics::FinancialReceiptMetadata, economics::SettlementStatus, kinds::TrustLevel,
        metadata::GuardEvidence,
    };
    use chio_credit::{CreditEvaluatorHook, LocalCreditAccount};
    use chio_kernel::ReceiptStore;
    use chio_test_support::prelude::*;
    use tempfile::tempdir;

    fn make_priced_receipt(kp: &Keypair, receipt_id: &str, cost: u64) -> ChioReceipt {
        let financial = FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged: cost,
            currency: "USD".to_string(),
            budget_remaining: 1000 - cost,
            budget_total: 1000,
            delegation_depth: 1,
            root_budget_holder: "tenant-a".to_string(),
            payment_reference: None,
            settlement_status: SettlementStatus::Pending,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: None,
        };
        let body = ChioReceiptBody {
            id: receipt_id.to_string(),
            timestamp: 1_710_000_000,
            capability_id: "cap-001".to_string(),
            tool_server: "srv".to_string(),
            tool_name: "tool".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({})).unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: sha256_hex(b"{}"),
            policy_hash: "policy".to_string(),
            evidence: vec![GuardEvidence {
                guard_name: "G".to_string(),
                verdict: true,
                details: None,
            }],
            metadata: Some(serde_json::json!({"financial": financial})),
            trust_level: TrustLevel::default(),
            tenant_id: Some("tenant-a".to_string()),
            kernel_key: kp.public_key(),
            bbs_projection_version: None,
        };
        ChioReceipt::sign(body, kp).unwrap()
    }

    fn open_store() -> SqliteIouEnvelopeStore {
        let dir = tempdir().unwrap();
        let path = dir.path().join("iou.sqlite");
        // Construct a pool directly so the test does not require a
        // sibling receipt store.
        let manager = SqliteConnectionManager::file(path);
        let pool = Pool::builder().max_size(2).build(manager).unwrap();
        // Leak the tempdir so the file outlives the test.
        std::mem::forget(dir);
        SqliteIouEnvelopeStore::open_with_pool(pool).unwrap()
    }

    fn open_store_at(path: &std::path::Path) -> SqliteIouEnvelopeStore {
        let manager = SqliteConnectionManager::file(path);
        let pool = Pool::builder().max_size(2).build(manager).unwrap();
        SqliteIouEnvelopeStore::open_with_pool(pool).unwrap()
    }

    fn wait_for_writer_queue_depth(store: &crate::SqliteReceiptStore, minimum: u64) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let depth = store.receipt_store_health().unwrap().writer.queue_depth;
            if depth >= minimum {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "writer queue depth stayed at {depth}, below required {minimum}"
            );
            std::thread::yield_now();
        }
    }

    #[test]
    fn insert_then_get_round_trip() {
        let kp = Keypair::generate();
        let account = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp.clone()),
            [kp.public_key()],
        );
        let receipt = make_priced_receipt(&kp, "rcpt-store-1", 250);
        let envelope = account.evaluate(&receipt).unwrap().unwrap();
        let store = open_store();
        assert!(store.insert(&envelope).unwrap());
        let fetched = store
            .get_by_receipt_id(&receipt.id)
            .unwrap()
            .expect("envelope was inserted");
        assert_eq!(fetched, envelope);
    }

    #[test]
    fn insert_rejects_declared_hybrid_algorithm_for_classical_signature() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("iou-algorithm-mismatch.sqlite3");
        let kp = Keypair::generate();
        let account = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp.clone()),
            [kp.public_key()],
        );
        let receipt = make_priced_receipt(&kp, "rcpt-algorithm-mismatch", 250);
        let mut envelope = account.evaluate(&receipt).unwrap().unwrap();
        envelope.algorithm = Some(SigningAlgorithm::Hybrid);

        let store = open_store_at(&path);
        assert!(matches!(
            store.insert(&envelope),
            Err(IouEnvelopeStoreError::Conflict(_))
        ));
        drop(store);

        let reopened = open_store_at(&path);
        assert!(reopened.get_by_receipt_id(&receipt.id).unwrap().is_none());
    }

    #[test]
    fn reopen_reads_reject_unknown_fields_and_algorithm_mismatch() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("iou-reopen-wire-validation.sqlite3");
        let kp = Keypair::generate();
        let account = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp.clone()),
            [kp.public_key()],
        );
        let unknown_receipt = make_priced_receipt(&kp, "rcpt-reopen-unknown", 100);
        let algorithm_receipt = make_priced_receipt(&kp, "rcpt-reopen-algorithm", 200);
        let unknown_envelope = account.evaluate(&unknown_receipt).unwrap().unwrap();
        let algorithm_envelope = account.evaluate(&algorithm_receipt).unwrap().unwrap();
        let store = open_store_at(&path);
        assert!(store.insert(&unknown_envelope).unwrap());
        assert!(store.insert(&algorithm_envelope).unwrap());
        drop(store);

        let mut unknown_value = serde_json::to_value(&unknown_envelope).unwrap();
        unknown_value
            .as_object_mut()
            .unwrap()
            .insert("unsigned_extension".to_string(), serde_json::json!(true));
        let unknown_canonical =
            String::from_utf8(canonical_json_bytes(&unknown_value).unwrap()).unwrap();

        let mut algorithm_value = serde_json::to_value(&algorithm_envelope).unwrap();
        algorithm_value["algorithm"] = serde_json::json!("hybrid");
        let algorithm_canonical =
            String::from_utf8(canonical_json_bytes(&algorithm_value).unwrap()).unwrap();

        let raw = rusqlite::Connection::open(&path).unwrap();
        raw.execute_batch("DROP TRIGGER iou_envelope_reject_update;")
            .unwrap();
        raw.execute(
            "UPDATE iou_envelope SET canonical_json = ?1 WHERE receipt_id = ?2",
            params![unknown_canonical, unknown_receipt.id.as_str()],
        )
        .unwrap();
        raw.execute(
            "UPDATE iou_envelope SET canonical_json = ?1 WHERE receipt_id = ?2",
            params![algorithm_canonical, algorithm_receipt.id.as_str()],
        )
        .unwrap();
        drop(raw);

        let reopened = open_store_at(&path);
        assert!(matches!(
            reopened.get_by_receipt_id(&unknown_receipt.id),
            Err(IouEnvelopeStoreError::Conflict(_))
        ));
        assert!(matches!(
            reopened.get_by_receipt_id(&algorithm_receipt.id),
            Err(IouEnvelopeStoreError::Conflict(_))
        ));
    }

    #[test]
    fn duplicate_insert_is_idempotent() {
        let kp = Keypair::generate();
        let account = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp.clone()),
            [kp.public_key()],
        );
        let receipt = make_priced_receipt(&kp, "rcpt-store-2", 100);
        let envelope = account.evaluate(&receipt).unwrap().unwrap();
        let store = open_store();
        assert!(store.insert(&envelope).unwrap());
        assert!(!store.insert(&envelope).unwrap());
    }

    #[test]
    fn standalone_iou_rows_reject_raw_mutation() {
        let kp = Keypair::generate();
        let account = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp.clone()),
            [kp.public_key()],
        );
        let receipt = make_priced_receipt(&kp, "rcpt-standalone-immutable", 100);
        let envelope = account.evaluate(&receipt).unwrap().unwrap();
        let store = open_store();
        assert!(store.insert(&envelope).unwrap());
        let connection = (store.connection_checkout)().unwrap();
        assert!(connection
            .connection()
            .execute(
                "UPDATE iou_envelope SET amount_units = amount_units + 1 \
                 WHERE receipt_id = ?1",
                params![receipt.id.as_str()],
            )
            .is_err());
        assert!(connection
            .connection()
            .execute(
                "DELETE FROM iou_envelope WHERE receipt_id = ?1",
                params![receipt.id.as_str()],
            )
            .is_err());
    }

    #[test]
    fn conflicting_envelope_for_same_receipt_id_errors() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt_a = make_priced_receipt(&kp_a, "rcpt-store-3", 100);
        let env_a = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp_a.clone()),
            [kp_a.public_key()],
        )
        .evaluate(&receipt_a)
        .unwrap()
        .unwrap();
        let env_b = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp_b),
            [kp_a.public_key()],
        )
        .evaluate(&receipt_a)
        .unwrap()
        .unwrap();
        assert_eq!(env_a.body.receipt_id, env_b.body.receipt_id);
        assert_ne!(env_a.body.issuer_key, env_b.body.issuer_key);
        let store = open_store();
        assert!(store.insert(&env_a).unwrap());
        match store.insert(&env_b) {
            Err(IouEnvelopeStoreError::Conflict(_)) => {}
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn get_missing_returns_none() {
        let store = open_store();
        assert!(store.get_by_receipt_id("nope").unwrap().is_none());
    }

    #[test]
    fn open_alongside_routes_writes_through_the_receipt_writer() {
        let dir = chio_test_support::private_fs::private_tempdir("receipt-iou-alongside")
            .test_expect("create private receipt IOU directory");
        let path = dir.path().join("iou-alongside.sqlite3");
        let receipt_store = crate::SqliteReceiptStore::open(&path).unwrap();
        let store = SqliteIouEnvelopeStore::open_alongside(&receipt_store).unwrap();
        assert!(
            store.writer.is_some(),
            "open_alongside must carry the receipt writer handle"
        );

        let kp = Keypair::generate();
        let account = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp.clone()),
            [kp.public_key()],
        );
        let receipt = make_priced_receipt(&kp, "rcpt-alongside-1", 42);
        receipt_store.append_chio_receipt(&receipt).unwrap();
        let envelope = account.evaluate(&receipt).unwrap().unwrap();
        let mut mismatched_timestamp = envelope.clone();
        mismatched_timestamp.body.receipt_timestamp += 1;
        assert!(matches!(
            store.insert(&mismatched_timestamp),
            Err(IouEnvelopeStoreError::Conflict(_))
        ));
        assert!(store.get_by_receipt_id(&receipt.id).unwrap().is_none());
        assert!(store.insert(&envelope).unwrap());
        assert!(!store.insert(&envelope).unwrap());
        let fetched = store
            .get_by_receipt_id(&receipt.id)
            .unwrap()
            .expect("envelope was inserted");
        assert_eq!(fetched, envelope);
        std::mem::forget(dir);
    }

    #[test]
    fn alongside_iou_rows_reject_raw_mutation() {
        let dir = chio_test_support::private_fs::private_tempdir("receipt-iou-immutable")
            .test_expect("create private immutable IOU directory");
        let path = dir.path().join("iou-immutable.sqlite3");
        let receipt_store = crate::SqliteReceiptStore::open(&path).unwrap();
        let store = SqliteIouEnvelopeStore::open_alongside(&receipt_store).unwrap();
        let kernel = Keypair::from_seed(&[91; 32]);
        let issuer = Keypair::from_seed(&[92; 32]);
        let receipt = make_priced_receipt(&kernel, "rcpt-immutable", 42);
        receipt_store.append_chio_receipt(&receipt).unwrap();
        let envelope = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(issuer),
            [kernel.public_key()],
        )
        .evaluate(&receipt)
        .unwrap()
        .unwrap();
        assert!(store.insert(&envelope).unwrap());

        let raw = rusqlite::Connection::open(&path).unwrap();
        assert!(raw
            .execute(
                "UPDATE iou_envelope SET receipt_timestamp = receipt_timestamp + 1 \
                 WHERE receipt_id = ?1",
                params![receipt.id.as_str()],
            )
            .is_err());
        assert!(raw
            .execute(
                "DELETE FROM iou_envelope WHERE receipt_id = ?1",
                params![receipt.id.as_str()],
            )
            .is_err());
        let persisted_timestamp: i64 = raw
            .query_row(
                "SELECT receipt_timestamp FROM iou_envelope WHERE receipt_id = ?1",
                params![receipt.id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            persisted_timestamp,
            i64::try_from(receipt.timestamp).unwrap()
        );
    }

    #[test]
    fn orphaned_existing_iou_rejects_without_partial_guard_installation() {
        let dir = chio_test_support::private_fs::private_tempdir("receipt-iou-orphaned")
            .test_expect("create private orphaned IOU directory");
        let path = dir.path().join("iou-orphaned-migration.sqlite3");
        let receipt_store = crate::SqliteReceiptStore::open(&path).unwrap();
        let raw = rusqlite::Connection::open(&path).unwrap();
        raw.execute_batch(IOU_ENVELOPE_MIGRATION).unwrap();
        raw.execute(
            "INSERT INTO iou_envelope \
             (receipt_id, iou_id, receipt_timestamp, tenant_id, amount_units, currency, issuer_key, canonical_json) \
             VALUES ('orphan', 'iou-orphan', 1, NULL, 1, 'USD', 'issuer', '{}')",
            [],
        )
        .unwrap();
        drop(raw);

        assert!(matches!(
            SqliteIouEnvelopeStore::open_alongside(&receipt_store),
            Err(IouEnvelopeStoreError::Conflict(_))
        ));
        let raw = rusqlite::Connection::open(&path).unwrap();
        let installed_guards: i64 = raw
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' \
                 AND tbl_name = 'iou_envelope' \
                 AND name IN ('iou_envelope_require_live_receipt_insert', \
                              'iou_envelope_reject_update', \
                              'iou_envelope_reject_delete')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(installed_guards, 0);
        let orphan_count: i64 = raw
            .query_row(
                "SELECT COUNT(*) FROM iou_envelope WHERE receipt_id = 'orphan'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(orphan_count, 1);
    }

    #[test]
    fn failed_writer_routed_insert_is_recorded_as_a_writer_failure() {
        // When an IOU store is opened alongside a
        // receipt store, a failed insert routed through the shared writer must
        // surface as a writer FAILURE, not be swallowed as a committed write, so
        // the receipt writer health telemetry stays accurate. The caller still
        // receives the original Conflict variant.
        let dir = chio_test_support::private_fs::private_tempdir("receipt-iou-writer-failure")
            .test_expect("create private IOU writer directory");
        let path = dir.path().join("iou-writer-failure.sqlite3");
        let receipt_store = crate::SqliteReceiptStore::open(&path).unwrap();
        let store = SqliteIouEnvelopeStore::open_alongside(&receipt_store).unwrap();
        assert!(store.writer.is_some());

        // Two envelopes share a receipt_id but carry different bytes (different
        // kernel signer), so the second insert conflicts.
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();
        let receipt = make_priced_receipt(&kp_a, "rcpt-writer-fail-1", 100);
        receipt_store.append_chio_receipt(&receipt).unwrap();
        let env_a = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp_a.clone()),
            [kp_a.public_key()],
        )
        .evaluate(&receipt)
        .unwrap()
        .unwrap();
        let env_b = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(kp_b),
            [kp_a.public_key()],
        )
        .evaluate(&receipt)
        .unwrap()
        .unwrap();
        assert_eq!(env_a.body.receipt_id, env_b.body.receipt_id);
        assert_ne!(env_a.body.issuer_key, env_b.body.issuer_key);

        assert!(store.insert(&env_a).unwrap());

        // `flush_receipt_writes` is a writer barrier, so its snapshot reflects the
        // fully-processed job outcome (no race with `record_write_job_outcome`).
        let failed_before = receipt_store
            .flush_receipt_writes()
            .unwrap()
            .writer
            .failed_total;

        // The conflicting insert must surface as a Conflict to the caller AND be
        // recorded as a writer failure.
        match store.insert(&env_b) {
            Err(IouEnvelopeStoreError::Conflict(_)) => {}
            other => panic!("expected Conflict, got {other:?}"),
        }

        let failed_after = receipt_store
            .flush_receipt_writes()
            .unwrap()
            .writer
            .failed_total;
        assert_eq!(
            failed_after,
            failed_before + 1,
            "a failed IOU insert must increment the receipt writer failed_total"
        );
        std::mem::forget(dir);
    }

    #[test]
    fn alongside_iou_writes_queued_or_blocked_after_rotation_cannot_strand_state() {
        let dir = chio_test_support::private_fs::private_tempdir("receipt-iou-rotation")
            .test_expect("create private IOU rotation directory");
        let path = dir.path().join("iou-post-rotation-ownership.sqlite3");
        let archive = dir
            .path()
            .join("iou-post-rotation-ownership-archive.sqlite3");
        let archive_path = archive.to_string_lossy().into_owned();
        let keypair = Keypair::from_seed(&[83; 32]);
        let receipts = std::sync::Arc::new(crate::SqliteReceiptStore::open(&path).unwrap());
        let receipt = make_priced_receipt(&keypair, "rcpt-post-rotation", 42);
        receipts.append_chio_receipt(&receipt).unwrap();
        assert!(
            receipts
                .create_next_receipt_checkpoint(1, &keypair)
                .unwrap()
                .created
        );
        let account = LocalCreditAccount::new_with_trusted_kernel_keys(
            Ed25519Backend::new(keypair.clone()),
            [keypair.public_key()],
        );
        let envelope = account.evaluate(&receipt).unwrap().unwrap();
        let store =
            std::sync::Arc::new(SqliteIouEnvelopeStore::open_alongside(receipts.as_ref()).unwrap());

        // Keep a separate writer and connection topology alive from before the
        // rotation, as a second process would.
        let independent_receipts =
            std::sync::Arc::new(crate::SqliteReceiptStore::open_existing(&path).unwrap());
        let independent_store =
            SqliteIouEnvelopeStore::open_alongside(independent_receipts.as_ref()).unwrap();

        // Park the local receipt actor, then establish FIFO ordering with a
        // rotation command ahead of the dependent IOU insert.
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker_handle = receipts.writer_handle();
        let blocker = std::thread::spawn(move || {
            blocker_handle.run_write(move |_connection| {
                started_tx.send(()).unwrap();
                release_rx
                    .recv_timeout(std::time::Duration::from_secs(30))
                    .unwrap();
                Ok(())
            })
        });
        started_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();

        let rotation_receipts = std::sync::Arc::clone(&receipts);
        let rotation_archive_path = archive_path.clone();
        let cutoff = receipt.timestamp + 1;
        let rotation = std::thread::spawn(move || {
            rotation_receipts.archive_receipts_before(cutoff, &rotation_archive_path)
        });
        wait_for_writer_queue_depth(receipts.as_ref(), 1);

        let queued_store = std::sync::Arc::clone(&store);
        let queued_envelope = envelope.clone();
        let queued = std::thread::spawn(move || queued_store.insert(&queued_envelope));
        wait_for_writer_queue_depth(receipts.as_ref(), 2);

        release_tx.send(()).unwrap();
        blocker.join().unwrap().unwrap();
        assert_eq!(rotation.join().unwrap().unwrap(), 1);
        assert!(matches!(
            queued.join().unwrap(),
            Err(IouEnvelopeStoreError::Conflict(_))
        ));
        assert!(store.get_by_receipt_id(&receipt.id).unwrap().is_none());

        let live_count: i64 = receipts
            .reader_connection_for_test()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM chio_tool_receipts WHERE receipt_id = ?1",
                params![receipt.id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(live_count, 0, "rotation must remove the live owner row");
        assert!(
            receipts.load_chio_receipt(&receipt.id).unwrap().is_some(),
            "the receipt remains readable only through the trusted archive"
        );
        let restored_immutability_guards: i64 = rusqlite::Connection::open(&path)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' \
                 AND tbl_name = 'iou_envelope' \
                 AND name IN ('iou_envelope_reject_update', 'iou_envelope_reject_delete')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(restored_immutability_guards, 2);

        // Block the independent writer at SQLite after rotation. Once
        // unblocked it must validate against live storage again and fail; the
        // archived receipt cannot authorize a new dependent row.
        let database_blocker = rusqlite::Connection::open(&path).unwrap();
        database_blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
        let independent_envelope = envelope.clone();
        let independent =
            std::thread::spawn(move || independent_store.insert(&independent_envelope));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let health = independent_receipts.receipt_store_health().unwrap();
            if health.writer.inflight == 1 && health.writer.queue_depth == 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "independent IOU writer did not block on the database lock"
            );
            std::thread::yield_now();
        }
        database_blocker.execute_batch("ROLLBACK").unwrap();
        assert!(matches!(
            independent.join().unwrap(),
            Err(IouEnvelopeStoreError::Conflict(_))
        ));
        assert!(store.get_by_receipt_id(&receipt.id).unwrap().is_none());
    }
}

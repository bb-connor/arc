//! One source-projection rule for retained reads and query snapshots.
//!
//! Filters and counts are derived from signed receipt content. A stored source
//! row is accepted only when its unsigned columns equal that projection.
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::lineage::ChildRequestReceipt;
use chio_kernel::ReceiptStoreError;
use rusqlite::{params, Connection, Statement};

use crate::receipt_store::support::{
    capability_lineage_store_error, extract_receipt_attribution, receipt_cost_projection,
    receipt_decision_kind, sqlite_i64, terminal_state_kind,
};
use crate::receipt_store::SqliteReceiptStore;

/// Exact source-row comparison for a tool receipt. Parameters are bound by
/// [`SignedToolProjection::source_matches`].
///
/// A subject or issuer the receipt does not sign comes from capability
/// lineage. An archived row records the lineage that existed when it was
/// archived, and lineage only gains rows, so such a value may be recorded
/// nowhere in the archive (?18, ?19) while current lineage supplies it. Any
/// value the archive does record must equal the projection.
pub(crate) const TOOL_SOURCE_PROJECTION_SQL: &str =
    "SELECT COUNT(*) = 1 AND COALESCE(MIN(r.receipt_id = ?2 AND r.raw_json = ?3
       AND r.timestamp = ?4 AND r.capability_id = ?5
       AND r.tool_server = ?6 AND r.tool_name = ?7 AND r.decision_kind = ?8
       AND r.tenant_id IS ?9 AND r.cost_currency IS ?10
       AND r.cost_charged_be IS ?11 AND r.attempted_cost_be IS ?12
       AND (COALESCE(r.subject_key, cl.subject_key) IS ?13
            OR (?18 AND r.subject_key IS NULL AND cl.capability_id IS NULL))
       AND (COALESCE(r.issuer_key, cl.issuer_key) IS ?14
            OR (?19 AND r.issuer_key IS NULL AND cl.capability_id IS NULL))
       AND r.grant_index IS ?15 AND r.policy_hash = ?16 AND r.content_hash = ?17), 0)
     FROM chio_tool_receipts r
     LEFT JOIN capability_lineage cl ON cl.capability_id = r.capability_id
     WHERE r.seq = ?1";

/// Exact source-row comparison for a child receipt.
pub(crate) const CHILD_SOURCE_PROJECTION_SQL: &str =
    "SELECT COUNT(*) = 1 AND COALESCE(MIN(receipt_id = ?2 AND raw_json = ?3 AND timestamp = ?4
       AND session_id = ?5 AND parent_request_id = ?6 AND request_id = ?7
       AND operation_kind = ?8 AND terminal_state = ?9
       AND policy_hash = ?10 AND outcome_hash = ?11), 0)
     FROM chio_child_receipts WHERE seq = ?1";

/// Queryable columns of a tool receipt, derived from its signed body. The
/// subject falls back to validated capability lineage only when the receipt
/// carries no signed attribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignedToolProjection {
    pub(crate) receipt_id: String,
    pub(crate) timestamp: i64,
    pub(crate) capability_id: String,
    pub(crate) tool_server: String,
    pub(crate) tool_name: String,
    pub(crate) decision: &'static str,
    pub(crate) tenant: Option<String>,
    pub(crate) cost_currency: Option<String>,
    pub(crate) cost_charged: Option<Vec<u8>>,
    pub(crate) attempted_cost: Option<Vec<u8>>,
    pub(crate) subject: Option<String>,
    pub(crate) subject_signed: bool,
    pub(crate) issuer: Option<String>,
    pub(crate) issuer_signed: bool,
    pub(crate) grant_index: Option<u32>,
    pub(crate) policy_hash: String,
    pub(crate) content_hash: String,
}

impl SignedToolProjection {
    /// Derive the projection. `lineage` must be the live store connection:
    /// unsigned archive lineage never selects a subject.
    pub(crate) fn derive(
        receipt: &ChioReceipt,
        lineage: &Connection,
    ) -> Result<Self, ReceiptStoreError> {
        let cost = receipt_cost_projection(receipt)?;
        let attribution = extract_receipt_attribution(receipt);
        let lineage_row = if attribution.subject_key.is_none() || attribution.issuer_key.is_none() {
            SqliteReceiptStore::get_lineage_on_connection(lineage, &receipt.capability_id)
                .map_err(capability_lineage_store_error)?
        } else {
            None
        };
        let subject_signed = attribution.subject_key.is_some();
        let issuer_signed = attribution.issuer_key.is_some();
        let subject = attribution
            .subject_key
            .or_else(|| lineage_row.as_ref().map(|row| row.subject_key.clone()));
        let issuer = attribution
            .issuer_key
            .or_else(|| lineage_row.as_ref().map(|row| row.issuer_key.clone()));
        Ok(Self {
            receipt_id: receipt.id.clone(),
            timestamp: sqlite_i64(receipt.timestamp, "retained receipt timestamp")?,
            capability_id: receipt.capability_id.clone(),
            tool_server: receipt.tool_server.clone(),
            tool_name: receipt.tool_name.clone(),
            decision: receipt_decision_kind(receipt),
            tenant: receipt.tenant_id.clone(),
            cost_currency: cost.currency,
            cost_charged: cost.charged,
            attempted_cost: cost.attempted,
            subject,
            subject_signed,
            issuer,
            issuer_signed,
            grant_index: attribution.grant_index,
            policy_hash: receipt.policy_hash.clone(),
            content_hash: receipt.content_hash.clone(),
        })
    }

    /// True when exactly one source row at `source_seq` carries `raw_json` and
    /// columns equal to this projection. `statement` is
    /// [`TOOL_SOURCE_PROJECTION_SQL`] prepared on the connection holding the row;
    /// `archived` when that is a retention archive.
    pub(crate) fn source_matches(
        &self,
        statement: &mut Statement<'_>,
        source_seq: i64,
        raw_json: &str,
        archived: bool,
    ) -> Result<bool, ReceiptStoreError> {
        Ok(statement.query_row(
            params![
                source_seq,
                self.receipt_id,
                raw_json,
                self.timestamp,
                self.capability_id,
                self.tool_server,
                self.tool_name,
                self.decision,
                self.tenant,
                self.cost_currency,
                self.cost_charged,
                self.attempted_cost,
                self.subject,
                self.issuer,
                self.grant_index.map(i64::from),
                self.policy_hash,
                self.content_hash,
                archived && !self.subject_signed,
                archived && !self.issuer_signed
            ],
            |row| row.get::<_, bool>(0),
        )?)
    }
}

/// True when exactly one child source row at `source_seq` equals the signed
/// child receipt. `statement` is [`CHILD_SOURCE_PROJECTION_SQL`].
pub(crate) fn child_source_matches(
    statement: &mut Statement<'_>,
    source_seq: i64,
    raw_json: &str,
    receipt: &ChildRequestReceipt,
) -> Result<bool, ReceiptStoreError> {
    Ok(statement.query_row(
        params![
            source_seq,
            receipt.id,
            raw_json,
            sqlite_i64(receipt.timestamp, "retained child timestamp")?,
            receipt.session_id.as_str(),
            receipt.parent_request_id.as_str(),
            receipt.request_id.as_str(),
            receipt.operation_kind.as_str(),
            terminal_state_kind(&receipt.terminal_state),
            receipt.policy_hash,
            receipt.outcome_hash
        ],
        |row| row.get::<_, bool>(0),
    )?)
}

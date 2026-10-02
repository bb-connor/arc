//! Complete session collection with bounds independent of portable proof bundles.

use chio_acp_proxy::ComplianceReceiptEntry;
use chio_errors::_generated::error_codes::CLI_IO;
use serde_json::Value;

use crate::CliError;

const MAX_SESSION_RECEIPTS: usize = 100_000;
const MAX_SESSION_BYTES: usize = 128 * 1024 * 1024;
const MAX_RECEIPT_BYTES: usize = 1024 * 1024;
const MAX_MEMBERSHIP_BYTES: usize = crate::input::MAX_DOCUMENT_BYTES;

#[derive(Debug, thiserror::Error)]
#[error("certificate receipt row {row}: {reason}")]
struct RowError {
    row: i64,
    reason: &'static str,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl RowError {
    fn new(row: i64, reason: &'static str) -> Self {
        Self {
            row,
            reason,
            source: None,
        }
    }

    fn caused_by(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }
}

impl From<RowError> for CliError {
    fn from(source: RowError) -> Self {
        Self::with_public_source(&CLI_IO, "certificate receipt collection failed", source)
    }
}

struct SessionBudget {
    receipts: usize,
    bytes: usize,
}

impl Default for SessionBudget {
    fn default() -> Self {
        Self {
            receipts: MAX_SESSION_RECEIPTS,
            bytes: MAX_SESSION_BYTES,
        }
    }
}

impl SessionBudget {
    fn charge(&mut self, row: i64, bytes: usize) -> Result<(), RowError> {
        if bytes > MAX_RECEIPT_BYTES {
            return Err(RowError::new(row, "receipt byte limit exceeded"));
        }
        let receipts = self
            .receipts
            .checked_sub(1)
            .ok_or_else(|| RowError::new(row, "session receipt limit exceeded"))?;
        let remaining_bytes = self
            .bytes
            .checked_sub(bytes)
            .ok_or_else(|| RowError::new(row, "session byte limit exceeded"))?;
        self.receipts = receipts;
        self.bytes = remaining_bytes;
        Ok(())
    }
}

/// Select from one SQLite statement snapshot, preserving the store's sequence.
/// Never truncate a session or infer membership from the unsigned capability index.
pub(super) fn load_session_receipts(
    conn: &rusqlite::Connection,
    session_id: &str,
) -> Result<Vec<ComplianceReceiptEntry>, CliError> {
    let table_exists = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='chio_receipts'")
        .and_then(|mut statement| statement.exists([]))
        .map_err(|source| CliError::with_source(&CLI_IO, source))?;
    if !table_exists {
        return Err(CliError::cli_other_error(
            "receipt store has no chio_receipts table",
        ));
    }
    let scan_bound = i64::try_from(MAX_MEMBERSHIP_BYTES)
        .map_err(|source| CliError::with_source(&CLI_IO, source))?;
    // Bound allocation before copying a row out of SQLite. A row whose membership
    // cannot be inspected invalidates collection, even if its index names another session.
    let mut statement = conn.prepare(
        "SELECT rowid, CASE WHEN typeof(json_data) = 'text' AND length(CAST(json_data AS BLOB)) <= ?1 THEN json_data ELSE NULL END FROM chio_receipts ORDER BY rowid"
    ).map_err(|source| CliError::with_source(&CLI_IO, source))?;
    let rows = statement
        .query_map([scan_bound], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?))
        })
        .map_err(|source| CliError::with_source(&CLI_IO, source))?;
    let mut entries = Vec::new();
    let mut budget = SessionBudget::default();
    for row in rows {
        let (seq, document) = row.map_err(|source| CliError::with_source(&CLI_IO, source))?;
        let document =
            document.ok_or_else(|| RowError::new(seq, "membership is not bounded text"))?;
        // Validate original bytes before projecting metadata: SQL json_extract and
        // permissive Value decoding can conceal duplicate session identifiers.
        let value: Value = crate::input::json(document.as_bytes()).map_err(|source| {
            RowError::new(seq, "membership document is invalid").caused_by(source)
        })?;
        if membership(&value).map_err(|reason| RowError::new(seq, reason))? != Some(session_id) {
            continue;
        }
        budget.charge(seq, document.len())?;
        let receipt = crate::input::project(value).map_err(|source| {
            RowError::new(seq, "selected receipt is invalid").caused_by(source)
        })?;
        let sequence = u64::try_from(seq).map_err(|source| {
            RowError::new(seq, "receipt sequence is invalid").caused_by(source)
        })?;
        entries.push(ComplianceReceiptEntry {
            receipt,
            seq: sequence,
        });
    }
    Ok(entries)
}

fn membership(value: &Value) -> Result<Option<&str>, &'static str> {
    let root = value.as_object().ok_or("receipt must be an object")?;
    let metadata = match root.get("metadata") {
        None | Some(Value::Null) => return Ok(None),
        Some(value) => value.as_object().ok_or("metadata must be an object")?,
    };
    let session = |container, key| {
        let Some(value) = metadata.get(container) else {
            return Ok(None);
        };
        let object = value
            .as_object()
            .ok_or("session metadata must be an object")?;
        object
            .get(key)
            .map(|value| value.as_str().ok_or("session identifier must be text"))
            .transpose()
    };
    let acp = session("acp", "sessionId")?;
    let context = session("receipt_context", "session_id")?;
    if acp.is_some() && context.is_some() && acp != context {
        return Err("session identifiers conflict");
    }
    Ok(acp.or(context))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    #[test]
    fn session_budgets_accept_the_boundary_and_refuse_the_next_receipt() {
        let mut count = SessionBudget::default();
        for _ in 0..MAX_SESSION_RECEIPTS {
            count.charge(1, 1).test_unwrap();
        }
        assert_eq!(
            count.charge(2, 1).test_unwrap_err().reason,
            "session receipt limit exceeded"
        );
        let mut bytes = SessionBudget::default();
        for _ in 0..MAX_SESSION_BYTES / MAX_RECEIPT_BYTES {
            bytes.charge(1, MAX_RECEIPT_BYTES).test_unwrap();
        }
        assert_eq!(
            bytes.charge(2, 1).test_unwrap_err().reason,
            "session byte limit exceeded"
        );
        assert!(SessionBudget::default().charge(1, usize::MAX).is_err());
    }
}

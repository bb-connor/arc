use super::*;
use chio_core::crypto::PublicKey;
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::decision::Decision;
use chio_core::receipt::kinds::{BoundaryClass, ReceiptKind};
use rusqlite::{Connection, OpenFlags};
use std::io::Read;

/// Inspect only a bounded recent sample. This does not establish log
/// completeness, checkpoint integrity, freshness, or liveness of an editor.
pub(super) fn inspect(
    server: &config::Server,
    limit: u32,
    policy_hash: Option<&str>,
) -> Result<Value, &'static str> {
    let database = std::fs::symlink_metadata(&server.receipt_db);
    let key_file = std::fs::symlink_metadata(&server.kernel_public_key_file);
    if database
        .as_ref()
        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        && key_file
            .as_ref()
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    {
        return Ok(json!({"status": "no_recorded_activity", "verified": 0, "recent": []}));
    }
    if !database.map(|m| m.is_file()).unwrap_or(false)
        || !key_file.map(|m| m.is_file()).unwrap_or(false)
    {
        return Err("missing_or_invalid_receipt_database_or_kernel_key");
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let key = options
        .open(&server.kernel_public_key_file)
        .map_err(|_| "kernel_key_unreadable")?;
    if !key
        .metadata()
        .map_err(|_| "kernel_key_unreadable")?
        .is_file()
    {
        return Err("kernel_key_is_not_a_regular_file");
    }
    let mut text = String::new();
    key.take(16_385)
        .read_to_string(&mut text)
        .map_err(|_| "kernel_key_unreadable")?;
    if text.len() > 16_384 {
        return Err("kernel_key_too_large");
    }
    let trusted_key = PublicKey::from_hex(text.trim()).map_err(|_| "kernel_key_invalid")?;
    let connection = Connection::open_with_flags(
        &server.receipt_db,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| "receipt_database_unreadable")?;
    connection
        .busy_timeout(std::time::Duration::from_secs(2))
        .map_err(|_| "receipt_database_unreadable")?;
    connection
        .execute_batch("PRAGMA query_only=ON;")
        .map_err(|_| "receipt_database_unreadable")?;
    // Bound both the number and size of payloads before materializing them.
    // Do not trust denormalized server/decision columns to establish mediation.
    let mut statement = connection
        .prepare(
            "SELECT CASE WHEN length(CAST(raw_json AS BLOB)) <= 1048576 THEN raw_json ELSE NULL END
         FROM chio_tool_receipts ORDER BY seq DESC LIMIT ?1",
        )
        .map_err(|_| "receipt_schema_unavailable")?;
    let mut rows = statement
        .query([limit + 1])
        .map_err(|_| "receipt_query_failed")?;
    let mut recent = Vec::new();
    let mut outcomes = json!({"allow": 0, "deny": 0, "cancelled": 0, "incomplete": 0});
    let mut more = false;
    while let Some(row) = rows.next().map_err(|_| "receipt_query_failed")? {
        if recent.len() >= limit as usize {
            more = true;
            break;
        }
        let raw: Option<String> = row.get(0).map_err(|_| "receipt_payload_invalid")?;
        let raw = raw.ok_or("receipt_payload_too_large")?;
        let receipt: ChioReceipt =
            serde_json::from_str(&raw).map_err(|_| "receipt_payload_invalid")?;
        if receipt.kernel_key != trusted_key {
            return Err("receipt_signer_mismatch");
        }
        if !receipt
            .verify_signature()
            .map_err(|_| "receipt_integrity_invalid")?
            || !receipt
                .action
                .verify_hash()
                .map_err(|_| "receipt_arguments_invalid")?
        {
            return Err("receipt_integrity_invalid");
        }
        if receipt.tool_server != server.server {
            return Err("receipt_server_mismatch");
        }
        if receipt.receipt_kind != ReceiptKind::MediatedDecision
            || receipt.boundary_class != BoundaryClass::Prevent
        {
            return Err("receipt_is_not_a_preventive_kernel_decision");
        }
        let outcome = match receipt.decision {
            Some(Decision::Allow) => "allow",
            Some(Decision::Deny { .. }) => "deny",
            Some(Decision::Cancelled { .. }) => "cancelled",
            Some(Decision::Incomplete { .. }) => "incomplete",
            None => return Err("receipt_has_no_kernel_decision"),
        };
        outcomes[outcome] = json!(outcomes[outcome].as_u64().unwrap_or(0) + 1);
        recent.push(json!({
            "id": receipt.id, "timestamp": receipt.timestamp, "tool": receipt.tool_name,
            "outcome": outcome,
            "matches_current_policy": policy_hash.map(|hash| hash == receipt.policy_hash),
        }));
    }
    Ok(json!({
        "status": if recent.is_empty() { "no_recorded_activity" } else { "verified_sample" },
        "verified": recent.len(), "has_older_receipts": more,
        "outcomes": outcomes, "recent": recent,
    }))
}

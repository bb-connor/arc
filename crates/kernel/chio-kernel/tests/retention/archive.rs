#![allow(clippy::unwrap_used)]

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::Signature;
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::checkpoint::KernelCheckpoint;
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

pub(super) fn open(path: &Path) -> Connection {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
}

pub(super) fn tool_receipt_count(connection: &Connection) -> u64 {
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
            row.get(0)
        })
        .unwrap();
    u64::try_from(count).unwrap()
}

pub(super) fn child_receipt_count(connection: &Connection) -> u64 {
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM chio_child_receipts", [], |row| {
            row.get(0)
        })
        .unwrap();
    u64::try_from(count).unwrap()
}

pub(super) fn checkpoint_count(connection: &Connection, sequence: u64) -> u64 {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM kernel_checkpoints WHERE checkpoint_seq = ?1",
            [i64::try_from(sequence).unwrap()],
            |row| row.get(0),
        )
        .unwrap();
    u64::try_from(count).unwrap()
}

pub(super) fn checkpoint(connection: &Connection, sequence: u64) -> KernelCheckpoint {
    let (body, signature): (String, String) = connection
        .query_row(
            "SELECT statement_json, signature FROM kernel_checkpoints WHERE checkpoint_seq = ?1",
            [i64::try_from(sequence).unwrap()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    KernelCheckpoint {
        body: serde_json::from_str(&body).unwrap(),
        signature: Signature::from_hex(&signature).unwrap(),
    }
}

pub(super) fn receipt_bytes(connection: &Connection, start: u64, end: u64) -> Vec<(u64, Vec<u8>)> {
    let mut statement = connection
        .prepare(
            "SELECT entry_seq, raw_json FROM claim_receipt_log_entries \
             WHERE entry_seq BETWEEN ?1 AND ?2 ORDER BY entry_seq",
        )
        .unwrap();
    statement
        .query_map(
            [i64::try_from(start).unwrap(), i64::try_from(end).unwrap()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .unwrap()
        .map(|row| {
            let (sequence, raw) = row.unwrap();
            let receipt: ChioReceipt = serde_json::from_str(&raw).unwrap();
            assert!(receipt.verify_integrity_embedded_key().unwrap());
            (
                u64::try_from(sequence).unwrap(),
                canonical_json_bytes(&receipt).unwrap(),
            )
        })
        .collect()
}

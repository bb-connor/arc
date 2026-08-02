//! Contract tests for `SqliteMemoryProvenanceStore`.
//!
//! These tests exercise the trait contract (`append` is atomic and
//! chain-linked, `verify_entry` detects tamper, `chain_digest` follows
//! the tail) and the SQLite-specific durability guarantee (the chain
//! survives a reopen).

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::{
    recompute_memory_provenance_entry_hash, MemoryProvenanceAppend, MemoryProvenanceStore,
    ProvenanceVerification, UnverifiedReason, MEMORY_PROVENANCE_GENESIS_PREV_HASH,
};
use chio_store_sqlite::SqliteMemoryProvenanceStore;

use chio_test_support::prelude::*;

fn unique_db_path(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
}

fn sample_append(key: &str, receipt: &str, when: u64) -> MemoryProvenanceAppend {
    MemoryProvenanceAppend {
        store: "agent-context".to_string(),
        key: key.to_string(),
        capability_id: "cap-1".to_string(),
        receipt_id: receipt.to_string(),
        written_at: when,
    }
}

fn create_legacy_memory_provenance_table(conn: &rusqlite::Connection) {
    conn.execute_batch(&format!(
        r#"
        PRAGMA application_id = {};
        CREATE TABLE chio_memory_provenance (
            seq           INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_id      TEXT NOT NULL UNIQUE,
            store         TEXT NOT NULL,
            entry_key     TEXT NOT NULL,
            capability_id TEXT NOT NULL,
            receipt_id    TEXT NOT NULL,
            written_at    INTEGER NOT NULL,
            prev_hash     TEXT NOT NULL,
            hash          TEXT NOT NULL
        );
        "#,
        chio_store_sqlite::schema_version::CHIO_SQLITE_APPLICATION_ID
    ))
    .test_expect("create legacy memory provenance table");
}

fn insert_valid_legacy_entry(
    conn: &rusqlite::Connection,
    entry_id: &str,
    key: &str,
    receipt_id: &str,
    written_at: u64,
    prev_hash: &str,
) -> String {
    let written_at_i64 = i64::try_from(written_at).test_expect("legacy timestamp fits SQLite");
    let hash = recompute_memory_provenance_entry_hash(
        entry_id,
        "agent-context",
        key,
        "cap-1",
        receipt_id,
        written_at,
        prev_hash,
    )
    .test_expect("compute legacy provenance hash");
    conn.execute(
        r#"
        INSERT INTO chio_memory_provenance
            (entry_id, store, entry_key, capability_id, receipt_id, written_at, prev_hash, hash)
        VALUES (?1, 'agent-context', ?2, 'cap-1', ?3, ?4, ?5, ?6)
        "#,
        rusqlite::params![entry_id, key, receipt_id, written_at_i64, prev_hash, hash],
    )
    .test_expect("insert valid legacy provenance entry");
    hash
}

#[test]
fn append_assigns_genesis_prev_hash_for_first_entry() {
    let store = SqliteMemoryProvenanceStore::open_in_memory().test_expect("open in-memory store");
    let entry = store
        .append(sample_append("doc-1", "rcpt-1", 100))
        .test_expect("append");
    assert_eq!(entry.prev_hash, MEMORY_PROVENANCE_GENESIS_PREV_HASH);
    assert_eq!(entry.hash.len(), 64);
    assert!(entry.hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn append_is_idempotent_by_receipt_id() {
    let store = SqliteMemoryProvenanceStore::open_in_memory().test_expect("open in-memory store");
    let input = sample_append("doc-1", "rcpt-1", 100);
    let first = store
        .append(input.clone())
        .test_expect("first append succeeds");
    let first_digest = store.chain_digest().test_expect("first digest");
    let replay = store.append(input).test_expect("replay succeeds");

    assert_eq!(replay, first);
    assert_eq!(
        store.chain_digest().test_expect("replay digest"),
        first_digest,
        "a replay must not extend the provenance chain"
    );
    assert!(store.append(sample_append("doc-2", "rcpt-1", 100)).is_err());
}

#[test]
fn append_rejects_timestamp_outside_sqlite_range_without_extending_the_chain() {
    let store = SqliteMemoryProvenanceStore::open_in_memory().test_expect("open in-memory store");
    let first = store
        .append(sample_append("doc-1", "receipt-1", 100))
        .test_expect("first append");

    let error = match store.append(sample_append("doc-2", "receipt-2", u64::MAX)) {
        Ok(entry) => panic!("timestamp outside SQLite INTEGER range was stored: {entry:?}"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("outside SQLite INTEGER range"));
    assert_eq!(
        store.chain_digest().test_expect("chain after rejection"),
        first.hash
    );
    assert!(store
        .latest_for_key("agent-context", "doc-2")
        .test_expect("query absent rejected key")
        .is_none());
}

#[test]
fn persisted_negative_timestamp_is_rejected_instead_of_wrapping() {
    let path = unique_db_path("chio-mem-prov-negative-timestamp");
    let store = SqliteMemoryProvenanceStore::open(&path).test_expect("open provenance store");
    let entry = store
        .append(sample_append("doc-1", "receipt-1", 100))
        .test_expect("append provenance entry");
    drop(store);

    let conn = rusqlite::Connection::open(&path).test_expect("open raw provenance database");
    conn.execute(
        "UPDATE chio_memory_provenance SET written_at = -1 WHERE entry_id = ?1",
        [&entry.entry_id],
    )
    .test_expect("corrupt persisted timestamp");
    drop(conn);

    let store = SqliteMemoryProvenanceStore::open(&path).test_expect("reopen provenance store");
    assert!(store.get_entry(&entry.entry_id).is_err());
    drop(store);
    let _ = fs::remove_file(path);
}

#[test]
fn migration_deduplicates_identical_legacy_receipts_and_rebuilds_the_chain() {
    let path = unique_db_path("chio-mem-prov-duplicate-receipt");
    let conn = rusqlite::Connection::open(&path).test_expect("open legacy database");
    create_legacy_memory_provenance_table(&conn);
    let first_hash = insert_valid_legacy_entry(
        &conn,
        "entry-a",
        "doc-1",
        "receipt-reused",
        1,
        MEMORY_PROVENANCE_GENESIS_PREV_HASH,
    );
    let duplicate_hash =
        insert_valid_legacy_entry(&conn, "entry-b", "doc-1", "receipt-reused", 1, &first_hash);
    let original_tail_hash = insert_valid_legacy_entry(
        &conn,
        "entry-c",
        "doc-2",
        "receipt-next",
        2,
        &duplicate_hash,
    );
    drop(conn);

    let store = SqliteMemoryProvenanceStore::open(&path)
        .test_expect("identical legacy receipt replays must migrate");
    let first = store
        .get_entry("entry-a")
        .test_expect("read retained entry")
        .test_expect("retained entry exists");
    assert!(store
        .get_entry("entry-b")
        .test_expect("read duplicate entry")
        .is_none());
    let tail = store
        .get_entry("entry-c")
        .test_expect("read repaired tail")
        .test_expect("repaired tail exists");
    assert_eq!(tail.prev_hash, first.hash);
    assert_ne!(tail.hash, original_tail_hash);
    assert!(matches!(
        store
            .verify_entry("entry-c")
            .test_expect("verify repaired chain"),
        ProvenanceVerification::Verified { .. }
    ));
    let replay = store
        .append(sample_append("doc-1", "receipt-reused", 1))
        .test_expect("replay after migration");
    assert_eq!(replay.entry_id, "entry-a");
    let appended = store
        .append(sample_append("doc-3", "receipt-after-migration", 3))
        .test_expect("append after migration");
    assert_eq!(appended.prev_hash, tail.hash);
    drop(store);

    let reopened = SqliteMemoryProvenanceStore::open(&path)
        .test_expect("migration must remain idempotent after reopen");
    assert_eq!(
        reopened
            .get_entry("entry-c")
            .test_expect("read tail after reopen")
            .test_expect("tail after reopen")
            .hash,
        tail.hash
    );
    drop(reopened);
    let _ = fs::remove_file(path);
}

#[test]
fn migration_rejects_conflicting_legacy_receipts_without_partial_changes() {
    let path = unique_db_path("chio-mem-prov-conflicting-receipt");
    let conn = rusqlite::Connection::open(&path).test_expect("open legacy database");
    create_legacy_memory_provenance_table(&conn);
    let first_hash = insert_valid_legacy_entry(
        &conn,
        "entry-a",
        "doc-1",
        "receipt-reused",
        1,
        MEMORY_PROVENANCE_GENESIS_PREV_HASH,
    );
    let second_hash = insert_valid_legacy_entry(
        &conn,
        "entry-b",
        "doc-conflict",
        "receipt-reused",
        2,
        &first_hash,
    );
    drop(conn);

    let error = match SqliteMemoryProvenanceStore::open(&path) {
        Ok(_) => panic!("conflicting legacy receipt reuse must fail closed"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("reused with different fields"));

    let conn = rusqlite::Connection::open(&path).test_expect("reopen rejected legacy database");
    let rows: Vec<(String, String)> = conn
        .prepare("SELECT entry_id, hash FROM chio_memory_provenance ORDER BY seq")
        .test_expect("prepare legacy row query")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .test_expect("query legacy rows")
        .collect::<Result<_, _>>()
        .test_expect("collect legacy rows");
    assert_eq!(
        rows,
        vec![
            ("entry-a".to_string(), first_hash),
            ("entry-b".to_string(), second_hash)
        ]
    );
    let unique_index_exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'idx_chio_memory_provenance_receipt')",
            [],
            |row| row.get(0),
        )
        .test_expect("query unique index");
    assert!(!unique_index_exists);
    let schema_table_exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'chio_store_schema_versions')",
            [],
            |row| row.get(0),
        )
        .test_expect("query schema stamp table");
    assert!(!schema_table_exists);
    drop(conn);
    let _ = fs::remove_file(path);
}

#[test]
fn migration_rejects_tampered_legacy_chain_without_stamping_it() {
    let path = unique_db_path("chio-mem-prov-tampered-chain");
    let conn = rusqlite::Connection::open(&path).test_expect("open legacy database");
    create_legacy_memory_provenance_table(&conn);
    let valid_hash = insert_valid_legacy_entry(
        &conn,
        "entry-a",
        "doc-1",
        "receipt-1",
        1,
        MEMORY_PROVENANCE_GENESIS_PREV_HASH,
    );
    conn.execute(
        "UPDATE chio_memory_provenance SET hash = ?1 WHERE entry_id = 'entry-a'",
        ["f".repeat(64)],
    )
    .test_expect("tamper legacy chain");
    drop(conn);

    let error = match SqliteMemoryProvenanceStore::open(&path) {
        Ok(_) => panic!("tampered legacy chain must fail closed"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("legacy provenance chain is invalid"));

    let conn = rusqlite::Connection::open(&path).test_expect("reopen tampered database");
    let stored_hash: String = conn
        .query_row(
            "SELECT hash FROM chio_memory_provenance WHERE entry_id = 'entry-a'",
            [],
            |row| row.get(0),
        )
        .test_expect("read tampered hash");
    assert_eq!(stored_hash, "f".repeat(64));
    assert_ne!(stored_hash, valid_hash);
    drop(conn);
    let _ = fs::remove_file(path);
}

#[test]
fn append_links_successive_entries_via_prev_hash() {
    let store = SqliteMemoryProvenanceStore::open_in_memory().test_expect("open in-memory store");
    let first = store
        .append(sample_append("doc-1", "rcpt-1", 100))
        .test_expect("first append");
    let second = store
        .append(sample_append("doc-2", "rcpt-2", 101))
        .test_expect("second append");
    assert_eq!(second.prev_hash, first.hash);
    assert_ne!(second.hash, first.hash);
    assert_eq!(store.chain_digest().test_expect("digest"), second.hash);
}

#[test]
fn latest_for_key_returns_most_recent_entry() {
    let store = SqliteMemoryProvenanceStore::open_in_memory().test_expect("open in-memory store");
    let _earlier = store
        .append(sample_append("doc-9", "rcpt-earlier", 100))
        .test_expect("earlier");
    let later = store
        .append(sample_append("doc-9", "rcpt-later", 150))
        .test_expect("later");
    let latest = store
        .latest_for_key("agent-context", "doc-9")
        .test_expect("latest_for_key")
        .test_expect("entry for doc-9");
    assert_eq!(latest.entry_id, later.entry_id);
    assert_eq!(latest.receipt_id, "rcpt-later");
}

#[test]
fn latest_for_key_returns_none_for_unknown_key() {
    let store = SqliteMemoryProvenanceStore::open_in_memory().test_expect("open in-memory store");
    let result = store
        .latest_for_key("agent-context", "doc-ghost")
        .test_expect("latest_for_key");
    assert!(result.is_none());
}

#[test]
fn verify_entry_accepts_valid_chain() {
    let store = SqliteMemoryProvenanceStore::open_in_memory().test_expect("open in-memory store");
    let _first = store
        .append(sample_append("doc-1", "rcpt-1", 100))
        .test_expect("first append");
    let second = store
        .append(sample_append("doc-2", "rcpt-2", 101))
        .test_expect("second append");
    let verification = store
        .verify_entry(&second.entry_id)
        .test_expect("verify_entry");
    match verification {
        ProvenanceVerification::Verified {
            entry,
            chain_digest,
        } => {
            assert_eq!(entry.entry_id, second.entry_id);
            assert_eq!(chain_digest, second.hash);
        }
        ProvenanceVerification::Unverified { reason } => {
            panic!("expected verified chain, got unverified: {reason:?}");
        }
    }
}

#[test]
fn verify_entry_detects_hash_tamper() {
    let store = SqliteMemoryProvenanceStore::open_in_memory().test_expect("open in-memory store");
    let entry = store
        .append(sample_append("doc-1", "rcpt-1", 100))
        .test_expect("append");
    let forged = "b".repeat(64);
    let updated = store
        .tamper_entry_hash(&entry.entry_id, &forged)
        .test_expect("tamper helper");
    assert!(updated, "tamper helper should find the row");
    let verification = store
        .verify_entry(&entry.entry_id)
        .test_expect("verify_entry");
    assert!(
        matches!(
            verification,
            ProvenanceVerification::Unverified {
                reason: UnverifiedReason::ChainTampered
            }
        ),
        "expected ChainTampered, got {verification:?}"
    );
}

#[test]
fn verify_entry_detects_broken_link_when_prev_row_mutated() {
    let store = SqliteMemoryProvenanceStore::open_in_memory().test_expect("open in-memory store");
    let first = store
        .append(sample_append("doc-1", "rcpt-1", 100))
        .test_expect("first");
    let second = store
        .append(sample_append("doc-2", "rcpt-2", 101))
        .test_expect("second");
    // Tamper the FIRST entry: verify on the second now observes a
    // mismatched predecessor hash because `second.prev_hash` was
    // derived from the *original* first-entry hash.
    let forged = "c".repeat(64);
    store
        .tamper_entry_hash(&first.entry_id, &forged)
        .test_expect("tamper helper");
    let verification = store
        .verify_entry(&second.entry_id)
        .test_expect("verify_entry on second");
    assert!(
        matches!(
            verification,
            ProvenanceVerification::Unverified {
                reason: UnverifiedReason::ChainLinkBroken
            }
        ),
        "expected ChainLinkBroken, got {verification:?}"
    );
}

#[test]
fn verify_entry_flags_unknown_entry_as_no_provenance() {
    let store = SqliteMemoryProvenanceStore::open_in_memory().test_expect("open in-memory store");
    let verification = store
        .verify_entry("missing-id")
        .test_expect("verify_entry on unknown id");
    assert!(matches!(
        verification,
        ProvenanceVerification::Unverified {
            reason: UnverifiedReason::NoProvenance
        }
    ));
}

#[test]
fn chain_digest_is_genesis_on_empty_store() {
    let store = SqliteMemoryProvenanceStore::open_in_memory().test_expect("open in-memory store");
    assert_eq!(
        store.chain_digest().test_expect("digest"),
        MEMORY_PROVENANCE_GENESIS_PREV_HASH
    );
}

#[test]
fn chain_persists_across_reopen() {
    let path = unique_db_path("chio-mem-prov");
    let first_hash;
    let first_entry_id;
    {
        let store = SqliteMemoryProvenanceStore::open(&path).test_expect("open on disk");
        let entry = store
            .append(sample_append("doc-1", "rcpt-1", 100))
            .test_expect("append");
        first_hash = entry.hash.clone();
        first_entry_id = entry.entry_id.clone();
    }
    let reopened = SqliteMemoryProvenanceStore::open(&path).test_expect("reopen");
    // Chain digest must have survived the reopen.
    assert_eq!(reopened.chain_digest().test_expect("digest"), first_hash);
    // Next append must chain on top of the persisted tail.
    let second = reopened
        .append(sample_append("doc-2", "rcpt-2", 200))
        .test_expect("second append on reopened store");
    assert_eq!(second.prev_hash, first_hash);
    // The original entry is still verifiable.
    let verification = reopened
        .verify_entry(&first_entry_id)
        .test_expect("verify_entry persisted row");
    assert!(matches!(
        verification,
        ProvenanceVerification::Verified { .. }
    ));
    let _ = fs::remove_file(path);
}

#[test]
fn get_entry_returns_the_committed_row() {
    let store = SqliteMemoryProvenanceStore::open_in_memory().test_expect("open in-memory store");
    let entry = store
        .append(sample_append("doc-1", "rcpt-1", 100))
        .test_expect("append");
    let fetched = store
        .get_entry(&entry.entry_id)
        .test_expect("get_entry")
        .test_expect("row should exist after append");
    assert_eq!(fetched, entry);
}

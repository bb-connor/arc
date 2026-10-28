//! Contract tests for `SqliteMemoryProvenanceStore`.
//!
//! These tests exercise the trait contract (`append` is atomic and
//! chain-linked, `verify_entry` detects tamper, `chain_digest` follows
//! the tail) and the SQLite-specific durability guarantee (the chain
//! survives a reopen).

use std::fs;

use chio_kernel::{
    MemoryProvenanceAppend, MemoryProvenanceStore, ProvenanceVerification, UnverifiedReason,
    MEMORY_PROVENANCE_GENESIS_PREV_HASH,
};
use chio_store_sqlite::SqliteMemoryProvenanceStore;

use chio_test_support::prelude::*;

use chio_test_support::temp_sqlite_path;

fn sample_append(key: &str, receipt: &str, when: u64) -> MemoryProvenanceAppend {
    MemoryProvenanceAppend {
        store: "agent-context".to_string(),
        key: key.to_string(),
        capability_id: "cap-1".to_string(),
        receipt_id: receipt.to_string(),
        written_at: when,
    }
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
    let replay = store.append(input).test_expect("replay succeeds");

    assert_eq!(replay, first);
    assert!(store.append(sample_append("doc-2", "rcpt-1", 100)).is_err());
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
    let (_path_dir, path) = temp_sqlite_path("chio-mem-prov");
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
fn reopen_refuses_a_deleted_schema_stamp_without_repair() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("provenance.sqlite3");
    let store = SqliteMemoryProvenanceStore::open(&path)?;
    let entry = store.append(sample_append("doc-1", "rcpt-1", 100))?;
    drop(store);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute(
        "DELETE FROM chio_store_schema_versions WHERE store_key = 'memory_provenance'",
        [],
    )?;
    let error = match SqliteMemoryProvenanceStore::open(&path) {
        Err(error) => error,
        Ok(_) => panic!("deleted schema stamp was accepted"),
    };
    assert_eq!(
        error.to_string(),
        "sqlite memory provenance store error: schema namespace memory_provenance is missing"
    );
    let stamps: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_store_schema_versions WHERE store_key = 'memory_provenance'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(stamps, 0);
    let hash: String = connection.query_row(
        "SELECT hash FROM chio_memory_provenance WHERE entry_id = ?1",
        [&entry.entry_id],
        |row| row.get(0),
    )?;
    assert_eq!(hash, entry.hash);
    Ok(())
}

#[test]
fn reopen_refuses_a_missing_index_without_repair() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("provenance.sqlite3");
    drop(SqliteMemoryProvenanceStore::open(&path)?);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch("DROP INDEX idx_chio_memory_provenance_key;")?;
    let error = match SqliteMemoryProvenanceStore::open(&path) {
        Err(error) => error,
        Ok(_) => panic!("missing schema index was accepted"),
    };
    assert_eq!(
        error.to_string(),
        "sqlite memory provenance store error: schema catalog differs from its canonical definition"
    );
    let present: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'idx_chio_memory_provenance_key')",
        [],
        |row| row.get(0),
    )?;
    assert!(!present);
    Ok(())
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

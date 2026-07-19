//! Contract tests for `SqliteExecutionNonceStore`.
//!
//! Exercises the `ExecutionNonceStore` trait contract plus the durable
//! replay-prevention guarantees specific to the SQLite backend:
//!
//! * `reserve(id)` returns `Ok(true)` on first call and `Ok(false)` on
//!   every replay.
//! * Consumed nonces persist across store reopen so a kernel restart
//!   does not open a replay window.
//! * Signed expiry is audit metadata. Clock movement never deletes or
//!   recycles a consumed identifier.

use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::{ExecutionNonceStore, ExecutionNonceStoreProfile};
use chio_store_sqlite::SqliteExecutionNonceStore;

use chio_test_support::prelude::*;

fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_expect("time before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
}

#[test]
fn fresh_nonce_is_reserved() {
    let store = SqliteExecutionNonceStore::open_in_memory().test_unwrap();
    assert!(store.reserve("nonce-a").test_unwrap());
}

#[test]
fn nonce_store_profile_reflects_instance_durability() {
    let memory = SqliteExecutionNonceStore::open_in_memory().test_unwrap();
    assert_eq!(
        memory.authority_profile(),
        ExecutionNonceStoreProfile::EphemeralLocal
    );
    let path = unique_db_path("chio-exec-nonce-profile");
    let disk = SqliteExecutionNonceStore::open(&path).test_unwrap();
    assert_eq!(
        disk.authority_profile(),
        ExecutionNonceStoreProfile::SingleNodeDurable
    );
    assert!(SqliteExecutionNonceStore::open(":memory:").is_err());
    assert!(SqliteExecutionNonceStore::open("file::memory:?cache=shared").is_err());
    let _ = std::fs::remove_file(path);
}

#[test]
fn replayed_nonce_is_rejected_permanently() {
    let store = SqliteExecutionNonceStore::open_in_memory().test_unwrap();
    let now = 1_000_000;
    let expires_at = now + 60;
    assert!(store.try_reserve("nonce-b", now, expires_at).test_unwrap());
    assert!(!store
        .try_reserve("nonce-b", now + 1, expires_at)
        .test_unwrap());
}

#[test]
fn forward_clock_jump_then_rollback_keeps_nonce_consumed() {
    let store = SqliteExecutionNonceStore::open_in_memory().test_unwrap();
    assert!(store.try_reserve("nonce-c", 1_000, 1_010).test_unwrap());
    assert!(!store.try_reserve("nonce-c", 2_000, 2_060).test_unwrap());
    assert!(!store.try_reserve("nonce-c", 1_001, 1_010).test_unwrap());
}

#[test]
fn persists_consumed_marker_across_reopen() {
    let path = unique_db_path("chio-exec-nonce-persist");
    {
        let store = SqliteExecutionNonceStore::open(&path).test_unwrap();
        assert!(store
            .try_reserve("persistent-id", 1_000, 10_000_000_000)
            .test_unwrap());
    }
    let reopened = SqliteExecutionNonceStore::open(&path).test_unwrap();
    assert!(!reopened
        .try_reserve("persistent-id", 1_001, 10_000_000_000)
        .test_unwrap());
    let _ = std::fs::remove_file(path);
}

#[test]
fn distinct_ids_each_succeed() {
    let store = SqliteExecutionNonceStore::open_in_memory().test_unwrap();
    assert!(store.reserve("a").test_unwrap());
    assert!(store.reserve("b").test_unwrap());
    assert!(store.reserve("c").test_unwrap());
    assert!(!store.reserve("a").test_unwrap());
    assert!(!store.reserve("b").test_unwrap());
}

#[test]
fn trait_reserve_uses_wall_clock_now() {
    // Sanity: the trait impl goes through try_reserve with a now
    // derived from SystemTime, so it should succeed for a fresh id.
    let store = SqliteExecutionNonceStore::open_in_memory().test_unwrap();
    assert!(
        <SqliteExecutionNonceStore as ExecutionNonceStore>::reserve(&store, "trait-path")
            .test_unwrap()
    );
}

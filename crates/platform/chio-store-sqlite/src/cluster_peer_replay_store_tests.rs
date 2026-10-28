use super::*;
use chio_test_support::prelude::*;

const NODE_B: &str = "https://node-b.example:9101";
const NODE_C: &str = "https://node-c.example:9101";

fn store_path(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().join("cluster-peer-replay.sqlite3")
}

#[test]
fn high_water_survives_reopen() {
    let dir = tempfile::tempdir().test_unwrap();
    let store = SqliteClusterPeerReplayStore::open(store_path(&dir)).test_unwrap();
    assert!(store.high_waters().test_unwrap().is_empty());
    store.advance(NODE_B, 100).test_unwrap();
    store.advance(NODE_B, 105).test_unwrap();
    store.advance(NODE_C, 7).test_unwrap();
    drop(store);
    let reopened = SqliteClusterPeerReplayStore::open(store_path(&dir)).test_unwrap();
    assert_eq!(
        reopened.high_waters().test_unwrap(),
        BTreeMap::from([(NODE_B.to_string(), 105), (NODE_C.to_string(), 7)])
    );
}

#[test]
fn advance_requires_a_strictly_greater_issue_time() {
    let dir = tempfile::tempdir().test_unwrap();
    let store = SqliteClusterPeerReplayStore::open(store_path(&dir)).test_unwrap();
    store.advance(NODE_B, 100).test_unwrap();
    for issued_at in [100, 99] {
        assert!(matches!(
            store.advance(NODE_B, issued_at).test_unwrap_err(),
            ClusterPeerReplayStoreError::NotAdvanced
        ));
    }
    store.advance(NODE_C, 50).test_unwrap();
    assert_eq!(
        store.high_waters().test_unwrap(),
        BTreeMap::from([(NODE_B.to_string(), 100), (NODE_C.to_string(), 50)])
    );
}

#[test]
fn advance_refuses_invalid_rows() {
    let dir = tempfile::tempdir().test_unwrap();
    let store = SqliteClusterPeerReplayStore::open(store_path(&dir)).test_unwrap();
    for (node_id, issued_at) in [("", 1), (NODE_B, -1)] {
        assert!(matches!(
            store.advance(node_id, issued_at).test_unwrap_err(),
            ClusterPeerReplayStoreError::InvalidRow
        ));
    }
    let long = "n".repeat(MAX_NODE_ID_BYTES + 1);
    assert!(matches!(
        store.advance(&long, 1).test_unwrap_err(),
        ClusterPeerReplayStoreError::InvalidRow
    ));
}

#[test]
fn store_holds_at_most_the_peer_cap() {
    let dir = tempfile::tempdir().test_unwrap();
    let store = SqliteClusterPeerReplayStore::open(store_path(&dir)).test_unwrap();
    for index in 0..CLUSTER_PEER_REPLAY_MAX_PEERS {
        store.advance(&format!("node-{index}"), 1).test_unwrap();
    }
    assert!(matches!(
        store.advance("node-extra", 1).test_unwrap_err(),
        ClusterPeerReplayStoreError::CapacityExhausted
    ));
    store.advance("node-0", 2).test_unwrap();
}

#[test]
fn in_memory_paths_refuse() {
    for path in [":memory:", "file:replay?mode=memory", ""] {
        assert!(matches!(
            SqliteClusterPeerReplayStore::open(path).test_unwrap_err(),
            ClusterPeerReplayStoreError::InvalidPath
        ));
    }
}

#[test]
fn corrupt_rows_refuse_on_open() {
    let dir = tempfile::tempdir().test_unwrap();
    SqliteClusterPeerReplayStore::open(store_path(&dir))
        .test_unwrap()
        .advance(NODE_B, 100)
        .test_unwrap();
    let raw = Connection::open(store_path(&dir)).test_unwrap();
    raw.execute_batch("PRAGMA ignore_check_constraints = ON;")
        .test_unwrap();
    raw.execute(
        "UPDATE cluster_peer_replay_high_water SET issued_at = -5 WHERE node_id = ?1",
        [NODE_B],
    )
    .test_unwrap();
    drop(raw);
    assert!(matches!(
        SqliteClusterPeerReplayStore::open(store_path(&dir)).test_unwrap_err(),
        ClusterPeerReplayStoreError::InvalidRow
    ));
}

#[test]
fn foreign_schema_refuses_on_open() {
    let dir = tempfile::tempdir().test_unwrap();
    SqliteClusterPeerReplayStore::open(store_path(&dir)).test_unwrap();
    let raw = Connection::open(store_path(&dir)).test_unwrap();
    raw.execute_batch("CREATE TABLE intruder (id INTEGER) STRICT;")
        .test_unwrap();
    drop(raw);
    assert!(matches!(
        SqliteClusterPeerReplayStore::open(store_path(&dir)).test_unwrap_err(),
        ClusterPeerReplayStoreError::Schema(SchemaVersionError::CatalogMismatch)
    ));
}

#[test]
fn a_dropped_table_refuses_reads_and_advances() {
    let dir = tempfile::tempdir().test_unwrap();
    let store = SqliteClusterPeerReplayStore::open(store_path(&dir)).test_unwrap();
    let raw = Connection::open(store_path(&dir)).test_unwrap();
    raw.execute_batch("DROP TABLE cluster_peer_replay_high_water;")
        .test_unwrap();
    drop(raw);
    assert!(matches!(
        store.advance(NODE_B, 1).test_unwrap_err(),
        ClusterPeerReplayStoreError::Sqlite(_)
    ));
    assert!(matches!(
        store.high_waters().test_unwrap_err(),
        ClusterPeerReplayStoreError::Sqlite(_)
    ));
}

use super::*;
use chio_test_support::prelude::*;

const NODE_B: &str = "https://node-b.example:9101";
const NODE_C: &str = "https://node-c.example:9101";

fn store_path(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().join("cluster-peer-replay.sqlite3")
}

fn open(
    dir: &tempfile::TempDir,
) -> Result<SqliteClusterPeerReplayStore, ClusterPeerReplayStoreError> {
    SqliteClusterPeerReplayStore::open(store_path(dir))
}

fn node(id: &str) -> ClusterPeerNodeId {
    ClusterPeerNodeId::new(id).test_unwrap()
}

fn at(secs: i64) -> PeerIssuedAtSecs {
    PeerIssuedAtSecs::new(secs).test_unwrap()
}

fn marks(entries: &[(&str, i64)]) -> BTreeMap<ClusterPeerNodeId, PeerIssuedAtSecs> {
    entries
        .iter()
        .map(|(node_id, issued_at)| (node(node_id), at(*issued_at)))
        .collect()
}

#[test]
fn high_water_survives_reopen() {
    let dir = tempfile::tempdir().test_unwrap();
    let store = open(&dir).test_unwrap();
    assert!(store.high_waters().test_unwrap().is_empty());
    store.advance(&node(NODE_B), at(100)).test_unwrap();
    store.advance(&node(NODE_B), at(105)).test_unwrap();
    store.advance(&node(NODE_C), at(7)).test_unwrap();
    drop(store);
    let reopened = open(&dir).test_unwrap();
    assert_eq!(
        reopened.high_waters().test_unwrap(),
        marks(&[(NODE_B, 105), (NODE_C, 7)])
    );
}

#[test]
fn advance_requires_a_strictly_greater_issue_time() {
    let dir = tempfile::tempdir().test_unwrap();
    let store = open(&dir).test_unwrap();
    store.advance(&node(NODE_B), at(100)).test_unwrap();
    for issued_at in [100, 99] {
        assert_eq!(
            store
                .advance(&node(NODE_B), at(issued_at))
                .test_unwrap_err(),
            PeerReplayStoreError::NotAdvanced
        );
    }
    store.advance(&node(NODE_C), at(50)).test_unwrap();
    assert_eq!(
        store.high_waters().test_unwrap(),
        marks(&[(NODE_B, 100), (NODE_C, 50)])
    );
}

#[test]
fn peer_values_refuse_out_of_range_input() {
    let long = "n".repeat(CLUSTER_PEER_NODE_ID_MAX_BYTES + 1);
    for node_id in ["", long.as_str()] {
        assert_eq!(ClusterPeerNodeId::new(node_id), None);
    }
    assert_eq!(PeerIssuedAtSecs::new(-1), None);
}

#[test]
fn store_holds_at_most_the_peer_cap() {
    let dir = tempfile::tempdir().test_unwrap();
    let store = open(&dir).test_unwrap();
    for index in 0..CLUSTER_PEER_REPLAY_MAX_PEERS {
        store
            .advance(&node(&format!("node-{index}")), at(1))
            .test_unwrap();
    }
    assert_eq!(
        store.advance(&node("node-extra"), at(1)).test_unwrap_err(),
        PeerReplayStoreError::CapacityExhausted
    );
    store.advance(&node("node-0"), at(2)).test_unwrap();
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
    open(&dir)
        .test_unwrap()
        .advance(&node(NODE_B), at(100))
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
        open(&dir).test_unwrap_err(),
        ClusterPeerReplayStoreError::InvalidRow
    ));
}

#[test]
fn foreign_schema_refuses_on_open() {
    let dir = tempfile::tempdir().test_unwrap();
    open(&dir).test_unwrap();
    let raw = Connection::open(store_path(&dir)).test_unwrap();
    raw.execute_batch("CREATE TABLE intruder (id INTEGER) STRICT;")
        .test_unwrap();
    drop(raw);
    assert!(matches!(
        open(&dir).test_unwrap_err(),
        ClusterPeerReplayStoreError::Schema(SchemaVersionError::CatalogMismatch)
    ));
}

#[test]
fn a_dropped_table_refuses_reads_and_advances() {
    let dir = tempfile::tempdir().test_unwrap();
    let store = open(&dir).test_unwrap();
    let raw = Connection::open(store_path(&dir)).test_unwrap();
    raw.execute_batch("DROP TABLE cluster_peer_replay_high_water;")
        .test_unwrap();
    drop(raw);
    assert_eq!(
        store.advance(&node(NODE_B), at(1)).test_unwrap_err(),
        PeerReplayStoreError::Unavailable
    );
    assert_eq!(
        store.high_waters().test_unwrap_err(),
        PeerReplayStoreError::Unavailable
    );
}

fn seed_raw_row(dir: &tempfile::TempDir, node_id_sql: &str, issued_at_sql: &str) {
    open(dir)
        .test_unwrap()
        .advance(&node(NODE_B), at(100))
        .test_unwrap();
    let raw = Connection::open(store_path(dir)).test_unwrap();
    raw.execute_batch("PRAGMA ignore_check_constraints = ON;")
        .test_unwrap();
    raw.execute(
        &format!(
            "INSERT INTO cluster_peer_replay_high_water (node_id, issued_at) VALUES ({node_id_sql}, {issued_at_sql})"
        ),
        [],
    )
    .test_unwrap();
}

#[test]
fn oversized_undecodable_node_id_refuses_on_open_before_it_is_read() {
    let dir = tempfile::tempdir().test_unwrap();
    seed_raw_row(&dir, "CAST(zeroblob(1048576) || x'ff' AS TEXT)", "1");
    assert!(matches!(
        open(&dir).test_unwrap_err(),
        ClusterPeerReplayStoreError::InvalidRow
    ));
}

#[test]
fn oversized_node_id_refuses_on_open() {
    let dir = tempfile::tempdir().test_unwrap();
    seed_raw_row(&dir, "printf('%.*c', 1048576, 'n')", "1");
    assert!(matches!(
        open(&dir).test_unwrap_err(),
        ClusterPeerReplayStoreError::InvalidRow
    ));
}

#[test]
fn a_valid_store_reopens_after_corrupt_row_controls() {
    let dir = tempfile::tempdir().test_unwrap();
    let store = open(&dir).test_unwrap();
    store
        .advance(&node(&"n".repeat(CLUSTER_PEER_NODE_ID_MAX_BYTES)), at(1))
        .test_unwrap();
    drop(store);
    assert_eq!(
        open(&dir).test_unwrap().high_waters().test_unwrap().len(),
        1
    );
}

#[test]
fn utf16_node_id_over_the_utf8_bound_refuses_on_open() {
    let dir = tempfile::tempdir().test_unwrap();
    Connection::open(store_path(&dir))
        .test_unwrap()
        .execute_batch("PRAGMA encoding = 'UTF-16'; CREATE TABLE fixture (x); DROP TABLE fixture;")
        .test_unwrap();
    seed_raw_row(&dir, "printf('%.*c', 1024, char(8364))", "1");
    let raw = Connection::open(store_path(&dir)).test_unwrap();
    let (encoding, stored_octets): (String, i64) = raw
        .query_row(
            "SELECT (SELECT encoding FROM pragma_encoding), octet_length(node_id) \
             FROM cluster_peer_replay_high_water WHERE node_id != ?1",
            [NODE_B],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .test_unwrap();
    drop(raw);
    assert!(encoding.starts_with("UTF-16"), "{encoding}");
    assert_eq!(stored_octets, 2048);
    assert!(matches!(
        open(&dir).test_unwrap_err(),
        ClusterPeerReplayStoreError::InvalidRow
    ));
}

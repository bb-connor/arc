use super::*;
use crate::store::SqlitePheromoneRelayStore;
use chio_core_types::canonical::UntrustedJsonError;
use chio_federation::pheromone_gossip::PHEROMONE_GOSSIP_BATCH_SCHEMA;
use chio_pheromone_runtime::store::SqlitePheromoneRuntimeStore;

fn seeded_store(path: &std::path::Path) -> SqlitePheromoneRelayStore {
    let store = SqlitePheromoneRelayStore::open(path).unwrap();
    let batch = PheromoneGossipBatch {
        schema: PHEROMONE_GOSSIP_BATCH_SCHEMA.to_string(),
        recipient_kernel_id: "did:chio:recipient".to_string(),
        treaty_id: "treaty:catchup".to_string(),
        frames: Vec::new(),
        flushed_at_unix_ms: 4_000_000,
    };
    store
        .enqueue_batch(
            "did:chio:sender",
            &batch.recipient_kernel_id,
            &batch.treaty_id,
            &batch,
            4_000_000,
        )
        .unwrap();
    store
}

fn assert_internal(error: &PheromoneRelayError) {
    assert_eq!(
        relay_error_response(error),
        refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            RELAY_INTERNAL_ERROR_CODE,
            RELAY_INTERNAL_ERROR_DETAIL
        )
    );
}

#[test]
fn retired_runtime_table_returns_fixed_server_error() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("runtime.sqlite");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch("CREATE TABLE chio_pheromone_pair_counts (value INTEGER)")
        .unwrap();
    let error = SqlitePheromoneRuntimeStore::open(&path).unwrap_err();
    assert!(
        matches!(&error, PheromoneRuntimeError::SchemaInvalid(detail)
        if detail == "stale pheromone runtime schema: retired table chio_pheromone_pair_counts is present")
    );
    assert_internal(&PheromoneRelayError::Runtime(error));
}

#[test]
fn malformed_stored_catchup_json_returns_fixed_server_error() {
    assert_corrupt_catchup("{", "urn:chio:error:attest:signed-json-invalid-input");
}

#[test]
fn duplicate_stored_catchup_json_returns_fixed_server_error() {
    assert_corrupt_catchup(
        r#"{"schema":"first","schema":"second"}"#,
        "urn:chio:error:attest:signed-json-invalid-input",
    );
}

#[test]
fn wrong_shape_stored_catchup_json_returns_fixed_server_error() {
    assert_corrupt_catchup("{}", "urn:chio:error:attest:signed-json-invalid-shape");
}

fn assert_corrupt_catchup(json: &str, expected_code: &str) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("relay.sqlite");
    let store = seeded_store(&path);
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE chio_pheromone_relay_outbox SET batch_json = ?1",
            [json],
        )
        .unwrap();
    let error = store
        .catchup_batches("did:chio:recipient", "treaty:catchup", "", 10, usize::MAX)
        .unwrap_err();
    assert_internal(&error);
    assert!(
        matches!(&error, PheromoneRelayError::StoredInput(source) if source.code() == expected_code)
    );
    let source = std::error::Error::source(&error)
        .unwrap()
        .downcast_ref::<UntrustedJsonError>()
        .unwrap();
    assert_eq!(source.code(), expected_code);
}

#[test]
fn oversized_stored_catchup_json_returns_fixed_server_error() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("relay.sqlite");
    let store = seeded_store(&path);
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE chio_pheromone_relay_outbox SET batch_json = CAST(zeroblob(?1) AS TEXT)",
            [i64::try_from(crate::input::MAX_DOCUMENT_BYTES + 1).unwrap()],
        )
        .unwrap();
    let error = store
        .catchup_batches("did:chio:recipient", "treaty:catchup", "", 10, usize::MAX)
        .unwrap_err();
    assert_internal(&error);
    assert!(
        matches!(error, PheromoneRelayError::StoredInput(UntrustedJsonError::TooLarge { bytes, bound })
        if bytes == crate::input::MAX_DOCUMENT_BYTES + 1 && bound == crate::input::MAX_DOCUMENT_BYTES)
    );
}

#[test]
fn malformed_peer_input_remains_a_fixed_client_error() {
    let source = crate::input::decode::<serde_json::Value>(b"{").unwrap_err();
    assert_eq!(
        relay_error_response(&PheromoneRelayError::Input(source)),
        refusal(
            StatusCode::BAD_REQUEST,
            "urn:chio:error:attest:signed-json-invalid-input",
            "relay request body violates the JSON input policy",
        )
    );
}

#[test]
fn valid_stored_catchup_batch_is_returned() {
    let root = tempfile::tempdir().unwrap();
    let store = seeded_store(&root.path().join("relay.sqlite"));
    let (batches, cursor) = store
        .catchup_batches("did:chio:recipient", "treaty:catchup", "", 10, usize::MAX)
        .unwrap();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].recipient_kernel_id, "did:chio:recipient");
    assert_eq!(cursor, "1");
}

//! The only test in this binary: the operator trace is captured by a global
//! subscriber installed before any relay callsite registers, so no other test
//! can cache a disabled interest for the callsite under test.

#![allow(clippy::unwrap_used)]

use async_trait::async_trait;
use chio_federation::pheromone_gossip::PheromoneGossipBatch;
use chio_pheromone_relay::{
    peer_directory_from_json, PheromoneRelayConfig, PheromoneRelayError, PheromoneRelayService,
    RelayBatchReceiver, RelayProfile, SqlitePheromoneRelayStore,
    PHEROMONE_RELAY_OBSERVABILITY_PATH,
};
use chio_pheromone_runtime::PheromoneReceiveReport;
use std::sync::{Arc, Mutex};

const NOW: u64 = 1_766_000_000_000;
const MISSING_EVENTS: &str = "no such table: chio_pheromone_relay_events";
const OPERATOR_DIAGNOSTIC: &str = "operator token is required for relay observability";

struct UnusedReceiver;

#[async_trait]
impl RelayBatchReceiver for UnusedReceiver {
    async fn receive_batch(
        &self,
        _batch: PheromoneGossipBatch,
        _authenticated_sender_kernel_id: String,
        _received_at_unix_ms: u64,
    ) -> Result<PheromoneReceiveReport, PheromoneRelayError> {
        unreachable!("no batch is relayed in this test")
    }
}

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl LogBuffer {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl std::io::Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn operator_trace_survives_both_report_destination_failures() {
    let logs = LogBuffer::default();
    let writer = logs.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish(),
    )
    .unwrap();

    let root = tempfile::tempdir().unwrap();
    let directory = peer_directory_from_json(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../examples/chio-3vendor/fixtures/pheromone/relay/peer-directory.json"
        )),
        NOW,
    )
    .unwrap();
    let path = root.path().join("relay.sqlite");
    let store = Arc::new(SqlitePheromoneRelayStore::open(&path).unwrap());
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("DROP TABLE chio_pheromone_relay_events")
        .unwrap();
    std::fs::write(root.path().join("reports"), "occupied").unwrap();
    let service = PheromoneRelayService::new(
        PheromoneRelayConfig {
            local_kernel_id: directory.local_kernel_id().to_string(),
            profile: RelayProfile::Production,
            now_unix_ms: NOW,
            freshness_window_ms: 60_000,
            max_body_bytes: 256_000,
            use_system_clock: false,
            operator_token: Some("operator-secret".to_string()),
            report_dir: Some(root.path().join("reports")),
        },
        directory,
        Arc::new(UnusedReceiver),
        store,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(service.serve(listener));

    let denied = reqwest::Client::new()
        .get(format!(
            "http://{address}{PHEROMONE_RELAY_OBSERVABILITY_PATH}"
        ))
        .send()
        .await
        .unwrap();
    server.abort();

    assert_eq!(denied.status(), reqwest::StatusCode::UNAUTHORIZED);
    let text = logs.text();
    assert!(
        text.contains(OPERATOR_DIAGNOSTIC),
        "original operator diagnostic missing: {text}"
    );
    assert!(
        text.contains(MISSING_EVENTS),
        "report-store failure missing: {text}"
    );
}

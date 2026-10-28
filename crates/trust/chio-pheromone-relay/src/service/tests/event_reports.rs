use super::super::{relay_http_error, PheromoneRelayConfig, PheromoneRelayService};
use super::{SilentReceiver, INTERNAL_TEXT};
use crate::{
    peer_directory_from_json, PheromoneRelayError, RelayEventReport, RelayProfile,
    SqlitePheromoneRelayStore,
};
use axum::http::StatusCode;
use rusqlite::Connection;
use std::path::Path;
use std::sync::Arc;

const NOW: u64 = 1_766_000_000_000;
const MISSING_EVENTS: &str = "no such table: chio_pheromone_relay_events";

fn service(root: &Path) -> (PheromoneRelayService, Connection) {
    let directory = peer_directory_from_json(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../examples/chio-3vendor/fixtures/pheromone/relay/peer-directory.json"
        )),
        NOW,
    )
    .unwrap();
    let path = root.join("relay.sqlite");
    let store = Arc::new(SqlitePheromoneRelayStore::open(&path).unwrap());
    let connection = Connection::open(path).unwrap();
    let service = PheromoneRelayService::new(
        PheromoneRelayConfig {
            local_kernel_id: directory.local_kernel_id().to_string(),
            profile: RelayProfile::Production,
            now_unix_ms: NOW,
            freshness_window_ms: 60_000,
            max_body_bytes: 256_000,
            use_system_clock: false,
            operator_token: None,
            report_dir: Some(root.join("reports")),
        },
        directory,
        Arc::new(SilentReceiver),
        store,
    );
    (service, connection)
}

fn read_single_report(root: &Path) -> RelayEventReport {
    let directory = root.join("reports");
    assert!(directory.is_dir(), "operator file destination was skipped");
    let files = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    assert_eq!(files.len(), 1);
    serde_json::from_slice(&std::fs::read(&files[0]).unwrap()).unwrap()
}

#[test]
fn file_report_survives_event_store_failure() {
    let root = tempfile::tempdir().unwrap();
    let (service, connection) = service(root.path());
    connection
        .execute_batch("DROP TABLE chio_pheromone_relay_events")
        .unwrap();

    let error = service
        .emit_event_report("request_rejected", false, "sqlite", INTERNAL_TEXT, NOW)
        .unwrap_err();

    assert!(matches!(error, PheromoneRelayError::Sqlite(ref detail) if detail == MISSING_EVENTS));
    let report = read_single_report(root.path());
    assert!(!report.accepted);
    assert_eq!(report.code, "sqlite");
    assert_eq!(report.detail, INTERNAL_TEXT);
    assert_eq!(report.stable_failure_code.as_deref(), Some("sqlite"));
}

#[test]
fn store_report_survives_file_destination_failure() {
    let root = tempfile::tempdir().unwrap();
    let (service, connection) = service(root.path());
    std::fs::write(root.path().join("reports"), "occupied").unwrap();

    let error = service
        .emit_event_report("request_rejected", false, "sqlite", INTERNAL_TEXT, NOW)
        .unwrap_err();

    assert!(matches!(error, PheromoneRelayError::Http(_)));
    let stored: String = connection
        .query_row(
            "SELECT report_json FROM chio_pheromone_relay_events",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let report: RelayEventReport = serde_json::from_str(&stored).unwrap();
    assert_eq!(report.detail, INTERNAL_TEXT);
    assert_eq!(report.code, "sqlite");
}

#[test]
fn simultaneous_destination_failures_preserve_store_error() {
    let root = tempfile::tempdir().unwrap();
    let (service, connection) = service(root.path());
    connection
        .execute_batch("DROP TABLE chio_pheromone_relay_events")
        .unwrap();
    std::fs::write(root.path().join("reports"), "occupied").unwrap();

    let error = service
        .emit_event_report("request_rejected", false, "sqlite", INTERNAL_TEXT, NOW)
        .unwrap_err();

    assert!(matches!(error, PheromoneRelayError::Sqlite(ref detail) if detail == MISSING_EVENTS));
}

#[test]
fn http_error_keeps_public_body_fixed_when_event_store_fails() {
    let root = tempfile::tempdir().unwrap();
    let (service, connection) = service(root.path());
    connection
        .execute_batch("DROP TABLE chio_pheromone_relay_events")
        .unwrap();

    let (status, response) = relay_http_error(
        &service,
        PheromoneRelayError::Sqlite(INTERNAL_TEXT.to_string()),
    );

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response.0.code, "relay_internal_error");
    assert_eq!(response.0.detail, "relay internal error");
    assert!(!response.0.accepted);
    let report = read_single_report(root.path());
    assert_eq!(report.detail, format!("sqlite: {INTERNAL_TEXT}"));
}

#[derive(Clone, Default)]
struct LogBuffer(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn operator_trace_survives_both_report_destination_failures() {
    let root = tempfile::tempdir().unwrap();
    let (service, connection) = service(root.path());
    connection
        .execute_batch("DROP TABLE chio_pheromone_relay_events")
        .unwrap();
    std::fs::write(root.path().join("reports"), "occupied").unwrap();
    let logs = LogBuffer::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        let _ = relay_http_error(
            &service,
            PheromoneRelayError::Sqlite(INTERNAL_TEXT.to_string()),
        );
    });

    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(
        text.contains(INTERNAL_TEXT),
        "original operator diagnostic missing: {text}"
    );
    assert!(
        text.contains(MISSING_EVENTS),
        "report-store failure missing: {text}"
    );
}

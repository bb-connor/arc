//! Readiness of a spawned `chio trust serve` process for receipt reads.

use reqwest::blocking::Client;
use serde_json::Value;

/// Receipt reads refuse with 503 until the receipt query snapshot publishes
/// its first version. A service without a receipt store reports
/// `unconfigured` and has no snapshot to wait for.
pub(crate) fn receipt_reads_ready(health: &Value) -> bool {
    matches!(
        health["receiptQuerySnapshot"]["state"].as_str(),
        Some("ready" | "unconfigured")
    )
}

/// `/health` answers 200 and receipt reads are served.
pub(crate) fn trust_service_ready(client: &Client, base_url: &str) -> bool {
    client
        .get(format!("{base_url}/health"))
        .send()
        .ok()
        .filter(|response| response.status() == reqwest::StatusCode::OK)
        .and_then(|response| response.json::<Value>().ok())
        .is_some_and(|health| receipt_reads_ready(&health))
}

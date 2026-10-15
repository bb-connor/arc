use std::io::Read;
use std::time::Duration;

use reqwest::blocking::Client;
use serde_json::{json, Value};

use super::{try_get_json, try_internal_cluster_status, wait_until_with_diagnostics};

pub(super) fn wait_for_node_health(client: &Client, base_url: &str, token: &str, label: &str) {
    wait_until_with_diagnostics(
        label,
        Duration::from_secs(30),
        || {
            try_get_json(client, &format!("{base_url}/health"), token)
                .is_some_and(|health| super::trust_health::receipt_reads_ready(&health))
        },
        || {
            json!({
                "baseUrl": base_url,
                "health": try_get_json(client, &format!("{base_url}/health"), token),
                "clusterStatus": try_internal_cluster_status(client, base_url, token),
                "receiptQuery": receipt_query_diagnostics(client, base_url, token),
            })
        },
    );
}

fn receipt_query_diagnostics(client: &Client, base_url: &str, token: &str) -> Value {
    const MAX_BODY_BYTES: usize = 16 * 1024;
    let response = match client
        .get(format!("{base_url}/v1/receipts/tools?limit=1"))
        .bearer_auth(token)
        .timeout(Duration::from_secs(2))
        .send()
    {
        Ok(response) => response,
        Err(error) => return json!({"transportError": error.to_string()}),
    };
    let status = response.status().as_u16();
    let mut bytes = Vec::new();
    let read_error = response
        .take(MAX_BODY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .err()
        .map(|error| error.to_string());
    let truncated = bytes.len() > MAX_BODY_BYTES;
    bytes.truncate(MAX_BODY_BYTES);
    let body = serde_json::from_slice::<Value>(&bytes)
        .unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes)));
    json!({
        "status": status,
        "body": body,
        "bodyTruncated": truncated,
        "readError": read_error,
    })
}

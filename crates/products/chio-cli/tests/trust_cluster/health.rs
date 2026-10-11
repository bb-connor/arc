use std::time::Duration;

use reqwest::blocking::Client;
use serde_json::json;

use super::{try_get_json, try_internal_cluster_status, wait_until_with_diagnostics};

pub(super) fn wait_for_node_health(client: &Client, base_url: &str, token: &str, label: &str) {
    wait_until_with_diagnostics(
        label,
        Duration::from_secs(30),
        || try_get_json(client, &format!("{base_url}/health"), token).is_some(),
        || {
            json!({
                "baseUrl": base_url,
                "health": try_get_json(client, &format!("{base_url}/health"), token),
                "clusterStatus": try_internal_cluster_status(client, base_url, token),
            })
        },
    );
}

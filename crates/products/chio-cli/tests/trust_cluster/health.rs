use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::AUTHORIZATION;
use serde_json::{json, Value};

use super::{bearer, try_get_json, try_internal_cluster_status, wait_until_with_diagnostics};

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

pub(super) fn assert_unavailable_leader_health(client: &Client, leader_url: &str, token: &str) {
    let health_response = client
        .get(format!("{leader_url}/health"))
        .header(AUTHORIZATION, bearer(token))
        .send()
        .expect("read late leader health");
    assert_eq!(
        health_response.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    let health: Value = health_response.json().expect("decode late leader health");
    assert_eq!(health["leaderUrl"].as_str(), Some(leader_url));
    assert_eq!(health["ok"].as_bool(), Some(false));
    assert_eq!(health["authority"]["configured"].as_bool(), Some(true));
    assert_eq!(health["authority"]["available"].as_bool(), Some(false));
}

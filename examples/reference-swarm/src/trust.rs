//! The trust-control service as the orchestrator reads it: health and the
//! receipts every edge forwarded.

use std::error::Error;

use reqwest::blocking::Client;
use reqwest::header::AUTHORIZATION;
use serde_json::Value;

type Fallible<T> = Result<T, Box<dyn Error>>;

pub struct TrustClient {
    http: Client,
    base_url: String,
    bearer: String,
}

impl TrustClient {
    pub fn new(base_url: &str, service_bearer: &str) -> Self {
        Self {
            http: Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
            base_url: base_url.trim_end_matches('/').to_string(),
            bearer: service_bearer.to_string(),
        }
    }

    pub fn healthy(&self) -> bool {
        self.http
            .get(format!("{}/health", self.base_url))
            .send()
            .is_ok_and(|response| response.status().is_success())
    }

    /// The receipts recorded for one capability, newest last.
    pub fn receipts(&self, capability_id: &str) -> Fallible<Vec<Value>> {
        let payload: Value = self
            .http
            .get(format!("{}/v1/receipts/query", self.base_url))
            .query(&[("capabilityId", capability_id), ("limit", "200")])
            .header(AUTHORIZATION, format!("Bearer {}", self.bearer))
            .send()?
            .error_for_status()?
            .json()?;
        Ok(payload["receipts"].as_array().cloned().unwrap_or_default())
    }
}

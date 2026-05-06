//! Real Rekor (Sigstore transparency log) witness-lane client.
//!
//! `RekorClient::publish` POSTs the canonical-JSON encoding of
//! `batch.body` to `${endpoint}/api/v1/log/entries` with a Sigstore
//! "intoto" envelope shape; `verify_inclusion` GETs
//! `${endpoint}/api/v1/log/entries/${uuid}` and asserts that the
//! returned `body.spec.data.hash.value` matches
//! `sha256_hex(batch.body)`.
//!
//! This module makes a real HTTP call (via `reqwest`). The negative
//! conformance test
//! `crates/chio-conformance/tests/anchor_batch_witness_impersonation_rejected.rs`
//! exercises the full surface against a `tiny_http` mock server.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chio_core::canonical_json_bytes;
use chio_core::hashing::sha256;
use serde::{Deserialize, Serialize};

use crate::batch::{AnchorBatch, AnchorBatchWitnessKind};
use crate::witness::{batch_body_hash, AnchorWitnessClient, AnchorWitnessError, WitnessReceipt};

/// Production Rekor client. The endpoint is configurable so tests can
/// point at a local mock; production wiring uses
/// `https://rekor.sigstore.dev`.
#[derive(Debug, Clone)]
pub struct RekorClient {
    endpoint: String,
    http: reqwest::Client,
    /// Maximum age in seconds for a witness receipt. Receipts older
    /// than this are reported as `AnchorWitnessError::Stale` on
    /// `verify_inclusion`.
    max_witness_age_seconds: i64,
}

impl RekorClient {
    /// `endpoint` example: `"https://rekor.sigstore.dev"` (no
    /// trailing slash). `max_witness_age_seconds` MUST be
    /// non-negative.
    pub fn new(
        endpoint: impl Into<String>,
        max_witness_age_seconds: i64,
    ) -> Result<Self, AnchorWitnessError> {
        let endpoint = endpoint.into();
        if endpoint.is_empty() {
            return Err(AnchorWitnessError::Config(
                "rekor endpoint must be non-empty".to_string(),
            ));
        }
        if max_witness_age_seconds < 0 {
            return Err(AnchorWitnessError::Config(
                "max_witness_age_seconds must be non-negative".to_string(),
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .https_only(false)
            .build()
            .map_err(|error| AnchorWitnessError::Config(error.to_string()))?;
        Ok(RekorClient {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            http,
            max_witness_age_seconds,
        })
    }

    fn entries_url(&self) -> String {
        format!("{}/api/v1/log/entries", self.endpoint)
    }

    fn entry_by_uuid_url(&self, uuid: &str) -> String {
        format!("{}/api/v1/log/entries/{}", self.endpoint, uuid)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RekorIntotoSpec<'a> {
    content: RekorIntotoContent<'a>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RekorIntotoContent<'a> {
    envelope: RekorIntotoEnvelope<'a>,
    /// SHA-256 of the canonical-JSON batch body, hex-prefixed.
    hash: RekorHash<'a>,
}

#[derive(Debug, Serialize)]
struct RekorIntotoEnvelope<'a> {
    payload: &'a str,
    payload_type: &'a str,
}

#[derive(Debug, Serialize, Deserialize)]
struct RekorHash<'a> {
    algorithm: &'a str,
    /// Hex-encoded SHA-256 (no `0x` prefix per Rekor convention).
    value: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RekorEntryRequest<'a> {
    api_version: &'a str,
    kind: &'a str,
    spec: RekorIntotoSpec<'a>,
}

/// Returned by `POST /api/v1/log/entries`. Rekor's real response is a
/// map keyed by UUID; we treat the first key as the canonical UUID.
#[derive(Debug, Deserialize)]
struct RekorPublishResponse {
    #[serde(flatten)]
    entries: std::collections::BTreeMap<String, RekorEntry>,
}

/// A single Rekor entry (subset of fields). `body` is base64-JCS of
/// the original `RekorEntryRequest`; we re-decode and pull
/// `spec.content.hash.value` to detect lane-side substitution.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RekorEntry {
    body: String,
    integrated_time: i64,
    log_id: Option<String>,
    log_index: Option<i64>,
    verification: Option<RekorVerification>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RekorVerification {
    inclusion_proof: Option<RekorInclusionProof>,
    signed_entry_timestamp: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RekorInclusionProof {
    log_index: Option<i64>,
    root_hash: Option<String>,
    tree_size: Option<i64>,
    hashes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct RekorEntryBody {
    spec: RekorEntryBodySpec,
}

#[derive(Debug, Deserialize)]
struct RekorEntryBodySpec {
    content: RekorEntryBodyContent,
}

#[derive(Debug, Deserialize)]
struct RekorEntryBodyContent {
    hash: RekorHashOwned,
}

#[derive(Debug, Deserialize)]
struct RekorHashOwned {
    algorithm: String,
    value: String,
}

fn extract_lane_body_hash(entry: &RekorEntry) -> Result<String, AnchorWitnessError> {
    let raw = BASE64_STANDARD
        .decode(entry.body.as_bytes())
        .map_err(|error| AnchorWitnessError::Decode(format!("rekor body base64: {error}")))?;
    let parsed: RekorEntryBody = serde_json::from_slice(&raw)
        .map_err(|error| AnchorWitnessError::Decode(format!("rekor body json: {error}")))?;
    if !parsed
        .spec
        .content
        .hash
        .algorithm
        .eq_ignore_ascii_case("sha256")
    {
        return Err(AnchorWitnessError::Decode(format!(
            "rekor entry hash algorithm {} is not sha256",
            parsed.spec.content.hash.algorithm
        )));
    }
    Ok(parsed.spec.content.hash.value.to_ascii_lowercase())
}

#[async_trait::async_trait]
impl AnchorWitnessClient for RekorClient {
    async fn publish(&self, batch: &AnchorBatch) -> Result<WitnessReceipt, AnchorWitnessError> {
        let body_bytes = canonical_json_bytes(&batch.body)
            .map_err(|error| AnchorWitnessError::Decode(error.to_string()))?;
        let body_hash = sha256(&body_bytes);
        let body_hash_hex = body_hash.to_hex();
        let payload_b64 = BASE64_STANDARD.encode(&body_bytes);
        let request = RekorEntryRequest {
            api_version: "0.0.1",
            kind: "intoto",
            spec: RekorIntotoSpec {
                content: RekorIntotoContent {
                    envelope: RekorIntotoEnvelope {
                        payload: &payload_b64,
                        payload_type: "application/vnd.chio.anchor_batch+json",
                    },
                    hash: RekorHash {
                        algorithm: "sha256",
                        value: body_hash_hex.clone(),
                    },
                },
            },
        };

        let response = self
            .http
            .post(self.entries_url())
            .json(&request)
            .send()
            .await
            .map_err(|error| AnchorWitnessError::Network(error.to_string()))?;
        let status = response.status();
        let raw_body = response
            .text()
            .await
            .map_err(|error| AnchorWitnessError::Network(error.to_string()))?;
        if !status.is_success() {
            return Err(AnchorWitnessError::Http {
                status: status.as_u16(),
                body: raw_body,
            });
        }
        let parsed: RekorPublishResponse = serde_json::from_str(&raw_body)
            .map_err(|error| AnchorWitnessError::Decode(error.to_string()))?;
        let (uuid, entry) = parsed.entries.into_iter().next().ok_or_else(|| {
            AnchorWitnessError::Decode("rekor publish returned no entries".to_string())
        })?;
        let lane_hash = extract_lane_body_hash(&entry)?;
        if lane_hash != body_hash_hex.to_ascii_lowercase() {
            return Err(AnchorWitnessError::BodyHashMismatch {
                lane: lane_hash,
                batch: body_hash_hex,
            });
        }
        let inclusion_proof_bytes = entry
            .verification
            .as_ref()
            .and_then(|verification| verification.inclusion_proof.as_ref())
            .and_then(|proof| serde_json::to_vec(proof).ok())
            .unwrap_or_default();
        Ok(WitnessReceipt {
            kind: AnchorBatchWitnessKind::Rekor,
            external_uuid: uuid,
            published_at: entry.integrated_time,
            inclusion_proof: inclusion_proof_bytes,
            witness_root: batch.body.tree_root,
            body_hash,
        })
    }

    async fn verify_inclusion(&self, receipt: &WitnessReceipt) -> Result<(), AnchorWitnessError> {
        if receipt.kind != AnchorBatchWitnessKind::Rekor {
            return Err(AnchorWitnessError::Config(format!(
                "RekorClient asked to verify {:?} receipt",
                receipt.kind
            )));
        }
        let response = self
            .http
            .get(self.entry_by_uuid_url(&receipt.external_uuid))
            .send()
            .await
            .map_err(|error| AnchorWitnessError::Network(error.to_string()))?;
        let status = response.status();
        let raw_body = response
            .text()
            .await
            .map_err(|error| AnchorWitnessError::Network(error.to_string()))?;
        if !status.is_success() {
            return Err(AnchorWitnessError::Http {
                status: status.as_u16(),
                body: raw_body,
            });
        }
        let parsed: RekorPublishResponse = serde_json::from_str(&raw_body)
            .map_err(|error| AnchorWitnessError::Decode(error.to_string()))?;
        let entry = parsed.entries.get(&receipt.external_uuid).ok_or_else(|| {
            AnchorWitnessError::Decode(format!(
                "rekor returned no entry for uuid {}",
                receipt.external_uuid
            ))
        })?;
        let lane_hash_hex = extract_lane_body_hash(entry)?;
        let expected_hex = receipt.body_hash.to_hex();
        if lane_hash_hex != expected_hex.to_ascii_lowercase() {
            return Err(AnchorWitnessError::BodyHashMismatch {
                lane: lane_hash_hex,
                batch: expected_hex,
            });
        }
        let now = chrono_now_unix();
        if self.max_witness_age_seconds > 0
            && now.saturating_sub(entry.integrated_time) > self.max_witness_age_seconds
        {
            return Err(AnchorWitnessError::Stale {
                published_at: entry.integrated_time,
                now,
                max_age_seconds: self.max_witness_age_seconds,
            });
        }
        let _ = entry.log_id.as_deref();
        let _ = entry.log_index;
        Ok(())
    }
}

fn chrono_now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// Build the canonical Rekor "body" payload that a real Rekor server
/// would echo back. Exposed so tests (and the negative conformance
/// suite) can stage faithful mock responses without depending on the
/// production Rekor staging deployment.
pub fn build_rekor_entry_body_b64(batch: &AnchorBatch) -> Result<String, AnchorWitnessError> {
    let body_hash = batch_body_hash(batch)?;
    let body_hash_hex = body_hash.to_hex();
    let canonical = canonical_json_bytes(&batch.body)
        .map_err(|error| AnchorWitnessError::Decode(error.to_string()))?;
    let payload_b64 = BASE64_STANDARD.encode(&canonical);
    let request = RekorEntryRequest {
        api_version: "0.0.1",
        kind: "intoto",
        spec: RekorIntotoSpec {
            content: RekorIntotoContent {
                envelope: RekorIntotoEnvelope {
                    payload: &payload_b64,
                    payload_type: "application/vnd.chio.anchor_batch+json",
                },
                hash: RekorHash {
                    algorithm: "sha256",
                    value: body_hash_hex,
                },
            },
        },
    };
    let bytes = serde_json::to_vec(&request)
        .map_err(|error| AnchorWitnessError::Decode(error.to_string()))?;
    Ok(BASE64_STANDARD.encode(bytes))
}

/// Build a Rekor body payload that commits to `forged_hash` instead of
/// the batch's real body hash. Used by the witness-impersonation
/// negative test to simulate a lane that returns an entry whose
/// `spec.content.hash.value` does not match the batch.
pub fn build_rekor_entry_body_b64_with_hash(
    batch: &AnchorBatch,
    forged_hash_hex: &str,
) -> Result<String, AnchorWitnessError> {
    let canonical = canonical_json_bytes(&batch.body)
        .map_err(|error| AnchorWitnessError::Decode(error.to_string()))?;
    let payload_b64 = BASE64_STANDARD.encode(&canonical);
    let request = RekorEntryRequest {
        api_version: "0.0.1",
        kind: "intoto",
        spec: RekorIntotoSpec {
            content: RekorIntotoContent {
                envelope: RekorIntotoEnvelope {
                    payload: &payload_b64,
                    payload_type: "application/vnd.chio.anchor_batch+json",
                },
                hash: RekorHash {
                    algorithm: "sha256",
                    value: forged_hash_hex.to_string(),
                },
            },
        },
    };
    let bytes = serde_json::to_vec(&request)
        .map_err(|error| AnchorWitnessError::Decode(error.to_string()))?;
    Ok(BASE64_STANDARD.encode(bytes))
}

/// Build a synthetic Rekor publish response payload. Tests use this
/// to stage mock-server responses that look indistinguishable from
/// production Rekor.
pub fn build_rekor_publish_response(
    uuid: &str,
    body_b64: &str,
    integrated_time: i64,
    log_index: i64,
) -> serde_json::Value {
    serde_json::json!({
        uuid: {
            "body": body_b64,
            "integratedTime": integrated_time,
            "logID": "0".repeat(64),
            "logIndex": log_index,
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::batch::{build_anchor_batch, AnchorBatchWitness, AnchorBatchWitnessKind};
    use crate::witness::batch_body_hash;
    use chio_core::hashing::Hash;
    use chio_core::Keypair;

    fn sample_batch() -> AnchorBatch {
        let kp = Keypair::generate();
        let witness = AnchorBatchWitness {
            kind: AnchorBatchWitnessKind::Rekor,
            witness_id: "rekor:placeholder".to_string(),
            root: Hash::zero(),
            observed_at: Some(1_700_000_000),
        };
        build_anchor_batch(
            vec!["ck-1".to_string(), "ck-2".to_string()],
            witness,
            1_700_000_000,
            &kp,
        )
        .unwrap()
    }

    #[test]
    fn rekor_body_b64_round_trips_real_batch_hash() {
        let batch = sample_batch();
        let body = build_rekor_entry_body_b64(&batch).unwrap();
        let raw = BASE64_STANDARD.decode(body.as_bytes()).unwrap();
        let parsed: RekorEntryBody = serde_json::from_slice(&raw).unwrap();
        let expected = batch_body_hash(&batch).unwrap().to_hex();
        assert_eq!(parsed.spec.content.hash.value, expected);
    }

    #[test]
    fn rekor_client_rejects_blank_endpoint() {
        let err = RekorClient::new("", 60).unwrap_err();
        assert!(matches!(err, AnchorWitnessError::Config(_)));
    }
}

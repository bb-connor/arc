//! W2.3 negative conformance test: witness-lane impersonation.
//!
//! Threat: a malicious or compromised Rekor mirror returns an
//! `getEntryByUUID` response whose `body.spec.content.hash.value`
//! does NOT match `sha256(canonical_jcs(batch.body))`. The verifier
//! looks up the receipt's UUID, gets a "valid-looking" entry back,
//! and would accept the batch if it short-circuits on UUID presence.
//!
//! This test stages a tiny_http mock that responds to
//! `GET /api/v1/log/entries/<uuid>` with a Rekor entry whose body
//! commits to a DIFFERENT digest than the one the receipt claims.
//! The real `RekorClient::verify_inclusion` MUST detect the mismatch
//! and return `AnchorWitnessError::BodyHashMismatch`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use chio_anchor::{
    batch_body_hash, build_anchor_batch, build_rekor_entry_body_b64,
    build_rekor_entry_body_b64_with_hash, build_rekor_publish_response, AnchorBatchWitness,
    AnchorBatchWitnessKind, AnchorWitnessClient, AnchorWitnessError, RekorClient, WitnessReceipt,
};
use chio_core::hashing::{sha256, Hash};
use chio_core::Keypair;
use tiny_http::{Method, Response, Server};

struct MockServer {
    base_url: String,
    shutdown: Option<mpsc::Sender<()>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockServer {
    fn start<F>(handler: F) -> Self
    where
        F: Fn(&tiny_http::Request) -> tiny_http::Response<std::io::Cursor<Vec<u8>>>
            + Send
            + Sync
            + 'static,
    {
        let server = Server::http("127.0.0.1:0").expect("bind tiny_http");
        let port = server.server_addr().to_ip().expect("ip").port();
        let base_url = format!("http://127.0.0.1:{port}");
        let (tx, rx) = mpsc::channel::<()>();
        let handler = Arc::new(handler);
        let server = Arc::new(server);
        let server_clone = Arc::clone(&server);
        let handler_clone = Arc::clone(&handler);
        let handle = thread::spawn(move || loop {
            if rx.try_recv().is_ok() {
                break;
            }
            match server_clone.recv_timeout(Duration::from_millis(50)) {
                Ok(Some(req)) => {
                    let resp = handler_clone(&req);
                    let _ = req.respond(resp);
                }
                Ok(None) => {}
                Err(_) => break,
            }
        });
        MockServer {
            base_url,
            shutdown: Some(tx),
            handle: Some(handle),
        }
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(sender) = self.shutdown.take() {
            let _ = sender.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn sample_batch() -> chio_anchor::AnchorBatch {
    let kp = Keypair::generate();
    let witness = AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:placeholder".to_string(),
        root: Hash::zero(),
        observed_at: Some(1_700_000_000),
    };
    build_anchor_batch(
        vec!["ck-1".to_string(), "ck-2".to_string(), "ck-3".to_string()],
        witness,
        1_700_000_000,
        &kp,
    )
    .unwrap()
}

#[test]
fn rekor_publish_round_trips_a_batch_against_a_faithful_mock() {
    let batch = sample_batch();
    let body_b64 = build_rekor_entry_body_b64(&batch).unwrap();
    let body_b64_owned = body_b64.clone();
    let server = MockServer::start(move |req| {
        let body =
            build_rekor_publish_response("uuid-honest-1", &body_b64_owned, 1_700_000_010, 12345);
        let payload = serde_json::to_vec(&body).unwrap();
        let _ = req.method();
        Response::from_data(payload)
            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
    });

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let client = RekorClient::new(server.base_url.clone(), 0).unwrap();
    let receipt = runtime
        .block_on(client.publish(&batch))
        .expect("honest mock must produce a witness receipt");
    assert_eq!(receipt.kind, AnchorBatchWitnessKind::Rekor);
    assert_eq!(receipt.witness_root, batch.body.tree_root);
    assert_eq!(receipt.body_hash, batch_body_hash(&batch).unwrap());
}

#[test]
fn rekor_publish_rejects_lane_that_returns_a_forged_body_hash() {
    let batch = sample_batch();
    // Lane returns a Rekor body that commits to sha256("imposter")
    // instead of sha256(canonical(batch.body)). The real client MUST
    // detect this on the publish path itself.
    let forged_hash_hex = sha256(b"chio.anchor_batch.imposter").to_hex();
    let forged_b64 = build_rekor_entry_body_b64_with_hash(&batch, &forged_hash_hex).unwrap();
    let forged_b64_owned = forged_b64.clone();

    let server = MockServer::start(move |req| {
        let body = build_rekor_publish_response(
            "uuid-impersonator-1",
            &forged_b64_owned,
            1_700_000_010,
            999,
        );
        let payload = serde_json::to_vec(&body).unwrap();
        let _ = req.method();
        Response::from_data(payload)
            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
    });

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let client = RekorClient::new(server.base_url.clone(), 0).unwrap();
    let err = runtime
        .block_on(client.publish(&batch))
        .expect_err("publish must reject lane-side body-hash mismatch");
    match err {
        AnchorWitnessError::BodyHashMismatch { lane, batch: real } => {
            assert_eq!(lane, forged_hash_hex);
            assert_eq!(real, batch_body_hash(&batch).unwrap().to_hex());
        }
        other => panic!("expected BodyHashMismatch, got {other:?}"),
    }
}

#[test]
fn rekor_verify_inclusion_rejects_lane_that_returns_a_substituted_entry() {
    let batch = sample_batch();
    let real_body_hash = batch_body_hash(&batch).unwrap();

    // The verifier already holds an honest receipt (we pre-populated
    // it from a previous successful publish). At verify_inclusion
    // time, the mirror has been compromised: GET /entries/<uuid>
    // returns a Rekor body whose hash.value points at a different
    // batch.
    let receipt = WitnessReceipt {
        kind: AnchorBatchWitnessKind::Rekor,
        external_uuid: "uuid-attacked".to_string(),
        published_at: 1_700_000_010,
        inclusion_proof: vec![],
        witness_root: batch.body.tree_root,
        body_hash: real_body_hash,
    };

    let forged_hash_hex = sha256(b"chio.anchor_batch.different-batch").to_hex();
    let forged_b64 = build_rekor_entry_body_b64_with_hash(&batch, &forged_hash_hex).unwrap();
    let forged_b64_owned = forged_b64.clone();
    let server = MockServer::start(move |req| {
        let response_body =
            build_rekor_publish_response("uuid-attacked", &forged_b64_owned, 1_700_000_010, 42);
        let payload = serde_json::to_vec(&response_body).unwrap();
        let _ = req.method();
        Response::from_data(payload)
            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
    });

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let client = RekorClient::new(server.base_url.clone(), 0).unwrap();
    let err = runtime
        .block_on(client.verify_inclusion(&receipt))
        .expect_err("verify_inclusion must reject lane substitution");
    match err {
        AnchorWitnessError::BodyHashMismatch { lane, batch: held } => {
            assert_eq!(lane, forged_hash_hex);
            assert_eq!(held, real_body_hash.to_hex());
        }
        other => panic!("expected BodyHashMismatch on verify_inclusion, got {other:?}"),
    }
}

#[test]
fn rekor_verify_inclusion_rejects_uuid_substitution() {
    // The receipt claims uuid-X, but the mirror responds to
    // GET /entries/uuid-X with an entry keyed under uuid-Y. Real
    // production Rekor mirrors that try this attack get caught here.
    let batch = sample_batch();
    let real_body_hash = batch_body_hash(&batch).unwrap();
    let receipt = WitnessReceipt {
        kind: AnchorBatchWitnessKind::Rekor,
        external_uuid: "uuid-original-receipt".to_string(),
        published_at: 1_700_000_010,
        inclusion_proof: vec![],
        witness_root: batch.body.tree_root,
        body_hash: real_body_hash,
    };

    let body_b64 = build_rekor_entry_body_b64(&batch).unwrap();
    let body_b64_owned = body_b64.clone();
    let server = MockServer::start(move |req| {
        // Always reply with a SUBSTITUTED uuid keyspace, no matter
        // which uuid the verifier asked for.
        let payload_value = build_rekor_publish_response(
            "uuid-attacker-replaced",
            &body_b64_owned,
            1_700_000_010,
            7,
        );
        let payload = serde_json::to_vec(&payload_value).unwrap();
        let _ = req.method();
        Response::from_data(payload)
            .with_header(tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap())
    });

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let client = RekorClient::new(server.base_url.clone(), 0).unwrap();
    let err = runtime
        .block_on(client.verify_inclusion(&receipt))
        .expect_err("verify_inclusion must reject uuid substitution");
    match err {
        AnchorWitnessError::Decode(message) => {
            assert!(
                message.contains("rekor returned no entry for uuid"),
                "expected uuid-substitution decode error, got: {message}"
            );
        }
        other => panic!("expected Decode error on uuid substitution, got {other:?}"),
    }

    // Required by `tiny_http::Method` import lint.
    let _ = Method::Get;
}

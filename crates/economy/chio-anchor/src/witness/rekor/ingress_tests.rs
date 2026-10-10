use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type TestResult = Result<(), Box<dyn std::error::Error>>;

async fn serve(
    body: Vec<u8>,
    status: &str,
) -> Result<(String, tokio::task::JoinHandle<()>), std::io::Error> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let status = status.to_owned();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .unwrap_or_else(|e| panic!("accept: {e}"));
        let mut request = [0_u8; 8192];
        let count = stream
            .read(&mut request)
            .await
            .unwrap_or_else(|e| panic!("request: {e}"));
        assert!(count > 0);
        let headers = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        // A bounded reader may close as soon as the declared size exceeds its budget.
        if stream.write_all(headers.as_bytes()).await.is_ok() {
            let _ = stream.write_all(&body).await;
        }
    });
    Ok((endpoint, task))
}

fn signed_response(
    time: i64,
) -> Result<(serde_json::Value, String, WitnessReceipt), Box<dyn std::error::Error>> {
    let key = p256::ecdsa::SigningKey::from_slice(&[7_u8; 32])?;
    let body_hash = Hash::zero();
    let body = BASE64_STANDARD.encode(serde_json::to_vec(&serde_json::json!({"spec":{"content":{"hash":{"algorithm":"sha256","value":body_hash.to_hex()}}}}))?);
    let set = sign_set_with_test_key(&body, time, &"0".repeat(64), 0, &key)?;
    Ok((
        build_rekor_publish_response_with_set("entry-1", &body, time, 0, &set),
        verifying_key_to_pem(key.verifying_key())?,
        WitnessReceipt {
            kind: AnchorBatchWitnessKind::Rekor,
            external_uuid: "entry-1".to_owned(),
            published_at: time,
            inclusion_proof: Vec::new(),
            witness_root: Hash::zero(),
            body_hash,
        },
    ))
}

#[tokio::test]
async fn original_rekor_rejects_authenticated_future_time() -> TestResult {
    let (response, key, receipt) = signed_response(i64::MAX)?;
    let (endpoint, task) = serve(serde_json::to_vec(&response)?, "200 OK").await?;
    let client = RekorClient::new(endpoint, 0)?.with_trusted_keys(vec![key]);
    let result = client.verify_inclusion(&receipt).await;
    task.await?;
    assert!(matches!(result, Err(error) if error.to_string().contains("not yet valid")));
    Ok(())
}

#[tokio::test]
async fn original_rekor_receipt_timestamp_is_bound_to_signed_entry() -> TestResult {
    let (response, key, mut receipt) = signed_response(1_700_000_000)?;
    receipt.published_at += 1;
    let (endpoint, task) = serve(serde_json::to_vec(&response)?, "200 OK").await?;
    let client = RekorClient::new(endpoint, 0)?.with_trusted_keys(vec![key]);
    let result = client.verify_inclusion(&receipt).await;
    task.await?;
    assert!(matches!(result, Err(error) if error.to_string().contains("timestamp")));
    Ok(())
}

#[tokio::test]
async fn original_rekor_response_budget_precedes_projection() -> TestResult {
    let (mut response, key, receipt) = signed_response(1_700_000_000)?;
    response["entry-1"]["ignored"] = serde_json::Value::String("x".repeat(4 * 1024 * 1024));
    let (endpoint, task) = serve(serde_json::to_vec(&response)?, "200 OK").await?;
    let client = RekorClient::new(endpoint, 0)?.with_trusted_keys(vec![key]);
    let result = client.verify_inclusion(&receipt).await;
    task.await?;
    assert!(matches!(result, Err(error) if error.to_string().contains("too-large")));
    Ok(())
}

#[test]
fn original_witness_proof_decode_is_bounded() -> TestResult {
    let (_, _, receipt) = signed_response(1_700_000_000)?;
    let mut value = serde_json::to_value(receipt)?;
    value["inclusionProof"] = BASE64_STANDARD.encode(vec![0; 1024 * 1024 + 1]).into();
    assert!(
        matches!(serde_json::from_value::<WitnessReceipt>(value), Err(error) if error.to_string().contains("bound"))
    );
    Ok(())
}

struct ScriptClock(
    std::sync::Mutex<
        std::collections::VecDeque<Result<chio_security_types::clock::ClockReading, ClockError>>,
    >,
);
impl Clock for ScriptClock {
    fn read(&self) -> Result<chio_security_types::clock::ClockReading, ClockError> {
        self.0
            .lock()
            .map_err(|_| ClockError::Unavailable)?
            .pop_front()
            .unwrap_or(Err(ClockError::Unavailable))
    }
}
fn reading(
    seconds: u64,
    ticks: u64,
) -> Result<chio_security_types::clock::ClockReading, ClockError> {
    use chio_security_types::clock::{ClockReading, MonotonicInstant, UnixMillis};
    Ok(ClockReading::new(
        UnixMillis::from_secs(seconds)?,
        MonotonicInstant::from_nanos(ticks),
    ))
}

#[tokio::test]
async fn witness_clock_failure_denies_before_network() -> TestResult {
    let (_, _, receipt) = signed_response(100)?;
    let clock = Arc::new(ScriptClock(std::sync::Mutex::new(
        [Err(ClockError::Unavailable)].into(),
    )));
    let client = RekorClient::new_with_clock("http://127.0.0.1:9", 30, clock)?;
    assert!(matches!(
        client.verify_inclusion(&receipt).await,
        Err(AnchorWitnessError::Clock(ClockError::Unavailable))
    ));
    Ok(())
}

#[tokio::test]
async fn witness_client_clones_share_both_clock_fences() -> TestResult {
    for (last, expected) in [
        (reading(99, 12), ClockError::WallClockRegression),
        (reading(101, 9), ClockError::MonotonicRegression),
    ] {
        let (response, key, receipt) = signed_response(100)?;
        let (endpoint, task) = serve(serde_json::to_vec(&response)?, "200 OK").await?;
        let clock = Arc::new(ScriptClock(std::sync::Mutex::new(
            [reading(100, 10), reading(101, 11), last].into(),
        )));
        let client = RekorClient::new_with_clock(endpoint, 30, clock)?.with_trusted_keys(vec![key]);
        let clone = client.clone();
        client.verify_inclusion(&receipt).await?;
        task.await?;
        // The one-response server is gone. Regression must precede any second request.
        assert!(
            matches!(clone.verify_inclusion(&receipt).await, Err(AnchorWitnessError::Clock(error)) if error == expected)
        );
    }
    Ok(())
}

#[tokio::test]
async fn witness_rejects_ambiguous_entry_maps_and_redacts_http_failures() -> TestResult {
    let (mut response, key, receipt) = signed_response(100)?;
    response["entry-2"] = response["entry-1"].clone();
    let (endpoint, task) = serve(serde_json::to_vec(&response)?, "200 OK").await?;
    let client = RekorClient::new(endpoint, 0)?.with_trusted_keys(vec![key]);
    assert!(
        matches!(client.verify_inclusion(&receipt).await, Err(AnchorWitnessError::Decode(message)) if message.contains("exactly one"))
    );
    task.await?;
    let (endpoint, task) = serve(b"private-marker".to_vec(), "503 Unavailable").await?;
    let client = RekorClient::new(endpoint, 0)?;
    let result = client.verify_inclusion(&receipt).await;
    task.await?;
    assert!(matches!(
        result,
        Err(AnchorWitnessError::Http { status: 503, .. })
    ));
    assert!(!format!("{result:?}").contains("private-marker"));
    Ok(())
}

#[tokio::test]
async fn witness_publish_authenticates_and_binds_receipt_at_injected_time() -> TestResult {
    use crate::batch::{build_anchor_batch, AnchorBatchWitness};
    let signer = chio_core::Keypair::from_seed(&[11; 32]);
    let batch = build_anchor_batch(
        vec!["checkpoint-1".to_owned()],
        AnchorBatchWitness {
            kind: AnchorBatchWitnessKind::Rekor,
            witness_id: "pending".to_owned(),
            root: Hash::zero(),
            observed_at: Some(100),
        },
        100,
        &signer,
    )?;
    let key = p256::ecdsa::SigningKey::from_slice(&[7; 32])?;
    let body = build_rekor_entry_body_b64(&batch)?;
    let set = sign_set_with_test_key(&body, 100, &"0".repeat(64), 0, &key)?;
    let response = build_rekor_publish_response_with_set("entry-1", &body, 100, 0, &set);
    let (endpoint, task) = serve(serde_json::to_vec(&response)?, "200 OK").await?;
    let client = RekorClient::new_with_clock(
        endpoint,
        30,
        Arc::new(chio_security_types::clock::FixedClock::new(100)),
    )?
    .with_trusted_keys(vec![verifying_key_to_pem(key.verifying_key())?]);
    let receipt = client.publish(&batch).await?;
    task.await?;
    assert_eq!(receipt.external_uuid, "entry-1");
    assert_eq!(receipt.published_at, 100);
    assert_eq!(receipt.body_hash, batch_body_hash(&batch)?);
    assert_eq!(receipt.witness_root, batch.body.tree_root);
    let client = RekorClient::new_with_clock(
        "http://127.0.0.1:9",
        30,
        Arc::new(ScriptClock(std::sync::Mutex::new(
            [Err(ClockError::Unavailable)].into(),
        ))),
    )?;
    assert!(matches!(
        client.publish(&batch).await,
        Err(AnchorWitnessError::Clock(ClockError::Unavailable))
    ));
    Ok(())
}

#[test]
fn original_rekor_hash_shape_precedes_public_mismatch_diagnostics() -> TestResult {
    let (response, _, _) = signed_response(100)?;
    let mut entry: RekorEntry = serde_json::from_value(response["entry-1"].clone())?;
    for invalid in ["private-marker", &"g".repeat(64)] {
        entry.body = BASE64_STANDARD.encode(serde_json::to_vec(&serde_json::json!({"spec":{"content":{"hash":{"algorithm":"sha256","value":invalid}}}}))?);
        assert!(
            matches!(extract_lane_body_hash(&entry), Err(AnchorWitnessError::Decode(message)) if message == "Rekor entry hash is not SHA-256 hex")
        );
    }
    Ok(())
}

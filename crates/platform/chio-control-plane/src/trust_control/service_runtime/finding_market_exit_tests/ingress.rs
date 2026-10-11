use super::*;

#[tokio::test]
async fn noncanonical_publish_ingress_rejects() -> TestResult {
    let mut stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    stack.seed_market().await?;
    let web = &stack.web;

    let parsed: serde_json::Value = serde_json::from_str(&web.second_raw_finding)?;

    // Duplicate member names never reach the schema layer.
    let duplicate_keys = r#"{"schema":"chio.finding.v1","schema":"chio.finding.v1"}"#.to_string();

    // Uppercase hex survives canonicalization byte-for-byte and is caught
    // by the registered schema's lowercase digest pattern.
    let mut uppercase = parsed.clone();
    uppercase["payload_sha256"] = serde_json::json!(HEX64.to_uppercase());
    let uppercase = canonical_string(&uppercase)?;

    // An explicit null option is either rejected by the schema or erased
    // by typed deserialization, breaking typed-canonical equality.
    let mut explicit_null = parsed.clone();
    explicit_null["license_ref"] = serde_json::Value::Null;
    let explicit_null = canonical_string(&explicit_null)?;

    // A float token spells the same number noncanonically.
    let float_token = web
        .second_raw_finding
        .replacen("\"units\":10}", "\"units\":10.0}", 1);
    assert_ne!(float_token, web.second_raw_finding);

    // Whitespace padding breaks raw-equals-canonical.
    let padded = format!(" {}", web.second_raw_finding);

    for raw in [
        duplicate_keys,
        uppercase,
        explicit_null,
        float_token,
        padded,
    ] {
        let (status, body) = send(&stack.state, authed_post("/v1/findings/publish", raw)?).await?;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{}",
            String::from_utf8_lossy(&body)
        );
    }
    // Nothing was indexed by any rejected spelling.
    let (status, _) = send(
        &stack.state,
        public_get(&format!("/v1/findings/{}", web.second_finding_id))?,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn oversized_publish_body_rejects() -> TestResult {
    let stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    let oversized = "x".repeat(FINDING_PUBLISH_MAX_BODY_BYTES + 1);
    let (status, _) = send(
        &stack.state,
        authed_post("/v1/findings/publish", oversized)?,
    )
    .await?;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    Ok(())
}

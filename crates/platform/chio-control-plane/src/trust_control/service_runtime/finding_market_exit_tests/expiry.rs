use super::*;

#[tokio::test]
async fn expired_admission_loses_the_marker() -> TestResult {
    let mut stack = provision_stack(LONG_EPOCH_SECS, WINDOW_EXPIRES_AT)?;
    stack.seed_market().await?;
    // Start the six-second admission window after provisioning, which signs
    // and publishes the collateral evidence before activation can be tested.
    let expires_at = unix_timestamp_now() + 6;
    let admission =
        stack
            .web
            .admission_body(&stack.web.schedule_sha256, &stack.web.report, expires_at)?;
    stack.web.admission = sign_admission(admission, &stack.web.venue)?;
    stack.web.admission_json = canonical_string(&stack.web.admission)?;
    let (status, body) = stack.activate().await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert!(stack.admission_marker().await?.is_some());
    let remaining = expires_at.saturating_sub(unix_timestamp_now()) + 1;
    tokio::time::sleep(std::time::Duration::from_secs(remaining)).await;
    assert!(
        stack.admission_marker().await?.is_none(),
        "an expired admission must clear the qualified-profile marker"
    );
    let (status, _) = send(
        &stack.state,
        public_get(&format!("/v1/findings/{}/admission", stack.web.finding_id))?,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let renewal = participation_request(&stack.web.schedule, None)?;
    let (status, body) = send(
        &stack.state,
        authed_post(
            &format!("/v1/findings/{}/participation", stack.web.finding_id),
            renewal.to_string(),
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&body).contains("not live"));
    assert_eq!(
        stack.store.paid_through_epoch(
            &stack.web.finding_id,
            LISTING_ID,
            &stack.web.schedule_sha256,
        )?,
        Some(0)
    );
    Ok(())
}

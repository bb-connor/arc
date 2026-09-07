use super::*;

#[tokio::test]
async fn unpaid_epoch_drops_the_marker_until_renewal() -> TestResult {
    // One-second audit epochs: the epoch lapses on the wall clock right
    // after activation, so the unpaid-epoch read-time filter is
    // observable without touching the stored envelope.
    let mut stack = provision_stack(1, ADMISSION_EXPIRES_AT)?;
    stack.seed_market().await?;
    let (status, body) = stack.activate().await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
    assert!(
        stack.admission_marker().await?.is_none(),
        "an unpaid epoch must clear the qualified-profile marker"
    );
    let (status, _) = send(
        &stack.state,
        public_get(&format!("/v1/findings/{}/admission", stack.web.finding_id))?,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Renewal restores currency. Epochs advance one wall-clock second at
    // a time here, so a short bounded loop of renewals catches up.
    let renewal = participation_request(&stack.web.schedule, None)?.to_string();
    let mut restored = false;
    for _ in 0..8 {
        let (status, body) = send(
            &stack.state,
            authed_post(
                &format!("/v1/findings/{}/participation", stack.web.finding_id),
                renewal.clone(),
            )?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        if stack.admission_marker().await?.is_some() {
            restored = true;
            break;
        }
    }
    assert!(
        restored,
        "participation renewal must restore the qualified-profile marker"
    );
    let paid_through = stack
        .store
        .paid_through_epoch(
            &stack.web.finding_id,
            LISTING_ID,
            &stack.web.schedule_sha256,
        )?
        .ok_or_else(|| missing("paid-through epoch after renewal"))?;
    assert!(paid_through >= 1);
    Ok(())
}

#[tokio::test]
async fn fee_routes_require_an_explicit_authoritative_rail() -> TestResult {
    let mut activation = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    activation.seed_market().await?;
    let mut no_rail_state = activation.state.clone();
    no_rail_state.finding_rail = None;
    let (status, body) = send(
        &no_rail_state,
        authed_post(
            &format!("/v1/findings/{}/activate", activation.web.finding_id),
            activation.web.activate_request(
                &activation.web.admission,
                &activation.web.schedule,
                &activation.web.report,
            )?,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(String::from_utf8_lossy(&body).contains("no evidenced rail observer"));
    assert_nothing_admitted(&activation).await?;

    let mut participation = provision_stack(1, ADMISSION_EXPIRES_AT)?;
    participation.seed_market().await?;
    let (status, body) = participation.activate().await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
    let mut no_rail_state = participation.state.clone();
    no_rail_state.finding_rail = None;
    let renewal = participation_request(&participation.web.schedule, None)?;
    let (status, body) = send(
        &no_rail_state,
        authed_post(
            &format!(
                "/v1/findings/{}/participation",
                participation.web.finding_id
            ),
            renewal.to_string(),
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(String::from_utf8_lossy(&body).contains("no evidenced rail observer"));
    assert_eq!(
        participation.store.paid_through_epoch(
            &participation.web.finding_id,
            LISTING_ID,
            &participation.web.schedule_sha256,
        )?,
        Some(0)
    );
    assert!(participation.admission_marker().await?.is_none());
    Ok(())
}

#[tokio::test]
async fn activation_rejects_a_mismatched_rail_observation() -> TestResult {
    let mut stack = provision_stack(LONG_EPOCH_SECS, ADMISSION_EXPIRES_AT)?;
    stack.seed_market().await?;
    let mut mismatched_state = stack.state.clone();
    mismatched_state.finding_rail = Some(Arc::new(MismatchedRail));
    let (status, body) = send(
        &mismatched_state,
        authed_post(
            &format!("/v1/findings/{}/activate", stack.web.finding_id),
            stack.web.activate_request(
                &stack.web.admission,
                &stack.web.schedule,
                &stack.web.report,
            )?,
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(String::from_utf8_lossy(&body).contains("does not reconcile"));
    let publication_event = stack
        .store
        .get_fee_event(&stack.publication_fee_key())?
        .ok_or_else(|| missing("publication fee intent after rail mismatch"))?;
    assert_eq!(publication_event.state, FindingFeeState::Failed);
    assert!(publication_event.observation_sha256.is_none());
    assert_not_admitted_with_allocation(&stack, FindingAllocationState::Consumed).await?;
    Ok(())
}

#[tokio::test]
async fn participation_renewal_rejects_a_mismatched_rail_observation() -> TestResult {
    let mut stack = provision_stack(1, ADMISSION_EXPIRES_AT)?;
    stack.seed_market().await?;
    let (status, body) = stack.activate().await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));

    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
    let mut mismatched_state = stack.state.clone();
    mismatched_state.finding_rail = Some(Arc::new(MismatchedRail));
    let renewal = participation_request(&stack.web.schedule, None)?;
    let (status, body) = send(
        &mismatched_state,
        authed_post(
            &format!("/v1/findings/{}/participation", stack.web.finding_id),
            renewal.to_string(),
        )?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(String::from_utf8_lossy(&body).contains("does not reconcile"));
    assert_eq!(
        stack.store.paid_through_epoch(
            &stack.web.finding_id,
            LISTING_ID,
            &stack.web.schedule_sha256,
        )?,
        Some(0)
    );
    assert!(stack.admission_marker().await?.is_none());
    Ok(())
}

#[tokio::test]
async fn expired_admission_loses_the_marker() -> TestResult {
    // Provisioning performs several cryptographic and SQLite setup steps. Keep
    // enough wall-clock headroom for this test to remain valid under the full
    // parallel control-plane suite before deliberately waiting for expiry.
    let expires_at = unix_timestamp_now() + 30;
    let mut stack = provision_stack(LONG_EPOCH_SECS, expires_at)?;
    stack.seed_market().await?;
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

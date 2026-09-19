use super::*;

/// A settlement retried after a crash arrives with a later clock. The
/// terminal artifacts must not embed that clock: the store compares the
/// retained bytes against the retry's bytes, so a clock-dependent artifact
/// would turn an honest retry into an unresolvable conflict. Both closes
/// must therefore replay byte-identically whatever `now` the retry carries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_settlement_replays_byte_identically_across_clocks() -> TestResult {
    let lane = open_lane(LaneOptions::standard()).await?;
    let response = lane.reveal("wedge-clock-replay-1", "nonce-clock-replay-1")?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);

    let purchase_store = lane.authority.finding_purchase_store();
    let reservation_id = lane.purchase.handshake.reservation_id.clone();
    let now = unix_timestamp_now();
    purchase_store.register_community_fund_destination(
        &lane.deployment.web.allocation_id,
        COMMUNITY_FUND_DESTINATION,
        now,
    )?;
    let first = lane.coordinator.finalize_delivery(
        &reservation_id,
        &response.receipt,
        &lane.deployment.web.admission,
        &lane.deployment.web.backing,
        now,
    )?;
    let retry = lane.coordinator.finalize_delivery(
        &reservation_id,
        &response.receipt,
        &lane.deployment.web.admission,
        &lane.deployment.web.backing,
        now.saturating_add(41),
    )?;
    assert_eq!(canonical_json_bytes(&first)?, canonical_json_bytes(&retry)?);
    Ok(())
}

/// The denial close must replay across clocks the same way: the terminal id
/// is content-addressed over the artifact body, so a clock inside the body
/// would give every retry a different identity for the same denial.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_denial_replays_byte_identically_across_clocks() -> TestResult {
    let lane = open_lane(LaneOptions {
        case: RevealCase::digest_mismatch(),
        ..LaneOptions::standard()
    })
    .await?;
    let response = lane.reveal("wedge-clock-deny-1", "nonce-clock-deny-1")?;
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);

    let reservation_id = lane.purchase.handshake.reservation_id.clone();
    let now = unix_timestamp_now();
    let (checkpoint, inclusion_proof) = denial_checkpoint(&response.receipt)?;
    let first = lane.coordinator.finalize_denial(
        &reservation_id,
        &response.receipt,
        &lane.deployment.web.admission,
        &checkpoint,
        &inclusion_proof,
        now,
    )?;
    let retry = lane.coordinator.finalize_denial(
        &reservation_id,
        &response.receipt,
        &lane.deployment.web.admission,
        &checkpoint,
        &inclusion_proof,
        now.saturating_add(41),
    )?;
    assert_eq!(first.body.failed_delivery_id, retry.body.failed_delivery_id);
    assert_eq!(canonical_json_bytes(&first)?, canonical_json_bytes(&retry)?);
    Ok(())
}

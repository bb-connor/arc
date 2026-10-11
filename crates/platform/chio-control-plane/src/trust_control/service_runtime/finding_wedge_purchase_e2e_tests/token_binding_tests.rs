//! Exact token binding and the public projection of its private rejection.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedge_purchase_alternate_token_denies() -> TestResult {
    let lane = open_lane(LaneOptions::standard()).await?;

    // A second mint for the same subject and sale: same grant profile, a
    // different token identity, so the carrier's ask no longer names it.
    let alternate = handshake(
        &lane.deployment.web,
        &lane.witness,
        &lane.buyer,
        BUYER_PAYOUT,
        "finding-purchase-token-0002",
    )?;
    assert_ne!(
        alternate.ask.body.token_offer.id,
        lane.purchase.capability.id
    );
    let request = reveal_request(&RevealRequestInputs {
        request_id: "wedge-alternate-token-1",
        capability: &alternate.ask.body.token_offer,
        buyer: &lane.buyer,
        finding_id: &lane.deployment.web.finding_id,
        context_b64: Some(&lane.purchase.context_b64),
        status_proof_b64: None,
        nonce: "nonce-alternate-token-1",
    })?;
    use chio_open_market::purchase_verification::{
        verify_purchase_context_pure, PurchaseVerificationError, PurchaseVerificationInputs,
    };
    // Check the private cause at its owner, then the kernel's stable public
    // projection. Public diagnostics intentionally do not expose native causes.
    assert!(matches!(
        verify_purchase_context_pure(
            &PurchaseVerificationInputs {
                marker_finding_id: &lane.deployment.web.finding_id,
                marker_listing_id: LISTING_ID,
                expected_output_digest: &lane.deployment.web.finding.payload_sha256,
                context_b64: &lane.purchase.context_b64,
                capability: &request.capability,
                server_id: &request.server_id,
                tool_name: &request.tool_name,
                arguments: &request.arguments,
            },
            &purchase_authorities(&lane.deployment.web),
        ),
        Err(PurchaseVerificationError::TokenByteMismatch)
    ));
    let response = lane.kernel.evaluate_tool_call_blocking(&request)?;
    assert_denied_with(&response, "purchase context verification failed");
    assert_eq!(lane.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(lane.calls.authorizations.load(Ordering::SeqCst), 0);
    Ok(())
}

use super::*;
use chio_security_types::clock::{Clock, ClockError, ClockReading, FixedClock};
use futures_util::StreamExt;

struct FilingClock(Mutex<Result<u64, ClockError>>);

impl Clock for FilingClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let seconds = *self.0.lock().map_err(|_| ClockError::Unavailable)?;
        FixedClock::from_millis(seconds?.checked_mul(1_000).ok_or(ClockError::Overflow)?).read()
    }
}

/// Moving the authority sample ahead of body I/O must allow neither late filing
/// nor a filing whose clock failed while the client was uploading it.
#[tokio::test]
async fn finding_challenge_upload_cannot_reuse_entry_time() -> TestResult {
    for unavailable in [false, true] {
        let deployment = deployment()?;
        let (finding, raw_finding) = finding_artifact()?;
        deployment.market.put_finding(
            &FindingRecordInput {
                finding_id: &finding.finding_id,
                artifact_json: &raw_finding,
                topic: &finding.descriptor.topic,
                context_sha256: &finding.descriptor.context_sha256,
                issued_at: finding.issued_at,
                expires_at: finding.expires_at,
            },
            NOW,
        )?;
        let terms = market_terms(CLAIM_WINDOW_SECS)?;
        let deadline = terms.body.issued_at + terms.body.filing_window_secs;
        let challenge = buyer_challenge(&keypair(41))?;
        let raw_challenge = canonical_json_string(&challenge)?;
        let coordinator =
            Arc::new(deployment.coordinator(FindingDisputeLockDisposition::Forfeited)?);
        let mut state = challenge_route_state(&deployment, coordinator);
        let clock = Arc::new(FilingClock(Mutex::new(Ok(NOW))));
        state.finding_challenge_clock = clock.clone();
        // The first chunk is accepted at handler-entry time. The stream then
        // advances or faults the clock before delivering the rest of the body.
        let split = raw_challenge.len() / 2;
        let first = Bytes::copy_from_slice(&raw_challenge.as_bytes()[..split]);
        let last = Bytes::copy_from_slice(&raw_challenge.as_bytes()[split..]);
        let body = Body::from_stream(stream::iter([Ok::<Bytes, std::io::Error>(first)]).chain(
            stream::once(async move {
                tokio::task::yield_now().await;
                *clock
                    .0
                    .lock()
                    .map_err(|_| std::io::Error::other("clock lock poisoned"))? = if unavailable {
                    Err(ClockError::Unavailable)
                } else {
                    Ok(deadline + 1)
                };
                Ok(last)
            }),
        ));
        let response = build_router(state)
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri(format!("/v1/findings/{}/challenges", finding.finding_id))
                    .header("content-type", "application/json")
                    .header(AUTHORIZATION, "Bearer challenge-service-secret")
                    .body(body)?,
            )
            .await?;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 4096).await?;
        let message = std::str::from_utf8(&bytes)?;
        if unavailable {
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{message}");
            assert!(
                message.contains(ClockError::Unavailable.code()),
                "{message}"
            );
        } else {
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{message}");
            assert!(
                message.contains(&ChallengeCoordinatorError::FilingWindowClosed.to_string()),
                "{message}"
            );
        }
        assert!(deployment
            .challenges
            .get_challenge(&challenge.body.challenge_id)?
            .is_none());
        assert!(deployment.rail.charges().is_empty());
    }
    Ok(())
}

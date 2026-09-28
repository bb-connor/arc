use super::credentials::evaluate;
use super::*;
use chio_security_types::clock::{Clock, ClockError, ClockReading};

struct UnavailableClock;
impl Clock for UnavailableClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        Err(ClockError::Unavailable)
    }
}

#[test]
fn nonce_clock_failure_keeps_its_code_in_the_signed_denial() -> TestResult {
    for nested in [false, true] {
        let (mut kernel, _, request, _) =
            request_with_recording_execution_nonce_store("nonce-clock-denial")?;
        let config = kernel
            .execution_nonce_config
            .clone()
            .ok_or("nonce config")?;
        kernel.set_execution_nonce_store(
            config,
            Box::new(InMemoryExecutionNonceStore::with_clock(
                4,
                Arc::new(UnavailableClock),
            )),
        );
        let response = evaluate(&kernel, &request, nested)?;
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response.receipt.verify_signature()?);
        assert_eq!(
            response
                .receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.pointer("/chio_kernel/rejection_code"))
                .and_then(serde_json::Value::as_str),
            Some(ClockError::Unavailable.code())
        );
        assert!(response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("trusted clock unavailable")));
    }
    Ok(())
}

#[test]
fn governed_window_refusals_keep_their_code_in_root_and_nested_receipts() -> TestResult {
    for nested in [false, true] {
        for (issued_delta, expiry_delta, expected) in [
            (0_i64, 0_i64, ClockError::InvalidWindow.code()),
            (0, -1, ClockError::InvalidWindow.code()),
            (60, 120, ClockError::NotYetValid.code()),
            (-120, -60, ClockError::Expired.code()),
            (
                -1,
                3_601,
                "urn:chio:error:kernel:governed-approval-lifetime",
            ),
        ] {
            let mut fixture = post_dispatch_approval_commit_fixture(
                "approval-window-denial",
                PostDispatchApprovalCommitFailure::StoreError,
            );
            let now = current_unix_timestamp();
            let mut body = fixture
                .request
                .approval_token
                .as_ref()
                .ok_or("approval")?
                .body();
            body.issued_at = now.checked_add_signed(issued_delta).ok_or("issued at")?;
            body.expires_at = now.checked_add_signed(expiry_delta).ok_or("expires at")?;
            fixture.request.approval_token = Some(GovernedApprovalToken::sign(
                body,
                &fixture.kernel.config.keypair,
            )?);
            let response = evaluate(&fixture.kernel, &fixture.request, nested)?;
            assert_eq!(response.verdict, Verdict::Deny);
            assert!(response.receipt.verify_signature()?);
            assert_eq!(
                response
                    .receipt
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.pointer("/chio_kernel/rejection_code"))
                    .and_then(serde_json::Value::as_str),
                Some(expected)
            );
            assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        }
    }
    Ok(())
}

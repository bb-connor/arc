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

#[test]
fn dpop_rule_codes_survive_root_and_nested_signed_denials() -> TestResult {
    use crate::dpop::DpopError;
    for nested in [false, true] {
        for (kind, code) in [
            (0, DpopError::Action.code()),
            (1, DpopError::Expired.code()),
            (2, DpopError::Signature.code()),
            (3, DpopError::Replayed.code()),
            (4, DpopError::MissingProof.code()),
        ] {
            let agent = Keypair::generate();
            let (kernel, cap) = make_dpop_kernel_and_cap(&agent, "srv-a", "read_file");
            let mut request = make_request("dpop-code", &cap, "read_file", "srv-a");
            let mut proof = make_dpop_proof(
                &agent,
                &cap,
                "srv-a",
                "read_file",
                &request.arguments,
                "nonce",
            );
            match kind {
                0 => proof.body.action_hash = "wrong-action".into(),
                1 => proof.body.issued_at = 1,
                2 => proof.signature = Keypair::generate().sign(b"not-the-proof"),
                3 => {
                    assert!(kernel
                        .dpop_nonce_store
                        .as_ref()
                        .ok_or("DPoP store")?
                        .check_and_insert_through("nonce", &cap.id, proof.body.issued_at + 300)?);
                }
                _ => {}
            }
            request.dpop_proof = (kind != 4).then_some(proof);
            let response = evaluate(&kernel, &request, nested)?;
            assert_eq!(response.verdict, Verdict::Deny);
            assert!(response.receipt.verify_signature()?);
            assert_eq!(
                response
                    .receipt
                    .metadata
                    .as_ref()
                    .and_then(|m| m.pointer("/chio_kernel/rejection_code"))
                    .and_then(serde_json::Value::as_str),
                Some(code)
            );
        }
    }
    Ok(())
}

#[test]
fn installed_dpop_and_default_approval_follow_the_kernel_clock() -> TestResult {
    use crate::replay_retention::tests::TestClock;
    let clock = Arc::new(TestClock::new(100));
    let mut kernel = ChioKernel::new_with_clock(make_config(), clock.clone());
    kernel.set_dpop_store(
        DpopNonceStore::new(2, Duration::from_secs(60)),
        DpopConfig::default(),
    )?;
    let dpop = kernel.dpop_nonce_store.as_ref().ok_or("DPoP store")?;
    let approval = kernel
        .approval_replay_store
        .as_ref()
        .ok_or("approval store")?;
    assert!(dpop.check_and_insert_until("nonce", "cap", 110)?);
    assert!(approval.reserve_for_dispatch("subject", "request", "intent", 110, "owner")?);
    clock.fail();
    assert!(matches!(
        dpop.check_and_insert_until("next", "cap", 110),
        Err(KernelError::Clock(ClockError::Unavailable))
    ));
    assert!(matches!(
        approval.reserve_for_dispatch("subject", "next", "intent", 110, "owner"),
        Err(KernelError::Clock(ClockError::Unavailable))
    ));
    clock.set(110, 10);
    assert!(matches!(
        dpop.check_and_insert_until("next", "cap", 110),
        Err(KernelError::Dpop(crate::dpop::DpopError::Expired))
    ));
    assert!(matches!(
        approval.reserve_for_dispatch("subject", "next", "intent", 110, "owner"),
        Err(KernelError::ApprovalReplay(
            crate::governed_approval_replay::ApprovalReplayError::Expired
        ))
    ));
    Ok(())
}

#[test]
fn dropped_dispatch_retains_dpop_without_rollback_ownership() -> TestResult {
    use crate::admission_operation::AdmissionIdentifier;
    use crate::dpop::replay_source::{DpopReplaySourceBinding, DpopReplaySourcePort};
    let agent = Keypair::generate();
    let (kernel, cap) = make_dpop_kernel_and_cap(&agent, "srv-a", "read_file");
    let mut request = make_request("dropped-dpop", &cap, "read_file", "srv-a");
    let proof = make_dpop_proof(
        &agent,
        &cap,
        "srv-a",
        "read_file",
        &request.arguments,
        "nonce",
    );
    let now = proof.body.issued_at;
    request.dpop_proof = Some(proof);
    let store = kernel.dpop_nonce_store.as_ref().ok_or("DPoP store")?;
    let binding = DpopReplaySourceBinding {
        dpop_authority_id: AdmissionIdentifier::try_new("authority", "dpop")?,
        destination_authority_id: AdmissionIdentifier::try_new("destination", "kernel")?,
    };
    let mut reservation = kernel.reserve_dispatch_credentials(&request, &cap, true, now, false)?;
    let before = store.preview_unsealed(&binding)?;
    let owner = before.markers()[0]
        .dispatch_reservation_id
        .as_deref()
        .ok_or("owner")?;
    reservation.retain_if_dropped()?;
    drop(reservation);
    let after = store.preview_unsealed(&binding)?;
    assert_eq!(after.markers().len(), 1);
    assert_eq!(after.markers()[0].dispatch_reservation_id, None);
    assert!(!store.rollback_dispatch_reservation("nonce", &cap.id, owner)?);
    assert!(!store.check_and_insert_through("nonce", &cap.id, now + 300)?);
    Ok(())
}

use super::*;


#[test]
fn authority_rpc_completion_uses_current_trusted_time() {
    let fixture = advancing_authority_fixture("normal");
    let (request, _) = execution(&fixture, 210, 1);
    fixture
        .service
        .validate_request_authorities(&request, "combined-authority", 20, true)
        .test_expect("fresh responses produced after the request started");
    assert!(fixture
        .observed_authorizations
        .lock()
        .test_expect("provider observations")
        .is_empty());
}

#[test]
fn authority_rpc_completion_rejects_future_expired_and_unavailable_time() {
    for mode in [
        "future",
        "future_revocation",
        "expired",
        "expires_during_revocation",
        "rollback",
        "unavailable",
    ] {
        let fixture = advancing_authority_fixture(mode);
        let (request, _) = execution(&fixture, 211, 1);
        let error = fixture
            .service
            .validate_request_authorities(&request, "combined-authority", 20, true)
            .err()
            .test_expect("invalid authority observation must deny");
        if mode == "rollback" {
            assert!(error.to_string().contains("moved backwards"));
        } else if mode == "unavailable" {
            assert!(error.to_string().contains("clock unavailable"));
        }
        assert!(fixture
            .observed_authorizations
            .lock()
            .test_expect("provider observations")
            .is_empty());
    }
}

#[test]
fn authority_rpc_completion_time_is_bound_into_independently_verified_audit() {
    let fixture = advancing_authority_fixture("normal");
    let (request, _) = execution(&fixture, 212, 1);
    let (reference, precommitment) = audit_reference_for_execution(&fixture, &request, true);
    let (runner, admin, signed_runner) = authorized_audit(
        &fixture,
        &request,
        &reference,
        "audit-delayed-authority",
        20,
    );
    let completed = fixture
        .service
        .audit_compare_outbound_request(
            &request,
            reference,
            runner,
            &admin,
            fixture.audit_admin.as_ref(),
            20,
        )
        .test_expect("audit observes authority completion time");
    assert_eq!(completed.comparison.body.issued_at_unix_seconds, 22);
    let mut context = completed_audit_context(
        &request,
        "audit-delayed-authority",
        "legacy-provider-observation",
        &precommitment,
        audit_trust(&fixture),
    );
    context.expires_at_unix_seconds = 24;
    verify_completed_audit(&completed, &signed_runner, &admin, context)
        .test_expect("independent verification preserves original request times");
}


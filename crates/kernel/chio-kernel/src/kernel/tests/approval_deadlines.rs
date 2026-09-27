use super::*;

#[test]
fn inverted_signed_window_has_one_refusal_independent_of_verifier_time() {
    let store = StdArc::new(InMemoryApprovalStore::new());
    let guard = ApprovalGuard::new(store.clone());
    let request = hitl_make_request();
    let approver = CoreKeypair::generate();
    guard
        .evaluate(
            ApprovalContext {
                request: &request,
                constraints: &[],
                policy_id: "policy-hitl",
                trusted_approvers: &[approver.public_key()],
                presented_token: None,
                force_approval: true,
                approval_id_override: Some("inverted".into()),
            },
            90,
        )
        .unwrap();
    let pending = store.get_pending("inverted").unwrap().unwrap();
    let token = ApprovalToken {
        approval_id: pending.approval_id.clone(),
        approver: approver.public_key(),
        governed_token: GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: "inverted-token".into(),
                approver: approver.public_key(),
                subject: request.capability.subject.clone(),
                governed_intent_hash: pending.parameter_hash.clone(),
                request_id: pending.approval_id.clone(),
                threshold_proposal_hash: None,
                issued_at: 101,
                expires_at: 100,
                decision: GovernedApprovalDecision::Approved,
            },
            &approver,
        )
        .unwrap(),
    };
    for now in [99, 100, 101] {
        let result = token.verify_against(&pending, now);
        assert!(
            matches!(result, Err(KernelError::ApprovalRejected(ref reason)) if reason == "approval token validity window is inverted"),
            "{result:?}"
        );
    }
    assert!(!store
        .is_consumed("inverted-token", &pending.parameter_hash)
        .unwrap());
}

#[test]
fn invalid_deadlines_publish_neither_pending_request_nor_notification() {
    for (now, ttl, expected) in [
        (
            100,
            0,
            "approval request lifetime is outside the supported range",
        ),
        (
            100,
            3601,
            "approval request lifetime is outside the supported range",
        ),
        (u64::MAX, 1, "approval request expiry overflow"),
        (u64::MAX - 3599, 3600, "approval request expiry overflow"),
    ] {
        let store = StdArc::new(InMemoryApprovalStore::new());
        let recorder = StdArc::new(RecordingChannel::new());
        let guard = ApprovalGuard::new(store.clone())
            .with_channel(recorder.clone())
            .with_default_ttl(ttl);
        let request = hitl_make_request();
        let approver = CoreKeypair::generate();
        let result = guard.evaluate(
            ApprovalContext {
                request: &request,
                constraints: &[],
                policy_id: "policy-hitl",
                trusted_approvers: &[approver.public_key()],
                presented_token: None,
                force_approval: true,
                approval_id_override: Some("deadline-boundary".into()),
            },
            now,
        );
        assert!(
            matches!(result, Err(KernelError::ApprovalRejected(ref reason)) if reason == expected),
            "{result:?}"
        );
        assert!(store.get_pending("deadline-boundary").unwrap().is_none());
        assert_eq!(recorder.len(), 0);
    }
}

#[test]
fn largest_representable_approval_expiry_is_published_exactly() {
    let store = StdArc::new(InMemoryApprovalStore::new());
    let recorder = StdArc::new(RecordingChannel::new());
    let guard = ApprovalGuard::new(store.clone())
        .with_channel(recorder.clone())
        .with_default_ttl(3600);
    let request = hitl_make_request();
    let approver = CoreKeypair::generate();
    let verdict = guard
        .evaluate(
            ApprovalContext {
                request: &request,
                constraints: &[],
                policy_id: "policy-hitl",
                trusted_approvers: &[approver.public_key()],
                presented_token: None,
                force_approval: true,
                approval_id_override: Some("deadline-boundary".into()),
            },
            u64::MAX - 3600,
        )
        .unwrap();
    let HitlVerdict::Pending { request, .. } = verdict else {
        panic!("expected pending request");
    };
    assert_eq!(request.expires_at, u64::MAX);
    assert_eq!(request.created_at, u64::MAX - 3600);
    assert_eq!(
        store
            .get_pending("deadline-boundary")
            .unwrap()
            .unwrap()
            .expires_at,
        u64::MAX
    );
    assert_eq!(recorder.len(), 1);
}

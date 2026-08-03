#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::capability::governance::{GovernedApprovalDecision, GovernedApprovalTokenBody};
    use chio_core::capability::threshold_approval::{
        ThresholdApprovalProposal, ThresholdApprovalProposalBody, ThresholdApprovalRequirement,
    };
    use chio_core::crypto::Keypair;
    use std::collections::BTreeMap;

    fn operation_id(hex_pair: &str) -> String {
        hex_pair.repeat(32)
    }

    fn make_request(approval_id: &str, parameter_hash: &str) -> ApprovalRequest {
        let subject = Keypair::generate();
        let approver = Keypair::generate();
        ApprovalRequest {
            approval_id: approval_id.to_string(),
            policy_id: "policy-1".into(),
            subject_id: "agent-1".into(),
            capability_id: "cap-1".into(),
            subject_public_key: Some(subject.public_key()),
            tool_server: "srv".into(),
            tool_name: "invoke".into(),
            action: "invoke".into(),
            parameter_hash: parameter_hash.to_string(),
            expires_at: 1_000_000,
            callback_hint: None,
            created_at: 0,
            summary: String::new(),
            governed_intent: None,
            trusted_approvers: vec![approver.public_key()],
            triggered_by: vec![],
        }
    }

    fn make_token(
        approver: &Keypair,
        subject: &Keypair,
        approval_id: &str,
        parameter_hash: &str,
        decision: GovernedApprovalDecision,
    ) -> GovernedApprovalToken {
        let body = GovernedApprovalTokenBody {
            id: format!("tok-{approval_id}"),
            approver: approver.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: parameter_hash.to_string(),
            threshold_proposal_hash: None,
            request_id: approval_id.to_string(),
            issued_at: 10,
            expires_at: 100,
            decision,
        };
        GovernedApprovalToken::sign(body, approver).unwrap()
    }

    struct ThresholdCollectorFixture {
        policy_authority: Keypair,
        subject: Keypair,
        submitter: Keypair,
        approver_two: Keypair,
        approver_three: Keypair,
        eligible: BTreeMap<String, PublicKey>,
        requirement: ThresholdApprovalRequirement,
        policy_hash: String,
        intent_hash: String,
        proposal: ThresholdApprovalProposal,
    }

    impl ThresholdCollectorFixture {
        fn new() -> Self {
            let policy_authority = Keypair::generate();
            let subject = Keypair::generate();
            let submitter = Keypair::generate();
            let approver_two = Keypair::generate();
            let approver_three = Keypair::generate();
            let eligible = BTreeMap::from([
                ("submitter".to_string(), submitter.public_key()),
                ("approver-two".to_string(), approver_two.public_key()),
                ("approver-three".to_string(), approver_three.public_key()),
            ]);
            let policy_hash = "ab".repeat(32);
            let intent_hash = "cd".repeat(32);
            let requirement =
                ThresholdApprovalRequirement::new(2, eligible.clone(), 100, policy_hash.clone(), 1)
                    .unwrap();
            let body = ThresholdApprovalProposalBody::new(
                "proposal-collector",
                "request-collector",
                intent_hash.clone(),
                subject.public_key(),
                "ef".repeat(32),
                policy_hash.clone(),
                requirement.required(),
                requirement.eligible_set_digest(),
                100,
                requirement.proposal_timeout_seconds(),
                1_000,
                1_000,
            )
            .unwrap();
            let proposal = ThresholdApprovalProposal::sign(body, &policy_authority).unwrap();
            Self {
                policy_authority,
                subject,
                submitter,
                approver_two,
                approver_three,
                eligible,
                requirement,
                policy_hash,
                intent_hash,
                proposal,
            }
        }

        fn registration(&self) -> ThresholdApprovalProposalRegistration {
            let context = self.creation_context();
            ThresholdApprovalProposalRegistration::new(
                self.proposal.clone(),
                &context,
                &[self.policy_authority.public_key()],
                105,
            )
            .unwrap()
        }

        fn creation_context(&self) -> ThresholdApprovalProposalCreationContext {
            ThresholdApprovalProposalCreationContext::new(self.creation_parameters()).unwrap()
        }

        fn creation_parameters(&self) -> ThresholdApprovalProposalCreationParameters {
            ThresholdApprovalProposalCreationParameters {
                matched_request: ThresholdApprovalRequest::new(
                    self.proposal.body().request_id(),
                    "payments",
                    "transfer",
                )
                .unwrap(),
                requirement: self.requirement.clone(),
                subject: self.subject.public_key(),
                governed_intent_hash: self.intent_hash.clone(),
                authorization_capability_hash: "ef".repeat(32),
                authorizing_capability_expires_at: 1_000,
                governed_operation_expires_at: 1_000,
                submitter: Some(self.submitter.public_key()),
                separation_of_duties: true,
            }
        }

        fn token(&self, id: &str, approver: &Keypair, issued_at: u64) -> GovernedApprovalToken {
            GovernedApprovalToken::sign(
                GovernedApprovalTokenBody {
                    id: id.to_string(),
                    approver: approver.public_key(),
                    subject: self.subject.public_key(),
                    governed_intent_hash: self.intent_hash.clone(),
                    threshold_proposal_hash: Some(self.proposal.proposal_hash().unwrap()),
                    request_id: self.proposal.body().request_id().to_string(),
                    issued_at,
                    expires_at: 190,
                    decision: GovernedApprovalDecision::Approved,
                },
                approver,
            )
            .unwrap()
        }
    }

    #[test]
    fn threshold_collector_registration_rejects_untrusted_stale_and_future_proposals() {
        let fixture = ThresholdCollectorFixture::new();
        let untrusted = Keypair::generate();
        let context = fixture.creation_context();
        assert!(matches!(
            ThresholdApprovalProposalRegistration::new(
                fixture.proposal.clone(),
                &context,
                &[untrusted.public_key()],
                105,
            ),
            Err(ApprovalStoreError::Invalid(_))
        ));
        let stale_requirement =
            ThresholdApprovalRequirement::new(2, fixture.eligible.clone(), 100, "01".repeat(32), 2)
                .unwrap();
        let mut stale_parameters = fixture.creation_parameters();
        stale_parameters.requirement = stale_requirement;
        let stale_context =
            ThresholdApprovalProposalCreationContext::new(stale_parameters).unwrap();
        assert!(matches!(
            ThresholdApprovalProposalRegistration::new(
                fixture.proposal.clone(),
                &stale_context,
                &[fixture.policy_authority.public_key()],
                105,
            ),
            Err(ApprovalStoreError::Conflict(_))
        ));
        assert!(matches!(
            ThresholdApprovalProposalRegistration::new(
                fixture.proposal.clone(),
                &context,
                &[fixture.policy_authority.public_key()],
                99,
            ),
            Err(ApprovalStoreError::Invalid(_))
        ));
    }

    #[test]
    fn threshold_collector_registration_requires_exact_authenticated_deadline_bounds() {
        let fixture = ThresholdCollectorFixture::new();
        let sign_with_timeout = |proposal_id: &str, timeout: u64| {
            ThresholdApprovalProposal::sign(
                ThresholdApprovalProposalBody::new(
                    proposal_id,
                    "request-deadline",
                    fixture.intent_hash.clone(),
                    fixture.subject.public_key(),
                    "ef".repeat(32),
                    fixture.policy_hash.clone(),
                    fixture.requirement.required(),
                    fixture.requirement.eligible_set_digest(),
                    100,
                    timeout,
                    1_000,
                    1_000,
                )
                .unwrap(),
                &fixture.policy_authority,
            )
            .unwrap()
        };
        for proposal in [
            sign_with_timeout("proposal-short-deadline", 50),
            sign_with_timeout("proposal-long-deadline", 150),
        ] {
            let mut parameters = fixture.creation_parameters();
            parameters.matched_request =
                ThresholdApprovalRequest::new("request-deadline", "payments", "transfer").unwrap();
            assert!(matches!(
                ThresholdApprovalProposalRegistration::new(
                    proposal,
                    &ThresholdApprovalProposalCreationContext::new(parameters).unwrap(),
                    &[fixture.policy_authority.public_key()],
                    105,
                ),
                Err(ApprovalStoreError::Conflict(_))
            ));
        }

        let mut shortened_parameters = fixture.creation_parameters();
        shortened_parameters.authorizing_capability_expires_at = 150;
        let shortened_by_current_expiry =
            ThresholdApprovalProposalCreationContext::new(shortened_parameters).unwrap();
        assert!(matches!(
            ThresholdApprovalProposalRegistration::new(
                fixture.proposal.clone(),
                &shortened_by_current_expiry,
                &[fixture.policy_authority.public_key()],
                105,
            ),
            Err(ApprovalStoreError::Conflict(_))
        ));
        let mut missing_submitter = fixture.creation_parameters();
        missing_submitter.submitter = None;
        assert!(ThresholdApprovalProposalCreationContext::new(missing_submitter).is_err());
    }

    #[test]
    fn in_memory_threshold_collector_persists_status_before_returning_original_tokens() {
        let fixture = ThresholdCollectorFixture::new();
        let store = InMemoryApprovalStore::new();
        let created = store
            .create_threshold_approval_proposal(
                &fixture.registration(),
                &fixture.creation_context(),
                &[fixture.policy_authority.public_key()],
                105,
            )
            .unwrap();
        assert_eq!(
            created.status(),
            ThresholdApprovalCollectorStatus::Collecting
        );
        assert!(created.approval_tokens().is_empty());

        let submitter_vote = fixture.token("token-submitter", &fixture.submitter, 110);
        assert!(matches!(
            store.append_threshold_approval_vote(
                fixture.proposal.body().proposal_id(),
                &submitter_vote,
                &fixture.creation_context(),
                &[fixture.policy_authority.public_key()],
                111,
            ),
            Err(ApprovalStoreError::Invalid(_))
        ));

        let first = fixture.token("token-two", &fixture.approver_two, 112);
        let collecting = store
            .append_threshold_approval_vote(
                fixture.proposal.body().proposal_id(),
                &first,
                &fixture.creation_context(),
                &[fixture.policy_authority.public_key()],
                113,
            )
            .unwrap();
        assert_eq!(
            collecting.status(),
            ThresholdApprovalCollectorStatus::Collecting
        );

        let second = fixture.token("token-three", &fixture.approver_three, 114);
        let satisfied = store
            .append_threshold_approval_vote(
                fixture.proposal.body().proposal_id(),
                &second,
                &fixture.creation_context(),
                &[fixture.policy_authority.public_key()],
                115,
            )
            .unwrap();
        assert_eq!(
            satisfied.status(),
            ThresholdApprovalCollectorStatus::Satisfied
        );
        assert_eq!(
            satisfied.approval_tokens(),
            vec![first.clone(), second.clone()]
        );
        assert_eq!(satisfied.satisfied_at(), Some(115));

        let retry = store
            .append_threshold_approval_vote(
                fixture.proposal.body().proposal_id(),
                &second,
                &fixture.creation_context(),
                &[fixture.policy_authority.public_key()],
                116,
            )
            .unwrap();
        assert_eq!(retry, satisfied);
        let changed_token = fixture.token("token-two-again", &fixture.approver_two, 116);
        assert!(matches!(
            store.append_threshold_approval_vote(
                fixture.proposal.body().proposal_id(),
                &changed_token,
                &fixture.creation_context(),
                &[fixture.policy_authority.public_key()],
                117,
            ),
            Err(ApprovalStoreError::AlreadyResolved(_))
        ));

        let delivered = store
            .mark_threshold_approval_response_delivered(
                fixture.proposal.body().proposal_id(),
                &fixture.creation_context(),
                &[fixture.policy_authority.public_key()],
                118,
            )
            .unwrap();
        assert_eq!(
            delivered.status(),
            ThresholdApprovalCollectorStatus::Delivered
        );
        assert_eq!(delivered.delivered_at(), Some(118));
        assert_eq!(delivered.approval_tokens(), vec![first, second]);
        let reservation = store
            .reserve_approval_set(
                operation_id("0a").as_str(),
                &delivered.reservation_input().unwrap(),
            )
            .unwrap();
        assert_eq!(reservation.state(), ReplayReservationState::Reserved);
        let committed = store
            .commit_approval_reservation(operation_id("0a").as_str())
            .unwrap();
        assert_eq!(committed.state(), ReplayReservationState::Committed);
        assert_eq!(
            store
                .get_threshold_approval_proposal(
                    fixture.proposal.body().proposal_id(),
                    &fixture.creation_context(),
                    &[fixture.policy_authority.public_key()],
                    300,
                )
                .unwrap(),
            Some(delivered)
        );
    }

    #[test]
    fn resume_flow_approved() {
        let store = InMemoryApprovalStore::new();
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let mut req = make_request("a-1", "h-1");
        req.subject_public_key = Some(subject.public_key());
        req.trusted_approvers = vec![approver.public_key()];
        store.store_pending(&req).unwrap();

        let token = make_token(
            &approver,
            &subject,
            "a-1",
            "h-1",
            GovernedApprovalDecision::Approved,
        );
        let decision = ApprovalDecision {
            approval_id: "a-1".into(),
            outcome: ApprovalOutcome::Approved,
            reason: None,
            approver: approver.public_key(),
            token,
            received_at: 50,
        };

        let outcome = resume_with_decision(&store, &decision, 50).unwrap();
        assert_eq!(outcome, ApprovalOutcome::Approved);
        assert_eq!(store.count_approved("agent-1", "policy-1").unwrap(), 1);
    }

    #[test]
    fn resume_flow_replay_rejected() {
        let store = InMemoryApprovalStore::new();
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let mut req = make_request("a-2", "h-2");
        req.subject_public_key = Some(subject.public_key());
        req.trusted_approvers = vec![approver.public_key()];
        store.store_pending(&req).unwrap();

        let token = make_token(
            &approver,
            &subject,
            "a-2",
            "h-2",
            GovernedApprovalDecision::Approved,
        );
        let decision = ApprovalDecision {
            approval_id: "a-2".into(),
            outcome: ApprovalOutcome::Approved,
            reason: None,
            approver: approver.public_key(),
            token,
            received_at: 50,
        };

        // First resolution succeeds.
        resume_with_decision(&store, &decision, 50).unwrap();
        // Second resolution must fail (replay).
        let err = resume_with_decision(&store, &decision, 51).unwrap_err();
        match err {
            KernelError::ApprovalRejected(_) => {}
            other => panic!("expected ApprovalRejected, got {other:?}"),
        }
    }

    #[test]
    fn resume_flow_duplicate_resolution_reports_already_resolved() {
        let store = InMemoryApprovalStore::new();
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let mut req = make_request("a-2b", "h-2b");
        req.subject_public_key = Some(subject.public_key());
        req.trusted_approvers = vec![approver.public_key()];
        store.store_pending(&req).unwrap();

        let token = make_token(
            &approver,
            &subject,
            "a-2b",
            "h-2b",
            GovernedApprovalDecision::Approved,
        );
        let decision = ApprovalDecision {
            approval_id: "a-2b".into(),
            outcome: ApprovalOutcome::Approved,
            reason: None,
            approver: approver.public_key(),
            token,
            received_at: 50,
        };

        resume_with_decision(&store, &decision, 50).unwrap();
        let err = resume_with_decision(&store, &decision, 51).unwrap_err();
        match err {
            KernelError::ApprovalRejected(reason) => {
                assert!(reason.contains("already resolved"), "{reason}");
            }
            other => panic!("expected ApprovalRejected, got {other:?}"),
        }
    }

    #[test]
    fn verify_against_rejects_wrong_request_id() {
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let token = make_token(
            &approver,
            &subject,
            "a-X",
            "h-X",
            GovernedApprovalDecision::Approved,
        );
        let req = make_request("a-other", "h-X");
        let approval_token = ApprovalToken {
            approval_id: "a-X".into(),
            governed_token: token,
            approver: approver.public_key(),
        };
        let err = approval_token.verify_against(&req, 50).unwrap_err();
        match err {
            KernelError::ApprovalRejected(_) => {}
            other => panic!("expected ApprovalRejected, got {other:?}"),
        }
    }

    #[test]
    fn verify_against_rejects_untrusted_approver() {
        let trusted_approver = Keypair::generate();
        let rogue_approver = Keypair::generate();
        let subject = Keypair::generate();
        let token = make_token(
            &rogue_approver,
            &subject,
            "a-1",
            "h-1",
            GovernedApprovalDecision::Approved,
        );
        let req = ApprovalRequest {
            approval_id: "a-1".into(),
            policy_id: "policy-1".into(),
            subject_id: "agent-1".into(),
            capability_id: "cap-1".into(),
            subject_public_key: Some(subject.public_key()),
            tool_server: "srv".into(),
            tool_name: "invoke".into(),
            action: "invoke".into(),
            parameter_hash: "h-1".into(),
            expires_at: 1_000_000,
            callback_hint: None,
            created_at: 0,
            summary: String::new(),
            governed_intent: None,
            trusted_approvers: vec![trusted_approver.public_key()],
            triggered_by: vec![],
        };
        let approval_token = ApprovalToken {
            approval_id: "a-1".into(),
            governed_token: token,
            approver: rogue_approver.public_key(),
        };
        let err = approval_token.verify_against(&req, 50).unwrap_err();
        match err {
            KernelError::ApprovalRejected(reason) => {
                assert!(reason.contains("not trusted"), "{reason}");
            }
            other => panic!("expected ApprovalRejected, got {other:?}"),
        }
    }

    #[test]
    fn verify_against_rejects_subject_mismatch() {
        let approver = Keypair::generate();
        let expected_subject = Keypair::generate();
        let rogue_subject = Keypair::generate();
        let token = make_token(
            &approver,
            &rogue_subject,
            "a-1",
            "h-1",
            GovernedApprovalDecision::Approved,
        );
        let req = ApprovalRequest {
            approval_id: "a-1".into(),
            policy_id: "policy-1".into(),
            subject_id: "agent-1".into(),
            capability_id: "cap-1".into(),
            subject_public_key: Some(expected_subject.public_key()),
            tool_server: "srv".into(),
            tool_name: "invoke".into(),
            action: "invoke".into(),
            parameter_hash: "h-1".into(),
            expires_at: 1_000_000,
            callback_hint: None,
            created_at: 0,
            summary: String::new(),
            governed_intent: None,
            trusted_approvers: vec![approver.public_key()],
            triggered_by: vec![],
        };
        let approval_token = ApprovalToken {
            approval_id: "a-1".into(),
            governed_token: token,
            approver: approver.public_key(),
        };
        let err = approval_token.verify_against(&req, 50).unwrap_err();
        match err {
            KernelError::ApprovalRejected(reason) => {
                assert!(reason.contains("subject"), "{reason}");
            }
            other => panic!("expected ApprovalRejected, got {other:?}"),
        }
    }

    #[test]
    fn approval_reservation_requires_a_bounded_proposal_deadline() {
        let member =
            ApprovalReservationMember::new("token-deadline".to_string(), "11".repeat(32)).unwrap();
        let input = ApprovalSetReservationInput::new("aa".repeat(32), vec![member.clone()], 10_000)
            .unwrap();
        assert_eq!(input.proposal_deadline(), 10_000);
        assert!(ApprovalReservation::new("not-a-digest".to_string(), input).is_err());
        assert!(ApprovalSetReservationInput::new("bb".repeat(32), vec![member], 0).is_err());
    }

    #[test]
    fn in_memory_approval_reservations_are_normalized_owned_and_terminal() {
        let store = InMemoryApprovalStore::new();
        let first_digest = "11".repeat(32);
        let second_digest = "22".repeat(32);
        let approval_set = ApprovalSetReservationInput::new(
            "aa".repeat(32),
            vec![
                ApprovalReservationMember::new("token-2".to_string(), second_digest.clone())
                    .unwrap(),
                ApprovalReservationMember::new("token-1".to_string(), first_digest.clone())
                    .unwrap(),
            ],
            10_000,
        )
        .unwrap();
        let reserved = store
            .reserve_approval_set(operation_id("01").as_str(), &approval_set)
            .unwrap();
        assert_eq!(reserved.operation_id(), operation_id("01").as_str());
        assert_eq!(
            reserved
                .approval_set()
                .members()
                .iter()
                .map(ApprovalReservationMember::token_id)
                .collect::<Vec<_>>(),
            vec!["token-1", "token-2"]
        );
        assert_eq!(reserved.approval_set().approval_set_hash(), "aa".repeat(32));
        assert_eq!(reserved.state(), ReplayReservationState::Reserved);
        for state in [
            ReplayReservationState::Reserved,
            ReplayReservationState::Committed,
            ReplayReservationState::Cancelled,
        ] {
            assert_eq!(ReplayReservationState::parse(state.as_str()), Some(state));
        }
        assert_eq!(ReplayReservationState::parse("unknown"), None);
        let deserialized_invalid_set =
            serde_json::from_value::<ApprovalSetReservationInput>(serde_json::json!({
                "approval_set_hash": "ff".repeat(32),
                "members": [],
                "proposal_deadline": 10_000
            }))
            .unwrap();
        assert!(matches!(
            store.reserve_approval_set(operation_id("09").as_str(), &deserialized_invalid_set),
            Err(ApprovalStoreError::Invalid(_))
        ));
        assert!(matches!(
            ApprovalSetReservationInput::new(
                "bb".repeat(32),
                vec![
                    ApprovalReservationMember::new("duplicate-1".to_string(), first_digest.clone())
                        .unwrap(),
                    ApprovalReservationMember::new("duplicate-2".to_string(), first_digest.clone())
                        .unwrap(),
                ],
                10_000
            ),
            Err(ApprovalStoreError::Invalid(_))
        ));
        assert_eq!(
            store
                .reserve_approval_set(operation_id("01").as_str(), &approval_set)
                .unwrap(),
            reserved
        );
        let overlapping_set = ApprovalSetReservationInput::new(
            "bb".repeat(32),
            vec![
                ApprovalReservationMember::new("token-1".to_string(), first_digest.clone())
                    .unwrap(),
            ],
            10_000,
        )
        .unwrap();
        assert!(matches!(
            store.reserve_approval_set(operation_id("02").as_str(), &overlapping_set),
            Err(ApprovalStoreError::Replay(_))
        ));
        let duplicate_hash_set = ApprovalSetReservationInput::new(
            "aa".repeat(32),
            vec![
                ApprovalReservationMember::new("token-hash".to_string(), "55".repeat(32)).unwrap(),
            ],
            10_000,
        )
        .unwrap();
        assert!(matches!(
            store.reserve_approval_set(operation_id("05").as_str(), &duplicate_hash_set),
            Err(ApprovalStoreError::Replay(_))
        ));
        assert!(matches!(
            store.record_consumed("token-1", "parameter-hash", 1),
            Err(ApprovalStoreError::Replay(_))
        ));
        assert!(store.is_consumed("token-1", "parameter-hash").unwrap());

        let committed = store
            .commit_approval_reservation(operation_id("01").as_str())
            .unwrap();
        assert_eq!(committed.state(), ReplayReservationState::Committed);
        assert_eq!(
            store
                .commit_approval_reservation(operation_id("01").as_str())
                .unwrap(),
            committed
        );
        assert!(matches!(
            store.cancel_approval_reservation(operation_id("01").as_str()),
            Err(ApprovalStoreError::Replay(_))
        ));

        let cancellation_set = ApprovalSetReservationInput::new(
            "cc".repeat(32),
            vec![ApprovalReservationMember::new("token-3".to_string(), "33".repeat(32)).unwrap()],
            10_000,
        )
        .unwrap();
        let cancelled = store
            .reserve_approval_set(operation_id("03").as_str(), &cancellation_set)
            .and_then(|_| store.cancel_approval_reservation(operation_id("03").as_str()))
            .unwrap();
        assert_eq!(cancelled.state(), ReplayReservationState::Cancelled);
        assert_eq!(
            store
                .cancel_approval_reservation(operation_id("03").as_str())
                .unwrap(),
            cancelled
        );
        assert_eq!(
            store
                .get_approval_reservation(operation_id("03").as_str())
                .unwrap(),
            Some(cancelled)
        );
        assert!(matches!(
            store.reserve_approval_set(operation_id("04").as_str(), &cancellation_set),
            Err(ApprovalStoreError::Replay(_))
        ));

        store
            .record_consumed("legacy-token", "legacy-parameter", 2)
            .unwrap();
        assert!(matches!(
            store.record_consumed("legacy-token", "different-parameter", 3),
            Err(ApprovalStoreError::Replay(_))
        ));
        assert!(store
            .is_consumed("legacy-token", "different-parameter")
            .unwrap());
        let legacy_consumed_set = ApprovalSetReservationInput::new(
            "dd".repeat(32),
            vec![
                ApprovalReservationMember::new("legacy-token".to_string(), "44".repeat(32))
                    .unwrap(),
            ],
            10_000,
        )
        .unwrap();
        assert!(matches!(
            store.reserve_approval_set(operation_id("06").as_str(), &legacy_consumed_set),
            Err(ApprovalStoreError::Replay(_))
        ));
    }
}

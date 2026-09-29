use super::*;

#[test]
fn cumulative_approval_membership_does_not_change_operation_identity() {
    let (kernel, mut request, _store, _invocations) =
        durable_admission_fixture("cumulative-stable-operation");
    let mut body = request.capability.body();
    body.scope.grants[0]
        .constraints
        .push(Constraint::RequireCumulativeApprovalAbove {
            threshold: MonetaryAmount {
                units: 100,
                currency: "USD".to_owned(),
            },
            approval_budget_id: "budget-identity".to_owned(),
            approval_budget_epoch: 1,
            cumulative_approval_root_binding: None,
        });
    request.capability = CapabilityToken::sign(body, &kernel.config.keypair)
        .expect("cumulative capability must sign");
    let first = {
        let matching = [MatchingGrant {
            index: 0,
            grant: &request.capability.scope.grants[0],
            specificity: (0, 0, 0),
        }];
        kernel
            .begin_durable_tool_admission(&request, &matching, current_unix_timestamp_ms())
            .expect("prepare cumulative operation")
            .expect("cumulative admission must be durable")
    };

    let first_operation_id = first.operation_id().to_owned();
    drop(first);
    let approver = CoreKeypair::generate();
    let subject = CoreKeypair::generate();
    request.approval_tokens.push(hitl_sign_token(
        &approver,
        &subject,
        "cumulative-stable-operation",
        &sha256_hex(b"cumulative-stable-intent"),
        GovernedApprovalDecision::Approved,
        current_unix_timestamp(),
    ));
    let resumed = {
        let matching = [MatchingGrant {
            index: 0,
            grant: &request.capability.scope.grants[0],
            specificity: (0, 0, 0),
        }];
        kernel
            .begin_durable_tool_admission(&request, &matching, current_unix_timestamp_ms())
            .expect("resume cumulative operation")
            .expect("cumulative admission must remain durable")
    };

    assert_eq!(first_operation_id, resumed.operation_id());
}

#[test]
fn cumulative_approval_resumes_the_same_hold_and_dispatches_once() {
    let (mut kernel, mut request, store, invocations) =
        durable_admission_fixture("cumulative-approval-dispatch");
    let approver_a = CoreKeypair::generate();
    let approver_b = CoreKeypair::generate();
    let requirement = ThresholdApprovalRequirement::new(
        kernel.config.policy_hash.clone(),
        2,
        vec![
            ThresholdApproverIdentity {
                identifier: "approver-a".to_owned(),
                public_key: approver_a.public_key(),
            },
            ThresholdApproverIdentity {
                identifier: "approver-b".to_owned(),
                public_key: approver_b.public_key(),
            },
        ],
        "cumulative-approval-directory-v1".to_owned(),
        300,
    )
    .expect("threshold requirement");
    kernel.set_threshold_approval_requirement_resolver(StdArc::new(FixedThresholdRequirement(
        requirement,
    )));
    let mut body = request.capability.body();
    body.scope.grants[0]
        .constraints
        .push(Constraint::RequireCumulativeApprovalAbove {
            threshold: MonetaryAmount {
                units: 100,
                currency: "USD".to_owned(),
            },
            approval_budget_id: "budget-dispatch".to_owned(),
            approval_budget_epoch: 7,
            cumulative_approval_root_binding: None,
        });
    request.capability = CapabilityToken::sign(body, &kernel.config.keypair)
        .expect("cumulative capability must sign");
    let intent = GovernedTransactionIntent {
        id: "cumulative-approval-intent".to_owned(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "authorize a bounded ledger mutation".to_owned(),
        max_amount: Some(MonetaryAmount {
            units: 100,
            currency: "USD".to_owned(),
        }),
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    };
    let intent_hash = intent.binding_hash().expect("intent hash");
    request.governed_intent = Some(intent);

    let pending = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("pending approval response");
    assert_eq!(
        pending.verdict,
        Verdict::PendingApproval,
        "{:?}",
        pending.reason
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let proposal: ThresholdApprovalProposal = match pending.output {
        Some(ToolCallOutput::Value(value)) => {
            serde_json::from_value(value).expect("stored threshold proposal")
        }
        _ => panic!("pending response must return the stored proposal"),
    };
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::ApprovalRequired
    );
    let operation_id = store
        .operation()
        .binding()
        .operation_id()
        .as_str()
        .to_owned();
    let proposal_hash = proposal.artifact_digest().expect("proposal digest");
    let sign_token = |id: &str, approver: &CoreKeypair| {
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: id.to_owned(),
                approver: approver.public_key(),
                subject: request.capability.subject.clone(),
                governed_intent_hash: intent_hash.clone(),
                request_id: request.request_id.clone(),
                threshold_proposal_hash: Some(proposal_hash.clone()),
                issued_at: proposal.body.proposal_created_at,
                expires_at: proposal.body.proposal_deadline,
                decision: GovernedApprovalDecision::Approved,
            },
            approver,
        )
        .expect("approval token")
    };
    let approval_tokens = vec![
        sign_token("cumulative-token-b", &approver_b),
        sign_token("cumulative-token-a", &approver_a),
    ];
    let mut approved = request.clone();
    approved.threshold_approval_proposal = Some(proposal);
    approved.approval_tokens = approval_tokens;

    let response = kernel
        .evaluate_tool_call_blocking(&approved)
        .expect("approved cumulative dispatch");
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.operation().binding().operation_id().as_str(),
        operation_id
    );
    let usage = crate::budget_store::BudgetStore::get_cumulative_approval_operation_usage(
        store.budget_store().as_ref(),
        &operation_id,
    )
    .expect("cumulative operation lookup")
    .expect("captured cumulative operation");
    assert_eq!(
        usage.state,
        crate::budget_store::BudgetCumulativeApprovalState::Captured
    );

    let replay = kernel
        .evaluate_tool_call_blocking(&approved)
        .expect("completed cumulative replay");
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn cumulative_approval_below_threshold_dispatches_without_a_proposal() {
    let (kernel, mut request, store, invocations) =
        durable_admission_fixture("cumulative-below-threshold");
    let mut body = request.capability.body();
    body.scope.grants[0]
        .constraints
        .push(Constraint::RequireCumulativeApprovalAbove {
            threshold: MonetaryAmount {
                units: 100,
                currency: "USD".to_owned(),
            },
            approval_budget_id: "budget-below-threshold".to_owned(),
            approval_budget_epoch: 1,
            cumulative_approval_root_binding: None,
        });
    request.capability = CapabilityToken::sign(body, &kernel.config.keypair)
        .expect("cumulative capability must sign");
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "cumulative-below-threshold-intent".to_owned(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "authorize a bounded ledger mutation".to_owned(),
        max_amount: Some(MonetaryAmount {
            units: 60,
            currency: "USD".to_owned(),
        }),
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    });

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("below-threshold cumulative dispatch");
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert!(store.operation().threshold_proposal().is_none());
}

#[test]
fn cumulative_approval_guard_denial_creates_no_budget_state() {
    struct DenyAll;

    impl Guard for DenyAll {
        fn name(&self) -> &str {
            "cumulative-deny-all"
        }

        fn evaluate(&self, _context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
            Ok(GuardDecision::deny(Vec::new()))
        }
    }

    let (mut kernel, mut request, store, invocations) =
        durable_admission_fixture("cumulative-guard-denial");
    let mut body = request.capability.body();
    body.scope.grants[0]
        .constraints
        .push(Constraint::RequireCumulativeApprovalAbove {
            threshold: MonetaryAmount {
                units: 100,
                currency: "USD".to_owned(),
            },
            approval_budget_id: "budget-guard-denial".to_owned(),
            approval_budget_epoch: 1,
            cumulative_approval_root_binding: None,
        });
    request.capability = CapabilityToken::sign(body, &kernel.config.keypair)
        .expect("cumulative capability must sign");
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "cumulative-guard-denial-intent".to_owned(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "authorize a bounded ledger mutation".to_owned(),
        max_amount: Some(MonetaryAmount {
            units: 60,
            currency: "USD".to_owned(),
        }),
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    });
    kernel.add_guard(Box::new(DenyAll));

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("guard denial must produce a signed response");
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let operation = store.operation();
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(
        crate::budget_store::BudgetStore::get_cumulative_approval_operation_usage(
            store.budget_store().as_ref(),
            operation.binding().operation_id().as_str(),
        )
        .expect("cumulative operation lookup")
        .is_none()
    );
}

#[test]
fn nested_cumulative_approval_resumes_and_dispatches_once() {
    let (mut kernel, mut request, _store, invocations) =
        durable_admission_fixture("nested-cumulative-approval");
    let approver = CoreKeypair::generate();
    let requirement = ThresholdApprovalRequirement::new(
        kernel.config.policy_hash.clone(),
        1,
        vec![ThresholdApproverIdentity {
            identifier: "nested-approver".to_owned(),
            public_key: approver.public_key(),
        }],
        "nested-cumulative-directory-v1".to_owned(),
        300,
    )
    .expect("threshold requirement");
    kernel.set_threshold_approval_requirement_resolver(StdArc::new(FixedThresholdRequirement(
        requirement,
    )));
    let mut body = request.capability.body();
    body.scope.grants[0]
        .constraints
        .push(Constraint::RequireCumulativeApprovalAbove {
            threshold: MonetaryAmount {
                units: 25,
                currency: "USD".to_owned(),
            },
            approval_budget_id: "nested-cumulative-budget".to_owned(),
            approval_budget_epoch: 1,
            cumulative_approval_root_binding: None,
        });
    request.capability = CapabilityToken::sign(body, &kernel.config.keypair)
        .expect("cumulative capability must sign");
    let intent = GovernedTransactionIntent {
        id: "nested-cumulative-intent".to_owned(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "authorize nested ledger mutation".to_owned(),
        max_amount: Some(MonetaryAmount {
            units: 25,
            currency: "USD".to_owned(),
        }),
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    };
    let intent_hash = intent.binding_hash().expect("intent hash");
    request.governed_intent = Some(intent);
    let session_id = kernel
        .open_session("nested-cumulative-parent".to_owned(), Vec::new())
        .expect("parent session");
    kernel
        .activate_session(&session_id)
        .expect("activate parent session");
    let parent_context = make_operation_context(
        &session_id,
        "nested-cumulative-parent-request",
        "nested-cumulative-parent",
    );
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .expect("begin parent request");
    let mut client = NoopNestedFlowClient;

    let pending = kernel
        .evaluate_tool_call_with_nested_flow_client(&parent_context, &request, &mut client, None)
        .expect("nested pending response");
    assert_eq!(
        pending.verdict,
        Verdict::PendingApproval,
        "{:?}",
        pending.reason
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let proposal: ThresholdApprovalProposal = match pending.output {
        Some(ToolCallOutput::Value(value)) => {
            serde_json::from_value(value).expect("stored nested proposal")
        }
        _ => panic!("nested pending response must return its proposal"),
    };
    let proposal_hash = proposal.artifact_digest().expect("proposal digest");
    let token = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "nested-cumulative-token".to_owned(),
            approver: approver.public_key(),
            subject: request.capability.subject.clone(),
            governed_intent_hash: intent_hash,
            request_id: request.request_id.clone(),
            threshold_proposal_hash: Some(proposal_hash),
            issued_at: proposal.body.proposal_created_at,
            expires_at: proposal.body.proposal_deadline,
            decision: GovernedApprovalDecision::Approved,
        },
        &approver,
    )
    .expect("nested approval token");
    request.threshold_approval_proposal = Some(proposal);
    request.approval_tokens = vec![token];

    let response = kernel
        .evaluate_tool_call_with_nested_flow_client(&parent_context, &request, &mut client, None)
        .expect("nested approved response");
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn aggregate_invocation_budget_exhausts_across_grants_atomically() {
    use chio_core::capability::aggregate_invocation::{
        AggregateInvocationBudget, AggregateInvocationScope,
    };

    let mut first_grant = make_grant("durable-server", "mutate");
    first_grant.max_invocations = Some(1);
    let mut second_grant = make_grant("durable-server", "mutate-alt");
    second_grant.max_invocations = Some(1);
    let (kernel, mut first, store, invocations) =
        durable_admission_fixture_with_grants("aggregate-first", vec![first_grant, second_grant]);
    let mut body = first.capability.body();
    body.aggregate_invocation_budget = Some(AggregateInvocationBudget {
        scope: AggregateInvocationScope::Capability,
        max_invocations: 1,
        root_binding: None,
    });
    first.capability = CapabilityToken::sign(body, &kernel.config.keypair)
        .expect("aggregate capability must sign");

    let first_response = kernel
        .evaluate_tool_call_blocking(&first)
        .expect("first aggregate invocation");
    assert_eq!(
        first_response.verdict,
        Verdict::Allow,
        "{:?}",
        first_response.reason
    );

    let mut second = first.clone();
    second.request_id = "aggregate-second".to_string();
    second.tool_name = "mutate-alt".to_string();
    let second_response = kernel
        .evaluate_tool_call_blocking(&second)
        .expect("aggregate exhaustion must produce a signed denial");
    assert_eq!(second_response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let second_grant_usage = store
        .budget_store()
        .get_invocation_quota_usage(&crate::budget_store::BudgetQuotaKey::grant(
            first.capability.id.clone(),
            1,
        ))
        .expect("second grant quota lookup");
    assert!(second_grant_usage.is_none());
}

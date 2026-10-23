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
fn cumulative_approval_resumes_the_same_hold_and_dispatches_once(
) -> Result<(), Box<dyn std::error::Error>> {
    exercise_cumulative_approval(false)
}

#[test]
fn cumulative_approval_cleanup_remains_owned_by_original_durable_admission(
) -> Result<(), Box<dyn std::error::Error>> {
    exercise_cumulative_approval(true)
}

fn exercise_cumulative_approval(
    compensate_before_dispatch: bool,
) -> Result<(), Box<dyn std::error::Error>> {
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
    let mut intent = GovernedTransactionIntent {
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
    crate::approval::ToolApprovalContext::bind(
        &mut intent,
        &request.capability,
        &request.arguments,
        &request.request_id,
        kernel.policy_hash(),
        "cumulative-approval-test",
    )?;
    let intent_hash = intent.binding_hash()?;
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
    assert!(pending.receipt.verify_integrity_embedded_key()?);
    assert_eq!(
        pending
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.pointer("/chio_runtime/identity_disposition")),
        None,
        "approval-required is not a terminal refusal",
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

    if compensate_before_dispatch {
        let matching = resolve_required_matching_grants(
            &approved.capability,
            &approved.tool_name,
            &approved.server_id,
            &approved.arguments,
            approved.model_metadata.as_ref(),
        )?;
        let now = current_unix_timestamp_ms();
        let mut admission = kernel
            .begin_durable_tool_admission(&approved, &matching, now)?
            .expect("original cumulative admission");
        let (_, mutation) = kernel
            .check_and_increment_budget(
                &approved,
                &approved.capability,
                &matching,
                false,
                Some(&mut admission),
                now,
            )?
            .into_authorized()?;
        let charge = mutation
            .durable_hold_result()
            .expect("approved cumulative hold");
        assert_eq!(
            charge.cleanup_custody,
            crate::budget_store::BudgetHoldCleanupCustody::Unknown
        );
        let refusal = format!(
            "budget hold cleanup requires fresh custody; current call custody is {}",
            charge.cleanup_custody.as_str()
        );
        assert!(matches!(
            kernel.reverse_budget_charge(&approved.capability.id, charge),
            Err(KernelError::BudgetStore(
                crate::budget_store::BudgetStoreError::Invariant(reason)
            )) if reason == refusal
        ));
        assert_eq!(
            admission.operation().state(),
            AdmissionOperationState::BudgetAuthorized
        );
        kernel.compensate_durable_admission_before_dispatch(
            admission.operation(),
            serde_json::json!({"authority": "original-cumulative-admission-owner"}),
            now + 1,
            None,
            compensation_response(),
        )?;
        assert_eq!(
            store.operation().state(),
            AdmissionOperationState::CompensatedBeforeDispatch
        );
        let budget = store.budget_store();
        assert_eq!(
            budget
                .get_budget_hold(&charge.budget_hold_id)?
                .expect("owned hold")
                .disposition,
            crate::budget_store::BudgetHoldDispositionView::Reversed
        );
        let usage = budget
            .get_cumulative_approval_operation_usage(&operation_id)?
            .expect("released cumulative operation");
        assert_eq!(
            usage.state,
            crate::budget_store::BudgetCumulativeApprovalState::ReversedBeforeDispatch
        );
        assert_eq!(usage.reserved_authorized_after.units, 0);
        assert_eq!(usage.captured_authorized_after.units, 0);
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        return Ok(());
    }

    let response = kernel
        .evaluate_tool_call_blocking(&approved)
        .expect("approved cumulative dispatch");
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
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
    Ok(())
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
fn nested_cumulative_approval_resumes_and_dispatches_once() -> Result<(), Box<dyn std::error::Error>>
{
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
    let mut intent = GovernedTransactionIntent {
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
    crate::approval::ToolApprovalContext::bind(
        &mut intent,
        &request.capability,
        &request.arguments,
        &request.request_id,
        kernel.policy_hash(),
        "nested-cumulative-approval-test",
    )?;
    let intent_hash = intent.binding_hash()?;
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
    Ok(())
}

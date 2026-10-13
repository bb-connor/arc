use super::payment_custody::Harness;
use super::*;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedTransactionIntent, MeteredBillingContext, MeteredBillingQuote, MeteredSettlementMode,
};
use chio_core::capability::scope::{ChioScope, Constraint, MonetaryAmount, Operation, ToolGrant};
use chio_core::crypto::sha256_hex;
use chio_kernel::admission_operation::governed_approval_claim::GovernedApprovalAuthorityBindingV1;
use chio_kernel::admission_operation::AdmissionDigest;
use chio_kernel::dpop::authority::{
    DpopReplayAuthorityInputV1, DpopReplayAuthorityV1, DPOP_AUTHORITY_SCHEMA,
};
use chio_kernel::dpop::replay_source::{DpopReplaySourceBinding, DpopReplaySourcePort};
use chio_kernel::dpop::{DpopNonceStore, DpopProof, DpopProofBody};
use chio_kernel::payment::PaymentJournalState;
use chio_kernel::CallerStartCredentials;
use chio_store_sqlite::{SqliteGovernedApprovalReplaySource, SqliteGovernedApprovalReplayStore};
use std::sync::Arc;

const TENANT: &str = "prepaid-credential-custody";

fn authority_time() -> TestResult<u64> {
    Ok(chio_test_support::clock::clock().unix_millis()?.get())
}

fn prepaid_request(
    harness: &Harness,
    runtime: &Runtime,
    dpop: bool,
) -> TestResult<ToolCallRequest> {
    let mut request = harness
        .fixture
        .request(runtime, "prepaid-credential-custody")?;
    let mut constraints = vec![Constraint::GovernedIntentRequired];
    if !dpop {
        constraints.push(Constraint::RequireApprovalAbove {
            threshold_units: 50,
        });
    }
    let amount = MonetaryAmount {
        units: 100,
        currency: "USD".into(),
    };
    request.capability = runtime.kernel.issue_capability(
        &harness.fixture.agent.public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: SERVER_ID.into(),
                tool_name: TOOL_NAME.into(),
                operations: vec![Operation::Invoke],
                constraints,
                max_invocations: Some(1),
                dpop_required: dpop.then_some(true),
                max_cost_per_invocation: Some(amount.clone()),
                max_total_cost: Some(amount.clone()),
            }],
            ..Default::default()
        },
        600,
    )?;
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "prepaid-credential-intent".into(),
        server_id: SERVER_ID.into(),
        tool_name: TOOL_NAME.into(),
        purpose: "prepaid invocation".into(),
        max_amount: Some(amount.clone()),
        commerce: None,
        metered_billing: Some(MeteredBillingContext {
            settlement_mode: MeteredSettlementMode::MustPrepay,
            quote: MeteredBillingQuote {
                quote_id: "prepaid-credential-quote".into(),
                provider: "prepaid-credential-provider".into(),
                billing_unit: "invocation".into(),
                quoted_units: 1,
                quoted_cost: amount,
                issued_at: request.capability.issued_at,
                expires_at: Some(request.capability.expires_at),
            },
            max_billed_units: Some(1),
            verified_outcome: None,
        }),
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    });
    Ok(request)
}

fn configure_dpop(runtime: &mut Runtime) -> TestResult<DpopReplayAuthorityV1> {
    let source = DpopNonceStore::new(8, Duration::from_secs(3600))?;
    let authority_id = AdmissionIdentifier::try_new("authority_id", "prepaid-dpop-authority")?;
    let fence = runtime.authority.mutation_fence();
    let snapshot = source.preview_unsealed(&DpopReplaySourceBinding {
        dpop_authority_id: authority_id.clone(),
        destination_authority_id: AdmissionIdentifier::try_new("destination", &fence.store_uuid)?,
    })?;
    let store = runtime.authority.admission_operation_store();
    let now = authority_time()?;
    let pinned = store.expect_dpop_replay_source(
        &AdmissionIdentifier::try_new("instance", snapshot.instance_id())?,
        &authority_id,
        &source,
        &fence,
        now,
    )?;
    let imported = store.import_dpop_replay_source(
        &authority_id,
        pinned.expectation_id(),
        &source,
        &fence,
        now,
    )?;
    let domain = DpopReplayAuthorityV1::new(DpopReplayAuthorityInputV1 {
        destination_store_uuid: AdmissionIdentifier::try_new("destination", &fence.store_uuid)?,
        dpop_authority_id: authority_id,
        expectation_id: AdmissionDigest::try_new(
            "expectation",
            imported.expectation_id().as_str(),
        )?,
        proof_ttl_secs: 300,
        max_clock_skew_secs: 30,
    })?;
    assert!(store
        .activate_dpop_replay_source(&domain, &source, &fence, now)?
        .is_active());
    Arc::get_mut(&mut runtime.kernel)
        .ok_or("exclusive kernel")?
        .set_operation_owned_dpop_authority(domain.clone())?;
    Ok(domain)
}

fn configure_approval(harness: &Harness, runtime: &mut Runtime) -> TestResult {
    let path = harness
        .fixture
        .directory
        .path()
        .join("prepaid-approval-source.db");
    drop(SqliteGovernedApprovalReplayStore::open_with_clock(
        &path,
        8,
        chio_test_support::clock::clock(),
    )?);
    let source = Arc::new(SqliteGovernedApprovalReplaySource::open_with_clock(
        &path,
        chio_test_support::clock::clock(),
    )?);
    let authority_id = AdmissionIdentifier::try_new("authority_id", "prepaid-approval-authority")?;
    let fence = runtime.authority.mutation_fence();
    let store = runtime.authority.admission_operation_store();
    let now = authority_time()?;
    let pinned = store.expect_governed_approval_replay_source(
        &AdmissionIdentifier::try_new("source_id", "prepaid-approval-source")?,
        &authority_id,
        source.as_ref(),
        &fence,
        now,
    )?;
    let imported = store.import_governed_approval_replay_source(
        &authority_id,
        pinned.expectation_id(),
        source.as_ref(),
        &fence,
        now,
    )?;
    let binding =
        GovernedApprovalAuthorityBindingV1::new(authority_id, imported.expectation_id().clone());
    assert!(store
        .activate_governed_approval_replay_source(&binding, source.as_ref(), &fence, now,)?
        .is_active());
    let kernel = Arc::get_mut(&mut runtime.kernel).ok_or("exclusive kernel")?;
    kernel
        .set_governed_approval_policy(TENANT.into(), vec![harness.fixture.signer.public_key()])?;
    kernel.set_operation_owned_governed_approval_source(binding, source)?;
    Ok(())
}

fn reserve_and_start(
    harness: &Harness,
    runtime: &Runtime,
    request: &mut ToolCallRequest,
) -> TestResult<SignedCallerDispatchAuthorizationV1> {
    let reserved = runtime.kernel.reserve_caller_execution_blocking(request)?;
    assert_eq!(reserved.verdict, Verdict::Allow, "{:?}", reserved.reason);
    request.execution_nonce = Some(*reserved.execution_nonce.ok_or("reserved nonce")?);
    harness.assert_calls(0, 0, 0, 0);
    assert_eq!(harness.captured_payments()?, 0);
    let result = runtime
        .kernel
        .start_caller_execution_with_credentials_blocking(
            request.execution_nonce.as_ref().ok_or("nonce")?,
            &request.arguments,
            CallerStartCredentials {
                dpop_proof: request.dpop_proof.clone(),
                approval_token: request.approval_token.clone(),
                ..Default::default()
            },
        )?;
    let CallerStartResponse::Authorized(authorization) = result else {
        return Err("valid prepaid caller start denied".into());
    };
    assert_retained(harness, runtime, request)?;
    Ok(*authorization)
}

fn assert_retained(harness: &Harness, runtime: &Runtime, request: &ToolCallRequest) -> TestResult {
    assert_state(&harness.fixture, request, "dispatch_committed")?;
    assert_eq!(harness.captured_payments()?, 1);
    assert_eq!(harness.committed(runtime, request)?, 100);
    assert_eq!(
        harness.journal(runtime, request)?.state,
        PaymentJournalState::Settled
    );
    harness.assert_calls(1, 1, 0, 0);
    assert_eq!(harness.fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn prepaid_caller_dpop_denial_preserves_original_captured_liability() -> TestResult {
    let harness = Harness::new(true, None, false)?;
    let mut runtime = harness.open()?;
    let domain = configure_dpop(&mut runtime)?;
    let mut request = prepaid_request(&harness, &runtime, true)?;
    request.dpop_proof = Some(DpopProof::sign(
        DpopProofBody {
            schema: DPOP_AUTHORITY_SCHEMA.into(),
            replay_authority: Some(domain),
            capability_id: request.capability.id.clone(),
            tool_server: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            action_hash: sha256_hex(&canonical(&request.arguments)?),
            nonce: "prepaid-caller-proof".into(),
            issued_at: request.capability.issued_at,
            agent_key: harness.fixture.agent.public_key(),
        },
        &harness.fixture.agent,
    )?);
    let authorization = reserve_and_start(&harness, &runtime, &mut request)?;
    let original_journal = harness.journal(&runtime, &request)?;
    for altered in [false, true] {
        let mut retry = request.clone();
        if altered {
            retry
                .dpop_proof
                .as_mut()
                .ok_or("proof")?
                .body
                .nonce
                .push_str("-changed");
        } else {
            retry.dpop_proof = None;
        }
        let denied = runtime.kernel.reserve_caller_execution_blocking(&retry)?;
        assert_eq!(denied.verdict, Verdict::Deny);
        assert_eq!(
            denied.reason.as_deref(),
            Some(if altered {
                "DPoP signature verification failed"
            } else {
                "required DPoP proof missing"
            })
        );
        assert!(denied.execution_nonce.is_none());
        assert!(denied.output.is_none());
        assert!(denied.receipt.verify_signature()?);
        assert_retained(&harness, &runtime, &request)?;
        assert_eq!(harness.journal(&runtime, &request)?, original_journal);
        assert_eq!(authorization, start(&runtime, &request)?);
    }
    Ok(())
}

#[test]
fn prepaid_caller_approval_replay_denial_preserves_original_captured_liability() -> TestResult {
    let harness = Harness::new(true, None, false)?;
    let mut runtime = harness.open()?;
    configure_approval(&harness, &mut runtime)?;
    let mut request = prepaid_request(&harness, &runtime, false)?;
    let intent = request.governed_intent.as_mut().ok_or("intent")?;
    chio_kernel::approval::ToolApprovalContext::bind(
        intent,
        &request.capability,
        &request.arguments,
        &request.request_id,
        runtime.kernel.policy_hash(),
        TENANT,
    )?;
    request.approval_token = Some(GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "prepaid-caller-approval".into(),
            approver: harness.fixture.signer.public_key(),
            subject: request.capability.subject.clone(),
            governed_intent_hash: intent.binding_hash()?,
            request_id: request.request_id.clone(),
            threshold_proposal_hash: None,
            issued_at: request.capability.issued_at,
            expires_at: request.capability.expires_at,
            decision: GovernedApprovalDecision::Approved,
        },
        &harness.fixture.signer,
    )?);
    let authorization = reserve_and_start(&harness, &runtime, &mut request)?;
    let original_journal = harness.journal(&runtime, &request)?;
    let (operation_id, _) =
        operation_state(&harness.fixture, &request.request_id)?.ok_or("operation")?;
    for altered in [false, true] {
        let mut retry = request.clone();
        if altered {
            retry.approval_token.as_mut().ok_or("approval")?.signature =
                harness.fixture.agent.sign(b"different approval");
        } else {
            retry.approval_token = None;
        }
        let denied = runtime.kernel.reserve_caller_execution_blocking(&retry)?;
        assert_eq!(denied.verdict, Verdict::Deny);
        let reason = if altered {
            "durable admission failed: request replay is retained in state DispatchCommitted"
                .to_string()
        } else {
            format!(
                "durable admission failed: request id conflicts with retained operation {}",
                operation_id.as_str()
            )
        };
        assert_eq!(denied.reason.as_deref(), Some(reason.as_str()));
        assert!(denied.execution_nonce.is_none());
        assert!(denied.output.is_none());
        assert!(denied.receipt.verify_signature()?);
        assert_retained(&harness, &runtime, &request)?;
        assert_eq!(harness.journal(&runtime, &request)?, original_journal);
        assert_eq!(authorization, start(&runtime, &request)?);
    }
    Ok(())
}

use super::*;
use std::sync::{Arc, Mutex};

#[path = "dispatch_commit_failure/mustprepay.rs"]
mod mustprepay;
#[path = "dispatch_commit_failure/payment_adapter.rs"]
mod payment_adapter;
use payment_adapter::LostPaymentAcknowledgement;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const FREEZE_REJECTION: &str = "injected return context rejection after payment authorization";

#[derive(Clone, Copy)]
enum FailureBoundary {
    Freeze,
    Security,
    CommitFence,
    UnwindAcknowledgement,
    AuthorizationAcknowledgement,
}

/// Remain valid through admission and payment, then fault at the real freeze
/// boundary. No request, credential, or admission ownership is fabricated.
struct FailAfterPaymentAuthorization {
    store: Arc<TestAdmissionOperationStore>,
    boundary: FailureBoundary,
    reached: Arc<AtomicU64>,
}

impl crate::post_invocation::PostInvocationHook for FailAfterPaymentAuthorization {
    fn name(&self) -> &str {
        "fail-after-payment-authorization"
    }

    fn inspect(
        &self,
        _: &crate::post_invocation::PostInvocationContext<'_>,
        _: &serde_json::Value,
    ) -> crate::post_invocation::PostInvocationVerdict {
        crate::post_invocation::PostInvocationVerdict::Allow
    }

    fn durable_identity(
        &self,
    ) -> Result<Option<crate::post_invocation::PostInvocationHookIdentity>, String> {
        if self
            .store
            .payment_journal()
            .is_some_and(|journal| journal.state == PaymentJournalState::Authorized)
        {
            self.reached.fetch_add(1, Ordering::SeqCst);
            match self.boundary {
                FailureBoundary::Freeze
                | FailureBoundary::Security
                | FailureBoundary::UnwindAcknowledgement => {
                    return Err(FREEZE_REJECTION.to_owned());
                }
                FailureBoundary::AuthorizationAcknowledgement => {
                    return Err("lost authorization acknowledgement reached dispatch freeze".into());
                }
                FailureBoundary::CommitFence => {
                    let mut replacement = admission_test_fence();
                    replacement.owner_epoch += 1;
                    replacement.lease_id = "dispatch-commit-replacement-owner".to_owned();
                    self.store.rotate_fence(replacement);
                }
            }
        }
        crate::post_invocation::PostInvocationHookIdentity::from_canonical_config(
            self.name(),
            "1",
            "chio-kernel.tests.dispatch-commit-failure.v1",
            &(),
        )
        .map(Some)
    }
}

struct RejectSecurity(Arc<AtomicU64>);

impl SecurityPreDispatchHook for RejectSecurity {
    fn name(&self) -> &str {
        "reject-security-after-payment"
    }

    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::GuardDenied("security policy rejected".into()))
    }
}

fn security_context(
    request: &ToolCallRequest,
    session: &str,
) -> Result<SecurityInvocationContext, Box<dyn std::error::Error>> {
    Ok(SecurityInvocationContext::v1(
        SecurityInvocationContextV1::new(
            chio_security_types::ports::TenantId::new("payment-security-tenant")?,
            chio_security_types::ports::SessionId::new(session)?,
            chio_security_types::PrincipalId::new(request.agent_id.clone())?,
            chio_security_types::ports::IsolationEpochId::new("payment-security-epoch")?,
            chio_security_types::ports::LineageId::new(request.capability.id.clone())?,
            1,
        ),
    ))
}

fn payment_dispatch_failure(
    nested: bool,
    present_approval: bool,
    boundary: FailureBoundary,
) -> TestResult {
    let mut grant = make_grant("durable-server", "mutate");
    grant.max_invocations = Some(1);
    grant.max_cost_per_invocation = Some(MonetaryAmount {
        units: 10,
        currency: "USD".to_owned(),
    });
    grant.max_total_cost = Some(MonetaryAmount {
        units: 100,
        currency: "USD".to_owned(),
    });
    let (mut kernel, mut request, store, invocations) =
        durable_admission_fixture_with_grants("payment-dispatch-commit-failure", vec![grant]);
    let authorizations = Arc::new(Mutex::new(Vec::new()));
    let settlements = Arc::new(Mutex::new(Vec::new()));
    let settlement_references = Arc::new(Mutex::new(Vec::new()));
    let adapter = QualifiedDurablePaymentAdapter {
        authorization_references: authorizations.clone(),
        settlement_actions: settlements.clone(),
        settlement_references: settlement_references.clone(),
    };
    if matches!(
        boundary,
        FailureBoundary::UnwindAcknowledgement | FailureBoundary::AuthorizationAcknowledgement
    ) {
        kernel.set_payment_adapter(Box::new(LostPaymentAcknowledgement { adapter, boundary }));
    } else {
        kernel.set_payment_adapter(Box::new(adapter));
    }
    if present_approval {
        kernel.set_governed_approval_replay_store(Box::new(
            InMemoryGovernedApprovalReplayStore::new(8),
        ));
        let intent = make_governed_intent(
            "payment-dispatch-commit-failure-intent",
            "durable-server",
            "mutate",
            "exercise owned approval retention after payment authorization",
            10,
            "USD",
        );
        request.approval_token = Some(make_governed_approval_token(
            &kernel.config.keypair,
            &request.capability.subject,
            &intent,
            &request.request_id,
        ));
        request.governed_intent = Some(intent);
    }
    let reached = Arc::new(AtomicU64::new(0));
    if matches!(boundary, FailureBoundary::Security) {
        kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
        kernel.set_security_pre_dispatch_hook(Arc::new(RejectSecurity(reached.clone())));
    } else {
        kernel.add_post_invocation_hook(Box::new(FailAfterPaymentAuthorization {
            store: store.clone(),
            boundary,
            reached: reached.clone(),
        }));
    }

    let response = if nested {
        let session = kernel.open_session("dispatch-failure-parent".to_owned(), Vec::new())?;
        kernel.activate_session(&session)?;
        let parent = make_operation_context(
            &session,
            "dispatch-failure-parent-request",
            "dispatch-failure-parent",
        );
        kernel.begin_session_request(&parent, OperationKind::ToolCall, true)?;
        let context = matches!(boundary, FailureBoundary::Security)
            .then(|| security_context(&request, session.as_str()))
            .transpose()?;
        kernel.evaluate_tool_call_with_nested_flow_client_and_security_context(
            &parent,
            &request,
            &mut NoopNestedFlowClient,
            None,
            context.as_ref(),
        )?
    } else if matches!(boundary, FailureBoundary::Security) {
        kernel.evaluate_tool_call_blocking_with_security_context(
            &request,
            &security_context(&request, "payment-security-session")?,
        )?
    } else {
        kernel.evaluate_tool_call_blocking(&request)?
    };
    assert_eq!(response.verdict, Verdict::Deny, "{response:?}");
    assert!(response.receipt.verify_signature()?);
    assert_eq!(
        reached.load(Ordering::SeqCst),
        u64::from(!matches!(
            boundary,
            FailureBoundary::AuthorizationAcknowledgement
        ))
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let operation = store.operation();
    let operation_id = operation.binding().operation_id().as_str();
    assert_eq!(
        authorizations
            .lock()
            .map_err(|_| "authorization lock")?
            .as_slice(),
        [operation_id]
    );
    let hold = store
        .budget_store()
        .get_budget_hold(
            operation
                .budget_hold_id()
                .ok_or("missing hold ID")?
                .as_str(),
        )?
        .ok_or("missing original hold")?;
    assert_eq!(hold.capability_id, request.capability.id);
    assert_eq!(hold.authorized_exposure_units, 10);
    let quota = store
        .budget_store()
        .get_invocation_quota_usage(&crate::budget_store::BudgetQuotaKey::grant(
            &request.capability.id,
            0,
        ))?
        .ok_or("missing original invocation quota")?;
    let journal = store
        .payment_journal()
        .ok_or("missing original payment journal")?;
    assert_eq!(journal.operation_id, operation_id);
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or("missing denial metadata")?;
    let runtime = &metadata["chio_runtime"];

    match boundary {
        FailureBoundary::Freeze | FailureBoundary::Security => {
            assert!(response
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains(
                    if matches!(boundary, FailureBoundary::Security) {
                        "security pre-dispatch"
                    } else {
                        FREEZE_REJECTION
                    }
                )));
            assert_eq!(
                operation.state(),
                AdmissionOperationState::CompensatedBeforeDispatch
            );
            assert_eq!(
                hold.disposition,
                crate::budget_store::BudgetHoldDispositionView::Reversed
            );
            assert_eq!(hold.remaining_exposure_units, 0);
            assert_eq!(
                (quota.reserved_invocations, quota.captured_invocations),
                (0, 0)
            );
            assert_eq!(journal.state, PaymentJournalState::Settled);
            assert_eq!(
                journal.settle_action,
                Some(crate::payment::PaymentSettleAction::Release)
            );
            assert_eq!(
                settlements
                    .lock()
                    .map_err(|_| "settlement lock")?
                    .as_slice(),
                ["release"]
            );
            assert_eq!(
                settlement_references
                    .lock()
                    .map_err(|_| "settlement reference lock")?
                    .as_slice(),
                [operation_id]
            );
            let expected_disposition = if present_approval {
                assert_eq!(
                    runtime["dispatch_credential_disposition"],
                    "retained_after_authorization"
                );
                "retained_after_authorization"
            } else {
                assert!(runtime.get("dispatch_credential_disposition").is_none());
                assert!(runtime.get("payment_credential_disposition").is_none());
                assert!(runtime
                    .get("dispatch_credential_retention_outcome_unknown")
                    .is_none());
                "none_present"
            };
            assert_eq!(
                runtime["pre_dispatch_payment_unwind"]["credential_disposition"],
                expected_disposition
            );
        }
        FailureBoundary::CommitFence
        | FailureBoundary::UnwindAcknowledgement
        | FailureBoundary::AuthorizationAcknowledgement => {
            assert_eq!(operation.state(), AdmissionOperationState::CapturePending);
            assert!(hold.disposition.is_open());
            assert_eq!(hold.remaining_exposure_units, 10);
            assert_eq!(
                (quota.reserved_invocations, quota.captured_invocations),
                (1, 0)
            );
            let authorization_unknown =
                matches!(boundary, FailureBoundary::AuthorizationAcknowledgement);
            assert_eq!(
                journal.state,
                if authorization_unknown {
                    PaymentJournalState::HoldPlaced
                } else {
                    PaymentJournalState::Authorized
                }
            );
            if matches!(boundary, FailureBoundary::UnwindAcknowledgement) {
                assert!(response.reason.as_deref().is_some_and(|reason| {
                    reason.contains("payment unwind acknowledgement was not confirmed")
                }));
                assert_eq!(
                    settlements
                        .lock()
                        .map_err(|_| "settlement lock")?
                        .as_slice(),
                    ["release"]
                );
                let attempted = settlement_references
                    .lock()
                    .map_err(|_| "settlement reference lock")?;
                assert_eq!(attempted.as_slice(), [operation_id]);
                assert_ne!(operation_id, request.request_id);
                assert_eq!(
                    metadata["financial"]["payment_unwind_attempt_reference"].as_str(),
                    attempted.first().map(String::as_str)
                );
                assert_eq!(metadata["financial"]["payment_unwind_unconfirmed"], true);
                assert_eq!(
                    metadata["financial"]["payment_authorization_may_be_retained"],
                    true
                );
            } else {
                assert!(settlements
                    .lock()
                    .map_err(|_| "settlement lock")?
                    .is_empty());
                assert!(settlement_references
                    .lock()
                    .map_err(|_| "settlement reference lock")?
                    .is_empty());
                if authorization_unknown {
                    let attempted = authorizations.lock().map_err(|_| "authorization lock")?;
                    assert_ne!(operation_id, request.request_id);
                    assert_eq!(
                        metadata["financial"]["payment_attempt_reference"].as_str(),
                        attempted.first().map(String::as_str)
                    );
                    assert_eq!(
                        metadata["financial"]["payment_authorization_ambiguous"],
                        true
                    );
                    assert!(journal.authorization_id.is_none());
                    assert!(journal.settle_action.is_none());
                } else {
                    assert_eq!(
                        metadata["financial"]["payment_authorization_retained"],
                        true
                    );
                }
            }
            assert!(runtime.get("pre_dispatch_payment_unwind").is_none());
        }
    }
    if present_approval {
        assert!(
            kernel
                .consume_governed_approval_for_dispatch(&request)
                .is_err(),
            "payment-authorizing approval became reusable after a failed dispatch"
        );
    }
    assert!(store
        .state
        .lock()
        .map_err(|_| "admission lock")?
        .raw_outcome
        .is_none());
    Ok(())
}

#[test]
fn security_rejection_after_payment_preserves_actual_credential_disposition() -> TestResult {
    for nested in [false, true] {
        for present_approval in [false, true] {
            payment_dispatch_failure(nested, present_approval, FailureBoundary::Security)?;
        }
    }
    Ok(())
}

#[test]
fn freeze_rejection_after_payment_does_not_invent_credential_custody() -> TestResult {
    for nested in [false, true] {
        payment_dispatch_failure(nested, false, FailureBoundary::Freeze)?;
    }
    Ok(())
}

#[test]
fn freeze_rejection_after_payment_retains_the_authorizing_approval() -> TestResult {
    for nested in [false, true] {
        payment_dispatch_failure(nested, true, FailureBoundary::Freeze)?;
    }
    Ok(())
}

#[test]
fn unconfirmed_dispatch_commit_retains_payment_quota_and_approval() -> TestResult {
    for nested in [false, true] {
        payment_dispatch_failure(nested, true, FailureBoundary::CommitFence)?;
    }
    Ok(())
}

#[test]
fn unconfirmed_payment_unwind_receipt_names_the_attempted_durable_operation() -> TestResult {
    for nested in [false, true] {
        payment_dispatch_failure(nested, true, FailureBoundary::UnwindAcknowledgement)?;
    }
    Ok(())
}

#[test]
fn unconfirmed_payment_authorization_receipt_names_the_attempted_durable_operation() -> TestResult {
    for nested in [false, true] {
        payment_dispatch_failure(nested, true, FailureBoundary::AuthorizationAcknowledgement)?;
    }
    Ok(())
}

//! Security rejection precedes the tool effect and irreversible nonce consumption.

use super::*;

#[derive(Clone, Copy, Debug)]
enum Rollback {
    Confirmed,
    OwnershipLost,
    Error,
    Panic,
}

struct ApprovalProbe {
    store: InMemoryGovernedApprovalReplayStore,
    rollback: Rollback,
    counts: Arc<[AtomicU64; 3]>,
}

impl GovernedApprovalReplayStore for ApprovalProbe {
    fn reserve_for_dispatch(
        &self,
        subject: &str,
        request: &str,
        intent: &str,
        expiry: u64,
        owner: &str,
    ) -> Result<bool, KernelError> {
        self.counts[0].fetch_add(1, Ordering::SeqCst);
        self.store
            .reserve_for_dispatch(subject, request, intent, expiry, owner)
    }

    fn commit_dispatch_reservation(
        &self,
        subject: &str,
        request: &str,
        intent: &str,
        owner: &str,
    ) -> Result<bool, KernelError> {
        self.counts[1].fetch_add(1, Ordering::SeqCst);
        self.store
            .commit_dispatch_reservation(subject, request, intent, owner)
    }

    fn rollback_dispatch_reservation(
        &self,
        subject: &str,
        request: &str,
        intent: &str,
        owner: &str,
    ) -> Result<bool, KernelError> {
        self.counts[2].fetch_add(1, Ordering::SeqCst);
        match self.rollback {
            Rollback::Confirmed => self
                .store
                .rollback_dispatch_reservation(subject, request, intent, owner),
            Rollback::OwnershipLost => Ok(false),
            Rollback::Error => Err(KernelError::Internal(
                "injected approval rollback failure".into(),
            )),
            Rollback::Panic => panic!("injected approval rollback panic"),
        }
    }
}

pub(super) fn evaluate(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
    nested: bool,
) -> Result<ToolCallResponse, Box<dyn std::error::Error>> {
    let session = kernel.open_session(request.agent_id.clone(), vec![])?;
    kernel.activate_session(&session)?;
    let context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        chio_security_types::ports::TenantId::new("security-credential-tenant")?,
        chio_security_types::ports::SessionId::new(session.as_str())?,
        chio_security_types::PrincipalId::new(request.agent_id.clone())?,
        chio_security_types::ports::IsolationEpochId::new("security-credential-epoch")?,
        chio_security_types::ports::LineageId::new(request.capability.id.clone())?,
        1,
    ));
    Ok(if nested {
        let parent = make_operation_context(&session, "credential-parent", &request.agent_id);
        kernel.begin_session_request(&parent, OperationKind::ToolCall, true)?;
        kernel.evaluate_tool_call_with_nested_flow_client_and_security_context(
            &parent,
            request,
            &mut NoopNestedFlowClient,
            None,
            Some(&context),
        )?
    } else {
        kernel.evaluate_tool_call_blocking_with_security_context(request, &context)?
    })
}

fn security_rejection(nested: bool, fault: Fault, rollback: Rollback) -> TestResult {
    let (mut kernel, _, mut request, nonce_reserves) =
        request_with_legacy_execution_nonce_store("security-credential-rejection")?;
    let invocations = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(CountingDispatchServer {
        id: request.server_id.clone(),
        tool: request.tool_name.clone(),
        invocations: invocations.clone(),
    }));
    let counts = Arc::new(std::array::from_fn(|_| AtomicU64::new(0)));
    kernel.set_governed_approval_replay_store(Box::new(ApprovalProbe {
        store: InMemoryGovernedApprovalReplayStore::default(),
        rollback,
        counts: counts.clone(),
    }));
    let intent = make_governed_intent(
        "security-credential-intent",
        &request.server_id,
        &request.tool_name,
        "exercise security rejection credential custody",
        1,
        "USD",
    );
    request.approval_token = Some(make_governed_approval_token(
        &kernel.config.keypair,
        &request.capability.subject,
        &intent,
        &request.request_id,
    ));
    request.governed_intent = Some(intent);
    request.execution_nonce = Some(mint_execution_nonce(
        &kernel.config.keypair,
        binding_for_request(&request.capability, &request),
        kernel
            .execution_nonce_config
            .as_ref()
            .ok_or("nonce configuration")?,
        i64::try_from(current_unix_timestamp())?,
    )?);
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(Arc::new(Hook(fault)));
    let response = evaluate(&kernel, &request, nested)?;
    assert_eq!(response.verdict, Verdict::Deny, "{fault:?}: {response:?}");
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("security pre-dispatch")),
        "{response:?}"
    );
    assert!(response.receipt.verify_signature()?);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(
        nonce_reserves.load(Ordering::SeqCst),
        0,
        "security denial consumed a legacy nonce"
    );
    assert_eq!(
        counts.each_ref().map(|count| count.load(Ordering::SeqCst)),
        [1, 0, 1]
    );
    let disposition = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("chio_runtime"))
        .and_then(|runtime| runtime.get("dispatch_credential_disposition"));
    if matches!(rollback, Rollback::Confirmed) {
        assert!(disposition.is_none(), "{response:?}");
        kernel.set_security_pre_dispatch_hook(Arc::new(Hook(Fault::None)));
        let accepted = evaluate(&kernel, &request, nested)?;
        assert_eq!(accepted.verdict, Verdict::Allow, "{accepted:?}");
        assert_eq!(invocations.load(Ordering::SeqCst), 1);
        assert_eq!(nonce_reserves.load(Ordering::SeqCst), 1);
        assert_eq!(
            counts.each_ref().map(|count| count.load(Ordering::SeqCst)),
            [2, 1, 1]
        );
    } else {
        assert_eq!(
            disposition.and_then(serde_json::Value::as_str),
            Some("retention_outcome_unknown")
        );
        assert!(response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("rollback failed")));
    }
    Ok(())
}

#[test]
fn security_rejection_releases_dpop_nonce_and_approval_as_one_attempt() -> TestResult {
    for nested in [false, true] {
        for fault in [
            Fault::Acquire,
            Fault::Commit,
            Fault::WrongOwner,
            Fault::Reject,
        ] {
            let (mut kernel, _, _, request, _) =
                request_with_replayed_approval("security-all-credentials")?;
            let counts = Arc::new(std::array::from_fn(|_| AtomicU64::new(0)));
            kernel.set_governed_approval_replay_store(Box::new(ApprovalProbe {
                store: InMemoryGovernedApprovalReplayStore::default(),
                rollback: Rollback::Confirmed,
                counts: counts.clone(),
            }));
            let invocations = Arc::new(AtomicU64::new(0));
            kernel.register_tool_server(Box::new(CountingDispatchServer {
                id: request.server_id.clone(),
                tool: request.tool_name.clone(),
                invocations: invocations.clone(),
            }));
            kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
            kernel.set_security_pre_dispatch_hook(Arc::new(Hook(fault)));
            let denied = evaluate(&kernel, &request, nested)?;
            assert_eq!(denied.verdict, Verdict::Deny);
            assert!(
                denied
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("security pre-dispatch")),
                "{denied:?}"
            );
            assert_eq!(invocations.load(Ordering::SeqCst), 0);
            assert_eq!(
                kernel
                    .dpop_nonce_store
                    .as_ref()
                    .ok_or("dpop store")?
                    .utilization()?
                    .0,
                0
            );
            assert!(!kernel
                .execution_nonce_store
                .as_ref()
                .ok_or("nonce store")?
                .is_consumed(request.execution_nonce.as_ref().ok_or("nonce")?.nonce_id())?);
            assert_eq!(
                counts.each_ref().map(|count| count.load(Ordering::SeqCst)),
                [1, 0, 1]
            );
            kernel.set_security_pre_dispatch_hook(Arc::new(Hook(Fault::None)));
            let accepted = evaluate(&kernel, &request, nested)?;
            assert_eq!(accepted.verdict, Verdict::Allow, "{accepted:?}");
            assert_eq!(invocations.load(Ordering::SeqCst), 1);
            assert_eq!(
                kernel
                    .dpop_nonce_store
                    .as_ref()
                    .ok_or("dpop store")?
                    .utilization()?
                    .0,
                1
            );
            assert!(kernel
                .execution_nonce_store
                .as_ref()
                .ok_or("nonce store")?
                .is_consumed(request.execution_nonce.as_ref().ok_or("nonce")?.nonce_id())?);
            assert_eq!(
                counts.each_ref().map(|count| count.load(Ordering::SeqCst)),
                [2, 1, 1]
            );
        }
    }
    Ok(())
}

#[test]
fn security_rejection_keeps_credentials_reversible_until_dispatch() -> TestResult {
    for nested in [false, true] {
        for fault in [
            Fault::Acquire,
            Fault::Commit,
            Fault::WrongOwner,
            Fault::Reject,
        ] {
            security_rejection(nested, fault, Rollback::Confirmed)?;
        }
    }
    Ok(())
}

#[test]
fn security_rejection_reports_unconfirmed_credential_rollback() -> TestResult {
    for nested in [false, true] {
        for rollback in [Rollback::OwnershipLost, Rollback::Error, Rollback::Panic] {
            security_rejection(nested, Fault::Reject, rollback)?;
        }
    }
    Ok(())
}

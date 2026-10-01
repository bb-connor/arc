// Negative native caller cases retain physical custody and never release raw output.
use super::*;
use chio_kernel::caller_delivery::SignedCallerDispatchAuthorizationV1;
use chio_kernel::RevocationStore;

fn pin(fixture: &mut Fixture) -> TestResult<Keypair> {
    let key = Keypair::generate();
    fixture
        .kernel
        .set_caller_executor(CallerExecutorIdentityV1 {
            executor_id: AdmissionIdentifier::try_new("executor", "native-denial-executor")?,
            public_key: key.public_key(),
            key_epoch: 7,
        })?;
    Ok(key)
}

fn reserve(fixture: &mut Fixture) -> TestResult {
    super::super::nonce::execution::issue(fixture)?;
    let response = fixture
        .kernel
        .reserve_caller_execution_blocking_with_security_context(
            &fixture.request,
            &fixture.context,
        )?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    fixture.request.execution_nonce = Some(*response.execution_nonce.ok_or("nonce")?);
    Ok(())
}

fn start(fixture: &Fixture) -> TestResult<SignedCallerDispatchAuthorizationV1> {
    match fixture
        .kernel
        .start_caller_execution_blocking_with_security_context(
            fixture.request.execution_nonce.as_ref().ok_or("nonce")?,
            &fixture.request.arguments,
            start_credentials(fixture),
            &fixture.context,
        )? {
        CallerStartResponse::Authorized(value) => Ok(*value),
        CallerStartResponse::Denied(value) => {
            Err(format!("start denied: {:?}", value.reason).into())
        }
    }
}

#[test]
fn native_caller_preflight_requires_fresh_host_flow_state_before_reservation() -> TestResult {
    let mut fixture = Fixture::new(std::array::from_fn(|_| InformationLabel::bottom()))?;
    super::super::nonce::execution::configure(&mut fixture, false)?;
    pin(&mut fixture)?;
    let preflight = fixture
        .kernel
        .reserve_caller_execution_blocking_with_security_context(
            &fixture.request,
            &fixture.context,
        )?;
    assert_eq!(preflight.verdict, Verdict::Allow, "{:?}", preflight.reason);
    assert!(preflight.output.is_none());
    fixture.request.execution_nonce = Some(*preflight.execution_nonce.ok_or("preflight nonce")?);
    let store = fixture.authority.admission_operation_store();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("preflight operation")?;
    assert_ne!(operation.state(), AdmissionOperationState::ReadyToDispatch);
    assert!(operation.dispatch_commit().is_none());
    let context = fixture.context.as_v1();
    let key = FlowStateKey {
        tenant_id: context.tenant_id().clone(),
        principal_id: context.principal_id().clone(),
        session_id: context.session_id().clone(),
        lineage_id: context.lineage_root_id().clone(),
        isolation_epoch_id: context.isolation_epoch_id().clone(),
    };
    let observed = store.observe_native_security_flow(
        &fixture.binding,
        &key,
        &fixture.authority.mutation_fence(),
        now_ms()?,
    )?;
    fixture.context = SecurityInvocationContext::v1(
        context.clone().with_flow_state_generation(
            observed
                .stored_context_generation()
                .ok_or("preflight flow state")?,
        ),
    );
    let reserved = fixture
        .kernel
        .reserve_caller_execution_blocking_with_security_context(
            &fixture.request,
            &fixture.context,
        )?;
    assert_eq!(reserved.verdict, Verdict::Allow, "{:?}", reserved.reason);
    let authorization = start(&fixture)?;
    assert_eq!(
        &authorization.authorization.invocation.operation_id,
        operation.binding().operation_id()
    );
    assert_captured_quota(&fixture)?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn native_caller_changed_input_cannot_replace_original_reserved_join() -> TestResult {
    let mut fixture = Fixture::new(std::array::from_fn(|_| InformationLabel::bottom()))?;
    super::super::nonce::execution::configure(&mut fixture, false)?;
    pin(&mut fixture)?;
    reserve(&mut fixture)?;
    let store = fixture.authority.admission_operation_store();
    let (before, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("reserved operation")?;
    let (_, original) = store
        .load_native_security_input_join(
            before.binding().operation_id(),
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("input operation")?;
    let original = original.ok_or("original input")?;
    let mut config = flow_config();
    config.operator_input_floor = super::super::super::restricted_label();
    fixture.kernel.set_security_pre_dispatch_hook(Arc::new(
        NativeFlowResolver::new(
            fixture.binding.clone(),
            super::super::super::registry(false, super::super::super::restricted_label())?,
            Arc::new(CountingEmptyClassifier::new()),
            Arc::new(Clock::default()),
            config,
        )?
        .with_captured_lifecycle(),
    ));
    let denied = fixture
        .kernel
        .start_caller_execution_blocking_with_security_context(
            fixture.request.execution_nonce.as_ref().ok_or("nonce")?,
            &fixture.request.arguments,
            start_credentials(&fixture),
            &fixture.context,
        )?;
    let CallerStartResponse::Denied(denied) = denied else {
        return Err("changed native input acquired permission".into());
    };
    assert!(denied.output.is_none());
    assert!(
        format!("{:?}", denied.reason).contains("original classified input custody"),
        "{:?}",
        denied.reason
    );
    let (after, retained) = store
        .load_native_security_input_join(
            before.binding().operation_id(),
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("retained input")?;
    assert_eq!(retained, Some(original));
    assert!(after.dispatch_commit().is_none());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

struct RefuseOutput {
    binding: NativeSecurityAuthorityBindingV1,
}
impl SecurityPreDispatchHook for RefuseOutput {
    fn name(&self) -> &str {
        "native-caller-output-refusal"
    }
    fn supports_native_dispatch(&self) -> bool {
        true
    }
    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        Ok(Some(self.binding.clone()))
    }
    fn prepare_native_output(
        &self,
        _: &chio_kernel::tool_outcome::DurableSecurityReleaseContext<'_>,
        _: &chio_kernel::NativeSecurityOutputJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        Err(KernelError::GuardDenied(
            "native caller output refused".into(),
        ))
    }
    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Err(KernelError::GuardDenied("no new dispatch".into()))
    }
}

#[test]
fn native_caller_output_refusal_revocation_and_stop_never_release_raw_delivery() -> TestResult {
    for fault in ["output", "revocation", "stop"] {
        let mut fixture = Fixture::new(std::array::from_fn(|_| InformationLabel::bottom()))?;
        super::super::nonce::execution::configure(&mut fixture, true)?;
        let key = pin(&mut fixture)?;
        reserve(&mut fixture)?;
        let authorization = start(&fixture)?;
        let ledger = SqliteCallerExecutionLedger::provision(
            &fixture._directory.path().join("executor.db"),
            authorization.authorization.executor.clone(),
            2,
        )?;
        let report = ledger.execute_once(
            &authorization,
            &fixture.signer.public_key(),
            &authorization.authorization.invocation,
            &key,
            || {
                Ok(CallerExecutionReport {
                    output: serde_json::json!({"secret_raw_output": true}),
                    realized_cost: None,
                })
            },
        )?;
        match fault {
            "output" => fixture
                .kernel
                .set_security_pre_dispatch_hook(Arc::new(RefuseOutput {
                    binding: fixture.binding.clone(),
                })),
            "revocation" => {
                assert!(fixture
                    .authority
                    .revocation_store()
                    .revoke(&fixture.request.capability.id)?);
            }
            "stop" => fixture
                .kernel
                .emergency_stop("native caller stop before delivery")?,
            _ => unreachable!(),
        }
        for _ in 0..2 {
            let result = fixture
                .kernel
                .reconcile_authenticated_caller_execution_blocking(&authorization, &report);
            if let Ok(response) = result {
                assert_eq!(response.verdict, Verdict::Deny, "{fault}");
                assert!(response.output.is_none(), "{fault}");
            }
        }
        assert_captured_quota(&fixture)?;
        assert!(
            fixture
                .authority
                .tool_outcome_store()
                .lookup_security_release(&authorization.authorization.invocation.operation_id)?
                .is_none(),
            "{fault}"
        );
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

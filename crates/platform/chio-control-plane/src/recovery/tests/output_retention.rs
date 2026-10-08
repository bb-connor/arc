//! Native output retention is selected before capture or external effects.
use super::*;
use chio_kernel::tool_outcome::ToolOutcomeStore;
use chio_security_types::semantic::SemanticOutputDispositionV1;

fn captured_invocations(f: &RecoveryFixture) -> TestResult<u64> {
    let connection = rusqlite::Connection::open_with_flags(
        f.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let count: i64 = connection.query_row(
        "SELECT count(*) FROM authority_global_commits
         WHERE projection_kind='budget' AND mutation_kind='capture_invocation'",
        [],
        |row| row.get(0),
    )?;
    Ok(u64::try_from(count)?)
}

#[tokio::test]
async fn native_missing_output_retention_bound_refuses_before_capture_or_effect() -> TestResult {
    // No new selector or synthetic profile is installed here. This uses the
    // genuine native authority, signed semantic contract, capability verifier,
    // physical budget capture and independently counted provider effect.
    let f = semantic::empty_import::native_fixture_from_empty_import("write").await?;
    let key = "unbounded-native-return";
    let (runtime, request, _) =
        semantic::prepare(&f, key, SemanticOutputDispositionV1::ReturnValue)?;
    let before_captures = captured_invocations(&f)?;
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    let result = runtime
        .execute_step(&f.process, "root", key, &request)
        .await;
    let effects = f.effects.load(Ordering::SeqCst);
    let captures = captured_invocations(&f)?
        .checked_sub(before_captures)
        .ok_or("native capture count regressed")?;
    assert!(
        effects == 0 && captures == 0,
        "missing retained-output bound admitted {effects} provider effects and {captures} physical captures"
    );
    assert!(
        result.is_err()
            || result.as_ref().is_ok_and(|response| {
                response.verdict == Verdict::Deny && response.output.is_none()
            }),
        "unsupported retained-output profile did not refuse before dispatch"
    );
    Ok(())
}

/// Productive prerequisite control, not qualification of a financed profile.
#[tokio::test]
async fn native_write_control_reaches_capture_once_from_empty_import() -> TestResult {
    let f = semantic::empty_import::native_fixture_from_empty_import("write").await?;
    let key = "native-output-prerequisite-control";
    let (runtime, request, _) =
        semantic::prepare(&f, key, SemanticOutputDispositionV1::ReturnValue)?;
    let before_captures = captured_invocations(&f)?;
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    let result = runtime
        .execute_step(&f.process, "root", key, &request)
        .await?;
    assert_eq!(result.verdict, Verdict::Allow);
    assert!(result.receipt.verify_signature()?);
    assert!(
        result.output.is_some(),
        "productive native control withheld output"
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        captured_invocations(&f)?.checked_sub(before_captures),
        Some(1)
    );
    let store = f.authority.admission_operation_store();
    let (operation, original) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("productive native control original admission absent")?;
    original.validate_binding(operation.binding())?;
    original.validate_request_material(&request)?;
    assert_eq!(operation.state(), AdmissionOperationState::Completed);
    assert!(operation.dispatch_commit().is_some());
    assert!(operation.native_dispatch_ledger_digest().is_some());
    assert!(f
        .authority
        .tool_outcome_store()
        .load_raw_invocation_by_operation(operation.binding().operation_id())?
        .is_some());
    let replay = runtime
        .execute_step(&f.process, "root", key, &request)
        .await?;
    assert_eq!(replay.request_id, result.request_id);
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        captured_invocations(&f)?.checked_sub(before_captures),
        Some(1)
    );
    Ok(())
}

#[derive(Clone, Default)]
struct PaymentParticipantCalls {
    authorization: Arc<AtomicUsize>,
    completion: Arc<AtomicUsize>,
}

/// This local adapter moves no funds and performs no network IO. A definite
/// decline stops execution at the real external-participant call boundary.
struct CountingDecliningPaymentAdapter {
    calls: PaymentParticipantCalls,
}

impl chio_kernel::PaymentAdapter for CountingDecliningPaymentAdapter {
    fn rail_id(&self) -> &'static str {
        "local-participant-order-control"
    }

    fn rail_mode(&self) -> Option<chio_kernel::PaymentRailMode> {
        Some(chio_kernel::PaymentRailMode::ReversibleHold)
    }

    fn authorize(
        &self,
        request: &chio_kernel::PaymentAuthorizeRequest,
    ) -> Result<chio_kernel::PaymentAuthorization, chio_kernel::PaymentError> {
        if request.amount_units != 10 || request.currency != "USD" || request.reference.is_empty() {
            return Err(chio_kernel::PaymentError::RailError(
                "participant control received an invalid original payment".into(),
            ));
        }
        self.calls.authorization.fetch_add(1, Ordering::SeqCst);
        Err(chio_kernel::PaymentError::Declined(
            "local participant control declined without moving funds".into(),
        ))
    }

    fn capture(
        &self,
        _: &str,
        _: u64,
        _: &str,
        _: &str,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        self.unexpected_completion()
    }

    fn release(
        &self,
        _: &str,
        _: &str,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        self.unexpected_completion()
    }

    fn refund(
        &self,
        _: &str,
        _: u64,
        _: &str,
        _: &str,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        self.unexpected_completion()
    }

    fn settlement_state(
        &self,
        _: &str,
        _: Option<&str>,
    ) -> Result<chio_kernel::RailSettlementState, chio_kernel::PaymentError> {
        Ok(chio_kernel::RailSettlementState::NoAuthorization)
    }
}

impl CountingDecliningPaymentAdapter {
    fn unexpected_completion(
        &self,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        self.calls.completion.fetch_add(1, Ordering::SeqCst);
        Err(chio_kernel::PaymentError::RailError(
            "declined participant control cannot complete a payment".into(),
        ))
    }
}

#[tokio::test]
async fn native_missing_retention_financing_refuses_before_payment_authorization() -> TestResult {
    let calls = PaymentParticipantCalls::default();
    let adapter = Box::new(CountingDecliningPaymentAdapter {
        calls: calls.clone(),
    });
    let f = semantic::empty_import::native_fixture_from_empty_import_with_payment("write", adapter)
        .await?;
    assert_eq!(calls.authorization.load(Ordering::SeqCst), 0);
    let key = "native-payment-without-retained-financing";
    let (runtime, request, _) =
        semantic::prepare(&f, key, SemanticOutputDispositionV1::ReturnValue)?;
    let before_captures = captured_invocations(&f)?;
    let grant_index = request
        .capability
        .scope
        .grants
        .iter()
        .position(|grant| {
            grant.server_id == request.server_id && grant.tool_name == request.tool_name
        })
        .ok_or("native payment control selected grant absent")?;
    let budget = f.authority.budget_store();
    let before_balance = budget
        .get_usage(&request.capability.id, grant_index)?
        .map(|usage| {
            (
                usage.invocation_count,
                usage.total_cost_exposed,
                usage.total_cost_realized_spend,
            )
        })
        .unwrap_or((0, 0, 0));
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    let result = runtime
        .execute_step(&f.process, "root", key, &request)
        .await;
    let authorizations = calls.authorization.load(Ordering::SeqCst);
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    assert_eq!(captured_invocations(&f)?, before_captures);
    assert_eq!(calls.completion.load(Ordering::SeqCst), 0);
    assert!(
        authorizations == 0,
        "missing retained finishing plan reached {authorizations} payment authorizations before native capture refusal"
    );
    let (operation, original) = f
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("native payment regression original admission absent")?;
    original.validate_binding(operation.binding())?;
    original.validate_request_material(&request)?;
    assert_eq!(
        operation.binding().effect_class(),
        chio_kernel::admission_operation::SideEffectClass::Monetary
    );
    assert!(original.native_security_authority_binding().is_some());
    assert!(operation.dispatch_commit().is_none());
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    let response = result?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert!(response.execution_nonce.is_none());
    assert!(response.receipt.verify_signature()?);
    assert!(
        response.receipt.metadata.as_ref().is_none_or(|metadata| {
            metadata["financial"]["payment_authorization_ambiguous"] != true
        }),
        "known local refusal was recorded as an uncertain external authorization"
    );
    let hold = budget
        .get_budget_hold(
            operation
                .budget_hold_id()
                .ok_or("native payment original hold absent")?
                .as_str(),
        )?
        .ok_or("native payment original hold is not retained")?;
    assert_eq!(hold.capability_id, request.capability.id);
    assert_eq!(hold.remaining_exposure_units, 0);
    assert_eq!(
        hold.disposition,
        chio_kernel::budget_store::BudgetHoldDispositionView::Reversed
    );
    let quota = budget
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(
            &request.capability.id,
            u32::try_from(grant_index)?,
        ))?
        .ok_or("native payment original quota absent")?;
    assert_eq!(
        (quota.reserved_invocations, quota.captured_invocations),
        (0, 0)
    );
    let after_balance = budget
        .get_usage(&request.capability.id, grant_index)?
        .map(|usage| {
            (
                usage.invocation_count,
                usage.total_cost_exposed,
                usage.total_cost_realized_spend,
            )
        })
        .unwrap_or((0, 0, 0));
    assert_eq!(after_balance, before_balance);
    Ok(())
}

/// The same rail and real durable store still authorize ordinary monetary
/// calls. The native-only pre-effect gate must preserve this existing path.
#[tokio::test]
async fn ordinary_monetary_control_reaches_local_authorization_without_dispatch() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path();
    let locks = path.join("locks");
    std::fs::create_dir_all(&locks)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for private_path in [path, locks.as_path()] {
            std::fs::set_permissions(private_path, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    let database = path.join("admission.db");
    SqliteAuthorityStore::provision(&database, &locks)?;
    let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
    let issuer = Keypair::from_seed(&[140; 32]);
    let agent = Keypair::from_seed(&[141; 32]);
    let (mut kernel, effects) = open_kernel(path, &authority, &issuer)?;
    kernel.configure_durable_admission(DurableAdmissionMode::All, false)?;
    let calls = PaymentParticipantCalls::default();
    kernel.set_payment_adapter(Box::new(CountingDecliningPaymentAdapter {
        calls: calls.clone(),
    }));
    kernel.register_tool_server(Box::new(PersistentEffectServer::new(
        path.join("effects.db"),
        effects.clone(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    )?));
    let capability = kernel.issue_capability(
        &agent.public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "server-a".into(),
                tool_name: "send".into(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: Some(8),
                max_cost_per_invocation: Some(chio_core::capability::scope::MonetaryAmount {
                    units: 10,
                    currency: "USD".into(),
                }),
                max_total_cost: Some(chio_core::capability::scope::MonetaryAmount {
                    units: 80,
                    currency: "USD".into(),
                }),
                dpop_required: None,
            }],
            ..Default::default()
        },
        600,
    )?;
    let request = ToolCallRequest {
        request_id: "ordinary-monetary-participant-control".into(),
        capability,
        tool_name: "send".into(),
        server_id: "server-a".into(),
        agent_id: agent.public_key().to_hex(),
        arguments: serde_json::json!({"title":"local participant control"}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: vec![],
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    let response = kernel.evaluate_tool_call(&request).await?;
    assert_eq!(calls.authorization.load(Ordering::SeqCst), 1);
    assert_eq!(calls.completion.load(Ordering::SeqCst), 0);
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert!(response.receipt.verify_signature()?);
    let store = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    // This ordinary local-system path has no operation-owned authority profile.
    // Its real admission exists without a retained original request record.
    let namespace =
        chio_kernel::admission_operation::AuthenticatedRequestNamespace::for_local_system(
            AdmissionIdentifier::try_new("coordinator_authority_id", &fence.store_uuid)?,
        )?;
    let selector = chio_kernel::admission_operation::AdmissionReplayKey {
        request_namespace_digest: namespace.digest().clone(),
        request_id: AdmissionIdentifier::try_new("request_id", &request.request_id)?,
    };
    let operation = store
        .load_by_replay_key(&selector)?
        .ok_or("ordinary local-system monetary control admission absent")?;
    operation.validate()?;
    assert!(
        operation.binding().replay_key() == selector,
        "ordinary monetary control changed its authenticated namespace"
    );
    assert!(
        operation.binding().request_id().as_str() == request.request_id
            && operation.binding().capability_id().as_str() == request.capability.id,
        "ordinary monetary control changed its actual request or capability"
    );
    let canonical_capability = chio_core::canonical_json_bytes(&request.capability)?;
    assert!(
        operation.binding().authorization_capability_hash().as_str()
            == chio_core::sha256_hex(&canonical_capability),
        "ordinary monetary control changed its original signed capability"
    );
    let action = chio_core_types::receipt::decision::ToolCallAction::from_parameters(
        request.arguments.clone(),
    )?;
    assert!(
        operation.binding().action_parameter_hash().as_str() == action.parameter_hash,
        "ordinary monetary control changed its actual action"
    );
    assert!(operation.binding().participant_requirements().payment);
    assert!(store
        .load_retained_tool_request(operation.binding().operation_id(), &fence, now_ms()?)?
        .is_none());
    assert!(store
        .load_security_participant_flow_join(operation.binding().operation_id(), &fence, now_ms()?)?
        .is_none());
    assert!(store
        .load_native_dispatch_ledger(operation.binding().operation_id(), &fence, now_ms()?)?
        .is_none());
    assert_eq!(
        operation.binding().effect_class(),
        chio_kernel::admission_operation::SideEffectClass::Monetary
    );

    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    let connection = rusqlite::Connection::open_with_flags(
        &database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let captures: i64 = connection.query_row(
        "SELECT count(*) FROM authority_global_commits
         WHERE projection_kind='budget' AND mutation_kind='capture_invocation'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(captures, 0);
    Ok(())
}

// Real public nested invocation using the host's current process context.
use chio_core::session::{
    CreateElicitationOperation, CreateElicitationResult, CreateMessageOperation,
    CreateMessageResult, OperationContext, RequestId, RootDefinition, ToolCallOperation,
};
use chio_kernel::{
    NestedFlowClient, SecurityInvocationContext, SecurityInvocationContextAuthority,
};

struct RefuseNestedRequests;

impl NestedFlowClient for RefuseNestedRequests {
    fn list_roots(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
    ) -> Result<Vec<RootDefinition>, KernelError> {
        Err(KernelError::Internal(
            "unexpected nested roots request".into(),
        ))
    }
    fn create_message(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
        _: &CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError> {
        Err(KernelError::Internal(
            "unexpected nested message request".into(),
        ))
    }
    fn create_elicitation(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
        _: &CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError> {
        Err(KernelError::Internal(
            "unexpected nested elicitation request".into(),
        ))
    }
    fn notify_elicitation_completed(
        &mut self,
        _: &OperationContext,
        _: &str,
    ) -> Result<(), KernelError> {
        Err(KernelError::Internal(
            "unexpected nested elicitation notification".into(),
        ))
    }
    fn notify_resource_updated(
        &mut self,
        _: &OperationContext,
        _: &str,
    ) -> Result<(), KernelError> {
        Err(KernelError::Internal(
            "unexpected nested resource notification".into(),
        ))
    }
    fn notify_resources_list_changed(&mut self, _: &OperationContext) -> Result<(), KernelError> {
        Err(KernelError::Internal(
            "unexpected nested resource inventory notification".into(),
        ))
    }
}

/// The configured trusted host supplies the actual signed Process identity
/// with its mutable observation freshly read through the native fenced reader.
struct CurrentProcessPaymentContext {
    operation: OperationContext,
    capability: String,
    current: SecurityInvocationContext,
}
impl SecurityInvocationContextAuthority for CurrentProcessPaymentContext {
    fn resolve_security_invocation_context(
        &self,
        operation: &OperationContext,
        call: &ToolCallOperation,
    ) -> Result<SecurityInvocationContext, KernelError> {
        if operation != &self.operation || call.capability.id != self.capability {
            return Err(KernelError::GuardDenied(
                "native payment context substitution".into(),
            ));
        }
        Ok(self.current.clone())
    }
}

fn original_capture_count_at(path: &std::path::Path) -> TestResult<u64> {
    let connection = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let count: i64 = connection.query_row(
        "SELECT count(*) FROM authority_global_commits WHERE projection_kind='budget' AND mutation_kind='capture_invocation'", [], |row| row.get(0)
    )?;
    Ok(u64::try_from(count)?)
}

// Only mutable observation is refreshed. Every actual signed Process identity
// field remains unchanged, and the native admission writer rechecks it itself.
fn current_native_payment_context(
    kernel: &ChioKernel,
    authority: &SqliteAuthorityStore,
    scope: &RecoveryScopeV1,
    original: &SecurityInvocationContext,
) -> TestResult<SecurityInvocationContext> {
    let current = kernel.refresh_native_security_context(original)?;
    let before = original.as_v1();
    let after = current.as_v1();
    assert!(
        before.tenant_id() == after.tenant_id()
            && before.principal_id() == after.principal_id()
            && before.lineage_root_id() == after.lineage_root_id()
            && before.session_id() == after.session_id()
            && before.isolation_epoch_id() == after.isolation_epoch_id()
            && before.context_generation() == after.context_generation(),
        "native payment observation refresh changed actual Process identity"
    );
    let deployment = kernel.recovery_deployment(scope)?;
    let key = recovery_flow_key(&current);
    let observed = authority
        .admission_operation_store()
        .observe_security_participant_flow(
            &deployment.native_authority,
            &key,
            &authority.mutation_fence(),
            now_ms()?,
        )?;
    assert!(
        observed.binding() == &deployment.native_authority && observed.key() == &key,
        "native payment observation differs from actual selected authority or Process key"
    );
    assert!(
        observed.stored_context_generation().is_some()
            && observed.stored_context_generation() == after.flow_state_generation(),
        "native payment flow generation is not the current stored source"
    );
    Ok(current)
}

#[derive(Debug)]
enum NativePaymentRefusalPhase {
    BeforeAuthorizationFunding,
    CallerBeforeAuthorizationFunding,
    StaleNativeInputObservation,
    SemanticInputRefused,
    OtherRefusal,
    NoRefusal,
}

fn native_payment_refusal_phase(reason: Option<&str>) -> NativePaymentRefusalPhase {
    match reason {
        Some("payment authorization failed: declined") => {
            NativePaymentRefusalPhase::BeforeAuthorizationFunding
        }
        Some(reason)
            if reason.starts_with(
                "MustPrepay prepayment authorization failed before reserving an execution nonce:",
            ) =>
        {
            NativePaymentRefusalPhase::CallerBeforeAuthorizationFunding
        }
        Some(reason) if reason.contains("native flow observation is stale or absent") => {
            NativePaymentRefusalPhase::StaleNativeInputObservation
        }
        Some(reason) if reason.contains("native semantic remedy refused") => {
            NativePaymentRefusalPhase::SemanticInputRefused
        }
        Some(_) => NativePaymentRefusalPhase::OtherRefusal,
        None => NativePaymentRefusalPhase::NoRefusal,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_nested_unfunded_payment_reverses_before_external_authorization() -> TestResult {
    let calls = PaymentParticipantCalls::default();
    let adapter = Box::new(CountingDecliningPaymentAdapter {
        calls: calls.clone(),
    });
    let f = semantic::empty_import::native_fixture_from_empty_import_with_payment("write", adapter)
        .await?;
    let (semantic_runtime, request, _) = semantic::prepare(
        &f,
        "native-nested-unfunded-payment",
        SemanticOutputDispositionV1::ReturnValue,
    )?;
    let native_scope = f.runtime.scope().clone();
    // The host obtains this from the real signed Process journal. No context
    // constructor, origin rewrite or weakened source authority is used.
    let current = f.process.recovery_security_context("root")?;
    let captures_before = captured_invocations(&f)?;
    assert_eq!(calls.authorization.load(Ordering::SeqCst), 0);
    let budget = f.authority.budget_store();
    let selected_grant_index = request
        .capability
        .scope
        .grants
        .iter()
        .position(|grant| {
            grant.server_id == request.server_id && grant.tool_name == request.tool_name
        })
        .ok_or("native nested grant absent")?;
    let balance_before = budget
        .get_usage(&request.capability.id, selected_grant_index)?
        .map(|usage| {
            (
                usage.invocation_count,
                usage.total_cost_exposed,
                usage.total_cost_realized_spend,
            )
        })
        .unwrap_or((0, 0, 0));
    drop(semantic_runtime);
    drop(f.runtime);
    drop(f.process);
    let mut kernel =
        Arc::try_unwrap(f.kernel).map_err(|_| "native nested Kernel remains shared")?;
    let session = kernel.open_session_with_id(
        chio_core::session::SessionId::new(current.as_v1().session_id().as_str()),
        request.agent_id.clone(),
        vec![request.capability.clone()],
    )?;
    kernel.activate_session(&session)?;
    let operation = OperationContext::new(
        session,
        RequestId::new(&request.request_id),
        request.agent_id.clone(),
    );
    // Process invocation refreshes this observation through the fenced native
    // reader immediately before evaluation. Direct public hosts must do so too.
    let current = current_native_payment_context(&kernel, &f.authority, &native_scope, &current)?;
    kernel.set_security_invocation_context_authority(Arc::new(CurrentProcessPaymentContext {
        operation: operation.clone(),
        capability: request.capability.id.clone(),
        current,
    }));
    let call: ToolCallOperation = serde_json::from_value(serde_json::to_value(&request)?)?;
    let response = kernel
        .evaluate_tool_call_operation_with_nested_flow_client_async(
            &operation,
            &call,
            &mut RefuseNestedRequests,
        )
        .await?;
    assert_eq!(calls.authorization.load(Ordering::SeqCst), 0);
    assert_eq!(calls.completion.load(Ordering::SeqCst), 0);
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    assert_eq!(original_capture_count_at(&f.path)?, captures_before);
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert!(response.receipt.verify_signature()?);
    assert!(
        response.reason.as_deref() == Some("payment authorization failed: declined"),
        "native nested payment refusal phase: {:?}",
        native_payment_refusal_phase(response.reason.as_deref())
    );
    assert!(
        response
            .receipt
            .metadata
            .as_ref()
            .is_none_or(
                |metadata| metadata["financial"]["payment_authorization_ambiguous"] != true
            ),
        "known local refusal was recorded as an uncertain external authorization"
    );
    let (retained, original) = f
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("native nested payment original admission absent")?;
    original.validate_request_material(&request)?;
    original.validate_binding(retained.binding())?;
    assert!(original.native_security_authority_binding().is_some());
    assert_eq!(
        retained.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(retained.dispatch_commit().is_none());
    let hold = budget
        .get_budget_hold(
            retained
                .budget_hold_id()
                .ok_or("original native nested payment hold absent")?
                .as_str(),
        )?
        .ok_or("original native nested payment hold unavailable")?;
    assert_eq!(hold.remaining_exposure_units, 0);
    assert_eq!(
        hold.disposition,
        chio_kernel::budget_store::BudgetHoldDispositionView::Reversed
    );
    let quota = budget
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(
            &request.capability.id,
            u32::try_from(hold.grant_index)?,
        ))?
        .ok_or("original native nested payment quota absent")?;
    assert_eq!(
        (quota.reserved_invocations, quota.captured_invocations),
        (0, 0)
    );
    let balance_after = budget
        .get_usage(&request.capability.id, selected_grant_index)?
        .map(|usage| {
            (
                usage.invocation_count,
                usage.total_cost_exposed,
                usage.total_cost_realized_spend,
            )
        })
        .unwrap_or((0, 0, 0));
    assert_eq!(balance_after, balance_before);
    Ok(())
}

// Real native caller preflight with activated operation-owned approval custody.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_caller_unfunded_prepayment_releases_approval_before_authorization() -> TestResult {
    use chio_core::capability::governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
        GovernedTransactionIntent, MeteredBillingContext, MeteredBillingQuote,
        MeteredSettlementMode,
    };
    use chio_kernel::admission_operation::governed_approval_claim::{
        GovernedApprovalAuthorityBindingV1, GovernedApprovalClaimDisposition,
    };
    let calls = PaymentParticipantCalls::default();
    let adapter = Box::new(CountingDecliningPaymentAdapter {
        calls: calls.clone(),
    });
    let f = semantic::empty_import::native_fixture_from_empty_import_with_payment("write", adapter)
        .await?;
    let (semantic_runtime, mut request, mut selected) = semantic::prepare(
        &f,
        "native-caller-unfunded-prepayment",
        SemanticOutputDispositionV1::ReturnValue,
    )?;
    let native_scope = f.runtime.scope().clone();
    let current = f.process.recovery_security_context("root")?;
    let captures_before = captured_invocations(&f)?;
    let signer = Keypair::from_seed(&[140; 32]);
    assert!(
        request.capability.issuer == signer.public_key(),
        "caller control must use the actual fixture trust root"
    );
    let now = now_ms()? / 1000;
    let expires = now
        .checked_add(120)
        .ok_or("native caller quote expiry overflow")?;
    let intent = GovernedTransactionIntent {
        id: "native-caller-quoted-invocation".into(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "native caller quoted invocation".into(),
        max_amount: Some(chio_core::capability::scope::MonetaryAmount {
            units: 10,
            currency: "USD".into(),
        }),
        commerce: None,
        metered_billing: Some(MeteredBillingContext {
            settlement_mode: MeteredSettlementMode::MustPrepay,
            quote: MeteredBillingQuote {
                quote_id: "native-caller-original-quote".into(),
                provider: "local-participant-order-control".into(),
                billing_unit: "invocation".into(),
                quoted_units: 1,
                quoted_cost: chio_core::capability::scope::MonetaryAmount {
                    units: 10,
                    currency: "USD".into(),
                },
                issued_at: now,
                expires_at: Some(expires),
            },
            max_billed_units: Some(1),
            verified_outcome: None,
        }),
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    };
    let approval = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "native-caller-original-approval".into(),
            approver: signer.public_key(),
            subject: request.capability.subject.clone(),
            governed_intent_hash: intent.binding_hash()?,
            request_id: request.request_id.clone(),
            threshold_proposal_hash: None,
            issued_at: now,
            expires_at: expires,
            decision: GovernedApprovalDecision::Approved,
        },
        &signer,
    )?;
    assert!(approval.verify_signature()?);
    request.governed_intent = Some(intent);
    request.approval_token = Some(approval);
    // The complete final request, including governed approval semantics,
    // must be framed and endorsed before the runtime owners are dropped.
    selected.invocation.action =
        semantic_runtime.frame_action(&request, selected.invocation.action, &selected.payload)?;
    let mut endorsement = selected.invocation.endorsements.as_slice()[0]
        .body()
        .clone();
    endorsement.target = chio_security_types::semantic::SemanticEndorsementTargetV1::ExactAction {
        action: chio_core_types::recovery::semantic_action_digest(&selected.invocation.action)?,
    };
    endorsement.destination = selected.invocation.action.destination.clone();
    endorsement.influence = selected.invocation.action.influence;
    endorsement.issued_at_unix_ms = selected.invocation.action.issued_at_unix_ms;
    endorsement.valid_until_unix_ms = selected.invocation.action.valid_until_unix_ms;
    selected.invocation.endorsements = chio_security_types::recovery::BoundedList::new(vec![
        chio_core_types::recovery::SignedScopedEndorsementV1::sign(
            endorsement,
            &selected.endorser,
        )?,
    ])?;
    request.arguments = serde_json::to_value(&selected.invocation)?;
    assert!(
        selected.invocation.action.request_semantics
            == chio_kernel::recovery::semantic_request_semantics(&request)?,
        "caller action must bind every final governed request field"
    );
    drop(semantic_runtime);
    drop(f.runtime);
    drop(f.process);
    let mut kernel =
        Arc::try_unwrap(f.kernel).map_err(|_| "native caller Kernel remains shared")?;
    let executor_key = Keypair::from_seed(&[151; 32]);
    kernel.set_caller_executor(chio_kernel::caller_delivery::CallerExecutorIdentityV1 {
        executor_id: AdmissionIdentifier::try_new("executor_id", "native-payment-caller")?,
        public_key: executor_key.public_key(),
        key_epoch: 7,
    })?;
    let nonce_config = chio_kernel::execution_nonce::ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 16,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        nonce_config,
        Box::new(
            chio_store_sqlite::SqliteExecutionNonceStore::open_with_capacity(
                f.path.join("caller-nonces.db"),
                16,
            )?,
        ),
    );
    let source_path = f.path.join("caller-approvals.db");
    drop(
        chio_store_sqlite::SqliteGovernedApprovalReplayStore::open_with_capacity(&source_path, 16)?,
    );
    let approval_source = Arc::new(chio_store_sqlite::SqliteGovernedApprovalReplaySource::open(
        &source_path,
    )?);
    let store = f.authority.admission_operation_store();
    let fence = f.authority.mutation_fence();
    let authority =
        AdmissionIdentifier::try_new("approval_authority_id", "native-payment-caller-approval")?;
    let expected = store.expect_governed_approval_replay_source(
        &AdmissionIdentifier::try_new("source_id", "native-payment-caller-approval-source")?,
        &authority,
        approval_source.as_ref(),
        &fence,
        now_ms()?,
    )?;
    let imported = store.import_governed_approval_replay_source(
        &authority,
        expected.expectation_id(),
        approval_source.as_ref(),
        &fence,
        now_ms()?,
    )?;
    let approval_binding =
        GovernedApprovalAuthorityBindingV1::new(authority, imported.expectation_id().clone());
    store.activate_governed_approval_replay_source(
        &approval_binding,
        approval_source.as_ref(),
        &fence,
        now_ms()?,
    )?;
    kernel.set_operation_owned_governed_approval_source(approval_binding, approval_source)?;
    let budget = f.authority.budget_store();
    let grant_index = request
        .capability
        .scope
        .grants
        .iter()
        .position(|grant| {
            grant.server_id == request.server_id && grant.tool_name == request.tool_name
        })
        .ok_or("native caller grant absent")?;
    let balance_before = budget
        .get_usage(&request.capability.id, grant_index)?
        .map(|usage| {
            (
                usage.invocation_count,
                usage.total_cost_exposed,
                usage.total_cost_realized_spend,
            )
        })
        .unwrap_or((0, 0, 0));
    let current = current_native_payment_context(&kernel, &f.authority, &native_scope, &current)?;
    // Native callers first obtain a non-executable operation-bound nonce.
    // The public API leaves the operation Prepared and requires a fresh host
    // flow observation before a second call can reserve executable permission.
    let preflight =
        kernel.reserve_caller_execution_blocking_with_security_context(&request, &current)?;
    assert_eq!(preflight.verdict, Verdict::Allow);
    assert!(preflight.output.is_none());
    assert!(preflight.receipt.verify_signature()?);
    assert!(
        preflight.receipt.kernel_key == kernel.receipt_signing_public_key(),
        "caller preflight receipt must use the actual selected Kernel signer"
    );
    assert_eq!(calls.authorization.load(Ordering::SeqCst), 0);
    assert_eq!(calls.completion.load(Ordering::SeqCst), 0);
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    assert_eq!(original_capture_count_at(&f.path)?, captures_before);
    let issued = preflight
        .execution_nonce
        .as_deref()
        .ok_or("native caller preflight omitted its operation-bound nonce")?;
    let (prepared, prepared_original) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("native caller preflight original admission absent")?;
    prepared_original.validate_binding(prepared.binding())?;
    prepared_original.validate_request_material(&request)?;
    assert_eq!(prepared.state(), AdmissionOperationState::Prepared);
    assert!(prepared.dispatch_commit().is_none());
    assert!(prepared_original
        .native_security_authority_binding()
        .is_some());
    chio_kernel::admission_operation::AdmissionExecutionNonceReservationV1::verify(
        &prepared,
        &prepared_original,
        issued,
        &kernel.receipt_signing_public_key(),
        now_ms()?,
    )?;
    let retained_issuance = store
        .load_execution_nonce_issuance(prepared.binding().operation_id(), &fence, now_ms()?)?
        .ok_or("native caller preflight nonce was not durably issued")?;
    assert!(
        retained_issuance.signed_nonce() == issued,
        "caller preflight must return the exact persisted signed nonce"
    );
    let prepared_operation_id = prepared.binding().operation_id().clone();
    request.execution_nonce = Some(issued.clone());
    assert!(
        selected.invocation.action.request_semantics
            == chio_kernel::recovery::semantic_request_semantics(&request)?,
        "presenting the issued nonce must preserve final semantic framing"
    );
    let current = current_native_payment_context(&kernel, &f.authority, &native_scope, &current)?;
    let reservation =
        kernel.reserve_caller_execution_blocking_with_security_context(&request, &current)?;
    // Reserving is deliberately non-executable and precedes the rail gate.
    // Actual committed start is the boundary that must refuse absent funding.
    assert_eq!(reservation.verdict, Verdict::Allow);
    assert!(reservation.output.is_none());
    assert!(reservation.receipt.verify_signature()?);
    assert_eq!(calls.authorization.load(Ordering::SeqCst), 0);
    assert_eq!(calls.completion.load(Ordering::SeqCst), 0);
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    assert_eq!(original_capture_count_at(&f.path)?, captures_before);
    let (ready, ready_original) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("native caller reservation original admission absent")?;
    ready_original.validate_binding(ready.binding())?;
    ready_original.validate_request_material(&request)?;
    assert!(
        ready.binding().operation_id() == &prepared_operation_id,
        "caller reservation must retain the real preflight operation"
    );
    assert_eq!(ready.state(), AdmissionOperationState::ReadyToDispatch);
    assert!(ready.dispatch_commit().is_none());
    let reserved = store
        .load_execution_nonce_reservation(ready.binding().operation_id(), &fence, now_ms()?)?
        .ok_or("native caller reservation nonce absent")?;
    assert!(
        ready.execution_nonce_id() == Some(reserved.nonce_id()),
        "ready reservation must own its exact retained nonce"
    );
    let presented = reservation
        .execution_nonce
        .as_deref()
        .ok_or("native caller reservation omitted its retained nonce")?;
    assert!(
        reserved.signed_nonce() == presented,
        "caller reservation must return its actual retained signed nonce"
    );
    chio_kernel::admission_operation::AdmissionExecutionNonceReservationV1::verify(
        &ready,
        &ready_original,
        presented,
        &kernel.receipt_signing_public_key(),
        now_ms()?,
    )?;
    let current = current_native_payment_context(&kernel, &f.authority, &native_scope, &current)?;
    let response = match kernel.start_caller_execution_blocking_with_security_context(
        presented,
        &request.arguments,
        chio_kernel::CallerStartCredentials {
            approval_token: request.approval_token.clone(),
            approval_tokens: request.approval_tokens.clone(),
            threshold_approval_proposal: request.threshold_approval_proposal.clone(),
            dpop_proof: request.dpop_proof.clone(),
            declassification_grant: None,
        },
        &current,
    )? {
        chio_kernel::CallerStartResponse::Denied(response) => *response,
        chio_kernel::CallerStartResponse::Authorized(_) => {
            return Err("native caller start authorized unfunded external execution".into());
        }
    };
    assert_eq!(calls.authorization.load(Ordering::SeqCst), 0);
    assert_eq!(calls.completion.load(Ordering::SeqCst), 0);
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    assert_eq!(original_capture_count_at(&f.path)?, captures_before);
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert!(response.execution_nonce.is_none());
    assert!(response.receipt.verify_signature()?);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason == "payment authorization failed: declined"),
        "native caller payment refusal phase: {:?}",
        native_payment_refusal_phase(response.reason.as_deref())
    );
    assert!(
        response
            .receipt
            .metadata
            .as_ref()
            .is_none_or(
                |metadata| metadata["financial"]["payment_authorization_ambiguous"] != true
            ),
        "native caller local refusal was recorded as an uncertain external authorization"
    );
    let (operation, original) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("native caller original admission absent")?;
    original.validate_binding(operation.binding())?;
    original.validate_request_material(&request)?;
    assert!(original.native_security_authority_binding().is_some());
    assert!(
        operation.binding().operation_id() == &prepared_operation_id,
        "caller reservation must finish the same nonce-preflight operation"
    );
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    // The immutable reservation remains historical DATA. Compensation must
    // refuse a new start; deleting its identity would erase the earlier work.
    assert!(
        operation.execution_nonce_id() == Some(reserved.nonce_id()),
        "caller compensation must preserve its original nonce reservation"
    );
    assert!(
        store
            .load_caller_dispatch_context(operation.binding().operation_id(), &fence, now_ms()?)?
            .is_none(),
        "unfunded caller start must not retain a dispatch snapshot"
    );
    let (_, approvals) = store
        .load_governed_approval_claim_history(
            operation.binding().operation_id(),
            &fence,
            now_ms()?,
        )?
        .ok_or("native caller approval custody absent")?;
    assert!(
        !approvals.is_empty(),
        "caller control never reserved its real approval"
    );
    assert!(
        approvals
            .iter()
            .all(|claim| claim.disposition
                == GovernedApprovalClaimDisposition::ReleasedBeforeDispatch),
        "caller local refusal retained a governed approval credential"
    );
    let hold = budget
        .get_budget_hold(
            operation
                .budget_hold_id()
                .ok_or("native caller original hold absent")?
                .as_str(),
        )?
        .ok_or("native caller original hold unavailable")?;
    assert_eq!(hold.remaining_exposure_units, 0);
    assert_eq!(
        hold.disposition,
        chio_kernel::budget_store::BudgetHoldDispositionView::Reversed
    );
    let quota = budget
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(
            &request.capability.id,
            u32::try_from(grant_index)?,
        ))?
        .ok_or("native caller original quota absent")?;
    assert_eq!(
        (quota.reserved_invocations, quota.captured_invocations),
        (0, 0)
    );
    let balance_after = budget
        .get_usage(&request.capability.id, grant_index)?
        .map(|usage| {
            (
                usage.invocation_count,
                usage.total_cost_exposed,
                usage.total_cost_realized_spend,
            )
        })
        .unwrap_or((0, 0, 0));
    assert_eq!(balance_after, balance_before);
    Ok(())
}

#[tokio::test]
async fn native_original_freezes_the_selected_bounded_materializer_before_capture() -> TestResult {
    use chio_kernel::admission_operation::{
        NativeOutputEnvelopeBoundsV1, NativeOutputRetentionProfileV1,
    };
    let profile = NativeOutputRetentionProfileV1::new(NativeOutputEnvelopeBoundsV1::new(
        1024 * 1024,
        1024 * 1024,
        1024 * 1024,
        1024 * 1024,
        1,
    )?);
    let expected = profile.materialization_identity()?;
    let f =
        semantic::empty_import::native_fixture_from_empty_import_with_retention("write", &profile)
            .await?;
    let key = "original-bounded-native-materializer-selection";
    let (runtime, request, _) =
        semantic::prepare(&f, key, SemanticOutputDispositionV1::ReturnValue)?;
    let physical_context = f.process.recovery_security_context("root")?;
    let current_context = current_native_payment_context(
        &f.kernel,
        &f.authority,
        f.runtime.scope(),
        &physical_context,
    )?;
    let preview = f
        .kernel
        .recovery_native_identity(&request, &current_context)?;
    let before = captured_invocations(&f)?;
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    let result = runtime
        .execute_step(&f.process, "root", key, &request)
        .await;
    assert!(
        result.is_err()
            || result.as_ref().is_ok_and(|response| {
                response.verdict == Verdict::Deny && response.output.is_none()
            }),
        "unfunded selected profile did not refuse before provider dispatch"
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    assert_eq!(captured_invocations(&f)?, before);
    let (operation, original) = f
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("genuine selected native original is absent")?;
    original.validate_binding(operation.binding())?;
    original.validate_request_material(&request)?;
    assert!(
        preview.binding() == operation.binding(),
        "fresh native identity preview differs from actual original admission",
    );
    assert!(original.native_security_authority_binding().is_some());
    assert!(
        original.native_output_retention() == Some(&profile),
        "actual native original did not retain the explicit selected profile"
    );
    assert!(operation.dispatch_commit().is_none());
    assert!(operation.native_dispatch_ledger_digest().is_none());
    // Profile selection is DATA, and cannot fund this capture. Nevertheless,
    // its immutable producer must be frozen now, before any provider effect.
    assert!(
        original.post_return_steps() == [expected],
        "actual selected native original froze a different materializer program"
    );
    Ok(())
}

#[path = "output_retention/cold_read_bounds.rs"]
mod cold_read_bounds;

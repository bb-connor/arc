use super::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Waker};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Clone, Copy)]
enum OwnedOutcome {
    Complete,
    CancelPreparation,
    CancelDispatch,
    Revoke,
    WrongServer,
}

struct OwnedFactory {
    outcome: OwnedOutcome,
    live: Arc<AtomicU64>,
    calls: Arc<AtomicU64>,
    revocations: Arc<crate::InMemoryRevocationStore>,
    capability: String,
}

struct OwnedConnection {
    outcome: OwnedOutcome,
    live: Arc<AtomicU64>,
    calls: Arc<AtomicU64>,
}

impl Drop for OwnedConnection {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for OwnedFactory {
    fn server_id(&self) -> &str {
        "durable-server"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::ToolServerError(
            "factory must never dispatch".into(),
        ))
    }
    async fn prepare_invocation_connection(
        &self,
        _: &ToolDispatchContext,
    ) -> Result<Option<Arc<dyn ToolServerConnection>>, KernelError> {
        self.live.fetch_add(1, Ordering::SeqCst);
        let child = Arc::new(OwnedConnection {
            outcome: self.outcome,
            live: self.live.clone(),
            calls: self.calls.clone(),
        });
        match self.outcome {
            OwnedOutcome::CancelPreparation => std::future::pending::<()>().await,
            OwnedOutcome::Revoke => {
                self.revocations
                    .revoke(&self.capability)
                    .map_err(|error| KernelError::Internal(error.to_string()))?;
            }
            _ => {}
        }
        Ok(Some(child))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for OwnedConnection {
    fn server_id(&self) -> &str {
        if matches!(self.outcome, OwnedOutcome::WrongServer) {
            "substituted"
        } else {
            "durable-server"
        }
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if matches!(self.outcome, OwnedOutcome::CancelDispatch) {
            std::future::pending::<()>().await;
        }
        Ok(serde_json::json!({"owned": true}))
    }
}

#[test]
fn invocation_owned_connections_close_on_completion_denial_and_cancellation() -> TestResult {
    for nested in [false, true] {
        for outcome in [
            OwnedOutcome::Complete,
            OwnedOutcome::CancelPreparation,
            OwnedOutcome::CancelDispatch,
            OwnedOutcome::Revoke,
            OwnedOutcome::WrongServer,
        ] {
            let (mut kernel, request, store, calls) = durable_admission_fixture("owned-delivery");
            let live = Arc::new(AtomicU64::new(0));
            let revocations = Arc::new(crate::InMemoryRevocationStore::new());
            kernel.set_revocation_store_handle(revocations.clone());
            kernel.register_tool_server(Box::new(OwnedFactory {
                outcome,
                live: live.clone(),
                calls: calls.clone(),
                revocations,
                capability: request.capability.id.clone(),
            }));
            let session = kernel.open_session("owned-parent".into(), Vec::new())?;
            kernel.activate_session(&session)?;
            let parent = make_operation_context(&session, "owned-parent-request", "owned-parent");
            kernel.begin_session_request(&parent, OperationKind::ToolCall, true)?;
            let mut client = NoopNestedFlowClient;
            let mut evaluation: Pin<
                Box<dyn Future<Output = Result<ToolCallResponse, KernelError>> + '_>,
            > = if nested {
                Box::pin(kernel.evaluate_tool_call_with_nested_flow_client_async(
                    &parent,
                    &request,
                    &mut client,
                    None,
                ))
            } else {
                Box::pin(kernel.evaluate_tool_call(&request))
            };
            if matches!(
                outcome,
                OwnedOutcome::CancelPreparation | OwnedOutcome::CancelDispatch
            ) {
                assert!(evaluation
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
                assert_eq!(live.load(Ordering::SeqCst), 1);
                let committed =
                    matches!(outcome, OwnedOutcome::CancelDispatch).then(|| store.operation());
                drop(evaluation);
                if let Some(committed) = committed {
                    assert_eq!(
                        committed.state(),
                        AdmissionOperationState::DispatchCommitted
                    );
                    assert_eq!(
                        store.operation(),
                        committed,
                        "Drop retains the original saga for its real recovery driver"
                    );
                    assert!(kernel.receipt_log().is_empty());
                    kernel.reconcile_recoverable_admissions()?;
                    let terminal = assert_original_unknown_incident(
                        &store,
                        &request,
                        &chio_core::receipt::decision::Decision::Deny {
                            reason: "dispatch outcome is unknown after recovery".into(),
                            guard: "kernel".into(),
                        },
                    );
                    assert_eq!(terminal.binding(), committed.binding());
                    assert_eq!(terminal.dispatch_commit(), committed.dispatch_commit());
                    assert_eq!(kernel.receipt_log().len(), 1);
                    let receipt = store
                        .state
                        .lock()
                        .map_err(|_| "test admission state lock")?
                        .receipt
                        .clone()
                        .ok_or("missing original unknown-outcome receipt")?;
                    kernel.reconcile_recoverable_admissions()?;
                    assert_eq!(
                        store.operation(),
                        terminal,
                        "recovery cannot replace the terminal projection"
                    );
                    assert_unknown_replay(
                        kernel.evaluate_tool_call_blocking(&request),
                        &terminal,
                        &store,
                    );
                    assert_same_receipt(
                        store
                            .state
                            .lock()
                            .map_err(|_| "test admission state lock")?
                            .receipt
                            .as_ref()
                            .ok_or("missing canonical unknown-outcome receipt")?,
                        &receipt,
                    );
                    assert_eq!(kernel.receipt_log().len(), 1);
                }
                assert_eq!(
                    store.operation().state(),
                    if matches!(outcome, OwnedOutcome::CancelDispatch) {
                        AdmissionOperationState::OutcomeUnknownAfterDispatch
                    } else {
                        AdmissionOperationState::CompensatedBeforeDispatch
                    }
                );
            } else {
                let response = block_on_async_tool_dispatch(evaluation)?;
                assert_eq!(
                    response.verdict,
                    if matches!(outcome, OwnedOutcome::Complete) {
                        Verdict::Allow
                    } else {
                        Verdict::Deny
                    },
                    "{response:?}"
                );
            }
            assert_eq!(
                live.load(Ordering::SeqCst),
                0,
                "invocation retained its connection after termination"
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                u64::from(matches!(
                    outcome,
                    OwnedOutcome::Complete | OwnedOutcome::CancelDispatch
                ))
            );
        }
    }
    Ok(())
}

enum PreparationMutation {
    None,
    Revoke(Arc<crate::InMemoryRevocationStore>, String),
    Reject,
    InvalidateAdmission(Arc<AtomicBool>),
}

struct PreparingServer {
    mutation: PreparationMutation,
    yield_once: bool,
    preparations: Arc<AtomicU64>,
    invocations: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for PreparingServer {
    fn server_id(&self) -> &str {
        "durable-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".to_owned()]
    }

    async fn prepare_delivery(&self, _: &ToolDispatchContext) -> Result<(), KernelError> {
        self.preparations.fetch_add(1, Ordering::SeqCst);
        let mut yielded = !self.yield_once;
        std::future::poll_fn(|cx| {
            if yielded {
                std::task::Poll::Ready(())
            } else {
                yielded = true;
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
        })
        .await;
        match &self.mutation {
            PreparationMutation::None => {}
            PreparationMutation::Revoke(store, capability) => {
                store
                    .revoke(capability)
                    .map_err(|error| KernelError::Internal(error.to_string()))?;
            }
            PreparationMutation::Reject => {
                return Err(KernelError::ToolServerError(
                    "injected unreachable server".to_owned(),
                ));
            }
            PreparationMutation::InvalidateAdmission(live) => live.store(false, Ordering::SeqCst),
        }
        Ok(())
    }

    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"mutated": true}))
    }
}

fn assert_delivery_revocation_denied(nested: bool) -> TestResult {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("revoke-during-delivery-preparation");
    let revocations = Arc::new(crate::InMemoryRevocationStore::new());
    kernel.set_revocation_store_handle(revocations.clone());
    let preparations = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(PreparingServer {
        mutation: PreparationMutation::Revoke(revocations, request.capability.id.clone()),
        yield_once: true,
        preparations: preparations.clone(),
        invocations: invocations.clone(),
    }));
    let response = if nested {
        let session_id = kernel.open_session("delivery-parent".to_owned(), Vec::new())?;
        kernel.activate_session(&session_id)?;
        let parent =
            make_operation_context(&session_id, "delivery-parent-request", "delivery-parent");
        kernel.begin_session_request(&parent, OperationKind::ToolCall, true)?;
        kernel.evaluate_tool_call_with_nested_flow_client(
            &parent,
            &request,
            &mut NoopNestedFlowClient,
            None,
        )?
    } else {
        kernel.evaluate_tool_call_blocking(&request)?
    };
    assert_eq!(preparations.load(Ordering::SeqCst), 1);
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        0,
        "revoked capability reached the tool"
    );
    assert_eq!(response.verdict, Verdict::Deny, "{response:?}");
    assert!(response.receipt.verify_integrity_embedded_key()?);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    Ok(())
}

#[test]
fn remote_delivery_rechecks_revocation_after_preparation() -> TestResult {
    assert_delivery_revocation_denied(false)
}

#[test]
fn nested_remote_delivery_rechecks_revocation_after_preparation() -> TestResult {
    assert_delivery_revocation_denied(true)
}

#[derive(Clone, Copy)]
enum SuspendedOutcome {
    Allow,
    Expire,
    Revoke,
    Drop,
    Refuse,
}

fn suspended_delivery(nested: bool, outcome: SuspendedOutcome) -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(current_unix_timestamp());
    let (mut kernel, request, store, invocations) = durable_admission_fixture("suspended-delivery");
    let preparations = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(PreparingServer {
        mutation: if matches!(outcome, SuspendedOutcome::Refuse) {
            PreparationMutation::Reject
        } else {
            PreparationMutation::None
        },
        yield_once: true,
        preparations: preparations.clone(),
        invocations: invocations.clone(),
    }));
    let session_id = kernel.open_session("delivery-parent".to_owned(), Vec::new())?;
    kernel.activate_session(&session_id)?;
    let parent = make_operation_context(&session_id, "delivery-parent-request", "delivery-parent");
    kernel.begin_session_request(&parent, OperationKind::ToolCall, true)?;
    let mut client = NoopNestedFlowClient;
    let mut evaluation: Pin<Box<dyn Future<Output = Result<ToolCallResponse, KernelError>> + '_>> =
        if nested {
            Box::pin(kernel.evaluate_tool_call_with_nested_flow_client_async(
                &parent,
                &request,
                &mut client,
                None,
            ))
        } else {
            Box::pin(kernel.evaluate_tool_call(&request))
        };
    let first_poll = evaluation
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()));
    assert!(
        first_poll.is_pending(),
        "delivery preparation: {first_poll:?}"
    );
    assert_eq!(preparations.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::BudgetAuthorized
    );
    if matches!(outcome, SuspendedOutcome::Drop) {
        drop(evaluation);
        assert_eq!(
            store.operation().state(),
            AdmissionOperationState::CompensatedBeforeDispatch
        );
        let persisted = store
            .state
            .lock()
            .map_err(|_| "state lock")?
            .receipt
            .clone()
            .ok_or("persisted compensation receipt")?;
        let logged = kernel.receipt_log().receipts();
        assert_eq!(logged.len(), 1);
        assert_eq!(
            chio_core::canonical::canonical_json_bytes(&logged[0])?,
            chio_core::canonical::canonical_json_bytes(&persisted)?
        );
        assert!(matches!(
            persisted.decision,
            Some(chio_core::receipt::decision::Decision::Cancelled { .. })
        ));
        assert_eq!(
            persisted
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.pointer("/chio_runtime/identity_disposition")),
            Some(&serde_json::json!("terminal"))
        );
        return Ok(());
    }
    let _expired_clock = matches!(outcome, SuspendedOutcome::Expire)
        .then(|| chio_test_support::clock::scope_unix_secs(request.capability.expires_at));
    if matches!(outcome, SuspendedOutcome::Revoke) {
        kernel.revoke_capability(&request.capability.id)?;
    }
    let response = block_on_async_tool_dispatch(evaluation)?;
    assert!(response.receipt.verify_integrity_embedded_key()?);
    if matches!(outcome, SuspendedOutcome::Allow) {
        assert_eq!(response.verdict, Verdict::Allow, "{response:?}");
        assert_eq!(invocations.load(Ordering::SeqCst), 1);
        assert_eq!(
            store.operation().state(),
            AdmissionOperationState::Completed
        );
    } else {
        assert_eq!(response.verdict, Verdict::Deny, "{response:?}");
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        assert_eq!(
            store.operation().state(),
            AdmissionOperationState::CompensatedBeforeDispatch
        );
        let reason = response.reason.as_deref().unwrap_or_default();
        let expected = if matches!(outcome, SuspendedOutcome::Expire) {
            "expired"
        } else if matches!(outcome, SuspendedOutcome::Revoke) {
            "revoked"
        } else {
            "could not prepare delivery"
        };
        assert!(reason.contains(expected), "unexpected denial: {reason}");
    }
    Ok(())
}

#[test]
fn prepared_delivery_with_unchanged_authority_dispatches_once() -> TestResult {
    for nested in [false, true] {
        suspended_delivery(nested, SuspendedOutcome::Allow)?;
    }
    Ok(())
}

#[test]
fn delivery_wait_samples_expiry_after_readiness() -> TestResult {
    for nested in [false, true] {
        suspended_delivery(nested, SuspendedOutcome::Expire)?;
    }
    Ok(())
}

#[test]
fn dropped_delivery_preparation_compensates_before_dispatch() -> TestResult {
    for nested in [false, true] {
        suspended_delivery(nested, SuspendedOutcome::Drop)?;
    }
    Ok(())
}

#[test]
fn kernel_revocation_during_delivery_wait_prevents_tool_execution() -> TestResult {
    for nested in [false, true] {
        suspended_delivery(nested, SuspendedOutcome::Revoke)?;
    }
    Ok(())
}

#[test]
fn refused_delivery_preparation_compensates_before_dispatch() -> TestResult {
    for nested in [false, true] {
        suspended_delivery(nested, SuspendedOutcome::Refuse)?;
    }
    Ok(())
}

struct MutableAdmission(Arc<AtomicBool>);

impl RuntimeAdmissionHook for MutableAdmission {
    fn name(&self) -> &str {
        "mutable-delivery-admission"
    }

    fn evaluate(
        &self,
        _: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        Ok(RuntimeAdmissionDecision::allow(None))
    }

    fn revalidate_before_dispatch(
        &self,
        _: &RuntimeAdmissionRevalidationContext<'_>,
    ) -> Result<(), KernelError> {
        if self.0.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(KernelError::GuardDenied(
                "admission changed during delivery preparation".to_owned(),
            ))
        }
    }
}

#[test]
fn immediately_ready_delivery_still_revalidates_runtime_admission() -> TestResult {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("immediately-ready-delivery");
    let live = Arc::new(AtomicBool::new(true));
    let preparations = Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(Arc::new(MutableAdmission(live.clone())));
    kernel.register_tool_server(Box::new(PreparingServer {
        mutation: PreparationMutation::InvalidateAdmission(live),
        yield_once: false,
        preparations: preparations.clone(),
        invocations: invocations.clone(),
    }));
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(preparations.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(response.verdict, Verdict::Deny, "{response:?}");
    assert!(response.receipt.verify_integrity_embedded_key()?);
    assert!(response
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("admission changed during delivery preparation"));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    Ok(())
}

struct LaunchedServer {
    launch: chio_core::receipt::body::ChioReceipt,
    invocations: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for LaunchedServer {
    fn server_id(&self) -> &str {
        "durable-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".to_owned()]
    }

    fn prepared_native_launch_receipt(&self) -> Option<chio_core::receipt::body::ChioReceipt> {
        Some(self.launch.clone())
    }

    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"mutated": true}))
    }
}

fn launch_receipt(
    state: &str,
    decision: Option<chio_core::receipt::decision::Decision>,
) -> Result<chio_core::receipt::body::ChioReceipt, Box<dyn std::error::Error>> {
    let keypair = chio_core::crypto::Keypair::from_seed(&[47; 32]);
    let (receipt_kind, boundary_class, observation_outcome, trust_level) = if decision.is_some() {
        (
            chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            chio_core::receipt::kinds::BoundaryClass::Prevent,
            None,
            chio_core::receipt::kinds::TrustLevel::Mediated,
        )
    } else {
        (
            chio_core::receipt::kinds::ReceiptKind::TraceObservation,
            chio_core::receipt::kinds::BoundaryClass::DetectOnly,
            Some(chio_core::receipt::kinds::ObservationOutcome::Observed),
            chio_core::receipt::kinds::TrustLevel::Verified,
        )
    };
    Ok(chio_core::receipt::body::ChioReceipt::sign(
        chio_core::receipt::body::ChioReceiptBody {
            id: format!("launch-{state}"),
            timestamp: 1,
            capability_id: "launch-capability".to_owned(),
            tool_server: "durable-server".to_owned(),
            tool_name: "launch".to_owned(),
            action: chio_core::receipt::decision::ToolCallAction::from_parameters(
                serde_json::json!({"attempt_id": "attempt-1", "stage": "enforcement", "state": state}),
            )?,
            decision,
            receipt_kind,
            boundary_class,
            observation_outcome,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::ChioInternal,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::Summary,
            actor_chain: Vec::new(),
            content_hash: sha256_hex(b"launch-content"),
            policy_hash: sha256_hex(b"launch-policy"),
            evidence: Vec::new(),
            metadata: None,
            trust_level,
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )?)
}

#[test]
fn long_lived_server_binds_its_fully_enforced_launch_at_dispatch() -> TestResult {
    let (mut kernel, request, store, invocations) = durable_admission_fixture("launched-delivery");
    let launch = launch_receipt(
        "fully_enforced",
        Some(chio_core::receipt::decision::Decision::Allow),
    )?;
    kernel.register_tool_server(Box::new(LaunchedServer {
        launch: launch.clone(),
        invocations: invocations.clone(),
    }));
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{response:?}");
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or("receipt metadata")?;
    assert_eq!(
        metadata["native_launch"],
        serde_json::json!({
            "receipt_id": launch.id,
            "receipt_sha256": sha256_hex(&chio_core::canonical_json_bytes(&launch)?),
        })
    );
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    Ok(())
}

#[test]
fn launch_without_full_enforcement_is_never_bound_and_denies_dispatch() -> TestResult {
    let deny = || chio_core::receipt::decision::Decision::Deny {
        reason: "native cage launch did not reach full enforcement".to_owned(),
        guard: "chio-cage".to_owned(),
    };
    for (state, decision) in [
        ("bootstrap_failed", Some(deny())),
        ("rejected", Some(deny())),
        ("exited", None),
        ("fully_enforced", Some(deny())),
    ] {
        let (mut kernel, request, store, invocations) =
            durable_admission_fixture("unenforced-delivery");
        kernel.register_tool_server(Box::new(LaunchedServer {
            launch: launch_receipt(state, decision)?,
            invocations: invocations.clone(),
        }));
        let response = kernel.evaluate_tool_call_blocking(&request)?;
        assert_eq!(response.verdict, Verdict::Deny, "{state}: {response:?}");
        assert_eq!(invocations.load(Ordering::SeqCst), 0, "{state}");
        assert!(response
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("not fully enforced"));
        assert!(response
            .receipt
            .metadata
            .as_ref()
            .is_none_or(|metadata| metadata.get("native_launch").is_none()));
        assert_eq!(
            store.operation().state(),
            AdmissionOperationState::CompensatedBeforeDispatch
        );
    }
    Ok(())
}

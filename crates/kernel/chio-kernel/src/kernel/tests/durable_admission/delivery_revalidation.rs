use super::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Waker};

type TestResult = Result<(), Box<dyn std::error::Error>>;

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
    assert!(response.receipt.verify_signature()?);
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
    let _clock = crate::scope_fixed_runtime_for_current_thread(request.capability.issued_at, []);
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
    assert!(evaluation
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
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
        assert!(kernel.receipt_log().receipts().is_empty());
        return Ok(());
    }
    let _expired_clock = matches!(outcome, SuspendedOutcome::Expire)
        .then(|| crate::scope_fixed_runtime_for_current_thread(request.capability.expires_at, []));
    if matches!(outcome, SuspendedOutcome::Revoke) {
        kernel.revoke_capability(&request.capability.id)?;
    }
    let response = block_on_async_tool_dispatch(evaluation)?;
    assert!(response.receipt.verify_signature()?);
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
    assert!(response.receipt.verify_signature()?);
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

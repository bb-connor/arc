// Observe the real SQLite native capture refusal without changing its outcome.
use super::*;
use std::sync::{Mutex, PoisonError};
use tracing::field::{Field, Visit};
use tracing_subscriber::{layer::Context, prelude::*, Layer, Registry};

#[derive(Clone, Default)]
struct CaptureLines(Arc<Mutex<Vec<(String, String)>>>);

#[derive(Default)]
struct CaptureFields {
    stage: Option<String>,
    category: Option<String>,
}

impl Visit for CaptureFields {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "native_capture_stage" => self.stage = Some(value.to_owned()),
            "native_capture_category" => self.category = Some(value.to_owned()),
            _ => {}
        }
    }

    fn record_debug(&mut self, _: &Field, _: &dyn std::fmt::Debug) {}
}

impl<S: tracing::Subscriber> Layer<S> for CaptureLines {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        if event.metadata().target() != "chio::native_capture" {
            return;
        }
        let mut fields = CaptureFields::default();
        event.record(&mut fields);
        if let (Some(stage), Some(category)) = (fields.stage, fields.category) {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((stage, category));
        }
    }
}

#[test]
fn native_capture_store_diagnostic_commit_runtime_expiry_keeps_physical_rollback() -> TestResult {
    let mut fixture = Fixture::combined_native_credentials()?;
    fixture.clock.advance_to(now_ms()? + 2)?;
    fixture
        .authority
        .admission_operation_store()
        .inject_native_capture_runtime_expiry_for_test({
            let clock = fixture.clock.clone();
            move |until| clock.advance_to(until).map_err(|error| error.to_string())
        })?;
    let resolver = Arc::new(NativeFlowResolver::new(
        fixture.binding.clone(),
        super::super::super::registry(false, InformationLabel::bottom())?,
        Arc::new(CountingEmptyClassifier::new()),
        fixture.clock.clone(),
        flow_config(),
    )?);
    fixture
        .kernel
        .set_security_pre_dispatch_hook(resolver.clone());
    fixture
        .kernel
        .install_native_capture_checkpoint_hook(Arc::new(move |authority| {
            resolver
                .prepare_dispatch(authority.prepare_egress()?)
                .and_then(|planned| planned.capture_invocation(authority))
                .map(|_| ())
                .map_err(|error| KernelError::GuardDenied(error.to_string()))
        }));
    let lines = CaptureLines::default();
    let response = {
        let _subscriber = tracing::subscriber::set_default(Registry::default().with(lines.clone()));
        fixture
            .kernel
            .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?
    };
    fixture
        .authority
        .admission_operation_store()
        .clear_native_capture_runtime_expiry_for_test()?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fence,
            fixture.clock.snapshot(),
        )?
        .ok_or("original refused operation")?;
    assert_eq!(operation.state(), AdmissionOperationState::CapturePending);
    assert!(operation.dispatch_commit().is_none());
    assert!(operation.native_dispatch_ledger_digest().is_none());
    assert!(store
        .load_native_dispatch_capture(
            operation.binding().operation_id(),
            &fence,
            fixture.clock.snapshot()
        )?
        .is_none());
    let quota = fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
        .ok_or("original quota reservation")?;
    assert_eq!(
        (quota.reserved_invocations, quota.captured_invocations),
        (1, 0)
    );
    let observed = lines.0.lock().map_err(|_| "trace lock poisoned")?;
    assert!(
        observed.contains(&("commit_runtime_expired".to_owned(), "invariant".to_owned())),
        "physical transaction lost its actual fixed refusal: {observed:?}"
    );
    Ok(())
}

#[test]
fn native_capture_store_diagnostic_sqlite_aborts_keep_distinct_physical_stages() -> TestResult {
    use chio_store_sqlite::admission_operation_store::NativeDispatchCaptureTestFault as Fault;
    for (fault, stage, category) in [
        (Fault::AfterBudgetCapture, "budget_mutation", "sqlite"),
        (
            Fault::AfterOperationCapture,
            "admission_advance",
            "unavailable",
        ),
    ] {
        let mut fixture = super::super::super::public_fixture()?;
        fixture
            .authority
            .admission_operation_store()
            .inject_native_dispatch_capture_failure_for_test(fault)?;
        let resolver = Arc::new(NativeFlowResolver::new(
            fixture.binding.clone(),
            super::super::super::registry(false, InformationLabel::bottom())?,
            Arc::new(CountingEmptyClassifier::new()),
            fixture.clock.clone(),
            flow_config(),
        )?);
        fixture
            .kernel
            .set_security_pre_dispatch_hook(resolver.clone());
        fixture
            .kernel
            .install_native_capture_checkpoint_hook(Arc::new(move |authority| {
                resolver
                    .prepare_dispatch(authority.prepare_egress()?)
                    .and_then(|planned| planned.capture_invocation(authority))
                    .map(|_| ())
                    .map_err(|error| KernelError::GuardDenied(error.to_string()))
            }));
        let lines = CaptureLines::default();
        let response = {
            let _subscriber =
                tracing::subscriber::set_default(Registry::default().with(lines.clone()));
            fixture
                .kernel
                .evaluate_tool_call_blocking_with_security_context(
                    &fixture.request,
                    &fixture.context,
                )?
        };
        fixture
            .authority
            .admission_operation_store()
            .clear_native_dispatch_capture_failure_for_test()?;
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response.output.is_none());
        assert!(response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("injected native capture failure")));
        assert_uncaptured(&fixture)?;
        assert_eq!(
            lines
                .0
                .lock()
                .map_err(|_| "trace lock poisoned")?
                .as_slice(),
            &[(stage.to_owned(), category.to_owned())],
            "{fault:?}"
        );
    }
    Ok(())
}

#[test]
fn native_capture_store_diagnostic_success_preserves_output_and_replay() -> TestResult {
    let mut fixture = Fixture::combined_native_credentials()?;
    fixture.kernel.set_security_pre_dispatch_hook(Arc::new(
        NativeFlowResolver::new(
            fixture.binding.clone(),
            super::super::super::registry(false, InformationLabel::bottom())?,
            Arc::new(CountingEmptyClassifier::new()),
            fixture.clock.clone(),
            flow_config(),
        )?
        .with_captured_lifecycle(),
    ));
    let lines = CaptureLines::default();
    let (response, replay) = {
        let _subscriber = tracing::subscriber::set_default(Registry::default().with(lines.clone()));
        let response = fixture
            .kernel
            .evaluate_tool_call_blocking_with_security_context(
                &fixture.request,
                &fixture.context,
            )?;
        let replay = fixture
            .kernel
            .evaluate_tool_call_blocking_with_security_context(
                &fixture.request,
                &fixture.context,
            )?;
        (response, replay)
    };
    assert_eq!(response.verdict, Verdict::Allow);
    assert!(
        matches!(&response.output, Some(chio_kernel::ToolCallOutput::Value(value)) if value == &fixture.request.arguments)
    );
    assert!(response.receipt.verify_signature()?);
    assert_eq!(
        chio_core::canonical_json_bytes(&response.receipt)?,
        chio_core::canonical_json_bytes(&replay.receipt)?
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fence,
            fixture.clock.snapshot(),
        )?
        .ok_or("original completed operation")?;
    assert_eq!(operation.state(), AdmissionOperationState::Completed);
    assert!(operation.dispatch_commit().is_some());
    assert!(operation.native_dispatch_ledger_digest().is_some());
    assert!(lines
        .0
        .lock()
        .map_err(|_| "trace lock poisoned")?
        .is_empty());
    Ok(())
}

fn assert_uncaptured(fixture: &Fixture) -> TestResult {
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fence,
            fixture.clock.snapshot(),
        )?
        .ok_or("original refused operation")?;
    assert_eq!(operation.state(), AdmissionOperationState::CapturePending);
    assert!(operation.dispatch_commit().is_none());
    assert!(operation.native_dispatch_ledger_digest().is_none());
    assert!(store
        .load_native_dispatch_capture(
            operation.binding().operation_id(),
            &fence,
            fixture.clock.snapshot()
        )?
        .is_none());
    let quota = fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
        .ok_or("original quota reservation")?;
    assert_eq!(
        (quota.reserved_invocations, quota.captured_invocations),
        (1, 0)
    );
    Ok(())
}

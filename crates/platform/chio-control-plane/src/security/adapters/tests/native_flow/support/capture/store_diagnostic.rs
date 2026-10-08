// Observe the real SQLite native capture refusal without changing its outcome.
use super::*;
use std::sync::{Mutex, PoisonError};
use tracing::field::{Field, Visit};
use tracing_subscriber::{layer::Context, prelude::*, Layer, Registry};

type Refusal = (String, String, Option<String>);

#[derive(Debug)]
struct Profile {
    outcome: String,
    timeline: String,
    stages: String,
}

#[derive(Clone, Default)]
struct CaptureLines(Arc<Mutex<Vec<Refusal>>>, Arc<Mutex<Vec<Profile>>>);

#[derive(Default)]
struct CaptureFields {
    stage: Option<String>,
    category: Option<String>,
    phase: Option<String>,
    outcome: Option<String>,
    timeline: Option<String>,
    stages: Option<String>,
}

impl Visit for CaptureFields {
    fn record_str(&mut self, field: &Field, value: &str) {
        let slot = match field.name() {
            "native_capture_stage" => &mut self.stage,
            "native_capture_category" => &mut self.category,
            "native_capture_phase" => &mut self.phase,
            "native_capture_outcome" => &mut self.outcome,
            "native_capture_timeline" => &mut self.timeline,
            "native_capture_stages" => &mut self.stages,
            _ => return,
        };
        *slot = Some(value.to_owned());
    }

    fn record_debug(&mut self, _: &Field, _: &dyn std::fmt::Debug) {}
}

impl<S: tracing::Subscriber> Layer<S> for CaptureLines {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        let mut fields = CaptureFields::default();
        event.record(&mut fields);
        match event.metadata().target() {
            "chio::native_capture" => {
                if let (Some(stage), Some(category)) = (fields.stage, fields.category) {
                    self.0.lock().unwrap_or_else(PoisonError::into_inner).push((
                        stage,
                        category,
                        fields.phase,
                    ));
                }
            }
            "chio::native_capture_profile" => {
                if let (Some(outcome), Some(timeline), Some(stages)) =
                    (fields.outcome, fields.timeline, fields.stages)
                {
                    self.1
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(Profile {
                            outcome,
                            timeline,
                            stages,
                        });
                }
            }
            _ => {}
        }
    }
}

impl CaptureLines {
    fn refusals(&self) -> TestResult<Vec<Refusal>> {
        Ok(self.0.lock().map_err(|_| "trace lock poisoned")?.clone())
    }

    /// The single physical capture's outcome, timeline and visited stages.
    fn profile(&self) -> TestResult<(String, String, Vec<String>)> {
        let profiles = self.1.lock().map_err(|_| "trace lock poisoned")?;
        let [profile] = profiles.as_slice() else {
            return Err(format!("expected one native capture profile: {profiles:?}").into());
        };
        let mut stages = Vec::new();
        for visit in profile.stages.split(',') {
            let (stage, costs) = visit.split_once(':').ok_or("profile visit lacks costs")?;
            let (wall, cpu) = costs.split_once('/').ok_or("profile visit lacks cpu")?;
            wall.parse::<u32>()?;
            cpu.parse::<u32>()?;
            stages.push(stage.to_owned());
        }
        Ok((profile.outcome.clone(), profile.timeline.clone(), stages))
    }
}

fn refusal(stage: &str, category: &str, phase: Option<&str>) -> Refusal {
    (
        stage.to_owned(),
        category.to_owned(),
        phase.map(str::to_owned),
    )
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
    let observed = lines.refusals()?;
    assert_eq!(
        observed,
        [refusal(
            "commit_runtime_expired",
            "invariant",
            Some("commit_time")
        )],
        "physical transaction lost its actual fixed refusal"
    );
    let (outcome, timeline, stages) = lines.profile()?;
    assert_eq!(outcome, "refused");
    // Policy preparation at epoch + 2; the runtime report ends at epoch + 60_001.
    assert_eq!(
        timeline,
        "valid_until:10000,retain_decision:0,retain_entry:0,capture_decision:0,\
         capture_entry:0,commit_state:0,commit_time:59999"
    );
    assert_eq!(stages.first().map(String::as_str), Some("store_callback"));
    assert_eq!(
        stages.last().map(String::as_str),
        Some("commit_runtime_expired")
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
            lines.refusals()?,
            [refusal(stage, category, None)],
            "{fault:?}"
        );
        let (outcome, timeline, stages) = lines.profile()?;
        assert_eq!(outcome, "refused", "{fault:?}");
        assert_eq!(
            timeline,
            "valid_until:10000,retain_decision:0,retain_entry:0,capture_decision:0,\
             capture_entry:0",
            "{fault:?}"
        );
        assert_eq!(stages.last().map(String::as_str), Some(stage), "{fault:?}");
    }
    Ok(())
}

/// The same fixed policy refusal names whether the fence had already passed at
/// the transaction's first sample or passed only before the physical commit.
#[test]
fn native_capture_store_diagnostic_policy_expiry_names_entry_and_commit_phases() -> TestResult {
    const FENCE_MS: u64 = 10_000;
    for (at_entry, phase, timeline) in [
        (
            true,
            "capture_entry",
            "valid_until:10000,retain_decision:0,retain_entry:0,capture_decision:10000,\
             capture_entry:10000",
        ),
        (
            false,
            "commit_time",
            "valid_until:10000,retain_decision:0,retain_entry:0,capture_decision:0,\
             capture_entry:0,commit_state:0,commit_time:10000",
        ),
    ] {
        let mut fixture = super::super::super::public_fixture()?;
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
        let clock = fixture.clock.clone();
        let expires_at = clock.snapshot() + FENCE_MS;
        if at_entry {
            fixture
                .kernel
                .install_native_capture_checkpoint_hook(Arc::new(move |authority| {
                    let planned = resolver
                        .prepare_dispatch(authority.prepare_egress()?)
                        .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
                    let policy = planned.policy_evidence().canonical_bytes().to_vec();
                    let deadline = planned
                        .admission()
                        .egress_fence_plan
                        .as_ref()
                        .map(|plan| plan.expires_at_unix_ms);
                    drop(planned);
                    let grant_index = authority.grant_index()?;
                    let (prepared, _, ledger) = authority.prepare_egress()?.retain_for_capture(
                        deadline,
                        grant_index,
                        &policy,
                    )?;
                    clock
                        .advance_to(expires_at)
                        .map_err(|error| KernelError::Internal(error.to_string()))?;
                    authority.capture(prepared, &ledger, &policy).map(|_| ())
                }));
        } else {
            fixture
                .authority
                .admission_operation_store()
                .inject_native_capture_policy_expiry_for_test(move |until| {
                    clock.advance_to(until).map_err(|error| error.to_string())
                })?;
            fixture
                .kernel
                .install_native_capture_checkpoint_hook(Arc::new(move |authority| {
                    resolver
                        .prepare_dispatch(authority.prepare_egress()?)
                        .and_then(|planned| planned.capture_invocation(authority))
                        .map(|_| ())
                        .map_err(|error| KernelError::GuardDenied(error.to_string()))
                }));
        }
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
        if !at_entry {
            fixture
                .authority
                .admission_operation_store()
                .clear_native_capture_policy_expiry_for_test()?;
        }
        assert_eq!(response.verdict, Verdict::Deny, "{phase}");
        assert!(response.output.is_none(), "{phase}");
        assert_eq!(fixture.clock.snapshot(), expires_at, "{phase}");
        assert_uncaptured(&fixture)?;
        assert_eq!(
            lines.refusals()?,
            [refusal("policy_expired", "invariant", Some(phase))],
            "{phase}"
        );
        let (outcome, observed, stages) = lines.profile()?;
        assert_eq!(outcome, "refused", "{phase}");
        assert_eq!(observed, timeline, "{phase}");
        assert_eq!(
            stages.last().map(String::as_str),
            Some("policy_expired"),
            "{phase}"
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
    assert!(lines.refusals()?.is_empty());
    let (outcome, timeline, stages) = lines.profile()?;
    assert_eq!(outcome, "captured");
    assert_eq!(
        timeline,
        "valid_until:10000,retain_decision:0,retain_entry:0,capture_decision:0,\
         capture_entry:0,commit_state:0,commit_time:0"
    );
    assert_eq!(stages.first().map(String::as_str), Some("store_callback"));
    assert_eq!(stages.last().map(String::as_str), Some("anchor_sync"));
    for stage in ["native_policy", "budget_mutation", "commit_clock", "commit"] {
        assert!(stages.iter().any(|visited| visited == stage), "{stages:?}");
    }
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

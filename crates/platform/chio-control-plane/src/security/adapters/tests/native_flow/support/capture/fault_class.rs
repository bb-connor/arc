// The private host log names the existing native dispatch check that refused.
// Public denials, receipts, durable state and tool effects stay unchanged.
use super::*;
use chio_core::receipt::decision::Decision;
use std::sync::{Mutex, PoisonError};
use tracing::field::{Field, Visit};
use tracing_subscriber::{layer::Context, prelude::*, Layer, Registry};

const CAPTURE_FAILED: &str = "security dispatch outcome requires reconciliation: security native dispatch capture callback failed; authoritative recovery required";
const HANDOFF_FAILED: &str = "security dispatch outcome requires reconciliation: security native lifecycle handoff callback failed; authoritative recovery required";
const RETENTION_EXPIRED: &str =
    "durable admission failed: native capture authority expired before retention";

/// The existing check that observes `deadline - early_ms` first.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Site {
    /// The resolver's own capture time check, before any kernel custody step.
    BeforeCapture,
    /// The kernel retention comparison against its live deadline.
    Retention,
    /// The kernel handoff entry comparison against the captured deadline.
    Handoff,
}

/// Plans with the real resolver and captures through the public kernel
/// authority. The shared clock moves only immediately before the site's check.
struct SiteHook {
    resolver: NativeFlowResolver,
    clock: Arc<FlowTestClock>,
    site: Site,
    early_ms: u64,
    outcomes: Mutex<Vec<String>>,
}

impl SiteHook {
    fn plan_and_capture(
        &self,
        authority: &mut chio_kernel::NativeSecurityDispatchCaptureAuthority<'_, '_>,
    ) -> Result<(), KernelError> {
        let planned = self
            .resolver
            .prepare_dispatch(authority.prepare_egress()?)
            .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
        let at = policy_deadline(planned.policy_evidence().canonical_bytes())?
            .checked_sub(self.early_ms)
            .ok_or_else(|| KernelError::Internal("site time precedes the epoch".into()))?;
        match self.site {
            Site::BeforeCapture => {
                self.advance(at)?;
                let captured = planned.capture_invocation(authority);
                self.record(captured.as_ref().map(|_| ()).map_err(|e| format!("{e:?}")))?;
                captured
                    .map(|_| ())
                    .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
            }
            Site::Retention => {
                let policy = planned.policy_evidence().canonical_bytes().to_vec();
                drop(planned);
                let egress = authority.prepare_egress()?;
                self.advance(at)?;
                let retained = authority.retain_for_capture(egress, None, &policy, None);
                self.record(retained.as_ref().map(|_| ()).map_err(ToString::to_string))?;
                let (prepared, _, ledger) = retained?;
                authority.capture(prepared, &ledger, &policy).map(|_| ())?;
            }
            Site::Handoff => {
                let captured = planned.capture_invocation(authority);
                self.record(captured.as_ref().map(|_| ()).map_err(|e| format!("{e:?}")))?;
                captured
                    .map(|_| ())
                    .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
                self.advance(at)?;
            }
        }
        Ok(())
    }

    fn record(&self, outcome: Result<(), String>) -> Result<(), KernelError> {
        self.outcomes
            .lock()
            .map_err(|_| KernelError::Internal("site hook outcomes poisoned".into()))?
            .push(match outcome {
                Ok(()) => "ok".to_owned(),
                Err(error) => error,
            });
        Ok(())
    }

    fn advance(&self, unix_ms: u64) -> Result<(), KernelError> {
        self.clock
            .advance_to(unix_ms)
            .map_err(|error| KernelError::Internal(error.to_string()))
    }
}

fn policy_deadline(policy: &[u8]) -> Result<u64, KernelError> {
    serde_json::from_slice::<serde_json::Value>(policy)
        .ok()
        .and_then(|value| {
            value
                .pointer("/inputs/valid_until_unix_ms")
                .and_then(serde_json::Value::as_u64)
        })
        .ok_or_else(|| KernelError::Internal("policy deadline absent".into()))
}

impl SecurityPreDispatchHook for SiteHook {
    fn name(&self) -> &str {
        "native-dispatch-fault-site"
    }

    fn supports_native_dispatch(&self) -> bool {
        true
    }

    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        self.resolver.native_authority_binding()
    }

    fn prepare_native_admission(
        &self,
        context: &NativeSecurityAdmissionContext<'_>,
        authority: &NativeSecurityFlowJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        self.resolver.prepare_native_admission(context, authority)
    }

    fn prepare_native_output(
        &self,
        context: &chio_kernel::tool_outcome::DurableSecurityReleaseContext<'_>,
        authority: &chio_kernel::NativeSecurityOutputJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        self.resolver.prepare_native_output(context, authority)
    }

    fn commit_native_dispatch(
        &self,
        authority: &mut chio_kernel::NativeSecurityDispatchCaptureAuthority<'_, '_>,
    ) -> Result<(), KernelError> {
        self.plan_and_capture(authority)
    }

    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Err(KernelError::Internal(
            "native fault site reached legacy dispatch".into(),
        ))
    }
}

/// Every event carrying the fault field, formatted as the host prints it.
#[derive(Clone, Default)]
struct FaultLines(Arc<Mutex<Vec<String>>>);

struct Fields(Vec<String>);

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.push(format!("{}={value}", field.name()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.push(format!("{}={value:?}", field.name()));
    }
}

impl<S: tracing::Subscriber> Layer<S> for FaultLines {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        let metadata = event.metadata();
        if metadata.fields().field("native_dispatch_fault").is_none() {
            return;
        }
        let mut fields = Fields(Vec::new());
        event.record(&mut fields);
        self.0.lock().unwrap_or_else(PoisonError::into_inner).push(format!(
            "{} {} {}",
            metadata.level(),
            metadata.target(),
            fields.0.join(" ")
        ));
    }
}

struct Observed {
    fixture: Fixture,
    response: chio_kernel::ToolCallResponse,
    outcomes: Vec<String>,
    lines: Vec<String>,
}

fn observe(site: Site, early_ms: u64) -> TestResult<Observed> {
    let mut fixture = super::super::super::public_fixture()?;
    let hook = Arc::new(SiteHook {
        resolver: NativeFlowResolver::new(
            fixture.binding.clone(),
            super::super::super::registry(false, InformationLabel::bottom())?,
            Arc::new(CountingEmptyClassifier::new()),
            fixture.clock.clone(),
            flow_config(),
        )?
        .with_captured_lifecycle(),
        clock: fixture.clock.clone(),
        site,
        early_ms,
        outcomes: Mutex::new(Vec::new()),
    });
    fixture.kernel.set_security_pre_dispatch_hook(hook.clone());
    let lines = FaultLines::default();
    let response = {
        let _subscriber = tracing::subscriber::set_default(Registry::default().with(lines.clone()));
        fixture
            .kernel
            .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?
    };
    let outcomes = hook
        .outcomes
        .lock()
        .map_err(|_| "site hook outcomes poisoned")?
        .clone();
    let lines = lines
        .0
        .lock()
        .map_err(|_| "fault lines poisoned")?
        .clone();
    Ok(Observed {
        fixture,
        response,
        outcomes,
        lines,
    })
}

fn custody(fixture: &Fixture) -> TestResult<(AdmissionOperationState, (u32, u32))> {
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fence,
            fixture.clock.snapshot(),
        )?
        .ok_or("original fault site operation")?;
    let quota = fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
        .map_or((0, 0), |usage| {
            (usage.reserved_invocations, usage.captured_invocations)
        });
    Ok((operation.state(), quota))
}

fn fault_line(fixture: &Fixture, class: &str) -> String {
    format!(
        "WARN chio::native_dispatch message=native dispatch failed request_id={} native_dispatch_fault={class}",
        fixture.request.request_id
    )
}

/// Preconditions first: the exact public denial, signed receipt reason,
/// durable state and absent tool effect. Only then the private class line.
fn assert_refused(
    observed: &Observed,
    outcome: &str,
    reason: &str,
    state: AdmissionOperationState,
    quota: (u32, u32),
    class: &str,
) -> TestResult {
    let Observed {
        fixture,
        response,
        outcomes,
        lines,
    } = observed;
    assert_eq!(outcomes, &[outcome], "{lines:?}");
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    assert_eq!(response.reason.as_deref(), Some(reason));
    assert!(response.output.is_none());
    assert_eq!(
        response.receipt.decision,
        Some(Decision::Deny {
            reason: reason.to_owned(),
            guard: "kernel".to_owned(),
        })
    );
    assert!(response.receipt.verify_signature()?);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(custody(fixture)?, (state, quota));
    assert_eq!(lines, &[fault_line(fixture, class)]);
    Ok(())
}

#[test]
fn native_dispatch_fault_names_the_hook_refusal_before_capture() -> TestResult {
    let observed = observe(Site::BeforeCapture, 0)?;
    assert_refused(
        &observed,
        "ClockChanged",
        CAPTURE_FAILED,
        AdmissionOperationState::CompensatedBeforeDispatch,
        (0, 0),
        "hook_before_capture",
    )
}

#[test]
fn native_dispatch_fault_names_the_retention_deadline_comparison() -> TestResult {
    let observed = observe(Site::Retention, 0)?;
    assert_refused(
        &observed,
        RETENTION_EXPIRED,
        CAPTURE_FAILED,
        AdmissionOperationState::CompensatedBeforeDispatch,
        (0, 0),
        "retention_deadline",
    )
}

#[test]
fn native_dispatch_fault_names_the_handoff_deadline_at_entry() -> TestResult {
    let observed = observe(Site::Handoff, 0)?;
    assert_refused(
        &observed,
        "ok",
        HANDOFF_FAILED,
        AdmissionOperationState::DispatchCommitted,
        (0, 1),
        "handoff_deadline_at_entry",
    )
}

#[test]
fn native_dispatch_fault_is_absent_one_millisecond_before_each_deadline() -> TestResult {
    for site in [Site::BeforeCapture, Site::Retention, Site::Handoff] {
        let Observed {
            fixture,
            response,
            outcomes,
            lines,
        } = observe(site, 1)?;
        assert_eq!(outcomes, ["ok"], "{site:?}");
        assert_eq!(
            response.verdict,
            Verdict::Allow,
            "{site:?}: {:?}",
            response.reason
        );
        assert!(
            matches!(&response.output, Some(chio_kernel::ToolCallOutput::Value(value)) if value == &fixture.request.arguments),
            "{site:?}"
        );
        assert!(response.receipt.verify_signature()?);
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1, "{site:?}");
        assert_eq!(
            custody(&fixture)?,
            (AdmissionOperationState::Completed, (0, 1)),
            "{site:?}"
        );
        assert!(lines.is_empty(), "{site:?}: {lines:?}");
    }
    Ok(())
}

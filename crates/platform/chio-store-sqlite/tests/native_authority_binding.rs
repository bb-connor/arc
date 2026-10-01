//! The real kernel begin retains native selection before any native mutation.
//! A permissive legacy callback is not native lifecycle or dispatch authority.
#[path = "native_authority_binding/capture.rs"]
mod capture;
#[path = "native_authority_binding/egress_coordinator.rs"]
mod egress_coordinator;
#[path = "native_authority_binding/observation.rs"]
mod observation;
#[path = "execution_nonce_kernel_lifecycle/support.rs"]
mod support;

use chio_kernel::admission_operation::{
    AdmissionIdentifier, AdmissionOperationState, AdmissionOperationStore,
    NativeSecurityAuthorityBindingV1, StoreMutationFence,
};
use chio_kernel::{
    KernelError, NativeSecurityAdmissionContext, NativeSecurityFlowJoinAuthority,
    RuntimeAdmissionContext, RuntimeAdmissionDecision, RuntimeAdmissionHook,
    SecurityDispatchOutcomeHandle, SecurityInvocationContext, SecurityInvocationContextV1,
    SecurityPreDispatchContext, SecurityPreDispatchHook, SecurityPreDispatchPolicy, Verdict,
};
use chio_security_types::ports::{IsolationEpochId, LineageId, RecordId, SessionId, TenantId};
use chio_security_types::{InformationLabel, PrincipalId};
use chio_store_sqlite::security_state::SqliteSecurityParticipantSource;
use chio_store_sqlite::{
    SecurityParticipantStateInitialization, SqliteAdmissionOperationStore, SqliteSecurityStateStore,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use support::*;

struct NativeAdmissionProbe {
    store: SqliteAdmissionOperationStore,
    fence: StoreMutationFence,
    selected: SecurityParticipantStateInitialization,
    context: SecurityInvocationContext,
    calls: AtomicUsize,
    preparation_calls: AtomicUsize,
    dispatch_calls: AtomicUsize,
    mode: PreparationMode,
}

#[derive(Clone, Copy, Debug)]
enum PreparationMode {
    Normal,
    LegacyCommit,
    Silent,
    Twice,
    DenyAfter,
    PanicAfter,
}

impl SecurityPreDispatchHook for NativeAdmissionProbe {
    fn name(&self) -> &str {
        "native-binding-admission-probe"
    }
    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        self.selected
            .admission_binding()
            .map(Some)
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))
    }
    fn prepare_native_admission(
        &self,
        _: &NativeSecurityAdmissionContext<'_>,
        authority: &NativeSecurityFlowJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        self.preparation_calls.fetch_add(1, Ordering::SeqCst);
        if matches!(self.mode, PreparationMode::Silent) {
            return Ok(());
        }
        let join = || {
            authority.join(
                RecordId::new("actual-admission-join")
                    .map_err(|error| KernelError::Internal(error.to_string()))?,
                InformationLabel::bottom(),
                InformationLabel::bottom(),
                InformationLabel::bottom(),
            )
        };
        join()?;
        match self.mode {
            PreparationMode::Twice => {
                assert!(join().is_err());
            }
            PreparationMode::DenyAfter => {
                return Err(KernelError::GuardDenied("denied after native join".into()))
            }
            PreparationMode::PanicAfter => panic!("native verifier panicked after physical join"),
            _ => {}
        }
        Ok(())
    }
    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        self.dispatch_calls.fetch_add(1, Ordering::SeqCst);
        if matches!(self.mode, PreparationMode::LegacyCommit) {
            return Ok(None);
        }
        Err(KernelError::GuardDenied(
            "probe must stop before dispatch".into(),
        ))
    }
}

impl RuntimeAdmissionHook for NativeAdmissionProbe {
    fn name(&self) -> &str {
        "native-binding-admission-probe"
    }
    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.probe(context)
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(RuntimeAdmissionDecision::deny(
            "test stopped after native admission join",
            None,
        ))
    }
}

impl NativeAdmissionProbe {
    fn probe(&self, context: &RuntimeAdmissionContext<'_>) -> TestResult {
        // Begin refreshes trusted time before committing. The earlier callback
        // context timestamp cannot stand in for a fresh lease decision clock.
        let now = now_ms()?;
        let (operation, retained) = self
            .store
            .load_unambiguous_retained_tool_request(
                &AdmissionIdentifier::try_new("request", &context.request.request_id)?,
                &self.fence,
                now,
            )?
            .ok_or("original kernel admission")?;
        assert_eq!(
            operation.state(),
            AdmissionOperationState::BrokerAttemptRegistered
        );
        retained.validate_native_security_context(&self.context)?;
        retained.validate_native_security_authority(&self.selected.admission_binding()?)?;
        let wire: serde_json::Value = serde_json::from_slice(retained.canonical_bytes())?;
        assert_eq!(wire["schema"], "chio.retained-tool-admission-request.v4");
        assert!(retained.authority_profile().is_some());
        let (current, joined) = self
            .store
            .load_native_security_flow_join(operation.binding().operation_id(), &self.fence, now)?
            .ok_or("kernel-owned native operation")?;
        assert_eq!(current, operation);
        let joined = joined.ok_or("kernel must have joined before runtime admission")?;
        assert_eq!(joined.binding, self.selected.admission_binding()?);
        assert_eq!(
            joined.command.transition_id,
            RecordId::new("actual-admission-join")?
        );
        assert_eq!(
            joined.snapshot.key.principal_id,
            *self.context.as_v1().principal_id()
        );
        Ok(())
    }
}

fn now_ms() -> TestResult<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}

fn initialize(
    fixture: &Fixture,
    runtime: &Runtime,
    name: &str,
) -> TestResult<SecurityParticipantStateInitialization> {
    let path = fixture.directory.path().join(format!("{name}.db"));
    drop(SqliteSecurityStateStore::open(&path)?);
    let source = SqliteSecurityParticipantSource::open(path)?;
    let store = runtime.authority.admission_operation_store();
    let fence = runtime.authority.mutation_fence();
    let authority = AdmissionIdentifier::try_new("authority", name)?;
    let now = now_ms()?;
    let expected =
        store.expect_security_participant_source(&authority, &authority, &source, &fence, now)?;
    store.import_security_participant_source(
        &authority,
        expected.expectation_id(),
        &source,
        &fence,
        now,
    )?;
    Ok(store.hydrate_security_participant_state(
        &authority,
        expected.expectation_id(),
        &fence,
        now,
    )?)
}

#[test]
fn actual_kernel_admission_binds_the_first_native_join_before_any_dispatch() -> TestResult {
    preparation_case(PreparationMode::Normal, false)
}

#[test]
fn native_join_only_hook_cannot_activate_dispatch() -> TestResult {
    preparation_case(PreparationMode::LegacyCommit, false)
}

#[test]
fn silent_native_preparation_cannot_reach_budget_or_runtime() -> TestResult {
    preparation_case(PreparationMode::Silent, false)
}

#[test]
fn repeated_native_preparation_cannot_reach_budget_or_runtime() -> TestResult {
    preparation_case(PreparationMode::Twice, false)
}

#[test]
fn denied_native_preparation_retains_monotone_history() -> TestResult {
    preparation_case(PreparationMode::DenyAfter, false)
}

#[test]
fn panicked_native_preparation_retains_monotone_history() -> TestResult {
    preparation_case(PreparationMode::PanicAfter, false)
}

#[test]
fn native_nonce_preflight_cannot_borrow_dispatch_join_authority() -> TestResult {
    preparation_case(PreparationMode::Normal, true)
}

fn preparation_case(mode: PreparationMode, nonce_enabled: bool) -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.nonce_enabled = nonce_enabled;
    let mut runtime = fixture.open()?;
    let selected = initialize(&fixture, &runtime, "source")?;
    let request = fixture.request(&runtime, "native-original-selection")?;
    let context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        TenantId::new("native-tenant")?,
        SessionId::new("native-session")?,
        PrincipalId::new(request.agent_id.clone())?,
        IsolationEpochId::new("native-epoch")?,
        LineageId::new(request.capability.id.clone())?,
        1,
    ));
    let probe = Arc::new(NativeAdmissionProbe {
        store: runtime.authority.admission_operation_store(),
        fence: runtime.authority.mutation_fence(),
        selected,
        context: context.clone(),
        calls: AtomicUsize::new(0),
        preparation_calls: AtomicUsize::new(0),
        dispatch_calls: AtomicUsize::new(0),
        mode,
    });
    let kernel = Arc::get_mut(&mut runtime.kernel).ok_or("unique test kernel")?;
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(probe.clone());
    if !matches!(mode, PreparationMode::LegacyCommit) {
        kernel.set_runtime_admission_hook(probe.clone());
    }
    let response = kernel.evaluate_tool_call_blocking_with_security_context(&request, &context)?;
    assert_eq!(
        fixture.invocations.load(Ordering::SeqCst),
        0,
        "native preparation is not dispatch activation: {mode:?}: {response:?}"
    );
    assert_eq!(response.verdict, Verdict::Deny);
    if matches!(mode, PreparationMode::LegacyCommit) {
        assert_eq!(
            response.reason.as_deref(),
            Some("native security dispatch lifecycle is unsupported"),
            "a successful native join must reach the final lifecycle boundary"
        );
    }
    if matches!(mode, PreparationMode::Normal) && !nonce_enabled {
        assert!(
            response
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("test stopped after native admission join")),
            "{:?}",
            response.reason
        );
    }
    assert!(response.output.is_none());
    assert_eq!(
        probe.preparation_calls.load(Ordering::SeqCst),
        usize::from(!nonce_enabled),
        "{mode:?}: {response:?}"
    );
    assert_eq!(
        probe.calls.load(Ordering::SeqCst),
        usize::from(matches!(mode, PreparationMode::Normal) && !nonce_enabled)
    );
    assert_eq!(probe.dispatch_calls.load(Ordering::SeqCst), 0);
    assert_eq!(grant_quota(&runtime, &request)?, (0, 0));
    let (operation, _) = probe
        .store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &request.request_id)?,
            &probe.fence,
            now_ms()?,
        )?
        .ok_or("original native operation")?;
    let joined = probe.store.load_security_participant_flow_join(
        operation.binding().operation_id(),
        &probe.fence,
        now_ms()?,
    )?;
    assert_eq!(
        joined.is_some(),
        !matches!(mode, PreparationMode::Silent) && !nonce_enabled,
        "{mode:?}"
    );
    if nonce_enabled {
        assert_eq!(
            response.reason.as_deref(),
            Some(
                "durable admission failed: native security nonce preflight preparation is unsupported"
            ),
            "dispatch preparation cannot supply the missing nonce preflight authority"
        );
        assert!(response.execution_nonce.is_none());
        assert_eq!(count_rows(&fixture, "budget_authorization_holds")?, 0);
    }
    Ok(())
}

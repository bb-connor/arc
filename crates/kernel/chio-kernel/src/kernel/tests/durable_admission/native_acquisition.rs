//! Coordinator failure contracts. The SQLite integration separately proves
//! physical ownership; these adapters inject acknowledgement and hook faults.
use super::*;
use crate::admission_operation::{
    NativeSecurityAuthorityBindingV1, NativeSecurityFlowJoinRecordV1,
};
use chio_security_types::ports::{FlowJoinRequest, FlowStateSnapshot, RecordId};
use chio_security_types::InformationLabel;
use std::sync::Mutex;

#[path = "native_acquisition/egress_ports.rs"]
mod egress_ports;
#[path = "native_acquisition/input.rs"]
mod input;

#[derive(Clone, Copy, Debug, Default)]
enum Mode {
    #[default]
    Normal,
    NoOp,
    DeniedBeforeWrite,
    LostAck,
    ClaimPanic,
    HistoryPanic,
    WrongAck,
    WrongCommand,
    WrongBinding,
    WrongOperation,
    ChangedHistory,
    WrongInput,
    MalformedInputResolution,
}

#[derive(Default)]
struct State {
    mode: Mode,
    history: Option<NativeSecurityFlowJoinRecordV1>,
    input: Option<crate::admission_operation::NativeSecurityInputJoinRequestV1>,
    reads: u64,
}

#[derive(Default)]
pub(super) struct TestNative(Mutex<State>);

impl TestNative {
    pub(super) fn join(
        &self,
        operation: &AdmissionOperationV1,
        binding: &NativeSecurityAuthorityBindingV1,
        command: &FlowJoinRequest,
    ) -> Result<FlowStateSnapshot, AdmissionOperationStoreError> {
        self.join_inner(operation, binding, command, None)
    }

    fn join_inner(
        &self,
        operation: &AdmissionOperationV1,
        binding: &NativeSecurityAuthorityBindingV1,
        command: &FlowJoinRequest,
        input: Option<&crate::admission_operation::NativeSecurityInputJoinRequestV1>,
    ) -> Result<FlowStateSnapshot, AdmissionOperationStoreError> {
        let mut state = self.0.lock().expect("native test state");
        let mode = state.mode;
        if matches!(mode, Mode::DeniedBeforeWrite) {
            return Err(AdmissionOperationStoreError::Invariant(
                "native physical join denied".into(),
            ));
        }
        let snapshot = FlowStateSnapshot {
            key: command.key.clone(),
            principal_label: command.principal_join.clone(),
            lineage_label: command.lineage_join.clone(),
            session_label: command.session_join.clone(),
            context_generation: 1,
        };
        if matches!(mode, Mode::NoOp) {
            return Ok(snapshot);
        }
        let history = NativeSecurityFlowJoinRecordV1 {
            binding: binding.clone(),
            operation_id: operation.binding().operation_id().clone(),
            command: command.clone(),
            snapshot: snapshot.clone(),
            mutation_digest: crate::admission_operation::AdmissionDigest::try_new(
                "mutation",
                sha256_hex(b"native-test-join"),
            )?,
        };
        if let Some(existing) = &state.history {
            assert_eq!(existing, &history, "retry must preserve its command");
        }
        state.history = Some(history);
        state.input = input.cloned();
        drop(state);
        match mode {
            Mode::LostAck => Err(AdmissionOperationStoreError::OutcomeUnknown(
                "native lost acknowledgement".into(),
            )),
            Mode::ClaimPanic => panic!("native test claim panic after write"),
            Mode::WrongAck => Ok(FlowStateSnapshot {
                context_generation: 999,
                ..snapshot
            }),
            _ => Ok(snapshot),
        }
    }

    pub(super) fn history(
        &self,
        operation: Option<AdmissionOperationV1>,
    ) -> Result<
        Option<(AdmissionOperationV1, Option<NativeSecurityFlowJoinRecordV1>)>,
        AdmissionOperationStoreError,
    > {
        let Some(mut operation) = operation else {
            return Ok(None);
        };
        let mut state = self.0.lock().expect("native test state");
        state.reads += 1;
        let mode = state.mode;
        let reads = state.reads;
        let mut history = state.history.clone();
        drop(state);
        if matches!(mode, Mode::HistoryPanic) {
            panic!("native test history panic");
        }
        if let Some(record) = &mut history {
            match mode {
                Mode::WrongCommand => {
                    record.command.transition_id =
                        RecordId::new("substituted-command").expect("test id")
                }
                Mode::WrongBinding => record.binding = selection("substituted-authority"),
                Mode::ChangedHistory if reads > 1 => {
                    record.mutation_digest = crate::admission_operation::AdmissionDigest::try_new(
                        "mutation",
                        sha256_hex(b"changed-history"),
                    )?
                }
                _ => {}
            }
        }
        if matches!(mode, Mode::WrongOperation) {
            let mut persisted = operation.to_persisted();
            persisted.version += 1;
            operation = AdmissionOperationV1::from_persisted(persisted)?;
        }
        Ok(Some((operation, history)))
    }
}

fn selection(authority: &str) -> NativeSecurityAuthorityBindingV1 {
    NativeSecurityAuthorityBindingV1::new(
        AdmissionIdentifier::try_new("store", "native-store").expect("store"),
        AdmissionIdentifier::try_new("authority", authority).expect("authority"),
        crate::admission_operation::AdmissionDigest::try_new(
            "initialization",
            sha256_hex(b"native-initialization"),
        )
        .expect("digest"),
    )
}

pub(super) fn join(
    authority: &NativeSecurityFlowJoinAuthority<'_>,
) -> Result<FlowStateSnapshot, KernelError> {
    authority.join(
        RecordId::new("kernel-owned-native-join").expect("test transition"),
        InformationLabel::bottom(),
        InformationLabel::bottom(),
        InformationLabel::bottom(),
    )
}

#[derive(Clone, Copy, Debug)]
enum HookMode {
    Normal,
    Silent,
    SwallowFailure,
    Twice,
    PanicBefore,
    PanicAfter,
    ChangedSelection,
}

struct Hook {
    mode: HookMode,
    binding: Mutex<NativeSecurityAuthorityBindingV1>,
}

impl SecurityPreDispatchHook for Hook {
    fn name(&self) -> &str {
        "native-acquisition-faults"
    }
    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        Ok(Some(self.binding.lock().expect("selection").clone()))
    }
    fn prepare_native_admission(
        &self,
        _: &NativeSecurityAdmissionContext<'_>,
        authority: &NativeSecurityFlowJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        match self.mode {
            HookMode::Silent => return Ok(()),
            HookMode::PanicBefore => panic!("native callback before write"),
            HookMode::SwallowFailure => {
                let _ = join(authority);
                return Ok(());
            }
            _ => {}
        }
        join(authority)?;
        match self.mode {
            HookMode::Twice => {
                assert!(join(authority).is_err());
            }
            HookMode::PanicAfter => panic!("native callback after write"),
            HookMode::ChangedSelection => {
                *self.binding.lock().expect("selection") = selection("other")
            }
            _ => {}
        }
        Ok(())
    }
    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Ok(None)
    }
}

#[test]
fn native_recovery_lease_panic_does_not_poison_the_mutation_sequencer(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::kernel::admission_coordinator::DispatchTransport;
    let (mut kernel, request, store, calls) = durable_admission_fixture("native-lease-panic");
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(Arc::new(Hook {
        mode: HookMode::Normal,
        binding: Mutex::new(selection("source")),
    }));
    let context = security_binding::context(&request, 1)?;
    let now = current_unix_timestamp_ms();
    let admission = kernel
        .begin_durable_tool_admission_for_transport(
            &request,
            &security_binding::matching(&request)?,
            Some(&context),
            now,
            DispatchTransport::KernelToolServer,
        )?
        .ok_or("durable native operation")?;
    store
        .recovery_lease_faults
        .arm(recovery_lease::Stage::ClaimBefore);
    assert!(kernel
        .run_native_admission_preparation(&request, Some(&context), Some(&admission), now)
        .is_err());
    assert!(store
        .native_recovery
        .0
        .lock()
        .expect("state")
        .history
        .is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    kernel.run_native_admission_preparation(&request, Some(&context), Some(&admission), now)?;
    assert!(store
        .native_recovery
        .0
        .lock()
        .expect("state")
        .history
        .is_some());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn native_hook_without_preparation_support_denies_before_any_join(
) -> Result<(), Box<dyn std::error::Error>> {
    struct Unsupported;
    impl SecurityPreDispatchHook for Unsupported {
        fn name(&self) -> &str {
            "unsupported-native-preparation"
        }
        fn native_authority_binding(
            &self,
        ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
            Ok(Some(selection("source")))
        }
        fn commit(
            &self,
            _: &SecurityPreDispatchContext<'_>,
        ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
            panic!("unsupported native preparation dispatched")
        }
    }
    let (mut kernel, request, store, calls) = durable_admission_fixture("native-unsupported");
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(Arc::new(Unsupported));
    let context = security_binding::context(&request, 1)?;
    let response = kernel.evaluate_tool_call_blocking_with_security_context(&request, &context)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("preparation is unsupported")),
        "{response:?}"
    );
    assert!(store
        .native_recovery
        .0
        .lock()
        .expect("state")
        .history
        .is_none());
    assert!(store
        .state
        .lock()
        .expect("state")
        .budget_authorization
        .is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn native_join_requires_matching_acknowledgement_and_anchored_readback(
) -> Result<(), Box<dyn std::error::Error>> {
    for mode in [
        Mode::Normal,
        Mode::NoOp,
        Mode::DeniedBeforeWrite,
        Mode::LostAck,
        Mode::ClaimPanic,
        Mode::HistoryPanic,
        Mode::WrongAck,
        Mode::WrongCommand,
        Mode::WrongBinding,
        Mode::WrongOperation,
        Mode::ChangedHistory,
    ] {
        let (mut kernel, request, store, calls) =
            durable_admission_fixture("native-store-contract");
        store.native_recovery.0.lock().expect("state").mode = mode;
        kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
        kernel.set_security_pre_dispatch_hook(Arc::new(Hook {
            mode: HookMode::Normal,
            binding: Mutex::new(selection("source")),
        }));
        let context = security_binding::context(&request, 1)?;
        let response =
            kernel.evaluate_tool_call_blocking_with_security_context(&request, &context)?;
        assert_eq!(response.verdict, Verdict::Deny, "{mode:?}: {response:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "{mode:?}");
        if matches!(mode, Mode::Normal) {
            assert_eq!(
                response.reason.as_deref(),
                Some("native security dispatch lifecycle is unsupported"),
                "a verified join reaches the lifecycle gate, not the connector"
            );
        }
        let state = store.native_recovery.0.lock().expect("state");
        assert_eq!(
            state.history.is_some(),
            !matches!(mode, Mode::NoOp | Mode::DeniedBeforeWrite),
            "{mode:?}"
        );
        assert!(
            state.reads > 0,
            "must read back after a failed write: {mode:?}"
        );
        if matches!(mode, Mode::DeniedBeforeWrite) {
            assert!(
                response
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("native physical join denied")),
                "{response:?}"
            );
        }
        drop(state);
        if !matches!(mode, Mode::Normal) {
            assert!(store
                .state
                .lock()
                .expect("state")
                .budget_authorization
                .is_none());
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum DispatchSelection {
    Native,
    Missing,
    Error,
    Panic,
}

#[test]
fn nested_native_join_only_hook_cannot_activate_dispatch() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut kernel, request, store, calls) = durable_admission_fixture("nested-native-lifecycle");
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(Arc::new(Hook {
        mode: HookMode::Normal,
        binding: Mutex::new(selection("source")),
    }));
    let session = kernel.open_session(request.agent_id.clone(), vec![])?;
    kernel.activate_session(&session)?;
    let parent = make_operation_context(&session, "native-parent", &request.agent_id);
    kernel.begin_session_request(&parent, OperationKind::ToolCall, true)?;
    let mut context = serde_json::to_value(security_binding::context(&request, 1)?)?;
    context["context"]["sessionId"] = serde_json::json!(session.as_str());
    let context = serde_json::from_value(context)?;
    let response = kernel.evaluate_tool_call_with_nested_flow_client_and_security_context(
        &parent,
        &request,
        &mut NoopNestedFlowClient,
        None,
        Some(&context),
    )?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.reason.as_deref(),
        Some("native security dispatch lifecycle is unsupported")
    );
    assert!(response.output.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(store
        .native_recovery
        .0
        .lock()
        .expect("state")
        .history
        .is_some());
    Ok(())
}

struct DispatchProbe {
    selection: DispatchSelection,
    callbacks: AtomicU64,
    reads: AtomicU64,
}

impl DispatchProbe {
    fn new(selection: DispatchSelection) -> Self {
        Self {
            selection,
            callbacks: AtomicU64::new(0),
            reads: AtomicU64::new(0),
        }
    }
}

impl SecurityPreDispatchHook for DispatchProbe {
    fn name(&self) -> &str {
        "native-final-dispatch-probe"
    }

    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        match self.selection {
            DispatchSelection::Native => Ok(Some(selection("source"))),
            DispatchSelection::Missing => Ok(None),
            DispatchSelection::Error => {
                Err(KernelError::DurableAdmission("selection fault".into()))
            }
            DispatchSelection::Panic => panic!("selection callback fault"),
        }
    }

    fn acquire_request_lifecycle(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<Box<dyn SecurityRequestLifecyclePermit>>, KernelError> {
        self.callbacks.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }

    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        self.callbacks.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }
}

#[test]
fn native_dispatch_retains_original_requirement_when_live_selection_is_absent(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::kernel::admission_coordinator::DispatchTransport;
    for policy in [
        SecurityPreDispatchPolicy::Optional,
        SecurityPreDispatchPolicy::Enforce,
    ] {
        for has_context in [false, true] {
            for has_hook in [false, true] {
                let (mut kernel, request, store, calls) =
                    durable_admission_fixture("native-downgrade");
                kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
                kernel.set_security_pre_dispatch_hook(Arc::new(Hook {
                    mode: HookMode::Normal,
                    binding: Mutex::new(selection("source")),
                }));
                let context = security_binding::context(&request, 1)?;
                let now = current_unix_timestamp_ms();
                let admission = kernel
                    .begin_durable_tool_admission_for_transport(
                        &request,
                        &security_binding::matching(&request)?,
                        Some(&context),
                        now,
                        DispatchTransport::KernelToolServer,
                    )?
                    .ok_or("durable native operation")?;
                kernel.run_native_admission_preparation(
                    &request,
                    Some(&context),
                    Some(&admission),
                    now,
                )?;
                let operation = store.operation();
                let probe = Arc::new(DispatchProbe::new(DispatchSelection::Missing));
                kernel.security_pre_dispatch_hook = None;
                if has_hook {
                    kernel.set_security_pre_dispatch_hook(probe.clone());
                }
                kernel.set_security_pre_dispatch_policy(policy);
                let denial = kernel
                    .run_security_pre_dispatch_hook(
                        &request,
                        has_context.then_some(&context),
                        Some(&admission),
                    )
                    .err()
                    .ok_or("original native selection silently entered legacy dispatch")?;
                assert_eq!(
                    denial.reason,
                    "native security dispatch lifecycle is unsupported"
                );
                assert_eq!(
                    probe.reads.load(Ordering::SeqCst),
                    u64::from(has_hook),
                    "live selection is checked without weakening the original native requirement"
                );
                assert_eq!(probe.callbacks.load(Ordering::SeqCst), 0);
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                assert_eq!(
                    store.operation(),
                    operation,
                    "final gate cannot mutate admission"
                );
                assert!(store
                    .native_recovery
                    .0
                    .lock()
                    .expect("state")
                    .history
                    .is_some());
            }
        }
    }
    Ok(())
}

#[test]
fn native_dispatch_checks_live_selection_before_optional_fallbacks(
) -> Result<(), Box<dyn std::error::Error>> {
    for selection in [
        DispatchSelection::Native,
        DispatchSelection::Missing,
        DispatchSelection::Error,
        DispatchSelection::Panic,
    ] {
        for policy in [
            SecurityPreDispatchPolicy::Optional,
            SecurityPreDispatchPolicy::Enforce,
        ] {
            for has_context in [false, true] {
                let (mut kernel, request, _, calls) =
                    durable_admission_fixture("native-late-selection");
                let context = security_binding::context(&request, 1)?;
                let probe = Arc::new(DispatchProbe::new(selection));
                kernel.set_security_pre_dispatch_hook(probe.clone());
                kernel.set_security_pre_dispatch_policy(policy);
                let result = kernel.run_security_pre_dispatch_hook(
                    &request,
                    has_context.then_some(&context),
                    None,
                );
                let legacy = matches!(selection, DispatchSelection::Missing);
                assert_eq!(
                    result.is_ok(),
                    legacy && (has_context || policy == SecurityPreDispatchPolicy::Optional),
                    "{selection:?}: {policy:?}: context={has_context}"
                );
                assert_eq!(probe.reads.load(Ordering::SeqCst), 1);
                assert_eq!(
                    probe.callbacks.load(Ordering::SeqCst),
                    if legacy && has_context { 2 } else { 0 }
                );
                assert_eq!(calls.load(Ordering::SeqCst), 0);
            }
        }
    }
    Ok(())
}

#[test]
fn native_callback_cannot_suppress_skip_repeat_or_retarget_its_join(
) -> Result<(), Box<dyn std::error::Error>> {
    for mode in [
        HookMode::Silent,
        HookMode::SwallowFailure,
        HookMode::Twice,
        HookMode::PanicBefore,
        HookMode::PanicAfter,
        HookMode::ChangedSelection,
    ] {
        let (mut kernel, request, store, calls) = durable_admission_fixture("native-hook-contract");
        if matches!(mode, HookMode::SwallowFailure) {
            store.native_recovery.0.lock().expect("state").mode = Mode::LostAck;
        }
        kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
        kernel.set_security_pre_dispatch_hook(Arc::new(Hook {
            mode,
            binding: Mutex::new(selection("source")),
        }));
        let context = security_binding::context(&request, 1)?;
        let response =
            kernel.evaluate_tool_call_blocking_with_security_context(&request, &context)?;
        assert_eq!(response.verdict, Verdict::Deny, "{mode:?}: {response:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "{mode:?}");
        assert!(store
            .state
            .lock()
            .expect("state")
            .budget_authorization
            .is_none());
        assert_eq!(
            store
                .native_recovery
                .0
                .lock()
                .expect("state")
                .history
                .is_some(),
            !matches!(mode, HookMode::Silent | HookMode::PanicBefore),
            "monotone history must survive denial: {mode:?}"
        );
    }
    Ok(())
}

#[test]
fn native_preparation_rejects_substituted_original_request_before_any_join(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::kernel::admission_coordinator::DispatchTransport;
    for field in ["request", "arguments", "metadata", "server", "capability"] {
        let (mut kernel, request, store, calls) =
            durable_admission_fixture("native-original-request");
        kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
        kernel.set_security_pre_dispatch_hook(Arc::new(Hook {
            mode: HookMode::Normal,
            binding: Mutex::new(selection("source")),
        }));
        let context = security_binding::context(&request, 1)?;
        let now = current_unix_timestamp_ms();
        let admission = kernel
            .begin_durable_tool_admission_for_transport(
                &request,
                &security_binding::matching(&request)?,
                Some(&context),
                now,
                DispatchTransport::KernelToolServer,
            )?
            .ok_or("durable native operation")?;
        let mut changed = request.clone();
        match field {
            "request" => changed.request_id = "different-request".into(),
            "arguments" => changed.arguments = serde_json::json!({"different": true}),
            "metadata" => {
                changed.model_metadata = Some(serde_json::from_value(
                    serde_json::json!({"model_id": "different-model"}),
                )?)
            }
            "server" => changed.server_id = "different-server".into(),
            "capability" => changed.capability.id = "different-capability".into(),
            _ => unreachable!("test field"),
        }
        assert!(
            kernel
                .run_native_admission_preparation(&changed, Some(&context), Some(&admission), now)
                .is_err(),
            "{field}"
        );
        assert!(
            store
                .native_recovery
                .0
                .lock()
                .expect("state")
                .history
                .is_none(),
            "{field}"
        );
        assert!(store
            .state
            .lock()
            .expect("state")
            .budget_authorization
            .is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

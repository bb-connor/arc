use super::*;
use crate::admission_operation::{
    NativeSecurityInputJoinRecordV1, NativeSecurityInputJoinRequestV1,
};

impl TestNative {
    pub(in crate::kernel::tests) fn join_input(
        &self,
        operation: &AdmissionOperationV1,
        binding: &NativeSecurityAuthorityBindingV1,
        input: &NativeSecurityInputJoinRequestV1,
    ) -> Result<NativeSecurityInputJoinRecordV1, AdmissionOperationStoreError> {
        let command = FlowJoinRequest {
            key: input.key().clone(),
            transition_id: input.transition_id().clone(),
            principal_join: input.input_label().clone(),
            lineage_join: input.input_label().clone(),
            session_join: input.input_label().clone(),
        };
        let snapshot = self.join_inner(operation, binding, &command, Some(input))?;
        let mut state = self.0.lock().expect("test input state");
        if matches!(state.mode, Mode::MalformedInputResolution) {
            let history = state.history.as_mut().expect("committed input history");
            history.command.session_join = chio_security_types::InformationLabel::try_known(
                Default::default(),
                std::collections::BTreeSet::from([chio_security_types::Compartment::new(
                    "unpropagated",
                )
                .expect("compartment")]),
            )
            .expect("label");
            history.snapshot.session_label = history.command.session_join.clone();
        }
        if matches!(state.mode, Mode::WrongInput) {
            let mut key = input.key().clone();
            key.session_id =
                chio_security_types::ports::SessionId::new("other-session").expect("session");
            state.input = Some(NativeSecurityInputJoinRequestV1::new(
                input.operation_id().clone(),
                key,
                input.input_label().clone(),
            )?);
        }
        let mut join = state
            .history
            .clone()
            .unwrap_or(NativeSecurityFlowJoinRecordV1 {
                binding: binding.clone(),
                operation_id: operation.binding().operation_id().clone(),
                command,
                snapshot: snapshot.clone(),
                mutation_digest: crate::admission_operation::AdmissionDigest::try_new(
                    "mutation",
                    sha256_hex(b"unrecorded"),
                )?,
            });
        if matches!(state.mode, Mode::WrongAck) {
            join.snapshot = snapshot;
        }
        Ok(NativeSecurityInputJoinRecordV1 {
            input: state.input.clone().unwrap_or_else(|| input.clone()),
            join,
        })
    }

    pub(in crate::kernel::tests) fn input_history(
        &self,
        operation: Option<AdmissionOperationV1>,
    ) -> Result<
        Option<(
            AdmissionOperationV1,
            Option<NativeSecurityInputJoinRecordV1>,
        )>,
        AdmissionOperationStoreError,
    > {
        self.history(operation)?
            .map(|(operation, history)| {
                let input = self.0.lock().expect("test input state").input.clone();
                Ok((
                    operation,
                    history
                        .map(|join| {
                            Ok::<_, AdmissionOperationStoreError>(NativeSecurityInputJoinRecordV1 {
                                input: input.ok_or_else(|| {
                                    AdmissionOperationStoreError::Invariant(
                                        "raw history is not input".into(),
                                    )
                                })?,
                                join,
                            })
                        })
                        .transpose()?,
                ))
            })
            .transpose()
    }
}

struct InputHook {
    mode: HookMode,
    raw_second: bool,
    binding: Mutex<NativeSecurityAuthorityBindingV1>,
}
impl SecurityPreDispatchHook for InputHook {
    fn name(&self) -> &str {
        "input-join-contract"
    }
    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        Ok(Some(self.binding.lock().expect("test selection").clone()))
    }
    fn prepare_native_admission(
        &self,
        _: &NativeSecurityAdmissionContext<'_>,
        authority: &NativeSecurityFlowJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        match self.mode {
            HookMode::Silent => return Ok(()),
            HookMode::PanicBefore => panic!("before input join"),
            _ => {}
        }
        let result = authority.join_input(InformationLabel::bottom());
        if matches!(self.mode, HookMode::SwallowFailure) {
            return Ok(());
        }
        result?;
        match self.mode {
            HookMode::Twice => {
                if self.raw_second {
                    assert!(join(authority).is_err());
                } else {
                    assert!(authority.join_input(InformationLabel::bottom()).is_err());
                }
            }
            HookMode::PanicAfter => panic!("after input join"),
            HookMode::ChangedSelection => {
                *self.binding.lock().expect("test selection") = selection("other")
            }
            _ => {}
        }
        Ok(())
    }
    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        panic!("native input hook must not reach legacy dispatch")
    }
}

#[test]
fn input_join_requires_exact_intent_acknowledgement_and_independent_history(
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
        Mode::WrongInput,
        Mode::MalformedInputResolution,
    ] {
        let (mut kernel, request, store, calls) =
            durable_admission_fixture("native-input-contract");
        store.native_recovery.0.lock().expect("test state").mode = mode;
        kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
        kernel.set_security_pre_dispatch_hook(Arc::new(InputHook {
            mode: HookMode::Normal,
            raw_second: false,
            binding: Mutex::new(selection("source")),
        }));
        let context = security_binding::context(&request, 1)?;
        let response =
            kernel.evaluate_tool_call_blocking_with_security_context(&request, &context)?;
        assert_eq!(response.verdict, Verdict::Deny, "{mode:?}: {response:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        if matches!(mode, Mode::Normal) {
            assert_eq!(
                response.reason.as_deref(),
                Some("native security dispatch lifecycle is unsupported")
            );
        } else {
            assert!(
                store
                    .state
                    .lock()
                    .expect("test state")
                    .budget_authorization
                    .is_none(),
                "{mode:?}: {response:?}"
            );
        }
        let state = store.native_recovery.0.lock().expect("test native state");
        assert!(
            state.reads > 0,
            "write failure must not skip independent readback: {mode:?}"
        );
        assert_eq!(
            state.history.is_some(),
            !matches!(mode, Mode::NoOp | Mode::DeniedBeforeWrite)
        );
        assert_eq!(state.input.is_some(), state.history.is_some());
        if matches!(mode, Mode::DeniedBeforeWrite) {
            assert!(response
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("native physical join denied")));
        }
    }
    Ok(())
}

#[test]
fn input_callback_cannot_suppress_skip_repeat_or_retarget_the_join(
) -> Result<(), Box<dyn std::error::Error>> {
    for (mode, raw_second) in [
        (HookMode::Silent, false),
        (HookMode::SwallowFailure, false),
        (HookMode::Twice, false),
        (HookMode::Twice, true),
        (HookMode::PanicBefore, false),
        (HookMode::PanicAfter, false),
        (HookMode::ChangedSelection, false),
    ] {
        let (mut kernel, request, store, calls) = durable_admission_fixture("native-input-hook");
        if matches!(mode, HookMode::SwallowFailure) {
            store.native_recovery.0.lock().expect("test state").mode = Mode::LostAck;
        }
        kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
        kernel.set_security_pre_dispatch_hook(Arc::new(InputHook {
            mode,
            raw_second,
            binding: Mutex::new(selection("source")),
        }));
        let context = security_binding::context(&request, 1)?;
        let response =
            kernel.evaluate_tool_call_blocking_with_security_context(&request, &context)?;
        assert_eq!(response.verdict, Verdict::Deny, "{mode:?}: {response:?}");
        assert!(
            store
                .state
                .lock()
                .expect("test state")
                .budget_authorization
                .is_none(),
            "{mode:?}"
        );
        assert_eq!(
            store
                .native_recovery
                .0
                .lock()
                .expect("test state")
                .history
                .is_some(),
            !matches!(mode, HookMode::Silent | HookMode::PanicBefore)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

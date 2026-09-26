//! Actual admission consumes current observations, not historical join results.
use super::*;
use chio_kernel::admission_operation::NativeSecurityFlowObservationV1;
use chio_security_types::ports::FlowStateKey;

struct ObservedJoinHook {
    binding: NativeSecurityAuthorityBindingV1,
    joined: AtomicUsize,
    stale_denials: AtomicUsize,
    commits: AtomicUsize,
}

impl SecurityPreDispatchHook for ObservedJoinHook {
    fn name(&self) -> &str {
        "observed-native-join"
    }

    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        Ok(Some(self.binding.clone()))
    }

    fn prepare_native_admission(
        &self,
        input: &NativeSecurityAdmissionContext<'_>,
        authority: &NativeSecurityFlowJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        let transition = RecordId::new(format!("observed-join:{}", input.request.request_id))
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        if let Err(error) = authority.join(
            transition,
            InformationLabel::bottom(),
            InformationLabel::bottom(),
            InformationLabel::bottom(),
        ) {
            if error
                .to_string()
                .contains("native flow observation is stale or absent")
            {
                self.stale_denials.fetch_add(1, Ordering::SeqCst);
            }
            return Err(error);
        }
        self.joined.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        self.commits.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }
}

fn context(observation: &NativeSecurityFlowObservationV1) -> SecurityInvocationContext {
    let key = observation.key();
    let context = SecurityInvocationContextV1::new(
        key.tenant_id.clone(),
        key.session_id.clone(),
        key.principal_id.clone(),
        key.isolation_epoch_id.clone(),
        key.lineage_id.clone(),
        1,
    );
    SecurityInvocationContext::v1(match observation.stored_context_generation() {
        Some(generation) => context.with_flow_state_generation(generation),
        None => context,
    })
}

#[test]
fn fresh_observations_drive_first_and_later_admission_but_never_activate_dispatch() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.nonce_enabled = false;
    let mut runtime = fixture.open()?;
    let selected = initialize(&fixture, &runtime, "observed-source")?;
    let store = runtime.authority.admission_operation_store();
    let fence = runtime.authority.mutation_fence();
    let binding = selected.admission_binding()?;
    let request = fixture.request(&runtime, "first-observed-admission")?;
    let key = FlowStateKey {
        tenant_id: TenantId::new("native-tenant")?,
        session_id: SessionId::new("native-session")?,
        principal_id: PrincipalId::new(request.agent_id.clone())?,
        isolation_epoch_id: IsolationEpochId::new("native-epoch")?,
        lineage_id: LineageId::new(request.capability.id.clone())?,
    };
    let hook = Arc::new(ObservedJoinHook {
        binding: binding.clone(),
        joined: AtomicUsize::new(0),
        stale_denials: AtomicUsize::new(0),
        commits: AtomicUsize::new(0),
    });
    let kernel = Arc::get_mut(&mut runtime.kernel).ok_or("unique test kernel")?;
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(hook.clone());
    let observe = || -> TestResult<NativeSecurityFlowObservationV1> {
        let reader: &dyn AdmissionOperationStore = &store;
        Ok(reader.observe_native_security_flow(&binding, &key, &fence, now_ms()?)?)
    };
    let evaluate = |id: &str,
                    observation: &NativeSecurityFlowObservationV1,
                    joins: bool|
     -> TestResult {
        // Keep the same capability lineage and scope for every distinct request.
        let mut request = request.clone();
        request.request_id = id.into();
        let response = runtime
            .kernel
            .evaluate_tool_call_blocking_with_security_context(&request, &context(observation))?;
        assert_eq!(response.verdict, Verdict::Deny, "{response:?}");
        let reason = response.reason.as_deref().ok_or("denial reason")?;
        if joins {
            assert_eq!(reason, "native security dispatch lifecycle is unsupported");
        } else {
            assert!(
                reason.contains("native flow observation is stale or absent"),
                "{reason}"
            );
        }
        assert!(response.output.is_none());
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        assert_eq!(hook.commits.load(Ordering::SeqCst), 0);
        assert_eq!(grant_quota(&runtime, &request)?, (0, 0));
        let (operation, _) = store
            .load_unambiguous_retained_tool_request(
                &AdmissionIdentifier::try_new("request", id)?,
                &fence,
                now_ms()?,
            )?
            .ok_or("retained observed admission")?;
        let joined = store.load_security_participant_flow_join(
            operation.binding().operation_id(),
            &fence,
            now_ms()?,
        )?;
        assert_eq!(joined.is_some(), joins);
        Ok(())
    };
    let initial = observe()?;
    assert!(initial.snapshot().is_none());
    assert_eq!(initial.stored_context_generation(), None);
    evaluate("first-observed-admission", &initial, true)?;
    let first = observe()?;
    assert!(first.stored_context_generation().is_some());
    evaluate("second-observed-admission", &first, true)?;
    let second = observe()?;
    assert!(second.stored_context_generation() > first.stored_context_generation());
    evaluate("stale-observed-admission", &first, false)?;
    // Mandatory history readback must not obscure the physical write denial.
    assert_eq!(hook.stale_denials.load(Ordering::SeqCst), 1);
    assert_eq!(observe()?.snapshot(), second.snapshot());
    evaluate("refreshed-observed-admission", &second, true)?;
    assert!(observe()?.stored_context_generation() > second.stored_context_generation());
    assert_eq!(hook.joined.load(Ordering::SeqCst), 3);
    Ok(())
}

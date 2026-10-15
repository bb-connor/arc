//! Real signed runtime artifacts and physical claims exercise the native
//! revalidation contract. A retained claim used here is test input, not a permit:
//! production capture additionally requires the kernel's live credential borrow.

use super::*;
use chio_kernel::admission_operation::runtime_participant::RuntimeParticipantClaimIntentV1;
use chio_kernel::admission_operation::{AdmissionOperationStore, RuntimeReplaySourceSnapshotV1};
use chio_kernel::{KernelError, RuntimeAdmissionDecision, RuntimeParticipantClaimAuthority};

type Hook = ChioRuntimeAdmissionHook<SqliteRuntimeOrchestrationStore>;

#[test]
fn native_swarm_evolution_preserves_treaty_and_original_physical_claim() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let (prior, next) = crate::swarm_evolution::treaty_versions()?;
    let fixture = CombinedFixture::with_swarm_input(None, |_, _, _| Ok(()), prior.clone())?;
    // A restart must retain the owner's verifier configuration, not generate a
    // fresh trust root as the default independent-test fixture does.
    let policy_inputs = signed_policy_inputs(0.1)?;
    let hook = Arc::new(
        fixture
            .inner
            .hook_with_inputs(policy_inputs.clone())?
            .with_swarm_witness_keys(trusted_swarm_witness_keys()),
    );
    let kernel = fixture.kernel(SharedHook(hook.clone()))?;
    let response = kernel.evaluate_tool_call_blocking_with_metadata(
        &fixture.inner.request,
        Some(swarm_route_metadata()),
    )?;
    assert_eq!(response.verdict, Verdict::Allow, "{response:#?}");
    assert!(kernel
        .federation_dsse_envelope(&response.receipt.id)
        .is_some());
    let (source, intent) = physical_input(&fixture.inner)?;
    assert_eq!(intent.resources().len(), 3);
    let before = faults::history(&fixture.inner)?;
    crate::swarm_evolution::open(&fixture.inner._directory.path().join("runtime.sqlite3"))?
        .extend_swarm_authority_bundle(
            &canonical_test_hash(&prior)?,
            next,
            &trusted_swarm_witness_keys(),
        )?;
    // This explicitly exercises historical artifact resolution; a completed
    // request's fast receipt replay alone would not test the changed resolver.
    hook.revalidate_operation_owned_for_native_capture(
        &revalidation_input(&fixture.inner, &response),
        &source,
        &intent,
    )?
    .validate_at(NOW)?;
    drop(kernel);
    drop(hook);
    let fixture = fixture.reopen()?;
    let hook = fixture
        .inner
        .hook_with_inputs(policy_inputs)?
        .with_swarm_witness_keys(trusted_swarm_witness_keys());
    let (source, intent) = physical_input(&fixture.inner)?;
    hook.revalidate_operation_owned_for_native_capture(
        &revalidation_input(&fixture.inner, &response),
        &source,
        &intent,
    )?
    .validate_at(NOW)?;
    let mut stripped = fixture.inner.request.clone();
    stripped
        .governed_intent
        .as_mut()
        .and_then(|i| i.context.as_mut())
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("context")?
        .remove("chioTreaty");
    let mut context = revalidation_input(&fixture.inner, &response);
    context.request = &stripped;
    assert!(hook
        .revalidate_operation_owned_for_native_capture(&context, &source, &intent)
        .is_err());
    let kernel = fixture.kernel(hook)?;
    let replay = kernel.evaluate_tool_call_blocking_with_metadata(
        &fixture.inner.request,
        Some(swarm_route_metadata()),
    )?;
    assert_eq!(
        canonical_json_bytes(&response.receipt)?,
        canonical_json_bytes(&replay.receipt)?
    );
    assert_eq!(faults::history(&fixture.inner)?, before);
    assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

struct SharedHook(Arc<Hook>);

impl RuntimeAdmissionHook for SharedHook {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn runtime_participant_binding(&self) -> Option<&RuntimeParticipantAuthorityBindingV1> {
        self.0.runtime_participant_binding()
    }
    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }
    fn enforces_swarm_authority(&self) -> bool {
        self.0.enforces_swarm_authority()
    }
    fn evaluate(
        &self,
        _: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        panic!("native validity fixture cannot use legacy admission")
    }
    fn evaluate_operation_owned(
        &self,
        context: &RuntimeAdmissionContext<'_>,
        authority: &RuntimeParticipantClaimAuthority<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.0.evaluate_operation_owned(context, authority)
    }
    fn revalidate_operation_owned_before_dispatch(
        &self,
        context: &RuntimeAdmissionRevalidationContext<'_>,
        source: &RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), KernelError> {
        self.0
            .revalidate_operation_owned_before_dispatch(context, source)
    }
}

fn revalidation_input<'a>(
    fixture: &'a Fixture,
    response: &'a chio_kernel::ToolCallResponse,
) -> RuntimeAdmissionRevalidationContext<'a> {
    RuntimeAdmissionRevalidationContext {
        request: &fixture.request,
        admission_metadata: response.receipt.metadata.as_ref(),
        now_unix_ms: NOW,
        now_unix_secs: NOW / 1000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".into(),
    }
}

fn physical_input(
    fixture: &Fixture,
) -> TestResult<(
    RuntimeReplaySourceSnapshotV1,
    RuntimeParticipantClaimIntentV1,
)> {
    let history = super::super::faults::history(fixture)?;
    assert_eq!(history.len(), 1);
    assert!(!history[0].intent.resources().is_empty());
    let source = fixture
        .authority
        .admission_operation_store()
        .load_runtime_participant_activation(
            &fixture.binding,
            &fixture.authority.mutation_fence(),
            NOW,
        )?;
    Ok((source, history[0].intent.clone()))
}

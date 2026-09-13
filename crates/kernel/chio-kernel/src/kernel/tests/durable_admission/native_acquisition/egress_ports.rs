//! A backend without native egress support must never acknowledge custody.
use super::*;
use crate::admission_operation::{
    NativeSecurityEgressContext, QualifiedAdmissionOperationStoreExt,
};
use crate::kernel::admission_coordinator::DispatchTransport;
use chio_security_types::ports::{
    Digest32, EgressFence, EgressFenceCommit, EgressFenceRequest, FlowStateKey, RequestId,
};

#[test]
fn unsupported_native_egress_ports_reject_commands_and_history_without_mutation(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut kernel, request, store, calls) =
        durable_admission_fixture("native-egress-unsupported");
    let binding = selection("source");
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(Arc::new(Hook {
        mode: HookMode::Normal,
        binding: Mutex::new(binding.clone()),
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
        .ok_or("durable native operation absent")?;
    let fence = store
        .fence
        .lock()
        .map_err(|_| "test fence poisoned")?
        .clone();
    let lease = store.claim_recovery(
        admission.operation().binding().operation_id(),
        admission.operation().version(),
        &AdmissionIdentifier::try_new("claimant", "native-egress-unsupported")?,
        now,
        now + 60_000,
        &fence,
    )?;
    let input = NativeSecurityEgressContext {
        operation: admission.operation(),
        lease: &lease,
        binding: &binding,
        security_context: &context,
        request: &request,
        trusted_now_unix_ms: now,
    };
    let trusted = context.as_v1();
    let plan = EgressFenceRequest {
        key: FlowStateKey {
            tenant_id: trusted.tenant_id().clone(),
            principal_id: trusted.principal_id().clone(),
            lineage_id: trusted.lineage_root_id().clone(),
            session_id: trusted.session_id().clone(),
            isolation_epoch_id: trusted.isolation_epoch_id().clone(),
        },
        request_id: RequestId::new(&request.request_id)?,
        request_hash: Digest32::new([0; 32]),
        expected_context_generation: 1,
        expires_at_unix_ms: now + 10_000,
    };
    // Command-shaped data is not acquired authority. The default backend must
    // report unsupported, not return an acknowledgement or empty valid history.
    let command = EgressFenceCommit {
        fence: EgressFence {
            fence_id: RecordId::new("never-acquired-fence")?,
            key: plan.key.clone(),
            request_id: plan.request_id.clone(),
            request_hash: plan.request_hash,
            context_generation: plan.expected_context_generation,
            expires_at_unix_ms: plan.expires_at_unix_ms,
        },
        dispatch_commitment_id: RecordId::new("never-committed-dispatch")?,
        committed_at_unix_ms: now,
    };
    let port: &dyn AdmissionOperationStore = store.as_ref();
    assert_eq!(
        port.acquire_native_security_egress(&input, &plan).err(),
        Some(AdmissionOperationStoreError::Unavailable(
            "operation-owned native egress acquisition is unsupported".into()
        ))
    );
    assert_eq!(
        port.commit_native_security_egress(&input, &command).err(),
        Some(AdmissionOperationStoreError::Unavailable(
            "operation-owned native egress commitment is unsupported".into()
        ))
    );
    assert_eq!(
        port.load_native_security_egress(
            admission.operation().binding().operation_id(),
            lease.store_fence(),
            now
        )
        .err(),
        Some(AdmissionOperationStoreError::Unavailable(
            "operation-owned native egress history is unsupported".into()
        ))
    );
    assert_eq!(store.operation(), *admission.operation());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

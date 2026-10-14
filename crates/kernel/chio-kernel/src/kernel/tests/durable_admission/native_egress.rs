//! Coordinator acknowledgement faults. Physical SQLite ownership is exercised
//! separately; no successful custody result activates native tool dispatch.
use super::*;
use crate::admission_operation::{
    AdmissionDigest, NativeSecurityAuthorityBindingV1, NativeSecurityEgressAcquisitionV1,
    NativeSecurityEgressCommitmentV1, NativeSecurityEgressContext, NativeSecurityEgressHistoryV1,
    NativeSecurityFlowObservationV1,
};
use crate::kernel::admission_coordinator::DispatchTransport;
use chio_security_types::ports::{
    CommittedEgressFence, EgressFence, EgressFenceCommit, EgressFenceRequest, FlowStateKey,
    FlowStateSnapshot, RecordId,
};
use chio_security_types::InformationLabel;
use std::sync::Mutex;

#[path = "native_egress/backend.rs"]
mod backend;
#[path = "native_egress/declassification.rs"]
mod declassification;
pub(super) use backend::TestEgress;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Debug, Default)]
enum Fault {
    #[default]
    None,
    Deny,
    NoWrite,
    LostAck,
    PanicWrite,
    WrongAck,
    MissingHistory,
    PanicRead,
    WrongBinding,
    WrongOperation,
    WrongRequest,
    ChangedAcquisition,
    WrongPredecessor,
    ChangedObservation,
    StaleObservationTime,
    FutureObservationTime,
    PhysicalEventClock,
    EarlyEventClock,
    FutureEventClock,
    StaleConsumptionClock,
}

struct Hook(NativeSecurityAuthorityBindingV1);
impl SecurityPreDispatchHook for Hook {
    fn name(&self) -> &str {
        "native-egress-test"
    }
    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        Ok(Some(self.0.clone()))
    }
    fn prepare_native_admission(
        &self,
        _: &NativeSecurityAdmissionContext<'_>,
        authority: &NativeSecurityFlowJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        super::native_acquisition::join(authority).map(|_| ())
    }
    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        panic!("native custody must not call legacy dispatch")
    }
}

pub(super) fn fixture(
    name: &str,
) -> TestResult<(
    ChioKernel,
    ToolCallRequest,
    SecurityInvocationContext,
    Arc<TestAdmissionOperationStore>,
)> {
    let (mut kernel, request, store, _) = durable_admission_fixture(name);
    let binding = NativeSecurityAuthorityBindingV1::new(
        AdmissionIdentifier::try_new("store", "native-store")?,
        AdmissionIdentifier::try_new("authority", "native-authority")?,
        AdmissionDigest::try_new("initialization", sha256_hex(b"native-init"))?,
    );
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(Arc::new(Hook(binding)));
    let context = security_binding::context(&request, 1)?;
    let now = current_unix_timestamp_ms();
    let matching = security_binding::matching(&request)?;
    let mut admission = kernel
        .begin_durable_tool_admission_for_transport(
            &request,
            &matching,
            Some(&context),
            now,
            DispatchTransport::KernelToolServer,
        )?
        .ok_or("original admission")?;
    kernel.run_native_admission_preparation(&request, Some(&context), Some(&admission), now)?;
    kernel
        .check_and_increment_budget(
            &request,
            &request.capability,
            &matching,
            false,
            Some(&mut admission),
            now,
        )?
        .into_authorized()?;
    kernel.mark_durable_capture_pending(&mut admission, now)?;
    // Model a later independent join. The kernel must observe generation 7,
    // never reuse the original join's historical generation 1.
    store.native_egress.enable(7)?;
    Ok((kernel, request, context, store))
}

#[test]
fn native_egress_coordinator_binds_fresh_generation_and_both_commitments() -> TestResult {
    let (kernel, mut request, context, store) = fixture("coordinator-positive")?;
    request.supplemental_authorization = Some(
        chio_core::capability::supplemental_authorization::OpaqueSupplementalAuthorization {
            signed_extension: "private-live-credential".into(),
        },
    );
    let operation = store.operation();
    let prepared = kernel.prepare_native_security_egress(
        operation.binding().operation_id(),
        &request,
        &context,
    )?;
    assert_eq!(prepared.observation().stored_context_generation(), Some(7));
    assert!(std::ptr::eq(prepared.request(), &request));
    assert_eq!(prepared.operation_id(), operation.binding().operation_id());
    assert!(prepared.validate_current()? >= prepared.observation().observed_at_unix_ms());
    assert!(store.native_egress.acquisition().is_err());
    assert_eq!(store.operation(), operation);
    assert_eq!(
        prepared.security_context().as_v1().flow_state_generation(),
        Some(7)
    );
    assert_eq!(
        format!("{prepared:?}"),
        "PreparedNativeSecurityEgress { .. }"
    );
    let expected_commitment = crate::kernel::dispatch::derive_security_dispatch_commitment_id(
        &canonical_json_bytes(&request)?,
        prepared.security_context(),
    )?;
    let acquired = prepared.acquire(current_unix_timestamp_ms() + 60_000)?;
    assert_eq!(
        format!("{acquired:?}"),
        "AcquiredNativeSecurityEgress { .. }"
    );
    let acquisition = acquired.history().acquisition.clone();
    let history = acquired.commit()?;
    assert_eq!(history.acquisition, acquisition);
    assert_eq!(
        history.live_request_hash.as_str(),
        sha256_hex(&canonical_json_bytes(&request)?)
    );
    assert_eq!(
        history.acquisition.fence.request_hash.as_bytes(),
        chio_core::sha256(&canonical_json_bytes(&request.arguments)?).as_bytes()
    );
    let committed = history.commitment.ok_or("commitment")?;
    assert_eq!(committed.acquisition_digest, acquisition.event_digest);
    assert_eq!(
        committed.commitment.dispatch_commitment_id,
        expected_commitment
    );
    assert_eq!(store.operation(), operation);
    // The ordinary entry point still refuses native lifecycle activation.
    assert_eq!(
        kernel
            .run_security_pre_dispatch_hook(&request, Some(&context), None)
            .err()
            .ok_or("dispatch denied")?
            .reason,
        "native security dispatch lifecycle is unsupported"
    );
    Ok(())
}

#[test]
fn native_egress_acquisition_faults_never_return_custody_and_read_after_writes() -> TestResult {
    for fault in [
        Fault::Deny,
        Fault::NoWrite,
        Fault::LostAck,
        Fault::PanicWrite,
        Fault::WrongAck,
        Fault::MissingHistory,
        Fault::PanicRead,
        Fault::WrongBinding,
        Fault::WrongOperation,
        Fault::WrongRequest,
        Fault::ChangedObservation,
    ] {
        let (kernel, request, context, store) = fixture(&format!("acquire-{fault:?}"))?;
        let operation = store.operation();
        let prepared = kernel.prepare_native_security_egress(
            operation.binding().operation_id(),
            &request,
            &context,
        )?;
        store.native_egress.arm(fault)?;
        let error = prepared
            .acquire(current_unix_timestamp_ms() + 60_000)
            .err()
            .ok_or("fault accepted")?;
        if matches!(fault, Fault::Deny) {
            assert!(
                error.to_string().contains("injected write denial"),
                "{error}"
            );
        }
        assert_eq!(store.native_egress.reads()?, 1, "{fault:?}");
        assert_eq!(store.operation(), operation);
        store.native_egress.arm(Fault::None)?;
        // Panics must not poison the kernel's mutation sequencer.
        let _prepared = kernel.prepare_native_security_egress(
            operation.binding().operation_id(),
            &request,
            &context,
        )?;
    }
    Ok(())
}

#[test]
fn native_egress_commit_faults_preserve_acquisition_and_deny_success() -> TestResult {
    for fault in [
        Fault::Deny,
        Fault::NoWrite,
        Fault::LostAck,
        Fault::PanicWrite,
        Fault::WrongAck,
        Fault::MissingHistory,
        Fault::PanicRead,
        Fault::WrongBinding,
        Fault::WrongOperation,
        Fault::WrongRequest,
        Fault::ChangedAcquisition,
        Fault::WrongPredecessor,
        Fault::ChangedObservation,
    ] {
        let (kernel, request, context, store) = fixture(&format!("commit-{fault:?}"))?;
        let operation = store.operation();
        let acquired = kernel
            .prepare_native_security_egress(operation.binding().operation_id(), &request, &context)?
            .acquire(current_unix_timestamp_ms() + 60_000)?;
        let original = acquired.history().acquisition.clone();
        store.native_egress.arm_commit(fault)?;
        let error = acquired.commit().err().ok_or("commit fault accepted")?;
        if matches!(fault, Fault::Deny) {
            assert!(
                error.to_string().contains("injected write denial"),
                "{error}"
            );
        }
        assert_eq!(
            store.native_egress.reads()?,
            4,
            "{fault:?}: pre-write and post-write readbacks"
        );
        assert_eq!(store.native_egress.acquisition()?, original);
        assert_eq!(store.operation(), operation);
        store.native_egress.arm(Fault::None)?;
        let _prepared = kernel.prepare_native_security_egress(
            operation.binding().operation_id(),
            &request,
            &context,
        )?;
    }
    Ok(())
}

#[test]
fn native_egress_commit_accepts_the_physical_event_clock_after_preparation() -> TestResult {
    let (kernel, request, context, store) = fixture("physical-event-clock")?;
    let operation = store.operation();
    let acquired = kernel
        .prepare_native_security_egress(operation.binding().operation_id(), &request, &context)?
        .acquire(current_unix_timestamp_ms() + 60_000)?;
    let before_commit = current_unix_timestamp_ms();
    store.native_egress.arm_commit(Fault::PhysicalEventClock)?;
    let history = acquired.commit()?;
    let committed = history.commitment.ok_or("commitment")?;
    assert!(committed.commitment.committed_at_unix_ms > before_commit);
    assert_eq!(store.operation(), operation);
    Ok(())
}

#[test]
fn native_egress_commit_event_clock_must_fall_inside_the_physical_interval() -> TestResult {
    for fault in [Fault::EarlyEventClock, Fault::FutureEventClock] {
        let (kernel, request, context, store) = fixture(&format!("event-clock-{fault:?}"))?;
        let operation = store.operation();
        let acquired = kernel
            .prepare_native_security_egress(operation.binding().operation_id(), &request, &context)?
            .acquire(current_unix_timestamp_ms() + 60_000)?;
        let original = acquired.history().acquisition.clone();
        store.native_egress.arm_commit(fault)?;
        let error = acquired.commit().err().ok_or("event clock accepted")?;
        assert!(
            error.to_string().contains("event clock differs"),
            "{fault:?}: {error}"
        );
        assert_eq!(store.native_egress.acquisition()?, original);
        assert_eq!(store.operation(), operation);
    }
    Ok(())
}

#[cfg(feature = "admission-test-support")]
#[test]
fn native_egress_commit_after_a_writer_delay_keeps_the_original_expiry() -> TestResult {
    for (lifetime_ms, delay_ms, commits) in [(60_000_u64, 5_100_u64, true), (1_000, 1_200, false)] {
        let (kernel, request, context, store) = fixture(&format!("writer-delay-{delay_ms}"))?;
        let operation = store.operation();
        let acquired = kernel
            .prepare_native_security_egress(operation.binding().operation_id(), &request, &context)?
            .acquire(current_unix_timestamp_ms() + lifetime_ms)?;
        let prepared_at = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let _observer = kernel.observe_native_egress_commit_for_test(Arc::new({
            let prepared_at = prepared_at.clone();
            let owner_thread = std::thread::current().id();
            move |time| {
                // Other parallel fixtures share this test store identity. Only
                // this synchronous owner's commit may incur the injected wait.
                if std::thread::current().id() != owner_thread {
                    return;
                }
                prepared_at.store(time, std::sync::atomic::Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            }
        }))?;
        store.native_egress.arm_commit(Fault::PhysicalEventClock)?;
        let result = acquired.commit();
        if commits {
            let committed = result?.commitment.ok_or("commitment")?;
            assert!(
                committed.commitment.committed_at_unix_ms
                    > prepared_at.load(std::sync::atomic::Ordering::SeqCst) + 5_000
            );
        } else {
            let error = result.err().ok_or("expired fence accepted")?;
            assert!(error.to_string().contains("expired or invalid"), "{error}");
            assert!(!store.native_egress.committed()?);
        }
        assert_eq!(store.operation(), operation);
    }
    Ok(())
}

#[test]
fn native_egress_slow_post_write_verification_refuses_at_the_final_deadline() -> TestResult {
    // The first case keeps the fence alive through the same slow readback.
    for (fence_lifetime_ms, readback_delay_ms, accepted) in
        [(60_000_u64, 1_800_u64, true), (1_500, 1_800, false)]
    {
        let (kernel, request, context, store) =
            fixture(&format!("slow-readback-{readback_delay_ms}"))?;
        let operation = store.operation();
        let acquired = kernel
            .prepare_native_security_egress(operation.binding().operation_id(), &request, &context)?
            .acquire(current_unix_timestamp_ms() + fence_lifetime_ms)?;
        let original = acquired.history().acquisition.clone();
        store
            .native_egress
            .delay_committed_readback(readback_delay_ms)?;
        let result = acquired.commit();
        if accepted {
            assert!(result?.commitment.is_some());
        } else {
            let error = result
                .err()
                .ok_or("expired fence accepted after readback")?;
            assert!(error.to_string().contains("expired or invalid"), "{error}");
            // The write already happened; custody stays visible to recovery.
            assert!(store.native_egress.committed()?);
        }
        assert_eq!(store.native_egress.acquisition()?, original);
        assert_eq!(store.operation(), operation);
    }
    Ok(())
}

#[test]
fn native_egress_expired_fence_refuses_commit_before_any_physical_write() -> TestResult {
    let (kernel, request, context, store) = fixture("expired-before-commit")?;
    let operation = store.operation();
    let acquired = kernel
        .prepare_native_security_egress(operation.binding().operation_id(), &request, &context)?
        .acquire(current_unix_timestamp_ms() + 1_000)?;
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    let error = acquired.commit().err().ok_or("expired fence accepted")?;
    assert!(error.to_string().contains("expired or invalid"), "{error}");
    assert!(!store.native_egress.committed()?);
    assert_eq!(store.operation(), operation);
    Ok(())
}

#[test]
fn native_egress_changed_observation_or_expiry_denies_before_acquisition() -> TestResult {
    for expired in [false, true] {
        let (kernel, request, context, store) = fixture("stale-preparation")?;
        let operation = store.operation();
        let prepared = kernel.prepare_native_security_egress(
            operation.binding().operation_id(),
            &request,
            &context,
        )?;
        let deadline = if expired {
            1
        } else {
            store.native_egress.enable(8)?;
            assert!(prepared.validate_current().is_err());
            current_unix_timestamp_ms() + 60_000
        };
        assert!(prepared.acquire(deadline).is_err());
        assert_eq!(store.native_egress.reads()?, 0);
        assert!(store.native_egress.acquisition().is_err());
    }
    Ok(())
}

#[test]
fn native_egress_changed_live_material_or_identity_cannot_prepare() -> TestResult {
    let (mut kernel, request, context, store) = fixture("prepare-substitution")?;
    let operation = store.operation();
    let mut changed = request.clone();
    changed.arguments = serde_json::json!({"changed": true});
    assert!(kernel
        .prepare_native_security_egress(operation.binding().operation_id(), &changed, &context)
        .is_err());
    let changed_context = security_binding::context(&request, 2)?;
    assert!(kernel
        .prepare_native_security_egress(
            operation.binding().operation_id(),
            &request,
            &changed_context
        )
        .is_err());
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Optional);
    assert!(kernel
        .prepare_native_security_egress(operation.binding().operation_id(), &request, &context)
        .is_err());
    assert_eq!(store.native_egress.reads()?, 0);
    Ok(())
}

#[test]
fn native_egress_generation_change_after_acquisition_prevents_commitment() -> TestResult {
    let (kernel, request, context, store) = fixture("stale-acquisition")?;
    let operation = store.operation();
    let acquired = kernel
        .prepare_native_security_egress(operation.binding().operation_id(), &request, &context)?
        .acquire(current_unix_timestamp_ms() + 60_000)?;
    let original = acquired.history().acquisition.clone();
    store.native_egress.enable(8)?;
    assert!(acquired
        .commit()
        .err()
        .ok_or("stale generation accepted")?
        .to_string()
        .contains("observation changed"));
    assert_eq!(store.native_egress.acquisition()?, original);
    assert_eq!(store.native_egress.reads()?, 2);
    Ok(())
}

#[test]
fn native_egress_operation_change_after_preparation_prevents_acquisition() -> TestResult {
    let (kernel, request, context, store) = fixture("changed-admission")?;
    let operation = store.operation();
    let prepared = kernel.prepare_native_security_egress(
        operation.binding().operation_id(),
        &request,
        &context,
    )?;
    let mut persisted = operation.to_persisted();
    persisted.version += 1;
    store
        .state
        .lock()
        .map_err(|_| "test admission poisoned")?
        .operation = Some(AdmissionOperationV1::from_persisted(persisted)?);
    assert!(prepared.validate_current().is_err());
    assert!(prepared
        .acquire(current_unix_timestamp_ms() + 60_000)
        .is_err());
    assert!(store.native_egress.acquisition().is_err());
    assert_eq!(store.native_egress.reads()?, 0);
    Ok(())
}

#[test]
fn native_egress_observation_time_must_fall_inside_the_read_interval() -> TestResult {
    for fault in [Fault::StaleObservationTime, Fault::FutureObservationTime] {
        let (kernel, request, context, store) = fixture(&format!("observation-time-{fault:?}"))?;
        let operation = store.operation();
        store.native_egress.arm(fault)?;
        assert!(kernel
            .prepare_native_security_egress(operation.binding().operation_id(), &request, &context)
            .is_err());
        assert_eq!(store.native_egress.reads()?, 0);
        assert!(store.native_egress.acquisition().is_err());
    }
    Ok(())
}

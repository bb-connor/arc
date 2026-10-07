//! Default-off observations of the exact process broker validation operations.
//! Runtime/process identity is private data; a guard grants no native authority.
use super::{
    KernelError, ProcessArtifactBroker, ProcessError, ProcessId, ProcessRuntime, RequestId,
};
use std::cell::RefCell;
use std::io::Write;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;

thread_local! {
    static OBSERVER: RefCell<Option<Registration>> = const { RefCell::new(None) };
}

#[derive(Clone, PartialEq)]
struct OwnerKey {
    store: usize,
    kernel: usize,
    namespace: String,
    process: ProcessId,
}

impl OwnerKey {
    fn matches(&self, broker: &ProcessArtifactBroker, process: &ProcessId) -> bool {
        self.store == Arc::as_ptr(&broker.runtime.store) as usize
            && self.kernel == Arc::as_ptr(&broker.runtime.kernel) as usize
            && self.namespace == broker.runtime.namespace
            && &self.process == process
    }
}

struct Registration {
    owner: OwnerKey,
    last_call: u32,
    current_call: Option<u32>,
}

pub(super) struct ProcessValidationTraceGuard {
    owner: OwnerKey,
    // Retain the actual backing objects while their pointer identity is observed.
    _runtime: ProcessRuntime,
    _same_thread: PhantomData<Rc<()>>,
}

impl Drop for ProcessValidationTraceGuard {
    fn drop(&mut self) {
        OBSERVER.with(|observer| {
            if let Ok(mut registration) = observer.try_borrow_mut() {
                if registration
                    .as_ref()
                    .is_some_and(|active| active.owner == self.owner)
                {
                    *registration = None;
                }
            }
        });
    }
}

pub(super) fn register(
    broker: &ProcessArtifactBroker,
    process: &ProcessId,
    request: &RequestId,
) -> Result<ProcessValidationTraceGuard, KernelError> {
    if !matches!(
        request.as_str(),
        "chunked-checkpoint-lost-ack" | "chunked-checkpoint-prefix-refusal"
    ) {
        return Err(unavailable());
    }
    let owner = OwnerKey {
        store: Arc::as_ptr(&broker.runtime.store) as usize,
        kernel: Arc::as_ptr(&broker.runtime.kernel) as usize,
        namespace: broker.runtime.namespace.clone(),
        process: process.clone(),
    };
    OBSERVER.with(|observer| {
        let mut registration = observer.try_borrow_mut().map_err(|_| unavailable())?;
        if registration.is_some() {
            return Err(unavailable());
        }
        *registration = Some(Registration {
            owner: owner.clone(),
            last_call: 0,
            current_call: None,
        });
        Ok(ProcessValidationTraceGuard {
            owner,
            _runtime: broker.runtime.clone(),
            _same_thread: PhantomData,
        })
    })
}

pub(super) struct ValidationCallGuard {
    owner: Option<OwnerKey>,
    previous: Option<u32>,
    _same_thread: PhantomData<Rc<()>>,
}

impl Drop for ValidationCallGuard {
    fn drop(&mut self) {
        OBSERVER.with(|observer| {
            if let Ok(mut registration) = observer.try_borrow_mut() {
                if let (Some(active), Some(owner)) = (registration.as_mut(), &self.owner) {
                    if &active.owner == owner {
                        active.current_call = self.previous;
                    }
                }
            }
        });
    }
}

pub(super) fn begin(broker: &ProcessArtifactBroker, process: &ProcessId) -> ValidationCallGuard {
    let (owner, previous) = OBSERVER.with(|observer| {
        let Ok(mut registration) = observer.try_borrow_mut() else {
            return (None, None);
        };
        let Some(active) = registration.as_mut() else {
            return (None, None);
        };
        let previous = active.current_call.take();
        if active.owner.matches(broker, process) {
            active.current_call = active.last_call.checked_add(1);
            if let Some(call) = active.current_call {
                active.last_call = call;
            }
        }
        (Some(active.owner.clone()), previous)
    });
    ValidationCallGuard {
        owner,
        previous,
        _same_thread: PhantomData,
    }
}

pub(super) enum ValidationStage {
    EnforcedKnowledge,
    RecoverySecurityContext,
    IdentityComparison,
    RetainedLineage,
    CapabilityLiveness,
    RunningState,
}

impl ValidationStage {
    fn name(&self) -> &'static str {
        match self {
            Self::EnforcedKnowledge => "process_validation_enforced_knowledge",
            Self::RecoverySecurityContext => "process_validation_recovery_security_context",
            Self::IdentityComparison => "process_validation_identity_comparison",
            Self::RetainedLineage => "process_validation_retained_lineage",
            Self::CapabilityLiveness => "process_validation_capability_liveness",
            Self::RunningState => "process_validation_running_state",
        }
    }
}

fn current_call(broker: &ProcessArtifactBroker, process: &ProcessId) -> Option<u32> {
    OBSERVER.with(|observer| {
        let registration = observer.try_borrow().ok()?;
        let active = registration.as_ref()?;
        active
            .owner
            .matches(broker, process)
            .then_some(active.current_call)
            .flatten()
    })
}

pub(super) fn observe<T, E: 'static>(
    broker: &ProcessArtifactBroker,
    process: &ProcessId,
    stage: ValidationStage,
    lineage_index: Option<usize>,
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let call = current_call(broker, process);
    if let Some(call) = call {
        emit(stage.name(), call, lineage_index, "entered", None);
    }
    // Observe the original Result before its existing refusal mapping. Do not
    // rerun its kernel, native context, Store or activity check for diagnostics.
    let result = operation();
    if let Some(call) = call {
        match &result {
            Ok(_) => emit(stage.name(), call, lineage_index, "complete", None),
            Err(error) => emit(
                stage.name(),
                call,
                lineage_index,
                "error",
                Some(error_class(error)),
            ),
        }
    }
    result
}

pub(super) fn observe_identity(
    broker: &ProcessArtifactBroker,
    process: &ProcessId,
    comparison: impl FnOnce() -> bool,
) -> bool {
    let call = current_call(broker, process);
    if let Some(call) = call {
        emit(
            ValidationStage::IdentityComparison.name(),
            call,
            None,
            "entered",
            None,
        );
    }
    // Keep the original short-circuit predicate and refusal branch intact.
    let mismatch = comparison();
    if let Some(call) = call {
        emit(
            ValidationStage::IdentityComparison.name(),
            call,
            None,
            if mismatch { "mismatch" } else { "complete" },
            None,
        );
    }
    mismatch
}

fn error_class<E: 'static>(error: &E) -> &'static str {
    let error: &dyn std::any::Any = error;
    if let Some(error) = error.downcast_ref::<KernelError>() {
        return kernel_error_class(error);
    }
    if let Some(error) = error.downcast_ref::<ProcessError>() {
        return match error {
            ProcessError::Unauthenticated => "process_unauthenticated",
            ProcessError::Configuration(_) => "process_configuration",
            ProcessError::Invalid(_) => "process_invalid",
            ProcessError::NotFound(_) => "process_not_found",
            ProcessError::Cancelled(_) => "process_cancelled",
            ProcessError::Conflict => "process_conflict",
            ProcessError::Limit(_) => "process_limit",
            ProcessError::CheckpointConflict => "process_checkpoint_conflict",
            ProcessError::BlobMissing => "process_blob_missing",
            ProcessError::BlobCorrupt => "process_blob_corrupt",
            ProcessError::StorePoisoned => "process_store_poisoned",
            ProcessError::Io(_) => "process_io",
            ProcessError::Sqlite(_) => "process_sqlite",
            ProcessError::Json(_) => "process_json",
            ProcessError::Core(_) => "process_core",
            ProcessError::Kernel(error) => kernel_error_class(error),
        };
    }
    "other_operation_error"
}

fn kernel_error_class(error: &KernelError) -> &'static str {
    match error {
        KernelError::CapabilityExpired => "capability_expired",
        KernelError::CapabilityNotYetValid => "capability_not_yet_valid",
        KernelError::CapabilityRevoked(_) => "capability_revoked",
        KernelError::InvalidSignature => "invalid_signature",
        KernelError::UntrustedIssuer => "untrusted_issuer",
        KernelError::RecoveryAuthorityDenied => "recovery_authority_denied",
        KernelError::RecoveryMediationRequired => "recovery_mediation_required",
        KernelError::DurableAdmission(_) => "durable_admission",
        KernelError::DurableAdmissionRetained(_) => "durable_admission_retained",
        KernelError::Internal(_) => "internal",
        _ => "other_kernel_error",
    }
}

fn emit(
    stage: &'static str,
    call: u32,
    lineage_index: Option<usize>,
    status: &'static str,
    error: Option<&'static str>,
) {
    let _ = writeln!(
        std::io::stderr().lock(),
        "{}",
        serde_json::json!({
            "phase": stage,
            "call": call,
            "lineage_index": lineage_index,
            "status": status,
            "error_class": error,
        })
    );
}

fn unavailable() -> KernelError {
    KernelError::Internal("checkpoint process validation trace fixture unavailable".into())
}

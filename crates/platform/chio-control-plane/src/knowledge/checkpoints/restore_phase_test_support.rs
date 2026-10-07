//! Default-off observations of the exact synchronous Restore operations.
//! The thread-bound guard carries data identity only and grants no authority.
use super::{KernelError, NativeKnowledgeRuntime, RecoveryScopeV1, RequestId};
use chio_kernel::admission_operation::StoreMutationFence;
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
    fence: StoreMutationFence,
    scope: RecoveryScopeV1,
    request: RequestId,
}

impl OwnerKey {
    fn runtime_matches(&self, runtime: &NativeKnowledgeRuntime) -> bool {
        self.store == Arc::as_ptr(&runtime.store) as usize
            && self.fence == runtime.fence
            && self.scope == runtime.profile.scope
    }
}

struct Registration {
    owner: OwnerKey,
    last_call: u32,
    current_call: Option<u32>,
}

/// Keeping this guard alive enables only one closed fixture on this thread.
/// Rc's marker prevents moving a registration or its cleanup to another thread.
pub(super) struct RestoreTraceGuard {
    owner: OwnerKey,
    _same_thread: PhantomData<Rc<()>>,
}

impl Drop for RestoreTraceGuard {
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
    runtime: &NativeKnowledgeRuntime,
    request: &RequestId,
) -> Result<RestoreTraceGuard, KernelError> {
    if !matches!(
        request.as_str(),
        "chunked-checkpoint-lost-ack" | "chunked-checkpoint-prefix-refusal"
    ) {
        return Err(unavailable());
    }
    let owner = OwnerKey {
        store: Arc::as_ptr(&runtime.store) as usize,
        fence: runtime.fence.clone(),
        scope: runtime.profile.scope.clone(),
        request: request.clone(),
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
        Ok(RestoreTraceGuard {
            owner,
            _same_thread: PhantomData,
        })
    })
}

/// A synchronous call qualifies the existing registration only while it runs.
/// Nested or unselected Restore calls cannot inherit the enclosing call's tags.
pub(in crate::knowledge) struct RestoreCallGuard {
    owner: Option<OwnerKey>,
    previous: Option<u32>,
    _same_thread: PhantomData<Rc<()>>,
}

impl Drop for RestoreCallGuard {
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

pub(in crate::knowledge) fn begin(
    runtime: &NativeKnowledgeRuntime,
    request: &RequestId,
) -> RestoreCallGuard {
    let (owner, previous) = OBSERVER.with(|observer| {
        let Ok(mut registration) = observer.try_borrow_mut() else {
            return (None, None);
        };
        let Some(active) = registration.as_mut() else {
            return (None, None);
        };
        let previous = active.current_call.take();
        if active.owner.runtime_matches(runtime) && &active.owner.request == request {
            active.current_call = active.last_call.checked_add(1);
            if let Some(call) = active.current_call {
                active.last_call = call;
            }
        }
        (Some(active.owner.clone()), previous)
    });
    RestoreCallGuard {
        owner,
        previous,
        _same_thread: PhantomData,
    }
}

pub(in crate::knowledge) enum RestoreStage {
    AuthenticateActor,
    InitialCurrent,
    ProducerBrokerValidation,
    ProducerInstallationLookup,
    CheckpointLookup,
    RecipientSelection,
    InitialRecipientValidation,
    CheckpointCanonicalEnvelope,
    EnvelopeBound,
    ArtifactHandle,
    ArtifactPreparedRead,
    FrameByteBound,
    CurrentRecheck,
    FinalRecipientValidation,
    PrivateSealRead,
    PrivateSealEquality,
    RetainedAdmission,
    ReleaseCommittedCutpoint,
    BeforeDeliveryCutpoint,
    UncertainAcknowledgement,
    SinkDelivery,
    DeliveryCompletedCutpoint,
    DeliveryAcknowledgement,
    DeliveryResult,
}

impl RestoreStage {
    fn name(&self) -> &'static str {
        match self {
            Self::AuthenticateActor => "restore_inner_authenticate_actor",
            Self::InitialCurrent => "restore_inner_initial_current",
            Self::ProducerBrokerValidation => "restore_inner_producer_broker_validation",
            Self::ProducerInstallationLookup => "restore_inner_producer_installation_lookup",
            Self::CheckpointLookup => "restore_inner_checkpoint_lookup",
            Self::RecipientSelection => "restore_inner_recipient_selection",
            Self::InitialRecipientValidation => "restore_inner_initial_recipient_validation",
            Self::CheckpointCanonicalEnvelope => "restore_inner_checkpoint_canonical_envelope",
            Self::EnvelopeBound => "restore_inner_envelope_bound",
            Self::ArtifactHandle => "restore_inner_artifact_handle",
            Self::ArtifactPreparedRead => "restore_inner_artifact_prepared_read",
            Self::FrameByteBound => "restore_inner_frame_byte_bound",
            Self::CurrentRecheck => "restore_inner_current_recheck",
            Self::FinalRecipientValidation => "restore_inner_final_recipient_validation",
            Self::PrivateSealRead => "restore_inner_private_seal_read",
            Self::PrivateSealEquality => "restore_inner_private_seal_equality",
            Self::RetainedAdmission => "restore_inner_retained_admission",
            Self::ReleaseCommittedCutpoint => "restore_inner_release_committed_cutpoint",
            Self::BeforeDeliveryCutpoint => "restore_inner_before_delivery_cutpoint",
            Self::UncertainAcknowledgement => "restore_inner_uncertain_acknowledgement",
            Self::SinkDelivery => "restore_inner_sink_delivery",
            Self::DeliveryCompletedCutpoint => "restore_inner_delivery_completed_cutpoint",
            Self::DeliveryAcknowledgement => "restore_inner_delivery_acknowledgement",
            Self::DeliveryResult => "restore_inner_delivery_result",
        }
    }
}

pub(in crate::knowledge) fn observe<T, E: 'static>(
    runtime: &NativeKnowledgeRuntime,
    stage: RestoreStage,
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let call = OBSERVER.with(|observer| {
        let registration = observer.try_borrow().ok()?;
        let active = registration.as_ref()?;
        active
            .owner
            .runtime_matches(runtime)
            .then_some(active.current_call)
            .flatten()
    });
    if let Some(call) = call {
        emit(stage.name(), call, "entered", None);
    }
    // The original operation runs exactly once. Neither a trace failure nor a
    // disabled guard changes its authority checks, timing input or Result.
    let result = operation();
    if let Some(call) = call {
        match &result {
            Ok(_) => emit(stage.name(), call, "complete", None),
            Err(error) => emit(stage.name(), call, "error", Some(error_class(error))),
        }
    }
    result
}

fn error_class<E: 'static>(error: &E) -> &'static str {
    let error: &dyn std::any::Any = error;
    if let Some(error) = error.downcast_ref::<KernelError>() {
        return match error {
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
        };
    }
    "other_operation_error"
}

fn emit(stage: &'static str, call: u32, status: &'static str, error: Option<&'static str>) {
    let _ = writeln!(
        std::io::stderr().lock(),
        "{}",
        serde_json::json!({
            "phase": stage,
            "call": call,
            "status": status,
            "error_class": error,
        })
    );
}

fn unavailable() -> KernelError {
    KernelError::Internal("checkpoint restore trace fixture unavailable".into())
}

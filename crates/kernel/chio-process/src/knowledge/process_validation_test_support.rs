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
            ProcessError::ConfinedReturnAlreadyOrdered => "process_confined_return_already_ordered",
            ProcessError::Conflict => "process_conflict",
            ProcessError::Limit(_) => "process_limit",
            ProcessError::CheckpointConflict => "process_checkpoint_conflict",
            ProcessError::BlobMissing => "process_blob_missing",
            ProcessError::BlobCorrupt => "process_blob_corrupt",
            ProcessError::StorePoisoned => "process_store_poisoned",
            ProcessError::Io(_) => "process_io",
            ProcessError::Sqlite(_) => "process_sqlite",
            ProcessError::Json(_) => "process_json",
            ProcessError::Core(error) => core_error_class(error),
            ProcessError::Kernel(error) => kernel_error_class(error),
        };
    }
    "other_operation_error"
}

// All error output is a source-pinned static category. Payloads never cross
// this diagnostic boundary, including IDs, timestamps and backend messages.
fn kernel_error_class(error: &KernelError) -> &'static str {
    match error {
        KernelError::UnknownSession(_) => "unknown_session",
        KernelError::SessionAlreadyExists(_) => "session_already_exists",
        KernelError::Session(error) => session_error_class(error),
        KernelError::CapabilityExpired => "capability_expired",
        KernelError::CapabilityNotYetValid => "capability_not_yet_valid",
        KernelError::CapabilityRevoked(_) => "capability_revoked",
        KernelError::InvalidSignature => "invalid_signature",
        KernelError::UntrustedIssuer => "untrusted_issuer",
        KernelError::RecoveryAuthorityDenied => "recovery_authority_denied",
        KernelError::RecoveryMediationRequired => "recovery_mediation_required",
        KernelError::CapabilityIssuanceFailed(_) => "capability_issuance_failed",
        KernelError::CapabilityIssuanceDenied(_) => "capability_issuance_denied",
        KernelError::OutOfScope { .. } => "out_of_scope",
        KernelError::OutOfScopeResource { .. } => "out_of_scope_resource",
        KernelError::OutOfScopePrompt { .. } => "out_of_scope_prompt",
        KernelError::BudgetExhausted(_) => "budget_exhausted",
        KernelError::CapturedBudgetReplay(_) => "captured_budget_replay",
        KernelError::DirectDispatchUnavailable => "direct_dispatch_unavailable",
        KernelError::SubjectMismatch { .. } => "subject_mismatch",
        KernelError::DelegationChainRevoked(_) => "delegation_chain_revoked",
        KernelError::DelegationInvalid(_) => "delegation_invalid",
        KernelError::InvalidConstraint(_) => "invalid_constraint",
        KernelError::GovernedTransactionDenied(_) => "governed_transaction_denied",
        KernelError::ActiveResponseNeverCommitted(_) => "active_response_never_committed",
        KernelError::GuardDenied(reason) => guard_denial_class(reason),
        KernelError::ToolServerError(_) => "tool_server_error",
        KernelError::RequestIncomplete(_) => "request_incomplete",
        KernelError::InvalidReceiptMetadata(_) => "invalid_receipt_metadata",
        KernelError::FlowRuntimeUnavailable => "flow_runtime_unavailable",
        KernelError::ToolNotRegistered(_) => "tool_not_registered",
        KernelError::ResourceNotRegistered(_) => "resource_not_registered",
        KernelError::ResourceRootDenied { .. } => "resource_root_denied",
        KernelError::PromptNotRegistered(_) => "prompt_not_registered",
        KernelError::SamplingNotAllowedByPolicy => "sampling_not_allowed_by_policy",
        KernelError::SamplingNotNegotiated => "sampling_not_negotiated",
        KernelError::SamplingContextNotSupported => "sampling_context_not_supported",
        KernelError::SamplingToolUseNotAllowedByPolicy => "sampling_tool_use_not_allowed_by_policy",
        KernelError::SamplingToolUseNotNegotiated => "sampling_tool_use_not_negotiated",
        KernelError::ElicitationNotAllowedByPolicy => "elicitation_not_allowed_by_policy",
        KernelError::ElicitationNotNegotiated => "elicitation_not_negotiated",
        KernelError::ElicitationFormNotSupported => "elicitation_form_not_supported",
        KernelError::ElicitationUrlNotSupported => "elicitation_url_not_supported",
        KernelError::UrlElicitationsRequired { .. } => "url_elicitations_required",
        KernelError::RootsNotNegotiated => "roots_not_negotiated",
        KernelError::InvalidChildRequestParent => "invalid_child_request_parent",
        KernelError::RequestCancelled { .. } => "request_cancelled",
        KernelError::ReceiptSigningFailed(_) => "receipt_signing_failed",
        KernelError::ReceiptPersistence(error) => receipt_error_class(error),
        KernelError::RevocationStore(error) => revocation_error_class(error),
        KernelError::BudgetStore(error) => budget_error_class(error),
        KernelError::DurableAdmission(_) => "durable_admission",
        KernelError::DurableAdmissionRetained(_) => "durable_admission_retained",
        KernelError::SecurityDispatchOutcomeRecoveryRequired(_) => {
            "security_dispatch_outcome_recovery_required"
        }
        KernelError::FindingDenied(_) => "finding_denied",
        KernelError::NoCrossCurrencyOracle { .. } => "no_cross_currency_oracle",
        KernelError::CrossCurrencyOracle(_) => "cross_currency_oracle",
        KernelError::Web3EvidenceUnavailable(_) => "web3_evidence_unavailable",
        KernelError::SettlementConfiguration(error) => settlement_config_error_class(error),
        KernelError::Internal(_) => "internal",
        KernelError::DpopVerificationFailed(_) => "dpop_verification_failed",
        KernelError::RuntimeAdmissionReadinessTimeout { .. } => {
            "runtime_admission_readiness_timeout"
        }
        KernelError::ReplayClockAnomaly { direction, .. } => match direction {
            chio_kernel::ReplayClockDirection::Rollback => "replay_clock_rollback",
            chio_kernel::ReplayClockDirection::ForwardJump => "replay_clock_forward_jump",
        },
        KernelError::ApprovalRejected(_) => "approval_rejected",
        KernelError::SyncBridgeIncompatibleWithCurrentThreadRuntime => {
            "sync_bridge_incompatible_with_current_thread_runtime"
        }
        KernelError::ReservingAuthorizationRejectsPresentedNonce => {
            "reserving_authorization_rejects_presented_nonce"
        }
        KernelError::Overloaded { resource } => overload_error_class(resource),
        KernelError::HotPathDeadlineExceeded { stage, .. } => match stage {
            chio_kernel::HotPathStage::GuardPipeline => "hot_path_deadline_guard_pipeline",
            chio_kernel::HotPathStage::Dispatch => "hot_path_deadline_dispatch",
            chio_kernel::HotPathStage::ReceiptAppend => "hot_path_deadline_receipt_append",
        },
        KernelError::ReceiptWriterUnavailable(_) => "receipt_writer_unavailable",
    }
}

fn guard_denial_class(reason: &str) -> &'static str {
    // Exact literals come from the retained-capability and non-tool verifier
    // paths. Dynamic reasons fall back to their known GuardDenied family; never
    // parse, format or expose an original message or infer a typed backend cause.
    match reason {
        "original capability snapshot is absent" => "guard_denied_original_snapshot_absent",
        "capability liveness requires original signed token evidence" => {
            "guard_denied_original_signed_evidence_absent"
        }
        "original capability identity does not match" => "guard_denied_original_identity_mismatch",
        "kernel emergency stop active" => "guard_denied_emergency_stop",
        "capability issuer is not a trusted CA" => "guard_denied_untrusted_issuer",
        "capability signature is invalid" => "guard_denied_invalid_signature",
        "capability not yet valid" => "guard_denied_capability_not_yet_valid",
        "capability has expired" => "guard_denied_capability_expired",
        "delegation chain exceeds configured maximum depth" => {
            "guard_denied_delegation_depth_exceeded"
        }
        "delegated capability has no root delegation link" => {
            "guard_denied_missing_delegation_root"
        }
        _ => "guard_denied",
    }
}

fn receipt_error_class(error: &chio_kernel::ReceiptStoreError) -> &'static str {
    use chio_kernel::ReceiptStoreError;
    match error {
        ReceiptStoreError::Sqlite(_) => "receipt_store_sqlite",
        ReceiptStoreError::Pool(_) => "receipt_store_pool",
        ReceiptStoreError::Timeout { .. } => "receipt_store_timeout",
        ReceiptStoreError::Json(_) => "receipt_store_json",
        ReceiptStoreError::Io(_) => "receipt_store_io",
        ReceiptStoreError::CryptoDecode(_) => "receipt_store_crypto_decode",
        ReceiptStoreError::Canonical(_) => "receipt_store_canonical",
        ReceiptStoreError::InvalidOutcome(_) => "receipt_store_invalid_outcome",
        ReceiptStoreError::ReadBoundary(_) => "receipt_store_read_boundary",
        ReceiptStoreError::Conflict(_) => "receipt_store_conflict",
        ReceiptStoreError::NotFound(_) => "receipt_store_not_found",
        ReceiptStoreError::Unsupported(_) => "receipt_store_unsupported",
        ReceiptStoreError::Fenced => "receipt_store_fenced",
        ReceiptStoreError::OutcomeUnknown(_) => "receipt_store_outcome_unknown",
        ReceiptStoreError::RetentionArchiveIncomplete { .. } => {
            "receipt_store_retention_archive_incomplete"
        }
        ReceiptStoreError::RetentionWatermarkRegression { .. } => {
            "receipt_store_retention_watermark_regression"
        }
        ReceiptStoreError::ArchivedRangeProjection { .. } => {
            "receipt_store_archived_range_projection"
        }
        ReceiptStoreError::RetentionTenantScopeUnsupported => {
            "receipt_store_retention_tenant_scope_unsupported"
        }
        ReceiptStoreError::WriterDead { .. } => "receipt_store_writer_dead",
    }
}

fn revocation_error_class(error: &chio_kernel::RevocationStoreError) -> &'static str {
    use chio_kernel::RevocationStoreError;
    match error {
        RevocationStoreError::Sqlite(_) => "revocation_store_sqlite",
        RevocationStoreError::Io(_) => "revocation_store_io",
        RevocationStoreError::Sync(_) => "revocation_store_sync",
        RevocationStoreError::OutcomeUnknown(_) => "revocation_store_outcome_unknown",
        RevocationStoreError::Fenced { .. } => "revocation_store_fenced",
    }
}

fn budget_error_class(error: &chio_kernel::BudgetStoreError) -> &'static str {
    use chio_kernel::BudgetStoreError;
    match error {
        BudgetStoreError::Sqlite(_) => "budget_store_sqlite",
        BudgetStoreError::Io(_) => "budget_store_io",
        BudgetStoreError::Overflow(_) => "budget_store_overflow",
        BudgetStoreError::Fenced { .. } => "budget_store_fenced",
        BudgetStoreError::Invariant(_) => "budget_store_invariant",
        BudgetStoreError::OutcomeUnknown(_) => "budget_store_outcome_unknown",
    }
}

fn session_error_class(error: &chio_kernel::SessionError) -> &'static str {
    use chio_kernel::SessionError;
    match error {
        SessionError::InvalidTransition { .. } => "session_invalid_transition",
        SessionError::OperationNotAllowed { .. } => "session_operation_not_allowed",
        SessionError::ContextSessionMismatch { .. } => "session_context_mismatch",
        SessionError::ContextAgentMismatch { .. } => "session_agent_mismatch",
        SessionError::DuplicateInflightRequest { .. } => "session_duplicate_inflight_request",
        SessionError::DuplicateRequestLineage { .. } => "session_duplicate_request_lineage",
        SessionError::RequestNotInflight { .. } => "session_request_not_inflight",
        SessionError::ExecutionNonceRetryMismatch { .. } => {
            "session_execution_nonce_retry_mismatch"
        }
        SessionError::ThresholdApprovalRetryMismatch { .. } => {
            "session_threshold_approval_retry_mismatch"
        }
        SessionError::RequestNotCancellable { .. } => "session_request_not_cancellable",
        SessionError::CloseRequiresDrain { .. } => "session_close_requires_drain",
        SessionError::ParentRequestNotInflight { .. } => "session_parent_request_not_inflight",
        SessionError::ParentRequestCancelled { .. } => "session_parent_request_cancelled",
        SessionError::ParentRequestAnchorMismatch { .. } => {
            "session_parent_request_anchor_mismatch"
        }
    }
}

fn core_error_class(error: &chio_core_types::Error) -> &'static str {
    use chio_core_types::Error;
    match error {
        Error::InvalidPublicKey(_) => "core_invalid_public_key",
        Error::InvalidHex(_) => "core_invalid_hex",
        Error::InvalidSignature(_) => "core_invalid_signature",
        Error::Json(_) => "core_json",
        Error::CanonicalJson(_) => "core_canonical_json",
        Error::CapabilityExpired { .. } => "core_capability_expired",
        Error::CapabilityNotYetValid { .. } => "core_capability_not_yet_valid",
        Error::CapabilityRevoked { .. } => "core_capability_revoked",
        Error::DelegationChainBroken { .. } => "core_delegation_chain_broken",
        Error::AttenuationViolation { .. } => "core_attenuation_violation",
        Error::ScopeMismatch { .. } => "core_scope_mismatch",
        Error::SignatureVerificationFailed => "core_signature_verification_failed",
        Error::DelegationDepthExceeded { .. } => "core_delegation_depth_exceeded",
        Error::InvalidHashLength { .. } => "core_invalid_hash_length",
        Error::MerkleProofFailed => "core_merkle_proof_failed",
        Error::EmptyTree => "core_empty_tree",
        Error::InvalidProofIndex { .. } => "core_invalid_proof_index",
    }
}

fn overload_error_class(resource: &chio_kernel::OverloadResource) -> &'static str {
    use chio_kernel::OverloadResource;
    match resource {
        OverloadResource::ReceiptMirror => "overloaded_receipt_mirror",
        OverloadResource::FederationCache => "overloaded_federation_cache",
        OverloadResource::VelocityBuckets => "overloaded_velocity_buckets",
        OverloadResource::AdmissionKeys => "overloaded_admission_keys",
        OverloadResource::ConcurrencyBuckets => "overloaded_concurrency_buckets",
        OverloadResource::SessionJournal => "overloaded_session_journal",
        OverloadResource::StreamBytes => "overloaded_stream_bytes",
        OverloadResource::StreamChunks => "overloaded_stream_chunks",
        OverloadResource::Allocation => "overloaded_allocation",
    }
}

fn settlement_config_error_class(
    error: &chio_kernel::SettlementRuntimeConfigError,
) -> &'static str {
    use chio_kernel::SettlementRuntimeConfigError;
    match error {
        SettlementRuntimeConfigError::InvalidRetryPolicy(_) => "settlement_invalid_retry_policy",
        SettlementRuntimeConfigError::MissingReceiptStore => "settlement_missing_receipt_store",
        SettlementRuntimeConfigError::UnsupportedAtomicProjection => {
            "settlement_unsupported_atomic_projection"
        }
        SettlementRuntimeConfigError::MissingStoreBinding => "settlement_missing_store_binding",
        SettlementRuntimeConfigError::StoreBindingMismatch => "settlement_store_binding_mismatch",
        SettlementRuntimeConfigError::ReceiptStoreReplacement => {
            "settlement_receipt_store_replacement"
        }
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

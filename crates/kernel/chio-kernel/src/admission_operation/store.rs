use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionBeginResult {
    Created(AdmissionOperationV1),
    ExactReplay {
        operation: AdmissionOperationV1,
        terminal_replay: Option<AdmissionTerminalReplay>,
    },
    Conflict {
        existing_operation_id: AdmissionOperationId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionOperationStoreError {
    #[error("admission operation store is unavailable: {0}")]
    Unavailable(String),
    #[error("admission operation mutation was fenced")]
    Fenced,
    #[error("admission operation was not found")]
    NotFound,
    #[error("admission operation invariant failed: {0}")]
    Invariant(String),
    #[error("admission operation durable outcome is unknown: {0}")]
    OutcomeUnknown(String),
    #[error(transparent)]
    Operation(#[from] AdmissionOperationError),
}

pub trait AdmissionOperationStore: Send + Sync {
    /// Retain one exact operation-bound nonce before delivery, atomically with
    /// its immutable issuance digest on the Prepared operation. The caller must
    /// first complete current authorization and qualified preflight cleanup.
    /// This neither reserves a nonce nor grants dispatch authority. A changed
    /// candidate cannot replace an existing issuance, including after expiry.
    fn issue_execution_nonce_and_commit_admission(
        &self,
        _command: &AdmissionOperationCommand,
        _issuance: &AdmissionExecutionNonceReservationV1,
        _trusted_now_unix_ms: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "atomic durable execution nonce issuance is unsupported".into(),
        ))
    }

    /// Fenced historical issuance lookup for lost acknowledgements and recovery.
    /// Expired material remains evidence, never renewed delivery or execution
    /// authority. Callers must revalidate before delivering a still-live nonce.
    fn load_execution_nonce_issuance(
        &self,
        _operation_id: &AdmissionOperationId,
        _fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<Option<AdmissionExecutionNonceReservationV1>, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "fenced durable execution nonce issuance lookup is unsupported".into(),
        ))
    }

    /// Revalidate the retained nonce and prepare capture under the current fence.
    /// This is not a nonce commit or a dispatch permit. The capture authority must
    /// commit the nonce, budget effect and DispatchCommitted state atomically.
    /// Fresh preparation requires the operation-bound signature profile; decoded
    /// legacy history is not fresh authority.
    fn begin_execution_nonce_capture(
        &self,
        _command: &AdmissionOperationCommand,
        _trusted_now_unix_ms: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "atomic durable execution nonce capture preparation is unsupported".into(),
        ))
    }

    /// Reserve a verified nonce and advance the same operation to ReadyToDispatch
    /// atomically. The store must pin the issuer to the qualified coordinator,
    /// recheck original request provenance and expiry, and retain replay history.
    /// Require `require_operation_bound_profile` before both fresh reservation
    /// and reservation retries. Historical lookup is a separate, read-only port.
    fn reserve_execution_nonce_and_commit_admission(
        &self,
        _command: &AdmissionOperationCommand,
        _reservation: &AdmissionExecutionNonceReservationV1,
        _trusted_now_unix_ms: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "atomic durable execution nonce reservation is unsupported".into(),
        ))
    }

    /// Fenced historical reservation lookup. Expiry does not erase this record;
    /// returned material is not fresh authorization or permission to dispatch.
    fn load_execution_nonce_reservation(
        &self,
        _operation_id: &AdmissionOperationId,
        _fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<Option<AdmissionExecutionNonceReservationV1>, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "fenced durable execution nonce lookup is unsupported".into(),
        ))
    }

    /// Resolve a request ID in one fenced, anchored snapshot. Count all retained
    /// operations before selecting: another tenant, terminal operation or legacy
    /// row without request material still makes the selector ambiguous.
    fn load_unambiguous_retained_tool_request(
        &self,
        _request_id: &AdmissionIdentifier,
        _fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<
        Option<(AdmissionOperationV1, RetainedToolAdmissionRequestV1)>,
        AdmissionOperationStoreError,
    > {
        Err(AdmissionOperationStoreError::Unavailable(
            "unambiguous original request resolution is unsupported".to_owned(),
        ))
    }

    /// Atomically retain original request material with a new operation's begin
    /// commit. Exact replay must verify the original bytes, never backfill a
    /// missing record. Called only after the kernel's pre-admission checks.
    fn begin_with_retained_tool_request(
        &self,
        _operation: &AdmissionOperationV1,
        _request: &RetainedToolAdmissionRequestV1,
        _fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<AdmissionBeginResult, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "atomic original tool request retention is unsupported".to_owned(),
        ))
    }

    /// Read original material and its operation in one fenced, anchored,
    /// trusted-time-checked snapshot. This establishes storage provenance only,
    /// not current capability validity or permission to collect or execute.
    fn load_retained_tool_request(
        &self,
        _operation_id: &AdmissionOperationId,
        _fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<
        Option<(AdmissionOperationV1, RetainedToolAdmissionRequestV1)>,
        AdmissionOperationStoreError,
    > {
        Err(AdmissionOperationStoreError::Unavailable(
            "fenced original tool request retention is unsupported".to_owned(),
        ))
    }

    fn begin(
        &self,
        operation: &AdmissionOperationV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionBeginResult, AdmissionOperationStoreError>;

    fn load_by_operation_id(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError>;

    fn load_by_replay_key(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError>;

    fn compare_and_swap(
        &self,
        command: &AdmissionOperationCommand,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError>;

    /// Persist a structurally checked claim. The returned value remains
    /// untrusted until `QualifiedAdmissionOperationStore::claim_recovery`
    /// rechecks it through this store.
    fn claim_recovery_untrusted(
        &self,
        operation_id: &AdmissionOperationId,
        expected_version: u64,
        claimant_id: &AdmissionIdentifier,
        trusted_now_unix_ms: u64,
        expires_at_unix_ms: u64,
        fence: &StoreMutationFence,
    ) -> Result<UntrustedAdmissionRecoveryClaim, AdmissionOperationStoreError>;

    /// Re-read the durable claim under the current store fence and verify its
    /// exact operation snapshot and historical coordinator lease.
    fn revalidate_recovery_claim(
        &self,
        operation: &AdmissionOperationV1,
        claim: &UntrustedAdmissionRecoveryClaim,
        trusted_now_unix_ms: u64,
        current_store_fence: &StoreMutationFence,
    ) -> Result<(), AdmissionOperationStoreError>;

    /// Lists non-terminal operations that require startup recovery work.
    ///
    /// Quiescent `ApprovalRequired` operations must be excluded before applying
    /// `limit`: they are waiting for external approval rather than recovery, and
    /// allowing them to occupy a page can starve later operations that do need
    /// reconciliation.
    fn list_recoverable(
        &self,
        not_after_unix_ms: u64,
        limit: usize,
    ) -> Result<Vec<AdmissionOperationV1>, AdmissionOperationStoreError>;

    fn load_terminal_replay(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionTerminalReplay>, AdmissionOperationStoreError>;
}

/// Explicit trust boundary for stores allowed to qualify durable recovery
/// claims.
///
/// # Implementation contract
///
/// Implementations must durably serialize claims with operation mutations,
/// enforce the current serving-owner fence and trusted time, and revalidate the
/// exact persisted claim and historical coordinator lease. An implementation
/// that returns success without those guarantees can authorize an unsafe
/// recovery transition.
pub trait QualifiedAdmissionOperationStore: AdmissionOperationStore {}

/// Non-overridable recovery qualification for explicitly trusted stores.
pub trait QualifiedAdmissionOperationStoreExt: QualifiedAdmissionOperationStore {
    fn claim_recovery(
        &self,
        operation_id: &AdmissionOperationId,
        expected_version: u64,
        claimant_id: &AdmissionIdentifier,
        trusted_now_unix_ms: u64,
        expires_at_unix_ms: u64,
        current_store_fence: &StoreMutationFence,
    ) -> Result<AdmissionRecoveryLease, AdmissionOperationStoreError> {
        let claim = self.claim_recovery_untrusted(
            operation_id,
            expected_version,
            claimant_id,
            trusted_now_unix_ms,
            expires_at_unix_ms,
            current_store_fence,
        )?;
        let operation = self
            .load_by_operation_id(operation_id)?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        claim.validate_for_qualification(
            &operation,
            expected_version,
            claimant_id,
            trusted_now_unix_ms,
            expires_at_unix_ms,
            current_store_fence,
        )?;
        self.revalidate_recovery_claim(
            &operation,
            &claim,
            trusted_now_unix_ms,
            current_store_fence,
        )?;
        Ok(AdmissionRecoveryLease::from_qualified(claim))
    }
}

impl<T: QualifiedAdmissionOperationStore + ?Sized> QualifiedAdmissionOperationStoreExt for T {}

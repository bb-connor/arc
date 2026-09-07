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

/// The recovery claim a coordinator asks a store to persist before it mutates
/// an operation.
#[derive(Debug, Clone, Copy)]
pub struct RecoveryClaimRequest<'a> {
    pub operation_id: &'a AdmissionOperationId,
    pub expected_version: u64,
    pub claimant_id: &'a AdmissionIdentifier,
    pub expires_at_unix_ms: u64,
    pub fence: &'a StoreMutationFence,
}

/// Turns a persisted, structurally checked claim into the command it
/// authorizes, or refuses. Runs before the mutation becomes durable.
pub type ClaimedCommand<'a> = dyn FnMut(
        &AdmissionOperationV1,
        UntrustedAdmissionRecoveryClaim,
    ) -> Result<AdmissionOperationCommand, AdmissionOperationStoreError>
    + 'a;

/// Turns a persisted, structurally checked claim into the lease a joint
/// transaction applies under, or refuses. Built only by [`qualified_lease`],
/// so a lease still exists only after qualification.
pub type ClaimedLease<'a> = dyn FnMut(
        &AdmissionOperationV1,
        UntrustedAdmissionRecoveryClaim,
    ) -> Result<AdmissionRecoveryLease, AdmissionOperationStoreError>
    + 'a;

/// The qualification a claim must pass before it becomes a lease: the
/// persisted claim names this operation at the expected version, this
/// claimant, this fence and an expiry no later than requested.
pub fn qualified_lease<'a>(
    request: RecoveryClaimRequest<'a>,
    trusted_now_unix_ms: u64,
) -> impl FnMut(
    &AdmissionOperationV1,
    UntrustedAdmissionRecoveryClaim,
) -> Result<AdmissionRecoveryLease, AdmissionOperationStoreError>
       + 'a {
    move |stored: &AdmissionOperationV1, claim: UntrustedAdmissionRecoveryClaim| {
        claim.validate_for_qualification(
            stored,
            request.expected_version,
            request.claimant_id,
            trusted_now_unix_ms,
            request.expires_at_unix_ms,
            request.fence,
        )?;
        Ok(AdmissionRecoveryLease::from_qualified(claim))
    }
}

/// The two-write path to a lease for stores that do not fuse the claim with
/// the mutation it protects: persist the claim, revalidate it against the
/// operation as stored, then qualify it.
pub fn claim_qualified_lease(
    store: &(impl AdmissionOperationStore + ?Sized),
    request: RecoveryClaimRequest<'_>,
    trusted_now_unix_ms: u64,
    lease: &mut ClaimedLease<'_>,
) -> Result<AdmissionRecoveryLease, AdmissionOperationStoreError> {
    let claim = store.claim_recovery_untrusted(
        request.operation_id,
        request.expected_version,
        request.claimant_id,
        trusted_now_unix_ms,
        request.expires_at_unix_ms,
        request.fence,
    )?;
    let operation = store
        .load_by_operation_id(request.operation_id)?
        .ok_or(AdmissionOperationStoreError::NotFound)?;
    store.revalidate_recovery_claim(&operation, &claim, trusted_now_unix_ms, request.fence)?;
    lease(&operation, claim)
}

pub trait AdmissionOperationStore: Send + Sync {
    /// Atomically reserve an internal nonce-preflight budget hold and attach its
    /// permanent ownership evidence to the same Prepared admission operation.
    /// This requires current caller authorization, never captures quota, and
    /// does not establish cleanup of non-budget admission participants.
    fn authorize_execution_nonce_preflight(
        &self,
        _operation: &AdmissionOperationV1,
        _recovery_lease: &AdmissionRecoveryLease,
        _request: crate::budget_store::BudgetAuthorizeHoldRequest,
        _trusted_now_unix_ms: u64,
    ) -> Result<
        (
            crate::budget_store::BudgetAuthorizeHoldDecision,
            AdmissionOperationV1,
        ),
        AdmissionCaptureError,
    > {
        Err(AdmissionCaptureError::Unavailable(
            "operation-owned nonce preflight budget authorization is unsupported".into(),
        ))
    }

    /// Fenced lookup of the exact internal participant for retry and restart
    /// cleanup. The result names the hold, its authorization commit and its
    /// physical disposition; it is not fresh authorization or proof that
    /// non-budget cleanup completed.
    fn load_execution_nonce_preflight(
        &self,
        _operation_id: &AdmissionOperationId,
        _fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<Option<AdmissionNoncePreflightRecoveryV1>, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "operation-owned nonce preflight lookup is unsupported".into(),
        ))
    }

    /// Retain one exact operation-bound nonce before delivery, atomically with
    /// its immutable issuance digest on the Prepared operation. The caller must
    /// first complete current authorization and qualified preflight cleanup.
    /// Fresh issuance requires durable ownership and physical budget reversal;
    /// absence in old history must never be treated as completed preflight.
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
    /// A quiescent `ApprovalRequired` operation waits for external approval
    /// rather than recovery. While its proposal deadline has not elapsed at
    /// `not_after_unix_ms` it must be excluded before applying `limit`, so it
    /// cannot occupy a page and starve later operations that do need
    /// reconciliation. Once the deadline has elapsed no token set can still
    /// deliver, and the operation is recoverable like any other pre-dispatch
    /// operation.
    fn list_recoverable(
        &self,
        not_after_unix_ms: u64,
        limit: usize,
    ) -> Result<Vec<AdmissionOperationV1>, AdmissionOperationStoreError>;

    fn load_terminal_replay(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionTerminalReplay>, AdmissionOperationStoreError>;

    /// Persist a recovery claim and apply the command it authorizes.
    ///
    /// `command` receives the operation as stored and the claim as persisted,
    /// after the store's own claim checks, and returns the command to apply.
    /// A store that serializes both in one durable write leaves nothing
    /// durable when `command` refuses or the mutation is fenced; this default
    /// persists the claim first, revalidates it, and applies the command as a
    /// second durable write.
    fn claim_and_compare_and_swap(
        &self,
        request: RecoveryClaimRequest<'_>,
        trusted_now_unix_ms: u64,
        command: &mut ClaimedCommand<'_>,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        let claim = self.claim_recovery_untrusted(
            request.operation_id,
            request.expected_version,
            request.claimant_id,
            trusted_now_unix_ms,
            request.expires_at_unix_ms,
            request.fence,
        )?;
        let operation = self
            .load_by_operation_id(request.operation_id)?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        self.revalidate_recovery_claim(&operation, &claim, trusted_now_unix_ms, request.fence)?;
        let command = command(&operation, claim)?;
        self.compare_and_swap(&command, trusted_now_unix_ms)
    }
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

/// Attachments and state a claimed command carries.
#[derive(Debug, Clone)]
pub struct ClaimedTransition {
    pub attachments: Vec<AdmissionAttachment>,
    pub next_state: AdmissionOperationState,
}

/// Claim recovery of an operation and apply a transition under that claim,
/// qualifying the persisted claim before the lease that authorizes the
/// command exists. A store that fuses both writes makes them one durable
/// write; the claim never outlives a refused or fenced command there.
pub trait QualifiedAdmissionTransitionExt: QualifiedAdmissionOperationStore {
    fn claim_and_apply(
        &self,
        request: RecoveryClaimRequest<'_>,
        trusted_now_unix_ms: u64,
        transition: ClaimedTransition,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        let mut transition = Some(transition);
        let mut lease = qualified_lease(request, trusted_now_unix_ms);
        let mut command = |stored: &AdmissionOperationV1,
                           claim: UntrustedAdmissionRecoveryClaim| {
            let lease = lease(stored, claim)?;
            let transition = transition.take().ok_or_else(|| {
                AdmissionOperationStoreError::Invariant(
                    "claimed transition was requested twice".to_string(),
                )
            })?;
            Ok(AdmissionOperationCommand::new(
                request.operation_id.clone(),
                request.expected_version,
                lease,
                transition.attachments,
                Some(transition.next_state),
                None,
                None,
            )?)
        };
        self.claim_and_compare_and_swap(request, trusted_now_unix_ms, &mut command)
    }
}

impl<T: QualifiedAdmissionOperationStore + ?Sized> QualifiedAdmissionTransitionExt for T {}

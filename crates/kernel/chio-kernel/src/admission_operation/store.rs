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

pub trait AdmissionOperationStore: Send + Sync {
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
        let mut command = |stored: &AdmissionOperationV1,
                           claim: UntrustedAdmissionRecoveryClaim| {
            claim.validate_for_qualification(
                stored,
                request.expected_version,
                request.claimant_id,
                trusted_now_unix_ms,
                request.expires_at_unix_ms,
                request.fence,
            )?;
            let transition = transition.take().ok_or_else(|| {
                AdmissionOperationStoreError::Invariant(
                    "claimed transition was requested twice".to_string(),
                )
            })?;
            Ok(AdmissionOperationCommand::new(
                request.operation_id.clone(),
                request.expected_version,
                AdmissionRecoveryLease::from_qualified(claim),
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

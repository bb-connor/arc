use super::dpop_claim::{
    DpopReplayClaimHistoryV1, DpopReplayClaimIntentV1, DpopReplayClaimReferenceV1,
};
use super::governed_approval_claim::{
    GovernedApprovalAuthorityBindingV1, GovernedApprovalClaimHistoryV1,
    GovernedApprovalClaimIntentV1, GovernedApprovalClaimReferenceV1,
};
use super::runtime_participant::{
    RuntimeParticipantAuthorityBindingV1, RuntimeParticipantClaimHistoryV1,
    RuntimeParticipantClaimIntentV1, RuntimeParticipantClaimReferenceV1,
};
use super::*;
use crate::dpop::authority::DpopReplayAuthorityV1;

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
    /// Retain exact native policy and actual physical participant references.
    /// This is not atomic budget capture, dispatch authority or activation.
    fn retain_native_dispatch_ledger(
        &self,
        _context: NativeSecurityDispatchLedgerContext<'_>,
    ) -> Result<NativeSecurityDispatchLedgerRecordV1, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "native dispatch ledger retention is unsupported".into(),
        ))
    }

    /// Fenced immutable history. Reading a record never renews its policy or
    /// participants and must not replay a preparation or authorize execution.
    fn load_native_dispatch_ledger(
        &self,
        _operation_id: &AdmissionOperationId,
        _fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<Option<NativeSecurityDispatchLedgerRecordV1>, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "native dispatch ledger history is unsupported".into(),
        ))
    }

    /// Fresh read-only native data under the current serving fence, scoped to
    /// independently verified initialization selected by the trusted host.
    /// This may precede original admission and its first join. It grants no
    /// activation or operation custody, and never returns historical join data
    /// as a current observation. Missing initialization is an error; a missing
    /// flow context is represented within the returned observation.
    fn observe_native_security_flow(
        &self,
        _binding: &NativeSecurityAuthorityBindingV1,
        _key: &chio_security_types::ports::FlowStateKey,
        _fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<NativeSecurityFlowObservationV1, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "native flow observations are unsupported".into(),
        ))
    }

    /// Monotone native preparation under the actual operation and recovery
    /// lease. No activation, egress acquisition or declassification is implied.
    /// The first write must check the original v4 authority selection and live
    /// flow observation. Exact retries return historical data only.
    fn join_native_security_flow(
        &self,
        _operation: &AdmissionOperationV1,
        _lease: &AdmissionRecoveryLease,
        _binding: &NativeSecurityAuthorityBindingV1,
        _context: &crate::SecurityInvocationContext,
        _command: &chio_security_types::ports::FlowJoinRequest,
        _trusted_now_unix_ms: u64,
    ) -> Result<chio_security_types::ports::FlowStateSnapshot, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "operation-owned native flow joins are unsupported".into(),
        ))
    }

    /// Join classified input with every inherited native label atomically, and
    /// propagate the complete source into principal, lineage and session. This
    /// is a distinct intent from three independent label updates. It must not
    /// fall back to the raw join port or reinterpret a historical raw join.
    fn join_native_security_input(
        &self,
        _operation: &AdmissionOperationV1,
        _lease: &AdmissionRecoveryLease,
        _binding: &NativeSecurityAuthorityBindingV1,
        _context: &crate::SecurityInvocationContext,
        _command: &NativeSecurityInputJoinRequestV1,
        _trusted_now_unix_ms: u64,
    ) -> Result<NativeSecurityInputJoinRecordV1, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "operation-owned native input joins are unsupported".into(),
        ))
    }

    /// Join strict nonce preflight input under its Prepared operation and lease.
    /// The dedicated history cannot substitute for dispatch preparation or a
    /// fresh flow observation. It must not fall back to the dispatch join port.
    fn join_native_security_nonce_preflight(
        &self,
        _operation: &AdmissionOperationV1,
        _lease: &AdmissionRecoveryLease,
        _binding: &NativeSecurityAuthorityBindingV1,
        _context: &crate::SecurityInvocationContext,
        _command: &NativeSecurityNoncePreflightJoinRequestV1,
        _trusted_now_unix_ms: u64,
    ) -> Result<NativeSecurityNoncePreflightJoinRecordV1, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "operation-owned native nonce preflight is unsupported".into(),
        ))
    }

    /// Independently read exact nonce preflight history under the serving fence.
    /// Successful readback never authorizes another join or a tool effect.
    fn load_native_security_nonce_preflight_join(
        &self,
        _operation_id: &AdmissionOperationId,
        _fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<
        Option<(
            AdmissionOperationV1,
            Option<NativeSecurityNoncePreflightJoinRecordV1>,
        )>,
        AdmissionOperationStoreError,
    > {
        Err(AdmissionOperationStoreError::Unavailable(
            "native nonce preflight history is unsupported".into(),
        ))
    }

    /// Join classified post-guard output under the original finalization lease.
    /// Implementations must bind the intent to the physical resolved outcome,
    /// evaluation and native capture. This neither publishes output nor releases
    /// egress custody. Historical retries cannot recreate a live release owner.
    fn join_native_security_output(
        &self,
        _operation: &AdmissionOperationV1,
        _lease: &AdmissionRecoveryLease,
        _binding: &NativeSecurityAuthorityBindingV1,
        _command: &NativeSecurityOutputJoinRequestV1,
        _trusted_now_unix_ms: u64,
    ) -> Result<NativeSecurityOutputJoinRecordV1, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "operation-owned native output joins are unsupported".into(),
        ))
    }

    /// Current operation and optional output journal in one fenced, anchored
    /// snapshot. A missing operation differs from an operation without output
    /// history. This does not observe current labels or grant mutation authority.
    fn load_native_security_output_join(
        &self,
        _operation_id: &AdmissionOperationId,
        _fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<
        Option<(
            AdmissionOperationV1,
            Option<NativeSecurityOutputJoinRecordV1>,
        )>,
        AdmissionOperationStoreError,
    > {
        Err(AdmissionOperationStoreError::Unavailable(
            "native output join history is unsupported".into(),
        ))
    }

    /// Read the exact input intent and resolved join together. Existing raw
    /// join history is not an input-join acknowledgement and must reject.
    fn load_native_security_input_join(
        &self,
        _operation_id: &AdmissionOperationId,
        _fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<
        Option<(
            AdmissionOperationV1,
            Option<NativeSecurityInputJoinRecordV1>,
        )>,
        AdmissionOperationStoreError,
    > {
        Err(AdmissionOperationStoreError::Unavailable(
            "native input join history is unsupported".into(),
        ))
    }

    /// Current operation and its optional monotone-join history in one fenced,
    /// anchored snapshot. Missing history is not evidence that a failed write
    /// was safe to replay. This method cannot acquire mutation authority.
    fn load_native_security_flow_join(
        &self,
        _operation_id: &AdmissionOperationId,
        _fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<
        Option<(AdmissionOperationV1, Option<NativeSecurityFlowJoinRecordV1>)>,
        AdmissionOperationStoreError,
    > {
        Err(AdmissionOperationStoreError::Unavailable(
            "operation-owned native flow history is unsupported".into(),
        ))
    }

    /// Acquire egress custody under the original tool operation in
    /// `CapturePending`. Implementations must reject imported/unowned fences,
    /// stale observations and substituted live requests. Exact retries return
    /// historical data, not renewed fences or native lifecycle activation.
    fn acquire_native_security_egress(
        &self,
        _context: &NativeSecurityEgressContext<'_>,
        _command: &chio_security_types::ports::EgressFenceRequest,
    ) -> Result<chio_security_types::ports::EgressFence, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "operation-owned native egress acquisition is unsupported".into(),
        ))
    }

    /// Commit only this operation's original acquisition with the same live
    /// request and current generation/lease. This records custody, not a tool
    /// dispatch or independently verified credential disposition.
    fn commit_native_security_egress(
        &self,
        _context: &NativeSecurityEgressContext<'_>,
        _command: &chio_security_types::ports::EgressFenceCommit,
    ) -> Result<chio_security_types::ports::CommittedEgressFence, AdmissionOperationStoreError>
    {
        Err(AdmissionOperationStoreError::Unavailable(
            "operation-owned native egress commitment is unsupported".into(),
        ))
    }

    /// Current operation and both historical egress phases in one verified
    /// snapshot. An absent operation differs from a present operation without
    /// custody. Reading expired history cannot reacquire or renew authority.
    fn load_native_security_egress(
        &self,
        _operation_id: &AdmissionOperationId,
        _fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<
        Option<(AdmissionOperationV1, Option<NativeSecurityEgressHistoryV1>)>,
        AdmissionOperationStoreError,
    > {
        Err(AdmissionOperationStoreError::Unavailable(
            "operation-owned native egress history is unsupported".into(),
        ))
    }

    /// Require an exact activated DPoP source and a non-regressed authority
    /// clock. Configuration and imported-inactive history cannot grant claims.
    fn load_dpop_replay_activation(
        &self,
        _binding: &DpopReplayAuthorityV1,
        _fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<DpopReplayAuthorityV1, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "operation-owned DPoP activation is unsupported".into(),
        ))
    }
    /// Atomically claim the verifier-prepared DPoP replay identity under
    /// the current exact operation lease. This does not verify signer trust or
    /// authorize execution. The first claim advances the operation version.
    fn claim_dpop_replay(
        &self,
        _operation: &AdmissionOperationV1,
        _lease: &AdmissionRecoveryLease,
        _intent: &DpopReplayClaimIntentV1,
        _trusted_now_unix_ms: u64,
    ) -> Result<(AdmissionOperationV1, DpopReplayClaimReferenceV1), AdmissionOperationStoreError>
    {
        Err(AdmissionOperationStoreError::Unavailable(
            "operation-owned DPoP claims are unsupported".into(),
        ))
    }
    /// Release only this exact historical claim before dispatch commitment.
    /// Expiry or a different episode reference must never erase a successor.
    fn release_dpop_replay(
        &self,
        _operation: &AdmissionOperationV1,
        _lease: &AdmissionRecoveryLease,
        _reference: &DpopReplayClaimReferenceV1,
        _trusted_now_unix_ms: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "operation-owned DPoP release is unsupported".into(),
        ))
    }
    /// Fenced history, not fresh DPoP authority. Expired credentials must
    /// remain recoverable without presenting or consuming their tokens again.
    fn load_dpop_replay_claim_history(
        &self,
        _operation_id: &AdmissionOperationId,
        _fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<
        Option<(AdmissionOperationV1, Vec<DpopReplayClaimHistoryV1>)>,
        AdmissionOperationStoreError,
    > {
        Err(AdmissionOperationStoreError::Unavailable(
            "operation-owned DPoP recovery is unsupported".into(),
        ))
    }
    /// Require an exact activated approval source and a non-regressed authority
    /// clock. Configuration and imported-inactive history cannot grant claims.
    fn load_governed_approval_activation(
        &self,
        _binding: &GovernedApprovalAuthorityBindingV1,
        _fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<
        super::governed_approval_replay::GovernedApprovalReplaySourceSnapshot,
        AdmissionOperationStoreError,
    > {
        Err(AdmissionOperationStoreError::Unavailable(
            "operation-owned approval activation is unsupported".into(),
        ))
    }
    /// Atomically claim the verifier-prepared approval replay identity under
    /// the current exact operation lease. This does not verify signer trust or
    /// authorize execution. The first claim advances the operation version.
    fn claim_governed_approval(
        &self,
        _operation: &AdmissionOperationV1,
        _lease: &AdmissionRecoveryLease,
        _intent: &GovernedApprovalClaimIntentV1,
        _trusted_now_unix_ms: u64,
    ) -> Result<
        (AdmissionOperationV1, GovernedApprovalClaimReferenceV1),
        AdmissionOperationStoreError,
    > {
        Err(AdmissionOperationStoreError::Unavailable(
            "operation-owned approval claims are unsupported".into(),
        ))
    }
    /// Release only this exact historical claim before dispatch commitment.
    /// Expiry or a different episode reference must never erase a successor.
    fn release_governed_approval(
        &self,
        _operation: &AdmissionOperationV1,
        _lease: &AdmissionRecoveryLease,
        _reference: &GovernedApprovalClaimReferenceV1,
        _trusted_now_unix_ms: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "operation-owned approval release is unsupported".into(),
        ))
    }
    /// Fenced history, not fresh approval authority. Expired credentials must
    /// remain recoverable without presenting or consuming their tokens again.
    fn load_governed_approval_claim_history(
        &self,
        _operation_id: &AdmissionOperationId,
        _fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<
        Option<(AdmissionOperationV1, Vec<GovernedApprovalClaimHistoryV1>)>,
        AdmissionOperationStoreError,
    > {
        Err(AdmissionOperationStoreError::Unavailable(
            "operation-owned approval recovery is unsupported".into(),
        ))
    }
    /// Require durable activation of this exact runtime source generation in a
    /// fenced, anchored read. An imported-inactive source must reject. Serving
    /// configuration alone is not evidence that legacy replay authority retired.
    fn load_runtime_participant_activation(
        &self,
        _binding: &RuntimeParticipantAuthorityBindingV1,
        _fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<super::RuntimeReplaySourceSnapshotV1, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "operation-owned runtime replay activation is unsupported".into(),
        ))
    }

    /// Reserve one complete, verifier-prepared replay resource set atomically.
    /// The first claim may advance the operation version. Every subsequent
    /// mutation, including release, requires a renewed exact-version lease.
    /// This port does not activate a runtime profile or verify its artifacts.
    fn claim_runtime_participants(
        &self,
        _operation: &AdmissionOperationV1,
        _lease: &AdmissionRecoveryLease,
        _intent: &RuntimeParticipantClaimIntentV1,
        _trusted_now_unix_ms: u64,
    ) -> Result<
        (AdmissionOperationV1, RuntimeParticipantClaimReferenceV1),
        AdmissionOperationStoreError,
    > {
        Err(AdmissionOperationStoreError::Unavailable(
            "operation-owned runtime replay claims are unsupported".into(),
        ))
    }

    /// Release an exact historical episode before dispatch commitment. This
    /// appends release evidence without changing the operation version. An
    /// older released reference must never release a successor episode.
    fn release_runtime_participants(
        &self,
        _operation: &AdmissionOperationV1,
        _lease: &AdmissionRecoveryLease,
        _reference: &RuntimeParticipantClaimReferenceV1,
        _trusted_now_unix_ms: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "operation-owned runtime replay release is unsupported".into(),
        ))
    }

    /// Load complete physical claim and release history with its exact current
    /// operation in one fenced, anchored snapshot. Missing ownership, truncated
    /// history or invalid commit coverage must reject. This is recovery data,
    /// not fresh execution authority, and does not revalidate expired artifacts.
    fn load_runtime_participant_history(
        &self,
        _operation_id: &AdmissionOperationId,
        _fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<
        Option<(AdmissionOperationV1, Vec<RuntimeParticipantClaimHistoryV1>)>,
        AdmissionOperationStoreError,
    > {
        Err(AdmissionOperationStoreError::Unavailable(
            "operation-owned runtime replay recovery is unsupported".into(),
        ))
    }

    /// Load private context in the same fenced, anchored snapshot as its
    /// operation and original request. No absent row may be silently backfilled.
    fn load_caller_dispatch_context(
        &self,
        _operation_id: &AdmissionOperationId,
        _fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<Option<AdmissionCallerDispatchContextV1>, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "caller dispatch context recovery is unsupported".into(),
        ))
    }

    /// Read one complete snapshot of funded caller shares under a parent.
    /// The store verifies the owner fence, trusted clock, operation integrity
    /// and retained-request binding in one read transaction. Expiry alone must
    /// not remove a share whose operation has not been compensated. Exceeding
    /// `limit` rejects; returning a truncated snapshot would permit oversubscription.
    fn load_caller_budget_shares(
        &self,
        _parent_id: &AdmissionIdentifier,
        _limit: usize,
        _fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<Vec<AdmissionCallerBudgetShare>, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "durable caller sibling-share accounting is unsupported".into(),
        ))
    }

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
///
/// Unwinding callback panics return `OutcomeUnknown` before they can unwind
/// through the caller's mutation sequencer. A claim may already be durable:
/// qualification neither erases it nor constructs authority from an uncertain
/// result. Backend state is not repaired, and process-aborting failures cannot
/// be contained here.
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
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
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
        }))
        .unwrap_or_else(|_| {
            Err(AdmissionOperationStoreError::OutcomeUnknown(
                "recovery lease qualification callback panicked".into(),
            ))
        })
    }
}

impl<T: QualifiedAdmissionOperationStore + ?Sized> QualifiedAdmissionOperationStoreExt for T {}

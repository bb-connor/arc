use super::*;
use crate::admission_operation::{AdmissionOperationStoreError, StoreMutationFence};
use chio_core_types::capability::token::CapabilityToken;
use chio_security_types::flow::PrincipalId;
use chio_security_types::recovery::*;

/// Only the kernel's full capability verifier and current operator assignment
/// lookup may construct this actor. It grants scoped control, never tool
/// dispatch. No constructor exists until that verifier is integrated, so no
/// `RecoveryAuthorityPort` caller exists yet.
///
/// ```
/// use chio_kernel::recovery::{AuthenticatedRecoveryActor, RecoveryPermission};
/// fn permission(actor: &AuthenticatedRecoveryActor) -> RecoveryPermission {
///     actor.permission()
/// }
/// let _ = serde_json::to_string(&RecoveryPermission::Create);
/// ```
///
/// Decoding cannot construct an actor. Expected diagnostic: E0277, the trait
/// bound `AuthenticatedRecoveryActor: Deserialize<'_>` is not satisfied.
/// ```compile_fail,E0277
/// use chio_kernel::recovery::AuthenticatedRecoveryActor;
/// fn decode(wire: &str) -> serde_json::Result<AuthenticatedRecoveryActor> {
///     serde_json::from_str(wire)
/// }
/// ```
pub struct AuthenticatedRecoveryActor {
    pub(crate) scope: RecoveryScopeV1,
    pub(crate) principal: PrincipalId,
    pub(crate) capability: CapabilityToken,
    pub(crate) permission: RecoveryPermission,
}
impl AuthenticatedRecoveryActor {
    pub fn scope(&self) -> &RecoveryScopeV1 {
        &self.scope
    }
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }
    pub fn capability(&self) -> &CapabilityToken {
        &self.capability
    }
    pub const fn permission(&self) -> RecoveryPermission {
        self.permission
    }
}
impl core::fmt::Debug for AuthenticatedRecoveryActor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AuthenticatedRecoveryActor([redacted])")
    }
}

/// A synchronous port ensures SQLite transactions cannot escape across await.
/// Trusted host-owned process journal adapter. Implementations must read the
/// committed reservation and compare the complete current route/profile binding.
pub trait RecoveryProcessReservationPort {
    fn verify_reservation(
        &self,
        reservation: &RecoveryProcessReservationV1,
    ) -> Result<(), AdmissionOperationStoreError>;
}

/// Trusted host-owned original process-journal provenance. Implementations must
/// compare the unchanged first-attempt request and current host binding in one
/// read snapshot, without reentering native admission or charging process quota.
pub trait RecoveryProcessOriginPort: Send + Sync {
    fn verify_original_request(
        &self,
        scope: &RecoveryScopeV1,
        request: &crate::ToolCallRequest,
        expected_session: &str,
    ) -> Result<(), AdmissionOperationStoreError>;

    /// Verify the committed first attempt and bind its exact request to this
    /// host's Kernel namespace selected by the trusted process owner.
    fn original_request_scope(
        &self,
        scope: &RecoveryScopeV1,
        request: &crate::ToolCallRequest,
        expected_session: &str,
    ) -> Result<RecoveryOriginalRequestScope, RecoveryOriginalRequestError>;
}

/// A live affine closure role produced by the actual Process runtime. The
/// owning store writer authenticates the exact immutable closure through
/// this role before sealing any cancelled admission or allocation
/// retirement. Implementations retain their live runtime borrow; this is
/// never a decoded closure receipt and grants no admission or refund.
///
/// ```
/// use chio_kernel::admission_operation::AdmissionOperationStoreError;
/// use chio_kernel::recovery::{
///     RecoveryProcessReservationV1, RecoveryUnusedReservationClosureRole,
/// };
/// fn verify(
///     role: &dyn RecoveryUnusedReservationClosureRole,
///     expected: &RecoveryProcessReservationV1,
/// ) -> Result<(), AdmissionOperationStoreError> {
///     role.verify_for(expected, "authority")
/// }
/// ```
///
/// A role cannot be duplicated. Expected diagnostic: E0277, the trait bound
/// `Box<dyn RecoveryUnusedReservationClosureRole + 'a>: Clone` is not satisfied.
/// ```compile_fail,E0277
/// use chio_kernel::recovery::RecoveryUnusedReservationClosureRole;
/// fn duplicate<'a>(
///     role: &Box<dyn RecoveryUnusedReservationClosureRole + 'a>,
/// ) -> Box<dyn RecoveryUnusedReservationClosureRole + 'a> {
///     Clone::clone(role)
/// }
/// ```
pub trait RecoveryUnusedReservationClosureRole {
    /// Reverify the immutable closure row and its exact reservation binding
    /// through the same live runtime that produced this role.
    fn verify_for(
        &self,
        expected: &RecoveryProcessReservationV1,
        authority_domain: &str,
    ) -> Result<(), AdmissionOperationStoreError>;
}

/// Trusted host-owned genuine unused reservation closure. Only the actual
/// Process runtime implements this port. The owning writer authenticates
/// its actor, operator, profile and stale replacement eligibility before
/// the physical closure is requested, then authenticates the returned live
/// role before any cancelled admission or retirement is sealed. The store
/// cannot depend on the Process crate directly, so this narrow typed port
/// crosses that boundary without exposing a wire closure DTO.
pub trait RecoveryUnusedReservationClosurePort: Send + Sync {
    /// Close the genuinely unused reservation (reserved, never finalized or
    /// dispatched) and return its live role for independent authentication.
    /// Repeated calls replay the same immutable closure row.
    fn close_unused_recovery_reservation(
        &self,
        reservation: &RecoveryProcessReservationV1,
    ) -> Result<Box<dyn RecoveryUnusedReservationClosureRole + '_>, AdmissionOperationStoreError>;
}

pub trait RecoveryAuthorityPort: Send + Sync {
    /// Read native setup requirements under the current serving fence. This
    /// grants neither readiness nor execution.
    fn protected_setup_required(
        &self,
        scope: &RecoveryScopeV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<bool, AdmissionOperationStoreError>;

    /// Check the immutable transport budget against fresh writer time before
    /// spending an original observation attempt.
    fn reserve_provider_lookup(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        fence: &StoreMutationFence,
        now: u64,
        budget: RecoveryProviderLookupBudget,
    ) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError>;
    fn attach_provider_finality(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        finality: &chio_core_types::recovery::SignedRecoveryProviderFinalityV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError>;

    fn release_result(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        basis: &RecoveryResultReleaseBasis,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError>;

    fn acknowledge_reservation(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        reservation: &RecoveryProcessReservationV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError>;

    fn reserve_review(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        review: &ApprovalIntentV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ApprovalIntentV1, AdmissionOperationStoreError>;
    fn deployment(
        &self,
        scope: &RecoveryScopeV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RecoveryDeploymentV1, AdmissionOperationStoreError>;
    /// Accept one command and retain its exact workflow generation.
    fn command_with_selection(
        &self,
        actor: &AuthenticatedRecoveryActor,
        command: &RecoveryCommandV1,
        original_process: Option<&dyn RecoveryProcessOriginPort>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RecoveryCommandPortOutcome, RecoveryCommandPortError>;

    fn load_selection(
        &self,
        actor: &AuthenticatedRecoveryActor,
        selection: &RecoveryCommandPortSelection,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RecoveryCommandSelectedWorkflowData, AdmissionOperationStoreError>;

    fn load_workflow(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError>;
    fn materialize(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        action: &ActionIntentV1,
        observation: &crate::admission_operation::NativeSecurityFlowObservationV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError>;
    fn reserve_issuance(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        body: &chio_core_types::recovery::RecoveryGrantBody,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<chio_core_types::recovery::RecoveryGrantBody, AdmissionOperationStoreError>;
    fn attach_signature(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        grant: &chio_core_types::recovery::SignedRecoveryGrant,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError>;
    fn finalize_envelope(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        envelope: &FinalizedRequestEnvelopeV1,
        identity: &RecoveryNativeIdentity,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError>;
    fn verification_context(
        &self,
        operation: &crate::admission_operation::AdmissionOperationId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<RecoveryVerificationContextV1>, AdmissionOperationStoreError>;
    /// Protected original custody for release-only settlement. Implementations
    /// verify physical capture, the exact native binding and retained original
    /// deployment. Expired initiating authority grants no new execution rights.
    fn historical_release(
        &self,
        operation: &crate::admission_operation::AdmissionOperationId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<RecoveryWorkflowRecordV1>, AdmissionOperationStoreError>;
    /// Authenticate captured custody. Missing mandatory custody is corruption;
    /// unavailable frozen verifier or signing custody requires quarantine.
    fn captured_deployment(
        &self,
        operation: &crate::admission_operation::AdmissionOperationId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<RecoveryCapturedDeploymentV1>, AdmissionOperationStoreError>;
    fn quarantine_historical(
        &self,
        operation: &crate::admission_operation::AdmissionOperationId,
        reason: RecoveryHistoricalHoldReasonV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError>;
    fn settle(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError>;
}

use super::*;
use crate::admission_operation::{AdmissionOperationStoreError, StoreMutationFence};
use crate::runtime::RecoveryRequestCustody;
use chio_core_types::capability::token::CapabilityToken;
use chio_security_types::flow::PrincipalId;
use chio_security_types::recovery::*;

/// Constructed only by the kernel's full capability verifier and current
/// operator assignment lookup. It grants scoped control, never tool dispatch.
///
/// ```compile_fail
/// use chio_kernel::recovery::AuthenticatedRecoveryActor;
/// let _: Result<AuthenticatedRecoveryActor, _> = serde_json::from_str("{}");
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
/// Qualified native admission implementations opt in explicitly. Default
/// kernels and unrelated stores cannot silently simulate these transitions.
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
    /// host's Kernel namespace. A legacy adapter cannot silently choose a RID.
    fn original_request_scope(
        &self,
        _scope: &RecoveryScopeV1,
        _request: &crate::ToolCallRequest,
        _expected_session: &str,
    ) -> Result<RecoveryOriginalRequestScope, RecoveryOriginalRequestError> {
        Err(RecoveryOriginalRequestError::Refused)
    }
}

pub trait RecoveryAuthorityPort: Send + Sync {
    /// Read native setup requirements under the current serving fence. This
    /// grants neither readiness nor execution; unsupported stores fail closed.
    fn protected_setup_required(
        &self,
        _scope: &RecoveryScopeV1,
        _fence: &StoreMutationFence,
        _now: u64,
    ) -> Result<bool, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "native protected setup requirement is unsupported".into(),
        ))
    }

    fn reserve_provider_lookup(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError>;
    /// Qualified implementations check the immutable transport budget against
    /// fresh writer time before spending an original observation attempt.
    /// An older port cannot replace this atomic check with its legacy path.
    fn reserve_provider_lookup_with_budget(
        &self,
        _actor: &AuthenticatedRecoveryActor,
        _workflow: &WorkflowId,
        _fence: &StoreMutationFence,
        _now: u64,
        _budget: RecoveryProviderLookupBudget,
    ) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "native provider request budget is unsupported".into(),
        ))
    }
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
    fn command(
        &self,
        actor: &AuthenticatedRecoveryActor,
        command: &RecoveryCommandV1,
        original_process: Option<&dyn RecoveryProcessOriginPort>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RecoveryCommandResponseV1, RecoveryCommandPortError>;
    // Proposed mandatory methods inside RecoveryAuthorityPort.
    fn command_with_selection(
        &self,
        _actor: &AuthenticatedRecoveryActor,
        _command: &RecoveryCommandV1,
        _original_process: Option<&dyn RecoveryProcessOriginPort>,
        _fence: &StoreMutationFence,
        _now: u64,
    ) -> Result<RecoveryCommandPortOutcome, RecoveryCommandPortError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "native command generation selection is unsupported".into(),
        )
        .into())
    }

    fn load_selection(
        &self,
        _actor: &AuthenticatedRecoveryActor,
        _selection: &RecoveryCommandPortSelection,
        _fence: &StoreMutationFence,
        _now: u64,
    ) -> Result<RecoveryCommandSelectedWorkflowData, AdmissionOperationStoreError> {
        Err(AdmissionOperationStoreError::Unavailable(
            "native selected generation read is unsupported".into(),
        ))
    }

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
        body: &chio_core_types::recovery::RecoveryGrantBodyV2,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<chio_core_types::recovery::RecoveryGrantBodyV2, AdmissionOperationStoreError>;
    fn attach_signature(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        grant: &chio_core_types::recovery::SignedRecoveryGrantV2,
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
    /// Authenticated captured custody only. Legacy absence is distinct from
    /// corrupt or missing mandatory versioned custody, which remains an error.
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

impl crate::ChioKernel {
    pub(crate) fn revalidate_recovery_actor(
        &self,
        actor: &AuthenticatedRecoveryActor,
    ) -> Result<(), crate::KernelError> {
        let current = self.authenticate_recovery_actor(
            actor.scope(),
            actor.capability(),
            actor.permission(),
        )?;
        if current.principal() != actor.principal() {
            return Err(crate::KernelError::RecoveryAuthorityDenied);
        }
        Ok(())
    }

    /// Full cryptographic authentication is repeated for each request. Durable
    /// mutations independently check current assignments, revocation and time.
    pub fn authenticate_recovery_actor(
        &self,
        scope: &RecoveryScopeV1,
        capability: &CapabilityToken,
        permission: RecoveryPermission,
    ) -> Result<AuthenticatedRecoveryActor, crate::KernelError> {
        let now = crate::kernel::current_unix_timestamp_ms();
        self.verify_capability_full_pre_admit_typed(capability, None, now / 1000)
            .map_err(|error| error.recovery_error())?;
        // This bounded control profile has its own durable command/lookup
        // quotas. It has no native invocation or sender-proof admission, so it
        // must refuse tokens that require those stateful enforcement paths.
        if capability.aggregate_invocation_budget.is_some()
            || capability.budget_share_bps.is_some()
            || !capability.delegation_chain.is_empty()
            || !capability.caveats.is_empty()
            || capability.scope_attenuations.is_some()
            || capability.attenuation_proof.is_some()
        {
            return Err(crate::KernelError::RecoveryAuthorityDenied);
        }
        if self.is_capability_revoked(&capability.id)? {
            return Err(crate::KernelError::RecoveryAuthorityDenied);
        }
        let deployment = self.recovery_deployment(scope)?;
        let assignment = deployment
            .actors
            .as_slice()
            .iter()
            .find(|actor| {
                actor.subject == capability.subject
                    && actor.permissions.as_slice().contains(&permission)
            })
            .ok_or(crate::KernelError::RecoveryAuthorityDenied)?;
        let matching: Vec<_> = capability
            .scope
            .grants
            .iter()
            .filter(|grant| {
                matches!(grant.server_id.as_str(), "chio.recovery" | "*")
                    && (grant.tool_name == permission.wire_name() || grant.tool_name == "*")
            })
            .collect();
        let permitted = !matching.is_empty()
            && matching.iter().all(|grant| {
                grant.server_id == "chio.recovery"
                    && grant.tool_name == permission.wire_name()
                    && grant.constraints.is_empty()
                    && grant.max_invocations.is_none()
                    && grant.max_cost_per_invocation.is_none()
                    && grant.max_total_cost.is_none()
                    && grant.dpop_required != Some(true)
                    && grant
                        .operations
                        .contains(&chio_core_types::capability::scope::Operation::Invoke)
            });
        if !permitted {
            return Err(crate::KernelError::RecoveryAuthorityDenied);
        }
        Ok(AuthenticatedRecoveryActor {
            scope: scope.clone(),
            principal: assignment.principal.clone(),
            capability: capability.clone(),
            permission,
        })
    }

    /// A protected, exact envelope is loaded through the native authority. The
    /// returned custody token still cannot bypass ordinary kernel admission.
    pub fn load_recovery_request_custody(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
    ) -> Result<RecoveryRequestCustody, crate::KernelError> {
        let record = self.read_recovery_workflow(actor, workflow)?;
        let original_nonce = self.load_recovery_original_nonce(&record)?;
        let envelope = record.envelope.ok_or_else(|| {
            crate::KernelError::DurableAdmission("recovery custody is absent".into())
        })?;
        let request: crate::ToolCallRequest = serde_json::from_str(envelope.request.as_str())
            .map_err(|_| {
                crate::KernelError::DurableAdmission("recovery custody is invalid".into())
            })?;
        Ok(RecoveryRequestCustody {
            scope: record.scope,
            continuation: record.continuation_id,
            action_intent: envelope.action_intent,
            request,
            process_request_digest: hex_digest(envelope.process_request_digest.as_bytes()),
            process_binding_digest: hex_digest(envelope.process_binding_digest.as_bytes()),
            original_nonce,
        })
    }
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 15)] as char);
    }
    encoded
}

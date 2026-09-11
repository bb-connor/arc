//! Native input and post-join policy use only kernel-owned mutation/custody.
//! No legacy flow, declassification or receipt store is installed by this resolver.

use super::*;
use chio_kernel::admission_operation::{
    AdmissionOperationId, NativeSecurityAuthorityBindingV1, NativeSecurityEgressHistoryV1,
    NativeSecurityFlowObservationV1,
};
use chio_kernel::{KernelError, PreparedNativeSecurityEgress};

const MAX_CANONICAL_TIME: u64 = (1_u64 << 53) - 1;

mod output;
mod policy;
pub use policy::NativeFlowPolicyEvidence;

#[derive(Debug, thiserror::Error)]
pub enum NativeFlowError {
    #[error("native flow authority differs from original kernel custody")]
    AuthorityMismatch,
    #[error("legacy evidence stores cannot configure native flow authority")]
    LegacyEvidenceConfigured,
    #[error("operation-owned native declassification is unsupported")]
    UnsupportedDeclassification,
    #[error("native flow classification exceeds the already recorded input taint")]
    UnrecordedInputTaint,
    #[error("native flow decision clock is stale, expired or outside kernel observation")]
    ClockChanged,
    #[error("native flow policy callback panicked")]
    CallbackPanicked,
    #[error("native flow policy evidence is invalid or exceeds its bound")]
    PolicyEvidence,
    #[error(transparent)]
    Policy(#[from] FlowDenial),
    #[error(transparent)]
    Custody(#[from] KernelError),
}

/// Trusted-host policy configuration for an independently initialized native
/// authority. Construction grants neither activation nor mutation authority.
/// Unlike the persistent legacy resolver, this type owns no flow-state store.
pub struct NativeFlowResolver {
    binding: NativeSecurityAuthorityBindingV1,
    manifests: Arc<VerifiedManifestRegistry>,
    classifier: Arc<dyn ClassificationPort>,
    clock: Arc<dyn SecurityClock>,
    config: FlowResolverConfig,
}

/// A verified policy result tied to the original resolver and kernel handle.
/// The manifest registry and policy stay borrowed until custody is committed.
/// It cannot be cloned, serialized or retargeted to another live request.
#[must_use]
pub struct PreparedNativeFlowDispatch<'a> {
    resolver: &'a NativeFlowResolver,
    custody: PreparedNativeSecurityEgress<'a>,
    admission: FlowAdmission,
    policy_evidence: NativeFlowPolicyEvidence,
    prepared_at: u64,
    valid_until: u64,
}

/// Historical policy, optional egress custody and optional durable preparation
/// ledger. This is not a dispatch permit or live credential verification. No
/// execution path accepts this data as authority. Non-egress has no fence.
pub struct NativeFlowCustody {
    operation_id: AdmissionOperationId,
    observation: NativeSecurityFlowObservationV1,
    live_request_digest: Digest32,
    admission: FlowAdmission,
    policy_evidence: NativeFlowPolicyEvidence,
    egress: Option<NativeSecurityEgressHistoryV1>,
    dispatch_ledger: Option<chio_kernel::admission_operation::NativeSecurityDispatchLedgerRecordV1>,
}

impl std::fmt::Debug for PreparedNativeFlowDispatch<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedNativeFlowDispatch")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for NativeFlowCustody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeFlowCustody").finish_non_exhaustive()
    }
}

impl NativeFlowResolver {
    pub fn new(
        binding: NativeSecurityAuthorityBindingV1,
        manifests: Arc<VerifiedManifestRegistry>,
        classifier: Arc<dyn ClassificationPort>,
        clock: Arc<dyn SecurityClock>,
        config: FlowResolverConfig,
    ) -> Result<Self, NativeFlowError> {
        if config.declassification_evidence.is_some() || config.receipt_evidence.is_some() {
            return Err(NativeFlowError::LegacyEvidenceConfigured);
        }
        Ok(Self {
            binding,
            manifests,
            classifier,
            clock,
            config,
        })
    }

    /// Classify the kernel handle's exact request using its fresh native state.
    /// Preparation is read-only. The existing operation must already contain
    /// the input taint; this phase never repeats its admission join.
    pub fn prepare_dispatch<'a>(
        &'a self,
        custody: PreparedNativeSecurityEgress<'a>,
    ) -> Result<PreparedNativeFlowDispatch<'a>, NativeFlowError> {
        if custody.observation().binding() != &self.binding {
            return Err(NativeFlowError::AuthorityMismatch);
        }
        if custody.request().declassification_grant.is_some() {
            return Err(NativeFlowError::UnsupportedDeclassification);
        }
        let state = custody
            .observation()
            .snapshot()
            .cloned()
            .ok_or(FlowDenial::StateChanged)?;
        let resolved = policy_call(|| {
            self.policy().resolve_pre_with_evidence(
                &FlowPreInvocationInput {
                    security_context: custody.security_context().as_v1(),
                    request: custody.request(),
                },
                state.clone(),
            )
        })??;
        let prepared_at = resolved.request.now_unix_ms;
        let valid_until = resolved.request.fence_expires_at_unix_ms;
        if prepared_at < custody.observation().observed_at_unix_ms()
            || valid_until > MAX_CANONICAL_TIME
        {
            return Err(NativeFlowError::ClockChanged);
        }
        let policy_inputs = policy::PreparedInputs::capture(self, &custody, &resolved)?;
        let admission = prepare_pre_invocation(resolved.request)?.into_admission()?;
        // Legacy preparation would now apply this transition. Native admission
        // has already joined exactly once. Classification drift or insufficient
        // propagation must deny, not silently discard a required taint write.
        let taint = &admission.taint_transition;
        if taint.key != state.key
            || !taint.principal_join.flows_to(&state.principal_label)
            || !taint.lineage_join.flows_to(&state.lineage_label)
            || !taint.session_join.flows_to(&state.session_label)
        {
            return Err(NativeFlowError::UnrecordedInputTaint);
        }
        let policy_evidence = policy_inputs.finish(&admission)?;
        let validated_at = custody.validate_current()?;
        require_time(
            custody.observation().observed_at_unix_ms(),
            prepared_at,
            validated_at,
            valid_until,
        )?;
        Ok(PreparedNativeFlowDispatch {
            resolver: self,
            custody,
            admission,
            policy_evidence,
            prepared_at,
            valid_until,
        })
    }

    fn policy(&self) -> flow_policy::FlowPolicyView<'_> {
        flow_policy::FlowPolicyView {
            manifests: &self.manifests,
            classifier: self.classifier.as_ref(),
            clock: self.clock.as_ref(),
            config: &self.config,
        }
    }
}

impl chio_kernel::SecurityPreDispatchHook for NativeFlowResolver {
    fn name(&self) -> &str {
        "native-flow-resolver"
    }

    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        Ok(Some(self.binding.clone()))
    }

    fn prepare_native_admission(
        &self,
        context: &chio_kernel::NativeSecurityAdmissionContext<'_>,
        authority: &chio_kernel::NativeSecurityFlowJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        let input_label = policy_call(|| {
            if authority.binding() != &self.binding {
                return Err(NativeFlowError::AuthorityMismatch);
            }
            if context.request.declassification_grant.is_some() {
                return Err(NativeFlowError::UnsupportedDeclassification);
            }
            self.policy()
                .classified_input_label(&FlowPreInvocationInput {
                    security_context: context.security_context.as_v1(),
                    request: context.request,
                })
                .map_err(NativeFlowError::from)
        })
        .and_then(|result| result)
        .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
        authority.join_input(input_label)?;
        Ok(())
    }

    fn prepare_native_output(
        &self,
        context: &chio_kernel::tool_outcome::DurableSecurityReleaseContext<'_>,
        authority: &chio_kernel::NativeSecurityOutputJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        if authority.binding() != &self.binding {
            return Err(KernelError::GuardDenied(
                NativeFlowError::AuthorityMismatch.to_string(),
            ));
        }
        let label = policy_call(|| self.classify_output(context))
            .and_then(|result| result)
            .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
        authority.join_output(label)?;
        Ok(())
    }

    fn commit(
        &self,
        _: &chio_kernel::SecurityPreDispatchContext<'_>,
    ) -> Result<Option<chio_kernel::SecurityDispatchOutcomeHandle>, KernelError> {
        // Native policy cannot fall back to legacy lifecycle or grant execution.
        Err(KernelError::GuardDenied(
            "native security dispatch lifecycle is unsupported".into(),
        ))
    }
}

impl PreparedNativeFlowDispatch<'_> {
    /// Qualified-host capture checkpoint using this live resolver's policy and
    /// the kernel's actual reservation. This records quota capture only; native
    /// connector execution and recovery use remain unsupported.
    pub fn capture_invocation(
        self,
        authority: &mut chio_kernel::NativeSecurityDispatchCaptureAuthority<'_, '_>,
    ) -> Result<(NativeFlowCustody, chio_kernel::AdmissionBudgetCapture), NativeFlowError> {
        let sampled = policy_call(|| self.resolver.clock.now_unix_ms())?
            .map_err(|_| NativeFlowError::ClockChanged)?;
        let validated = self.custody.validate_current()?;
        require_time(self.prepared_at, sampled, validated, self.valid_until)?;
        let operation_id = self.custody.operation_id().clone();
        let observation = self.custody.observation().clone();
        let live_request_digest =
            super::flow_dispatch::live_request_digest(self.custody.request())?;
        let (prepared, egress, ledger) = self.custody.retain_for_capture(
            self.admission
                .egress_fence_plan
                .as_ref()
                .map(|plan| plan.expires_at_unix_ms),
            authority.grant_index()?,
            self.policy_evidence.canonical_bytes(),
        )?;
        // Resolver policy, manifests and evidence remain borrowed through the
        // store call. No decoded NativeFlowCustody can manufacture this path.
        let capture =
            authority.capture(prepared, &ledger, self.policy_evidence.canonical_bytes())?;
        let custody = NativeFlowCustody {
            operation_id,
            observation,
            live_request_digest,
            admission: self.admission,
            policy_evidence: self.policy_evidence,
            egress,
            dispatch_ledger: Some(ledger),
        };
        Ok((custody, capture))
    }

    /// Verified policy data. Its taint transition is already covered by the
    /// native observation, not a command to perform another join.
    pub fn admission(&self) -> &FlowAdmission {
        &self.admission
    }

    /// Exact policy material from this preparation, not a serialized permit.
    pub fn policy_evidence(&self) -> &NativeFlowPolicyEvidence {
        &self.policy_evidence
    }

    /// Revalidate and commit only the custody required by the verified policy.
    /// This does not commit budget, verify credentials, attach a dispatch ledger,
    /// invoke a connector or activate an otherwise unsupported native profile.
    pub fn commit_custody(self) -> Result<NativeFlowCustody, NativeFlowError> {
        self.commit_custody_inner(None)
    }

    /// Retain this exact policy and the selected grant's physical participants
    /// in the native authority journal. This is not atomic budget capture or
    /// dispatch activation. Unsupported stores deny without a legacy fallback.
    pub fn commit_custody_with_dispatch_ledger(
        self,
        grant_index: usize,
    ) -> Result<NativeFlowCustody, NativeFlowError> {
        self.commit_custody_inner(Some(grant_index))
    }

    fn commit_custody_inner(
        self,
        grant_index: Option<usize>,
    ) -> Result<NativeFlowCustody, NativeFlowError> {
        let now = policy_call(|| self.resolver.clock.now_unix_ms())?
            .map_err(|_| NativeFlowError::ClockChanged)?;
        let validated_at = self.custody.validate_current()?;
        require_time(self.prepared_at, now, validated_at, self.valid_until)?;
        let operation_id = self.custody.operation_id().clone();
        let observation = self.custody.observation().clone();
        let live_request_digest =
            super::flow_dispatch::live_request_digest(self.custody.request())?;
        let (egress, dispatch_ledger) =
            match (self.admission.egress_fence_plan.as_ref(), grant_index) {
                (Some(plan), Some(grant)) => {
                    let (history, ledger) = self.custody.acquire_and_commit_with_dispatch_ledger(
                        plan.expires_at_unix_ms,
                        grant,
                        self.policy_evidence.canonical_bytes(),
                    )?;
                    (Some(history), Some(ledger))
                }
                (None, Some(grant)) => {
                    (
                        None,
                        Some(self.custody.retain_dispatch_ledger(
                            grant,
                            self.policy_evidence.canonical_bytes(),
                        )?),
                    )
                }
                (Some(plan), None) => (
                    Some(self.custody.acquire(plan.expires_at_unix_ms)?.commit()?),
                    None,
                ),
                (None, None) => (None, None),
            };
        Ok(NativeFlowCustody {
            operation_id,
            observation,
            live_request_digest,
            admission: self.admission,
            policy_evidence: self.policy_evidence,
            egress,
            dispatch_ledger,
        })
    }
}

impl NativeFlowCustody {
    /// Immutable preparation history, never proof of budget capture or execution.
    pub fn dispatch_ledger(
        &self,
    ) -> Option<&chio_kernel::admission_operation::NativeSecurityDispatchLedgerRecordV1> {
        self.dispatch_ledger.as_ref()
    }
    pub fn operation_id(&self) -> &AdmissionOperationId {
        &self.operation_id
    }
    pub fn observation(&self) -> &NativeSecurityFlowObservationV1 {
        &self.observation
    }
    pub fn live_request_digest(&self) -> Digest32 {
        self.live_request_digest
    }
    pub fn admission(&self) -> &FlowAdmission {
        &self.admission
    }
    pub fn policy_evidence(&self) -> &NativeFlowPolicyEvidence {
        &self.policy_evidence
    }
    pub fn egress_history(&self) -> Option<&NativeSecurityEgressHistoryV1> {
        self.egress.as_ref()
    }
}

fn require_time(
    earliest: u64,
    sampled: u64,
    validated: u64,
    deadline: u64,
) -> Result<(), NativeFlowError> {
    if sampled < earliest
        || sampled > validated
        || validated >= deadline
        || deadline > MAX_CANONICAL_TIME
    {
        return Err(NativeFlowError::ClockChanged);
    }
    Ok(())
}

fn policy_call<T>(callback: impl FnOnce() -> T) -> Result<T, NativeFlowError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(callback))
        .map_err(|_| NativeFlowError::CallbackPanicked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_policy_time_bounds_are_inclusive_at_observation_and_exclusive_at_expiry() {
        assert!(require_time(10, 10, 10, 11).is_ok());
        assert!(require_time(10, 11, 12, 13).is_ok());
        for (earliest, sampled, validated, deadline) in [
            (10, 9, 10, 11),
            (10, 11, 10, 12),
            (10, 10, 11, 11),
            (10, 10, 12, 11),
            (10, 10, 10, MAX_CANONICAL_TIME + 1),
        ] {
            assert!(matches!(
                require_time(earliest, sampled, validated, deadline),
                Err(NativeFlowError::ClockChanged)
            ));
        }
    }
}

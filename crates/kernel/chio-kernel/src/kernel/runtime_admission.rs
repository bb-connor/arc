//! Runtime verifier port: original-plan custody and bounded dispatch revalidation.
use super::{
    KernelError, RuntimeParticipantClaimAuthority, ToolCallRequest,
    VerifiedFederationTreatyMaterial,
};

/// Context passed to optional runtime admission hooks after capability,
/// request matching, governed-admission, and guard checks pass, but before
/// dispatch and federation co-signing side effects.
pub struct RuntimeAdmissionContext<'a> {
    pub request: &'a ToolCallRequest,
    pub extra_metadata: Option<&'a serde_json::Value>,
    pub now_unix_secs: u64,
    pub now_unix_ms: u64,
    pub matched_grant_index: Option<usize>,
    pub local_kernel_id: String,
}

/// Non-consuming context for the final runtime-admission check immediately
/// before payment authorization, nonce consumption, and tool dispatch.
pub struct RuntimeAdmissionRevalidationContext<'a> {
    pub request: &'a ToolCallRequest,
    pub admission_metadata: Option<&'a serde_json::Value>,
    pub now_unix_secs: u64,
    pub now_unix_ms: u64,
    pub matched_grant_index: Option<usize>,
    pub local_kernel_id: String,
}

/// Opaque identifier for one in-flight runtime-admission readiness poll.
/// Concurrent evaluations receive distinct tokens even when request IDs are
/// equal, so unregistering one wait cannot remove another wait's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RuntimeAdmissionReadinessToken(pub(super) u64);

impl RuntimeAdmissionReadinessToken {
    #[must_use]
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// Decision returned by a runtime admission hook.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeAdmissionDecision {
    pub allowed: bool,
    pub reason: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub(crate) verified_treaty_material: Option<VerifiedFederationTreatyMaterial>,
}

impl RuntimeAdmissionDecision {
    #[must_use]
    pub fn has_verified_treaty_material(&self) -> bool {
        self.verified_treaty_material.is_some()
    }

    #[must_use]
    pub fn allow(metadata: Option<serde_json::Value>) -> Self {
        Self {
            allowed: true,
            reason: None,
            metadata,
            verified_treaty_material: None,
        }
    }

    #[must_use]
    pub fn allow_with_verified_treaty_material(
        metadata: Option<serde_json::Value>,
        verified_treaty_material: VerifiedFederationTreatyMaterial,
    ) -> Self {
        Self {
            allowed: true,
            reason: None,
            metadata,
            verified_treaty_material: Some(verified_treaty_material),
        }
    }

    #[must_use]
    pub fn deny(reason: impl Into<String>, metadata: Option<serde_json::Value>) -> Self {
        Self {
            allowed: false,
            reason: Some(reason.into()),
            metadata,
            verified_treaty_material: None,
        }
    }
}

/// Optional pre-dispatch admission hook for product-specific runtime gates.
pub trait RuntimeAdmissionHook: Send + Sync {
    fn name(&self) -> &str;

    /// Select operation-owned replay custody from trusted hook configuration.
    /// The kernel independently requires durable activation of this generation.
    /// A configured hook never falls back to the legacy evaluate/release path.
    fn runtime_participant_binding(
        &self,
    ) -> Option<
        &crate::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1,
    > {
        None
    }

    /// Evaluate through a kernel-created, call-scoped claim authority. An Allow
    /// requires exactly one confirmed claim, including a plan with no resources.
    /// Claims survive callback failure and are cleaned up by the coordinator.
    fn evaluate_operation_owned(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
        _authority: &RuntimeParticipantClaimAuthority<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        Err(KernelError::DurableAdmission(
            "operation-owned runtime admission is unsupported by this hook".into(),
        ))
    }

    /// Declare that this trusted hook verifies stored swarm authority, binds
    /// the selected task to the exact request capability, and revalidates the
    /// evidence at dispatch. Required-swarm kernels reject the default.
    ///
    /// This declares an implementation contract, not evidence supplied by an
    /// agent. Implementations must also enable dispatch revalidation.
    fn enforces_swarm_authority(&self) -> bool {
        false
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError>;

    /// Poll readiness after admission state has been reserved but before tool
    /// dispatch is marked as started. The default is immediately ready.
    fn poll_ready_before_dispatch(
        &self,
        _request: &ToolCallRequest,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        std::task::Poll::Ready(())
    }

    /// Token-aware readiness poll. Hooks retaining per-wait state should
    /// override this method; the default preserves the original readiness API.
    fn poll_ready_before_dispatch_with_token(
        &self,
        request: &ToolCallRequest,
        _token: RuntimeAdmissionReadinessToken,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        self.poll_ready_before_dispatch(request, cx)
    }

    /// Return true when mutable admission state must be checked even if the
    /// readiness poll completes immediately.
    fn requires_dispatch_revalidation(&self) -> bool {
        false
    }

    /// Revalidate mutable admission state without acquiring another
    /// reservation. Mutable hooks opt in through
    /// [`Self::requires_dispatch_revalidation`].
    fn revalidate_before_dispatch(
        &self,
        _context: &RuntimeAdmissionRevalidationContext<'_>,
    ) -> Result<(), KernelError> {
        Ok(())
    }

    /// Revalidate an operation-owned plan against the durable activation's
    /// expected physical source. A legacy implementation cannot satisfy this
    /// contract by accepting request metadata or by skipping source verification.
    fn revalidate_operation_owned_before_dispatch(
        &self,
        _context: &RuntimeAdmissionRevalidationContext<'_>,
        _source: &crate::admission_operation::RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), KernelError> {
        Err(KernelError::DurableAdmission(
            "operation-owned runtime revalidation is unsupported".to_owned(),
        ))
    }

    /// Revalidate the exact physically owned plan and return the earliest
    /// exclusive validity bound of its authenticated artifacts. Called outside
    /// the mutation sequencer. Ordinary revalidation success is insufficient:
    /// native capture must recheck freshness inside its final transaction.
    fn revalidate_operation_owned_for_native_capture(
        &self,
        _context: &RuntimeAdmissionRevalidationContext<'_>,
        _source: &crate::admission_operation::RuntimeReplaySourceSnapshotV1,
        _intent: &crate::admission_operation::runtime_participant::RuntimeParticipantClaimIntentV1,
    ) -> Result<crate::admission_operation::runtime_participant::RuntimeDispatchValidity, KernelError>
    {
        Err(KernelError::DurableAdmission(
            "transaction-bound native runtime revalidation is unsupported".into(),
        ))
    }

    /// Remove request-scoped readiness state, including any retained waker.
    fn unregister_ready_before_dispatch(
        &self,
        _request: &ToolCallRequest,
        _token: RuntimeAdmissionReadinessToken,
    ) {
    }

    fn release_reserved(&self, _metadata: &serde_json::Value) -> Result<(), KernelError> {
        Ok(())
    }
}

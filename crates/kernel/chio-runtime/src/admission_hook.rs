//! Runtime hook configuration and delegation to the single core verifier.
use super::*;

#[derive(Debug, Clone)]
pub struct ChioRuntimeAdmissionHook<S> {
    profile: RuntimeAdmissionProfile,
    store: S,
    runtime_trust_input: Option<SignedRuntimeVerifierTrustBundle>,
    trusted_verifier_keys: Vec<RuntimeTrustedVerifierKey>,
    pheromone_query_report: Option<SignedRuntimePheromoneQueryReport>,
    runtime_pheromone_policy: Option<SignedRuntimePheromonePolicy>,
    runtime_peer_weights: Option<SignedRuntimePeerWeights>,
    swarm_witness_keys: Vec<chio_core_types::PublicKey>,
    fixed_now_unix_ms: Option<u64>,
    operation_owned_binding: Option<
        chio_kernel::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1,
    >,
}

impl<S> ChioRuntimeAdmissionHook<S> {
    #[must_use]
    pub fn new(profile: RuntimeAdmissionProfile, store: S) -> Self {
        Self {
            profile,
            store,
            runtime_trust_input: None,
            trusted_verifier_keys: Vec::new(),
            pheromone_query_report: None,
            runtime_pheromone_policy: None,
            runtime_peer_weights: None,
            swarm_witness_keys: Vec::new(),
            fixed_now_unix_ms: None,
            operation_owned_binding: None,
        }
    }

    #[must_use]
    pub fn with_operation_owned_runtime_replay(
        mut self,
        binding: chio_kernel::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1,
    ) -> Self {
        self.operation_owned_binding = Some(binding);
        self
    }

    #[must_use]
    pub fn with_runtime_trust_input(
        mut self,
        runtime_trust_input: SignedRuntimeVerifierTrustBundle,
        trusted_verifier_keys: Vec<RuntimeTrustedVerifierKey>,
    ) -> Self {
        self.runtime_trust_input = Some(runtime_trust_input);
        self.trusted_verifier_keys = trusted_verifier_keys;
        self
    }

    #[must_use]
    pub fn with_pheromone_query_report(
        mut self,
        report: SignedRuntimePheromoneQueryReport,
    ) -> Self {
        self.pheromone_query_report = Some(report);
        self
    }

    #[must_use]
    pub fn with_runtime_pheromone_policy(
        mut self,
        policy: SignedRuntimePheromonePolicy,
        peer_weights: SignedRuntimePeerWeights,
    ) -> Self {
        self.runtime_pheromone_policy = Some(policy);
        self.runtime_peer_weights = Some(peer_weights);
        self
    }

    #[must_use]
    pub fn with_swarm_witness_keys(
        mut self,
        witness_keys: Vec<chio_core_types::PublicKey>,
    ) -> Self {
        self.swarm_witness_keys = witness_keys;
        self
    }

    #[must_use]
    pub fn with_fixed_now_unix_ms(mut self, now_unix_ms: u64) -> Self {
        self.fixed_now_unix_ms = Some(now_unix_ms);
        self
    }

    fn core_hook(
        &self,
    ) -> chio_runtime_core::ChioRuntimeAdmissionHook<RuntimeCoreAdmissionStoreAdapter<'_>>
    where
        S: ChioRuntimeAdmissionStore,
    {
        let mut hook = chio_runtime_core::ChioRuntimeAdmissionHook::new(
            self.profile.clone(),
            RuntimeCoreAdmissionStoreAdapter { inner: &self.store },
        );
        if let Some(runtime_trust_input) = &self.runtime_trust_input {
            hook = hook.with_runtime_trust_input(
                runtime_trust_input.clone(),
                self.trusted_verifier_keys.clone(),
            );
        }
        if let Some(pheromone_query_report) = &self.pheromone_query_report {
            hook = hook.with_pheromone_query_report(pheromone_query_report.clone());
        }
        if let (Some(policy), Some(peer_weights)) =
            (&self.runtime_pheromone_policy, &self.runtime_peer_weights)
        {
            hook = hook.with_runtime_pheromone_policy(policy.clone(), peer_weights.clone());
        }
        hook = hook.with_swarm_witness_keys(self.swarm_witness_keys.clone());
        if let Some(binding) = &self.operation_owned_binding {
            hook = hook.with_operation_owned_runtime_replay(binding.clone());
        }
        if let Some(now_unix_ms) = self.fixed_now_unix_ms {
            hook = hook.with_fixed_now_unix_ms(now_unix_ms);
        }
        hook
    }
}

impl<S> chio_kernel::RuntimeAdmissionHook for ChioRuntimeAdmissionHook<S>
where
    S: ChioRuntimeAdmissionStore + Send + Sync,
{
    fn name(&self) -> &str {
        "chio-runtime-admission"
    }

    fn runtime_participant_binding(
        &self,
    ) -> Option<&chio_kernel::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1>{
        self.operation_owned_binding.as_ref()
    }

    fn evaluate_operation_owned(
        &self,
        context: &chio_kernel::RuntimeAdmissionContext<'_>,
        authority: &chio_kernel::RuntimeParticipantClaimAuthority<'_>,
    ) -> Result<chio_kernel::RuntimeAdmissionDecision, chio_kernel::KernelError> {
        chio_kernel::RuntimeAdmissionHook::evaluate_operation_owned(
            &self.core_hook(),
            context,
            authority,
        )
    }

    fn evaluate(
        &self,
        context: &chio_kernel::RuntimeAdmissionContext<'_>,
    ) -> Result<chio_kernel::RuntimeAdmissionDecision, chio_kernel::KernelError> {
        chio_kernel::RuntimeAdmissionHook::evaluate(&self.core_hook(), context)
    }

    fn release_reserved(
        &self,
        metadata: &serde_json::Value,
    ) -> Result<(), chio_kernel::KernelError> {
        chio_kernel::RuntimeAdmissionHook::release_reserved(&self.core_hook(), metadata)
    }

    fn requires_dispatch_revalidation(&self) -> bool {
        chio_kernel::RuntimeAdmissionHook::requires_dispatch_revalidation(&self.core_hook())
    }

    fn enforces_swarm_authority(&self) -> bool {
        chio_kernel::RuntimeAdmissionHook::enforces_swarm_authority(&self.core_hook())
    }

    fn revalidate_before_dispatch(
        &self,
        context: &chio_kernel::RuntimeAdmissionRevalidationContext<'_>,
    ) -> Result<(), chio_kernel::KernelError> {
        chio_kernel::RuntimeAdmissionHook::revalidate_before_dispatch(&self.core_hook(), context)
    }

    fn revalidate_operation_owned_before_dispatch(
        &self,
        context: &chio_kernel::RuntimeAdmissionRevalidationContext<'_>,
        source: &chio_kernel::admission_operation::RuntimeReplaySourceSnapshotV1,
    ) -> Result<(), chio_kernel::KernelError> {
        chio_kernel::RuntimeAdmissionHook::revalidate_operation_owned_before_dispatch(
            &self.core_hook(),
            context,
            source,
        )
    }

    fn revalidate_operation_owned_for_native_capture(
        &self,
        context: &chio_kernel::RuntimeAdmissionRevalidationContext<'_>,
        source: &chio_kernel::admission_operation::RuntimeReplaySourceSnapshotV1,
        intent: &chio_kernel::admission_operation::runtime_participant::RuntimeParticipantClaimIntentV1,
    ) -> Result<
        chio_kernel::admission_operation::runtime_participant::RuntimeDispatchValidity,
        chio_kernel::KernelError,
    > {
        chio_kernel::RuntimeAdmissionHook::revalidate_operation_owned_for_native_capture(
            &self.core_hook(),
            context,
            source,
            intent,
        )
    }
}

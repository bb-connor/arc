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
    swarm_graphs: Option<std::sync::Arc<IssuedSwarmGraphs>>,
    operation_owned_binding:
        chio_kernel::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1,
}

impl<S> ChioRuntimeAdmissionHook<S> {
    #[must_use]
    pub fn new(
        profile: RuntimeAdmissionProfile,
        store: S,
        binding: chio_kernel::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1,
    ) -> Self {
        Self {
            profile,
            store,
            runtime_trust_input: None,
            trusted_verifier_keys: Vec::new(),
            pheromone_query_report: None,
            runtime_pheromone_policy: None,
            runtime_peer_weights: None,
            swarm_witness_keys: Vec::new(),
            swarm_graphs: None,
            operation_owned_binding: binding,
        }
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
    pub fn with_swarm_graphs(mut self, graphs: IssuedSwarmGraphs) -> Self {
        self.swarm_graphs = Some(std::sync::Arc::new(graphs));
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
            self.operation_owned_binding.clone(),
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
        if let Some(graphs) = &self.swarm_graphs {
            hook = hook.with_swarm_graph_source(graphs.clone());
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
        Some(&self.operation_owned_binding)
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

    fn revalidate_reserved_operation(
        &self,
        context: &chio_kernel::RuntimeAdmissionContext<'_>,
        source: &chio_kernel::admission_operation::RuntimeSourceQualificationV1,
        claim: &chio_kernel::admission_operation::runtime_participant::RuntimeParticipantClaimHistoryV1,
    ) -> Result<chio_kernel::RuntimeAdmissionDecision, chio_kernel::KernelError> {
        chio_kernel::RuntimeAdmissionHook::revalidate_reserved_operation(
            &self.core_hook(),
            context,
            source,
            claim,
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
        source: &chio_kernel::admission_operation::RuntimeSourceQualificationV1,
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
        source: &chio_kernel::admission_operation::RuntimeSourceQualificationV1,
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

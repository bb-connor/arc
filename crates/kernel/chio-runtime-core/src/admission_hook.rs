use crate::*;

use chio_core_types::PublicKey;

mod dispatch_validity;
mod dsse;
mod metadata;
mod operation_owned;
mod preparation;
mod request;
mod store_artifacts;
mod swarm_authority;
mod swarm_ref;
mod swarm_request_binding;
mod treaty_evidence;
mod treaty_ref;

use crate::pheromone_policy::{evaluate_runtime_pheromone_policy, RuntimePolicyEvaluationInput};
use metadata::{runtime_context_denial_metadata, runtime_denial_metadata};
use request::{admission_ref_from_request, request_has_chio_runtime_context};
use swarm_authority::verify_swarm_authority_reference;
use swarm_ref::swarm_ref_from_request;
use treaty_evidence::verify_treaty_reference_from_store;
use treaty_ref::treaty_ref_from_request;

#[derive(Debug, Clone)]
pub struct ChioRuntimeAdmissionHook<S> {
    profile: RuntimeAdmissionProfile,
    store: S,
    runtime_trust_input: Option<SignedRuntimeVerifierTrustBundle>,
    trusted_verifier_keys: Vec<RuntimeTrustedVerifierKey>,
    pheromone_query_report: Option<SignedRuntimePheromoneQueryReport>,
    runtime_pheromone_policy: Option<SignedRuntimePheromonePolicy>,
    runtime_peer_weights: Option<SignedRuntimePeerWeights>,
    swarm_witness_keys: Vec<PublicKey>,
    swarm_graphs: Option<Arc<dyn SwarmGraphSource>>,
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
    pub fn with_swarm_witness_keys(mut self, witness_keys: Vec<PublicKey>) -> Self {
        self.swarm_witness_keys = witness_keys;
        self
    }

    /// The qualified S1 graph issuer that swarm-bound requests resolve against.
    #[must_use]
    pub fn with_swarm_graph_source(mut self, source: Arc<dyn SwarmGraphSource>) -> Self {
        self.swarm_graphs = Some(source);
        self
    }
}

impl<S> ChioRuntimeAdmissionHook<S>
where
    S: RuntimeAdmissionStore + Send + Sync,
{
    fn revalidate_admitted_request(
        &self,
        context: &KernelRuntimeAdmissionRevalidationContext<'_>,
    ) -> Result<(), KernelError> {
        let admission_ref = match admission_ref_from_request(context.request) {
            Ok(reference) => reference,
            Err(_) if !request_has_chio_runtime_context(context.request) => {
                if context
                    .admission_metadata
                    .and_then(|metadata| metadata.get("chio_runtime"))
                    .and_then(|runtime| runtime.get("accepted"))
                    .and_then(serde_json::Value::as_bool)
                    == Some(true)
                {
                    return Err(KernelError::Internal(
                        "runtime admission context disappeared before dispatch".to_string(),
                    ));
                }
                if context.request.federated_origin_kernel_id.is_some() {
                    return Err(KernelError::Internal(
                        "runtime admission revalidation requires treaty context for a federated request"
                            .to_string(),
                    ));
                }
                return Ok(());
            }
            Err(code) => {
                return Err(KernelError::Internal(format!(
                    "runtime admission revalidation rejected the request context: {code}"
                )));
            }
        };

        let runtime = context
            .admission_metadata
            .and_then(|metadata| metadata.get("chio_runtime"))
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                KernelError::Internal(
                    "runtime admission revalidation metadata is missing".to_string(),
                )
            })?;
        if runtime.get("accepted").and_then(serde_json::Value::as_bool) != Some(true)
            || runtime
                .get("admission_id")
                .and_then(serde_json::Value::as_str)
                != Some(admission_ref.admission_id.as_str())
        {
            return Err(KernelError::Internal(
                "runtime admission revalidation metadata does not identify the admitted decision"
                    .to_string(),
            ));
        }

        let now_unix_ms = context.now_unix_ms;
        if self.profile.schema != CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA
            || now_unix_ms < self.profile.issued_at_unix_ms
            || now_unix_ms >= self.profile.expires_at_unix_ms
            || context.local_kernel_id != self.profile.local_kernel_id
        {
            return Err(KernelError::Internal(
                "runtime admission profile is not valid at the dispatch boundary".to_string(),
            ));
        }

        let binding = RuntimeRequestBinding::from_tool_call_request(
            context.request,
            &context.local_kernel_id,
        )
        .map_err(|error| {
            KernelError::Internal(format!(
                "runtime admission request binding revalidation failed: {error}"
            ))
        })?;
        let bundle = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.store.bundle(&admission_ref.admission_id)
        })) {
            Ok(Ok(Some(bundle))) => bundle,
            Ok(Ok(None)) => {
                return Err(KernelError::Internal(
                    "runtime admission bundle disappeared before dispatch".to_string(),
                ));
            }
            Ok(Err(error)) => {
                return Err(KernelError::Internal(format!(
                    "runtime admission bundle revalidation failed: {error}"
                )));
            }
            Err(_) => {
                return Err(KernelError::Internal(
                    "runtime admission bundle revalidation panicked".to_string(),
                ));
            }
        };
        if bundle.schema != CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA
            || bundle.admission_id != admission_ref.admission_id
            || bundle.binding != binding
            || bundle.binding.host_kernel_id != self.profile.local_kernel_id
        {
            return Err(KernelError::Internal(
                "runtime admission bundle changed before dispatch".to_string(),
            ));
        }
        if let Some(expected_hash) = admission_ref.bundle_sha256.as_deref() {
            let actual_hash = runtime_admission_bundle_sha256(&bundle).map_err(|error| {
                KernelError::Internal(format!(
                    "runtime admission bundle hash revalidation failed: {error}"
                ))
            })?;
            if actual_hash != expected_hash {
                return Err(KernelError::Internal(
                    "runtime admission bundle hash changed before dispatch".to_string(),
                ));
            }
        }

        let metadata_matches_bundle = runtime
            .get("workflow_id")
            .and_then(serde_json::Value::as_str)
            == Some(bundle.workflow_id.as_str())
            && runtime
                .get("workflow_grant_id")
                .and_then(serde_json::Value::as_str)
                == Some(bundle.workflow_grant_id.as_str())
            && runtime
                .get("step_index")
                .and_then(serde_json::Value::as_u64)
                == Some(bundle.step_index)
            && runtime
                .get("destructive")
                .and_then(serde_json::Value::as_bool)
                == Some(bundle.destructive)
            && runtime.get("lease_id") == Some(&serde_json::json!(bundle.lease_id))
            && runtime.get("governance_receipt_id")
                == Some(&serde_json::json!(bundle.governance_receipt_id))
            && runtime
                .get("trust_bundle_sha256")
                .and_then(serde_json::Value::as_str)
                == Some(bundle.trust_bundle_sha256.as_str())
            && runtime
                .get("verification_context_sha256")
                .and_then(serde_json::Value::as_str)
                == Some(bundle.verification_context_sha256.as_str());
        if !metadata_matches_bundle {
            return Err(KernelError::Internal(
                "runtime admission metadata changed before dispatch".to_string(),
            ));
        }

        let mut checks = Vec::new();
        if let Some(runtime_trust_input) = self.runtime_trust_input.as_ref() {
            if runtime_trust_input.body.verifier_id != self.profile.verifier_id {
                return Err(KernelError::Internal(
                    "runtime trust input verifier changed before dispatch".to_string(),
                ));
            }
            let trust_floor_entry = crate::admission::validate_runtime_trust_input(
                runtime_trust_input,
                &self.trusted_verifier_keys,
                &bundle,
                now_unix_ms,
                &mut checks,
            )
            .map_err(|code| {
                KernelError::Internal(format!("runtime trust input revalidation failed: {code}"))
            })?;
            let persisted_floor =
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.store.runtime_trust_floor(
                        &trust_floor_entry.verifier_id,
                        &trust_floor_entry.key_id,
                    )
                })) {
                    Ok(Ok(Some(floor))) => floor,
                    Ok(Ok(None)) => {
                        return Err(KernelError::Internal(
                            "runtime trust floor disappeared before dispatch".to_string(),
                        ));
                    }
                    Ok(Err(error)) => {
                        return Err(KernelError::Internal(format!(
                            "runtime trust floor revalidation failed: {error}"
                        )));
                    }
                    Err(_) => {
                        return Err(KernelError::Internal(
                            "runtime trust floor revalidation panicked".to_string(),
                        ));
                    }
                };
            crate::admission::validate_runtime_trust_floor_transition(
                Some(persisted_floor.clone()),
                &trust_floor_entry,
                runtime_trust_input.body.previous_hash_sha256.as_deref(),
            )
            .map_err(|error| {
                KernelError::Internal(format!("runtime trust floor revalidation failed: {error}"))
            })?;
            if persisted_floor != trust_floor_entry {
                return Err(KernelError::Internal(
                    "runtime trust floor changed before dispatch".to_string(),
                ));
            }
        } else if !self.trusted_verifier_keys.is_empty() {
            return Err(KernelError::Internal(
                "runtime trust input disappeared before dispatch".to_string(),
            ));
        }

        let swarm_reference = swarm_ref_from_request(context.request).map_err(|code| {
            KernelError::Internal(format!(
                "runtime swarm reference revalidation failed: {code}"
            ))
        })?;
        let verified_swarm_route_metadata = runtime.get("verified_swarm_route_metadata");
        let verified_swarm = swarm_reference
            .as_ref()
            .map(|reference| {
                verify_swarm_authority_reference(
                    self.swarm_graphs.as_deref(),
                    reference,
                    context.request,
                    &self.swarm_witness_keys,
                    verified_swarm_route_metadata,
                    now_unix_ms,
                )
            })
            .transpose()
            .map_err(|error| {
                KernelError::Internal(format!(
                    "runtime swarm authority revalidation failed: {error}"
                ))
            })?;
        if runtime.get("verified_swarm_request_binding")
            != verified_swarm
                .as_ref()
                .map(|verified| &verified.request_binding)
        {
            return Err(KernelError::Internal(
                "runtime swarm request binding changed before dispatch".to_string(),
            ));
        }

        let mut action_class_id = None;
        let verified_treaty = match treaty_ref_from_request(context.request) {
            Ok(Some(treaty_ref)) => {
                action_class_id = Some(treaty_ref.action_class_id.clone());
                Some(
                    verify_treaty_reference_from_store(
                        &self.store,
                        &bundle,
                        &treaty_ref,
                        context.request,
                        now_unix_ms,
                    )
                    .map_err(|error| {
                        KernelError::Internal(format!(
                            "runtime treaty revalidation failed: {error}"
                        ))
                    })?,
                )
            }
            Ok(None) if context.request.federated_origin_kernel_id.is_some() => {
                return Err(KernelError::Internal(
                    "runtime treaty context disappeared before dispatch".to_string(),
                ));
            }
            Ok(None) => None,
            Err(code) => {
                return Err(KernelError::Internal(format!(
                    "runtime treaty reference revalidation failed: {code}"
                )));
            }
        };

        operation_owned::verify_revalidation_material(
            runtime,
            &bundle,
            verified_treaty.as_ref(),
            verified_swarm.as_ref(),
        )?;

        let (policy_decision, _) =
            evaluate_runtime_pheromone_policy(RuntimePolicyEvaluationInput {
                policy: self.runtime_pheromone_policy.as_ref(),
                peer_weights: self.runtime_peer_weights.as_ref(),
                query_report: self.pheromone_query_report.as_ref(),
                runtime_trust_input: self.runtime_trust_input.as_ref(),
                trusted_verifier_keys: &self.trusted_verifier_keys,
                bundle: &bundle,
                action_class_id: action_class_id.as_deref(),
                now_unix_ms,
                checks: &mut checks,
            })
            .map_err(|code| {
                KernelError::Internal(format!(
                    "runtime pheromone policy revalidation failed: {code}"
                ))
            })?;
        if policy_decision
            .as_ref()
            .is_some_and(|decision| matches!(decision.decision.as_str(), "deny" | "escalate"))
        {
            return Err(KernelError::Internal(
                "runtime pheromone policy no longer allows dispatch".to_string(),
            ));
        }
        Ok(())
    }
}

impl<S> RuntimeAdmissionHook for ChioRuntimeAdmissionHook<S>
where
    S: RuntimeAdmissionStore + Send + Sync,
{
    fn name(&self) -> &str {
        "chio-runtime-admission"
    }

    fn evaluate(
        &self,
        _context: &KernelRuntimeAdmissionContext<'_>,
    ) -> Result<KernelRuntimeAdmissionDecision, KernelError> {
        Err(KernelError::DurableAdmission(
            "runtime hook requires operation-owned claim authority".into(),
        ))
    }

    fn release_reserved(&self, _metadata: &serde_json::Value) -> Result<(), KernelError> {
        Err(KernelError::DurableAdmission(
            "runtime claims require operation-owned release custody".into(),
        ))
    }

    fn revalidate_before_dispatch(
        &self,
        _context: &KernelRuntimeAdmissionRevalidationContext<'_>,
    ) -> Result<(), KernelError> {
        Err(KernelError::DurableAdmission(
            "runtime revalidation requires source qualification".into(),
        ))
    }

    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }

    fn runtime_participant_binding(
        &self,
    ) -> Option<&chio_kernel::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1>{
        Some(&self.operation_owned_binding)
    }

    fn evaluate_operation_owned(
        &self,
        context: &KernelRuntimeAdmissionContext<'_>,
        authority: &chio_kernel::RuntimeParticipantClaimAuthority<'_>,
    ) -> Result<KernelRuntimeAdmissionDecision, KernelError> {
        if &self.operation_owned_binding != authority.binding() {
            return Err(KernelError::DurableAdmission(
                "runtime claim authority does not match the configured source generation".into(),
            ));
        }
        self.store
            .verify_operation_owned_runtime_source(authority.source_qualification())
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        match self.prepare_request(context)? {
            preparation::HookAdmissionPreparation::Immediate(decision) if !decision.allowed => {
                Ok(*decision)
            }
            preparation::HookAdmissionPreparation::Immediate(_) => {
                Ok(KernelRuntimeAdmissionDecision::deny(
                    "operation-owned runtime admission requires a complete prepared plan",
                    Some(runtime_context_denial_metadata(
                        "missing_operation_owned_runtime_plan",
                    )),
                ))
            }
            preparation::HookAdmissionPreparation::Prepared(prepared) => {
                prepared.reserve_operation_owned(authority)
            }
        }
    }

    fn enforces_swarm_authority(&self) -> bool {
        true
    }

    fn revalidate_reserved_operation(
        &self,
        context: &KernelRuntimeAdmissionContext<'_>,
        source: &chio_kernel::admission_operation::RuntimeSourceQualificationV1,
        claim: &chio_kernel::admission_operation::runtime_participant::RuntimeParticipantClaimHistoryV1,
    ) -> Result<KernelRuntimeAdmissionDecision, KernelError> {
        self.store
            .verify_operation_owned_runtime_source(source)
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        match self.prepare_request(context)? {
            preparation::HookAdmissionPreparation::Prepared(prepared) => {
                prepared.resume_operation_owned(claim, context.now_unix_ms)
            }
            preparation::HookAdmissionPreparation::Immediate(decision) if !decision.allowed => {
                Ok(*decision)
            }
            preparation::HookAdmissionPreparation::Immediate(_) => {
                Err(KernelError::DurableAdmission(
                    "reserved runtime revalidation requires its complete original plan".into(),
                ))
            }
        }
    }

    fn revalidate_operation_owned_before_dispatch(
        &self,
        context: &KernelRuntimeAdmissionRevalidationContext<'_>,
        source: &chio_kernel::admission_operation::RuntimeSourceQualificationV1,
    ) -> Result<(), KernelError> {
        let binding = &self.operation_owned_binding;
        if source.runtime_authority_id() != binding.runtime_authority_id().as_str() {
            return Err(KernelError::DurableAdmission(
                "runtime revalidation source authority differs".into(),
            ));
        }
        self.store
            .verify_operation_owned_runtime_source(source)
            .map_err(|error| {
                KernelError::DurableAdmission(format!(
                    "runtime revalidation source verification failed: {error}"
                ))
            })?;
        self.revalidate_admitted_request(context)
    }

    fn revalidate_operation_owned_for_native_capture(
        &self,
        context: &KernelRuntimeAdmissionRevalidationContext<'_>,
        source: &chio_kernel::admission_operation::RuntimeSourceQualificationV1,
        intent: &chio_kernel::admission_operation::runtime_participant::RuntimeParticipantClaimIntentV1,
    ) -> Result<
        chio_kernel::admission_operation::runtime_participant::RuntimeDispatchValidity,
        KernelError,
    > {
        self.revalidate_operation_owned_before_dispatch(context, source)?;
        if context
            .matched_grant_index
            .and_then(|index| u32::try_from(index).ok())
            != Some(intent.grant_index())
        {
            return Err(KernelError::DurableAdmission(
                "native runtime selected another grant".into(),
            ));
        }
        let preparation_context = KernelRuntimeAdmissionContext {
            request: context.request,
            extra_metadata: context
                .admission_metadata
                .and_then(|metadata| metadata.get("chio_runtime"))
                .and_then(|runtime| runtime.get("verified_swarm_route_metadata"))
                .or(context.admission_metadata),
            now_unix_ms: context.now_unix_ms,
            now_unix_secs: context.now_unix_secs,
            matched_grant_index: context.matched_grant_index,
            local_kernel_id: context.local_kernel_id.clone(),
        };
        // Rebuild the original material digest using the same read-only verifier
        // and codec as acquisition. No metadata digest can stand in for this.
        match self.prepare_request(&preparation_context)? {
            preparation::HookAdmissionPreparation::Prepared(prepared) => {
                prepared.verify_owned_dispatch(intent, context.now_unix_ms)
            }
            preparation::HookAdmissionPreparation::Immediate(_) => {
                Err(KernelError::DurableAdmission(
                    "native runtime capture requires its complete verified plan".into(),
                ))
            }
        }
    }
}

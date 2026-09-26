//! Read-only runtime evidence preparation, bound to the originating hook.

use super::*;

pub(super) enum HookAdmissionPreparation<'a, S> {
    Immediate(Box<KernelRuntimeAdmissionDecision>),
    Prepared(Box<PreparedHookAdmission<'a, S>>),
}

/// This plan owns validated inputs, not reservations or dispatch permission.
/// It cannot outlive or be committed through a different configured hook.
pub(super) struct PreparedHookAdmission<'a, S> {
    pub(super) hook: &'a ChioRuntimeAdmissionHook<S>,
    pub(super) admission_id: String,
    pub(super) core: PreparedRuntimeAdmission,
    pub(super) treaty_continuation_id_to_consume: Option<String>,
    pub(super) swarm_continuation_id_to_consume: Option<String>,
    pub(super) verified_swarm_route_metadata: Option<serde_json::Value>,
    pub(super) verified_swarm_request_binding: Option<serde_json::Value>,
    pub(super) federation_treaty_material: Option<chio_kernel::VerifiedFederationTreatyMaterial>,
    pub(super) treaty_artifact_digest: Option<String>,
    pub(super) treaty_evidence_digest: Option<String>,
    pub(super) swarm_artifact_digest: Option<String>,
    pub(super) swarm_evidence_digest: Option<String>,
    pub(super) valid_until_unix_ms: u64,
}

impl<S: RuntimeAdmissionStore + Send + Sync> ChioRuntimeAdmissionHook<S> {
    pub(super) fn prepare_request(
        &self,
        context: &KernelRuntimeAdmissionContext<'_>,
    ) -> Result<HookAdmissionPreparation<'_, S>, KernelError> {
        let stop = |decision| Ok(HookAdmissionPreparation::Immediate(Box::new(decision)));
        let admission_ref = match admission_ref_from_request(context.request) {
            Ok(reference) => reference,
            Err(_) if !request_has_chio_runtime_context(context.request) => {
                if context.request.federated_origin_kernel_id.is_some() {
                    return stop(KernelRuntimeAdmissionDecision::deny(
                        "chio treaty-bound runtime admission context missing",
                        Some(runtime_context_denial_metadata(
                            "missing_chio_treaty_context",
                        )),
                    ));
                }
                return stop(KernelRuntimeAdmissionDecision::allow(None));
            }
            Err(code) => {
                return stop(KernelRuntimeAdmissionDecision::deny(
                    "chio runtime admission reference missing or invalid",
                    Some(runtime_context_denial_metadata(code)),
                ));
            }
        };
        let binding = match RuntimeRequestBinding::from_tool_call_request(
            context.request,
            &context.local_kernel_id,
        ) {
            Ok(binding) => binding,
            Err(error) => {
                return stop(KernelRuntimeAdmissionDecision::deny(
                    "chio runtime admission request binding failed",
                    Some(runtime_denial_metadata(
                        &admission_ref.admission_id,
                        error.code(),
                    )),
                ));
            }
        };
        let bundle = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.store.bundle(&admission_ref.admission_id)
        })) {
            Ok(Ok(Some(bundle))) => {
                if let Some(expected_hash) = admission_ref.bundle_sha256.as_deref() {
                    let actual = runtime_admission_bundle_sha256(&bundle)
                        .map_err(|error| KernelError::Internal(error.to_string()))?;
                    if actual != expected_hash {
                        return stop(KernelRuntimeAdmissionDecision::deny(
                            "chio runtime admission bundle hash mismatch",
                            Some(runtime_denial_metadata(
                                &admission_ref.admission_id,
                                "admission_bundle_hash_mismatch",
                            )),
                        ));
                    }
                }
                bundle
            }
            Ok(Ok(None)) => {
                return stop(KernelRuntimeAdmissionDecision::deny(
                    "chio runtime admission bundle is missing",
                    Some(runtime_denial_metadata(
                        &admission_ref.admission_id,
                        "missing_admission_bundle",
                    )),
                ));
            }
            Ok(Err(error)) => return Err(KernelError::Internal(error.to_string())),
            Err(_) => {
                return stop(KernelRuntimeAdmissionDecision::deny(
                    "chio runtime admission bundle lookup panicked",
                    Some(runtime_denial_metadata(
                        &admission_ref.admission_id,
                        "admission_bundle_store_error",
                    )),
                ));
            }
        };
        if bundle.admission_id != admission_ref.admission_id {
            return stop(KernelRuntimeAdmissionDecision::deny(
                "chio runtime admission bundle identity mismatch",
                Some(runtime_denial_metadata(
                    &admission_ref.admission_id,
                    "admission_bundle_id_mismatch",
                )),
            ));
        }
        let admission_now_unix_ms = self.admission_time(context.now_unix_ms)?;
        let mut treaty_continuation_id_to_consume = None;
        let mut swarm_continuation_id_to_consume = None;
        let mut verified_swarm_route_metadata = None;
        let mut verified_swarm_request_binding = None;
        let mut federation_treaty_material = None;
        let mut runtime_action_class_id = None;
        let mut treaty_artifact_digest = None;
        let mut treaty_evidence_digest = None;
        let mut swarm_artifact_digest = None;
        let mut swarm_evidence_digest = None;
        let mut valid_until_unix_ms = self.profile.expires_at_unix_ms;
        let swarm_reference = match swarm_ref_from_request(context.request) {
            Ok(reference) => reference,
            Err(code) => {
                return stop(KernelRuntimeAdmissionDecision::deny(
                    "chio swarm-bound runtime admission reference invalid",
                    Some(runtime_denial_metadata(&admission_ref.admission_id, code)),
                ));
            }
        };
        if let Some(reference) = swarm_reference.as_ref() {
            match verify_swarm_authority_reference_from_store(
                &self.store,
                reference,
                context.request,
                &self.swarm_witness_keys,
                context.extra_metadata,
                admission_now_unix_ms,
            ) {
                Ok(verified) => {
                    valid_until_unix_ms = valid_until_unix_ms.min(verified.valid_until_unix_ms);
                    swarm_artifact_digest = Some(verified.continuation_artifact_digest);
                    swarm_evidence_digest = Some(verified.evidence_digest);
                    swarm_continuation_id_to_consume = verified.continuation_id_to_consume;
                    verified_swarm_route_metadata = Some(verified.route_metadata);
                    verified_swarm_request_binding = Some(verified.request_binding);
                }
                Err(ChioRuntimeError::Rejected { code, .. }) => {
                    return stop(KernelRuntimeAdmissionDecision::deny(
                        "chio swarm-bound runtime admission denied",
                        Some(runtime_denial_metadata(&admission_ref.admission_id, code)),
                    ));
                }
                Err(error) => return Err(KernelError::Internal(error.to_string())),
            }
        }
        match treaty_ref_from_request(context.request) {
            Ok(Some(treaty_ref)) => {
                runtime_action_class_id = Some(treaty_ref.action_class_id.clone());
                match verify_treaty_reference_from_store(
                    &self.store,
                    &bundle,
                    &treaty_ref,
                    context.request,
                    admission_now_unix_ms,
                ) {
                    Ok(verified) => {
                        valid_until_unix_ms = valid_until_unix_ms.min(verified.valid_until_unix_ms);
                        treaty_artifact_digest = verified.continuation_artifact_digest;
                        treaty_evidence_digest = Some(verified.evidence_digest);
                        treaty_continuation_id_to_consume = verified.continuation_id;
                        federation_treaty_material = verified.federation_treaty_material;
                    }
                    Err(ChioRuntimeError::Rejected { code, .. }) => {
                        return stop(KernelRuntimeAdmissionDecision::deny(
                            "chio treaty-bound runtime admission denied",
                            Some(runtime_denial_metadata(&admission_ref.admission_id, code)),
                        ));
                    }
                    Err(error) => return Err(KernelError::Internal(error.to_string())),
                }
            }
            Ok(None) => {
                if context.request.federated_origin_kernel_id.is_some() {
                    return stop(KernelRuntimeAdmissionDecision::deny(
                        "chio treaty-bound runtime admission context missing",
                        Some(runtime_denial_metadata(
                            &admission_ref.admission_id,
                            "missing_chio_treaty_context",
                        )),
                    ));
                }
            }
            Err(code) => {
                return stop(KernelRuntimeAdmissionDecision::deny(
                    "chio treaty-bound runtime admission reference invalid",
                    Some(runtime_denial_metadata(&admission_ref.admission_id, code)),
                ));
            }
        }
        let core = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prepare_runtime_admission_from_bundle(
                RuntimeAdmissionInput {
                    profile: &self.profile,
                    store: &self.store,
                    admission_id: &admission_ref.admission_id,
                    request: &binding,
                    action_class_id: runtime_action_class_id.as_deref(),
                    runtime_trust_input: self.runtime_trust_input.as_ref(),
                    trusted_verifier_keys: &self.trusted_verifier_keys,
                    pheromone_query_report: self.pheromone_query_report.as_ref(),
                    runtime_pheromone_policy: self.runtime_pheromone_policy.as_ref(),
                    runtime_peer_weights: self.runtime_peer_weights.as_ref(),
                    now_unix_ms: admission_now_unix_ms,
                },
                Some(bundle),
            )
        })) {
            Ok(Ok(RuntimeAdmissionPreparation::Prepared(core))) => core,
            Ok(Ok(RuntimeAdmissionPreparation::Rejected(report))) => {
                return stop(KernelRuntimeAdmissionDecision::deny(
                    "chio runtime admission denied",
                    Some(report.receipt_metadata),
                ));
            }
            Ok(Err(error)) => {
                return stop(KernelRuntimeAdmissionDecision::deny(
                    format!("chio runtime admission preparation failed: {error}"),
                    Some(runtime_denial_metadata(
                        &admission_ref.admission_id,
                        "runtime_admission_evaluation_error",
                    )),
                ));
            }
            Err(_) => {
                return stop(KernelRuntimeAdmissionDecision::deny(
                    "chio runtime admission preparation panicked",
                    Some(runtime_denial_metadata(
                        &admission_ref.admission_id,
                        "runtime_admission_evaluation_error",
                    )),
                ));
            }
        };
        Ok(HookAdmissionPreparation::Prepared(Box::new(
            PreparedHookAdmission {
                hook: self,
                admission_id: admission_ref.admission_id,
                core,
                treaty_continuation_id_to_consume,
                swarm_continuation_id_to_consume,
                verified_swarm_route_metadata,
                verified_swarm_request_binding,
                federation_treaty_material,
                treaty_artifact_digest,
                treaty_evidence_digest,
                swarm_artifact_digest,
                swarm_evidence_digest,
                valid_until_unix_ms,
            },
        )))
    }
}

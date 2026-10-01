//! One atomic replay claim for the exact prepared runtime plan. Every legacy
//! consume/release callback is excluded from this path.

use super::preparation::PreparedHookAdmission;
use super::*;
use chio_kernel::admission_operation::runtime_participant::{
    RuntimeDispatchValidity, RuntimeParticipantAuthorityBindingV1, RuntimeParticipantClaimIntentV1,
    RuntimeParticipantPhase, RuntimeParticipantResourceV1,
};
use chio_kernel::admission_operation::{
    AdmissionDigest, AdmissionIdentifier, RuntimeReplayParticipantKind,
};
use chio_kernel::RuntimeParticipantClaimAuthority;

impl<S: RuntimeAdmissionStore + Send + Sync> PreparedHookAdmission<'_, S> {
    pub(super) fn reserve_operation_owned(
        self,
        authority: &RuntimeParticipantClaimAuthority<'_>,
    ) -> Result<KernelRuntimeAdmissionDecision, KernelError> {
        let resources = self.operation_owned_resources()?;
        let plan_digest = self.operation_owned_plan_digest(
            authority.binding(),
            authority.request_binding_hash(),
            authority.grant_index(),
            authority.phase(),
        )?;
        let resources_digest = crate::hash::canonical_sha256(&resources).map_err(runtime_error)?;
        let reference = authority.claim(
            AdmissionDigest::try_new("runtime_plan_digest", &plan_digest)?,
            resources,
        )?;
        let bundle_digest = self.core.bundle_digest.clone();
        self.hook
            .store
            .verify_operation_owned_replay_source(authority.source_snapshot())
            .map_err(runtime_error)?;
        let report = self
            .core
            .commit_operation_owned(&self.hook.store)
            .map_err(runtime_error)?;
        if !report.accepted {
            return Ok(KernelRuntimeAdmissionDecision::deny(
                "chio operation-owned runtime admission denied",
                Some(report.receipt_metadata),
            ));
        }
        let mut metadata = report.receipt_metadata;
        metadata["chio_runtime"]["operation_owned_replay"] = serde_json::json!({
            "reference": reference,
            "plan_sha256": plan_digest,
            "bundle_sha256": bundle_digest,
            "resources_sha256": resources_digest,
            "treaty_evidence_sha256": self.treaty_evidence_digest,
            "swarm_evidence_sha256": self.swarm_evidence_digest,
        });
        if let Some(route) = self.verified_swarm_route_metadata {
            metadata["chio_runtime"]["verified_swarm_route_metadata"] = route;
        }
        if let Some(binding) = self.verified_swarm_request_binding {
            metadata["chio_runtime"]["verified_swarm_request_binding"] = binding;
        }
        Ok(match self.federation_treaty_material {
            Some(material) => KernelRuntimeAdmissionDecision::allow_with_verified_treaty_material(
                Some(metadata),
                material,
            ),
            None => KernelRuntimeAdmissionDecision::allow(Some(metadata)),
        })
    }

    /// Recomputed from the exact verified artifacts, not a plan digest copied
    /// out of receipt metadata. This read-only path cannot reserve or release.
    pub(super) fn verify_owned_dispatch(
        &self,
        intent: &RuntimeParticipantClaimIntentV1,
        now_unix_ms: u64,
    ) -> Result<RuntimeDispatchValidity, KernelError> {
        let binding = self.hook.operation_owned_binding.as_ref().ok_or_else(|| {
            KernelError::DurableAdmission("native runtime source is not configured".into())
        })?;
        if intent.runtime_authority_id() != binding.runtime_authority_id()
            || intent.expectation_id() != binding.expectation_id()
            || intent.phase() != RuntimeParticipantPhase::Dispatch
            || intent.plan_digest().as_str()
                != self.operation_owned_plan_digest(
                    binding,
                    intent.request_binding_hash(),
                    intent.grant_index(),
                    intent.phase(),
                )?
            || intent.resources() != self.operation_owned_resources()?
        {
            return Err(KernelError::DurableAdmission(
                "native runtime artifacts differ from the physically owned plan".into(),
            ));
        }
        self.hook
            .native_dispatch_validity(now_unix_ms, self.valid_until_unix_ms)
    }

    pub(super) fn resume_operation_owned(
        self,
        claim: &chio_kernel::admission_operation::runtime_participant::RuntimeParticipantClaimHistoryV1,
        now: u64,
    ) -> Result<KernelRuntimeAdmissionDecision, KernelError> {
        self.verify_owned_dispatch(&claim.intent, now)?;
        let resources_digest = crate::hash::canonical_sha256(&self.operation_owned_resources()?)
            .map_err(runtime_error)?;
        let bundle_digest = self.core.bundle_digest.clone();
        let report = self
            .core
            .resume_operation_owned(&self.hook.store)
            .map_err(runtime_error)?;
        let mut metadata = report.receipt_metadata;
        metadata["chio_runtime"]["operation_owned_replay"] = serde_json::json!({
            "reference": claim.reference,
            "plan_sha256": claim.intent.plan_digest().as_str(),
            "bundle_sha256": bundle_digest,
            "resources_sha256": resources_digest,
            "treaty_evidence_sha256": self.treaty_evidence_digest,
            "swarm_evidence_sha256": self.swarm_evidence_digest,
        });
        if let Some(route) = self.verified_swarm_route_metadata {
            metadata["chio_runtime"]["verified_swarm_route_metadata"] = route;
        }
        if let Some(binding) = self.verified_swarm_request_binding {
            metadata["chio_runtime"]["verified_swarm_request_binding"] = binding;
        }
        Ok(match self.federation_treaty_material {
            Some(material) => KernelRuntimeAdmissionDecision::allow_with_verified_treaty_material(
                Some(metadata),
                material,
            ),
            None => KernelRuntimeAdmissionDecision::allow(Some(metadata)),
        })
    }

    fn operation_owned_resources(&self) -> Result<Vec<RuntimeParticipantResourceV1>, KernelError> {
        let mut resources = Vec::new();
        if let Some((id, digest)) = self.core.destructive_resource() {
            resources.push(resource(
                RuntimeReplayParticipantKind::DestructiveLease,
                id,
                digest,
            )?);
        }
        for (kind, id, digest) in [
            (
                RuntimeReplayParticipantKind::TreatyContinuation,
                self.treaty_continuation_id_to_consume.as_deref(),
                self.treaty_artifact_digest.as_deref(),
            ),
            (
                RuntimeReplayParticipantKind::SwarmContinuation,
                self.swarm_continuation_id_to_consume.as_deref(),
                self.swarm_artifact_digest.as_deref(),
            ),
        ] {
            if let Some(id) = id {
                let digest = digest.ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "prepared runtime continuation omitted its verified artifact digest".into(),
                    )
                })?;
                resources.push(resource(kind, id, digest)?);
            }
        }
        Ok(resources)
    }

    fn operation_owned_plan_digest(
        &self,
        binding: &RuntimeParticipantAuthorityBindingV1,
        request_binding_hash: &AdmissionDigest,
        grant_index: u32,
        phase: RuntimeParticipantPhase,
    ) -> Result<String, KernelError> {
        crate::hash::canonical_sha256(&(
            "chio.runtime-operation-owned-plan.v1",
            &self.core.material_digest,
            &self.treaty_evidence_digest,
            &self.swarm_evidence_digest,
            &self.verified_swarm_route_metadata,
            &self.verified_swarm_request_binding,
            &self.hook.swarm_witness_keys,
            binding.runtime_authority_id(),
            binding.expectation_id(),
            request_binding_hash,
            grant_index,
            phase,
        ))
        .map_err(runtime_error)
    }
}

fn resource(
    kind: RuntimeReplayParticipantKind,
    id: &str,
    digest: &str,
) -> Result<RuntimeParticipantResourceV1, KernelError> {
    Ok(RuntimeParticipantResourceV1::new(
        kind,
        AdmissionIdentifier::try_new("runtime_resource_id", id)?,
        AdmissionDigest::try_new("runtime_artifact_digest", digest)?,
    ))
}

fn runtime_error(error: ChioRuntimeError) -> KernelError {
    KernelError::DurableAdmission(error.to_string())
}

pub(super) fn verify_revalidation_material(
    runtime: &serde_json::Map<String, serde_json::Value>,
    bundle: &RuntimeAdmissionBundle,
    treaty: Option<&super::treaty_evidence::VerifiedTreatyReference>,
    swarm: Option<&super::swarm_authority::VerifiedSwarmAuthorityReference>,
) -> Result<(), KernelError> {
    let owned = runtime
        .get("operation_owned_replay")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            KernelError::DurableAdmission("operation-owned runtime evidence is absent".into())
        })?;
    let bundle_digest =
        crate::hash::runtime_admission_bundle_sha256(bundle).map_err(runtime_error)?;
    let mut resources = Vec::new();
    if bundle.destructive {
        let id = bundle.lease_id.as_deref().ok_or_else(|| {
            KernelError::DurableAdmission("destructive runtime bundle lost its lease".into())
        })?;
        resources.push(resource(
            RuntimeReplayParticipantKind::DestructiveLease,
            id,
            &bundle_digest,
        )?);
    }
    if let Some(treaty) = treaty {
        if let Some(id) = &treaty.continuation_id {
            let digest = treaty
                .continuation_artifact_digest
                .as_deref()
                .ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "runtime treaty continuation lost its artifact digest".into(),
                    )
                })?;
            resources.push(resource(
                RuntimeReplayParticipantKind::TreatyContinuation,
                id,
                digest,
            )?);
        }
    }
    if let Some(swarm) = swarm {
        if let Some(id) = &swarm.continuation_id_to_consume {
            resources.push(resource(
                RuntimeReplayParticipantKind::SwarmContinuation,
                id,
                &swarm.continuation_artifact_digest,
            )?);
        }
    }
    let resources_digest = crate::hash::canonical_sha256(&resources).map_err(runtime_error)?;
    for (field, expected) in [
        ("bundle_sha256", serde_json::json!(bundle_digest)),
        ("resources_sha256", serde_json::json!(resources_digest)),
        (
            "treaty_evidence_sha256",
            serde_json::json!(treaty.map(|value| &value.evidence_digest)),
        ),
        (
            "swarm_evidence_sha256",
            serde_json::json!(swarm.map(|value| &value.evidence_digest)),
        ),
    ] {
        if owned.get(field) != Some(&expected) {
            return Err(KernelError::DurableAdmission(format!(
                "operation-owned runtime {field} changed before dispatch",
            )));
        }
    }
    if [
        "reserved_destructive_lease_id",
        "reserved_treaty_continuation_id",
        "reserved_swarm_continuation_id",
    ]
    .iter()
    .any(|field| runtime.contains_key(*field))
    {
        return Err(KernelError::DurableAdmission(
            "operation-owned runtime evidence contains legacy reservations".into(),
        ));
    }
    Ok(())
}

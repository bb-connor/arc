//! Explicit profile fixtures prepared before begin, never a history backfill.

use super::*;
use chio_kernel::admission_operation::governed_approval_claim::GovernedApprovalAuthorityBindingV1;
use chio_kernel::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1;
use chio_kernel::admission_operation::{
    AdmissionAuthorityProfileV1, AdmissionAuthoritySelectionV1,
};
use chio_kernel::dpop::authority::DpopReplayAuthorityV1;

pub(crate) fn selection(
    runtime: Option<RuntimeParticipantAuthorityBindingV1>,
    approval: Option<GovernedApprovalAuthorityBindingV1>,
    dpop: Option<DpopReplayAuthorityV1>,
) -> TestResult<AdmissionAuthorityProfileV1> {
    Ok(AdmissionAuthorityProfileV1::new(
        AdmissionAuthoritySelectionV1 {
            runtime_hook_installed: runtime.is_some(),
            runtime_requires_dispatch_revalidation: runtime.is_some(),
            runtime_enforces_swarm_authority: false,
            swarm_admission_required: false,
            runtime,
            approval,
            dpop,
        },
    )?)
}

pub(crate) fn prepare_with_profile(
    operation: AdmissionOperationV1,
    original: RetainedToolAdmissionRequestV1,
    profile: AdmissionAuthorityProfileV1,
) -> TestResult<(AdmissionOperationV1, RetainedToolAdmissionRequestV1)> {
    assert_eq!(operation.state(), AdmissionOperationState::Prepared);
    assert_eq!(operation.version(), 1);
    assert!(original.authority_profile().is_none());
    original.validate_binding(operation.binding())?;
    let immutable = sha256_hex(&canonical_json_bytes(&serde_json::json!({
        "schema": "chio.tool-admission-request.v4",
        "prior_request_hash": operation.binding().immutable_request_hash(),
        "authority_profile": profile,
    }))?);
    let mut wire: serde_json::Value = serde_json::from_slice(original.canonical_bytes())?;
    wire["schema"] = "chio.retained-tool-admission-request.v4".into();
    wire["authority_profile"] = serde_json::to_value(profile)?;
    let retained =
        RetainedToolAdmissionRequestV1::from_canonical_bytes(&canonical_json_bytes(&wire)?)?;
    let old = operation.to_persisted().binding;
    assert_eq!(
        old.authenticated_tenant_id.as_str(),
        chio_kernel::admission_operation::LOCAL_SYSTEM_TENANT_ID
    );
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: old.kind,
        namespace: AuthenticatedRequestNamespace::for_local_system(old.coordinator_authority_id)?,
        request_id: old.request_id,
        capability_id: old.capability_id,
        authorization_capability_hash: old.authorization_capability_hash,
        request_binding: AdmissionRequestBindingV1::new_with_action_parameter_hash(
            AdmissionDigest::try_new("immutable", immutable)?,
            operation.binding().action_parameter_hash().clone(),
            operation.binding().participant_requirements(),
        )?,
        policy_hash: old.policy_hash,
        effect_class: old.effect_class,
    })?;
    let prepared = AdmissionOperationV1::prepare(binding, operation.coordinator_lease_epoch())?;
    retained.validate_binding(prepared.binding())?;
    Ok((prepared, retained))
}

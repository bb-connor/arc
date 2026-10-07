use super::*;
use chio_core_types::recovery::RecoveryGrantBodyV2;
use chio_security_types::flow::InformationLabel;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn hash<T: serde::Serialize>(
    domain: chio_core_types::recovery::RecoveryDigestDomain,
    value: &T,
) -> Result<[u8; 32], AdmissionOperationStoreError> {
    chio_kernel::recovery::recovery_digest(domain, value)
        .map_err(|_| invariant("recovery digest refused"))
}
pub(super) fn hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 15)] as char);
    }
    encoded
}
pub(super) fn validate_deployment(
    profile: &RecoveryDeploymentV1,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    let context = profile.security_context.as_v1();
    if profile.scope.authority_domain.as_str() != fence.store_uuid
        || profile.native_authority.store_uuid().as_str() != fence.store_uuid
        || profile.scope.tenant_id.as_str() != context.tenant_id().as_str()
        || profile.recipient.as_str() != profile.server_id.as_str()
        || profile.effect_cardinality.get() != 1
        || profile.aggregate_issuer.algorithm() != chio_core_types::SigningAlgorithm::Ed25519
        || !(1..=65536).contains(&profile.effect_contract.max_response_bytes.get())
        || !profile
            .effect_contract
            .resource
            .as_str()
            .starts_with("https://")
        || profile.contract_digest
            != ContractDigest::from_bytes(hash(
                chio_core_types::recovery::RecoveryDigestDomain::EffectContract,
                &profile.effect_contract,
            )?)
        || profile.authority_scope
            != recovery_authority_scope_digest(profile)
                .map_err(|_| invariant("recovery scope digest refused"))?
    {
        return Err(invariant("recovery deployment refused"));
    }
    let mut subjects = BTreeSet::new();
    let mut principals = BTreeSet::new();
    for actor in profile.actors.as_slice() {
        if !subjects.insert(actor.subject.to_hex())
            || !principals.insert(actor.principal.clone())
            || actor.permissions.as_slice().is_empty()
            || actor
                .permissions
                .as_slice()
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(invariant("recovery actor assignment refused"));
        }
    }
    let mut issuers = BTreeSet::new();
    let mut represented = BTreeSet::new();
    for coverage in profile.coverage.as_slice() {
        if !issuers.insert(coverage.issuer_id.clone())
            || !represented.insert(coverage.principal.clone())
            || coverage.obligations.as_slice().iter().any(|power| {
                !matches!(
                    power,
                    AuthorityObligationV1::OwnerRelease { .. }
                        | AuthorityObligationV1::CompartmentRelease { .. }
                )
            })
        {
            return Err(invariant("recovery coverage assignment refused"));
        }
    }
    Ok(())
}

/// Fresh operator installation refuses an unbounded preview clearance.
/// Authenticated historical profiles retain their original structural codec.
pub(super) fn validate_deployment_installation(
    profile: &RecoveryDeploymentV1,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    validate_deployment(profile, fence)?;
    if profile
        .actors
        .as_slice()
        .iter()
        .any(|actor| matches!(actor.preview_clearance, InformationLabel::Top))
    {
        return Err(invariant("recovery preview clearance refused"));
    }
    Ok(())
}
pub(in crate::admission_operation_store) fn verify_actor(
    tx: &Connection,
    actor: &AuthenticatedRecoveryActor,
    profile: &RecoveryDeploymentV1,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    if actor.scope() != &profile.scope
        || now / 1000 >= actor.capability().expires_at
        || now / 1000 < actor.capability().issued_at
    {
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    }
    let assignment = profile.actors.as_slice().iter().find(|assignment| {
        assignment.subject == actor.capability().subject
            && assignment.principal == *actor.principal()
            && assignment
                .permissions
                .as_slice()
                .contains(&actor.permission())
    });
    if assignment.is_none() {
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    }
    for id in std::iter::once(actor.capability().id.as_str()).chain(
        actor
            .capability()
            .delegation_chain
            .iter()
            .map(|link| link.capability_id.as_str()),
    ) {
        let revoked: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id=?1)",
                [id],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if revoked {
            return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
        }
    }
    Ok(())
}
pub(in crate::admission_operation_store) fn verify_status(
    actor: &AuthenticatedRecoveryActor,
    profile: &RecoveryDeploymentV1,
    record: &RecoveryWorkflowRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    if actor.scope() != &record.scope || record.scope != profile.scope {
        return Err(invariant("recovery audience refused"));
    }
    Ok(())
}
pub(super) fn verify_preview(
    actor: &AuthenticatedRecoveryActor,
    profile: &RecoveryDeploymentV1,
    record: &RecoveryWorkflowRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    verify_status(actor, profile, record)?;
    let clearance = profile
        .actors
        .as_slice()
        .iter()
        .find(|assignment| assignment.principal == *actor.principal())
        .ok_or(AdmissionOperationStoreError::RecoveryAuthorityDenied)?;
    if matches!(clearance.preview_clearance, InformationLabel::Top) {
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    }
    if record.action.is_none() && record.created_by == *actor.principal() {
        return Ok(());
    }
    let source = record
        .action
        .as_ref()
        .map(|action| action.authorization_requirements.source_label.clone())
        .unwrap_or(InformationLabel::Top);
    if matches!(source, InformationLabel::Top) || !source.flows_to(&clearance.preview_clearance) {
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    }
    Ok(())
}
pub(super) fn validate_seed(
    seed: &ToolCallRequest,
    profile: &RecoveryDeploymentV1,
) -> Result<(), AdmissionOperationStoreError> {
    let _: RecoverySupportIssueInputV1 = serde_json::from_value(seed.arguments.clone())
        .map_err(|_| invariant("recovery issue input refused"))?;
    if seed.server_id != profile.server_id.as_str()
        || seed.tool_name != profile.tool_name.as_str()
        || seed.agent_id != seed.capability.subject.to_hex()
        || seed.declassification_grant.is_some()
        || seed.execution_nonce.is_some()
        || seed.governed_intent.is_some()
        || seed.dpop_proof.is_some()
        || seed.approval_token.is_some()
        || !seed.approval_tokens.is_empty()
        || seed.threshold_approval_proposal.is_some()
        || seed.supplemental_authorization.is_some()
        || seed.federated_origin_kernel_id.is_some()
    {
        return Err(invariant("recovery request profile refused"));
    }
    Ok(())
}
pub(super) fn require_active(
    record: &RecoveryWorkflowRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    if record.control != WorkflowControlV1::Active
        || record.admission_closed
        || record.effect.is_settled()
    {
        return Err(invariant("recovery work is closed"));
    }
    Ok(())
}
pub(super) fn coverage(
    record: &RecoveryWorkflowRecordV1,
    submission: &RecoveryRetainedApprovalV1,
    profile: &RecoveryDeploymentV1,
    now: u64,
) -> Result<chio_flow::VerifiedRecoveryCoverage, AdmissionOperationStoreError> {
    let action = record
        .action
        .as_ref()
        .ok_or_else(|| invariant("recovery action is absent"))?;
    chio_flow::verify_recovery_coverage(
        &submission.intent,
        &action.authorization_requirements,
        action.basis,
        &submission.coverage,
        &coverage_assignments(profile),
        now,
    )
    .map_err(|_| invariant("recovery coverage refused"))
}

fn coverage_assignments(
    profile: &RecoveryDeploymentV1,
) -> BTreeMap<IssuerId, chio_flow::RecoveryAuthorityAssignment> {
    profile
        .coverage
        .as_slice()
        .iter()
        .map(|assignment| {
            (
                assignment.issuer_id.clone(),
                chio_flow::RecoveryAuthorityAssignment {
                    principal: assignment.principal.clone(),
                    key: assignment.key.clone(),
                    obligations: assignment.obligations.as_slice().iter().cloned().collect(),
                },
            )
        })
        .collect()
}

fn historical_coverage_digest(
    record: &RecoveryWorkflowRecordV1,
    submission: &RecoveryRetainedApprovalV1,
    profile: &RecoveryDeploymentV1,
    prepared_at: u64,
) -> Result<CoverageDigest, AdmissionOperationStoreError> {
    let action = record
        .action
        .as_ref()
        .ok_or_else(|| invariant("recovery action is absent"))?;
    chio_flow::verify_historical_recovery_coverage_digest(
        &submission.intent,
        &action.authorization_requirements,
        action.basis,
        &submission.coverage,
        &coverage_assignments(profile),
        prepared_at,
    )
    .map_err(|_| invariant("recovery coverage refused"))
}
pub(super) fn validate_review(
    record: &RecoveryWorkflowRecordV1,
    intent: &ApprovalIntentV1,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let action = record
        .action
        .as_ref()
        .ok_or_else(|| invariant("recovery action is absent"))?;
    let action_digest = IntentDigest::from_bytes(hash(
        chio_core_types::recovery::RecoveryDigestDomain::ActionIntent,
        action,
    )?);
    let requirements = AuthorizationRequirementsDigest::from_bytes(hash(
        chio_core_types::recovery::RecoveryDigestDomain::AuthorizationRequirements,
        &action.authorization_requirements,
    )?);
    if intent.action_intent != action_digest
        || intent.authorization_requirements != requirements
        || intent.preview
            != recovery_review_digest(action, &record.seed)
                .map_err(|_| invariant("recovery exact preview refused"))?
        || intent.offer
            != OfferDigest::from_bytes(hash(
                chio_core_types::recovery::RecoveryDigestDomain::Offer,
                &(action_digest, action.basis, &action.scope),
            )?)
        || intent.plan
            != PlanDigest::from_bytes(hash(
                chio_core_types::recovery::RecoveryDigestDomain::Plan,
                &(action_digest, requirements),
            )?)
        || intent.approval_intent.as_str() != format!("approval:{}", hex(action_digest.as_bytes()))
        || intent.challenge.as_str() != format!("challenge:{}", hex(action_digest.as_bytes()))
        || intent.issued_at_unix_ms.get() > now
        || intent.expires_at_unix_ms.get() <= now
        || intent
            .expires_at_unix_ms
            .get()
            .saturating_sub(intent.issued_at_unix_ms.get())
            > MAX_RECOVERY_REVIEW_MS
        || intent.expires_at_unix_ms > action.authorization_requirements.validity_ceiling_unix_ms
    {
        return Err(invariant("recovery exact review refused"));
    }
    Ok(())
}
pub(super) fn validate_approval(
    record: &RecoveryWorkflowRecordV1,
    submission: &RecoveryRetainedApprovalV1,
    profile: &RecoveryDeploymentV1,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    if record.review.as_ref() != Some(&submission.intent) {
        return Err(invariant("recovery reviewed intent changed"));
    }
    validate_review(record, &submission.intent, now)?;
    coverage(record, submission, profile, now)?;
    Ok(())
}
pub(super) fn fresh_basis(
    tx: &Transaction<'_>,
    profile: &RecoveryDeploymentV1,
    record: &RecoveryWorkflowRecordV1,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    super::origins::verify(tx, record, profile, now)?;
    let action = record
        .action
        .as_ref()
        .ok_or_else(|| invariant("recovery action is absent"))?;
    if record.deployment_digest
        != DeploymentDigest::from_bytes(hash(
            chio_core_types::recovery::RecoveryDigestDomain::Deployment,
            profile,
        )?)
        || action.policy_digest != profile.policy_digest
        || action.contract_digest != profile.contract_digest
        || action.authority_scope != profile.authority_scope
        || action.authorization_requirements.attachment_profile != profile.attachment_profile
        || now
            >= action
                .authorization_requirements
                .validity_ceiling_unix_ms
                .get()
    {
        return Err(invariant("recovery basis is stale"));
    }
    let original = record
        .original_flow
        .as_ref()
        .ok_or_else(|| invariant("recovery basis is absent"))?;
    let (current, _) = crate::security_state::observe_native_flow_state(
        tx,
        profile.native_authority.security_authority_id().as_str(),
        &original.key,
    )
    .map_err(|error| invariant(error.to_string()))?;
    let current = current.ok_or_else(|| invariant("recovery source is absent"))?;
    if current != *original
        && !super::native::proves_same_call_basis(tx, record, profile, original, &current)?
    {
        return Err(invariant("recovery source generation is stale"));
    }
    Ok(())
}
pub(super) fn validate_body(
    record: &RecoveryWorkflowRecordV1,
    body: &RecoveryGrantBodyV2,
    profile: &RecoveryDeploymentV1,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    validate_body_profile(record, body, profile, now, BodyValidation::Fresh)
}

/// Call only after the original physical capture, native binding and retained
/// deployment were authenticated. This verifies immutable custody, not new work.
pub(super) fn validate_historical_body(
    record: &RecoveryWorkflowRecordV1,
    body: &RecoveryGrantBodyV2,
    profile: &RecoveryDeploymentV1,
    prepared_at: u64,
) -> Result<(), AdmissionOperationStoreError> {
    if !record.captured || record.native_link.is_none() {
        return Err(invariant("recovery historical capture is absent"));
    }
    validate_body_profile(
        record,
        body,
        profile,
        prepared_at,
        BodyValidation::RetainedCapture,
    )
}

enum BodyValidation {
    Fresh,
    RetainedCapture,
}

fn validate_body_profile(
    record: &RecoveryWorkflowRecordV1,
    body: &RecoveryGrantBodyV2,
    profile: &RecoveryDeploymentV1,
    now: u64,
    validation: BodyValidation,
) -> Result<(), AdmissionOperationStoreError> {
    body.validate()
        .map_err(|_| invariant("recovery grant refused"))?;
    let action = record
        .action
        .as_ref()
        .ok_or_else(|| invariant("recovery action is absent"))?;
    let approval = record
        .approval
        .as_ref()
        .ok_or_else(|| invariant("recovery approval is absent"))?;
    if record.review.as_ref() != Some(&approval.intent) {
        return Err(invariant("recovery review changed"));
    }
    validate_review(record, &approval.intent, now)?;
    let coverage_digest = match validation {
        BodyValidation::Fresh => coverage(record, approval, profile, now)?.digest(),
        BodyValidation::RetainedCapture => {
            historical_coverage_digest(record, approval, profile, now)?
        }
    };
    let binding = &body.recovery;
    let intent = &approval.intent;
    if binding.authority_domain != record.scope.authority_domain
        || binding.process_id != record.scope.process_id
        || binding.workflow_id != record.workflow_id
        || binding.step_id != record.step_id
        || binding.continuation_id != record.continuation_id
        || binding.request_id != action.request_id
        || binding.request_namespace != action.request_namespace
        || binding.action_intent != intent.action_intent
        || binding.authorization_requirements != intent.authorization_requirements
        || binding.selected_offer != intent.offer
        || binding.approved_plan != intent.plan
        || binding.approval_intent != intent.approval_intent
        || binding.challenge != intent.challenge
        || binding.coverage_digest != coverage_digest
        || binding.policy_digest != action.policy_digest
        || binding.contract_digest != action.contract_digest
        || binding.authority_scope != action.authority_scope
        || binding.isolation_lineage != action.isolation_lineage
        || binding.isolation_epoch != action.isolation_epoch
        || binding.output_disposition != action.output_disposition
    {
        return Err(invariant("recovery grant binding refused"));
    }
    let claims = &body.claims;
    let context = profile.security_context.as_v1();
    if claims.capability_id().as_str() != record.seed.capability.id
        || claims.agent_id().as_str() != record.seed.agent_id
        || claims.tenant_id() != context.tenant_id()
        || claims.subject_id() != context.principal_id()
        || claims.session_id() != context.session_id()
        || claims.source_label_hash()
            != chio_flow::information_label_hash(&action.authorization_requirements.source_label)
                .map_err(|_| invariant("recovery source refused"))?
        || claims.target_label() != &profile.target_label
        || claims.destination_id() != &profile.recipient
        || claims.purpose() != &profile.purpose
        || claims.tool_name().as_str() != profile.tool_name.as_str()
        || claims.request_hash().as_bytes()
            != chio_core_types::sha256(&encode(&record.seed.arguments)?).as_bytes()
        || claims.authority_key_id() != &profile.aggregate_issuer_id
        || claims.issued_at_unix_seconds() > now / 1000
        || claims.expires_at_unix_seconds() <= now / 1000
        || claims.expires_at_unix_seconds() * 1000 > approval.intent.expires_at_unix_ms.get()
    {
        return Err(invariant("recovery grant claims refused"));
    }
    Ok(())
}

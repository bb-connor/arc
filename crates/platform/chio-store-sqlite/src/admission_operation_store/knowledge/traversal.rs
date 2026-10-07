use super::*;
use std::collections::BTreeSet;

/// Resolve every required path before computing restrictions. Overflow is refusal.
pub(super) fn dependencies(
    tx: &Transaction<'_>,
    scope: &RecoveryScopeV1,
    roots: &[ArtifactVersionRefV1],
) -> Result<Vec<NativeArtifactRecordV1>, AdmissionOperationStoreError> {
    let mut result = Vec::new();
    let mut visited = BTreeSet::new();
    let mut pending = roots.to_vec();
    while let Some(reference) = pending.pop() {
        if reference.scope != *scope {
            return Err(refused("dependency tenant"));
        }
        let identity = version_key(&reference)?;
        if !visited.insert(identity) {
            continue;
        }
        if visited.len() > MAX_ARTIFACT_TRAVERSAL {
            return Err(refused("dependency overflow"));
        }
        let record = artifact(tx, &reference)?;
        pending.extend_from_slice(record.metadata.dependencies.as_slice());
        if pending.len() > MAX_ARTIFACT_TRAVERSAL * MAX_ARTIFACT_DEPENDENCIES {
            return Err(refused("dependency work overflow"));
        }
        result.push(record);
    }
    Ok(result)
}
pub(super) fn join_metadata(
    label: InformationLabel,
    records: &[NativeArtifactRecordV1],
) -> Result<InformationLabel, AdmissionOperationStoreError> {
    records.iter().try_fold(label, |label, record| {
        label
            .join_restrictions(&record.metadata.label)
            .map_err(refused)
    })
}
pub(super) fn influence(
    tx: &Transaction<'_>,
    binding: &NativeSecurityAuthorityBindingV1,
    context: &SecurityInvocationContext,
    records: &[NativeArtifactRecordV1],
    unknown: bool,
) -> Result<ArtifactInfluenceV1, AdmissionOperationStoreError> {
    let observed = super::super::security_participant_state::knowledge::observed_influence(
        tx,
        binding.security_authority_id().as_str(),
        &recovery_flow_key(context),
    )?;
    let inherited = records
        .iter()
        .map(|record| &record.metadata.influence)
        .collect::<Vec<_>>();
    Ok(ArtifactInfluenceV1 {
        commitment: CanonicalPayloadDigest::from_bytes(
            knowledge_digest(
                RecoveryDigestDomain::KnowledgeInfluence,
                &(context, inherited, &observed, unknown),
            )
            .map_err(refused)?,
        ),
        externally_influenced: true,
        unknown: unknown
            || observed.is_some_and(|influence| influence.unknown)
            || records
                .iter()
                .any(|record| record.metadata.influence.unknown),
    })
}
pub(super) fn ensure_audience(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    label: &InformationLabel,
) -> Result<(), AdmissionOperationStoreError> {
    let deployment = protected::deployment_tx(tx, actor.scope())?;
    let assignment = deployment
        .actors
        .as_slice()
        .iter()
        .find(|assignment| assignment.principal == *actor.principal())
        .ok_or_else(|| refused("audience"))?;
    if *label == InformationLabel::Top
        || assignment.preview_clearance == InformationLabel::Top
        || !label.flows_to(&assignment.preview_clearance)
    {
        return Err(refused("audience"));
    }
    Ok(())
}

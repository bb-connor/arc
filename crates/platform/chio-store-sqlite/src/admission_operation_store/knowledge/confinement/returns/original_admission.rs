//! Owed fates bind the authenticated first RETURN, independent of fresh control.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store::knowledge::confinement) struct OriginalReturnOrigin {
    principal: chio_security_types::PrincipalId,
    capability: ConfinedCapabilityDigest,
    authority_scope: AuthorityScopeDigest,
    deployment: DeploymentDigest,
    deployment_version: SafeInteger,
    deployment_commit: SafeInteger,
    admission_version: SafeInteger,
    admission_commit: SafeInteger,
}

fn deployment_digest(
    profile: &RecoveryDeploymentV1,
) -> Result<DeploymentDigest, AdmissionOperationStoreError> {
    chio_kernel::recovery::recovery_digest(RecoveryDigestDomain::Deployment, profile)
        .map(DeploymentDigest::from_bytes)
        .map_err(refused)
}

fn original_assignment(profile: &RecoveryDeploymentV1, actor: &AuthenticatedRecoveryActor) -> bool {
    profile.actors.as_slice().iter().any(|assignment| {
        assignment.principal == *actor.principal()
            && assignment.subject == actor.capability().subject
            && assignment
                .permissions
                .as_slice()
                .contains(&RecoveryPermission::ConfinedReturn)
    })
}

/// Called only after the actual fresh native join, inside the original writer.
/// The immediately following retain is checked against its committed source.
pub(super) fn capture(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    record: &BoundaryRecord,
) -> Result<OriginalReturnOrigin, AdmissionOperationStoreError> {
    if actor.permission() != RecoveryPermission::ConfinedReturn
        || record.return_origin.is_some()
        || record.return_authority != Some(capability_digest(actor.capability())?)
        || record.return_admission.is_none()
        || record.reservation.state != IsolationStateV1::ReturnAdmitted
        || record.stop_requested
    {
        return Err(refused("original RETURN capture"));
    }
    let scope = scope_key(actor.scope())?;
    let profile = protected::deployment_tx(tx, actor.scope())?;
    let deployment_key = format!("deployment:{scope}");
    let deployment_source = protected::source_reference(tx, &deployment_key)?;
    if profile.scope != *actor.scope()
        || !original_assignment(&profile, actor)
        || deployment_source.scope_key() != scope
        || deployment_source.kind() != "deployment"
        || !protected::matches_historical_deployment(
            tx,
            &deployment_key,
            &scope,
            deployment_source.version(),
            &profile,
        )?
    {
        return Err(refused("original RETURN deployment"));
    }
    let source = protected::source_reference(
        tx,
        &key(actor.scope(), &record.reservation.boundary.request)?,
    )?;
    let admission_version = source
        .version()
        .checked_add(1)
        .ok_or_else(|| refused("original RETURN version"))?;
    let head: i64 = tx
        .query_row(
            "SELECT head_sequence FROM authority_global_commit_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let admission_commit = u64::try_from(head)
        .map_err(refused)?
        .checked_add(1)
        .ok_or_else(|| refused("original RETURN commit"))?;
    Ok(OriginalReturnOrigin {
        principal: actor.principal().clone(),
        capability: capability_digest(actor.capability())?,
        authority_scope: profile.authority_scope,
        deployment: deployment_digest(&profile)?,
        deployment_version: SafeInteger::new(deployment_source.version()).map_err(refused)?,
        deployment_commit: SafeInteger::new(deployment_source.global_commit_sequence())
            .map_err(refused)?,
        admission_version: SafeInteger::new(admission_version).map_err(refused)?,
        admission_commit: SafeInteger::new(admission_commit).map_err(refused)?,
    })
}

/// Authenticate the complete historical ReturnAdmitted envelope. A later Stop
/// or fate may change the current head without granting a new release.
pub(super) fn verify_source(
    tx: &Connection,
    record: &BoundaryRecord,
) -> Result<(), AdmissionOperationStoreError> {
    let origin = record
        .return_origin
        .as_ref()
        .ok_or_else(|| refused("original RETURN custody unavailable"))?;
    let boundary = &record.reservation.boundary;
    let record_key = key(&boundary.scope, &boundary.request)?;
    let source = protected::source_reference(tx, &record_key)?;
    if source.scope_key() != scope_key(&boundary.scope)?
        || source.kind() != "command"
        || origin.admission_version.get() == 0
        || origin.admission_version.get() > source.version()
        || record.return_authority != Some(origin.capability)
        || protected::historical_record_commit(tx, &record_key, origin.admission_version.get())?
            != origin.admission_commit.get()
    {
        return Err(refused("original RETURN source binding"));
    }
    let mut original = record.clone();
    original.stop_requested = false;
    original.reservation.state = IsolationStateV1::ReturnAdmitted;
    original
        .return_admission
        .as_mut()
        .ok_or_else(|| refused("original RETURN admission"))?
        .admitted
        .state = ArtifactDeliveryStateV1::Admitted;
    if !protected::matches_historical_source_command_payload(
        tx,
        &source,
        origin.admission_version.get(),
        &protected::encode(&original)?,
    )? {
        return Err(refused("original RETURN preimage changed"));
    }
    Ok(())
}

pub(super) fn verify_actor_and_admission(
    tx: &Connection,
    record: &BoundaryRecord,
    actor: &AuthenticatedRecoveryActor,
    admission: &ReturnAdmissionV1,
) -> Result<(), AdmissionOperationStoreError> {
    verify_source(tx, record)?;
    let origin = record
        .return_origin
        .as_ref()
        .ok_or_else(|| refused("original RETURN custody unavailable"))?;
    if actor.permission() != RecoveryPermission::ConfinedReturn
        || actor.scope() != &record.reservation.boundary.scope
        || *actor.principal() != origin.principal
        || capability_digest(actor.capability())? != origin.capability
    {
        return Err(refused("original RETURN actor changed"));
    }
    let mut supplied = admission.clone();
    supplied.admitted.state = ArtifactDeliveryStateV1::Admitted;
    let mut retained = record
        .return_admission
        .clone()
        .ok_or_else(|| refused("original RETURN admission"))?;
    retained.admitted.state = ArtifactDeliveryStateV1::Admitted;
    if supplied != retained {
        return Err(refused("original RETURN admission changed"));
    }
    let scope = scope_key(actor.scope())?;
    let archive_key = format!(
        "deployment-history:{scope}:{}",
        hex::encode(origin.deployment.as_bytes())
    );
    let archive = protected::raw_checked(tx, &archive_key)?
        .ok_or_else(|| refused("original RETURN deployment custody unavailable"))?;
    let profile: RecoveryDeploymentV1 = protected::decode(&archive.payload)?;
    if archive.kind != "deployment"
        || archive.scope != scope
        || archive.version != 1
        || profile.scope != *actor.scope()
        || profile.authority_scope != origin.authority_scope
        || deployment_digest(&profile)? != origin.deployment
        || !original_assignment(&profile, actor)
        || origin.deployment_commit.get() >= origin.admission_commit.get()
        || protected::historical_record_commit(
            tx,
            &format!("deployment:{scope}"),
            origin.deployment_version.get(),
        )? != origin.deployment_commit.get()
        || !protected::matches_historical_deployment(
            tx,
            &format!("deployment:{scope}"),
            &scope,
            origin.deployment_version.get(),
            &profile,
        )?
    {
        return Err(refused("original RETURN historical assignment"));
    }
    Ok(())
}

//! Bounded modeled predecessor profiles through the genuine protected writer.
//! This default-off fixture changes only a previously accepted Top audience.
use super::*;
use chio_security_types::InformationLabel;

/// Append one historical actor profile accepted by the predecessor validator.
/// This is modeled legacy evidence, not an old executable or fresh installation.
pub fn retain_recovery_fixture_legacy_top_actor(
    store: &SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
    scope: &RecoveryScopeV1,
    principal: &chio_security_types::PrincipalId,
) -> Result<RecoveryDeploymentV1, AdmissionOperationStoreError> {
    let mut connection = store.connection()?;
    let tx = store.begin_write(&mut connection, Some(fence))?;
    let mut profile = deployment_tx(&tx, scope)?;
    validate_deployment(&profile, fence)?;
    let mut actors = profile.actors.as_slice().to_vec();
    let actor = actors
        .iter_mut()
        .find(|actor| &actor.principal == principal)
        .ok_or_else(|| invariant("legacy audience fixture principal absent"))?;
    if actor.preview_clearance == InformationLabel::Top
        || !actor
            .permissions
            .as_slice()
            .contains(&RecoveryPermission::KnowledgeRead)
    {
        return Err(invariant("legacy audience fixture actor refused"));
    }
    actor.preview_clearance = InformationLabel::Top;
    profile.actors = NonEmptyBoundedList::new(actors)
        .map_err(|_| invariant("legacy audience fixture actor bound"))?;
    profile.authority_scope = recovery_authority_scope_digest(&profile)
        .map_err(|_| invariant("legacy audience fixture scope refused"))?;
    validate_deployment(&profile, fence)?;
    super::super::security_participant_state::verify_recovery_initialization(
        &tx,
        &profile.native_authority,
    )?;
    deployment_history::preserve_installation(&tx, &store.serving_owner, &profile)?;
    let scope_key = scope_key(scope)?;
    save(
        &tx,
        &store.serving_owner,
        &format!("deployment:{scope_key}"),
        &scope_key,
        "deployment",
        &encode(&profile)?,
        None,
    )?;
    store.commit_write(tx)?;
    store.sync_after_write(&connection)?;
    Ok(profile)
}

/// Append one exact existing recipient with the predecessor's Top clearance.
/// Caller cannot supply a profile, native context, policy or storage locator.
pub fn retain_knowledge_fixture_legacy_top_recipient(
    store: &SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
    scope: &RecoveryScopeV1,
    recipient: &ArtifactRecipientId,
) -> Result<NativeKnowledgeInstallationV1, AdmissionOperationStoreError> {
    let mut connection = store.connection()?;
    let tx = store.begin_write(&mut connection, Some(fence))?;
    let deployment = deployment_tx(&tx, scope)?;
    validate_deployment(&deployment, fence)?;
    let scope_key = scope_key(scope)?;
    let key = format!("knowledge-profile:{scope_key}");
    let row =
        raw(&tx, &key)?.ok_or_else(|| invariant("legacy recipient fixture profile absent"))?;
    let mut profile: NativeKnowledgeInstallationV1 = decode(&row.payload)?;
    if profile.scope != *scope
        || profile.native_authority != deployment.native_authority
        || profile.policy != deployment.policy_digest
        || recovery_flow_key(&profile.producer_context)
            != recovery_flow_key(&deployment.security_context)
    {
        return Err(invariant("legacy recipient fixture native binding changed"));
    }
    super::super::security_participant_state::verify_recovery_initialization(
        &tx,
        &profile.native_authority,
    )?;
    let mut recipients = profile.recipients.as_slice().to_vec();
    let selected = recipients
        .iter_mut()
        .find(|entry| &entry.recipient.recipient == recipient)
        .ok_or_else(|| invariant("legacy recipient fixture selection absent"))?;
    if selected.recipient.clearance == InformationLabel::Top {
        return Err(invariant("legacy recipient fixture already Top"));
    }
    selected.recipient.clearance = InformationLabel::Top;
    profile.recipients = NonEmptyBoundedList::new(recipients)
        .map_err(|_| invariant("legacy recipient fixture bound"))?;
    profile.generation = SafeInteger::new(
        profile
            .generation
            .get()
            .checked_add(1)
            .ok_or_else(|| invariant("legacy recipient fixture generation overflow"))?,
    )
    .map_err(|_| invariant("legacy recipient fixture generation refused"))?;
    save(
        &tx,
        &store.serving_owner,
        &key,
        &scope_key,
        "command",
        &encode(&profile)?,
        None,
    )?;
    store.commit_write(tx)?;
    store.sync_after_write(&connection)?;
    Ok(profile)
}

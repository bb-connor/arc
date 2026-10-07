//! Read custody and observation commit share the physical serving writer.
use super::*;

mod reference_source;
pub(in crate::admission_operation_store::knowledge) use reference_source::artifact_reference_source;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandleRecord {
    handle: ArtifactHandleV1,
    artifact: ArtifactVersionRefV1,
    recipient: ArtifactRecipientV1,
    principal: chio_security_types::PrincipalId,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseRecord {
    intent: ArtifactReleaseIntentV1,
    handle: ArtifactHandleV1,
    capability: ReleaseAuthorizationDigest,
}
fn handle_key(
    scope: &RecoveryScopeV1,
    handle: &ArtifactHandleId,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "knowledge-handle:{}:{}",
        scope_key(scope)?,
        handle.as_str()
    ))
}
fn release_key(
    actor: &AuthenticatedRecoveryActor,
    request: &RequestId,
) -> Result<String, AdmissionOperationStoreError> {
    actor_request_key(
        "knowledge-release",
        actor.scope(),
        actor.principal(),
        request,
    )
}

fn legacy_release_key(
    scope: &RecoveryScopeV1,
    request: &RequestId,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "knowledge-release:{}:{}",
        scope_key(scope)?,
        request.as_str()
    ))
}

fn release_for_actor(
    tx: &Connection,
    actor: &AuthenticatedRecoveryActor,
    request: &RequestId,
) -> Result<Option<(String, ReleaseRecord)>, AdmissionOperationStoreError> {
    let key = release_key(actor, request)?;
    if let Some(record) = load::<ReleaseRecord>(tx, &key)? {
        let handle: HandleRecord = load(tx, &handle_key(actor.scope(), &record.handle.handle)?)?
            .ok_or_else(|| refused("release original handle absent"))?;
        if handle.principal != *actor.principal()
            || handle.handle != record.handle
            || record.intent.artifact.scope != *actor.scope()
        {
            return Err(refused("release original actor changed"));
        }
        return Ok(Some((key, record)));
    }
    let legacy = legacy_release_key(actor.scope(), request)?;
    let Some(record) = load::<ReleaseRecord>(tx, &legacy)? else {
        return Ok(None);
    };
    let handle: HandleRecord = load(tx, &handle_key(actor.scope(), &record.handle.handle)?)?
        .ok_or_else(|| refused("legacy release original handle absent"))?;
    if handle.handle != record.handle || record.intent.artifact.scope != *actor.scope() {
        return Err(refused("legacy release binding changed"));
    }
    if handle.principal != *actor.principal() {
        // Authenticated old handle custody proves a different owner. Its
        // original flat record remains unchanged while this actor uses v2.
        return Ok(None);
    }
    Ok(Some((legacy, record)))
}
fn selected<'a>(
    profile: &'a NativeKnowledgeInstallationV1,
    id: &ArtifactRecipientId,
) -> Result<&'a NativeKnowledgeRecipientV1, AdmissionOperationStoreError> {
    profile
        .recipients
        .as_slice()
        .iter()
        .find(|selection| &selection.recipient.recipient == id)
        .ok_or_else(|| refused("recipient"))
}

pub(super) fn retained_archive_root(
    tx: &Connection,
    actor: &AuthenticatedRecoveryActor,
    handle: &ArtifactHandleV1,
    recipient: &ArtifactRecipientV1,
) -> Result<ArtifactVersionRefV1, AdmissionOperationStoreError> {
    if actor.permission() != RecoveryPermission::KnowledgeAdmin
        || recipient.scope != *actor.scope()
        || recipient.sink != ArtifactSinkV1::Archive
        || recipient.clearance == InformationLabel::Top
    {
        return Err(refused("retained archive root authority"));
    }
    let retained: HandleRecord = load(tx, &handle_key(actor.scope(), &handle.handle)?)?
        .ok_or_else(|| refused("retained archive root handle"))?;
    if retained.handle != *handle
        || retained.principal != *actor.principal()
        || retained.artifact.scope != *actor.scope()
        || retained.recipient != *recipient
        || handle.recipient != recipient.recipient
    {
        return Err(refused("retained archive root binding"));
    }
    Ok(retained.artifact)
}
pub(super) fn authority_digest(
    actor: &AuthenticatedRecoveryActor,
) -> Result<ReleaseAuthorizationDigest, AdmissionOperationStoreError> {
    Ok(ReleaseAuthorizationDigest::from_bytes(
        knowledge_digest(
            RecoveryDigestDomain::KnowledgeReadAuthority,
            actor.capability(),
        )
        .map_err(refused)?,
    ))
}
impl SqliteAdmissionOperationStore {
    pub fn issue_artifact_handle(
        &self,
        actor: &AuthenticatedRecoveryActor,
        reference: &ArtifactVersionRefV1,
        recipient: &ArtifactRecipientId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ArtifactHandleV1, AdmissionOperationStoreError> {
        if reference.scope != *actor.scope()
            || !matches!(
                actor.permission(),
                RecoveryPermission::KnowledgeRead
                    | RecoveryPermission::KnowledgeWrite
                    | RecoveryPermission::KnowledgeAdopt
            )
        {
            return Err(refused("handle authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, _| {
            let entry = selected(profile, recipient)?;
            require_finite_recipient(&entry.recipient)?;
            let record = artifact(&tx, reference)?;
            traversal::ensure_audience(&tx, actor, &record.metadata.label)?;
            if !record.metadata.label.flows_to(&entry.recipient.clearance) {
                return Err(refused("recipient clearance"));
            }
            let handle = ArtifactHandleV1 {
                handle: ArtifactHandleId::new(&hex::encode(
                    knowledge_digest(
                        RecoveryDigestDomain::KnowledgeHandleIdentity,
                        &(
                            actor.principal(),
                            reference,
                            &entry.recipient,
                            profile.generation,
                        ),
                    )
                    .map_err(refused)?,
                ))
                .map_err(refused)?,
                recipient: recipient.clone(),
            };
            let record = HandleRecord {
                handle: handle.clone(),
                artifact: reference.clone(),
                recipient: entry.recipient.clone(),
                principal: actor.principal().clone(),
            };
            let key = handle_key(actor.scope(), &handle.handle)?;
            if let Some(existing) = load::<HandleRecord>(&tx, &key)? {
                if existing != record {
                    return Err(refused("handle identity changed"));
                }
                return Ok((tx, handle));
            }
            save(&tx, &self.serving_owner, actor.scope(), &key, &record)?;
            Ok((tx, handle))
        })
    }
    /// Trusted host obtains private read staging only after scoped authentication.
    pub fn prepare_artifact_read(
        &self,
        actor: &AuthenticatedRecoveryActor,
        handle: &ArtifactHandleV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(NativeArtifactRecordV1, NativeKnowledgeRecipientV1), AdmissionOperationStoreError>
    {
        if actor.permission() != RecoveryPermission::KnowledgeRead {
            return Err(refused("read authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, _| {
            let retained: HandleRecord = load(&tx, &handle_key(actor.scope(), &handle.handle)?)?
                .ok_or_else(|| refused("handle"))?;
            let selection = selected(profile, &handle.recipient)?;
            require_finite_recipient(&selection.recipient)?;
            if retained.handle != *handle
                || retained.principal != *actor.principal()
                || retained.recipient != selection.recipient
            {
                return Err(refused("handle audience"));
            }
            let artifact = artifact(&tx, &retained.artifact)?;
            require_current_artifact(&artifact, profile)?;
            traversal::dependencies(
                &tx,
                actor.scope(),
                artifact.metadata.dependencies.as_slice(),
            )?;
            traversal::ensure_audience(&tx, actor, &artifact.metadata.label)?;
            if !artifact
                .metadata
                .label
                .flows_to(&selection.recipient.clearance)
            {
                return Err(refused("clearance"));
            }
            Ok((tx, (artifact, selection.clone())))
        })
    }
    /// Caller supplies a privately verified exact seal, never a path substitute.
    /// Returned intent is descriptive evidence. No bytes are exposed here.
    pub fn admit_artifact_release(
        &self,
        actor: &AuthenticatedRecoveryActor,
        handle: &ArtifactHandleV1,
        request: &RequestId,
        seal: &ArtifactBlobSealV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ArtifactReleaseIntentV1, AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeRead {
            return Err(refused("release authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, now| {
            let retained: HandleRecord = load(&tx, &handle_key(actor.scope(), &handle.handle)?)?
                .ok_or_else(|| refused("handle"))?;
            let selection = selected(profile, &handle.recipient)?;
            require_finite_recipient(&selection.recipient)?;
            if retained.handle != *handle
                || retained.principal != *actor.principal()
                || retained.recipient != selection.recipient
            {
                return Err(refused("recipient revoked"));
            }
            let artifact = artifact(&tx, &retained.artifact)?;
            require_current_artifact(&artifact, profile)?;
            if artifact.seal.as_ref() != Some(seal) {
                return Err(refused("exact bytes changed"));
            }
            let mut dependencies = traversal::dependencies(
                &tx,
                actor.scope(),
                artifact.metadata.dependencies.as_slice(),
            )?;
            let mut label = artifact.metadata.label.clone();
            // An authenticated projection already records its exact inputs. Their
            // restrictions do not re-taint certified immutable output content.
            if artifact.certificate.is_none() {
                label = traversal::join_metadata(label, &dependencies)?;
            }
            if let ArtifactSinkV1::Model { context } = &selection.recipient.sink {
                let side_files =
                    traversal::dependencies(&tx, actor.scope(), context.side_files.as_slice())?;
                label = traversal::join_metadata(label, &side_files)?;
                dependencies.extend(side_files);
            }
            dependencies.push(artifact.clone());
            traversal::ensure_audience(&tx, actor, &label)?;
            if !label.flows_to(&selection.recipient.clearance) {
                return Err(refused("current release policy"));
            }
            let digest = authority_digest(actor)?;
            if let Some((_, prior)) = release_for_actor(&tx, actor, request)? {
                if prior.handle != *handle
                    || prior.intent.artifact != retained.artifact
                    || prior.intent.recipient != selection.recipient
                    || prior.intent.policy != profile.policy
                    || prior.capability != digest
                {
                    return Err(refused("release identity changed"));
                }
                // A replay returns the original admitted transition after fresh
                // authority/recipient checks; it cannot mint another join.
                return Ok((tx, prior.intent));
            }
            let release = ReleaseId::new(&uuid::Uuid::new_v4().to_string()).map_err(refused)?;
            let intent = ArtifactReleaseIntentV1 {
                domain_version: VersionV1,
                release: release.clone(),
                kind: ArtifactReleaseKindV1::IndependentlyAdmitted {
                    request: request.clone(),
                },
                artifact: retained.artifact,
                influence: traversal::influence(
                    &tx,
                    &profile.native_authority,
                    &selection.context,
                    &dependencies,
                    artifact.metadata.influence.unknown,
                )?,
                source_label: label.clone(),
                admitted_label: label.clone(),
                recipient: selection.recipient.clone(),
                policy: profile.policy,
                authorization: digest,
                observation_transition: EvidenceRef::new(&format!(
                    "knowledge:{}",
                    release.as_str()
                ))
                .map_err(refused)?,
                observation_generation: SafeInteger::new(0).map_err(refused)?,
                state: ArtifactDeliveryStateV1::Admitted,
            };
            let (tx, intent) = super::super::security_participant_state::knowledge::join(
                tx,
                &self.serving_owner,
                super::super::security_participant_state::knowledge::KnowledgeJoin {
                    binding: &profile.native_authority,
                    key: &recovery_flow_key(&selection.context),
                    source: &label,
                    scope: actor.scope(),
                    release: intent,
                    now,
                },
            )?;
            let retained = ReleaseRecord {
                intent: intent.clone(),
                handle: handle.clone(),
                capability: digest,
            };
            let key = release_key(actor, request)?;
            save(&tx, &self.serving_owner, actor.scope(), &key, &retained)?;
            Ok((tx, intent))
        })
    }
    pub fn acknowledge_artifact_delivery(
        &self,
        actor: &AuthenticatedRecoveryActor,
        request: &RequestId,
        intent: &ArtifactReleaseIntentV1,
        delivered: bool,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeRead {
            return Err(refused("ack authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, _| {
            let (key, mut record) =
                release_for_actor(&tx, actor, request)?.ok_or_else(|| refused("release absent"))?;
            let handle: HandleRecord =
                load(&tx, &handle_key(actor.scope(), &record.handle.handle)?)?
                    .ok_or_else(|| refused("release handle absent"))?;
            let mut admitted = record.intent.clone();
            admitted.state = intent.state;
            if record.capability != authority_digest(actor)?
                || handle.principal != *actor.principal()
                || admitted != *intent
                || record.intent.recipient
                    != selected(profile, &intent.recipient.recipient)?.recipient
            {
                return Err(refused("release ack changed"));
            }
            let next = if delivered {
                ArtifactDeliveryStateV1::Delivered
            } else {
                ArtifactDeliveryStateV1::Uncertain
            };
            if record.intent.state != ArtifactDeliveryStateV1::Delivered
                && record.intent.state != next
            {
                record.intent.state = next;
                save(&tx, &self.serving_owner, actor.scope(), &key, &record)?;
            }
            Ok((tx, ()))
        })
    }
}

fn require_current_artifact(
    artifact: &NativeArtifactRecordV1,
    profile: &NativeKnowledgeInstallationV1,
) -> Result<(), AdmissionOperationStoreError> {
    if artifact.metadata.policy != profile.policy || artifact.metadata.contract != profile.contract
    {
        return Err(refused("artifact release basis changed"));
    }
    Ok(())
}
pub(super) fn pins(
    tx: &Transaction<'_>,
    key: &str,
    reference: &ArtifactVersionRefV1,
) -> Result<bool, AdmissionOperationStoreError> {
    let record: ReleaseRecord = load(tx, key)?.ok_or_else(|| refused("release pin"))?;
    Ok(record.intent.artifact == *reference
        && record.intent.state != ArtifactDeliveryStateV1::Delivered)
}

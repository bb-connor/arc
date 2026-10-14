//! Read custody and observation commit share the physical serving writer.
use super::*;

mod archive;
pub(in crate::admission_operation_store::knowledge) mod encoding;
pub(in crate::admission_operation_store::knowledge) mod encoding_source;
mod reference_source;
pub(in crate::admission_operation_store::knowledge) use reference_source::artifact_reference_source;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HandleRecord {
    pub(super) handle: ArtifactHandleV1,
    pub(super) artifact: ArtifactVersionRefV1,
    pub(super) recipient: ArtifactRecipientV1,
    pub(super) principal: chio_security_types::PrincipalId,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReleaseRecord {
    intent: ArtifactReleaseIntentV1,
    handle: ArtifactHandleV1,
    capability: ReleaseAuthorizationDigest,
    purpose: ReleasePurpose,
}

/// Typed admission purpose of one release record. An ordinary release
/// exports an existing artifact; a retained-archive release additionally
/// commits the exact ephemeral archive frame (content digest and byte
/// count) it delivered plus the bounded originally signed manifest, so a
/// replay must reproduce the same frame without a second signing call.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ReleasePurpose {
    Artifact,
    RetainedArchiveFrame {
        content: CanonicalPayloadDigest,
        bytes: SafeInteger,
        manifest: Box<SignedArtifactArchiveManifestV1>,
    },
}
pub(super) fn handle_key(
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

fn release_for_actor(
    tx: &Connection,
    actor: &AuthenticatedRecoveryActor,
    request: &RequestId,
) -> Result<Option<(String, ReleaseRecord)>, AdmissionOperationStoreError> {
    Ok(release_root_for_actor(tx, actor, request)?.map(|(key, _, record)| (key, record)))
}

/// The one typed release load. A row is the exact inline record or a strict
/// chunked root over the complete canonical record; either way the record with
/// state Admitted must equal the actual original admission bytes.
fn load_release_record(
    tx: &Connection,
    key: &str,
) -> Result<
    Option<(protected::ProtectedSourceReference, ReleaseRecord)>,
    AdmissionOperationStoreError,
> {
    let Some(row) = protected::raw_checked(tx, key)? else {
        return Ok(None);
    };
    let current = protected::source_reference(tx, key)?;
    let record = encoding::decode_release(tx, key, row.version, &row.payload)?;
    let scope = scope_key(&record.intent.artifact.scope)?;
    let mut original = record.clone();
    original.intent.state = ArtifactDeliveryStateV1::Admitted;
    if row.kind != "command"
        || row.scope != scope
        || current.kind() != "command"
        || current.scope_key() != scope
        || !protected::matches_historical_source_command_payload(
            tx,
            &current,
            encoding::ORIGINAL_RELEASE_VERSION,
            &protected::encode(&original)?,
        )?
    {
        return Err(refused("release changed its original admission"));
    }
    Ok(Some((current, record)))
}

fn release_root_for_actor(
    tx: &Connection,
    actor: &AuthenticatedRecoveryActor,
    request: &RequestId,
) -> Result<
    Option<(String, protected::ProtectedSourceReference, ReleaseRecord)>,
    AdmissionOperationStoreError,
> {
    let key = release_key(actor, request)?;
    if let Some((root, record)) = load_release_record(tx, &key)? {
        let handle = load_handle(tx, actor.scope(), &record.handle.handle)?;
        if handle.principal != *actor.principal()
            || handle.handle != record.handle
            || record.intent.artifact.scope != *actor.scope()
        {
            return Err(refused("release original actor changed"));
        }
        return Ok(Some((key, root, record)));
    }
    Ok(None)
}
pub(super) fn selected<'a>(
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
    let retained = load_handle(tx, actor.scope(), &handle.handle)?;
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

/// Retrieve the original manifest after checking the exact release binding.
/// The caller still verifies its signature and freshly reconstructed body.
pub(super) fn prior_retained_archive_manifest(
    tx: &Connection,
    actor: &AuthenticatedRecoveryActor,
    request: &super::retained_archive::NativeRetainedArchiveRequest<'_>,
    root: &ArtifactVersionRefV1,
    policy: &PolicyDigest,
    authorization: &ReleaseAuthorizationDigest,
) -> Result<Option<SignedArtifactArchiveManifestV1>, AdmissionOperationStoreError> {
    match release_for_actor(tx, actor, request.request)? {
        None => Ok(None),
        Some((_, prior)) => {
            let ReleasePurpose::RetainedArchiveFrame { manifest, .. } = prior.purpose else {
                return Err(refused("retained archive release purpose"));
            };
            if prior.handle != *request.root
                || prior.intent.artifact != *root
                || prior.intent.recipient != *request.recipient
                || prior.intent.policy != *policy
                || prior.capability != *authorization
            {
                return Err(refused("retained archive release identity changed"));
            }
            Ok(Some(*manifest))
        }
    }
}
/// The exact handle a current actor may hold for one Available version and
/// one selected finite recipient under the given profile generation.
pub(super) fn derive_handle(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
    reference: &ArtifactVersionRefV1,
    recipient: &ArtifactRecipientId,
) -> Result<(HandleRecord, NativeArtifactRecordV1), AdmissionOperationStoreError> {
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
    let entry = selected(profile, recipient)?;
    require_finite_recipient(&entry.recipient)?;
    let version = artifact(tx, reference)?;
    traversal::ensure_audience(tx, actor, &version.metadata.label)?;
    if !version.metadata.label.flows_to(&entry.recipient.clearance) {
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
    Ok((
        HandleRecord {
            handle,
            artifact: reference.clone(),
            recipient: entry.recipient.clone(),
            principal: actor.principal().clone(),
        },
        version,
    ))
}

/// The original admission row of one new release by the actor's own indexed
/// handle, with that handle and its version as bound heads. The purpose
/// selects the only permission that may admit it.
pub(super) fn derive_admission(
    tx: &Connection,
    actor: &AuthenticatedRecoveryActor,
    request: &RequestId,
    record: &ReleaseRecord,
) -> Result<(DerivedWrite, Vec<protected::ProtectedSourceReference>), AdmissionOperationStoreError>
{
    let key = release_key(actor, request)?;
    if protected::raw_checked(tx, &key)?.is_some() {
        return Err(refused("release already admitted"));
    }
    let handle = load_handle(tx, actor.scope(), &record.handle.handle)?;
    let admitted = matches!(
        &record.intent.kind,
        ArtifactReleaseKindV1::IndependentlyAdmitted { request: admitted } if admitted == request
    );
    if !matches!(
        (&record.purpose, actor.permission()),
        (ReleasePurpose::Artifact, RecoveryPermission::KnowledgeRead)
            | (
                ReleasePurpose::RetainedArchiveFrame { .. },
                RecoveryPermission::KnowledgeAdmin
            )
    ) || !admitted
        || !matches!(record.intent.state, ArtifactDeliveryStateV1::Admitted)
        || record.capability != authority_digest(actor)?
        || record.intent.authorization != record.capability
        || record.intent.artifact.scope != *actor.scope()
        || handle.handle != record.handle
        || handle.principal != *actor.principal()
        || handle.artifact != record.intent.artifact
        || handle.recipient != record.intent.recipient
    {
        return Err(refused("release admission changed its handle or authority"));
    }
    let witnesses = vec![
        protected::source_reference(tx, &handle_key(actor.scope(), &record.handle.handle)?)?,
        protected::source_reference(tx, &version_key(&record.intent.artifact)?)?,
    ];
    Ok((
        DerivedWrite {
            scope_key: scope_key(actor.scope())?,
            payload: protected::encode(record)?,
            key,
            expected: None,
        },
        witnesses,
    ))
}

/// One retained handle admitted by its version index, by exact listing or by
/// the baseline census of a supported prior-44 row. It does not require the
/// version to be readable, so admitted outcomes settle after collection.
fn load_handle(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    handle: &ArtifactHandleId,
) -> Result<HandleRecord, AdmissionOperationStoreError> {
    let record: HandleRecord =
        load(tx, &handle_key(scope, handle)?)?.ok_or_else(|| refused("handle"))?;
    if record.handle.handle != *handle
        || record.artifact.scope != *scope
        || !super::handle_index::current(tx, &record.artifact)?.admits(tx, &record)?
    {
        return Err(refused("handle index"));
    }
    Ok(record)
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
        mutate(self, actor, fence, now, |tx, profile, now| {
            let (handle, intake) = super::intake::AuthenticatedKnowledgeIntakeSource::handle_issue(
                &tx, actor, profile, now, reference, recipient,
            )?;
            if let Some(intake) = intake {
                protected::persist_knowledge_intake(&tx, &self.serving_owner, intake)?;
            }
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
            let retained = load_handle(&tx, actor.scope(), &handle.handle)?;
            let selection = selected(profile, &handle.recipient)?;
            require_finite_recipient(&selection.recipient)?;
            if retained.handle != *handle
                || retained.principal != *actor.principal()
                || retained.recipient != selection.recipient
            {
                return Err(refused("handle audience"));
            }
            let artifact = require_readable(&tx, actor, profile, &retained.artifact, selection)?;
            Ok((tx, (artifact, selection.clone())))
        })
    }
    /// Host-internal reads that deliver one composite body (checkpoint restore,
    /// archive export) need the same admission as a handle read but no durable
    /// custody: nothing is saved, so the read consumes no recovery record or
    /// event from the shared knowledge pool.
    pub fn prepare_artifact_read_for_recipient(
        &self,
        actor: &AuthenticatedRecoveryActor,
        reference: &ArtifactVersionRefV1,
        recipient: &ArtifactRecipientId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(NativeArtifactRecordV1, NativeKnowledgeRecipientV1), AdmissionOperationStoreError>
    {
        if actor.permission() != RecoveryPermission::KnowledgeRead
            || reference.scope != *actor.scope()
        {
            return Err(refused("read authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, _| {
            let selection = selected(profile, recipient)?;
            let artifact = require_readable(&tx, actor, profile, reference, selection)?;
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
            let retained = load_handle(&tx, actor.scope(), &handle.handle)?;
            let selection = selected(profile, &handle.recipient)?;
            require_finite_recipient(&selection.recipient)?;
            if retained.handle != *handle
                || retained.principal != *actor.principal()
                || retained.recipient != selection.recipient
            {
                return Err(refused("recipient revoked"));
            }
            let artifact = artifact(&tx, &retained.artifact)?;
            let basis = require_current_artifact(&artifact, profile);
            #[cfg(feature = "admission-test-support")]
            super::release_basis_observation::record_artifact_release_basis(
                actor, request, &artifact, profile, &basis,
            );
            basis?;
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
                if prior.purpose != ReleasePurpose::Artifact
                    || prior.handle != *handle
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
                purpose: ReleasePurpose::Artifact,
            };
            let key = release_key(actor, request)?;
            let admission = super::intake::AuthenticatedKnowledgeIntakeSource::release_admission(
                &tx, actor, profile, now, request, &retained,
            )?;
            protected::persist_knowledge_intake(&tx, &self.serving_owner, admission)?;
            super::reference_custody::retain_release_references(&tx, &self.serving_owner, &key)?;
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
        mutate(self, actor, fence, now, |tx, profile, now| {
            transition_delivery_state(
                &tx,
                &self.serving_owner,
                profile,
                actor,
                fence,
                request,
                intent,
                delivered,
                now,
            )?;
            Ok((tx, ()))
        })
    }
}

/// Shared monotone delivery transition over one admitted release record. Each
/// finite forward step (Admitted to Uncertain or Delivered, Uncertain to
/// Delivered) settles through the one encoded writer from its authenticated
/// outcome source; a repeat writes nothing. Uncertain retains the exact
/// release identity and its source pins; Delivered is sticky and retires the
/// pins, bound to the exact new root.
#[allow(clippy::too_many_arguments)]
fn transition_delivery_state(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    profile: &NativeKnowledgeInstallationV1,
    actor: &AuthenticatedRecoveryActor,
    fence: &StoreMutationFence,
    request: &RequestId,
    intent: &ArtifactReleaseIntentV1,
    delivered: bool,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let Some(source) = encoding_source::prepare_release_outcome(
        tx, actor, profile, fence, now, request, intent, delivered,
    )?
    else {
        return Ok(());
    };
    let refund = source.delivers();
    let key = source.key().to_owned();
    let body = source.body()?;
    let prepared = super::encoding::write::VerifiedKnowledgeEncodingWrite::release(source, body)?;
    let (root, _) = protected::persist_knowledge_encoding(tx, owner, prepared)?;
    if refund {
        let proof =
            super::reference_retirement::VerifiedKnowledgeReferenceRetirement::artifact_release(
                tx, &key,
            )?
            .ok_or_else(|| refused("delivered release has no genuine terminal source"))?;
        super::closure::require_terminal_head(proof.source(), &root)?;
        protected::persist_knowledge_reference_retirement(tx, owner, proof)?;
    }
    Ok(())
}

/// Current availability, dependency closure, requester audience and recipient
/// clearance for one selected recipient.
fn require_readable(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
    reference: &ArtifactVersionRefV1,
    selection: &NativeKnowledgeRecipientV1,
) -> Result<NativeArtifactRecordV1, AdmissionOperationStoreError> {
    require_finite_recipient(&selection.recipient)?;
    let artifact = artifact(tx, reference)?;
    require_current_artifact(&artifact, profile)?;
    traversal::dependencies(tx, actor.scope(), artifact.metadata.dependencies.as_slice())?;
    traversal::ensure_audience(tx, actor, &artifact.metadata.label)?;
    if !artifact
        .metadata
        .label
        .flows_to(&selection.recipient.clearance)
    {
        return Err(refused("clearance"));
    }
    Ok(artifact)
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

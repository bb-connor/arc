//! A restore binds one exact checkpoint and retained native observation.
use super::*;

mod encoding;
mod encoding_source;
pub(in crate::admission_operation_store) use encoding_source::AuthenticatedCheckpointRestoreEncodingSource;

/// Exact private preparation to revalidate under the serving writer. This
/// description carries no byte-delivery or native observation authority.
pub struct NativeCheckpointRestore<'a> {
    pub checkpoint: &'a LabeledCheckpointV1,
    pub recipient: &'a ArtifactRecipientV1,
    pub request: &'a RequestId,
    pub installation_generation: SafeInteger,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreActorBinding {
    principal: chio_security_types::PrincipalId,
    authority_scope: AuthorityScopeDigest,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreRecord {
    checkpoint: LabeledCheckpointV1,
    recipient: ArtifactRecipientV1,
    intent: ArtifactReleaseIntentV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actor_binding: Option<RestoreActorBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    installation_generation: Option<SafeInteger>,
}

/// Retained custody data. Outcome status is read from the owning restore row.
pub(in crate::admission_operation_store::knowledge) struct RestoreReferenceSource {
    material: super::reference_source::CheckpointMaterial,
    request: RequestId,
    release: ReleaseId,
    source: protected::ProtectedSourceReference,
    delivered: bool,
}

impl RestoreReferenceSource {
    pub(in crate::admission_operation_store::knowledge) fn scope(&self) -> &RecoveryScopeV1 {
        self.material.scope()
    }
    pub(in crate::admission_operation_store::knowledge) fn checkpoint(&self) -> &CheckpointId {
        self.material.checkpoint()
    }
    pub(in crate::admission_operation_store::knowledge) fn revision(&self) -> u64 {
        self.material.revision()
    }
    pub(in crate::admission_operation_store::knowledge) fn envelope(
        &self,
    ) -> &CanonicalPayloadDigest {
        self.material.envelope()
    }
    pub(in crate::admission_operation_store::knowledge) fn references(
        &self,
    ) -> &[ArtifactVersionRefV1] {
        self.material.references()
    }
    pub(in crate::admission_operation_store::knowledge) fn request(&self) -> &RequestId {
        &self.request
    }
    pub(in crate::admission_operation_store::knowledge) fn release(&self) -> &ReleaseId {
        &self.release
    }
    pub(in crate::admission_operation_store::knowledge) fn active(&self) -> bool {
        !self.delivered
    }
    pub(in crate::admission_operation_store::knowledge) fn source(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.source
    }
    pub(in crate::admission_operation_store::knowledge) fn terminal(
        &self,
    ) -> Option<&protected::ProtectedSourceReference> {
        self.delivered.then_some(&self.source)
    }
}

pub(in crate::admission_operation_store::knowledge) fn restore_reference_source(
    connection: &Connection,
    key: &str,
) -> Result<Option<RestoreReferenceSource>, AdmissionOperationStoreError> {
    if !key.starts_with("knowledge-restore:") {
        return Ok(None);
    }
    let Some(row) = protected::raw_checked(connection, key)? else {
        return Ok(None);
    };
    let record = encoding::decode(connection, key, row.version, &row.payload)?;
    let ArtifactReleaseKindV1::IndependentlyAdmitted { request } = &record.intent.kind else {
        return Err(refused("restore reference source kind"));
    };
    let scope = &record.checkpoint.scope;
    if row.kind != "command" || row.scope != scope_key(scope)? {
        return Err(refused("restore reference source ownership"));
    }
    validate_restore_identity(&record, scope, request)?;
    if key != legacy_restore_key(scope, request)? {
        let binding = record
            .actor_binding
            .as_ref()
            .ok_or_else(|| refused("restore reference source actor absent"))?;
        if key != actor_restore_key(scope, &binding.principal, request)?
            || record
                .installation_generation
                .is_none_or(|generation| generation.get() == 0)
        {
            return Err(refused("restore reference source actor identity"));
        }
    }
    let source = protected::source_reference(connection, key)?;
    Ok(Some(RestoreReferenceSource {
        request: request.clone(),
        release: record.intent.release.clone(),
        delivered: record.intent.state == ArtifactDeliveryStateV1::Delivered,
        material: super::reference_source::CheckpointMaterial::new(record.checkpoint)?,
        source,
    }))
}

fn load_restore(
    connection: &Connection,
    key: &str,
) -> Result<Option<RestoreRecord>, AdmissionOperationStoreError> {
    let Some(row) = protected::raw_checked(connection, key)? else {
        return Ok(None);
    };
    let record = encoding::decode(connection, key, row.version, &row.payload)?;
    if row.kind != "command" || row.scope != scope_key(&record.checkpoint.scope)? {
        return Err(refused("restore encoded source ownership"));
    }
    Ok(Some(record))
}

fn restore_key(
    actor: &AuthenticatedRecoveryActor,
    request: &RequestId,
) -> Result<String, AdmissionOperationStoreError> {
    actor_restore_key(actor.scope(), actor.principal(), request)
}

fn actor_restore_key(
    scope: &RecoveryScopeV1,
    principal: &chio_security_types::PrincipalId,
    request: &RequestId,
) -> Result<String, AdmissionOperationStoreError> {
    let identity = knowledge_digest(
        RecoveryDigestDomain::KnowledgeActorIdentity,
        &(scope, principal),
    )
    .map_err(refused)?;
    Ok(format!(
        "knowledge-restore:v2:{}:{}:{}",
        scope_key(scope)?,
        hex::encode(identity),
        sha256_hex(&protected::encode(request)?)
    ))
}

fn legacy_restore_key(
    scope: &RecoveryScopeV1,
    request: &RequestId,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "knowledge-restore:{}:{}",
        scope_key(scope)?,
        request.as_str()
    ))
}

fn validate_restore_identity(
    record: &RestoreRecord,
    scope: &RecoveryScopeV1,
    request: &RequestId,
) -> Result<(), AdmissionOperationStoreError> {
    record.checkpoint.validate().map_err(refused)?;
    if record.checkpoint.scope != *scope
        || record.recipient.scope != *scope
        || record.intent.kind
            != (ArtifactReleaseKindV1::IndependentlyAdmitted {
                request: request.clone(),
            })
        || record.intent.recipient != record.recipient
        || record.intent.artifact != record.checkpoint.artifacts.as_slice()[0]
        || record.intent.policy != record.checkpoint.policy
    {
        return Err(refused("restore record identity"));
    }
    Ok(())
}

fn retained_restore(
    tx: &Connection,
    actor: &AuthenticatedRecoveryActor,
    request: &RequestId,
    authorization: ReleaseAuthorizationDigest,
) -> Result<Option<(String, RestoreRecord)>, AdmissionOperationStoreError> {
    let key = restore_key(actor, request)?;
    if let Some(record) = load_restore(tx, &key)? {
        validate_restore_identity(&record, actor.scope(), request)?;
        if record.intent.authorization != authorization
            || record
                .installation_generation
                .is_none_or(|generation| generation.get() == 0)
            || record
                .actor_binding
                .as_ref()
                .is_none_or(|binding| binding.principal != *actor.principal())
        {
            return Err(refused("restore actor identity"));
        }
        return Ok(Some((key, record)));
    }

    let key = legacy_restore_key(actor.scope(), request)?;
    let Some(record) = load_restore(tx, &key)? else {
        return Ok(None);
    };
    validate_restore_identity(&record, actor.scope(), request)?;
    if let Some(binding) = &record.actor_binding {
        if binding.principal != *actor.principal() {
            return Ok(None);
        }
        if record.intent.authorization != authorization {
            return Err(refused("restore original authorization"));
        }
    } else {
        // The original opaque capability digest must match before its subject
        // can resolve an assignment in the proven original installation.
        if record.intent.authorization != authorization {
            return Err(refused("legacy restore original authorization"));
        }
        let (principal, _) =
            super::super::super::recovery::deployment_history::original_restore_actor(
                tx,
                actor.scope(),
                &key,
                &actor.capability().subject,
            )?
            .ok_or_else(|| refused("legacy restore actor proof unavailable"))?;
        if principal != *actor.principal() {
            return Ok(None);
        }
    }
    Ok(Some((key, record)))
}

pub(super) fn pins(
    tx: &Connection,
    key: &str,
    reference: &ArtifactVersionRefV1,
) -> Result<bool, AdmissionOperationStoreError> {
    let row = protected::raw_checked(tx, key)?.ok_or_else(|| refused("restore pin absent"))?;
    let record = encoding::decode(tx, key, row.version, &row.payload)?;
    let ArtifactReleaseKindV1::IndependentlyAdmitted { request } = &record.intent.kind else {
        return Err(refused("restore pin kind"));
    };
    let scope = &record.checkpoint.scope;
    if row.kind != "command" || row.scope != scope_key(scope)? {
        return Err(refused("restore pin source ownership"));
    }
    validate_restore_identity(&record, scope, request)?;
    if key != legacy_restore_key(scope, request)? {
        let binding = record
            .actor_binding
            .as_ref()
            .ok_or_else(|| refused("restore pin owner absent"))?;
        if key != actor_restore_key(scope, &binding.principal, request)? {
            return Err(refused("restore pin owner identity"));
        }
    }
    Ok(record.intent.state != ArtifactDeliveryStateV1::Delivered
        && (record.checkpoint.artifacts.as_slice().contains(reference)
            || record
                .checkpoint
                .model_contexts
                .as_slice()
                .iter()
                .any(|model| model.side_files.as_slice().contains(reference))))
}

impl SqliteAdmissionOperationStore {
    /// Bounded test custody observation through the same authenticated decoder.
    /// It reads only the requesting actor's original outcome and writes nothing.
    #[cfg(feature = "admission-test-support")]
    pub fn checkpoint_restore_outcome_fixture(
        &self,
        actor: &AuthenticatedRecoveryActor,
        request: &RequestId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<(ReleaseId, ArtifactDeliveryStateV1)>, AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeRead {
            return Err(refused("restore outcome fixture authority"));
        }
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        schema::verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        let now = schema::authority_validation_time(&tx, now)?;
        let deployment = protected::deployment_tx(&tx, actor.scope())?;
        super::super::super::recovery::verify_actor(&tx, actor, &deployment, now)?;
        let current = installation(&tx, actor.scope())?;
        validate_installation(&tx, &deployment, &current)?;
        let authorization = super::super::release::authority_digest(actor)?;
        let outcome = retained_restore(&tx, actor, request, authorization)?
            .map(|(_, record)| (record.intent.release, record.intent.state));
        tx.commit().map_err(sqlite_error)?;
        Ok(outcome)
    }

    /// Test-only readback of an exact authenticated historical restore root.
    #[cfg(feature = "admission-test-support")]
    pub fn checkpoint_restore_historical_outcome_fixture(
        &self,
        actor: &AuthenticatedRecoveryActor,
        request: &RequestId,
        version: u64,
        canonical_root: &[u8],
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(ReleaseId, ArtifactDeliveryStateV1), AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeRead
            || version == 0
            || canonical_root.is_empty()
            || canonical_root.len() > 262_144
        {
            return Err(refused("historical restore fixture authority"));
        }
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        schema::verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        let now = schema::authority_validation_time(&tx, now)?;
        let deployment = protected::deployment_tx(&tx, actor.scope())?;
        super::super::super::recovery::verify_actor(&tx, actor, &deployment, now)?;
        let current = installation(&tx, actor.scope())?;
        validate_installation(&tx, &deployment, &current)?;
        let authorization = super::super::release::authority_digest(actor)?;
        let (key, original) = retained_restore(&tx, actor, request, authorization)?
            .ok_or_else(|| refused("historical restore fixture original absent"))?;
        let source = protected::source_reference(&tx, &key)?;
        if source.kind() != "command"
            || source.scope_key() != scope_key(actor.scope())?
            || version > source.version()
            || !protected::matches_historical_source_command_payload(
                &tx,
                &source,
                version,
                canonical_root,
            )?
        {
            return Err(refused("historical restore fixture exact source"));
        }
        // The owning decoder authenticates the historical root's actual version
        // and global ordinal before resolving that version's immutable chunk set.
        let mut historical = encoding::decode(&tx, &key, version, canonical_root)?;
        validate_restore_identity(&historical, actor.scope(), request)?;
        let state = historical.intent.state;
        let release = historical.intent.release.clone();
        historical.intent.state = original.intent.state;
        if encoding::canonical(&historical)? != encoding::canonical(&original)? {
            return Err(refused("historical restore fixture immutable identity"));
        }
        tx.commit().map_err(sqlite_error)?;
        Ok((release, state))
    }

    /// One durable restore observation covers the entire checkpoint and remote
    /// context envelope before reconstruction or any artifact byte delivery.
    pub fn admit_checkpoint_restore(
        &self,
        actor: &AuthenticatedRecoveryActor,
        prepared: NativeCheckpointRestore<'_>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ArtifactReleaseIntentV1, AdmissionOperationStoreError> {
        let NativeCheckpointRestore {
            checkpoint,
            recipient,
            request,
            installation_generation,
        } = prepared;
        if actor.permission() != RecoveryPermission::KnowledgeRead {
            return Err(refused("restore authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, now| {
            let retained = load_visible_checkpoint(
                &tx,
                actor.scope(),
                &checkpoint.checkpoint,
                checkpoint.revision.get(),
            )?
            .ok_or_else(|| refused("restore checkpoint"))?;
            if profile.generation != installation_generation
                || retained != *checkpoint
                || checkpoint.scope != *actor.scope()
                || checkpoint.policy != profile.policy
                || checkpoint.runtime.as_str()
                    != profile.producer_context.as_v1().session_id().as_str()
                || checkpoint.lineage.as_str()
                    != profile.producer_context.as_v1().lineage_root_id().as_str()
                || checkpoint.isolation_epoch.as_str()
                    != profile
                        .producer_context
                        .as_v1()
                        .isolation_epoch_id()
                        .as_str()
            {
                return Err(refused("restore envelope changed"));
            }
            let entry = profile
                .recipients
                .as_slice()
                .iter()
                .find(|entry| &entry.recipient == recipient)
                .ok_or_else(|| refused("restore recipient"))?;
            require_finite_recipient(&entry.recipient)?;
            let mut roots = checkpoint.artifacts.as_slice().to_vec();
            for model in checkpoint.model_contexts.as_slice() {
                let model_recipient = profile
                    .recipients
                    .as_slice()
                    .iter()
                    .find(|entry| {
                        entry.recipient.sink
                            == (ArtifactSinkV1::Model {
                                context: model.clone(),
                            })
                    })
                    .ok_or_else(|| refused("remote context changed"))?;
                require_finite_recipient(&model_recipient.recipient)?;
                roots.extend_from_slice(model.side_files.as_slice());
            }
            if let ArtifactSinkV1::Model { context } = &entry.recipient.sink {
                roots.extend_from_slice(context.side_files.as_slice());
            }
            let dependencies = traversal::dependencies(&tx, actor.scope(), &roots)?;
            let label = traversal::join_metadata(checkpoint.label.clone(), &dependencies)?;
            traversal::ensure_audience(&tx, actor, &label)?;
            if !label.flows_to(&entry.recipient.clearance) {
                return Err(refused("restore audience"));
            }
            let authorization = super::super::release::authority_digest(actor)?;
            if let Some((_, old)) = retained_restore(&tx, actor, request, authorization)? {
                if old.checkpoint != *checkpoint
                    || old.recipient != entry.recipient
                    || old.intent.authorization != authorization
                {
                    return Err(refused("restore identity changed"));
                }
                return Ok((tx, old.intent));
            }
            #[cfg(feature = "admission-test-support")]
            let legacy =
                super::restore_test_support::consume_legacy_restore_construction(actor, request)?;
            #[cfg(not(feature = "admission-test-support"))]
            let legacy = false;
            let (key, actor_binding, installation_generation) = if legacy {
                let key = legacy_restore_key(actor.scope(), request)?;
                if protected::raw(&tx, &key)?.is_some() {
                    return Err(refused("legacy restore fixture already retained"));
                }
                (key, None, None)
            } else {
                (
                    restore_key(actor, request)?,
                    Some(RestoreActorBinding {
                        principal: actor.principal().clone(),
                        authority_scope: protected::deployment_tx(&tx, actor.scope())?
                            .authority_scope,
                    }),
                    Some(profile.generation),
                )
            };
            let id = ReleaseId::new(&uuid::Uuid::new_v4().to_string()).map_err(refused)?;
            let intent = ArtifactReleaseIntentV1 {
                domain_version: VersionV1,
                release: id.clone(),
                kind: ArtifactReleaseKindV1::IndependentlyAdmitted {
                    request: request.clone(),
                },
                artifact: checkpoint.artifacts.as_slice()[0].clone(),
                influence: traversal::influence(
                    &tx,
                    &profile.native_authority,
                    &entry.context,
                    &dependencies,
                    checkpoint.influence.unknown,
                )?,
                source_label: label.clone(),
                admitted_label: label.clone(),
                recipient: entry.recipient.clone(),
                policy: profile.policy,
                authorization,
                observation_transition: EvidenceRef::new(&format!("knowledge:{}", id.as_str()))
                    .map_err(refused)?,
                observation_generation: SafeInteger::new(0).map_err(refused)?,
                state: ArtifactDeliveryStateV1::Admitted,
            };
            let (tx, intent) = super::super::security_participant_state::knowledge::join(
                tx,
                &self.serving_owner,
                super::super::security_participant_state::knowledge::KnowledgeJoin {
                    binding: &profile.native_authority,
                    key: &recovery_flow_key(&entry.context),
                    source: &label,
                    scope: actor.scope(),
                    release: intent,
                    now,
                },
            )?;
            let record = RestoreRecord {
                checkpoint: checkpoint.clone(),
                recipient: entry.recipient.clone(),
                intent: intent.clone(),
                actor_binding,
                installation_generation,
            };
            let source = AuthenticatedCheckpointRestoreEncodingSource::admission(
                &tx, actor, profile, now, &key, &record,
            )?;
            let prepared = super::super::encoding::write::VerifiedKnowledgeEncodingWrite::restore(
                source,
                encoding::logical_body(&record)?,
            )?;
            #[cfg(feature = "admission-test-support")]
            super::super::super::security_participant_state::knowledge::observe_restore_record_encoding_bytes_fixture(
                actor.scope(),
                request,
                prepared.root_payload(),
            );
            let (_root_source, _encoded_delta) =
                protected::persist_knowledge_encoding(&tx, &self.serving_owner, prepared)?;
            super::super::reference_custody::retain_restore_references(
                &tx,
                &self.serving_owner,
                &key,
            )?;
            Ok((tx, intent))
        })
    }

    /// A delivery observation updates only the original admitted restore. Its
    /// read authorization remains immutable, and success cannot be downgraded.
    pub fn acknowledge_checkpoint_delivery(
        &self,
        actor: &AuthenticatedRecoveryActor,
        request: &RequestId,
        intent: &ArtifactReleaseIntentV1,
        delivered: bool,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeRead {
            return Err(refused("restore acknowledgement authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, trusted_now| {
            let authorization = super::super::release::authority_digest(actor)?;
            let (key, mut record) = retained_restore(&tx, actor, request, authorization)?
                .ok_or_else(|| refused("restore acknowledgement absent"))?;
            let selected = profile
                .recipients
                .as_slice()
                .iter()
                .find(|entry| entry.recipient.recipient == record.recipient.recipient)
                .ok_or_else(|| refused("restore acknowledgement recipient"))?;
            let mut original = record.intent.clone();
            original.state = intent.state;
            if record.checkpoint.scope != *actor.scope()
                || record.intent.authorization != authorization
                || record.intent.kind
                    != (ArtifactReleaseKindV1::IndependentlyAdmitted {
                        request: request.clone(),
                    })
                || record.recipient != selected.recipient
                || record.intent.recipient != record.recipient
                || record.intent.artifact != record.checkpoint.artifacts.as_slice()[0]
                || record.intent.policy != profile.policy
                || original != *intent
            {
                return Err(refused("restore acknowledgement identity changed"));
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
                let source = AuthenticatedCheckpointRestoreEncodingSource::acknowledgement(
                    &tx,
                    actor,
                    profile,
                    trusted_now,
                    &key,
                    &record,
                )?;
                let prepared =
                    super::super::encoding::write::VerifiedKnowledgeEncodingWrite::restore(
                        source,
                        encoding::logical_body(&record)?,
                    )?;
                let (_root_source, _encoded_delta) =
                    protected::persist_knowledge_encoding(&tx, &self.serving_owner, prepared)?;
                if next == ArtifactDeliveryStateV1::Delivered {
                    super::super::reference_retirement::retire_restore_references(
                        &tx,
                        &self.serving_owner,
                        &key,
                    )?;
                }
            }
            Ok((tx, ()))
        })
    }
}

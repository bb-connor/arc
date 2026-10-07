//! Collection crosses databases only after a protected retirement barrier.
use super::*;
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SweepState {
    Sweeping,
    Collected,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SweepRecord {
    seal: ArtifactBlobSealV1,
    state: SweepState,
}
fn sweep_key(
    scope: &RecoveryScopeV1,
    context: &SecurityInvocationContext,
    content: CanonicalPayloadDigest,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "knowledge-sweep:{}",
        sha256_hex(&protected::encode(&(
            scope.authority_domain.clone(),
            scope.tenant_id.clone(),
            scope.process_id.clone(),
            context.as_v1().session_id(),
            content
        ))?)
    ))
}

fn logical_object(seal: &ArtifactBlobSealV1) -> bool {
    seal.generation
        .as_str()
        .strip_prefix("object:")
        .is_some_and(|identity| uuid::Uuid::parse_str(identity).is_ok())
}

fn seal_sweep_key(
    scope: &RecoveryScopeV1,
    context: &SecurityInvocationContext,
    seal: &ArtifactBlobSealV1,
) -> Result<String, AdmissionOperationStoreError> {
    if !logical_object(seal) {
        return sweep_key(scope, context, seal.content);
    }
    Ok(format!(
        "knowledge-object-sweep:{}",
        hex::encode(
            knowledge_digest(RecoveryDigestDomain::KnowledgeObjectCustody, &(scope, seal),)
                .map_err(refused)?
        ),
    ))
}

/// Exact immutable collection acknowledgment, independent of a producer's
/// current execution profile. Missing or shared legacy custody stays live.
pub(super) fn publication_collection_source(
    tx: &Connection,
    record: &NativeArtifactRecordV1,
) -> Result<Option<protected::ProtectedSourceReference>, AdmissionOperationStoreError> {
    if record.state != ArtifactPublicationStateV1::Retired {
        return Ok(None);
    }
    let Some(seal) = &record.seal else {
        // A crash before recording the broker seal can leave an orphan object.
        // An absent envelope field does not prove its physical collection.
        return Ok(None);
    };
    let key = if logical_object(seal) {
        format!(
            "knowledge-object-sweep:{}",
            hex::encode(
                knowledge_digest(
                    RecoveryDigestDomain::KnowledgeObjectCustody,
                    &(&record.metadata.scope, seal),
                )
                .map_err(refused)?,
            )
        )
    } else {
        format!(
            "knowledge-sweep:{}",
            sha256_hex(&protected::encode(&(
                &record.metadata.scope.authority_domain,
                &record.metadata.scope.tenant_id,
                &record.metadata.scope.process_id,
                &seal.runtime,
                seal.content,
            ))?)
        )
    };
    let Some(row) = protected::raw_checked(tx, &key)? else {
        return Ok(None);
    };
    let source = protected::source_reference(tx, &key)?;
    if row.kind != "command" || row.scope != scope_key(&record.metadata.scope)? {
        return Err(refused("collection source changed its scope"));
    }
    let sweep: SweepRecord = protected::decode(&row.payload)?;
    Ok((sweep.seal == *seal && sweep.state == SweepState::Collected).then_some(source))
}

pub(super) fn require_stage_not_sweeping(
    tx: &Connection,
    profile: &NativeKnowledgeInstallationV1,
    seal: &ArtifactBlobSealV1,
) -> Result<(), AdmissionOperationStoreError> {
    if logical_object(seal) {
        return Ok(());
    }
    require_not_sweeping(tx, &profile.scope, &profile.producer_context, seal.content)
}
pub(super) fn require_not_sweeping(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    context: &SecurityInvocationContext,
    content: CanonicalPayloadDigest,
) -> Result<(), AdmissionOperationStoreError> {
    if load::<SweepRecord>(tx, &sweep_key(scope, context, content)?)?
        .is_some_and(|record| record.state == SweepState::Sweeping)
    {
        return Err(refused("collection in progress"));
    }
    Ok(())
}
fn publications(
    tx: &Connection,
    scope: &RecoveryScopeV1,
) -> Result<Vec<NativeArtifactRecordV1>, AdmissionOperationStoreError> {
    let mut statement=tx.prepare("SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-publication:*' AND scope_key=?1 AND json_extract(payload,'$.state')<>'retired' ORDER BY record_key LIMIT 513").map_err(sqlite_error)?;
    let keys = statement
        .query_map([scope_key(scope)?], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    if keys.len() > 512 {
        return Err(refused("publication inventory overflow"));
    }
    keys.into_iter()
        .map(|key| load(tx, &key)?.ok_or_else(|| refused("publication inventory")))
        .collect()
}
fn pinned(
    tx: &Transaction<'_>,
    reference: &ArtifactVersionRefV1,
) -> Result<bool, AdmissionOperationStoreError> {
    // New Product writers retain closed typed owner leaves. Keep the legacy
    // family barriers below until all their owning writers have joined this
    // index; zero typed owners alone does not prove safe collection.
    if super::references::active_reference_owner_count(tx, reference)? > 0 {
        return Ok(true);
    }
    // Dependencies include reserved/staged versions, so publication cannot lose
    // a required input between independent blob and metadata commits.
    for record in publications(tx, &reference.scope)? {
        if record.state != ArtifactPublicationStateV1::Retired
            && record.input.dependencies.as_slice().contains(reference)
        {
            return Ok(true);
        }
    }
    let mut statement=tx.prepare("SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-checkpoint:*' OR record_key GLOB 'knowledge-pin:*' OR record_key GLOB 'knowledge-release:*' OR record_key GLOB 'knowledge-restore:*' LIMIT 4097").map_err(sqlite_error)?;
    let keys = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    if keys.len() > 4096 {
        return Err(refused("pin inventory overflow"));
    }
    for key in keys {
        if key.starts_with("knowledge-checkpoint:") {
            if super::checkpoints::pins(tx, &key, reference)? {
                return Ok(true);
            }
        } else if key.starts_with("knowledge-restore:") {
            if super::checkpoints::restore_pins(tx, &key, reference)? {
                return Ok(true);
            }
        } else if key.starts_with("knowledge-pin:") {
            let pinned = super::pins::reference(tx, &key)?;
            if pinned.as_ref() == Some(reference) {
                return Ok(true);
            }
        } else if super::release::pins(tx, &key, reference)? {
            return Ok(true);
        }
    }
    Ok(false)
}
impl SqliteAdmissionOperationStore {
    /// A scoped operator pin may be retired without retiring native custody.
    /// This explicit route does not infer pin purpose from historical text.
    pub fn retire_operator_artifact_pin(
        &self,
        actor: &AuthenticatedRecoveryActor,
        reference: &ArtifactVersionRefV1,
        pin: &EvidenceRef,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeAdmin
            || reference.scope != *actor.scope()
        {
            return Err(refused("operator pin retirement authority"));
        }
        mutate_retained_admin(self, actor, fence, now, |tx, profile, now| {
            // The immutable publication stays available for authority/audience
            // checks after collection, without restoring execution or read access.
            let key: String = load(&tx, &version_key(reference)?)?
                .ok_or_else(|| refused("operator pin retirement version absent"))?;
            let record: NativeArtifactRecordV1 = load(&tx, &key)?
                .ok_or_else(|| refused("operator pin retirement artifact absent"))?;
            if record_publication_key(&record)? != key
                || artifact_version_reference(&record.metadata).map_err(refused)? != *reference
            {
                return Err(refused("operator pin retirement artifact changed"));
            }
            traversal::ensure_audience(&tx, actor, &record.metadata.label)?;
            traversal::ensure_audience(
                &tx,
                actor,
                &source(&tx, &profile.native_authority, &profile.producer_context)?,
            )?;
            super::pins::retire_operator(
                &tx,
                &self.serving_owner,
                actor,
                profile,
                reference,
                pin,
                now,
            )?;
            Ok((tx, ()))
        })
    }

    /// Stable evidence pin. An identity cannot be rebound after retirement.
    pub fn pin_artifact(
        &self,
        actor: &AuthenticatedRecoveryActor,
        reference: &ArtifactVersionRefV1,
        pin: &EvidenceRef,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeAdmin
            || reference.scope != *actor.scope()
        {
            return Err(refused("pin authority"));
        }
        mutate(self, actor, fence, now, |tx, _, _| {
            let record = artifact(&tx, reference)?;
            traversal::ensure_audience(&tx, actor, &record.metadata.label)?;
            super::pins::retain(
                &tx,
                &self.serving_owner,
                actor.scope(),
                super::pins::PinOwner::Operator {
                    principal: actor.principal().clone(),
                    evidence: pin.clone(),
                },
                reference,
            )?;
            Ok((tx, ()))
        })
    }
    pub fn move_artifact(
        &self,
        actor: &AuthenticatedRecoveryActor,
        reference: &ArtifactVersionRefV1,
        location: &ProtectedText<128>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeWrite
            || reference.scope != *actor.scope()
        {
            return Err(refused("move authority"));
        }
        mutate(self, actor, fence, now, |tx, _, _| {
            let mut record = artifact(&tx, reference)?;
            traversal::ensure_audience(&tx, actor, &record.metadata.label)?;
            record.location = location.clone();
            save(
                &tx,
                &self.serving_owner,
                actor.scope(),
                &record_publication_key(&record)?,
                &record,
            )?;
            Ok((tx, ()))
        })
    }
    /// Uncertain releases, dependencies, checkpoints, evidence and operations
    /// prevent collection. Sweep ownership bars new reservations of equal bytes.
    pub fn retire_artifact(
        &self,
        actor: &AuthenticatedRecoveryActor,
        reference: &ArtifactVersionRefV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<ArtifactBlobSealV1>, AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeAdmin
            || reference.scope != *actor.scope()
        {
            return Err(refused("retention authority"));
        }
        mutate_retained_admin(self, actor, fence, now, |tx, profile, _| {
            let key: String = load(&tx, &version_key(reference)?)?
                .ok_or_else(|| refused("retirement version"))?;
            let mut record: NativeArtifactRecordV1 =
                load(&tx, &key)?.ok_or_else(|| refused("retirement record"))?;
            traversal::ensure_audience(&tx, actor, &record.metadata.label)?;
            if artifact_version_reference(&record.metadata).map_err(refused)? != *reference
                || record.metadata.retention != ArtifactRetentionV1::Ephemeral
                || pinned(&tx, reference)?
            {
                return Err(refused("retention pin"));
            }
            if matches!(
                record.metadata.producer,
                ArtifactProducerV1::NativeOperation { .. }
            ) {
                return Err(refused("native receipt pin"));
            }
            if record.state != ArtifactPublicationStateV1::Retired {
                record.state = ArtifactPublicationStateV1::Retired;
                save(&tx, &self.serving_owner, actor.scope(), &key, &record)?;
            }
            let result = schedule_collection(&tx, &self.serving_owner, profile, &record)?;
            Ok((tx, result))
        })
    }
    pub fn finish_artifact_collection(
        &self,
        actor: &AuthenticatedRecoveryActor,
        seal: &ArtifactBlobSealV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeAdmin {
            return Err(refused("collection authority"));
        }
        mutate_retained_admin(self, actor, fence, now, |tx, profile, _| {
            let key = seal_sweep_key(actor.scope(), &profile.producer_context, seal)?;
            let mut record: SweepRecord =
                load(&tx, &key)?.ok_or_else(|| refused("sweep absent"))?;
            if record.seal != *seal {
                return Err(refused("sweep identity"));
            }
            if record.state == SweepState::Sweeping {
                record.state = SweepState::Collected;
                save(&tx, &self.serving_owner, actor.scope(), &key, &record)?;
            }
            Ok((tx, ()))
        })
    }
}

fn schedule_collection(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    profile: &NativeKnowledgeInstallationV1,
    record: &NativeArtifactRecordV1,
) -> Result<Option<ArtifactBlobSealV1>, AdmissionOperationStoreError> {
    let Some(seal) = &record.seal else {
        return Ok(None);
    };
    let key = seal_sweep_key(&record.metadata.scope, &profile.producer_context, seal)?;
    if let Some(old) = load::<SweepRecord>(tx, &key)? {
        if old.seal == *seal {
            return Ok(if old.state == SweepState::Collected {
                None
            } else {
                Some(seal.clone())
            });
        }
        if old.state == SweepState::Sweeping {
            return Err(refused("another collection owns bytes"));
        }
    }
    let shared = if logical_object(seal) {
        false
    } else {
        // Historical storage deduplicated by content and generation. It still
        // needs every old owner's barrier, while modern objects retire alone.
        publications(tx, &record.metadata.scope)?
            .iter()
            .any(|other| {
                other.state != ArtifactPublicationStateV1::Retired
                    && other.metadata.content == record.metadata.content
                    && other
                        .seal
                        .as_ref()
                        .is_none_or(|other| !logical_object(other))
            })
    };
    if shared {
        return Ok(None);
    }
    save(
        tx,
        owner,
        &record.metadata.scope,
        &key,
        &SweepRecord {
            seal: seal.clone(),
            state: SweepState::Sweeping,
        },
    )?;
    Ok(Some(seal.clone()))
}
impl SqliteAdmissionOperationStore {
    pub fn artifact_publication_for_collection(
        &self,
        actor: &AuthenticatedRecoveryActor,
        input: &ArtifactPublicationInputV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<NativeArtifactRecordV1, AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeAdmin {
            return Err(refused("collection inspect authority"));
        }
        mutate_retained_admin(self, actor, fence, now, |tx, _, _| {
            let record: NativeArtifactRecordV1 = load(
                &tx,
                &publication_key(actor.scope(), actor.principal(), &input.publication)?,
            )?
            .ok_or_else(|| refused("collection absent"))?;
            if record.input != *input || record.metadata.scope != *actor.scope() {
                return Err(refused("collection input changed"));
            }
            traversal::ensure_audience(&tx, actor, &record.metadata.label)?;
            Ok((tx, record))
        })
    }
    /// Abort unreachable staging explicitly. Its original publication identity
    /// stays retired, including orphan cleanup after an acknowledgement loss.
    pub fn abort_artifact_publication(
        &self,
        actor: &AuthenticatedRecoveryActor,
        input: &ArtifactPublicationInputV1,
        orphan: Option<&ArtifactBlobSealV1>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<ArtifactBlobSealV1>, AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeAdmin {
            return Err(refused("abort authority"));
        }
        mutate_retained_admin(self, actor, fence, now, |tx, profile, _| {
            let key = publication_key(actor.scope(), actor.principal(), &input.publication)?;
            let mut record: NativeArtifactRecordV1 =
                load(&tx, &key)?.ok_or_else(|| refused("abort absent"))?;
            traversal::ensure_audience(&tx, actor, &record.metadata.label)?;
            if record.input != *input
                || record.metadata.scope != *actor.scope()
                || record.state == ArtifactPublicationStateV1::Available
                || matches!(input.producer, ArtifactProducerV1::NativeOperation { .. })
            {
                return Err(refused("abort identity"));
            }
            record.state = ArtifactPublicationStateV1::Retired;
            save(&tx, &self.serving_owner, actor.scope(), &key, &record)?;
            if let Some(seal) = orphan {
                if seal.object != record.object
                    || seal.process != actor.scope().process_id
                    || seal.content != input.content
                    || seal.bytes != input.size_bytes
                    || seal.runtime.as_str()
                        != profile.producer_context.as_v1().session_id().as_str()
                {
                    return Err(refused("orphan identity"));
                }
                if record.seal.as_ref().is_some_and(|prior| prior != seal) {
                    return Err(refused("orphan generation changed"));
                }
                record.seal = Some(seal.clone());
                save(&tx, &self.serving_owner, actor.scope(), &key, &record)?;
            }
            let result = schedule_collection(&tx, &self.serving_owner, profile, &record)?;
            Ok((tx, result))
        })
    }
    /// The host connects actual captured/unknown native custody to retention.
    /// This profile keeps pins permanently; unknown custody cannot unpin itself.
    pub fn pin_native_artifact_operation(
        &self,
        actor: &AuthenticatedRecoveryActor,
        reference: &ArtifactVersionRefV1,
        operation: &OperationId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeAdmin
            || reference.scope != *actor.scope()
        {
            return Err(refused("native pin authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, _| {
            let record = artifact(&tx, reference)?;
            traversal::ensure_audience(&tx, actor, &record.metadata.label)?;
            let native = load_operation_for_participant_tx(
                &tx,
                &AdmissionOperationId::from_persisted(operation.as_str()).map_err(refused)?,
            )?
            .ok_or_else(|| refused("native pin absent"))?;
            if native.native_dispatch_ledger_digest().is_none() {
                return Err(refused("native pin uncaptured"));
            }
            let request = super::super::retained_request::load_retained_request_tx(&tx, &native)?
                .ok_or_else(|| refused("native pin request"))?;
            request.validate_native_security_authority(&profile.native_authority)?;
            request.validate_native_security_context(&profile.producer_context)?;
            super::pins::retain(
                &tx,
                &self.serving_owner,
                actor.scope(),
                super::pins::PinOwner::NativeOperation {
                    operation: operation.clone(),
                },
                reference,
            )?;
            Ok((tx, ()))
        })
    }
    pub fn pin_pending_artifact_approval(
        &self,
        actor: &AuthenticatedRecoveryActor,
        reference: &ArtifactVersionRefV1,
        workflow: &WorkflowId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeAdmin
            || reference.scope != *actor.scope()
        {
            return Err(refused("approval pin authority"));
        }
        mutate(self, actor, fence, now, |tx, _, _| {
            let record = artifact(&tx, reference)?;
            traversal::ensure_audience(&tx, actor, &record.metadata.label)?;
            let pending = protected::workflow_tx(&tx, actor.scope(), workflow)?;
            if pending.review.is_none() || pending.approval.is_some() || pending.captured {
                return Err(refused("approval not pending"));
            }
            super::pins::retain(
                &tx,
                &self.serving_owner,
                actor.scope(),
                super::pins::PinOwner::PendingApproval {
                    workflow: workflow.clone(),
                },
                reference,
            )?;
            Ok((tx, ()))
        })
    }
}

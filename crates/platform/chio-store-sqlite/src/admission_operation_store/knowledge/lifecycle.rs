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

pub(super) fn logical_object(seal: &ArtifactBlobSealV1) -> bool {
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
    let key = publication_sweep_key(record, seal)?;
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

fn publication_sweep_key(
    record: &NativeArtifactRecordV1,
    seal: &ArtifactBlobSealV1,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(if logical_object(seal) {
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
    })
}

/// An old shared sweep can advance to another generation. Authenticate the
/// exact retained acknowledgment and its preceding barrier rather than losing
/// the original collected owner's custody when its current projection moves.
pub(super) fn publication_collected_anchor(
    tx: &Connection,
    record: &NativeArtifactRecordV1,
) -> Result<Option<references::SourceAnchor>, AdmissionOperationStoreError> {
    if record.state != ArtifactPublicationStateV1::Retired {
        return Ok(None);
    }
    let Some(seal) = &record.seal else {
        return Ok(None);
    };
    let key = publication_sweep_key(record, seal)?;
    let Some(row) = protected::raw_checked(tx, &key)? else {
        return Ok(None);
    };
    let current = protected::source_reference(tx, &key)?;
    let _: SweepRecord = protected::decode(&row.payload)?;
    if row.scope != scope_key(&record.metadata.scope)? || row.kind != "command" {
        return Err(refused("publication sweep changed its original scope"));
    }
    let expected = protected::encode(&SweepRecord {
        seal: seal.clone(),
        state: SweepState::Collected,
    })?;
    for version in (2..=current.version()).rev() {
        if let Some(anchor) =
            references::SourceAnchor::historical_command(tx, &current, version, &expected)?
        {
            verify_publication_collected_anchor(tx, record, &anchor)?;
            return Ok(Some(anchor));
        }
    }
    Ok(None)
}

pub(super) fn verify_publication_collected_anchor(
    tx: &Connection,
    record: &NativeArtifactRecordV1,
    collected: &references::SourceAnchor,
) -> Result<u64, AdmissionOperationStoreError> {
    let seal = record
        .seal
        .as_ref()
        .ok_or_else(|| refused("collected publication lost its exact seal"))?;
    let key = publication_sweep_key(record, seal)?;
    let current = protected::source_reference(tx, &key)?;
    let expected = protected::encode(&SweepRecord {
        seal: seal.clone(),
        state: SweepState::Collected,
    })?;
    let before = collected
        .version()
        .checked_sub(1)
        .filter(|version| *version != 0)
        .ok_or_else(|| refused("collection acknowledgment has no original barrier"))?;
    if record.state != ArtifactPublicationStateV1::Retired
        || collected.record_key() != key
        || collected.scope_key() != scope_key(&record.metadata.scope)?
        || !collected.matches_historical_command_payload(tx, &expected)?
        || !protected::matches_historical_source_command_payload(
            tx,
            &current,
            before,
            &protected::encode(&SweepRecord {
                seal: seal.clone(),
                state: SweepState::Sweeping,
            })?,
        )?
    {
        return Err(refused(
            "collection acknowledgment changed its original barrier",
        ));
    }
    let barrier = protected::historical_record_commit(tx, &key, before)?;
    if barrier >= collected.global_commit_sequence() {
        return Err(refused(
            "collection acknowledgment precedes its original barrier",
        ));
    }
    Ok(barrier)
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
pub(super) fn pinned(
    tx: &Connection,
    reference: &ArtifactVersionRefV1,
) -> Result<bool, AdmissionOperationStoreError> {
    if super::references::active_reference_owner_count(tx, reference)? > 0 {
        return Ok(true);
    }
    let ready = super::references::ready_reference_account(tx, &reference.scope)?;
    ready.verify_current(tx)?;
    if ready.has_complete_writer_coverage() {
        return Ok(false);
    }
    // V1 and V2 activation predate confined input writer coverage. Their cold
    // census owns retained references through the authenticated cutoff. Keep
    // later retained sources as conservative barriers, including vanished
    // current projections. Streaming has no authority-wide lifetime ceiling.
    let mut statement = tx.prepare(
        "SELECT record_key FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-publication:*' OR record_key GLOB 'knowledge-checkpoint:*'
            OR record_key GLOB 'knowledge-pin:*' OR record_key GLOB 'knowledge-release:*'
            OR record_key GLOB 'knowledge-restore:*'
         UNION SELECT record_key FROM admission_operation_recovery_events
         WHERE record_key GLOB 'knowledge-publication:*' OR record_key GLOB 'knowledge-checkpoint:*'
            OR record_key GLOB 'knowledge-pin:*' OR record_key GLOB 'knowledge-release:*'
            OR record_key GLOB 'knowledge-restore:*'
         UNION SELECT projection_key FROM authority_global_commits WHERE projection_kind='recovery'
            AND (projection_key GLOB 'knowledge-publication:*' OR projection_key GLOB 'knowledge-checkpoint:*'
            OR projection_key GLOB 'knowledge-pin:*' OR projection_key GLOB 'knowledge-release:*'
            OR projection_key GLOB 'knowledge-restore:*') ORDER BY 1",
    ).map_err(sqlite_error)?;
    let mut keys = statement.query([]).map_err(sqlite_error)?;
    while let Some(row) = keys.next().map_err(sqlite_error)? {
        let key: String = row.get(0).map_err(sqlite_error)?;
        let source = protected::source_reference(tx, &key)?;
        if source.scope_key() != scope_key(&reference.scope)?
            || source.global_commit_sequence() <= ready.cutoff().sequence()
        {
            continue;
        }
        if key.starts_with("knowledge-publication:") {
            let record: NativeArtifactRecordV1 =
                load(tx, &key)?.ok_or_else(|| refused("legacy publication disappeared"))?;
            if record_publication_key(&record)? != key || record.metadata.scope != reference.scope {
                return Err(refused("legacy publication changed its dependency owner"));
            }
            if record.state != ArtifactPublicationStateV1::Retired
                && record.input.dependencies.as_slice().contains(reference)
            {
                return Ok(true);
            }
        } else if key.starts_with("knowledge-checkpoint:") {
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
            super::publication_capacity::validate_existing_allocation(&tx, &record)?;
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
            super::publication_capacity::validate_retained_allocation(&tx, &record)?;
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
                super::reference_retirement::retire_publication_references(
                    &tx,
                    &self.serving_owner,
                    &record,
                )?;
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
            super::publication_capacity::collection::acknowledge_collection(
                &tx,
                &self.serving_owner,
                actor.scope(),
                seal,
            )?;
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
            super::publication_capacity::validate_retained_allocation(&tx, &record)?;
            traversal::ensure_audience(&tx, actor, &record.metadata.label)?;
            if record.input != *input
                || record.metadata.scope != *actor.scope()
                || record.state == ArtifactPublicationStateV1::Available
                || matches!(input.producer, ArtifactProducerV1::NativeOperation { .. })
            {
                return Err(refused("abort identity"));
            }
            if super::publication_capacity::collection::collected_source(&tx, &record)?.is_some() {
                if orphan.is_some_and(|seal| record.seal.as_ref() != Some(seal)) {
                    return Err(refused("collected orphan identity changed"));
                }
                return Ok((tx, None));
            }
            record.state = ArtifactPublicationStateV1::Retired;
            save(&tx, &self.serving_owner, actor.scope(), &key, &record)?;
            super::reference_retirement::retire_publication_references(
                &tx,
                &self.serving_owner,
                &record,
            )?;
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

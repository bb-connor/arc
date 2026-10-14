//! Collection crosses databases only after a protected retirement barrier.
use super::closure::{Derivation, DerivedWrite, PreparedKnowledgeClosure};
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

/// The current head of the sweep whose retained Collected history anchors a
/// retired publication's collection acknowledgment.
pub(super) fn collected_sweep_source(
    tx: &Connection,
    record: &NativeArtifactRecordV1,
) -> Result<protected::ProtectedSourceReference, AdmissionOperationStoreError> {
    let seal = record
        .seal
        .as_ref()
        .ok_or_else(|| refused("collected publication lost its exact seal"))?;
    protected::source_reference(tx, &publication_sweep_key(record, seal)?)
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
        mutate(self, actor, fence, now, |tx, profile, now| {
            let record = artifact(&tx, reference)?;
            traversal::ensure_audience(&tx, actor, &record.metadata.label)?;
            super::pins::retain(
                &tx,
                &self.serving_owner,
                actor,
                profile,
                now,
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
        mutate(self, actor, fence, now, |tx, profile, now| {
            let record = artifact(&tx, reference)?;
            traversal::ensure_audience(&tx, actor, &record.metadata.label)?;
            if let Some(moved) =
                super::intake::AuthenticatedKnowledgeIntakeSource::publication_move(
                    &tx, actor, profile, now, reference, location,
                )?
            {
                protected::persist_knowledge_intake(&tx, &self.serving_owner, moved)?;
            }
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
        mutate_retained_admin(self, actor, fence, now, |tx, profile, now| {
            if let Some(closure) = PreparedKnowledgeClosure::publication_retirement(
                &tx, actor, profile, reference, now,
            )? {
                closure.settle(&tx, &self.serving_owner)?;
            }
            let (key, _) = retirement_publication(&tx, actor, reference)?;
            let result = schedule_collection(&tx, &self.serving_owner, actor, profile, &key, now)?;
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
        mutate_retained_admin(self, actor, fence, now, |tx, profile, now| {
            if let Some(closure) =
                PreparedKnowledgeClosure::collection_acknowledgment(&tx, actor, profile, seal, now)?
            {
                closure.settle(&tx, &self.serving_owner)?;
            }
            super::publication_capacity::collection::visit_collected_owners(
                &tx,
                actor.scope(),
                seal,
                |publication| {
                    if let Some(closure) = PreparedKnowledgeClosure::publication_slot_refund(
                        &tx,
                        actor,
                        profile,
                        publication,
                        now,
                    )? {
                        closure.settle(&tx, &self.serving_owner)?;
                    }
                    Ok(())
                },
            )?;
            Ok((tx, ()))
        })
    }
}

/// Return the seal the host must collect and settle its one Sweeping barrier
/// when this retired publication still owes it.
fn schedule_collection(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
    publication: &str,
    now: u64,
) -> Result<Option<ArtifactBlobSealV1>, AdmissionOperationStoreError> {
    let (collect, _) = sweep_plan(tx, profile, publication)?;
    if let Some(closure) =
        PreparedKnowledgeClosure::collection_sweep(tx, actor, profile, publication, now)?
    {
        closure.settle(tx, owner)?;
    }
    Ok(collect)
}

/// The seal still owed a physical collection and, when absent, its exact
/// Sweeping barrier. Shared historical content waits for every owner.
fn sweep_plan(
    tx: &Connection,
    profile: &NativeKnowledgeInstallationV1,
    publication: &str,
) -> Result<(Option<ArtifactBlobSealV1>, Option<Derivation>), AdmissionOperationStoreError> {
    let record: NativeArtifactRecordV1 =
        load(tx, publication)?.ok_or_else(|| refused("sweep publication absent"))?;
    if record_publication_key(&record)? != publication
        || record.state != ArtifactPublicationStateV1::Retired
    {
        return Err(refused("sweep publication is not retired"));
    }
    let Some(seal) = &record.seal else {
        return Ok((None, None));
    };
    // A publication whose own collection was already acknowledged owes no
    // barrier. A later shared sweep generation must not reopen it.
    if super::publication_capacity::collection::collected_source(tx, &record)?.is_some() {
        return Ok((None, None));
    }
    let key = seal_sweep_key(&record.metadata.scope, &profile.producer_context, seal)?;
    let mut expected = None;
    if let Some(old) = load::<SweepRecord>(tx, &key)? {
        if old.seal == *seal {
            let collect = (old.state != SweepState::Collected).then(|| seal.clone());
            return Ok((collect, None));
        }
        if old.state == SweepState::Sweeping {
            return Err(refused("another collection owns bytes"));
        }
        expected = Some(protected::source_reference(tx, &key)?);
    }
    // The retired owner's head and, for historical content, every live
    // same-content candidate examined by the sharing decision are bound.
    let mut witnesses = vec![protected::source_reference(tx, publication)?];
    if !logical_object(seal) {
        // Historical storage deduplicated by content and generation. It still
        // needs every old owner's barrier, while modern objects retire alone.
        let mut shared = false;
        for other in publications(tx, &record.metadata.scope)? {
            if other.metadata.content != record.metadata.content
                || other.seal.as_ref().is_some_and(logical_object)
            {
                continue;
            }
            shared |= other.state != ArtifactPublicationStateV1::Retired;
            witnesses.push(protected::source_reference(
                tx,
                &record_publication_key(&other)?,
            )?);
        }
        if shared {
            return Ok((None, None));
        }
    }
    Ok((
        Some(seal.clone()),
        Some(Derivation::bound(
            vec![DerivedWrite {
                scope_key: scope_key(&record.metadata.scope)?,
                payload: protected::encode(&SweepRecord {
                    seal: seal.clone(),
                    state: SweepState::Sweeping,
                })?,
                expected,
                key,
            }],
            witnesses,
        )),
    ))
}

/// The actor's own retired publication still owes its Sweeping barrier.
pub(super) fn pending_sweep(
    tx: &Connection,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
    publication: &str,
) -> Result<Option<Derivation>, AdmissionOperationStoreError> {
    let record: NativeArtifactRecordV1 =
        load(tx, publication)?.ok_or_else(|| refused("sweep publication absent"))?;
    if record.metadata.scope != *actor.scope() {
        return Err(refused("sweep publication changed its tenant scope"));
    }
    Ok(sweep_plan(tx, profile, publication)?.1)
}

/// The host relays its actual physical collection of this exact seal.
pub(super) fn pending_collection_acknowledgment(
    tx: &Connection,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
    seal: &ArtifactBlobSealV1,
) -> Result<Option<Derivation>, AdmissionOperationStoreError> {
    let key = seal_sweep_key(actor.scope(), &profile.producer_context, seal)?;
    let mut record: SweepRecord = load(tx, &key)?.ok_or_else(|| refused("sweep absent"))?;
    if record.seal != *seal {
        return Err(refused("sweep identity"));
    }
    if record.state == SweepState::Collected {
        return Ok(None);
    }
    record.state = SweepState::Collected;
    // The exact sweep is the only selected source; its head is the CAS.
    Ok(Some(Derivation::bound(
        vec![DerivedWrite {
            expected: Some(protected::source_reference(tx, &key)?),
            scope_key: scope_key(actor.scope())?,
            payload: protected::encode(&record)?,
            key,
        }],
        Vec::new(),
    )))
}

/// The exact retained Ephemeral publication this actor may retire, with no
/// live owner, native receipt or foreign audience.
fn retirement_publication(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    reference: &ArtifactVersionRefV1,
) -> Result<(String, NativeArtifactRecordV1), AdmissionOperationStoreError> {
    let key: String =
        load(tx, &version_key(reference)?)?.ok_or_else(|| refused("retirement version"))?;
    let record: NativeArtifactRecordV1 =
        load(tx, &key)?.ok_or_else(|| refused("retirement record"))?;
    super::publication_capacity::validate_retained_allocation(tx, &record)?;
    traversal::ensure_audience(tx, actor, &record.metadata.label)?;
    if artifact_version_reference(&record.metadata).map_err(refused)? != *reference
        || record.metadata.retention != ArtifactRetentionV1::Ephemeral
        || super::references::active_reference_owner_count(tx, reference)? > 0
    {
        return Err(refused("retention pin"));
    }
    if matches!(
        record.metadata.producer,
        ArtifactProducerV1::NativeOperation { .. }
    ) {
        return Err(refused("native receipt pin"));
    }
    Ok((key, record))
}

pub(super) fn pending_publication_retirement(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    reference: &ArtifactVersionRefV1,
) -> Result<Option<Derivation>, AdmissionOperationStoreError> {
    let (key, record) = retirement_publication(tx, actor, reference)?;
    // Version index, the initialized live-owner aggregate that proved zero
    // owners, and the original lease; the publication head is the CAS.
    let witnesses = vec![
        protected::source_reference(tx, &version_key(reference)?)?,
        protected::source_reference(
            tx,
            &super::references::aggregate_key(super::references::reference_identity(reference)?),
        )?,
        super::publication_capacity::retained_allocation_source(tx, &record)?,
    ];
    retired_successor(tx, actor, key, record, witnesses)
}

/// The actor's own unreachable staging publication.
fn abort_publication(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    input: &ArtifactPublicationInputV1,
) -> Result<(String, NativeArtifactRecordV1), AdmissionOperationStoreError> {
    let key = publication_key(actor.scope(), actor.principal(), &input.publication)?;
    let record: NativeArtifactRecordV1 = load(tx, &key)?.ok_or_else(|| refused("abort absent"))?;
    super::publication_capacity::validate_retained_allocation(tx, &record)?;
    traversal::ensure_audience(tx, actor, &record.metadata.label)?;
    if record.input != *input
        || record.metadata.scope != *actor.scope()
        || record.state == ArtifactPublicationStateV1::Available
        || matches!(input.producer, ArtifactProducerV1::NativeOperation { .. })
    {
        return Err(refused("abort identity"));
    }
    Ok((key, record))
}

pub(super) fn pending_publication_abort(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    input: &ArtifactPublicationInputV1,
) -> Result<Option<Derivation>, AdmissionOperationStoreError> {
    let (key, record) = abort_publication(tx, actor, input)?;
    let witnesses = vec![super::publication_capacity::retained_allocation_source(
        tx, &record,
    )?];
    retired_successor(tx, actor, key, record, witnesses)
}

/// The aborted publication's exact orphaned object generation.
pub(super) fn pending_orphan_seal(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
    input: &ArtifactPublicationInputV1,
    seal: &ArtifactBlobSealV1,
) -> Result<Option<Derivation>, AdmissionOperationStoreError> {
    let (key, mut record) = abort_publication(tx, actor, input)?;
    if record.state != ArtifactPublicationStateV1::Retired
        || seal.object != record.object
        || seal.process != actor.scope().process_id
        || seal.content != input.content
        || seal.bytes != input.size_bytes
        || seal.runtime.as_str() != profile.producer_context.as_v1().session_id().as_str()
    {
        return Err(refused("orphan identity"));
    }
    match &record.seal {
        Some(prior) if prior == seal => return Ok(None),
        Some(_) => return Err(refused("orphan generation changed")),
        None => {}
    }
    let lease = super::publication_capacity::retained_allocation_source(tx, &record)?;
    record.seal = Some(seal.clone());
    Ok(Some(Derivation::bound(
        vec![DerivedWrite {
            expected: Some(protected::source_reference(tx, &key)?),
            scope_key: scope_key(actor.scope())?,
            payload: protected::encode(&record)?,
            key,
        }],
        vec![lease],
    )))
}

fn retired_successor(
    tx: &Connection,
    actor: &AuthenticatedRecoveryActor,
    key: String,
    mut record: NativeArtifactRecordV1,
    witnesses: Vec<protected::ProtectedSourceReference>,
) -> Result<Option<Derivation>, AdmissionOperationStoreError> {
    if record.state == ArtifactPublicationStateV1::Retired {
        return Ok(None);
    }
    record.state = ArtifactPublicationStateV1::Retired;
    Ok(Some(Derivation::bound(
        vec![DerivedWrite {
            expected: Some(protected::source_reference(tx, &key)?),
            scope_key: scope_key(actor.scope())?,
            payload: protected::encode(&record)?,
            key,
        }],
        witnesses,
    )))
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
        mutate_retained_admin(self, actor, fence, now, |tx, profile, now| {
            let (key, record) = abort_publication(&tx, actor, input)?;
            if super::publication_capacity::collection::collected_source(&tx, &record)?.is_some() {
                if orphan.is_some_and(|seal| record.seal.as_ref() != Some(seal)) {
                    return Err(refused("collected orphan identity changed"));
                }
                return Ok((tx, None));
            }
            if let Some(closure) =
                PreparedKnowledgeClosure::publication_abort(&tx, actor, profile, input, now)?
            {
                closure.settle(&tx, &self.serving_owner)?;
            }
            if let Some(seal) = orphan {
                if let Some(closure) =
                    PreparedKnowledgeClosure::orphan_seal(&tx, actor, profile, input, seal, now)?
                {
                    closure.settle(&tx, &self.serving_owner)?;
                }
            }
            let result = schedule_collection(&tx, &self.serving_owner, actor, profile, &key, now)?;
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
        mutate(self, actor, fence, now, |tx, profile, now| {
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
                actor,
                profile,
                now,
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
        mutate(self, actor, fence, now, |tx, profile, now| {
            let record = artifact(&tx, reference)?;
            traversal::ensure_audience(&tx, actor, &record.metadata.label)?;
            let pending = protected::workflow_tx(&tx, actor.scope(), workflow)?;
            if pending.review.is_none() || pending.approval.is_some() || pending.captured {
                return Err(refused("approval not pending"));
            }
            super::pins::retain(
                &tx,
                &self.serving_owner,
                actor,
                profile,
                now,
                super::pins::PinOwner::PendingApproval {
                    workflow: workflow.clone(),
                },
                reference,
            )?;
            Ok((tx, ()))
        })
    }
}

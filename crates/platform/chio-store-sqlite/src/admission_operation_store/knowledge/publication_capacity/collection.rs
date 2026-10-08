//! Only original collection custody can return a logical publication slot.
use super::*;

/// A terminal command is authenticated in its complete retained framing. A
/// later idempotent abort may have advanced the current publication head.
pub(in crate::admission_operation_store::knowledge) fn retired_source_before(
    tx: &Connection,
    record: &NativeArtifactRecordV1,
    before: u64,
) -> Result<Option<SourceAnchor>, AdmissionOperationStoreError> {
    if record.state != ArtifactPublicationStateV1::Retired {
        return Err(refused("publication terminal source is not retired"));
    }
    let key = record_publication_key(record)?;
    let source = protected::source_reference(tx, &key)?;
    let actual: NativeArtifactRecordV1 =
        load(tx, &key)?.ok_or_else(|| refused("publication terminal source disappeared"))?;
    if protected::encode(&actual)? != protected::encode(record)?
        || source.scope_key() != scope_key(&record.metadata.scope)?
        || source.kind() != "command"
    {
        return Err(refused(
            "publication terminal source changed its original owner",
        ));
    }
    let full = protected::encode(record)?;
    let mut unsealed = record.clone();
    unsealed.seal = None;
    let unsealed = protected::encode(&unsealed)?;
    for version in (1..=source.version()).rev() {
        let commit = protected::historical_record_commit(tx, &key, version)?;
        if commit >= before {
            continue;
        }
        for payload in [&full, &unsealed] {
            if let Some(anchor) = SourceAnchor::historical_command(tx, &source, version, payload)? {
                return Ok(Some(anchor));
            }
        }
    }
    Ok(None)
}

pub(in crate::admission_operation_store::knowledge) fn collected_source(
    tx: &Connection,
    record: &NativeArtifactRecordV1,
) -> Result<Option<SourceAnchor>, AdmissionOperationStoreError> {
    let Some(collected) = lifecycle::publication_collected_anchor(tx, record)? else {
        return Ok(None);
    };
    verify_retained_collection(tx, record, &collected)?;
    Ok(Some(collected))
}

pub(super) fn verify_retained_collection(
    tx: &Connection,
    record: &NativeArtifactRecordV1,
    collected: &SourceAnchor,
) -> Result<(), AdmissionOperationStoreError> {
    let seal = record
        .seal
        .as_ref()
        .ok_or_else(|| refused("publication collection lacks an original sealed object"))?;
    if record.state != ArtifactPublicationStateV1::Retired
        || record.input.dependencies != record.metadata.dependencies
        || matches!(
            record.metadata.producer,
            ArtifactProducerV1::NativeOperation { .. }
        )
        || seal.object != record.object
        || seal.process != record.metadata.scope.process_id
        || seal.content != record.metadata.content
        || seal.bytes != record.metadata.size_bytes
    {
        return Err(refused(
            "publication collection changed its original physical owner",
        ));
    }
    let barrier = lifecycle::verify_publication_collected_anchor(tx, record, collected)?;
    if retired_source_before(tx, record, barrier)?.is_none() {
        return Err(refused(
            "collection barrier precedes original publication retirement",
        ));
    }
    references::verify_collected_publication_sources(tx, record).map(|_| ())
}

fn retire_one(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    record: &NativeArtifactRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    let (mut lease, previous_lease) = current_lease(tx, record)?;
    let collected = collected_source(tx, record)?
        .ok_or_else(|| refused("publication slot lacks actual collection acknowledgment"))?;
    if let Some(original) = &lease.collection {
        if *original != collected {
            return Err(refused(
                "publication collection changed its first acknowledgment",
            ));
        }
        return Ok(());
    }
    let closure = references::collected_publication_closure(tx, record)?;
    closure.verify_current(tx)?;
    let (mut capacity, previous_capacity) = current_capacity(tx, &record.metadata.scope)?;
    protected::verify_source_reference(tx, &previous_lease)?;
    protected::verify_source_reference(tx, &previous_capacity)?;
    lease.collection = Some(collected);
    lease.changes = 1;
    lease.validate(
        previous_lease
            .version()
            .checked_add(1)
            .ok_or_else(|| refused("publication lease revision exhausted"))?,
    )?;
    capacity.collected = capacity
        .collected
        .checked_add(1)
        .ok_or_else(|| refused("publication collection counter exhausted"))?;
    capacity.changes = capacity
        .changes
        .checked_add(1)
        .ok_or_else(|| refused("publication live counter exhausted"))?;
    capacity.validate(
        previous_capacity
            .version()
            .checked_add(1)
            .ok_or_else(|| refused("publication live revision exhausted"))?,
    )?;
    persist(
        tx,
        owner,
        &lease.account,
        previous_lease.record_key(),
        &lease,
        LEASE_BYTES,
    )?;
    persist(
        tx,
        owner,
        &capacity.account,
        previous_capacity.record_key(),
        &capacity,
        ACCOUNT_BYTES,
    )?;
    Ok(())
}

pub(in crate::admission_operation_store::knowledge) fn acknowledge_collection(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    scope: &RecoveryScopeV1,
    seal: &ArtifactBlobSealV1,
) -> Result<(), AdmissionOperationStoreError> {
    if lifecycle::logical_object(seal) {
        let key = object_key(scope, &seal.object)?;
        let identity = account(scope);
        let (pointer, source) =
            checked_row::<ObjectRecord>(tx, &key, &identity.scope_key()?, LEASE_BYTES)?;
        pointer.original.verify_historical_identity(tx)?;
        if source.version() != 1
            || pointer.identity.reference.scope != *scope
            || pointer.identity.object != seal.object
            || pointer.original.record_key() != pointer.publication
            || !protected::matches_historical_command_payload(
                tx,
                &key,
                source.scope_key(),
                1,
                &protected::encode(&pointer)?,
            )?
        {
            return Err(refused(
                "collection object pointer changed its original publication",
            ));
        }
        let record: NativeArtifactRecordV1 = load(tx, &pointer.publication)?
            .ok_or_else(|| refused("collection object publication disappeared"))?;
        if record_publication_key(&record)? != pointer.publication
            || !pointer.identity.matches_native_allocation(&record)?
            || record.seal.as_ref() != Some(seal)
        {
            return Err(refused("collection object changed its exact seal"));
        }
        let (lease, _) = current_lease(tx, &record)?;
        if pointer.identity != lease.identity || pointer.original != lease.original {
            return Err(refused(
                "collection pointer changed its original allocation source",
            ));
        }
        return retire_one(tx, owner, &record);
    }
    // Historical content-addressed storage can have several original owners.
    // Enumerate authentic sources without a lifetime bound or a count refund.
    let mut found = false;
    super::super::publication_census::visit_publication_sources(tx, scope, |record, _| {
        if record.metadata.scope == *scope && record.seal.as_ref() == Some(seal) {
            retire_one(tx, owner, record)?;
            found = true;
        }
        Ok(())
    })?;
    if !found {
        return Err(refused(
            "historical collection lost its exact publication owner",
        ));
    }
    Ok(())
}

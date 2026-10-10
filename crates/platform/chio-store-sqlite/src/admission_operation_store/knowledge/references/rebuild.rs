//! A fenced rebuild drains authenticated overflow into fresh bounded buckets.
use super::*;
use crate::admission_operation_store::knowledge::reference_source::VerifiedKnowledgeReferenceRebuildAuthority;

mod census;
use census::VerifiedKnowledgeReferenceRebuild;

pub(in crate::admission_operation_store) struct PreparedReferenceRebuild<'tx, 'conn> {
    source: VerifiedKnowledgeReferenceRebuild<'tx, 'conn>,
    writes: Vec<StagedReferenceUpdate>,
    footprint: ColdReferenceWriteFootprint,
}

/// The authority proof is minted by the native retained Admin writer. This
/// explicit cold path cannot use a publication or ordinary pin allowance.
pub(in crate::admission_operation_store) fn prepare_reference_rebuild<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    authority: VerifiedKnowledgeReferenceRebuildAuthority<'tx, 'conn>,
) -> Result<PreparedReferenceRebuild<'tx, 'conn>, AdmissionOperationStoreError> {
    let source = VerifiedKnowledgeReferenceRebuild::capture(tx, authority)?;
    let reference = source.reference();
    let identity = reference_identity(reference)?;
    let scope = scope_key(&reference.scope)?;
    let mut aggregate = source.aggregate().value.clone();
    let mut ordinal = aggregate.next_bucket.get();
    let mut inventory = Vec::new();
    let mut members = Vec::with_capacity(MAX_OWNERS_PER_BUCKET);
    let mut writes = Vec::new();
    let mut observed = 0_u64;
    source.visit_active_owners(|owner| {
        observed = observed
            .checked_add(1)
            .ok_or_else(|| refused("reference rebuild count overflow"))?;
        members.push(owner);
        if members.len() == MAX_OWNERS_PER_BUCKET {
            stage_bucket(tx, reference, ordinal, &mut members, &mut writes)?;
            inventory.push(SafeInteger::new(ordinal).map_err(refused)?);
            ordinal = ordinal
                .checked_add(1)
                .ok_or_else(|| refused("reference rebuild bucket ordinal exhausted"))?;
        }
        Ok(())
    })?;
    if observed != aggregate.active_owners.get() {
        return Err(refused("reference rebuild lost an active owner"));
    }
    if !members.is_empty() {
        stage_bucket(tx, reference, ordinal, &mut members, &mut writes)?;
        inventory.push(SafeInteger::new(ordinal).map_err(refused)?);
        ordinal = ordinal
            .checked_add(1)
            .ok_or_else(|| refused("reference rebuild bucket ordinal exhausted"))?;
    }
    aggregate.inventory = ReferenceInventory::Regular {
        active_buckets: BoundedList::new(inventory).map_err(refused)?,
    };
    aggregate.next_bucket = SafeInteger::new(ordinal).map_err(refused)?;
    aggregate.rebuilds = SafeInteger::new(1).map_err(refused)?;
    let version = source
        .aggregate()
        .head
        .version()
        .checked_add(1)
        .ok_or_else(|| refused("reference rebuild version exhausted"))?;
    aggregate.validate(version)?;
    writes.push(StagedReferenceUpdate::prepare(
        aggregate_key(identity),
        scope,
        Some(&source.aggregate().head),
        &aggregate,
    )?);
    if writes.len() > MAX_ACTIVE_REFERENCE_BUCKETS + 1 {
        return Err(refused("reference rebuild exceeds its bounded inventory"));
    }
    let bytes = writes.iter().try_fold(0_u64, |total, write| {
        total
            .checked_add(u64::try_from(write.payload().len()).map_err(refused)?)
            .ok_or_else(|| refused("reference rebuild byte footprint overflow"))
    })?;
    let records = u64::try_from(writes.len()).map_err(refused)?;
    let plan = PreparedReferenceRebuild {
        source,
        writes,
        footprint: ColdReferenceWriteFootprint::new(records, bytes),
    };
    plan.verify_current(tx)?;
    Ok(plan)
}

impl<'tx, 'conn> PreparedReferenceRebuild<'tx, 'conn> {
    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.source.transaction()
    }

    pub(in crate::admission_operation_store) fn reference(&self) -> &ArtifactVersionRefV1 {
        self.source.reference()
    }

    pub(in crate::admission_operation_store) fn write_footprint(
        &self,
    ) -> &ColdReferenceWriteFootprint {
        &self.footprint
    }

    pub(in crate::admission_operation_store) fn staged_updates(&self) -> &[StagedReferenceUpdate] {
        &self.writes
    }

    pub(in crate::admission_operation_store) fn verify_current(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.source.verify_current(tx)?;
        for write in &self.writes {
            match write.expected_version() {
                Some(expected) => {
                    if write.key() != self.source.aggregate().head.record_key()
                        || expected != self.source.aggregate().head.version()
                    {
                        return Err(refused("reference rebuild changed its owning aggregate"));
                    }
                }
                None => {
                    if protected::raw_checked(tx, write.key())?.is_some() {
                        return Err(refused("reference rebuild bucket ordinal was consumed"));
                    }
                }
            }
        }
        Ok(())
    }
}

fn stage_bucket(
    tx: &Connection,
    reference: &ArtifactVersionRefV1,
    ordinal: u64,
    members: &mut Vec<CanonicalPayloadDigest>,
    writes: &mut Vec<StagedReferenceUpdate>,
) -> Result<(), AdmissionOperationStoreError> {
    let key = bucket_key(reference_identity(reference)?, ordinal);
    if protected::raw_checked(tx, &key)?.is_some() {
        return Err(refused("reference rebuild would reuse a bucket ordinal"));
    }
    members.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    let value = ReferenceBucket {
        schema: ReferenceSchema::V1,
        reference: reference.clone(),
        bucket: SafeInteger::new(ordinal).map_err(refused)?,
        state: BucketState::Active,
        owners: BoundedList::new(std::mem::take(members)).map_err(refused)?,
    };
    value.validate()?;
    writes.push(StagedReferenceUpdate::prepare(
        key,
        scope_key(&reference.scope)?,
        None,
        &value,
    )?);
    Ok(())
}

impl std::fmt::Debug for PreparedReferenceRebuild<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedReferenceRebuild([redacted])")
    }
}

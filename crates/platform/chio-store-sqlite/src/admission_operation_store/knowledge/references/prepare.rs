//! Owning source proofs prepare bounded custody changes without writing them.
use super::*;
use crate::admission_operation_store::knowledge::reference_source::{
    VerifiedKnowledgeReferenceRetain, VerifiedKnowledgeReferenceRetirement,
};
use std::collections::BTreeMap;

pub(in crate::admission_operation_store) fn prepare_reference_retain<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    proof: VerifiedKnowledgeReferenceRetain<'tx, 'conn>,
) -> Result<PreparedReferenceUpdates<'tx, 'conn>, AdmissionOperationStoreError> {
    let source = OwningSource::Retain(proof);
    source.verify(tx)?;
    let references = unique_references(source.references())?;
    let mut heads = Vec::new();
    let mut writes = Vec::new();
    let mut accepted = 0_u64;
    for reference in references {
        let mut state = load_reference_state(tx, &reference)?;
        let existing = load_owner_leaf(tx, &reference, source.owner(), &state)?;
        if let Some(leaf) = existing {
            source.verify_original_anchor(tx, &leaf.value.original)?;
            if leaf.value.state == ReferenceOwnerState::Retired {
                return Err(refused("retired reference owner cannot be reacquired"));
            }
            // Exact retained ownership is a readback, including grandfathered
            // custody. It consumes no new owner or execution allowance.
            heads.push(leaf.head);
            retain_heads(state, &mut heads);
            continue;
        }
        if matches!(source.owner(), ReferenceOwner::LegacyPinSource { .. }) {
            return Err(refused("legacy reference owner requires its cold cohort"));
        }
        if matches!(
            &state.aggregate.value.inventory,
            ReferenceInventory::LegacyOverflow { .. }
        ) {
            return Err(refused("legacy reference overflow refuses fresh intake"));
        }
        let identity = reference_identity(&reference)?;
        let owner_identity = source.owner().identity(identity)?;
        let scope = scope_key(&reference.scope)?;
        let original = SourceAnchor::capture(source.source());
        original.validate_ordinary()?;
        let bucket = retain_bucket(tx, &reference, owner_identity, &mut state, &mut writes)?;
        let leaf = ReferenceLeaf {
            schema: ReferenceSchema::V1,
            reference: reference.clone(),
            owner: source.owner().clone(),
            original,
            location: ReferenceLocation::Bucket { bucket },
            state: ReferenceOwnerState::Active,
            retirement: None,
        };
        leaf.validate(1)?;
        writes.push(StagedReferenceUpdate::prepare(
            leaf_key(identity, owner_identity),
            scope.clone(),
            None,
            &leaf,
        )?);
        state.aggregate.value.accepted = increment(state.aggregate.value.accepted)?;
        state.aggregate.value.active_owners = increment(state.aggregate.value.active_owners)?;
        state
            .aggregate
            .value
            .validate(next_version(&state.aggregate.head)?)?;
        writes.push(StagedReferenceUpdate::prepare(
            aggregate_key(identity),
            scope,
            Some(&state.aggregate.head),
            &state.aggregate.value,
        )?);
        accepted = accepted
            .checked_add(1)
            .ok_or_else(|| refused("reference accepted batch count overflow"))?;
        retain_heads(state, &mut heads);
    }
    PreparedReferenceUpdates::prepare(tx, source, heads, writes, accepted, 0)
}

pub(in crate::admission_operation_store) fn prepare_reference_retirement<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    proof: VerifiedKnowledgeReferenceRetirement<'tx, 'conn>,
) -> Result<PreparedReferenceUpdates<'tx, 'conn>, AdmissionOperationStoreError> {
    let source = OwningSource::Retirement(proof);
    source.verify(tx)?;
    let references = unique_references(source.references())?;
    let mut heads = Vec::new();
    let mut writes = Vec::new();
    let mut retired = 0_u64;
    for reference in references {
        let mut state = load_reference_state(tx, &reference)?;
        let mut leaf = load_owner_leaf(tx, &reference, source.owner(), &state)?
            .ok_or_else(|| refused("reference retirement lacks its original owner"))?;
        source.verify_original_anchor(tx, &leaf.value.original)?;
        if leaf.value.state == ReferenceOwnerState::Retired {
            heads.push(leaf.head);
            retain_heads(state, &mut heads);
            continue;
        }
        let identity = reference_identity(&reference)?;
        let owner_identity = source.owner().identity(identity)?;
        if matches!(
            &state.aggregate.value.inventory,
            ReferenceInventory::Regular { .. }
        ) {
            retire_bucket(&reference, owner_identity, &mut state, &mut writes)?;
        }
        leaf.value.state = ReferenceOwnerState::Retired;
        leaf.value.retirement = Some(SourceAnchor::capture(source.source()));
        leaf.value.validate(next_version(&leaf.head)?)?;
        let scope = scope_key(&reference.scope)?;
        writes.push(StagedReferenceUpdate::prepare(
            leaf_key(identity, owner_identity),
            scope.clone(),
            Some(&leaf.head),
            &leaf.value,
        )?);
        state.aggregate.value.retired = increment(state.aggregate.value.retired)?;
        state.aggregate.value.active_owners = decrement(state.aggregate.value.active_owners)?;
        state
            .aggregate
            .value
            .validate(next_version(&state.aggregate.head)?)?;
        writes.push(StagedReferenceUpdate::prepare(
            aggregate_key(identity),
            scope,
            Some(&state.aggregate.head),
            &state.aggregate.value,
        )?);
        retired = retired
            .checked_add(1)
            .ok_or_else(|| refused("reference retired batch count overflow"))?;
        heads.push(leaf.head);
        retain_heads(state, &mut heads);
    }
    PreparedReferenceUpdates::prepare(tx, source, heads, writes, 0, retired)
}

fn retain_bucket(
    tx: &Connection,
    reference: &ArtifactVersionRefV1,
    owner: CanonicalPayloadDigest,
    state: &mut ReferenceState,
    writes: &mut Vec<StagedReferenceUpdate>,
) -> Result<SafeInteger, AdmissionOperationStoreError> {
    let identity = reference_identity(reference)?;
    let scope = scope_key(&reference.scope)?;
    if let Some(index) = state
        .buckets
        .iter()
        .position(|bucket| bucket.value.owners.as_slice().len() < MAX_OWNERS_PER_BUCKET)
    {
        let bucket = &mut state.buckets[index];
        let mut owners = bucket.value.owners.as_slice().to_vec();
        owners.push(owner);
        owners.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        bucket.value.owners = BoundedList::new(owners).map_err(refused)?;
        bucket.value.validate()?;
        writes.push(StagedReferenceUpdate::prepare(
            bucket_key(identity, bucket.value.bucket.get()),
            scope,
            Some(&bucket.head),
            &bucket.value,
        )?);
        return Ok(bucket.value.bucket);
    }
    let bucket = state.aggregate.value.next_bucket;
    let key = bucket_key(identity, bucket.get());
    if protected::raw_checked(tx, &key)?.is_some() {
        return Err(refused(
            "reference monotone bucket ordinal was already consumed",
        ));
    }
    let ReferenceInventory::Regular { active_buckets } = &state.aggregate.value.inventory else {
        return Err(refused("legacy reference overflow cannot allocate buckets"));
    };
    let mut inventory = active_buckets.as_slice().to_vec();
    inventory.push(bucket);
    state.aggregate.value.inventory = ReferenceInventory::Regular {
        active_buckets: BoundedList::new(inventory).map_err(refused)?,
    };
    state.aggregate.value.next_bucket = increment(bucket)?;
    let value = ReferenceBucket {
        schema: ReferenceSchema::V1,
        reference: reference.clone(),
        bucket,
        state: BucketState::Active,
        owners: BoundedList::new(vec![owner]).map_err(refused)?,
    };
    value.validate()?;
    writes.push(StagedReferenceUpdate::prepare(key, scope, None, &value)?);
    Ok(bucket)
}

fn retire_bucket(
    reference: &ArtifactVersionRefV1,
    owner: CanonicalPayloadDigest,
    state: &mut ReferenceState,
    writes: &mut Vec<StagedReferenceUpdate>,
) -> Result<(), AdmissionOperationStoreError> {
    let index = membership(state, owner)
        .ok_or_else(|| refused("reference retirement lost its active membership"))?;
    let bucket = &mut state.buckets[index];
    let mut owners = bucket.value.owners.as_slice().to_vec();
    owners.retain(|candidate| *candidate != owner);
    if owners.is_empty() {
        bucket.value.state = BucketState::Retired;
        let ReferenceInventory::Regular { active_buckets } = &state.aggregate.value.inventory
        else {
            return Err(refused("reference regular membership became overflow"));
        };
        let mut inventory = active_buckets.as_slice().to_vec();
        inventory.retain(|id| *id != bucket.value.bucket);
        state.aggregate.value.inventory = ReferenceInventory::Regular {
            active_buckets: BoundedList::new(inventory).map_err(refused)?,
        };
    }
    bucket.value.owners = BoundedList::new(owners).map_err(refused)?;
    bucket.value.validate()?;
    writes.push(StagedReferenceUpdate::prepare(
        bucket_key(reference_identity(reference)?, bucket.value.bucket.get()),
        scope_key(&reference.scope)?,
        Some(&bucket.head),
        &bucket.value,
    )?);
    Ok(())
}

fn unique_references(
    references: &[ArtifactVersionRefV1],
) -> Result<Vec<ArtifactVersionRefV1>, AdmissionOperationStoreError> {
    if references.len() > MAX_ARTIFACT_TRAVERSAL {
        return Err(refused(
            "reference batch exceeds its native traversal bound",
        ));
    }
    let mut unique = BTreeMap::new();
    for reference in references {
        let identity = *reference_identity(reference)?.as_bytes();
        if let Some(old) = unique.insert(identity, reference.clone()) {
            if old != *reference {
                return Err(refused("reference batch identity collision"));
            }
        }
    }
    Ok(unique.into_values().collect())
}

fn retain_heads(state: ReferenceState, heads: &mut Vec<protected::ProtectedSourceReference>) {
    heads.push(state.aggregate.head);
    heads.extend(state.buckets.into_iter().map(|bucket| bucket.head));
}

fn next_version(
    source: &protected::ProtectedSourceReference,
) -> Result<u64, AdmissionOperationStoreError> {
    source
        .version()
        .checked_add(1)
        .ok_or_else(|| refused("reference progress version exhausted"))
}

fn increment(value: SafeInteger) -> Result<SafeInteger, AdmissionOperationStoreError> {
    SafeInteger::new(
        value
            .get()
            .checked_add(1)
            .ok_or_else(|| refused("reference progress counter exhausted"))?,
    )
    .map_err(refused)
}

fn decrement(value: SafeInteger) -> Result<SafeInteger, AdmissionOperationStoreError> {
    SafeInteger::new(
        value
            .get()
            .checked_sub(1)
            .ok_or_else(|| refused("reference active owner counter underflow"))?,
    )
    .map_err(refused)
}

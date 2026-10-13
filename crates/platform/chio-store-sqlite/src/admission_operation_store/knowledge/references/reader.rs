//! Exact authenticated inventories replace lifetime pin-history scans.
use super::*;
use std::collections::BTreeSet;

pub(super) struct Indexed<T> {
    pub(super) value: T,
    pub(super) head: protected::ProtectedSourceReference,
}

pub(super) struct ReferenceState {
    pub(super) aggregate: Indexed<ReferenceAggregate>,
    pub(super) buckets: Vec<Indexed<ReferenceBucket>>,
}

pub(super) fn load_reference_state(
    tx: &Connection,
    reference: &ArtifactVersionRefV1,
) -> Result<ReferenceState, AdmissionOperationStoreError> {
    super::super::verify_reference_ready(tx, &reference.scope)?;
    let identity = reference_identity(reference)?;
    let key = aggregate_key(identity);
    let aggregate = indexed::<ReferenceAggregate>(tx, &key, &reference.scope)?
        .ok_or_else(|| refused("reference aggregate is not initialized"))?;
    if aggregate.value.reference != *reference {
        return Err(refused("reference aggregate changed its governed artifact"));
    }
    aggregate.value.validate(aggregate.head.version())?;
    super::super::verify_reference_baseline(tx, reference, &aggregate.value.baseline.source)?;
    if !protected::matches_historical_command_payload(
        tx,
        &key,
        aggregate.head.scope_key(),
        1,
        &protected::encode(&aggregate.value.original()?)?,
    )? {
        return Err(refused(
            "reference aggregate changed its immutable baseline",
        ));
    }
    let mut buckets = Vec::new();
    if let ReferenceInventory::Regular { active_buckets } = &aggregate.value.inventory {
        let mut owners = BTreeSet::new();
        let mut count = 0_u64;
        for id in active_buckets.as_slice() {
            let bucket =
                indexed::<ReferenceBucket>(tx, &bucket_key(identity, id.get()), &reference.scope)?
                    .ok_or_else(|| refused("reference active bucket disappeared"))?;
            bucket.value.validate()?;
            if bucket.value.reference != *reference
                || bucket.value.bucket != *id
                || bucket.value.state != BucketState::Active
            {
                return Err(refused("reference active bucket changed its identity"));
            }
            for owner in bucket.value.owners.as_slice() {
                if !owners.insert(*owner.as_bytes()) {
                    return Err(refused("reference owner occurs in multiple active buckets"));
                }
                count = count
                    .checked_add(1)
                    .ok_or_else(|| refused("reference active owner count overflow"))?;
            }
            buckets.push(bucket);
        }
        if count != aggregate.value.active_owners.get() {
            return Err(refused(
                "reference active inventory disagrees with its counters",
            ));
        }
    }
    Ok(ReferenceState { aggregate, buckets })
}

/// A zero is returned only from a ready, authenticated regular inventory.
/// Overflow remains a custody hold even after its one-way count reaches zero.
pub(in crate::admission_operation_store) fn active_reference_owner_count(
    tx: &Connection,
    reference: &ArtifactVersionRefV1,
) -> Result<u64, AdmissionOperationStoreError> {
    let state = load_reference_state(tx, reference)?;
    state.aggregate.value.collection_count()
}

/// This bounded observer counts authenticated product custody. Queue archival
/// does not retire a retained evidence owner or alter its immutable source.
#[cfg(feature = "admission-test-support")]
pub(in crate::admission_operation_store) fn active_product_evidence_owner_count(
    tx: &Transaction<'_>,
    reference: &ArtifactVersionRefV1,
) -> Result<usize, AdmissionOperationStoreError> {
    let state = load_reference_state(tx, reference)?;
    // An overflow has no bounded bucket inventory. It cannot report a clean
    // absence while its cold custody awaits an explicitly fenced rebuild.
    state.aggregate.value.collection_count()?;
    let identity = reference_identity(reference)?;
    let mut count = 0_usize;
    for bucket in &state.buckets {
        for owner_identity in bucket.value.owners.as_slice() {
            let key = leaf_key(identity, *owner_identity);
            let leaf = indexed::<ReferenceLeaf>(tx, &key, &reference.scope)?
                .ok_or_else(|| refused("product reference owner disappeared"))?;
            verify_owner_leaf(tx, reference, &key, &leaf, &state)?;
            if leaf.value.state != ReferenceOwnerState::Active {
                return Err(refused(
                    "product reference inventory retained a retired owner",
                ));
            }
            let evidence = match &leaf.value.owner {
                ReferenceOwner::ProductReport { scope, id, digest } => {
                    ProductEvidenceOwner::Report {
                        scope: scope.clone(),
                        id: id.clone(),
                        digest: *digest,
                    }
                }
                ReferenceOwner::ProductProposal { scope, id, digest } => {
                    ProductEvidenceOwner::Proposal {
                        scope: scope.clone(),
                        id: id.clone(),
                        digest: *digest,
                    }
                }
                _ => continue,
            };
            let source = super::super::super::product::verify_product_evidence_source(
                tx, &evidence, reference,
            )?;
            if leaf.value.original != SourceAnchor::capture(&source) {
                return Err(refused("product reference changed its immutable source"));
            }
            count = count
                .checked_add(1)
                .ok_or_else(|| refused("product reference owner count overflow"))?;
        }
    }
    Ok(count)
}

pub(super) fn load_owner_leaf(
    tx: &Connection,
    reference: &ArtifactVersionRefV1,
    owner: &ReferenceOwner,
    state: &ReferenceState,
) -> Result<Option<Indexed<ReferenceLeaf>>, AdmissionOperationStoreError> {
    let identity = reference_identity(reference)?;
    let owner_identity = owner.identity(identity)?;
    let key = leaf_key(identity, owner_identity);
    let Some(leaf) = indexed::<ReferenceLeaf>(tx, &key, &reference.scope)? else {
        if membership(state, owner_identity).is_some() {
            return Err(refused("reference indexed owner disappeared"));
        }
        return Ok(None);
    };
    verify_owner_leaf(tx, reference, &key, &leaf, state)?;
    if leaf.value.owner != *owner {
        return Err(refused("reference owner leaf changed its logical identity"));
    }
    Ok(Some(leaf))
}

/// Cold rebuilds use the same leaf identity and immutable-source validation as
/// hot exact-owner reads. Decoding an owner cannot grant a mutation role.
pub(super) fn verify_owner_leaf(
    tx: &Connection,
    reference: &ArtifactVersionRefV1,
    key: &str,
    leaf: &Indexed<ReferenceLeaf>,
    state: &ReferenceState,
) -> Result<(), AdmissionOperationStoreError> {
    let identity = reference_identity(reference)?;
    let owner_identity = leaf.value.owner.identity(identity)?;
    leaf.value.validate(leaf.head.version())?;
    if leaf.value.reference != *reference || leaf_key(identity, owner_identity) != key {
        return Err(refused("reference owner leaf changed its logical identity"));
    }
    let mut original = leaf.value.clone();
    original.state = ReferenceOwnerState::Active;
    original.retirement = None;
    if !protected::matches_historical_command_payload(
        tx,
        key,
        leaf.head.scope_key(),
        1,
        &protected::encode(&original)?,
    )? {
        return Err(refused(
            "reference owner changed its immutable first source",
        ));
    }
    leaf.value.original.verify_historical_identity(tx)?;
    if let Some(retirement) = &leaf.value.retirement {
        retirement.verify_historical_identity(tx)?;
    }
    match &leaf.value.location {
        ReferenceLocation::Bucket { bucket } => {
            if matches!(
                state.aggregate.value.inventory,
                ReferenceInventory::LegacyOverflow { .. }
            ) {
                return Err(refused("ordinary reference leaf entered legacy overflow"));
            }
            if leaf.value.state == ReferenceOwnerState::Active {
                let index = membership(state, owner_identity)
                    .ok_or_else(|| refused("reference active leaf lost its bucket"))?;
                if state.buckets[index].value.bucket != *bucket {
                    return Err(refused("reference active leaf changed its bucket"));
                }
            }
        }
        ReferenceLocation::LegacyCohort { cohort, census } => {
            let ReferenceBaselineSource::Cold {
                cutoff,
                cohort_digest,
                census_digest,
                ..
            } = &state.aggregate.value.baseline.source
            else {
                return Err(refused("legacy reference leaf lacks its cold baseline"));
            };
            if cohort != cohort_digest
                || census != census_digest
                || leaf.value.original.global_commit_sequence() > cutoff.sequence()
            {
                return Err(refused("legacy reference leaf changed its census"));
            }
            if matches!(
                state.aggregate.value.inventory,
                ReferenceInventory::Regular { .. }
            ) && leaf.value.state == ReferenceOwnerState::Active
                && membership(state, owner_identity).is_none()
            {
                return Err(refused("legacy active leaf lost its rebuilt bucket"));
            }
        }
    }
    if leaf.value.state == ReferenceOwnerState::Retired
        && membership(state, owner_identity).is_some()
    {
        return Err(refused(
            "retired reference owner remains in active inventory",
        ));
    }
    Ok(())
}

pub(super) fn membership(state: &ReferenceState, owner: CanonicalPayloadDigest) -> Option<usize> {
    state
        .buckets
        .iter()
        .position(|bucket| bucket.value.owners.as_slice().contains(&owner))
}

pub(super) fn indexed<T: Serialize + serde::de::DeserializeOwned>(
    tx: &Connection,
    key: &str,
    scope: &RecoveryScopeV1,
) -> Result<Option<Indexed<T>>, AdmissionOperationStoreError> {
    let Some(row) = protected::raw_checked(tx, key)? else {
        return Ok(None);
    };
    let head = protected::source_reference(tx, key)?;
    let header_is_local: bool = tx
        .query_row(
            "SELECT native_namespace IS NULL AND native_request IS NULL
             FROM admission_operation_recovery_records WHERE record_key=?1",
            [key],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if row.scope != scope_key(scope)?
        || row.kind != "command"
        || row.version != head.version()
        || head.scope_key() != row.scope
        || head.kind() != "command"
        || !header_is_local
    {
        return Err(refused(
            "reference indexed record changed its protected header",
        ));
    }
    Ok(Some(Indexed {
        value: protected::decode(&row.payload)?,
        head,
    }))
}

//! Baselines are created only from affine metadata or complete cold proofs.
use super::*;
use crate::admission_operation_store::knowledge::reference_source::{
    ReferenceCutoff, VerifiedKnowledgeReferenceColdCohort, VerifiedNewArtifactReferenceBaseline,
};
use std::ops::Deref;

pub(in crate::admission_operation_store) struct PreparedNewArtifactReferenceBaseline<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    source: VerifiedNewArtifactReferenceBaseline<'tx, 'conn>,
    write: StagedReferenceUpdate,
}

pub(in crate::admission_operation_store) fn prepare_new_artifact_reference_baseline<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    proof: VerifiedNewArtifactReferenceBaseline<'tx, 'conn>,
) -> Result<PreparedNewArtifactReferenceBaseline<'tx, 'conn>, AdmissionOperationStoreError> {
    proof.verify(tx)?;
    let source = SourceAnchor::capture(proof.source());
    source.validate_ordinary()?;
    let inventory = ReferenceInventory::Regular {
        active_buckets: BoundedList::new(vec![]).map_err(refused)?,
    };
    let value = ReferenceAggregate {
        schema: ReferenceSchema::V1,
        reference: proof.reference().clone(),
        baseline: ReferenceBaseline {
            source: ReferenceBaselineSource::NewArtifact { source },
            active_owners: SafeInteger::ZERO,
            next_bucket: SafeInteger::new(1).map_err(refused)?,
            inventory: inventory.clone(),
        },
        accepted: SafeInteger::ZERO,
        retired: SafeInteger::ZERO,
        rebuilds: SafeInteger::ZERO,
        active_owners: SafeInteger::ZERO,
        next_bucket: SafeInteger::new(1).map_err(refused)?,
        inventory,
    };
    value.validate(1)?;
    let write = StagedReferenceUpdate::prepare(
        aggregate_key(reference_identity(proof.reference())?),
        scope_key(&proof.reference().scope)?,
        None,
        &value,
    )?;
    let plan = PreparedNewArtifactReferenceBaseline {
        transaction: tx,
        source: proof,
        write,
    };
    plan.verify_current(tx)?;
    Ok(plan)
}

impl<'tx, 'conn> PreparedNewArtifactReferenceBaseline<'tx, 'conn> {
    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.transaction
    }

    pub(in crate::admission_operation_store) fn reference(&self) -> &ArtifactVersionRefV1 {
        self.source.reference()
    }

    pub(in crate::admission_operation_store) fn owner_source(
        &self,
    ) -> &protected::ProtectedSourceReference {
        self.source.source()
    }

    pub(in crate::admission_operation_store) fn staged_update(&self) -> &StagedReferenceUpdate {
        &self.write
    }

    pub(in crate::admission_operation_store) fn verify_current(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        verify_writer(self.transaction, tx)?;
        self.source.verify(tx)?;
        ready_reference_account(tx, &self.reference().scope)?;
        if protected::raw_checked(tx, self.write.key())?.is_some() {
            return Err(refused("new artifact reference baseline already exists"));
        }
        Ok(())
    }
}

/// Cold plans own the authenticated complete census, not a Vec of all owners.
pub(in crate::admission_operation_store) struct PreparedColdReferenceBaseline<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    source: VerifiedKnowledgeReferenceColdCohort<'tx, 'conn>,
    aggregate: ReferenceAggregate,
    footprint: ColdReferenceWriteFootprint,
}

pub(in crate::admission_operation_store) struct ColdReferenceWriteFootprint {
    record_count: u64,
    encoded_bytes: u64,
}

impl ColdReferenceWriteFootprint {
    pub(super) fn new(record_count: u64, encoded_bytes: u64) -> Self {
        Self {
            record_count,
            encoded_bytes,
        }
    }

    pub(in crate::admission_operation_store) fn record_count(&self) -> u64 {
        self.record_count
    }

    pub(in crate::admission_operation_store) fn event_count(&self) -> u64 {
        self.record_count
    }

    pub(in crate::admission_operation_store) fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
}

pub(in crate::admission_operation_store) fn prepare_cold_reference_baseline<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    proof: VerifiedKnowledgeReferenceColdCohort<'tx, 'conn>,
) -> Result<PreparedColdReferenceBaseline<'tx, 'conn>, AdmissionOperationStoreError> {
    proof.verify(tx)?;
    let aggregate = cold_aggregate(&proof)?;
    let mut plan = PreparedColdReferenceBaseline {
        transaction: tx,
        source: proof,
        aggregate,
        footprint: ColdReferenceWriteFootprint {
            record_count: 0,
            encoded_bytes: 0,
        },
    };
    plan.verify_current(tx)?;
    let mut records = 0_u64;
    let mut bytes = 0_u64;
    plan.visit_staged_updates(tx, |write| {
        records = records
            .checked_add(1)
            .ok_or_else(|| refused("cold reference record count overflow"))?;
        bytes = bytes
            .checked_add(u64::try_from(write.payload().len()).map_err(refused)?)
            .ok_or_else(|| refused("cold reference byte count overflow"))?;
        Ok(())
    })?;
    plan.footprint = ColdReferenceWriteFootprint {
        record_count: records,
        encoded_bytes: bytes,
    };
    Ok(plan)
}

impl<'tx, 'conn> PreparedColdReferenceBaseline<'tx, 'conn> {
    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.transaction
    }

    pub(in crate::admission_operation_store) fn reference(&self) -> &ArtifactVersionRefV1 {
        self.source.reference()
    }

    pub(in crate::admission_operation_store) fn baseline_active_owners(&self) -> u64 {
        self.source.baseline_active_count()
    }

    pub(in crate::admission_operation_store) fn global_cutoff(&self) -> &ReferenceCutoff {
        self.source.cutoff()
    }

    pub(in crate::admission_operation_store) fn census_digest(&self) -> CanonicalPayloadDigest {
        self.source.census_digest()
    }

    pub(in crate::admission_operation_store) fn cohort_digest(&self) -> CanonicalPayloadDigest {
        self.source.cohort_digest()
    }

    pub(in crate::admission_operation_store) fn write_footprint(
        &self,
    ) -> &ColdReferenceWriteFootprint {
        &self.footprint
    }

    pub(in crate::admission_operation_store) fn verify_current(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        verify_writer(self.transaction, tx)?;
        self.source.verify(tx)?;
        if protected::raw_checked(tx, &aggregate_key(reference_identity(self.reference())?))?
            .is_some()
        {
            return Err(refused("cold reference aggregate already exists"));
        }
        Ok(())
    }

    /// Individual leaves are streamed after complete source authentication.
    /// Regular grouping keeps only sixty-four digests, independent of source
    /// key lengths and immutable historical record count.
    pub(in crate::admission_operation_store) fn visit_staged_updates(
        &self,
        tx: &Transaction<'conn>,
        mut visit: impl FnMut(&StagedReferenceUpdate) -> Result<(), AdmissionOperationStoreError>,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.verify_current(tx)?;
        visit_cold_initial_updates(&self.source, &self.aggregate, |write| {
            if protected::raw_checked(tx, write.key())?.is_some() {
                return Err(refused("cold reference staged slot already exists"));
            }
            visit(write)
        })
    }
}

/// Pending activation reads require the same affine complete cold proof. This
/// verifies durable first rows without granting hot reads before readiness.
pub(in crate::admission_operation_store) fn verify_committed_cold_baseline<'conn>(
    tx: &Transaction<'conn>,
    proof: &VerifiedKnowledgeReferenceColdCohort<'_, 'conn>,
) -> Result<(), AdmissionOperationStoreError> {
    proof.verify(tx)?;
    let aggregate = cold_aggregate(proof)?;
    let mut expected_records = 0_u64;
    visit_cold_initial_updates(proof, &aggregate, |write| {
        verify_initial_cold_record(tx, proof, write)?;
        expected_records = expected_records
            .checked_add(1)
            .ok_or_else(|| refused("cold reference completion count overflow"))?;
        Ok(())
    })?;
    let identity = hex::encode(reference_identity(proof.reference())?.as_bytes());
    let key = aggregate_key(reference_identity(proof.reference())?);
    let leaf_pattern = format!("knowledge-reference-owner:{identity}:*");
    let bucket_pattern = format!("knowledge-reference-bucket:{identity}:*");
    let observed: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM (
              SELECT record_key FROM admission_operation_recovery_records
               WHERE record_key=?1 OR record_key GLOB ?2 OR record_key GLOB ?3
              UNION SELECT record_key FROM admission_operation_recovery_events
               WHERE record_key=?1 OR record_key GLOB ?2 OR record_key GLOB ?3
              UNION SELECT projection_key FROM authority_global_commits
               WHERE projection_kind='recovery' AND
                (projection_key=?1 OR projection_key GLOB ?2 OR projection_key GLOB ?3)
             )",
            params![key, leaf_pattern, bucket_pattern],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if u64::try_from(observed).map_err(refused)? != expected_records {
        return Err(refused(
            "cold reference completion has an unexpected inventory",
        ));
    }
    proof.verify(tx)
}

fn verify_initial_cold_record(
    tx: &Connection,
    proof: &VerifiedKnowledgeReferenceColdCohort<'_, '_>,
    expected: &StagedReferenceUpdate,
) -> Result<(), AdmissionOperationStoreError> {
    let row = protected::raw_checked(tx, expected.key())?
        .ok_or_else(|| refused("cold reference completion lost a first row"))?;
    let source = protected::source_reference(tx, expected.key())?;
    let local_header: bool = tx
        .query_row(
            "SELECT native_namespace IS NULL AND native_request IS NULL
             FROM admission_operation_recovery_records WHERE record_key=?1",
            [expected.key()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if row.kind != "command"
        || row.scope != expected.scope()
        || row.version != 1
        || row.payload.as_slice() != expected.payload()
        || source.kind() != "command"
        || source.scope_key() != expected.scope()
        || source.version() != 1
        || source.global_commit_sequence() <= proof.cutoff().sequence()
        || !local_header
        || !protected::matches_historical_command_payload(
            tx,
            expected.key(),
            expected.scope(),
            1,
            expected.payload(),
        )?
    {
        return Err(refused(
            "cold reference completion changed its first inventory",
        ));
    }
    Ok(())
}

fn cold_aggregate(
    proof: &VerifiedKnowledgeReferenceColdCohort<'_, '_>,
) -> Result<ReferenceAggregate, AdmissionOperationStoreError> {
    let active = proof.baseline_active_count();
    let cohort = proof.cohort_digest();
    let census = proof.census_digest();
    let (inventory, next_bucket) = if active > MAX_ACTIVE_REFERENCE_OWNERS {
        (
            ReferenceInventory::LegacyOverflow { cohort, census },
            SafeInteger::new(1).map_err(refused)?,
        )
    } else {
        let count = active.div_ceil(MAX_OWNERS_PER_BUCKET as u64);
        let buckets = (1..=count)
            .map(SafeInteger::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(refused)?;
        (
            ReferenceInventory::Regular {
                active_buckets: BoundedList::new(buckets).map_err(refused)?,
            },
            SafeInteger::new(count + 1).map_err(refused)?,
        )
    };
    let aggregate = ReferenceAggregate {
        schema: ReferenceSchema::V1,
        reference: proof.reference().clone(),
        baseline: ReferenceBaseline {
            source: ReferenceBaselineSource::Cold {
                cutoff: proof.cutoff().clone(),
                cohort_digest: cohort,
                census_digest: census,
            },
            active_owners: SafeInteger::new(active).map_err(refused)?,
            next_bucket,
            inventory: inventory.clone(),
        },
        accepted: SafeInteger::ZERO,
        retired: SafeInteger::ZERO,
        rebuilds: SafeInteger::ZERO,
        active_owners: SafeInteger::new(active).map_err(refused)?,
        next_bucket,
        inventory,
    };
    aggregate.validate(1)?;
    Ok(aggregate)
}

fn visit_cold_initial_updates(
    proof: &VerifiedKnowledgeReferenceColdCohort<'_, '_>,
    aggregate: &ReferenceAggregate,
    mut visit: impl FnMut(&StagedReferenceUpdate) -> Result<(), AdmissionOperationStoreError>,
) -> Result<(), AdmissionOperationStoreError> {
    let reference = proof.reference();
    let identity = reference_identity(reference)?;
    let scope = scope_key(&reference.scope)?;
    let regular = matches!(&aggregate.inventory, ReferenceInventory::Regular { .. });
    let cohort = proof.cohort_digest();
    let census = proof.census_digest();
    let mut ordinal = 1_u64;
    let mut observed = 0_u64;
    let mut members = Vec::with_capacity(MAX_OWNERS_PER_BUCKET);
    proof.visit_active_owners(|owner, original| {
        observed = observed
            .checked_add(1)
            .ok_or_else(|| refused("cold reference census count overflow"))?;
        let owner_identity = owner.identity(identity)?;
        let leaf = ReferenceLeaf {
            schema: ReferenceSchema::V1,
            reference: reference.clone(),
            owner: owner.clone(),
            original: original.clone(),
            location: if regular {
                ReferenceLocation::Bucket {
                    bucket: SafeInteger::new(ordinal).map_err(refused)?,
                }
            } else {
                ReferenceLocation::LegacyCohort { cohort, census }
            },
            state: ReferenceOwnerState::Active,
            retirement: None,
        };
        leaf.validate(1)?;
        let key = leaf_key(identity, owner_identity);
        visit(&StagedReferenceUpdate::prepare(
            key,
            scope.clone(),
            None,
            &leaf,
        )?)?;
        if regular {
            members.push(owner_identity);
            if members.len() == MAX_OWNERS_PER_BUCKET {
                visit_cold_bucket(reference, ordinal, &mut members, &mut visit)?;
                ordinal = ordinal
                    .checked_add(1)
                    .ok_or_else(|| refused("cold reference bucket ordinal exhausted"))?;
            }
        }
        Ok(())
    })?;
    if observed != proof.baseline_active_count() {
        return Err(refused("cold reference census changed during staging"));
    }
    if regular && !members.is_empty() {
        visit_cold_bucket(reference, ordinal, &mut members, &mut visit)?;
    }
    visit(&StagedReferenceUpdate::prepare(
        aggregate_key(identity),
        scope,
        None,
        aggregate,
    )?)
}

fn visit_cold_bucket(
    reference: &ArtifactVersionRefV1,
    ordinal: u64,
    members: &mut Vec<CanonicalPayloadDigest>,
    visit: &mut impl FnMut(&StagedReferenceUpdate) -> Result<(), AdmissionOperationStoreError>,
) -> Result<(), AdmissionOperationStoreError> {
    let key = bucket_key(reference_identity(reference)?, ordinal);
    let mut owners = std::mem::take(members);
    owners.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    let value = ReferenceBucket {
        schema: ReferenceSchema::V1,
        reference: reference.clone(),
        bucket: SafeInteger::new(ordinal).map_err(refused)?,
        state: BucketState::Active,
        owners: BoundedList::new(owners).map_err(refused)?,
    };
    value.validate()?;
    visit(&StagedReferenceUpdate::prepare(
        key,
        scope_key(&reference.scope)?,
        None,
        &value,
    )?)
}

fn verify_writer<'conn>(
    original: &Transaction<'conn>,
    current: &Transaction<'conn>,
) -> Result<(), AdmissionOperationStoreError> {
    if !std::ptr::eq::<Connection>(Deref::deref(original), Deref::deref(current)) {
        return Err(refused("reference baseline changed its physical writer"));
    }
    Ok(())
}

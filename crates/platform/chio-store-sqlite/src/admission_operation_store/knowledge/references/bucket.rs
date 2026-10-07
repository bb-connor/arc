//! Active inventories are bounded independently of immutable owner evidence.
use super::*;
use crate::admission_operation_store::knowledge::reference_source::ReferenceCutoff;

pub(super) const MAX_OWNERS_PER_BUCKET: usize = 64;
pub(super) const MAX_ACTIVE_REFERENCE_BUCKETS: usize = 64;
pub(super) const MAX_ACTIVE_REFERENCE_OWNERS: u64 = 4096;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReferenceBaseline {
    pub(super) source: ReferenceBaselineSource,
    pub(super) active_owners: SafeInteger,
    pub(super) next_bucket: SafeInteger,
    pub(super) inventory: ReferenceInventory,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "origin", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::admission_operation_store) enum ReferenceBaselineSource {
    NewArtifact {
        source: SourceAnchor,
    },
    Cold {
        cutoff: ReferenceCutoff,
        cohort_digest: CanonicalPayloadDigest,
        census_digest: CanonicalPayloadDigest,
    },
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "inventory", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ReferenceInventory {
    Regular {
        active_buckets: BoundedList<SafeInteger, MAX_ACTIVE_REFERENCE_BUCKETS>,
    },
    LegacyOverflow {
        cohort: CanonicalPayloadDigest,
        census: CanonicalPayloadDigest,
    },
}

impl ReferenceInventory {
    pub(super) fn validate(
        &self,
        active: u64,
        next: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if next == 0 {
            return Err(refused("reference bucket ordinal exhausted"));
        }
        match self {
            Self::Regular { active_buckets } => {
                let ids = active_buckets.as_slice();
                let count = u64::try_from(ids.len())
                    .map_err(|_| refused("reference inventory count overflow"))?;
                let capacity = count
                    .checked_mul(MAX_OWNERS_PER_BUCKET as u64)
                    .ok_or_else(|| refused("reference inventory capacity overflow"))?;
                if active > MAX_ACTIVE_REFERENCE_OWNERS
                    || active < count
                    || active > capacity
                    || (active == 0) != ids.is_empty()
                    || ids.iter().any(|id| id.get() == 0 || id.get() >= next)
                    || ids.windows(2).any(|pair| pair[0] >= pair[1])
                {
                    return Err(refused("reference active bucket inventory"));
                }
            }
            Self::LegacyOverflow { .. } => {}
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReferenceAggregate {
    pub(super) schema: ReferenceSchema,
    pub(super) reference: ArtifactVersionRefV1,
    pub(super) baseline: ReferenceBaseline,
    pub(super) accepted: SafeInteger,
    pub(super) retired: SafeInteger,
    pub(super) rebuilds: SafeInteger,
    pub(super) active_owners: SafeInteger,
    pub(super) next_bucket: SafeInteger,
    pub(super) inventory: ReferenceInventory,
}

impl ReferenceAggregate {
    pub(super) fn collection_count(&self) -> Result<u64, AdmissionOperationStoreError> {
        match &self.inventory {
            ReferenceInventory::Regular { .. } => Ok(self.active_owners.get()),
            ReferenceInventory::LegacyOverflow { .. } => {
                Err(refused("legacy reference census requires a fenced rebuild"))
            }
        }
    }

    pub(super) fn validate(&self, version: u64) -> Result<(), AdmissionOperationStoreError> {
        let accepted = self.accepted.get();
        let retired = self.retired.get();
        let total = self
            .baseline
            .active_owners
            .get()
            .checked_add(accepted)
            .ok_or_else(|| refused("reference accepted counter overflow"))?;
        let active = total
            .checked_sub(retired)
            .ok_or_else(|| refused("reference retirement counter underflow"))?;
        let expected_version = 1_u64
            .checked_add(accepted)
            .and_then(|value| value.checked_add(retired))
            .and_then(|value| value.checked_add(self.rebuilds.get()))
            .ok_or_else(|| refused("reference aggregate version overflow"))?;
        if self.active_owners.get() != active
            || version != expected_version
            || self.next_bucket < self.baseline.next_bucket
        {
            return Err(refused("reference aggregate counter identity"));
        }
        self.baseline.inventory.validate(
            self.baseline.active_owners.get(),
            self.baseline.next_bucket.get(),
        )?;
        self.inventory.validate(active, self.next_bucket.get())?;
        match &self.baseline.source {
            ReferenceBaselineSource::NewArtifact { source } => {
                source.validate()?;
                if self.baseline.active_owners.get() != 0
                    || self.baseline.next_bucket.get() != 1
                    || !matches!(
                        &self.baseline.inventory,
                        ReferenceInventory::Regular { active_buckets }
                            if active_buckets.as_slice().is_empty()
                    )
                {
                    return Err(refused("new artifact reference baseline was not empty"));
                }
            }
            ReferenceBaselineSource::Cold {
                cohort_digest,
                census_digest,
                ..
            } => {
                if let ReferenceInventory::LegacyOverflow { cohort, census } =
                    &self.baseline.inventory
                {
                    if cohort != cohort_digest || census != census_digest {
                        return Err(refused("legacy reference overflow changed its cohort"));
                    }
                }
            }
        }
        match (&self.baseline.inventory, &self.inventory) {
            (ReferenceInventory::Regular { .. }, ReferenceInventory::Regular { .. }) => {
                if self.rebuilds.get() != 0 {
                    return Err(refused("ordinary reference inventory cannot reset"));
                }
            }
            (
                ReferenceInventory::LegacyOverflow { .. },
                ReferenceInventory::LegacyOverflow { .. },
            ) => {
                if self.baseline.active_owners.get() <= MAX_ACTIVE_REFERENCE_OWNERS
                    || self.inventory != self.baseline.inventory
                    || accepted != 0
                    || self.rebuilds.get() != 0
                    || self.next_bucket != self.baseline.next_bucket
                {
                    return Err(refused("legacy reference overflow changed its census"));
                }
            }
            (ReferenceInventory::LegacyOverflow { .. }, ReferenceInventory::Regular { .. }) => {
                if self.baseline.active_owners.get() <= MAX_ACTIVE_REFERENCE_OWNERS
                    || self.rebuilds.get() != 1
                {
                    return Err(refused("legacy reference rebuild identity"));
                }
            }
            (ReferenceInventory::Regular { .. }, ReferenceInventory::LegacyOverflow { .. }) => {
                return Err(refused(
                    "ordinary reference inventory became legacy overflow",
                ));
            }
        }
        Ok(())
    }

    /// The owning reader compares this exact body with its authenticated first
    /// event. Current counters cannot choose a new baseline or census.
    pub(super) fn original(&self) -> Result<Self, AdmissionOperationStoreError> {
        let zero = SafeInteger::new(0).map_err(refused)?;
        Ok(Self {
            schema: self.schema.clone(),
            reference: self.reference.clone(),
            baseline: self.baseline.clone(),
            accepted: zero,
            retired: zero,
            rebuilds: zero,
            active_owners: self.baseline.active_owners,
            next_bucket: self.baseline.next_bucket,
            inventory: self.baseline.inventory.clone(),
        })
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReferenceBucket {
    pub(super) schema: ReferenceSchema,
    pub(super) reference: ArtifactVersionRefV1,
    pub(super) bucket: SafeInteger,
    pub(super) state: BucketState,
    pub(super) owners: BoundedList<CanonicalPayloadDigest, MAX_OWNERS_PER_BUCKET>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum BucketState {
    Active,
    Retired,
}

impl ReferenceBucket {
    pub(super) fn validate(&self) -> Result<(), AdmissionOperationStoreError> {
        if self.bucket.get() == 0
            || (self.state == BucketState::Retired) != self.owners.as_slice().is_empty()
            || self
                .owners
                .as_slice()
                .windows(2)
                .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        {
            return Err(refused("reference active bucket"));
        }
        Ok(())
    }
}

/// A legacy leaf retains its original cohort location after a fenced rebuild.
/// Current regular membership is resolved from authenticated bounded buckets.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "location", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ReferenceLocation {
    Bucket {
        bucket: SafeInteger,
    },
    LegacyCohort {
        cohort: CanonicalPayloadDigest,
        census: CanonicalPayloadDigest,
    },
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReferenceLeaf {
    pub(super) schema: ReferenceSchema,
    pub(super) reference: ArtifactVersionRefV1,
    pub(super) owner: ReferenceOwner,
    pub(super) original: SourceAnchor,
    pub(super) location: ReferenceLocation,
    pub(super) state: ReferenceOwnerState,
    pub(super) retirement: Option<SourceAnchor>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReferenceOwnerState {
    Active,
    Retired,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(super) enum ReferenceSchema {
    #[serde(rename = "chio.knowledge.reference-index.v1")]
    V1,
}

impl ReferenceLeaf {
    pub(super) fn validate(&self, version: u64) -> Result<(), AdmissionOperationStoreError> {
        self.original.validate()?;
        if self.owner.scope().authority_domain != self.reference.scope.authority_domain
            || self.owner.scope().tenant_id != self.reference.scope.tenant_id
            || self.original.scope_key() != scope_key(self.owner.scope())?
            || (self.state == ReferenceOwnerState::Retired) != self.retirement.is_some()
            || version
                != if self.state == ReferenceOwnerState::Retired {
                    2
                } else {
                    1
                }
        {
            return Err(refused("reference owner leaf identity"));
        }
        match &self.location {
            ReferenceLocation::Bucket { bucket } if bucket.get() == 0 => {
                return Err(refused("reference leaf bucket ordinal"));
            }
            ReferenceLocation::LegacyCohort { .. } => {}
            ReferenceLocation::Bucket { .. } => {}
        }
        if let ReferenceOwner::LegacyPinSource { original, .. } = &self.owner {
            if *original != self.original {
                return Err(refused("legacy reference owner changed its source"));
            }
        }
        if let Some(retirement) = &self.retirement {
            retirement.validate()?;
            if retirement.scope_key() != self.original.scope_key()
                || retirement.global_commit_sequence() < self.original.global_commit_sequence()
            {
                return Err(refused("reference retirement source ordering"));
            }
        }
        Ok(())
    }
}

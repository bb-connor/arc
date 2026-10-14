//! Active inventories are bounded independently of immutable owner evidence.
use super::*;

pub(super) const MAX_OWNERS_PER_BUCKET: usize = 64;
pub(super) const MAX_ACTIVE_REFERENCE_BUCKETS: usize = 64;
pub(super) const MAX_ACTIVE_REFERENCE_OWNERS: u64 = 4096;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReferenceInventory {
    pub(super) active_buckets: BoundedList<SafeInteger, MAX_ACTIVE_REFERENCE_BUCKETS>,
}

impl ReferenceInventory {
    pub(super) fn validate(
        &self,
        active: u64,
        next: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        let ids = self.active_buckets.as_slice();
        let count =
            u64::try_from(ids.len()).map_err(|_| refused("reference inventory count overflow"))?;
        let capacity = count
            .checked_mul(MAX_OWNERS_PER_BUCKET as u64)
            .ok_or_else(|| refused("reference inventory capacity overflow"))?;
        if next == 0
            || active > MAX_ACTIVE_REFERENCE_OWNERS
            || active < count
            || active > capacity
            || (active == 0) != ids.is_empty()
            || ids.iter().any(|id| id.get() == 0 || id.get() >= next)
            || ids.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(refused("reference active bucket inventory"));
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReferenceAggregate {
    pub(super) schema: ReferenceSchema,
    pub(super) reference: ArtifactVersionRefV1,
    pub(super) source: SourceAnchor,
    pub(super) accepted: SafeInteger,
    pub(super) retired: SafeInteger,
    pub(super) active_owners: SafeInteger,
    pub(super) next_bucket: SafeInteger,
    pub(super) inventory: ReferenceInventory,
}

impl ReferenceAggregate {
    pub(super) fn validate(&self, version: u64) -> Result<(), AdmissionOperationStoreError> {
        let accepted = self.accepted.get();
        let retired = self.retired.get();
        let active = accepted
            .checked_sub(retired)
            .ok_or_else(|| refused("reference retirement counter underflow"))?;
        let expected_version = 1_u64
            .checked_add(accepted)
            .and_then(|value| value.checked_add(retired))
            .ok_or_else(|| refused("reference aggregate version overflow"))?;
        if self.active_owners.get() != active || version != expected_version {
            return Err(refused("reference aggregate counter identity"));
        }
        self.source.validate_ordinary()?;
        self.inventory.validate(active, self.next_bucket.get())?;
        Ok(())
    }

    /// The owning reader compares this exact body with its authenticated first
    /// event. Current counters cannot choose a new baseline or census.
    pub(super) fn original(&self) -> Result<Self, AdmissionOperationStoreError> {
        let zero = SafeInteger::new(0).map_err(refused)?;
        Ok(Self {
            schema: self.schema.clone(),
            reference: self.reference.clone(),
            source: self.source.clone(),
            accepted: zero,
            retired: zero,
            active_owners: zero,
            next_bucket: SafeInteger::new(1).map_err(refused)?,
            inventory: ReferenceInventory {
                active_buckets: BoundedList::new(vec![]).map_err(refused)?,
            },
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

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReferenceLeaf {
    pub(super) schema: ReferenceSchema,
    pub(super) reference: ArtifactVersionRefV1,
    pub(super) owner: ReferenceOwner,
    pub(super) original: SourceAnchor,
    pub(super) bucket: SafeInteger,
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
        if self.bucket.get() == 0 {
            return Err(refused("reference leaf bucket ordinal"));
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

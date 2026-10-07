//! Private transaction-bound plans expose data only to the closed allocator.
use super::*;
use crate::admission_operation_store::knowledge::reference_source::{
    VerifiedKnowledgeReferenceRetain, VerifiedKnowledgeReferenceRetirement,
};
use std::ops::Deref;

pub(in crate::admission_operation_store) struct PreparedReferenceUpdates<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    source: OwningSource<'tx, 'conn>,
    heads: Vec<protected::ProtectedSourceReference>,
    writes: Vec<StagedReferenceUpdate>,
    footprint: ReferenceWriteFootprint,
}

pub(super) enum OwningSource<'tx, 'conn> {
    Retain(VerifiedKnowledgeReferenceRetain<'tx, 'conn>),
    Retirement(VerifiedKnowledgeReferenceRetirement<'tx, 'conn>),
}

impl<'tx, 'conn> OwningSource<'tx, 'conn> {
    pub(super) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        match self {
            Self::Retain(proof) => proof.verify(tx),
            Self::Retirement(proof) => proof.verify(tx),
        }
    }

    pub(super) fn owner(&self) -> &ReferenceOwner {
        match self {
            Self::Retain(proof) => proof.owner(),
            Self::Retirement(proof) => proof.owner(),
        }
    }

    pub(super) fn references(&self) -> &[ArtifactVersionRefV1] {
        match self {
            Self::Retain(proof) => proof.references(),
            Self::Retirement(proof) => proof.references(),
        }
    }

    pub(super) fn source(&self) -> &protected::ProtectedSourceReference {
        match self {
            Self::Retain(proof) => proof.source(),
            Self::Retirement(proof) => proof.source(),
        }
    }

    pub(super) fn verify_original_anchor(
        &self,
        tx: &Transaction<'conn>,
        anchor: &SourceAnchor,
    ) -> Result<(), AdmissionOperationStoreError> {
        match self {
            Self::Retain(proof) => proof.verify_original_anchor(tx, anchor),
            Self::Retirement(proof) => proof.verify_original_anchor(tx, anchor),
        }
    }
}

/// Counters describe exact staged writes. They do not supply storage capacity.
pub(in crate::admission_operation_store) struct ReferenceWriteFootprint {
    record_count: usize,
    event_count: usize,
    encoded_bytes: usize,
    new_active_owners: u64,
    retired_active_owners: u64,
}

impl ReferenceWriteFootprint {
    pub(in crate::admission_operation_store) fn record_count(&self) -> usize {
        self.record_count
    }

    pub(in crate::admission_operation_store) fn event_count(&self) -> usize {
        self.event_count
    }

    pub(in crate::admission_operation_store) fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }

    pub(in crate::admission_operation_store) fn new_active_owners(&self) -> u64 {
        self.new_active_owners
    }

    pub(in crate::admission_operation_store) fn retired_active_owners(&self) -> u64 {
        self.retired_active_owners
    }
}

/// Only this module's prepared writer can create a staged update. Its exact
/// head is retained inside the plan and checked again before allocator writes.
pub(in crate::admission_operation_store) struct StagedReferenceUpdate {
    key: String,
    scope: String,
    expected_version: Option<u64>,
    version: u64,
    payload: Vec<u8>,
}

impl StagedReferenceUpdate {
    pub(super) fn prepare<T: Serialize>(
        key: String,
        scope: String,
        expected: Option<&protected::ProtectedSourceReference>,
        value: &T,
    ) -> Result<Self, AdmissionOperationStoreError> {
        if key.is_empty()
            || scope.len() != 64
            || !scope.bytes().all(|byte| byte.is_ascii_hexdigit())
            || expected.is_some_and(|head| {
                head.record_key() != key || head.scope_key() != scope || head.kind() != "command"
            })
        {
            return Err(refused("reference staged identity changed"));
        }
        let expected_version = expected.map(protected::ProtectedSourceReference::version);
        let version = expected_version
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| refused("reference staged version exhausted"))?;
        SafeInteger::new(version).map_err(refused)?;
        Ok(Self {
            key,
            scope,
            expected_version,
            version,
            payload: protected::encode(value)?,
        })
    }

    pub(in crate::admission_operation_store) fn key(&self) -> &str {
        &self.key
    }

    pub(in crate::admission_operation_store) fn scope(&self) -> &str {
        &self.scope
    }

    pub(in crate::admission_operation_store) fn expected_version(&self) -> Option<u64> {
        self.expected_version
    }

    pub(in crate::admission_operation_store) fn version(&self) -> u64 {
        self.version
    }

    pub(in crate::admission_operation_store) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl<'tx, 'conn> PreparedReferenceUpdates<'tx, 'conn> {
    pub(super) fn prepare(
        transaction: &'tx Transaction<'conn>,
        source: OwningSource<'tx, 'conn>,
        heads: Vec<protected::ProtectedSourceReference>,
        mut writes: Vec<StagedReferenceUpdate>,
        new_active_owners: u64,
        retired_active_owners: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        writes.sort_by(|left, right| left.key.cmp(&right.key));
        let reference_count = source.references().len();
        let maximum_writes = reference_count
            .checked_mul(3)
            .ok_or_else(|| refused("reference staged write bound overflow"))?;
        let maximum_heads = reference_count
            .checked_mul(MAX_ACTIVE_REFERENCE_BUCKETS + 2)
            .ok_or_else(|| refused("reference staged head bound overflow"))?;
        let reference_count_u64 = u64::try_from(reference_count)
            .map_err(|_| refused("reference staged count overflow"))?;
        if reference_count > MAX_ARTIFACT_TRAVERSAL
            || writes.len() > maximum_writes
            || heads.len() > maximum_heads
            || new_active_owners > reference_count_u64
            || retired_active_owners > reference_count_u64
            || matches!(&source, OwningSource::Retain(_)) && retired_active_owners != 0
            || matches!(&source, OwningSource::Retirement(_)) && new_active_owners != 0
            || writes.windows(2).any(|pair| pair[0].key == pair[1].key)
        {
            return Err(refused("reference staged bounds or identity changed"));
        }
        let encoded_bytes = writes.iter().try_fold(0_usize, |total, write| {
            total
                .checked_add(write.payload.len())
                .ok_or_else(|| refused("reference staged bytes overflow"))
        })?;
        let footprint = ReferenceWriteFootprint {
            record_count: writes.len(),
            event_count: writes.len(),
            encoded_bytes,
            new_active_owners,
            retired_active_owners,
        };
        let plan = Self {
            transaction,
            source,
            heads,
            writes,
            footprint,
        };
        plan.verify_current(transaction)?;
        Ok(plan)
    }

    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.transaction
    }

    pub(in crate::admission_operation_store) fn scope(&self) -> &RecoveryScopeV1 {
        self.source.owner().scope()
    }

    pub(in crate::admission_operation_store) fn owner(&self) -> &ReferenceOwner {
        self.source.owner()
    }

    pub(in crate::admission_operation_store) fn owner_source(
        &self,
    ) -> &protected::ProtectedSourceReference {
        self.source.source()
    }

    pub(in crate::admission_operation_store) fn reference_count(&self) -> usize {
        self.source.references().len()
    }

    pub(in crate::admission_operation_store) fn references(&self) -> &[ArtifactVersionRefV1] {
        self.source.references()
    }

    pub(in crate::admission_operation_store) fn write_footprint(&self) -> &ReferenceWriteFootprint {
        &self.footprint
    }

    pub(in crate::admission_operation_store) fn staged_updates(&self) -> &[StagedReferenceUpdate] {
        &self.writes
    }

    pub(in crate::admission_operation_store) fn verify_current(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction), Deref::deref(tx)) {
            return Err(refused("reference plan changed its physical writer"));
        }
        self.source.verify(tx)?;
        for head in &self.heads {
            protected::verify_source_reference(tx, head)?;
        }
        for write in &self.writes {
            match write.expected_version {
                Some(version) => {
                    if !self.heads.iter().any(|head| {
                        head.record_key() == write.key
                            && head.scope_key() == write.scope
                            && head.kind() == "command"
                            && head.version() == version
                    }) {
                        return Err(refused("reference staged head is not retained"));
                    }
                }
                None => {
                    if protected::raw_checked(tx, &write.key)?.is_some() {
                        return Err(refused("reference absent slot was consumed"));
                    }
                }
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for PreparedReferenceUpdates<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedReferenceUpdates([redacted])")
    }
}

impl std::fmt::Debug for StagedReferenceUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StagedReferenceUpdate([redacted])")
    }
}

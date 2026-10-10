//! Each reference index starts at its actual metadata commitment.
use super::*;
use crate::admission_operation_store::knowledge::reference_source::VerifiedNewArtifactReferenceBaseline;
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
    let inventory = ReferenceInventory {
        active_buckets: BoundedList::new(vec![]).map_err(refused)?,
    };
    let value = ReferenceAggregate {
        schema: ReferenceSchema::V1,
        reference: proof.reference().clone(),
        source,
        accepted: SafeInteger::ZERO,
        retired: SafeInteger::ZERO,
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

fn verify_writer<'conn>(
    original: &Transaction<'conn>,
    current: &Transaction<'conn>,
) -> Result<(), AdmissionOperationStoreError> {
    if !std::ptr::eq::<Connection>(Deref::deref(original), Deref::deref(current)) {
        return Err(refused("reference baseline changed its physical writer"));
    }
    Ok(())
}

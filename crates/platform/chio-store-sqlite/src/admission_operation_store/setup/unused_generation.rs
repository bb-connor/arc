//! A transaction-bound closure witness preserves the selected original identity.
use super::*;

/// Only the setup owner can construct this effect-free retirement witness.
/// It cannot escape its writer, be cloned, or be decoded from wire data.
pub(in crate::admission_operation_store) struct VerifiedUnusedSetupGeneration<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    record: RecoveryWorkflowRecordV1,
    selected_creation: CanonicalPayloadDigest,
    selection: protected::ProtectedSourceReference,
    workflow: protected::ProtectedSourceReference,
}

impl<'tx, 'conn> VerifiedUnusedSetupGeneration<'tx, 'conn> {
    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.transaction
    }

    pub(in crate::admission_operation_store) fn record(&self) -> &RecoveryWorkflowRecordV1 {
        &self.record
    }

    pub(in crate::admission_operation_store) fn selected_creation_digest(
        &self,
    ) -> CanonicalPayloadDigest {
        self.selected_creation
    }

    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'_>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq(self.transaction, tx) {
            return Err(refused("setup retirement writer changed"));
        }
        protected::verify_source_reference(tx, &self.selection)?;
        protected::verify_source_reference(tx, &self.workflow)?;
        let selected = load(tx, &self.record.scope)?
            .ok_or_else(|| refused("unused setup selection disappeared"))?;
        if selected.creation != self.selected_creation
            || selected.probe.benign_workflow != self.record.workflow_id
            || selected.evidence.is_some()
            || selected.report.is_some()
        {
            return Err(refused("unused setup selection changed"));
        }
        let physical = protected::workflow_tx(tx, &self.record.scope, &self.record.workflow_id)?;
        if protected::encode(&physical)? != protected::encode(&self.record)? {
            return Err(refused("unused setup generation changed"));
        }
        require_unused(&physical)?;
        Ok(())
    }
}

impl core::fmt::Debug for VerifiedUnusedSetupGeneration<'_, '_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerifiedUnusedSetupGeneration([redacted])")
    }
}

pub(super) fn verify_unused_generation<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    selected: &Selection,
) -> Result<VerifiedUnusedSetupGeneration<'tx, 'conn>, AdmissionOperationStoreError> {
    if selected.evidence.is_some() || selected.report.is_some() {
        return Err(refused("completed setup cannot retire as unused"));
    }
    let record =
        protected::workflow_tx(tx, &selected.probe.scope, &selected.probe.benign_workflow)?;
    require_unused(&record)?;
    if creation(&record)? != selected.creation {
        return Err(refused("unused setup original changed"));
    }
    let scoped_key = key(&selected.probe.scope)?;
    let selected_key = if authenticated_record(tx, &scoped_key)?.is_some() {
        scoped_key
    } else {
        legacy_key(&selected.probe.scope)?
    };
    let workflow_key = protected::workflow_key(&record.scope, &record.workflow_id)?;
    let witness = VerifiedUnusedSetupGeneration {
        transaction: tx,
        selected_creation: selected.creation,
        selection: protected::source_reference(tx, &selected_key)?,
        workflow: protected::source_reference(tx, &workflow_key)?,
        record,
    };
    witness.verify(tx)?;
    Ok(witness)
}

fn require_unused(record: &RecoveryWorkflowRecordV1) -> Result<(), AdmissionOperationStoreError> {
    if record.origin.is_none()
        || record.control != WorkflowControlV1::Active
        || record.captured
        || record.native_link.is_some()
        || record.admission.is_some()
        || record.admission_closed
        || record.historical_hold.is_some()
        || record.effect != EffectObservationV1::NeverAdmitted
    {
        return Err(refused("setup generation is not effect free"));
    }
    Ok(())
}

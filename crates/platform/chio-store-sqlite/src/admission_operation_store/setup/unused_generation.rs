//! A transaction-bound closure witness preserves the selected original identity.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::admission_operation_store) enum UnusedSetupReplacementReason {
    ProfileChanged,
    InitialWindowExpired,
    WriterChanged,
    StaleSource,
}

/// Only the setup owner can construct this effect-free retirement witness.
/// It cannot escape its writer, be cloned, or be decoded from wire data.
pub(in crate::admission_operation_store) struct VerifiedUnusedSetupGeneration<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    record: RecoveryWorkflowRecordV1,
    selected_creation: CanonicalPayloadDigest,
    selection: protected::ProtectedSourceReference,
    workflow: protected::ProtectedSourceReference,
    deployment: RecoveryDeploymentV1,
    fence: StoreMutationFence,
    sampled_at: u64,
    reason: UnusedSetupReplacementReason,
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

    pub(in crate::admission_operation_store) fn selection_source(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.selection
    }

    pub(in crate::admission_operation_store) fn workflow_source(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.workflow
    }

    pub(in crate::admission_operation_store) fn replacement_reason(
        &self,
    ) -> Result<UnusedSetupReplacementReason, AdmissionOperationStoreError> {
        self.verify(self.transaction)?;
        Ok(self.reason)
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
        let deployment = protected::deployment_tx(tx, &self.record.scope)?;
        let now = schema::observe_authority_time(tx)?;
        if now < self.sampled_at
            || protected::encode(&deployment)? != protected::encode(&self.deployment)?
            || super::service::unused_replacement_reason(
                tx,
                &selected,
                &deployment,
                &self.fence,
                now,
            )? != Some(self.reason)
        {
            return Err(refused("unused setup replacement eligibility changed"));
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
    deployment: &RecoveryDeploymentV1,
    fence: &StoreMutationFence,
    sampled_at: u64,
) -> Result<VerifiedUnusedSetupGeneration<'tx, 'conn>, AdmissionOperationStoreError> {
    let reason =
        super::service::unused_replacement_reason(tx, selected, deployment, fence, sampled_at)?
            .ok_or_else(|| refused("fresh active setup cannot retire as unused"))?;
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
        deployment: deployment.clone(),
        fence: fence.clone(),
        sampled_at,
        reason,
        record,
    };
    witness.verify(tx)?;
    Ok(witness)
}

fn require_unused(record: &RecoveryWorkflowRecordV1) -> Result<(), AdmissionOperationStoreError> {
    if record.origin.is_none()
        || record.control != WorkflowControlV1::Active
        || record.action.is_some()
        || record.process_reservation.is_some()
        || record.captured
        || record.captured_deployment.is_some()
        || record.issuance.is_some()
        || record.signed_grant.is_some()
        || record.envelope.is_some()
        || record.native_link.is_some()
        || record.admission.is_some()
        || record.admission_closed
        || record.historical_hold.is_some()
        || record.provider_finality.is_some()
        || record.provider_lookups.get() != 0
        || record.reported_decision.is_some()
        || record.release != ReleaseDispositionV1::NotAvailable
        || record.effect != EffectObservationV1::NeverAdmitted
    {
        return Err(refused("setup generation is not effect free"));
    }
    Ok(())
}

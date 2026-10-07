//! Final readiness consumes the complete census and exact cold writer receipts.
use super::reference_census::VerifiedKnowledgeReferenceAccountBaseline;
use super::references::{ReferenceAccount, ReferenceReadyRecord, ReferenceReadySchema};
use super::*;

/// This token never leaves its original fenced native activation transaction.
/// Its expected global head advances only through private closed-writer receipts.
pub(in crate::admission_operation_store) struct KnowledgeReferenceColdActivation<'tx, 'conn> {
    baseline: VerifiedKnowledgeReferenceAccountBaseline<'tx, 'conn>,
    expected: super::reference_source::ReferenceCutoff,
}

pub(in crate::admission_operation_store) struct VerifiedKnowledgeReferenceReady<'tx, 'conn> {
    activation: KnowledgeReferenceColdActivation<'tx, 'conn>,
    record: ReferenceReadyRecord,
}

impl<'tx, 'conn> KnowledgeReferenceColdActivation<'tx, 'conn> {
    /// The account writer returns the original affine census along its own
    /// verified receipt. No decoded accounting row can construct activation.
    pub(super) fn after_account(
        tx: &'tx Transaction<'conn>,
        owner: &SqliteServingOwner,
        baseline: VerifiedKnowledgeReferenceAccountBaseline<'tx, 'conn>,
        receipt: protected::VerifiedKnowledgeReferenceColdProgress<'tx, 'conn>,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let expected = baseline.global_cutoff().clone();
        let mut activation = Self { baseline, expected };
        activation.accept_progress(tx, owner, receipt)?;
        Ok(activation)
    }

    pub(in crate::admission_operation_store) fn baseline(
        &self,
    ) -> &VerifiedKnowledgeReferenceAccountBaseline<'tx, 'conn> {
        &self.baseline
    }

    /// A receipt is privately minted by a bounded account or exact cold index
    /// writer. It verifies every staged row identity and footprint, not just
    /// a caller-selected prefix or an arithmetic global-head difference.
    pub(super) fn accept_progress(
        &mut self,
        tx: &'tx Transaction<'conn>,
        owner: &SqliteServingOwner,
        receipt: protected::VerifiedKnowledgeReferenceColdProgress<'tx, 'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        accept_receipt(&self.baseline, &mut self.expected, tx, owner, receipt)
    }

    /// Stream complete artifact cohorts while holding only one bounded cold
    /// plan. Splitting the affine baseline and cursor borrows prevents a second
    /// plan or cloned authority from being used to advance the same activation.
    pub(super) fn persist_baselines(
        &mut self,
        tx: &'tx Transaction<'conn>,
        owner: &SqliteServingOwner,
    ) -> Result<protected::ProtectedMutationDelta, AdmissionOperationStoreError> {
        let baseline = &self.baseline;
        let expected = &mut self.expected;
        let mut total = protected::ProtectedMutationDelta::zero();
        baseline.visit_artifacts(|reference| {
            let cohort = baseline.artifact_cohort(&reference)?;
            let plan = super::references::prepare_cold_reference_baseline(tx, cohort)?;
            let (receipt, delta) =
                protected::persist_knowledge_reference_cold_baseline(tx, owner, plan)?;
            accept_receipt(baseline, expected, tx, owner, receipt)?;
            total = total.checked_add(&delta)?;
            Ok(())
        })?;
        Ok(total)
    }

    pub(super) fn finish(
        self,
        tx: &'tx Transaction<'conn>,
        owner: &SqliteServingOwner,
    ) -> Result<VerifiedKnowledgeReferenceReady<'tx, 'conn>, AdmissionOperationStoreError> {
        self.verify(tx, owner)?;
        self.baseline.visit_artifacts(|reference| {
            let cohort = self.baseline.artifact_cohort(&reference)?;
            super::references::verify_committed_cold_baseline(tx, &cohort)
        })?;
        let record = ReferenceReadyRecord {
            schema: ReferenceReadySchema::V1,
            account: ReferenceAccount::from_scope(self.baseline.scope()),
            cutoff: self.baseline.global_cutoff().clone(),
            cohort_digest: self.baseline.cohort_digest(),
            census_digest: self.baseline.census_digest(),
            artifact_count: SafeInteger::new(self.baseline.artifact_count()).map_err(refused)?,
            active_owner_count: SafeInteger::new(self.baseline.active_reference_owners())
                .map_err(refused)?,
        };
        let key = record.account.ready_key()?;
        if protected::raw_checked(tx, &key)?.is_some() {
            return Err(refused(
                "reference ready identity has already been consumed",
            ));
        }
        let proof = VerifiedKnowledgeReferenceReady {
            activation: self,
            record,
        };
        proof.verify(tx, owner)?;
        Ok(proof)
    }

    fn verify(
        &self,
        tx: &Transaction<'conn>,
        owner: &SqliteServingOwner,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.baseline.verify(tx)?;
        let actual = super::reference_source::ReferenceCutoff::capture(tx, owner)?;
        if actual != self.expected {
            return Err(refused(
                "reference activation acquired an unaccepted global commit",
            ));
        }
        Ok(())
    }
}

fn accept_receipt<'tx, 'conn>(
    baseline: &VerifiedKnowledgeReferenceAccountBaseline<'tx, 'conn>,
    expected: &mut super::reference_source::ReferenceCutoff,
    tx: &'tx Transaction<'conn>,
    owner: &SqliteServingOwner,
    receipt: protected::VerifiedKnowledgeReferenceColdProgress<'tx, 'conn>,
) -> Result<(), AdmissionOperationStoreError> {
    receipt.verify(tx)?;
    baseline.verify(tx)?;
    let actual = super::reference_source::ReferenceCutoff::capture(tx, owner)?;
    if receipt.account_domain() != &baseline.scope().authority_domain
        || receipt.account_tenant() != &baseline.scope().tenant_id
        || receipt.before_sequence() != expected.sequence()
        || receipt.before_chain_digest() != expected.chain_digest()
        || receipt.after_sequence() != actual.sequence()
        || receipt.after_chain_digest() != actual.chain_digest()
    {
        return Err(refused(
            "reference cold progress admits unknown global interference",
        ));
    }
    *expected = actual;
    Ok(())
}

impl<'tx, 'conn> VerifiedKnowledgeReferenceReady<'tx, 'conn> {
    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.activation.baseline.transaction()
    }

    pub(in crate::admission_operation_store) fn record(&self) -> &ReferenceReadyRecord {
        &self.record
    }

    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
        owner: &SqliteServingOwner,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.activation.verify(tx, owner)?;
        self.activation.baseline.visit_artifacts(|reference| {
            let cohort = self.activation.baseline.artifact_cohort(&reference)?;
            super::references::verify_committed_cold_baseline(tx, &cohort)
        })?;
        if protected::raw_checked(tx, &self.record.account.ready_key()?)?.is_some() {
            return Err(refused("reference final marker was already emitted"));
        }
        Ok(())
    }
}

impl std::fmt::Debug for KnowledgeReferenceColdActivation<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KnowledgeReferenceColdActivation([redacted])")
    }
}
impl std::fmt::Debug for VerifiedKnowledgeReferenceReady<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedKnowledgeReferenceReady([redacted])")
    }
}

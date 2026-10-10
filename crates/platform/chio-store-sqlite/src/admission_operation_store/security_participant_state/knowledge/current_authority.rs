//! Warm influence reads borrow the actual owner and its anchored transaction.
use super::*;
use crate::serving_owner::NativeSourceTransactionOrigin;

/// No construction from a decoded role, supplied head, or raw connection.
/// This witness describes current custody and grants no mutation or delivery.
pub(in crate::admission_operation_store) struct CurrentNativeInfluenceAuthority<'tx, 'conn, 'owner>
{
    transaction: &'tx Transaction<'conn>,
    owner: &'owner SqliteServingOwner,
    origin: NativeSourceTransactionOrigin<'owner>,
    initialized: SecurityParticipantStateInitialization,
}

impl<'tx, 'conn, 'owner> CurrentNativeInfluenceAuthority<'tx, 'conn, 'owner> {
    pub(in crate::admission_operation_store) fn authenticate(
        transaction: &'tx Transaction<'conn>,
        owner: &'owner SqliteServingOwner,
        binding: &NativeSecurityAuthorityBindingV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        super::super::super::schema::verify_active_owner(transaction, owner, None)?;
        let origin = owner
            .prepare_native_source_transaction(transaction)
            .map_err(map_owner_error)?;
        let initialized = records::load_current_metadata(transaction, binding)?;
        if binding.store_uuid().as_str() != owner.fence.store_uuid {
            return Err(invalid(
                "current influence initialization changed its owner",
            ));
        }
        Ok(Self {
            transaction,
            owner,
            origin,
            initialized,
        })
    }

    pub(in crate::admission_operation_store) fn observe(
        &self,
        key: &FlowStateKey,
    ) -> Result<
        Option<chio_security_types::knowledge::ArtifactInfluenceV1>,
        AdmissionOperationStoreError,
    > {
        self.verify()?;
        self.require_supported_import_influence()?;
        super::observed_influence(self.transaction, self.initialized.authority.as_str(), key)
    }

    fn require_supported_import_influence(&self) -> Result<(), AdmissionOperationStoreError> {
        // Source40 has no compatible imported influence-origin adapter. Read
        // the actual sealed source and authenticate every retained row against
        // its original fingerprint. Current mutable rows, a zero count, or an
        // initialization header alone cannot replace that source custody.
        let source = security_participant_migration::load_imported_source(
            self.transaction,
            self.initialized.authority.as_str(),
        )?;
        if source.expectation_id() != self.initialized.expectation_id()
            || source.snapshot().digest().map_err(invalid)? != self.initialized.fingerprint
            || source
                .snapshot()
                .binding()
                .destination_store_uuid()
                .as_str()
                != self.owner.fence.store_uuid
            || source.snapshot().binding().security_authority_id().as_str()
                != self.initialized.authority.as_str()
        {
            return Err(invalid(
                "native imported influence changed its sealed source",
            ));
        }
        let relevant = source.snapshot().tables().iter().any(|table| {
            table.row_count != 0
                && matches!(
                    table.table.as_str(),
                    "security_flow_contexts"
                        | "security_principal_flow_state"
                        | "security_lineage_flow_state"
                        | "security_session_flow_state"
                        | "security_transitions"
                        | "security_egress_fences"
                        | "security_declassification_uses"
                        | "security_declassification_evidence_identity"
                        | "security_declassification_receipt_outbox"
                )
        });
        if relevant {
            return Err(invalid("native imported influence history remains held"));
        }
        Ok(())
    }

    fn verify(&self) -> Result<(), AdmissionOperationStoreError> {
        if !self.origin.matches_owner(self.owner) {
            return Err(invalid(
                "current influence source changed its owning writer",
            ));
        }
        self.origin
            .verify(self.transaction)
            .map_err(map_owner_error)?;
        let current = records::load_current_metadata(
            self.transaction,
            &self.initialized.admission_binding()?,
        )?;
        if current != self.initialized {
            return Err(invalid("current influence initialization changed"));
        }
        Ok(())
    }
}

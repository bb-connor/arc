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
    binding: NativeSecurityAuthorityBindingV1,
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
            binding: binding.clone(),
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
        // This warm read uses the same charged reader as the capture and release
        // callers. The sealed pre-recovery source contributes conservatively
        // through it, never a silent zero.
        let mut budget = chio_semantic_contracts::VerificationBudget::new(
            chio_security_types::recovery::MAX_RECOVERY_VERIFICATION_WORK,
        )
        .map_err(invalid)?;
        super::budgeted_observed_influence(self.transaction, &self.binding, key, &mut budget)
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

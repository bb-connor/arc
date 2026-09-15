//! Sibling-share accounting projected from operation-owned caller holds.

use super::*;

/// A funded caller operation's delegated share, not fresh dispatch authority.
/// Stores construct this only after a fenced, integrity-checked read of the
/// operation and its retained request. The executable hold is the owner: no
/// legacy nonce stamp or process-local lease is needed to keep it reserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionCallerBudgetShare {
    operation_id: AdmissionOperationId,
    parent_id: AdmissionIdentifier,
    child_id: AdmissionIdentifier,
    share_bps: u16,
    caller_reservation_established: bool,
}

impl AdmissionCallerBudgetShare {
    /// Whether an operation can still own a caller's delegated share.
    /// Outcome-unknown dispatches retain their shares; completed, compensated,
    /// contractually rejected and confirmed-undelivered operations do not.
    #[must_use]
    pub fn is_owned_by(operation: &AdmissionOperationV1) -> bool {
        operation.budget_hold_id().is_some()
            && operation
                .provider_attempt()
                .is_some_and(|attempt| attempt.is_caller_report())
            && (!operation.state().is_terminal()
                || operation.state() == AdmissionOperationState::OutcomeUnknownAfterDispatch)
    }

    /// Project a matching retained request without manufacturing provenance.
    /// Returns no share for a closed operation or a root capability. A store
    /// must not silently omit a record when validation returns an error.
    pub fn from_retained_operation(
        operation: &AdmissionOperationV1,
        retained: &RetainedToolAdmissionRequestV1,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        retained.validate_binding(operation.binding())?;
        if !Self::is_owned_by(operation) {
            return Ok(None);
        }
        if !operation
            .binding()
            .participant_requirements()
            .execution_nonce
        {
            return Err(AdmissionOperationStoreError::Invariant(
                "funded caller share has no operation-owned nonce participant".into(),
            ));
        }
        let capability = &retained.request_for_revalidation().capability;
        capability
            .validate_schema()
            .map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))?;
        let Some(parent) = capability.delegation_chain.last() else {
            return Ok(None);
        };
        Ok(Some(Self {
            operation_id: operation.binding().operation_id().clone(),
            parent_id: AdmissionIdentifier::try_new("parent_id", parent.capability_id.clone())?,
            child_id: operation.binding().capability_id().clone(),
            share_bps: capability
                .budget_share_bps
                .unwrap_or(chio_kernel_core::MAX_BUDGET_SHARE_BPS),
            caller_reservation_established: operation.execution_nonce_id().is_some(),
        }))
    }

    /// Immutable identifier of the operation that owns this share.
    #[must_use]
    pub fn operation_id(&self) -> &AdmissionOperationId {
        &self.operation_id
    }

    /// Immediate delegation parent whose headroom is reserved.
    #[must_use]
    pub fn parent_id(&self) -> &AdmissionIdentifier {
        &self.parent_id
    }

    /// Delegated child; multiple operations on one child share one edge.
    #[must_use]
    pub fn child_id(&self) -> &AdmissionIdentifier {
        &self.child_id
    }

    /// The signed child's share, with omission interpreted as the full ceiling.
    #[must_use]
    pub fn share_bps(&self) -> u16 {
        self.share_bps
    }

    /// Whether the operation committed its nonce reservation after share
    /// admission. A funded pending claim cannot displace this established owner.
    #[must_use]
    pub fn is_reserved_for_caller(&self) -> bool {
        self.caller_reservation_established
    }
}

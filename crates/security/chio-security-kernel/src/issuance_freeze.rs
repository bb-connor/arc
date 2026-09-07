use std::sync::Arc;

use chio_kernel::CapabilityIssuanceAdmissionAuthority;
use chio_security_types::ports::{
    validate_issuance_freeze_admission_decision, IssuanceFreezeAdmissionDecision,
    IssuanceFreezeAdmissionQuery, IssuanceFreezeStore, PortError, PortResult,
};

/// Fail-closed admission authority for capability issuance and delegation.
///
/// Callers must supply the authoritative tenant and lineage identity and call
/// this immediately before their issuance mutation. Descendant delegation is
/// additionally serialized with causal-fence acquisition by the causal
/// lineage store, which closes the admission-to-commit race.
pub struct IssuanceFreezeAdmission {
    freezes: Arc<dyn IssuanceFreezeStore>,
}

impl CapabilityIssuanceAdmissionAuthority for IssuanceFreezeAdmission {
    fn ensure_ready(&self) -> PortResult<()> {
        self.freezes.ensure_issuance_freezes_ready()
    }

    fn authorize(&self, query: &IssuanceFreezeAdmissionQuery) -> PortResult<()> {
        IssuanceFreezeAdmission::authorize(self, query)
    }
}

impl IssuanceFreezeAdmission {
    #[must_use]
    pub fn new(freezes: Arc<dyn IssuanceFreezeStore>) -> Self {
        Self { freezes }
    }

    pub fn evaluate(
        &self,
        query: &IssuanceFreezeAdmissionQuery,
    ) -> PortResult<IssuanceFreezeAdmissionDecision> {
        query
            .operation
            .validate_parent(query.parent_capability_id.as_ref())?;
        let decision = self.freezes.evaluate_issuance_freeze(query)?;
        validate_issuance_freeze_admission_decision(query, &decision)?;
        Ok(decision)
    }

    pub fn authorize(&self, query: &IssuanceFreezeAdmissionQuery) -> PortResult<()> {
        if self.evaluate(query)?.frozen {
            return Err(PortError::conflict());
        }
        Ok(())
    }
}

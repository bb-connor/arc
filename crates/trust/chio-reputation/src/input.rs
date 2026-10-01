//! Bounded native decoding for persisted capability-lineage scopes.
use crate::{CapabilityLineageRecord, CapabilityLineageScopeJsonInput, ReputationError};

impl CapabilityLineageRecord {
    pub fn from_scope_json(
        input: CapabilityLineageScopeJsonInput<'_>,
    ) -> Result<Self, ReputationError> {
        Ok(Self {
            capability_id: input.capability_id,
            subject_key: input.subject_key,
            issuer_key: input.issuer_key,
            issued_at: input.issued_at,
            expires_at: input.expires_at,
            scope: chio_core::canonical::UntrustedJsonText::from_wire(
                input.scope_json.as_bytes(),
                1024 * 1024,
            )?
            .decode_signed()?,
            delegation_depth: input.delegation_depth,
            parent_capability_id: input.parent_capability_id,
        })
    }
}

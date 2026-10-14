//! Exact source-owned slot identities are data, never finishing capacity.
use super::*;
use chio_core::recovery::{knowledge_digest, RecoveryDigestDomain};
use chio_security_types::ports::{IsolationEpochId, LineageId, SessionId, TenantId};

pub(in crate::admission_operation_store) const MAX_NATIVE_INFLUENCE_PAYLOAD_BYTES: usize =
    16 * 1024;

/// These scopes mirror the actual native label primary keys. Lineage
/// influence remains inherited when the principal or isolation epoch changes.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum InfluenceScope {
    Principal {
        tenant: TenantId,
        principal: chio_security_types::PrincipalId,
        epoch: IsolationEpochId,
    },
    Lineage {
        tenant: TenantId,
        lineage: LineageId,
    },
    Session {
        tenant: TenantId,
        principal: chio_security_types::PrincipalId,
        epoch: IsolationEpochId,
        session: SessionId,
    },
}

impl InfluenceScope {
    pub(super) fn inherited(key: &FlowStateKey) -> [Self; 3] {
        [
            Self::Principal {
                tenant: key.tenant_id.clone(),
                principal: key.principal_id.clone(),
                epoch: key.isolation_epoch_id.clone(),
            },
            Self::Lineage {
                tenant: key.tenant_id.clone(),
                lineage: key.lineage_id.clone(),
            },
            Self::Session {
                tenant: key.tenant_id.clone(),
                principal: key.principal_id.clone(),
                epoch: key.isolation_epoch_id.clone(),
                session: key.session_id.clone(),
            },
        ]
    }

    fn tenant(&self) -> &TenantId {
        match self {
            Self::Principal { tenant, .. }
            | Self::Lineage { tenant, .. }
            | Self::Session { tenant, .. } => tenant,
        }
    }

    /// Whether the native flow-state row this scope mirrors exists. A slot is
    /// bounded by its flow-state row, which no native writer deletes.
    pub(super) fn flow_row_exists(
        &self,
        connection: &Connection,
        authority: &str,
    ) -> Result<bool, AdmissionOperationStoreError> {
        match self {
            Self::Principal {
                tenant,
                principal,
                epoch,
            } => connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM security_participant_state_principal_flow_state
                 WHERE security_authority_id = ?1 AND tenant_id = ?2 AND principal_id = ?3
                   AND isolation_epoch_id = ?4)",
                params![
                    authority,
                    tenant.as_str(),
                    principal.as_str(),
                    epoch.as_str()
                ],
                |row| row.get(0),
            ),
            Self::Lineage { tenant, lineage } => connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM security_participant_state_lineage_flow_state
                 WHERE security_authority_id = ?1 AND tenant_id = ?2 AND lineage_id = ?3)",
                params![authority, tenant.as_str(), lineage.as_str()],
                |row| row.get(0),
            ),
            Self::Session {
                tenant,
                principal,
                epoch,
                session,
            } => connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM security_participant_state_session_flow_state
                 WHERE security_authority_id = ?1 AND tenant_id = ?2 AND principal_id = ?3
                   AND session_id = ?4 AND isolation_epoch_id = ?5)",
                params![
                    authority,
                    tenant.as_str(),
                    principal.as_str(),
                    session.as_str(),
                    epoch.as_str()
                ],
                |row| row.get(0),
            ),
        }
        .map_err(sqlite_error)
    }
}

/// Imported history scope identities. These select sealed pre-recovery source
/// custody for the warm reader. They are never native finishing slots, never
/// capacity and never an allocation: only the exact inherited scope union the
/// imported contribution rules already use.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ImportedInfluenceScope {
    Tenant {
        tenant: TenantId,
    },
    Lineage {
        tenant: TenantId,
        lineage: LineageId,
    },
    Principal {
        tenant: TenantId,
        principal: chio_security_types::PrincipalId,
        epoch: IsolationEpochId,
    },
}

impl ImportedInfluenceScope {
    /// The exact imported counterpart of the inherited influence union: a
    /// tenant's coarse custody, its lineage-inherited custody and its
    /// principal-and-epoch custody. Session identity never narrows it and a
    /// foreign tenant is never a member.
    pub(super) fn inherited(key: &FlowStateKey) -> [Self; 3] {
        [
            Self::Tenant {
                tenant: key.tenant_id.clone(),
            },
            Self::Lineage {
                tenant: key.tenant_id.clone(),
                lineage: key.lineage_id.clone(),
            },
            Self::Principal {
                tenant: key.tenant_id.clone(),
                principal: key.principal_id.clone(),
                epoch: key.isolation_epoch_id.clone(),
            },
        ]
    }

    /// The scope's distinct imported identity. The derivation binds the store
    /// and the native authority under its own domain tag, so an imported
    /// reference can never collide with a native slot, another store's index
    /// or another authority's custody.
    pub(super) fn scope_key(
        &self,
        binding: &NativeSecurityAuthorityBindingV1,
    ) -> Result<String, AdmissionOperationStoreError> {
        Ok(hex::encode(
            knowledge_digest(
                RecoveryDigestDomain::KnowledgeInfluenceScope,
                &(
                    "imported-influence-scope-v1",
                    binding.store_uuid().as_str(),
                    binding,
                    self,
                ),
            )
            .map_err(invalid)?,
        ))
    }
}

/// This descriptor contains no capacity, allocation, purpose or Ready proof.
/// Only a genuine producer plus an actual reservation owner can spend a slot.
pub(in crate::admission_operation_store) struct NativeInfluenceSlot {
    record_key: String,
    scope_key: String,
    inherited_scope: InfluenceScope,
}

impl NativeInfluenceSlot {
    pub(in crate::admission_operation_store) fn record_key(&self) -> &str {
        &self.record_key
    }

    pub(in crate::admission_operation_store) fn scope_key(&self) -> &str {
        &self.scope_key
    }

    pub(in crate::admission_operation_store) fn maximum_payload_bytes(&self) -> usize {
        MAX_NATIVE_INFLUENCE_PAYLOAD_BYTES
    }

    pub(super) fn inherited_scope(&self) -> &InfluenceScope {
        &self.inherited_scope
    }

    /// Recompute this slot's exact record and scope identities from the
    /// binding and the inherited scope. The record key carries the owning
    /// authority in its prefix so a cold reader selects this authority's
    /// rows without decoding any foreign authority's projections. The
    /// record key and the scope key are both derived from the binding's
    /// store identity, so neither can be supplied by a caller or borrowed
    /// across serving owners.
    pub(super) fn derive(
        binding: &NativeSecurityAuthorityBindingV1,
        scope: &InfluenceScope,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let domain = binding.store_uuid().as_str();
        let authority = binding.security_authority_id().as_str();
        let scope_key = hex::encode(
            knowledge_digest(
                RecoveryDigestDomain::KnowledgeInfluenceScope,
                &(
                    "native-influence-tenant-account-v1",
                    domain,
                    binding,
                    scope.tenant(),
                ),
            )
            .map_err(invalid)?,
        );
        Ok(Self {
            record_key: format!(
                "{}{}",
                authority_slot_prefix(authority),
                hex::encode(
                    knowledge_digest(
                        RecoveryDigestDomain::KnowledgeInfluenceScope,
                        &("native-influence-scope-v1", domain, binding, scope),
                    )
                    .map_err(invalid)?
                )
            ),
            scope_key,
            inherited_scope: scope.clone(),
        })
    }
}

/// The record-key prefix selecting one authority's inherited-scope
/// projection rows. The projection format is unreleased: no compatibility
/// reader accepts a row without this exact authority prefix.
pub(in crate::admission_operation_store) fn authority_slot_prefix(authority: &str) -> String {
    format!(
        "knowledge-influence-scope:{}:",
        sha256_hex(authority.as_bytes())
    )
}

/// The caller supplies the binding whose store identity domains every slot.
/// The admitted producer must independently authenticate this exact flow key.
pub(super) fn source_slots(
    binding: &NativeSecurityAuthorityBindingV1,
    key: &FlowStateKey,
) -> Result<[NativeInfluenceSlot; 3], AdmissionOperationStoreError> {
    let [principal, lineage, session] = InfluenceScope::inherited(key);
    Ok([
        NativeInfluenceSlot::derive(binding, &principal)?,
        NativeInfluenceSlot::derive(binding, &lineage)?,
        NativeInfluenceSlot::derive(binding, &session)?,
    ])
}

/// Authenticate one stored projection row's exact slot identities. Both the
/// record key and the scope key are recomputed from the binding and the
/// declared inherited scope, so an own-scope record cannot be served under a
/// foreign scope and a foreign key cannot borrow this scope's custody.
pub(super) fn authenticate_slot(
    record_key: &str,
    scope_key: &str,
    binding: &NativeSecurityAuthorityBindingV1,
    declared: &InfluenceScope,
) -> Result<NativeInfluenceSlot, AdmissionOperationStoreError> {
    let slot = NativeInfluenceSlot::derive(binding, declared)?;
    if record_key != slot.record_key() || scope_key != slot.scope_key() {
        return Err(invalid(
            "current influence head changed its exact slot identity",
        ));
    }
    Ok(slot)
}

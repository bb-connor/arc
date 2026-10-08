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
}

/// This descriptor contains no capacity, allocation, purpose or Ready proof.
/// Only a genuine producer plus an actual reservation owner can spend a slot.
pub(in crate::admission_operation_store) struct NativeInfluenceSlot {
    record_key: String,
    scope_key: String,
    inherited_scope: Option<InfluenceScope>,
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

    pub(super) fn inherited_scope(&self) -> Option<&InfluenceScope> {
        self.inherited_scope.as_ref()
    }
}

/// The caller supplies the actual owner, not an agent-selected serving domain.
/// The admitted producer must independently authenticate this exact flow key.
pub(super) fn source_slots(
    owner: &SqliteServingOwner,
    binding: &NativeSecurityAuthorityBindingV1,
    key: &FlowStateKey,
) -> Result<[NativeInfluenceSlot; 4], AdmissionOperationStoreError> {
    let domain = owner.fence.store_uuid.as_str();
    if binding.store_uuid().as_str() != domain {
        return Err(invalid(
            "influence slots changed their actual serving owner",
        ));
    }
    let header = hex::encode(
        knowledge_digest(
            RecoveryDigestDomain::KnowledgeInfluenceScope,
            &(
                "native-influence-tenant-account-v1",
                domain,
                binding,
                &key.tenant_id,
            ),
        )
        .map_err(invalid)?,
    );
    let [principal, lineage, session] = InfluenceScope::inherited(key).map(|scope| {
        Ok::<_, AdmissionOperationStoreError>(NativeInfluenceSlot {
            record_key: format!(
                "native-influence-scope:{}",
                hex::encode(
                    knowledge_digest(
                        RecoveryDigestDomain::KnowledgeInfluenceScope,
                        &("native-influence-scope-v1", domain, binding, &scope),
                    )
                    .map_err(invalid)?
                ),
            ),
            scope_key: header.clone(),
            inherited_scope: Some(scope),
        })
    });
    let authority_header = hex::encode(
        knowledge_digest(
            RecoveryDigestDomain::KnowledgeInfluenceScope,
            &("native-influence-authority-v1", domain, binding),
        )
        .map_err(invalid)?,
    );
    Ok([
        principal?,
        lineage?,
        session?,
        NativeInfluenceSlot {
            record_key: format!("native-influence-authority:{authority_header}"),
            scope_key: authority_header,
            inherited_scope: None,
        },
    ])
}

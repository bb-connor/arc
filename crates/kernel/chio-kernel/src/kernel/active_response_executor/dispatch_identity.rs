//! One canonical v1 dispatch preimage shared by plan and compact evidence readers.
use super::*;

pub(super) struct DispatchIdentity<'a> {
    pub(super) tenant_id: &'a TenantId,
    pub(super) action_id: &'a ActionId,
    pub(super) plan_hash: &'a Digest32,
    pub(super) executor_authority_id: &'a str,
    pub(super) executor_authority_generation: u64,
    pub(super) authorization_capability_hash: &'a str,
    pub(super) governed_intent_hash: &'a str,
    pub(super) policy_decision_hash: &'a str,
    pub(super) authorized_at_unix_ms: u64,
    pub(super) approval: &'a ActiveResponseExecutionApproval,
}

fn canonical_dispatch_identity(
    identity: DispatchIdentity<'_>,
) -> Result<Vec<u8>, ActiveResponseDispatchIdError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct DispatchBody<'a> {
        schema: &'static str,
        tenant_id: &'a TenantId,
        action_id: &'a ActionId,
        plan_hash: &'a Digest32,
        executor_authority_id: &'a str,
        executor_authority_generation: u64,
        authorization_capability_hash: &'a str,
        governed_intent_hash: &'a str,
        policy_decision_hash: &'a str,
        authorized_at_unix_ms: u64,
        approval_mode: &'static str,
        admission_operation_id: Option<&'a str>,
        admission_operation_version: Option<u64>,
        approval_set_hash: Option<&'a str>,
    }

    let (approval_mode, admission_operation_id, admission_operation_version, approval_set_hash) =
        match identity.approval {
            ActiveResponseExecutionApproval::Automatic => ("automatic", None, None, None),
            ActiveResponseExecutionApproval::Governed {
                admission_operation_id,
                admission_operation_version,
                approval_set_hash,
            } => (
                "governed",
                Some(admission_operation_id.as_str()),
                Some(*admission_operation_version),
                Some(approval_set_hash.as_str()),
            ),
        };
    canonical_json_bytes(&DispatchBody {
        schema: ACTIVE_RESPONSE_DISPATCH_SCHEMA,
        tenant_id: identity.tenant_id,
        action_id: identity.action_id,
        plan_hash: identity.plan_hash,
        executor_authority_id: identity.executor_authority_id,
        executor_authority_generation: identity.executor_authority_generation,
        authorization_capability_hash: identity.authorization_capability_hash,
        governed_intent_hash: identity.governed_intent_hash,
        policy_decision_hash: identity.policy_decision_hash,
        authorized_at_unix_ms: identity.authorized_at_unix_ms,
        approval_mode,
        admission_operation_id,
        admission_operation_version,
        approval_set_hash,
    })
    .map_err(|error| ActiveResponseDispatchIdError::Canonicalization(error.to_string()))
}

pub(super) fn derive_legacy_dispatch_id(
    identity: DispatchIdentity<'_>,
) -> Result<RecordId, ActiveResponseDispatchIdError> {
    let canonical = canonical_dispatch_identity(identity)?;
    let mut preimage = Vec::with_capacity(ACTIVE_RESPONSE_DISPATCH_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(ACTIVE_RESPONSE_DISPATCH_DOMAIN);
    preimage.extend_from_slice(&canonical);
    RecordId::new(format!(
        "active_response_dispatch_{}",
        sha256_hex(&preimage)
    ))
    .map_err(|error| ActiveResponseDispatchIdError::InvalidIdentifier(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_legacy_dispatch_preimages_and_identifiers_are_unchanged(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let tenant = TenantId::new("tenant-legacy-dispatch")?;
        let action = ActionId::new("action-legacy-dispatch")?;
        let plan_hash = Digest32::new([1; 32]);
        {
            let approval = ActiveResponseExecutionApproval::Automatic;
            let identity = || DispatchIdentity {
                tenant_id: &tenant,
                action_id: &action,
                plan_hash: &plan_hash,
                executor_authority_id:
                    "0202020202020202020202020202020202020202020202020202020202020202",
                executor_authority_generation: 7,
                authorization_capability_hash:
                    "0303030303030303030303030303030303030303030303030303030303030303",
                governed_intent_hash:
                    "0404040404040404040404040404040404040404040404040404040404040404",
                policy_decision_hash:
                    "0505050505050505050505050505050505050505050505050505050505050505",
                authorized_at_unix_ms: 41_000,
                approval: &approval,
            };
            assert_eq!(canonical_dispatch_identity(identity())?, br#"{"actionId":"action-legacy-dispatch","admissionOperationId":null,"admissionOperationVersion":null,"approvalMode":"automatic","approvalSetHash":null,"authorizationCapabilityHash":"0303030303030303030303030303030303030303030303030303030303030303","authorizedAtUnixMs":41000,"executorAuthorityGeneration":7,"executorAuthorityId":"0202020202020202020202020202020202020202020202020202020202020202","governedIntentHash":"0404040404040404040404040404040404040404040404040404040404040404","planHash":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"policyDecisionHash":"0505050505050505050505050505050505050505050505050505050505050505","schema":"chio.active-response-dispatch.v1","tenantId":"tenant-legacy-dispatch"}"#);
            assert_eq!(derive_legacy_dispatch_id(identity())?.as_str(), "active_response_dispatch_1638b515135d62993943c82d8a565b63f5845e8e83aa73cb1d39edd1a592e621");
        }
        {
            let approval = ActiveResponseExecutionApproval::Governed {
                admission_operation_id: "original-governed-operation".to_owned(),
                admission_operation_version: 9,
                approval_set_hash: "06".repeat(32),
            };
            let identity = || DispatchIdentity {
                tenant_id: &tenant,
                action_id: &action,
                plan_hash: &plan_hash,
                executor_authority_id:
                    "0202020202020202020202020202020202020202020202020202020202020202",
                executor_authority_generation: 7,
                authorization_capability_hash:
                    "0303030303030303030303030303030303030303030303030303030303030303",
                governed_intent_hash:
                    "0404040404040404040404040404040404040404040404040404040404040404",
                policy_decision_hash:
                    "0505050505050505050505050505050505050505050505050505050505050505",
                authorized_at_unix_ms: 41_000,
                approval: &approval,
            };
            assert_eq!(canonical_dispatch_identity(identity())?, br#"{"actionId":"action-legacy-dispatch","admissionOperationId":"original-governed-operation","admissionOperationVersion":9,"approvalMode":"governed","approvalSetHash":"0606060606060606060606060606060606060606060606060606060606060606","authorizationCapabilityHash":"0303030303030303030303030303030303030303030303030303030303030303","authorizedAtUnixMs":41000,"executorAuthorityGeneration":7,"executorAuthorityId":"0202020202020202020202020202020202020202020202020202020202020202","governedIntentHash":"0404040404040404040404040404040404040404040404040404040404040404","planHash":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"policyDecisionHash":"0505050505050505050505050505050505050505050505050505050505050505","schema":"chio.active-response-dispatch.v1","tenantId":"tenant-legacy-dispatch"}"#);
            assert_eq!(derive_legacy_dispatch_id(identity())?.as_str(), "active_response_dispatch_f74c081c99ef8eb5b0bd48c9c7647a73f32b47156274b6170ffa68cc88151fc7");
        }
        Ok(())
    }
}

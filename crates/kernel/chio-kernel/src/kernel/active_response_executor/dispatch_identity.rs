//! Canonical dispatch identities bind the authorization and admission artifact.
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
    pub(super) admission_artifact_fingerprint: &'a Digest32,
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
        admission_artifact_fingerprint: &'a Digest32,
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
        admission_artifact_fingerprint: identity.admission_artifact_fingerprint,
    })
    .map_err(|error| ActiveResponseDispatchIdError::Canonicalization(error.to_string()))
}

pub(super) fn derive_dispatch_id(
    identity: DispatchIdentity<'_>,
) -> Result<RecordId, ActiveResponseDispatchIdError> {
    if identity.admission_artifact_fingerprint.is_zero() {
        return Err(ActiveResponseDispatchIdError::InvalidIdentifier(
            "admission artifact fingerprint is zero".to_string(),
        ));
    }
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

    fn identity<'a>(
        tenant: &'a TenantId,
        action: &'a ActionId,
        plan_hash: &'a Digest32,
        approval: &'a ActiveResponseExecutionApproval,
        fingerprint: &'a Digest32,
    ) -> DispatchIdentity<'a> {
        DispatchIdentity {
            tenant_id: tenant,
            action_id: action,
            plan_hash,
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
            approval,
            admission_artifact_fingerprint: fingerprint,
        }
    }

    #[test]
    fn canonical_dispatch_preimages_and_identifiers_bind_the_artifact(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let tenant = TenantId::new("tenant-dispatch")?;
        let action = ActionId::new("action-dispatch")?;
        let plan_hash = Digest32::new([1; 32]);
        let fingerprint = Digest32::new([7; 32]);
        let automatic = ActiveResponseExecutionApproval::Automatic;
        let governed = ActiveResponseExecutionApproval::Governed {
            admission_operation_id: "governed-operation".to_owned(),
            admission_operation_version: 9,
            approval_set_hash: "06".repeat(32),
        };
        for (approval, expected_body, expected_id) in [
            (&automatic, br#"{"actionId":"action-dispatch","admissionArtifactFingerprint":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"admissionOperationId":null,"admissionOperationVersion":null,"approvalMode":"automatic","approvalSetHash":null,"authorizationCapabilityHash":"0303030303030303030303030303030303030303030303030303030303030303","authorizedAtUnixMs":41000,"executorAuthorityGeneration":7,"executorAuthorityId":"0202020202020202020202020202020202020202020202020202020202020202","governedIntentHash":"0404040404040404040404040404040404040404040404040404040404040404","planHash":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"policyDecisionHash":"0505050505050505050505050505050505050505050505050505050505050505","schema":"chio.active-response-dispatch.v1","tenantId":"tenant-dispatch"}"#.as_slice(), "active_response_dispatch_8ee0d2aaa467c7bfb5a71783c2b74ae4a5bb4b0bb15efe1609794d3a38605d4e"),
            (&governed, br#"{"actionId":"action-dispatch","admissionArtifactFingerprint":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"admissionOperationId":"governed-operation","admissionOperationVersion":9,"approvalMode":"governed","approvalSetHash":"0606060606060606060606060606060606060606060606060606060606060606","authorizationCapabilityHash":"0303030303030303030303030303030303030303030303030303030303030303","authorizedAtUnixMs":41000,"executorAuthorityGeneration":7,"executorAuthorityId":"0202020202020202020202020202020202020202020202020202020202020202","governedIntentHash":"0404040404040404040404040404040404040404040404040404040404040404","planHash":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"policyDecisionHash":"0505050505050505050505050505050505050505050505050505050505050505","schema":"chio.active-response-dispatch.v1","tenantId":"tenant-dispatch"}"#.as_slice(), "active_response_dispatch_7c478a20ff2aea853627b155e45157f25dd23716149b404f7f78d685fbf613e6"),
        ] {
            let input = || identity(&tenant, &action, &plan_hash, approval, &fingerprint);
            assert_eq!(canonical_dispatch_identity(input())?, expected_body);
            assert_eq!(derive_dispatch_id(input())?.as_str(), expected_id);
            assert_ne!(
                derive_dispatch_id(input())?,
                derive_dispatch_id(identity(&tenant, &action, &plan_hash, approval, &Digest32::new([8; 32])))?
            );
        }
        Ok(())
    }

    #[test]
    fn zero_artifact_fingerprint_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let tenant = TenantId::new("tenant-dispatch")?;
        let action = ActionId::new("action-dispatch")?;
        assert_eq!(
            derive_dispatch_id(identity(
                &tenant,
                &action,
                &Digest32::new([1; 32]),
                &ActiveResponseExecutionApproval::Automatic,
                &Digest32::new([0; 32]),
            )),
            Err(ActiveResponseDispatchIdError::InvalidIdentifier(
                "admission artifact fingerprint is zero".to_owned()
            ))
        );
        Ok(())
    }
}

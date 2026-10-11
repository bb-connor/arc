use chio_core::capability::scope::Operation;
use chio_core::capability::threshold_approval::ThresholdApprovalRequirement;
use sha2::{Digest, Sha256};

use super::types::{
    ChioPolicy, DefaultCapability, KernelPolicyConfig, PolicyAssetDigest, PolicyError,
    PolicyFormat, ReputationIssuancePolicy, RuntimeAssuranceIssuancePolicy,
};

const RUNTIME_POLICY_IDENTITY_SCHEMA: &str = "chio.runtime-policy.v3";

pub(super) fn parse_operations(operations: &[String]) -> Result<Vec<Operation>, PolicyError> {
    operations
        .iter()
        .map(|op| match op.as_str() {
            "invoke" => Ok(Operation::Invoke),
            "read_result" => Ok(Operation::ReadResult),
            "read" => Ok(Operation::Read),
            "subscribe" => Ok(Operation::Subscribe),
            "get" => Ok(Operation::Get),
            "delegate" => Ok(Operation::Delegate),
            _ => Err(PolicyError::Invalid(format!(
                "unsupported capability operation: {op}"
            ))),
        })
        .collect()
}

pub(super) fn runtime_hash_for_chio_yaml(
    policy: &ChioPolicy,
    default_capabilities: &[DefaultCapability],
) -> Result<String, PolicyError> {
    ensure_finite_policy_numbers(policy)?;
    let fingerprint = serde_json::json!({
        "schema": RUNTIME_POLICY_IDENTITY_SCHEMA,
        "format": PolicyFormat::ChioYaml.as_str(),
        "kernel": policy.kernel,
        "guards": policy.guards,
        "default_guard_profile": default_guard_profile_identity()?,
        "default_capabilities": default_capabilities,
    });
    hash_json_value(&fingerprint)
}

pub(super) fn runtime_hash_for_hushspec(
    kernel: &KernelPolicyConfig,
    default_capabilities: &[DefaultCapability],
    spec: &chio_policy::HushSpec,
    auxiliary_assets: &[PolicyAssetDigest],
    issuance_policy: Option<&ReputationIssuancePolicy>,
    runtime_assurance_policy: Option<&RuntimeAssuranceIssuancePolicy>,
    threshold_approval: Option<&ThresholdApprovalRequirement>,
) -> Result<String, PolicyError> {
    ensure_finite_policy_numbers(spec)?;
    ensure_finite_policy_numbers(&issuance_policy)?;
    ensure_finite_policy_numbers(&runtime_assurance_policy)?;
    // Bind resolved approval material before inserting the resulting policy
    // hash. Exhaustive destructuring makes new approval fields an explicit
    // identity decision rather than silently leaving them out of the digest.
    let approval_material = threshold_approval.map(|requirement| {
        let ThresholdApprovalRequirement {
            policy_hash: _,
            threshold,
            eligible_approvers,
            eligible_set_digest,
            directory_version,
            timeout_seconds,
        } = requirement;
        serde_json::json!({
            "threshold": threshold,
            "eligible_approvers": eligible_approvers,
            "eligible_set_digest": eligible_set_digest,
            "directory_version": directory_version,
            "timeout_seconds": timeout_seconds,
        })
    });
    let fingerprint = serde_json::json!({
        "schema": RUNTIME_POLICY_IDENTITY_SCHEMA,
        "format": PolicyFormat::HushSpec.as_str(),
        "kernel": kernel,
        "default_capabilities": default_capabilities,
        "resolved_policy": spec,
        "default_guard_profile": default_guard_profile_identity()?,
        "issuance_policy": issuance_policy,
        "runtime_assurance_policy": runtime_assurance_policy,
        "threshold_approval": approval_material,
        "auxiliary_assets": auxiliary_assets,
    });
    hash_json_value(&fingerprint)
}

fn default_guard_profile_identity() -> Result<String, PolicyError> {
    chio_guards::default_runtime_guard_profile_identity().map_err(|error| {
        PolicyError::Invalid(format!(
            "default guard profile identity is invalid: {error}"
        ))
    })
}

fn ensure_finite_policy_numbers(policy: &impl serde::Serialize) -> Result<(), PolicyError> {
    // JSON serialization silently turns NaN and infinities into null. Inspect
    // a typed representation that retains these numbers before JSON encoding
    // can erase differences in the configured enforcement behavior.
    let value = serde_yml::to_value(policy)?;
    let mut pending = vec![&value];
    while let Some(value) = pending.pop() {
        match value {
            serde_yml::Value::Number(number)
                if number.as_f64().is_some_and(|number| !number.is_finite()) =>
            {
                return Err(PolicyError::Invalid(
                    "policy identity requires finite numeric values".to_string(),
                ));
            }
            serde_yml::Value::Sequence(values) => pending.extend(values),
            serde_yml::Value::Mapping(values) => {
                pending.extend(values.keys());
                pending.extend(values.values());
            }
            serde_yml::Value::Tagged(value) => pending.push(&value.value),
            _ => {}
        }
    }
    Ok(())
}

pub(super) fn hash_json_value(value: &serde_json::Value) -> Result<String, PolicyError> {
    let encoded = chio_core::canonical::canonical_json_bytes(value).map_err(|error| {
        PolicyError::Invalid(format!("policy identity cannot be canonicalized: {error}"))
    })?;
    Ok(hash_bytes(&encoded))
}

pub(super) fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

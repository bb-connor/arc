use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::capability::{RuntimeAttestationEvidence, WorkloadIdentity};

pub const AZURE_MAA_ATTESTATION_SCHEMA: &str = "arc.runtime-attestation.azure-maa.jwt.v1";
pub const AWS_NITRO_ATTESTATION_SCHEMA: &str = "arc.runtime-attestation.aws-nitro-attestation.v1";
pub const GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA: &str =
    "arc.runtime-attestation.google-confidential-vm.jwt.v1";
pub const ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA: &str =
    "arc.runtime-attestation.enterprise-verifier.json.v1";
pub const AZURE_MAA_VERIFIER_ADAPTER: &str = "azure_maa";
pub const AWS_NITRO_VERIFIER_ADAPTER: &str = "aws_nitro";
pub const GOOGLE_CONFIDENTIAL_VM_VERIFIER_ADAPTER: &str = "google_confidential_vm";
pub const ENTERPRISE_VERIFIER_ADAPTER: &str = "enterprise_verifier";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerifierFamily {
    AzureMaa,
    AwsNitro,
    GoogleAttestation,
    EnterpriseVerifier,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RuntimeAttestationTrustMaterialError {
    #[error("runtime attestation schema `{schema}` is not supported by the shared trust boundary")]
    UnsupportedSchema { schema: String },
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RuntimeAttestationTrustMaterial {
    pub verifier_family: AttestationVerifierFamily,
    pub normalized_assertions: BTreeMap<String, Value>,
}

#[must_use]
pub fn verifier_family_for_attestation_schema(schema: &str) -> Option<AttestationVerifierFamily> {
    match schema {
        AZURE_MAA_ATTESTATION_SCHEMA => Some(AttestationVerifierFamily::AzureMaa),
        AWS_NITRO_ATTESTATION_SCHEMA => Some(AttestationVerifierFamily::AwsNitro),
        GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA => {
            Some(AttestationVerifierFamily::GoogleAttestation)
        }
        ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA => {
            Some(AttestationVerifierFamily::EnterpriseVerifier)
        }
        _ => None,
    }
}

pub(crate) fn derive_runtime_attestation_trust_material(
    evidence: &RuntimeAttestationEvidence,
) -> Result<RuntimeAttestationTrustMaterial, RuntimeAttestationTrustMaterialError> {
    let (verifier_family, normalized_assertions) = match evidence.schema.as_str() {
        AZURE_MAA_ATTESTATION_SCHEMA => (
            AttestationVerifierFamily::AzureMaa,
            azure_normalized_assertions(evidence),
        ),
        AWS_NITRO_ATTESTATION_SCHEMA => (
            AttestationVerifierFamily::AwsNitro,
            aws_nitro_normalized_assertions(evidence),
        ),
        GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA => (
            AttestationVerifierFamily::GoogleAttestation,
            google_confidential_vm_normalized_assertions(evidence),
        ),
        ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA => (
            AttestationVerifierFamily::EnterpriseVerifier,
            enterprise_verifier_normalized_assertions(evidence),
        ),
        _ => {
            return Err(RuntimeAttestationTrustMaterialError::UnsupportedSchema {
                schema: evidence.schema.clone(),
            });
        }
    };

    Ok(RuntimeAttestationTrustMaterial {
        verifier_family,
        normalized_assertions,
    })
}

fn extract_vendor_claims(
    evidence: &RuntimeAttestationEvidence,
    vendor_key: &str,
) -> BTreeMap<String, Value> {
    evidence
        .claims
        .as_ref()
        .and_then(|claims| claims.get(vendor_key))
        .and_then(Value::as_object)
        .map(|claims| {
            claims
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default()
}

fn azure_normalized_assertions(evidence: &RuntimeAttestationEvidence) -> BTreeMap<String, Value> {
    let vendor_claims = extract_vendor_claims(evidence, "azureMaa");
    let mut normalized = BTreeMap::new();
    if let Some(attestation_type) = vendor_claims.get("attestationType") {
        normalized.insert("attestationType".to_string(), attestation_type.clone());
    }
    if let Some(runtime_identity) = evidence.runtime_identity.as_ref() {
        normalized.insert(
            "runtimeIdentity".to_string(),
            Value::String(runtime_identity.clone()),
        );
    }
    push_workload_identity_assertions(&mut normalized, evidence.workload_identity.as_ref());
    normalized
}

fn aws_nitro_normalized_assertions(
    evidence: &RuntimeAttestationEvidence,
) -> BTreeMap<String, Value> {
    let vendor_claims = extract_vendor_claims(evidence, "awsNitro");
    let mut normalized = BTreeMap::new();
    if let Some(module_id) = vendor_claims.get("moduleId") {
        normalized.insert("moduleId".to_string(), module_id.clone());
    }
    if let Some(digest) = vendor_claims.get("digest") {
        normalized.insert("digest".to_string(), digest.clone());
    }
    if let Some(pcrs) = vendor_claims.get("pcrs") {
        normalized.insert("pcrs".to_string(), pcrs.clone());
    }
    normalized
}

fn google_confidential_vm_normalized_assertions(
    evidence: &RuntimeAttestationEvidence,
) -> BTreeMap<String, Value> {
    let vendor_claims = extract_vendor_claims(evidence, "googleAttestation");
    let mut normalized = BTreeMap::new();
    if let Some(attestation_type) = vendor_claims.get("attestationType") {
        normalized.insert("attestationType".to_string(), attestation_type.clone());
    }
    if let Some(hardware_model) = vendor_claims.get("hardwareModel") {
        normalized.insert("hardwareModel".to_string(), hardware_model.clone());
    }
    if let Some(secure_boot) = vendor_claims.get("secureBoot") {
        normalized.insert("secureBoot".to_string(), secure_boot.clone());
    }
    if let Some(runtime_identity) = evidence.runtime_identity.as_ref() {
        normalized.insert(
            "runtimeIdentity".to_string(),
            Value::String(runtime_identity.clone()),
        );
    }
    push_workload_identity_assertions(&mut normalized, evidence.workload_identity.as_ref());
    normalized
}

fn enterprise_verifier_normalized_assertions(
    evidence: &RuntimeAttestationEvidence,
) -> BTreeMap<String, Value> {
    let vendor_claims = extract_vendor_claims(evidence, "enterpriseVerifier");
    let mut normalized = BTreeMap::new();
    for key in [
        "attestationType",
        "moduleId",
        "digest",
        "pcrs",
        "hardwareModel",
        "secureBoot",
    ] {
        if let Some(value) = vendor_claims.get(key) {
            normalized.insert(key.to_string(), value.clone());
        }
    }
    if let Some(runtime_identity) = evidence.runtime_identity.as_ref() {
        normalized.insert(
            "runtimeIdentity".to_string(),
            Value::String(runtime_identity.clone()),
        );
    }
    push_workload_identity_assertions(&mut normalized, evidence.workload_identity.as_ref());
    normalized
}

fn push_workload_identity_assertions(
    normalized: &mut BTreeMap<String, Value>,
    workload_identity: Option<&WorkloadIdentity>,
) {
    if let Some(workload_identity) = workload_identity {
        normalized.insert(
            "workloadIdentityScheme".to_string(),
            Value::String(format!("{:?}", workload_identity.scheme).to_lowercase()),
        );
        normalized.insert(
            "workloadIdentityUri".to_string(),
            Value::String(workload_identity.uri.clone()),
        );
    }
}

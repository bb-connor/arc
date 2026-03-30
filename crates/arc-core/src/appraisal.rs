use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::capability::{RuntimeAssuranceTier, RuntimeAttestationEvidence, WorkloadIdentity};
use crate::receipt::SignedExportEnvelope;

pub const AZURE_MAA_ATTESTATION_SCHEMA: &str = "arc.runtime-attestation.azure-maa.jwt.v1";
pub const AWS_NITRO_ATTESTATION_SCHEMA: &str = "arc.runtime-attestation.aws-nitro-attestation.v1";
pub const GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA: &str =
    "arc.runtime-attestation.google-confidential-vm.jwt.v1";
pub const AZURE_MAA_VERIFIER_ADAPTER: &str = "azure_maa";
pub const AWS_NITRO_VERIFIER_ADAPTER: &str = "aws_nitro";
pub const GOOGLE_CONFIDENTIAL_VM_VERIFIER_ADAPTER: &str = "google_confidential_vm";

pub const RUNTIME_ATTESTATION_APPRAISAL_SCHEMA: &str = "arc.runtime-attestation.appraisal.v1";
pub const RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA: &str =
    "arc.runtime-attestation.appraisal-report.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerifierFamily {
    AzureMaa,
    AwsNitro,
    GoogleAttestation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAttestationAppraisalVerdict {
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAttestationAppraisalReasonCode {
    EvidenceVerified,
    UnsupportedEvidence,
    PolicyRejected,
    InvalidClaims,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeAttestationAppraisalError {
    #[error("runtime attestation schema `{schema}` is not recognized by the canonical appraisal boundary")]
    UnsupportedSchema { schema: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationEvidenceDescriptor {
    pub schema: String,
    pub verifier: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub evidence_sha256: String,
}

impl From<&RuntimeAttestationEvidence> for RuntimeAttestationEvidenceDescriptor {
    fn from(value: &RuntimeAttestationEvidence) -> Self {
        Self {
            schema: value.schema.clone(),
            verifier: value.verifier.clone(),
            issued_at: value.issued_at,
            expires_at: value.expires_at,
            evidence_sha256: value.evidence_sha256.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationAppraisal {
    pub schema: String,
    pub adapter: String,
    pub verifier_family: AttestationVerifierFamily,
    pub evidence: RuntimeAttestationEvidenceDescriptor,
    pub verdict: RuntimeAttestationAppraisalVerdict,
    pub effective_tier: RuntimeAssuranceTier,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub normalized_assertions: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vendor_claims: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<RuntimeAttestationAppraisalReasonCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_identity: Option<WorkloadIdentity>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationAppraisalRequest {
    pub runtime_attestation: RuntimeAttestationEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationPolicyOutcome {
    pub trust_policy_configured: bool,
    pub accepted: bool,
    pub effective_tier: RuntimeAssuranceTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationAppraisalReport {
    pub schema: String,
    pub generated_at: u64,
    pub appraisal: RuntimeAttestationAppraisal,
    pub policy_outcome: RuntimeAttestationPolicyOutcome,
}

pub type SignedRuntimeAttestationAppraisalReport =
    SignedExportEnvelope<RuntimeAttestationAppraisalReport>;

impl RuntimeAttestationAppraisal {
    #[must_use]
    pub fn accepted(
        adapter: impl Into<String>,
        verifier_family: AttestationVerifierFamily,
        evidence: &RuntimeAttestationEvidence,
        normalized_assertions: BTreeMap<String, Value>,
        vendor_claims: BTreeMap<String, Value>,
        reason_codes: Vec<RuntimeAttestationAppraisalReasonCode>,
    ) -> Self {
        Self {
            schema: RUNTIME_ATTESTATION_APPRAISAL_SCHEMA.to_string(),
            adapter: adapter.into(),
            verifier_family,
            evidence: RuntimeAttestationEvidenceDescriptor::from(evidence),
            verdict: RuntimeAttestationAppraisalVerdict::Accepted,
            effective_tier: evidence.tier,
            normalized_assertions,
            vendor_claims,
            reason_codes,
            workload_identity: evidence.workload_identity.clone(),
        }
    }

    #[must_use]
    pub fn rejected(
        adapter: impl Into<String>,
        verifier_family: AttestationVerifierFamily,
        evidence: &RuntimeAttestationEvidence,
        normalized_assertions: BTreeMap<String, Value>,
        vendor_claims: BTreeMap<String, Value>,
        reason_codes: Vec<RuntimeAttestationAppraisalReasonCode>,
    ) -> Self {
        Self {
            schema: RUNTIME_ATTESTATION_APPRAISAL_SCHEMA.to_string(),
            adapter: adapter.into(),
            verifier_family,
            evidence: RuntimeAttestationEvidenceDescriptor::from(evidence),
            verdict: RuntimeAttestationAppraisalVerdict::Rejected,
            effective_tier: RuntimeAssuranceTier::None,
            normalized_assertions,
            vendor_claims,
            reason_codes,
            workload_identity: evidence.workload_identity.clone(),
        }
    }
}

#[must_use]
pub fn verifier_family_for_attestation_schema(schema: &str) -> Option<AttestationVerifierFamily> {
    match schema {
        AZURE_MAA_ATTESTATION_SCHEMA => Some(AttestationVerifierFamily::AzureMaa),
        AWS_NITRO_ATTESTATION_SCHEMA => Some(AttestationVerifierFamily::AwsNitro),
        GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA => {
            Some(AttestationVerifierFamily::GoogleAttestation)
        }
        _ => None,
    }
}

pub fn derive_runtime_attestation_appraisal(
    evidence: &RuntimeAttestationEvidence,
) -> Result<RuntimeAttestationAppraisal, RuntimeAttestationAppraisalError> {
    match evidence.schema.as_str() {
        AZURE_MAA_ATTESTATION_SCHEMA => Ok(RuntimeAttestationAppraisal::accepted(
            AZURE_MAA_VERIFIER_ADAPTER,
            AttestationVerifierFamily::AzureMaa,
            evidence,
            azure_normalized_assertions(evidence),
            extract_vendor_claims(evidence, "azureMaa"),
            vec![RuntimeAttestationAppraisalReasonCode::EvidenceVerified],
        )),
        AWS_NITRO_ATTESTATION_SCHEMA => Ok(RuntimeAttestationAppraisal::accepted(
            AWS_NITRO_VERIFIER_ADAPTER,
            AttestationVerifierFamily::AwsNitro,
            evidence,
            aws_nitro_normalized_assertions(evidence),
            extract_vendor_claims(evidence, "awsNitro"),
            vec![RuntimeAttestationAppraisalReasonCode::EvidenceVerified],
        )),
        GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA => Ok(RuntimeAttestationAppraisal::accepted(
            GOOGLE_CONFIDENTIAL_VM_VERIFIER_ADAPTER,
            AttestationVerifierFamily::GoogleAttestation,
            evidence,
            google_confidential_vm_normalized_assertions(evidence),
            extract_vendor_claims(evidence, "googleAttestation"),
            vec![RuntimeAttestationAppraisalReasonCode::EvidenceVerified],
        )),
        _ => Err(RuntimeAttestationAppraisalError::UnsupportedSchema {
            schema: evidence.schema.clone(),
        }),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{
        RuntimeAssuranceTier, RuntimeAttestationEvidence, WorkloadCredentialKind, WorkloadIdentity,
        WorkloadIdentityScheme,
    };
    use serde_json::json;

    fn sample_evidence() -> RuntimeAttestationEvidence {
        RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "abc123".to_string(),
            runtime_identity: Some("spiffe://contoso.test/runtime/worker".to_string()),
            workload_identity: Some(WorkloadIdentity {
                scheme: WorkloadIdentityScheme::Spiffe,
                credential_kind: WorkloadCredentialKind::Uri,
                uri: "spiffe://contoso.test/runtime/worker".to_string(),
                trust_domain: "contoso.test".to_string(),
                path: "/runtime/worker".to_string(),
            }),
            claims: Some(json!({
                "azureMaa": {
                    "attestationType": "sgx"
                }
            })),
        }
    }

    #[test]
    fn runtime_attestation_appraisal_copies_evidence_descriptor_fields() {
        let evidence = sample_evidence();
        let appraisal = RuntimeAttestationAppraisal::accepted(
            "azure_maa",
            AttestationVerifierFamily::AzureMaa,
            &evidence,
            BTreeMap::new(),
            BTreeMap::new(),
            vec![RuntimeAttestationAppraisalReasonCode::EvidenceVerified],
        );

        assert_eq!(appraisal.schema, RUNTIME_ATTESTATION_APPRAISAL_SCHEMA);
        assert_eq!(appraisal.evidence.schema, evidence.schema);
        assert_eq!(appraisal.evidence.verifier, evidence.verifier);
        assert_eq!(appraisal.evidence.evidence_sha256, evidence.evidence_sha256);
        assert_eq!(
            appraisal.verdict,
            RuntimeAttestationAppraisalVerdict::Accepted
        );
        assert_eq!(appraisal.effective_tier, RuntimeAssuranceTier::Attested);
    }

    #[test]
    fn rejected_runtime_attestation_appraisal_drops_effective_tier() {
        let evidence = sample_evidence();
        let appraisal = RuntimeAttestationAppraisal::rejected(
            "azure_maa",
            AttestationVerifierFamily::AzureMaa,
            &evidence,
            BTreeMap::new(),
            BTreeMap::new(),
            vec![RuntimeAttestationAppraisalReasonCode::PolicyRejected],
        );

        assert_eq!(
            appraisal.verdict,
            RuntimeAttestationAppraisalVerdict::Rejected
        );
        assert_eq!(appraisal.effective_tier, RuntimeAssuranceTier::None);
        assert_eq!(
            appraisal.reason_codes,
            vec![RuntimeAttestationAppraisalReasonCode::PolicyRejected]
        );
    }

    #[test]
    fn derive_runtime_attestation_appraisal_supports_google_confidential_vm() {
        let evidence = RuntimeAttestationEvidence {
            schema: GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA.to_string(),
            verifier: "https://confidentialcomputing.googleapis.com".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "google-digest".to_string(),
            runtime_identity: Some(
                "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1"
                    .to_string(),
            ),
            workload_identity: None,
            claims: Some(json!({
                "googleAttestation": {
                    "attestationType": "confidential_vm",
                    "hardwareModel": "GCP_AMD_SEV",
                    "secureBoot": "enabled"
                }
            })),
        };

        let appraisal = derive_runtime_attestation_appraisal(&evidence)
            .expect("google evidence should derive a canonical appraisal");
        assert_eq!(
            appraisal.verifier_family,
            AttestationVerifierFamily::GoogleAttestation
        );
        assert_eq!(
            appraisal.normalized_assertions["attestationType"],
            "confidential_vm"
        );
        assert_eq!(
            appraisal.normalized_assertions["hardwareModel"],
            "GCP_AMD_SEV"
        );
        assert_eq!(appraisal.normalized_assertions["secureBoot"], "enabled");
    }
}

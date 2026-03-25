#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentPassport {
    pub schema: String,
    pub subject: String,
    pub credentials: Vec<ReputationCredential>,
    pub merkle_roots: Vec<String>,
    pub issued_at: String,
    pub valid_until: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PassportVerification {
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issuers: Vec<String>,
    pub issuer_count: usize,
    pub credential_count: usize,
    pub merkle_root_count: usize,
    pub verified_at: u64,
    pub valid_until: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct PassportVerifierPolicy {
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub issuer_allowlist: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_composite_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_reliability: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_least_privilege: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_delegation_hygiene: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_boundary_pressure: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_receipt_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_lineage_records: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_history_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_attestation_age_days: Option<u32>,
    #[serde(default)]
    pub require_checkpoint_coverage: bool,
    #[serde(default)]
    pub require_receipt_log_urls: bool,
}

impl PassportVerifierPolicy {
    pub fn validate(&self) -> Result<(), CredentialError> {
        validate_unit_interval("min_composite_score", self.min_composite_score)?;
        validate_unit_interval("min_reliability", self.min_reliability)?;
        validate_unit_interval("min_least_privilege", self.min_least_privilege)?;
        validate_unit_interval("min_delegation_hygiene", self.min_delegation_hygiene)?;
        validate_unit_interval("max_boundary_pressure", self.max_boundary_pressure)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SignedPassportVerifierPolicyBody {
    pub schema: String,
    pub policy_id: String,
    pub verifier: String,
    pub signer_public_key: PublicKey,
    pub created_at: u64,
    pub expires_at: u64,
    pub policy: PassportVerifierPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SignedPassportVerifierPolicy {
    pub body: SignedPassportVerifierPolicyBody,
    pub signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PassportVerifierPolicyReference {
    pub policy_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CredentialPolicyEvaluation {
    pub index: usize,
    pub issuer: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    pub issuance_date: String,
    pub expiration_date: String,
    pub attestation_until: u64,
    pub receipt_count: usize,
    pub lineage_records: usize,
    pub uncheckpointed_receipts: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composite_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reliability: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub least_privilege: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_hygiene: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary_pressure: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PassportPolicyEvaluation {
    pub verification: PassportVerification,
    pub accepted: bool,
    pub matched_credential_indexes: Vec<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_issuers: Vec<String>,
    pub policy: PassportVerifierPolicy,
    pub credential_results: Vec<CredentialPolicyEvaluation>,
}


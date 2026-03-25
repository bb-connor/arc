#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("did error: {0}")]
    Did(#[from] DidError),

    #[error("core error: {0}")]
    Core(#[from] pact_core::Error),

    #[error("invalid unix timestamp: {0}")]
    InvalidUnixTimestamp(u64),

    #[error("invalid RFC3339 timestamp: {0}")]
    InvalidTimestamp(String),

    #[error("credential proof type must be {PROOF_TYPE}")]
    InvalidProofType,

    #[error("credential proof purpose must be {PROOF_PURPOSE}")]
    InvalidProofPurpose,

    #[error("credential verification method does not match issuer DID")]
    IssuerVerificationMethodMismatch,

    #[error("credential subject DID does not match the embedded scorecard subject")]
    SubjectDidMismatch,

    #[error("credential has expired")]
    CredentialExpired,

    #[error("credential issuance date must be before or equal to expiration date")]
    InvalidCredentialValidityWindow,

    #[error("credential signature verification failed")]
    InvalidCredentialSignature,

    #[error("passport must contain at least one credential")]
    EmptyPassport,

    #[error("passport subject does not match credential subject {0}")]
    PassportSubjectMismatch(String),

    #[error("passport validUntil extends beyond at least one contained credential")]
    PassportValidityMismatch,

    #[error("verifier policy threshold for {field} must be within [0.0, 1.0], got {value}")]
    InvalidVerifierThreshold { field: &'static str, value: f64 },

    #[error("signed verifier policy schema must be {PASSPORT_VERIFIER_POLICY_SCHEMA}")]
    InvalidSignedVerifierPolicySchema,

    #[error("signed verifier policy created_at must be before or equal to expires_at")]
    InvalidSignedVerifierPolicyValidityWindow,

    #[error("signed verifier policy must include a non-empty policy_id")]
    MissingSignedVerifierPolicyId,

    #[error("signed verifier policy must include a non-empty verifier")]
    MissingSignedVerifierVerifier,

    #[error("signed verifier policy signature verification failed")]
    InvalidSignedVerifierPolicySignature,

    #[error("signed verifier policy is not yet valid")]
    SignedVerifierPolicyNotYetValid,

    #[error("signed verifier policy has expired")]
    SignedVerifierPolicyExpired,

    #[error("challenge schema must be {PASSPORT_PRESENTATION_CHALLENGE_SCHEMA}")]
    InvalidChallengeSchema,

    #[error("challenge issuance date must be before or equal to expiration date")]
    InvalidChallengeValidityWindow,

    #[error("challenge is not yet valid")]
    ChallengeNotYetValid,

    #[error("challenge has expired")]
    ChallengeExpired,

    #[error("presentation schema must be {PASSPORT_PRESENTATION_RESPONSE_SCHEMA}")]
    InvalidPresentationSchema,

    #[error("presentation holder key does not match passport subject")]
    PresentationHolderMismatch,

    #[error("presentation proof type must be {PROOF_TYPE}")]
    InvalidPresentationProofType,

    #[error("presentation proof purpose must be {PRESENTATION_PROOF_PURPOSE}")]
    InvalidPresentationProofPurpose,

    #[error("presentation verification method does not match passport subject DID")]
    PresentationVerificationMethodMismatch,

    #[error("presentation proof timestamp must fall within the challenge validity window")]
    PresentationProofOutsideChallengeWindow,

    #[error("presentation proof timestamp is in the future")]
    PresentationProofFromFuture,

    #[error("presentation signature verification failed")]
    InvalidPresentationSignature,

    #[error("expected challenge does not match embedded challenge")]
    ChallengeMismatch,

    #[error("presentation includes issuer {0} outside the challenge allowlist")]
    PresentationIssuerNotAllowed(String),

    #[error("presentation includes {actual} credential(s), exceeding challenge maximum {max}")]
    PresentationCredentialLimitExceeded { max: usize, actual: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AttestationWindow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    pub until: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PactCredentialEvidence {
    pub query: AttestationWindow,
    pub receipt_count: usize,
    pub receipt_ids: Vec<String>,
    pub checkpoint_roots: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipt_log_urls: Vec<String>,
    pub lineage_records: usize,
    pub uncheckpointed_receipts: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReputationCredentialSubject {
    pub id: String,
    pub metrics: LocalReputationScorecard,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedReputationCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,
    pub issuer: String,
    pub issuance_date: String,
    pub expiration_date: String,
    pub credential_subject: ReputationCredentialSubject,
    pub evidence: PactCredentialEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CredentialProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub created: String,
    pub proof_purpose: String,
    pub verification_method: String,
    pub proof_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReputationCredential {
    #[serde(flatten)]
    pub unsigned: UnsignedReputationCredential,
    pub proof: CredentialProof,
}


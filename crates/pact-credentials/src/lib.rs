//! Portable reputation credentials and Agent Passport verification for PACT.
//!
//! The alpha format is intentionally simple:
//! - credentials are canonically JSON-signed with Ed25519
//! - issuer and subject identities are `did:pact` identifiers
//! - a passport is an unsigned bundle of independently verifiable credentials
//! - verification is pure and requires no kernel or storage dependency

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::collections::BTreeSet;
use std::str::FromStr;

use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use pact_core::{canonical_json_bytes, Keypair, PublicKey, Signature};
use pact_did::{DidError, DidPact};
use pact_reputation::{LocalReputationScorecard, MetricValue};
use serde::{Deserialize, Serialize};

const VC_CONTEXT_V1: &str = "https://www.w3.org/2018/credentials/v1";
const PACT_CREDENTIAL_CONTEXT_V1: &str = "https://pact.dev/credentials/v1";
const VC_TYPE: &str = "VerifiableCredential";
const REPUTATION_ATTESTATION_TYPE: &str = "PactReputationAttestation";
const PASSPORT_SCHEMA: &str = "pact.agent-passport.v1";
const PASSPORT_VERIFIER_POLICY_SCHEMA: &str = "pact.passport-verifier-policy.v1";
const PASSPORT_PRESENTATION_CHALLENGE_SCHEMA: &str =
    "pact.agent-passport-presentation-challenge.v1";
const PASSPORT_PRESENTATION_RESPONSE_SCHEMA: &str = "pact.agent-passport-presentation-response.v1";
const PROOF_TYPE: &str = "Ed25519Signature2020";
const PROOF_PURPOSE: &str = "assertionMethod";
const PRESENTATION_PROOF_PURPOSE: &str = "authentication";

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

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PassportPresentationOptions {
    pub issuer_allowlist: BTreeSet<String>,
    pub max_credentials: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PassportPresentationChallenge {
    pub schema: String,
    pub verifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
    pub nonce: String,
    pub issued_at: String,
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub issuer_allowlist: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_credentials: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<PassportVerifierPolicyReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PassportVerifierPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PresentationProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub created: String,
    pub proof_purpose: String,
    pub verification_method: String,
    pub proof_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PassportPresentationResponse {
    pub schema: String,
    pub challenge: PassportPresentationChallenge,
    pub passport: AgentPassport,
    pub proof: PresentationProof,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PassportPresentationVerification {
    pub subject: String,
    pub verifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
    pub nonce: String,
    pub verified_at: u64,
    pub credential_count: usize,
    pub valid_until: String,
    pub challenge_expires_at: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(default)]
    pub policy_evaluated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_evaluation: Option<PassportPolicyEvaluation>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedPassportPresentationResponse {
    schema: String,
    challenge: PassportPresentationChallenge,
    passport: AgentPassport,
}

fn rfc3339_from_unix(timestamp: u64) -> Result<String, CredentialError> {
    let timestamp =
        i64::try_from(timestamp).map_err(|_| CredentialError::InvalidUnixTimestamp(timestamp))?;
    let datetime = Utc
        .timestamp_opt(timestamp, 0)
        .single()
        .ok_or(CredentialError::InvalidUnixTimestamp(timestamp as u64))?;
    Ok(datetime.to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn unix_from_rfc3339(value: &str) -> Result<u64, CredentialError> {
    let datetime = DateTime::parse_from_rfc3339(value)
        .map_err(|error| CredentialError::InvalidTimestamp(error.to_string()))?;
    u64::try_from(datetime.timestamp())
        .map_err(|_| CredentialError::InvalidTimestamp(value.to_string()))
}

pub fn issue_reputation_credential(
    issuer_keypair: &Keypair,
    scorecard: LocalReputationScorecard,
    evidence: PactCredentialEvidence,
    issued_at: u64,
    valid_until: u64,
) -> Result<ReputationCredential, CredentialError> {
    if issued_at > valid_until {
        return Err(CredentialError::InvalidCredentialValidityWindow);
    }

    let issuer = DidPact::from_public_key(issuer_keypair.public_key());
    let subject_did =
        DidPact::from_public_key(pact_core::PublicKey::from_hex(&scorecard.subject_key)?);
    let unsigned = UnsignedReputationCredential {
        context: vec![
            VC_CONTEXT_V1.to_string(),
            PACT_CREDENTIAL_CONTEXT_V1.to_string(),
        ],
        credential_type: vec![VC_TYPE.to_string(), REPUTATION_ATTESTATION_TYPE.to_string()],
        issuer: issuer.to_string(),
        issuance_date: rfc3339_from_unix(issued_at)?,
        expiration_date: rfc3339_from_unix(valid_until)?,
        credential_subject: ReputationCredentialSubject {
            id: subject_did.to_string(),
            metrics: scorecard,
        },
        evidence,
    };

    let (signature, _) = issuer_keypair.sign_canonical(&unsigned)?;
    Ok(ReputationCredential {
        unsigned,
        proof: CredentialProof {
            proof_type: PROOF_TYPE.to_string(),
            created: rfc3339_from_unix(issued_at)?,
            proof_purpose: PROOF_PURPOSE.to_string(),
            verification_method: issuer.verification_method_id(),
            proof_value: signature.to_hex(),
        },
    })
}

pub fn verify_reputation_credential(
    credential: &ReputationCredential,
    now: u64,
) -> Result<(), CredentialError> {
    if credential.proof.proof_type != PROOF_TYPE {
        return Err(CredentialError::InvalidProofType);
    }
    if credential.proof.proof_purpose != PROOF_PURPOSE {
        return Err(CredentialError::InvalidProofPurpose);
    }
    let issuer = DidPact::from_str(&credential.unsigned.issuer)?;
    if credential.proof.verification_method != issuer.verification_method_id() {
        return Err(CredentialError::IssuerVerificationMethodMismatch);
    }
    let subject = DidPact::from_str(&credential.unsigned.credential_subject.id)?;
    if subject.public_key().to_hex() != credential.unsigned.credential_subject.metrics.subject_key {
        return Err(CredentialError::SubjectDidMismatch);
    }

    let issuance_date = unix_from_rfc3339(&credential.unsigned.issuance_date)?;
    let expiration_date = unix_from_rfc3339(&credential.unsigned.expiration_date)?;
    if issuance_date > expiration_date {
        return Err(CredentialError::InvalidCredentialValidityWindow);
    }
    if now > expiration_date {
        return Err(CredentialError::CredentialExpired);
    }

    let signature = Signature::from_hex(&credential.proof.proof_value)?;
    let signed = issuer
        .public_key()
        .verify(&canonical_json_bytes(&credential.unsigned)?, &signature);
    if !signed {
        return Err(CredentialError::InvalidCredentialSignature);
    }
    Ok(())
}

pub fn build_agent_passport(
    subject: &str,
    credentials: Vec<ReputationCredential>,
) -> Result<AgentPassport, CredentialError> {
    if credentials.is_empty() {
        return Err(CredentialError::EmptyPassport);
    }

    let subject = DidPact::from_str(subject)?.to_string();
    let mut merkle_roots = BTreeSet::new();
    let mut issued_at = u64::MAX;
    let mut valid_until = u64::MAX;

    for credential in &credentials {
        if credential.unsigned.credential_subject.id != subject {
            return Err(CredentialError::PassportSubjectMismatch(
                credential.unsigned.credential_subject.id.clone(),
            ));
        }
        issued_at = issued_at.min(unix_from_rfc3339(&credential.unsigned.issuance_date)?);
        valid_until = valid_until.min(unix_from_rfc3339(&credential.unsigned.expiration_date)?);
        merkle_roots.extend(
            credential
                .unsigned
                .evidence
                .checkpoint_roots
                .iter()
                .cloned(),
        );
    }

    Ok(AgentPassport {
        schema: PASSPORT_SCHEMA.to_string(),
        subject,
        credentials,
        merkle_roots: merkle_roots.into_iter().collect(),
        issued_at: rfc3339_from_unix(issued_at)?,
        valid_until: rfc3339_from_unix(valid_until)?,
    })
}

pub fn verify_agent_passport(
    passport: &AgentPassport,
    now: u64,
) -> Result<PassportVerification, CredentialError> {
    if passport.credentials.is_empty() {
        return Err(CredentialError::EmptyPassport);
    }

    let subject = DidPact::from_str(&passport.subject)?.to_string();
    let passport_valid_until = unix_from_rfc3339(&passport.valid_until)?;
    let mut issuers = BTreeSet::new();
    let mut merkle_roots = BTreeSet::new();
    let mut min_credential_valid_until = u64::MAX;

    for credential in &passport.credentials {
        verify_reputation_credential(credential, now)?;
        if credential.unsigned.credential_subject.id != subject {
            return Err(CredentialError::PassportSubjectMismatch(
                credential.unsigned.credential_subject.id.clone(),
            ));
        }
        issuers.insert(credential.unsigned.issuer.clone());
        let credential_valid_until = unix_from_rfc3339(&credential.unsigned.expiration_date)?;
        min_credential_valid_until = min_credential_valid_until.min(credential_valid_until);
        merkle_roots.extend(
            credential
                .unsigned
                .evidence
                .checkpoint_roots
                .iter()
                .cloned(),
        );
    }

    if passport_valid_until > min_credential_valid_until {
        return Err(CredentialError::PassportValidityMismatch);
    }
    let issuers = issuers.into_iter().collect::<Vec<_>>();

    Ok(PassportVerification {
        subject,
        issuer: if issuers.len() == 1 {
            issuers.first().cloned()
        } else {
            None
        },
        issuers: issuers.clone(),
        issuer_count: issuers.len(),
        credential_count: passport.credentials.len(),
        merkle_root_count: merkle_roots.len(),
        verified_at: now,
        valid_until: passport.valid_until.clone(),
    })
}

pub fn present_agent_passport(
    passport: &AgentPassport,
    options: &PassportPresentationOptions,
) -> Result<AgentPassport, CredentialError> {
    let mut credentials: Vec<ReputationCredential> = passport
        .credentials
        .iter()
        .filter(|credential| {
            options.issuer_allowlist.is_empty()
                || options
                    .issuer_allowlist
                    .contains(&credential.unsigned.issuer)
        })
        .cloned()
        .collect();

    if let Some(limit) = options.max_credentials {
        credentials.truncate(limit);
    }

    build_agent_passport(&passport.subject, credentials)
}

pub fn evaluate_agent_passport(
    passport: &AgentPassport,
    now: u64,
    policy: &PassportVerifierPolicy,
) -> Result<PassportPolicyEvaluation, CredentialError> {
    policy.validate()?;
    let verification = verify_agent_passport(passport, now)?;
    let mut matched_credential_indexes = Vec::new();
    let mut matched_issuers = BTreeSet::new();
    let credential_results = passport
        .credentials
        .iter()
        .enumerate()
        .map(|(index, credential)| {
            let evaluation = evaluate_credential_against_policy(index, credential, now, policy);
            if evaluation.accepted {
                matched_credential_indexes.push(index);
                matched_issuers.insert(evaluation.issuer.clone());
            }
            evaluation
        })
        .collect::<Vec<_>>();

    Ok(PassportPolicyEvaluation {
        verification,
        accepted: !matched_credential_indexes.is_empty(),
        matched_credential_indexes,
        matched_issuers: matched_issuers.into_iter().collect(),
        policy: policy.clone(),
        credential_results,
    })
}

pub fn create_passport_presentation_challenge(
    verifier: impl Into<String>,
    nonce: impl Into<String>,
    issued_at: u64,
    expires_at: u64,
    options: PassportPresentationOptions,
    policy: Option<PassportVerifierPolicy>,
) -> Result<PassportPresentationChallenge, CredentialError> {
    create_passport_presentation_challenge_with_reference(
        verifier,
        None::<String>,
        nonce,
        issued_at,
        expires_at,
        options,
        None,
        policy,
    )
}

pub fn create_passport_presentation_challenge_with_reference(
    verifier: impl Into<String>,
    challenge_id: Option<String>,
    nonce: impl Into<String>,
    issued_at: u64,
    expires_at: u64,
    options: PassportPresentationOptions,
    policy_ref: Option<PassportVerifierPolicyReference>,
    policy: Option<PassportVerifierPolicy>,
) -> Result<PassportPresentationChallenge, CredentialError> {
    if issued_at > expires_at {
        return Err(CredentialError::InvalidChallengeValidityWindow);
    }
    if let Some(policy) = &policy {
        policy.validate()?;
    }

    Ok(PassportPresentationChallenge {
        schema: PASSPORT_PRESENTATION_CHALLENGE_SCHEMA.to_string(),
        verifier: verifier.into(),
        challenge_id,
        nonce: nonce.into(),
        issued_at: rfc3339_from_unix(issued_at)?,
        expires_at: rfc3339_from_unix(expires_at)?,
        issuer_allowlist: options.issuer_allowlist,
        max_credentials: options.max_credentials,
        policy_ref,
        policy,
    })
}

pub fn verify_passport_presentation_challenge(
    challenge: &PassportPresentationChallenge,
    now: u64,
) -> Result<(), CredentialError> {
    if challenge.schema != PASSPORT_PRESENTATION_CHALLENGE_SCHEMA {
        return Err(CredentialError::InvalidChallengeSchema);
    }

    let issued_at = unix_from_rfc3339(&challenge.issued_at)?;
    let expires_at = unix_from_rfc3339(&challenge.expires_at)?;
    if issued_at > expires_at {
        return Err(CredentialError::InvalidChallengeValidityWindow);
    }
    if now < issued_at {
        return Err(CredentialError::ChallengeNotYetValid);
    }
    if now > expires_at {
        return Err(CredentialError::ChallengeExpired);
    }
    if let Some(policy) = &challenge.policy {
        policy.validate()?;
    }
    Ok(())
}

pub fn create_signed_passport_verifier_policy(
    signer_keypair: &Keypair,
    policy_id: impl Into<String>,
    verifier: impl Into<String>,
    created_at: u64,
    expires_at: u64,
    policy: PassportVerifierPolicy,
) -> Result<SignedPassportVerifierPolicy, CredentialError> {
    let body = SignedPassportVerifierPolicyBody {
        schema: PASSPORT_VERIFIER_POLICY_SCHEMA.to_string(),
        policy_id: policy_id.into(),
        verifier: verifier.into(),
        signer_public_key: signer_keypair.public_key(),
        created_at,
        expires_at,
        policy,
    };
    verify_signed_passport_verifier_policy_body(&body)?;
    let (signature, _) = signer_keypair.sign_canonical(&body)?;
    let document = SignedPassportVerifierPolicy { body, signature };
    verify_signed_passport_verifier_policy(&document)?;
    Ok(document)
}

pub fn verify_signed_passport_verifier_policy(
    document: &SignedPassportVerifierPolicy,
) -> Result<(), CredentialError> {
    verify_signed_passport_verifier_policy_body(&document.body)?;
    if !document
        .body
        .signer_public_key
        .verify_canonical(&document.body, &document.signature)?
    {
        return Err(CredentialError::InvalidSignedVerifierPolicySignature);
    }
    Ok(())
}

pub fn ensure_signed_passport_verifier_policy_active(
    document: &SignedPassportVerifierPolicy,
    now: u64,
) -> Result<(), CredentialError> {
    if now < document.body.created_at {
        return Err(CredentialError::SignedVerifierPolicyNotYetValid);
    }
    if now > document.body.expires_at {
        return Err(CredentialError::SignedVerifierPolicyExpired);
    }
    Ok(())
}

pub fn respond_to_passport_presentation_challenge(
    holder_keypair: &Keypair,
    passport: &AgentPassport,
    challenge: &PassportPresentationChallenge,
    now: u64,
) -> Result<PassportPresentationResponse, CredentialError> {
    verify_passport_presentation_challenge(challenge, now)?;
    verify_agent_passport(passport, now)?;

    let holder_did = DidPact::from_public_key(holder_keypair.public_key());
    if holder_did.to_string() != passport.subject {
        return Err(CredentialError::PresentationHolderMismatch);
    }

    let passport = present_agent_passport(passport, &challenge_presentation_options(challenge))?;
    let unsigned = UnsignedPassportPresentationResponse {
        schema: PASSPORT_PRESENTATION_RESPONSE_SCHEMA.to_string(),
        challenge: challenge.clone(),
        passport: passport.clone(),
    };
    let (signature, _) = holder_keypair.sign_canonical(&unsigned)?;

    Ok(PassportPresentationResponse {
        schema: PASSPORT_PRESENTATION_RESPONSE_SCHEMA.to_string(),
        challenge: challenge.clone(),
        passport,
        proof: PresentationProof {
            proof_type: PROOF_TYPE.to_string(),
            created: rfc3339_from_unix(now)?,
            proof_purpose: PRESENTATION_PROOF_PURPOSE.to_string(),
            verification_method: holder_did.verification_method_id(),
            proof_value: signature.to_hex(),
        },
    })
}

pub fn verify_passport_presentation_response(
    response: &PassportPresentationResponse,
    expected_challenge: Option<&PassportPresentationChallenge>,
    now: u64,
) -> Result<PassportPresentationVerification, CredentialError> {
    verify_passport_presentation_response_with_policy(response, expected_challenge, now, None, None)
}

pub fn verify_passport_presentation_response_with_policy(
    response: &PassportPresentationResponse,
    expected_challenge: Option<&PassportPresentationChallenge>,
    now: u64,
    resolved_policy: Option<&PassportVerifierPolicy>,
    policy_source_override: Option<String>,
) -> Result<PassportPresentationVerification, CredentialError> {
    if response.schema != PASSPORT_PRESENTATION_RESPONSE_SCHEMA {
        return Err(CredentialError::InvalidPresentationSchema);
    }
    verify_passport_presentation_challenge(&response.challenge, now)?;
    if let Some(expected_challenge) = expected_challenge {
        if expected_challenge != &response.challenge {
            return Err(CredentialError::ChallengeMismatch);
        }
    }
    if response.proof.proof_type != PROOF_TYPE {
        return Err(CredentialError::InvalidPresentationProofType);
    }
    if response.proof.proof_purpose != PRESENTATION_PROOF_PURPOSE {
        return Err(CredentialError::InvalidPresentationProofPurpose);
    }

    let passport_verification = verify_agent_passport(&response.passport, now)?;
    let subject_did = DidPact::from_str(&response.passport.subject)?;
    if response.proof.verification_method != subject_did.verification_method_id() {
        return Err(CredentialError::PresentationVerificationMethodMismatch);
    }

    if !response.challenge.issuer_allowlist.is_empty() {
        for credential in &response.passport.credentials {
            if !response
                .challenge
                .issuer_allowlist
                .contains(&credential.unsigned.issuer)
            {
                return Err(CredentialError::PresentationIssuerNotAllowed(
                    credential.unsigned.issuer.clone(),
                ));
            }
        }
    }
    if let Some(max_credentials) = response.challenge.max_credentials {
        let actual = response.passport.credentials.len();
        if actual > max_credentials {
            return Err(CredentialError::PresentationCredentialLimitExceeded {
                max: max_credentials,
                actual,
            });
        }
    }

    let challenge_issued_at = unix_from_rfc3339(&response.challenge.issued_at)?;
    let challenge_expires_at = unix_from_rfc3339(&response.challenge.expires_at)?;
    let proof_created = unix_from_rfc3339(&response.proof.created)?;
    if proof_created > now {
        return Err(CredentialError::PresentationProofFromFuture);
    }
    if proof_created < challenge_issued_at || proof_created > challenge_expires_at {
        return Err(CredentialError::PresentationProofOutsideChallengeWindow);
    }

    let unsigned = UnsignedPassportPresentationResponse {
        schema: PASSPORT_PRESENTATION_RESPONSE_SCHEMA.to_string(),
        challenge: response.challenge.clone(),
        passport: response.passport.clone(),
    };
    let signature = Signature::from_hex(&response.proof.proof_value)?;
    let signed = subject_did
        .public_key()
        .verify(&canonical_json_bytes(&unsigned)?, &signature);
    if !signed {
        return Err(CredentialError::InvalidPresentationSignature);
    }

    let evaluation_policy = resolved_policy.or(response.challenge.policy.as_ref());
    let policy_source = if evaluation_policy.is_some() {
        Some(policy_source_override.unwrap_or_else(|| {
            if response.challenge.policy.is_some() {
                "embedded".to_string()
            } else if response.challenge.policy_ref.is_some() {
                "reference".to_string()
            } else {
                "resolved".to_string()
            }
        }))
    } else {
        None
    };
    let policy_evaluation = evaluation_policy
        .map(|policy| evaluate_agent_passport(&response.passport, now, policy))
        .transpose()?;
    let accepted = policy_evaluation
        .as_ref()
        .is_none_or(|evaluation| evaluation.accepted);

    Ok(PassportPresentationVerification {
        subject: passport_verification.subject,
        verifier: response.challenge.verifier.clone(),
        challenge_id: response.challenge.challenge_id.clone(),
        nonce: response.challenge.nonce.clone(),
        verified_at: now,
        credential_count: passport_verification.credential_count,
        valid_until: passport_verification.valid_until,
        challenge_expires_at: response.challenge.expires_at.clone(),
        accepted,
        policy_id: response
            .challenge
            .policy_ref
            .as_ref()
            .map(|reference| reference.policy_id.clone()),
        policy_evaluated: policy_evaluation.is_some(),
        policy_source,
        replay_state: None,
        policy_evaluation,
    })
}

fn challenge_presentation_options(
    challenge: &PassportPresentationChallenge,
) -> PassportPresentationOptions {
    PassportPresentationOptions {
        issuer_allowlist: challenge.issuer_allowlist.clone(),
        max_credentials: challenge.max_credentials,
    }
}

fn validate_unit_interval(field: &'static str, value: Option<f64>) -> Result<(), CredentialError> {
    if let Some(value) = value {
        if !(0.0..=1.0).contains(&value) {
            return Err(CredentialError::InvalidVerifierThreshold { field, value });
        }
    }
    Ok(())
}

fn verify_signed_passport_verifier_policy_body(
    body: &SignedPassportVerifierPolicyBody,
) -> Result<(), CredentialError> {
    if body.schema != PASSPORT_VERIFIER_POLICY_SCHEMA {
        return Err(CredentialError::InvalidSignedVerifierPolicySchema);
    }
    if body.policy_id.trim().is_empty() {
        return Err(CredentialError::MissingSignedVerifierPolicyId);
    }
    if body.verifier.trim().is_empty() {
        return Err(CredentialError::MissingSignedVerifierVerifier);
    }
    if body.created_at > body.expires_at {
        return Err(CredentialError::InvalidSignedVerifierPolicyValidityWindow);
    }
    body.policy.validate()?;
    Ok(())
}

fn evaluate_credential_against_policy(
    index: usize,
    credential: &ReputationCredential,
    now: u64,
    policy: &PassportVerifierPolicy,
) -> CredentialPolicyEvaluation {
    let mut reasons = Vec::new();
    let metrics = &credential.unsigned.credential_subject.metrics;
    let evidence = &credential.unsigned.evidence;

    if !policy.issuer_allowlist.is_empty()
        && !policy
            .issuer_allowlist
            .contains(&credential.unsigned.issuer)
    {
        reasons.push(format!(
            "issuer {} is not in the allowlist",
            credential.unsigned.issuer
        ));
    }

    if let Some(minimum) = policy.min_composite_score {
        require_metric_min(
            &mut reasons,
            "composite_score",
            metrics.composite_score,
            minimum,
        );
    }
    if let Some(minimum) = policy.min_reliability {
        require_metric_min(
            &mut reasons,
            "reliability",
            metrics.reliability.score,
            minimum,
        );
    }
    if let Some(minimum) = policy.min_least_privilege {
        require_metric_min(
            &mut reasons,
            "least_privilege",
            metrics.least_privilege.score,
            minimum,
        );
    }
    if let Some(minimum) = policy.min_delegation_hygiene {
        require_metric_min(
            &mut reasons,
            "delegation_hygiene",
            metrics.delegation_hygiene.score,
            minimum,
        );
    }
    if let Some(maximum) = policy.max_boundary_pressure {
        require_metric_max(
            &mut reasons,
            "boundary_pressure",
            metrics.boundary_pressure.deny_ratio,
            maximum,
        );
    }

    if let Some(minimum) = policy.min_receipt_count {
        if evidence.receipt_count < minimum {
            reasons.push(format!(
                "receipt_count {} is below required minimum {}",
                evidence.receipt_count, minimum
            ));
        }
    }
    if let Some(minimum) = policy.min_lineage_records {
        if evidence.lineage_records < minimum {
            reasons.push(format!(
                "lineage_records {} is below required minimum {}",
                evidence.lineage_records, minimum
            ));
        }
    }
    if let Some(minimum) = policy.min_history_days {
        if metrics.history_depth.span_days < minimum {
            reasons.push(format!(
                "history_depth_days {} is below required minimum {}",
                metrics.history_depth.span_days, minimum
            ));
        }
    }
    if let Some(max_days) = policy.max_attestation_age_days {
        let age_seconds = now.saturating_sub(evidence.query.until);
        let max_age_seconds = u64::from(max_days).saturating_mul(86_400);
        if age_seconds > max_age_seconds {
            reasons.push(format!(
                "attestation_age_days {:.2} exceeds maximum {}",
                age_seconds as f64 / 86_400.0,
                max_days
            ));
        }
    }
    if policy.require_checkpoint_coverage {
        if evidence.uncheckpointed_receipts > 0 {
            reasons.push(format!(
                "credential evidence has {} uncheckpointed receipt(s)",
                evidence.uncheckpointed_receipts
            ));
        }
        if evidence.checkpoint_roots.is_empty() {
            reasons.push("credential evidence does not include checkpoint roots".to_string());
        }
    }
    if policy.require_receipt_log_urls && evidence.receipt_log_urls.is_empty() {
        reasons.push("credential evidence does not include receipt log URLs".to_string());
    }

    CredentialPolicyEvaluation {
        index,
        issuer: credential.unsigned.issuer.clone(),
        accepted: reasons.is_empty(),
        reasons,
        issuance_date: credential.unsigned.issuance_date.clone(),
        expiration_date: credential.unsigned.expiration_date.clone(),
        attestation_until: evidence.query.until,
        receipt_count: evidence.receipt_count,
        lineage_records: evidence.lineage_records,
        uncheckpointed_receipts: evidence.uncheckpointed_receipts,
        composite_score: metrics.composite_score.as_option(),
        reliability: metrics.reliability.score.as_option(),
        least_privilege: metrics.least_privilege.score.as_option(),
        delegation_hygiene: metrics.delegation_hygiene.score.as_option(),
        boundary_pressure: metrics.boundary_pressure.deny_ratio.as_option(),
    }
}

fn require_metric_min(reasons: &mut Vec<String>, field: &str, value: MetricValue, minimum: f64) {
    match value.as_option() {
        Some(value) if value >= minimum => {}
        Some(value) => reasons.push(format!(
            "{field} {} is below required minimum {}",
            value, minimum
        )),
        None => reasons.push(format!("{field} is unknown but policy requires a minimum")),
    }
}

fn require_metric_max(reasons: &mut Vec<String>, field: &str, value: MetricValue, maximum: f64) {
    match value.as_option() {
        Some(value) if value <= maximum => {}
        Some(value) => reasons.push(format!(
            "{field} {} exceeds allowed maximum {}",
            value, maximum
        )),
        None => reasons.push(format!("{field} is unknown but policy requires a maximum")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pact_reputation::{LocalReputationScorecard, MetricValue};

    fn sample_scorecard(subject_key: &str) -> LocalReputationScorecard {
        LocalReputationScorecard {
            subject_key: subject_key.to_string(),
            computed_at: 1_710_000_000,
            boundary_pressure: pact_reputation::BoundaryPressureMetrics {
                deny_ratio: MetricValue::Known(0.1),
                policies_observed: 1,
                receipts_observed: 3,
            },
            resource_stewardship: pact_reputation::ResourceStewardshipMetrics {
                average_utilization: MetricValue::Known(0.6),
                fit_score: MetricValue::Known(0.9),
                capped_grants_observed: 1,
            },
            least_privilege: pact_reputation::LeastPrivilegeMetrics {
                score: MetricValue::Known(0.8),
                capabilities_observed: 1,
            },
            history_depth: pact_reputation::HistoryDepthMetrics {
                score: MetricValue::Known(0.7),
                receipt_count: 3,
                active_days: 3,
                first_seen: Some(1_709_900_000),
                last_seen: Some(1_710_000_000),
                span_days: 3,
                activity_ratio: MetricValue::Known(1.0),
            },
            specialization: pact_reputation::SpecializationMetrics {
                score: MetricValue::Known(0.5),
                distinct_tools: 2,
            },
            delegation_hygiene: pact_reputation::DelegationHygieneMetrics {
                score: MetricValue::Known(0.9),
                delegations_observed: 1,
                scope_reduction_rate: MetricValue::Known(1.0),
                ttl_reduction_rate: MetricValue::Known(1.0),
                budget_reduction_rate: MetricValue::Known(1.0),
            },
            reliability: pact_reputation::ReliabilityMetrics {
                score: MetricValue::Known(0.95),
                completion_rate: MetricValue::Known(1.0),
                cancellation_rate: MetricValue::Known(0.0),
                incompletion_rate: MetricValue::Known(0.0),
                receipts_observed: 3,
            },
            incident_correlation: pact_reputation::IncidentCorrelationMetrics {
                score: MetricValue::Unknown,
                incidents_observed: None,
            },
            composite_score: MetricValue::Known(0.82),
            effective_weight_sum: 0.9,
        }
    }

    fn sample_evidence() -> PactCredentialEvidence {
        PactCredentialEvidence {
            query: AttestationWindow {
                since: Some(1_709_900_000),
                until: 1_710_000_000,
            },
            receipt_count: 3,
            receipt_ids: vec![
                "rcpt-1".to_string(),
                "rcpt-2".to_string(),
                "rcpt-3".to_string(),
            ],
            checkpoint_roots: vec!["abc123".to_string()],
            receipt_log_urls: vec!["https://trust.example.com/v1/receipts".to_string()],
            lineage_records: 1,
            uncheckpointed_receipts: 0,
        }
    }

    #[test]
    fn issued_credential_verifies_against_issuer_did() {
        let issuer = Keypair::from_seed(&[9u8; 32]);
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");

        verify_reputation_credential(&credential, 1_710_010_000).expect("verify");
    }

    #[test]
    fn passport_verification_accepts_multi_issuer_bundle() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let credential_a = issue_reputation_credential(
            &Keypair::from_seed(&[1u8; 32]),
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let credential_b = issue_reputation_credential(
            &Keypair::from_seed(&[2u8; 32]),
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let did = DidPact::from_public_key(
            pact_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );

        let passport = build_agent_passport(&did.to_string(), vec![credential_a, credential_b])
            .expect("multi-issuer passport");
        let verification = verify_agent_passport(&passport, 1_710_010_000).expect("verify");
        assert_eq!(verification.issuer, None);
        assert_eq!(verification.issuer_count, 2);
        assert_eq!(verification.issuers.len(), 2);
    }

    #[test]
    fn verifier_policy_reports_mixed_multi_issuer_results() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let issuer_a = Keypair::from_seed(&[1u8; 32]);
        let issuer_b = Keypair::from_seed(&[2u8; 32]);
        let credential_a = issue_reputation_credential(
            &issuer_a,
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let credential_b = issue_reputation_credential(
            &issuer_b,
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = DidPact::from_public_key(
            pact_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential_a, credential_b])
                .expect("passport");
        let accepted_issuer = passport.credentials[0].unsigned.issuer.clone();
        let rejected_issuer = passport.credentials[1].unsigned.issuer.clone();

        let evaluation = evaluate_agent_passport(
            &passport,
            1_710_010_000,
            &PassportVerifierPolicy {
                issuer_allowlist: [accepted_issuer.clone()].into_iter().collect(),
                ..PassportVerifierPolicy::default()
            },
        )
        .expect("evaluation");

        assert!(evaluation.accepted);
        assert_eq!(evaluation.verification.issuer_count, 2);
        assert_eq!(evaluation.matched_credential_indexes, vec![0]);
        assert_eq!(evaluation.matched_issuers, vec![accepted_issuer.clone()]);
        assert_eq!(evaluation.credential_results[0].issuer, accepted_issuer);
        assert!(evaluation.credential_results[0].accepted);
        assert_eq!(evaluation.credential_results[1].issuer, rejected_issuer);
        assert!(!evaluation.credential_results[1].accepted);
    }

    #[test]
    fn verifier_policy_rejects_multi_issuer_bundle_when_no_credential_matches() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let credential_a = issue_reputation_credential(
            &Keypair::from_seed(&[1u8; 32]),
            sample_scorecard(&subject),
            sample_evidence(),
            1_900_000_000,
            1_900_086_400,
        )
        .expect("credential");
        let credential_b = issue_reputation_credential(
            &Keypair::from_seed(&[2u8; 32]),
            sample_scorecard(&subject),
            sample_evidence(),
            1_900_000_000,
            1_900_086_400,
        )
        .expect("credential");
        let subject_did = DidPact::from_public_key(
            pact_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential_a, credential_b])
                .expect("passport");

        let evaluation = evaluate_agent_passport(
            &passport,
            1_900_010_000,
            &PassportVerifierPolicy {
                issuer_allowlist: [
                    "did:pact:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                        .to_string(),
                ]
                .into_iter()
                .collect(),
                ..PassportVerifierPolicy::default()
            },
        )
        .expect("evaluation");

        assert!(!evaluation.accepted);
        assert!(evaluation.matched_credential_indexes.is_empty());
        assert!(evaluation.matched_issuers.is_empty());
        assert_eq!(evaluation.credential_results.len(), 2);
        assert!(evaluation
            .credential_results
            .iter()
            .all(|result| !result.accepted));
    }

    #[test]
    fn presentation_can_filter_credentials_by_issuer() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = DidPact::from_public_key(
            pact_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );
        let passport = build_agent_passport(&subject_did.to_string(), vec![credential.clone()])
            .expect("passport");

        let presented = present_agent_passport(
            &passport,
            &PassportPresentationOptions {
                issuer_allowlist: [credential.unsigned.issuer.clone()].into_iter().collect(),
                max_credentials: Some(1),
            },
        )
        .expect("presented passport");

        assert_eq!(presented.credentials.len(), 1);
        verify_agent_passport(&presented, 1_710_010_000).expect("verify presented passport");
    }

    #[test]
    fn verifier_policy_accepts_matching_single_issuer_passport() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = DidPact::from_public_key(
            pact_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");

        let evaluation = evaluate_agent_passport(
            &passport,
            1_710_010_000,
            &PassportVerifierPolicy {
                issuer_allowlist: [passport.credentials[0].unsigned.issuer.clone()]
                    .into_iter()
                    .collect(),
                min_composite_score: Some(0.80),
                min_reliability: Some(0.90),
                max_boundary_pressure: Some(0.20),
                min_receipt_count: Some(3),
                min_lineage_records: Some(1),
                min_history_days: Some(3),
                max_attestation_age_days: Some(7),
                require_checkpoint_coverage: true,
                require_receipt_log_urls: true,
                ..PassportVerifierPolicy::default()
            },
        )
        .expect("evaluate");

        assert!(evaluation.accepted);
        assert_eq!(evaluation.matched_credential_indexes, vec![0]);
        assert!(evaluation.credential_results[0].accepted);
    }

    #[test]
    fn verifier_policy_rejects_unknown_metric_and_stale_attestation() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let mut evidence = sample_evidence();
        evidence.uncheckpointed_receipts = 1;
        evidence.receipt_log_urls.clear();
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject),
            evidence,
            1_710_000_000,
            1_720_000_000,
        )
        .expect("credential");
        let subject_did = DidPact::from_public_key(
            pact_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");

        let evaluation = evaluate_agent_passport(
            &passport,
            1_712_000_000,
            &PassportVerifierPolicy {
                min_composite_score: Some(0.90),
                max_attestation_age_days: Some(1),
                require_checkpoint_coverage: true,
                require_receipt_log_urls: true,
                ..PassportVerifierPolicy::default()
            },
        )
        .expect("evaluate");

        assert!(!evaluation.accepted);
        assert!(evaluation.matched_credential_indexes.is_empty());
        let reasons = &evaluation.credential_results[0].reasons;
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("composite_score")),
            "expected composite score rejection"
        );
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("uncheckpointed")),
            "expected checkpoint rejection"
        );
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("receipt log URLs")),
            "expected receipt-log rejection"
        );
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("attestation_age_days")),
            "expected attestation-age rejection"
        );
    }

    #[test]
    fn verifier_policy_accepts_if_any_credential_matches_without_fake_aggregation() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let mut weaker = sample_scorecard(&subject);
        weaker.composite_score = MetricValue::Known(0.40);
        weaker.reliability.score = MetricValue::Known(0.60);
        let stronger = sample_scorecard(&subject);

        let weak_credential = issue_reputation_credential(
            &issuer,
            weaker,
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("weak credential");
        let strong_credential = issue_reputation_credential(
            &issuer,
            stronger,
            sample_evidence(),
            1_710_000_100,
            1_710_086_400,
        )
        .expect("strong credential");
        let subject_did = DidPact::from_public_key(
            pact_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );
        let passport = build_agent_passport(
            &subject_did.to_string(),
            vec![weak_credential, strong_credential],
        )
        .expect("passport");

        let evaluation = evaluate_agent_passport(
            &passport,
            1_710_010_000,
            &PassportVerifierPolicy {
                min_composite_score: Some(0.80),
                min_reliability: Some(0.90),
                ..PassportVerifierPolicy::default()
            },
        )
        .expect("evaluate");

        assert!(evaluation.accepted);
        assert_eq!(evaluation.matched_credential_indexes, vec![1]);
        assert!(!evaluation.credential_results[0].accepted);
        assert!(evaluation.credential_results[1].accepted);
    }

    #[test]
    fn challenge_bound_presentation_verifies_and_evaluates_policy() {
        let subject = Keypair::from_seed(&[7u8; 32]);
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = DidPact::from_public_key(subject.public_key());
        let passport = build_agent_passport(&subject_did.to_string(), vec![credential.clone()])
            .expect("passport");
        let challenge = create_passport_presentation_challenge(
            "https://rp.example.com",
            "nonce-123",
            1_710_000_050,
            1_710_000_350,
            PassportPresentationOptions {
                issuer_allowlist: [credential.unsigned.issuer.clone()].into_iter().collect(),
                max_credentials: Some(1),
            },
            Some(PassportVerifierPolicy {
                issuer_allowlist: [credential.unsigned.issuer.clone()].into_iter().collect(),
                min_composite_score: Some(0.80),
                min_reliability: Some(0.90),
                require_checkpoint_coverage: true,
                require_receipt_log_urls: true,
                ..PassportVerifierPolicy::default()
            }),
        )
        .expect("challenge");

        let response = respond_to_passport_presentation_challenge(
            &subject,
            &passport,
            &challenge,
            1_710_000_100,
        )
        .expect("response");
        let verification =
            verify_passport_presentation_response(&response, Some(&challenge), 1_710_000_120)
                .expect("verify");

        assert_eq!(verification.subject, subject_did.to_string());
        assert_eq!(verification.verifier, "https://rp.example.com");
        assert_eq!(verification.nonce, "nonce-123");
        assert_eq!(verification.credential_count, 1);
        assert!(verification.accepted);
        assert!(
            verification
                .policy_evaluation
                .as_ref()
                .expect("policy evaluation")
                .accepted
        );
    }

    #[test]
    fn challenge_bound_presentation_rejects_holder_mismatch() {
        let subject = Keypair::from_seed(&[7u8; 32]);
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = DidPact::from_public_key(subject.public_key());
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");
        let challenge = create_passport_presentation_challenge(
            "https://rp.example.com",
            "nonce-123",
            1_710_000_050,
            1_710_000_350,
            PassportPresentationOptions::default(),
            None,
        )
        .expect("challenge");

        let error = respond_to_passport_presentation_challenge(
            &Keypair::from_seed(&[8u8; 32]),
            &passport,
            &challenge,
            1_710_000_100,
        )
        .expect_err("holder mismatch should fail");
        assert!(matches!(error, CredentialError::PresentationHolderMismatch));
    }

    #[test]
    fn challenge_bound_presentation_rejects_tampered_signature() {
        let subject = Keypair::from_seed(&[7u8; 32]);
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = DidPact::from_public_key(subject.public_key());
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");
        let challenge = create_passport_presentation_challenge(
            "https://rp.example.com",
            "nonce-123",
            1_710_000_050,
            1_710_000_350,
            PassportPresentationOptions::default(),
            None,
        )
        .expect("challenge");
        let mut response = respond_to_passport_presentation_challenge(
            &subject,
            &passport,
            &challenge,
            1_710_000_100,
        )
        .expect("response");
        response.challenge.nonce = "tampered".to_string();

        let error = verify_passport_presentation_response(&response, None, 1_710_000_120)
            .expect_err("tampered signature should fail");
        assert!(matches!(
            error,
            CredentialError::InvalidPresentationSignature
        ));
    }

    #[test]
    fn challenge_bound_presentation_rejects_expired_challenge() {
        let subject = Keypair::from_seed(&[7u8; 32]);
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = DidPact::from_public_key(subject.public_key());
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");
        let challenge = create_passport_presentation_challenge(
            "https://rp.example.com",
            "nonce-123",
            1_710_000_050,
            1_710_000_150,
            PassportPresentationOptions::default(),
            None,
        )
        .expect("challenge");
        let response = respond_to_passport_presentation_challenge(
            &subject,
            &passport,
            &challenge,
            1_710_000_100,
        )
        .expect("response");

        let error =
            verify_passport_presentation_response(&response, Some(&challenge), 1_710_000_200)
                .expect_err("expired challenge should fail");
        assert!(matches!(error, CredentialError::ChallengeExpired));
    }

    #[test]
    fn challenge_bound_presentation_reports_policy_rejection_without_structural_failure() {
        let subject = Keypair::from_seed(&[7u8; 32]);
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = DidPact::from_public_key(subject.public_key());
        let passport = build_agent_passport(&subject_did.to_string(), vec![credential.clone()])
            .expect("passport");
        let challenge = create_passport_presentation_challenge(
            "https://rp.example.com",
            "nonce-123",
            1_710_000_050,
            1_710_000_350,
            PassportPresentationOptions {
                issuer_allowlist: [credential.unsigned.issuer.clone()].into_iter().collect(),
                max_credentials: Some(1),
            },
            Some(PassportVerifierPolicy {
                issuer_allowlist: [credential.unsigned.issuer.clone()].into_iter().collect(),
                min_composite_score: Some(0.99),
                require_checkpoint_coverage: true,
                require_receipt_log_urls: true,
                ..PassportVerifierPolicy::default()
            }),
        )
        .expect("challenge");
        let response = respond_to_passport_presentation_challenge(
            &subject,
            &passport,
            &challenge,
            1_710_000_100,
        )
        .expect("response");

        let verification =
            verify_passport_presentation_response(&response, Some(&challenge), 1_710_000_120)
                .expect("verify");

        assert!(!verification.accepted);
        assert!(
            !verification
                .policy_evaluation
                .as_ref()
                .expect("policy evaluation")
                .accepted
        );
    }
}

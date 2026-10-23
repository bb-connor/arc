pub const FINANCIAL_AGENT_PASSPORT_SCHEMA_V1: &str = "chio.financial-agent-passport.v1";
pub const FINANCIAL_AGENT_PASSPORT_SOURCE_MANIFEST_SCHEMA_V1: &str =
    "chio.financial-agent-passport.source-manifest.v1";
pub const PRESENTED_FINANCIAL_AGENT_PASSPORT_SCHEMA_V1: &str =
    "chio.financial-agent-passport.presentation.v1";
pub const FINANCIAL_PASSPORT_PRESENTATION_CHALLENGE_SCHEMA_V1: &str =
    "chio.financial-agent-passport-presentation-challenge.v1";
pub const FINANCIAL_PASSPORT_PRESENTATION_RESPONSE_SCHEMA_V1: &str =
    "chio.financial-agent-passport-presentation-response.v1";

const FINANCIAL_CREDENTIAL_ID_DOMAIN: &[u8] = b"chio.fincred.credential-id.v1\0";
const PASSPORT_CREDENTIAL_REF_DOMAIN: &[u8] = b"chio.financial-agent-passport.credential-ref.v1\0";
const PASSPORT_SOURCE_MANIFEST_ID_DOMAIN: &[u8] =
    b"chio.financial-agent-passport.source-manifest-id.v1\0";
const PASSPORT_PRESENTATION_DIGEST_DOMAIN: &[u8] =
    b"chio.financial-agent-passport.presentation-digest.v1\0";
const PASSPORT_PRESENTATION_CHALLENGE_DIGEST_DOMAIN: &[u8] =
    b"chio.financial-agent-passport.presentation-challenge-digest.v1\0";

const MAX_FINANCIAL_SOURCE_ARTIFACTS: usize = 256;
const MAX_FINANCIAL_BOUNDARY_PROOFS: usize = 32;
const MAX_FINANCIAL_POSITIONS: usize = 64;
const MAX_FINANCIAL_IDENTIFIER_BYTES: usize = 512;
const MAX_FINANCIAL_SOURCE_ARTIFACT_BYTES: usize = 512 * 1024;
const MAX_FINANCIAL_SOURCE_BUNDLE_BYTES: usize = 2 * 1024 * 1024;
const MAX_FINANCIAL_PRESENTATION_BYTES: usize = 16 * 1024 * 1024;
const I_JSON_MAX_SAFE_INTEGER: u64 = MAX_I_JSON_SAFE_INTEGER;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FinancialCredentialEnvelope {
    pub schema: String,
    pub family: FinancialCredentialFamilyV1,
    pub credential_id: String,
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,
    pub issuer: String,
    pub issuer_key_epoch: u64,
    pub issuance_date: String,
    pub expiration_date: String,
    pub credential_subject: FinancialCredentialSubjectV1,
    pub evidence: FinancialCredentialEvidenceV1,
    pub source_evidence_class: chio_core::capability::governance::ProvenanceEvidenceClass,
    pub presentation_evidence_class: chio_core::capability::governance::ProvenanceEvidenceClass,
    pub proof: CredentialProof,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FinancialCredentialWireV1 {
    schema: String,
    family: FinancialCredentialFamilyV1,
    credential_id: String,
    #[serde(rename = "@context")]
    context: Vec<String>,
    #[serde(rename = "type")]
    credential_type: Vec<String>,
    issuer: String,
    issuer_key_epoch: u64,
    issuance_date: String,
    expiration_date: String,
    credential_subject: FinancialCredentialSubjectV1,
    evidence: FinancialCredentialEvidenceV1,
    source_evidence_class: chio_core::capability::governance::ProvenanceEvidenceClass,
    presentation_evidence_class: chio_core::capability::governance::ProvenanceEvidenceClass,
    proof: CredentialProof,
}

impl From<FinancialCredentialWireV1> for FinancialCredentialEnvelope {
    fn from(wire: FinancialCredentialWireV1) -> Self {
        Self {
            schema: wire.schema,
            family: wire.family,
            credential_id: wire.credential_id,
            context: wire.context,
            credential_type: wire.credential_type,
            issuer: wire.issuer,
            issuer_key_epoch: wire.issuer_key_epoch,
            issuance_date: wire.issuance_date,
            expiration_date: wire.expiration_date,
            credential_subject: wire.credential_subject,
            evidence: wire.evidence,
            source_evidence_class: wire.source_evidence_class,
            presentation_evidence_class: wire.presentation_evidence_class,
            proof: wire.proof,
        }
    }
}

impl<'de> Deserialize<'de> for FinancialCredentialEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        preflight_financial_credential_value(&value).map_err(serde::de::Error::custom)?;
        let wire: FinancialCredentialWireV1 =
            serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        let envelope = Self::from(wire);
        envelope
            .validate_contract_shape()
            .map_err(serde::de::Error::custom)?;
        Ok(envelope)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FinancialCredentialIdPreimageV1<'a> {
    schema: &'a str,
    family: FinancialCredentialFamilyV1,
    #[serde(rename = "@context")]
    context: &'a [String],
    #[serde(rename = "type")]
    credential_type: &'a [String],
    issuer: &'a str,
    issuer_key_epoch: u64,
    issuance_date: &'a str,
    expiration_date: &'a str,
    credential_subject: &'a FinancialCredentialSubjectV1,
    evidence: &'a FinancialCredentialEvidenceV1,
    source_evidence_class: chio_core::capability::governance::ProvenanceEvidenceClass,
    presentation_evidence_class: chio_core::capability::governance::ProvenanceEvidenceClass,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FinancialCredentialSigningBodyV1<'a> {
    schema: &'a str,
    family: FinancialCredentialFamilyV1,
    credential_id: &'a str,
    #[serde(rename = "@context")]
    context: &'a [String],
    #[serde(rename = "type")]
    credential_type: &'a [String],
    issuer: &'a str,
    issuer_key_epoch: u64,
    issuance_date: &'a str,
    expiration_date: &'a str,
    credential_subject: &'a FinancialCredentialSubjectV1,
    evidence: &'a FinancialCredentialEvidenceV1,
    source_evidence_class: chio_core::capability::governance::ProvenanceEvidenceClass,
    presentation_evidence_class: chio_core::capability::governance::ProvenanceEvidenceClass,
}

impl FinancialCredentialEnvelope {
    #[must_use]
    pub const fn family(&self) -> FinancialCredentialFamilyV1 {
        self.family
    }

    #[must_use]
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    #[must_use]
    pub const fn source_evidence_class(
        &self,
    ) -> chio_core::capability::governance::ProvenanceEvidenceClass {
        self.source_evidence_class
    }

    #[must_use]
    pub const fn presentation_evidence_class(
        &self,
    ) -> chio_core::capability::governance::ProvenanceEvidenceClass {
        self.presentation_evidence_class
    }

    fn id_preimage(&self) -> FinancialCredentialIdPreimageV1<'_> {
        FinancialCredentialIdPreimageV1 {
            schema: &self.schema,
            family: self.family,
            context: &self.context,
            credential_type: &self.credential_type,
            issuer: &self.issuer,
            issuer_key_epoch: self.issuer_key_epoch,
            issuance_date: &self.issuance_date,
            expiration_date: &self.expiration_date,
            credential_subject: &self.credential_subject,
            evidence: &self.evidence,
            source_evidence_class: self.source_evidence_class,
            presentation_evidence_class: self.presentation_evidence_class,
        }
    }

    fn signing_body(&self) -> FinancialCredentialSigningBodyV1<'_> {
        FinancialCredentialSigningBodyV1 {
            schema: &self.schema,
            family: self.family,
            credential_id: &self.credential_id,
            context: &self.context,
            credential_type: &self.credential_type,
            issuer: &self.issuer,
            issuer_key_epoch: self.issuer_key_epoch,
            issuance_date: &self.issuance_date,
            expiration_date: &self.expiration_date,
            credential_subject: &self.credential_subject,
            evidence: &self.evidence,
            source_evidence_class: self.source_evidence_class,
            presentation_evidence_class: self.presentation_evidence_class,
        }
    }

    fn recompute_credential_id(&self) -> Result<String, CredentialError> {
        let canonical = canonical_json_bytes(&self.id_preimage())?;
        let mut preimage =
            Vec::with_capacity(FINANCIAL_CREDENTIAL_ID_DOMAIN.len() + canonical.len());
        preimage.extend_from_slice(FINANCIAL_CREDENTIAL_ID_DOMAIN);
        preimage.extend_from_slice(&canonical);
        Ok(sha256_hex(&preimage))
    }

    fn validate_contract(&self) -> Result<(), CredentialError> {
        let (issued_at, expires_at) = self.validate_contract_shape()?;
        validate_financial_evidence(self, issued_at, expires_at)
    }

    fn validate_contract_shape(&self) -> Result<(u64, u64), CredentialError> {
        let expected_family =
            FinancialCredentialFamilyV1::from_schema(&self.schema).ok_or_else(|| {
                CredentialError::UnsupportedFinancialCredentialSchema(self.schema.clone())
            })?;
        if expected_family != self.family || self.credential_subject.family() != self.family {
            return Err(CredentialError::FinancialCredentialSchemaFamilyMismatch {
                schema: self.schema.clone(),
                family: self.family.label().to_string(),
            });
        }
        if self.family == FinancialCredentialFamilyV1::SettlementReliability {
            return Err(CredentialError::FinancialReliabilityProofSubstrateUnavailable);
        }
        if self.context
            != [
                VC_CONTEXT_V1.to_string(),
                CHIO_CREDENTIAL_CONTEXT_V1.to_string(),
            ]
            || self.credential_type
                != [
                    VC_TYPE.to_string(),
                    self.family.credential_type().to_string(),
                ]
        {
            return invalid_financial("financial credential VC type binding is invalid");
        }
        validate_text("issuer", &self.issuer)?;
        let issuer = DidChio::from_str(&self.issuer)?;
        if self.issuer_key_epoch == 0 || self.issuer_key_epoch > I_JSON_MAX_SAFE_INTEGER {
            return invalid_financial("issuer key epoch is invalid");
        }
        validate_financial_subject(&self.credential_subject)?;
        let issued_at = unix_from_rfc3339(&self.issuance_date)?;
        let expires_at = unix_from_rfc3339(&self.expiration_date)?;
        validate_time("issuanceDate", issued_at)?;
        validate_time("expirationDate", expires_at)?;
        if issued_at >= expires_at {
            return Err(CredentialError::InvalidCredentialValidityWindow);
        }
        validate_evidence_classes(self)?;
        validate_digest("credentialId", &self.credential_id)?;
        if self.recompute_credential_id()? != self.credential_id {
            return invalid_financial("financial credential ID does not match its body");
        }
        if self.proof.proof_type != PROOF_TYPE {
            return Err(CredentialError::InvalidProofType);
        }
        if self.proof.proof_purpose != PROOF_PURPOSE {
            return Err(CredentialError::InvalidProofPurpose);
        }
        if self.proof.verification_method != issuer.verification_method_id() {
            return Err(CredentialError::IssuerVerificationMethodMismatch);
        }
        if self.proof.created != self.issuance_date {
            return invalid_financial("financial credential proof time does not match issuance");
        }
        Ok((issued_at, expires_at))
    }
}

pub fn issue_financial_credential(
    issuer_keypair: &Keypair,
    issuer_key_epoch: u64,
    input: chio_credit::financial_credentials::VerifiedFinancialCredentialIssuanceV1,
    issued_at: u64,
    expires_at: u64,
) -> Result<FinancialCredentialEnvelope, CredentialError> {
    validate_time("issuedAt", issued_at)?;
    validate_time("expiresAt", expires_at)?;
    if issued_at >= expires_at {
        return Err(CredentialError::InvalidCredentialValidityWindow);
    }
    let (credential_subject, evidence, source_evidence_class, proof_issued_at, proof_expires_at) =
        input.into_validated_parts();
    if issued_at < proof_issued_at || issued_at >= proof_expires_at || expires_at > proof_expires_at
    {
        return Err(CredentialError::InvalidCredentialValidityWindow);
    }
    let family = credential_subject.family();
    let issuer = DidChio::from_public_key(issuer_keypair.public_key())?;
    let mut envelope = FinancialCredentialEnvelope {
        schema: family.schema().to_string(),
        family,
        credential_id: String::new(),
        context: vec![
            VC_CONTEXT_V1.to_string(),
            CHIO_CREDENTIAL_CONTEXT_V1.to_string(),
        ],
        credential_type: vec![VC_TYPE.to_string(), family.credential_type().to_string()],
        issuer: issuer.to_string(),
        issuer_key_epoch,
        issuance_date: rfc3339_from_unix(issued_at)?,
        expiration_date: rfc3339_from_unix(expires_at)?,
        credential_subject,
        evidence,
        source_evidence_class,
        presentation_evidence_class:
            chio_core::capability::governance::ProvenanceEvidenceClass::Asserted,
        proof: CredentialProof {
            proof_type: PROOF_TYPE.to_string(),
            created: rfc3339_from_unix(issued_at)?,
            proof_purpose: PROOF_PURPOSE.to_string(),
            verification_method: issuer.verification_method_id(),
            proof_value: String::new(),
        },
    };
    envelope.credential_id = envelope.recompute_credential_id()?;
    envelope.validate_contract()?;
    envelope.proof.proof_value = issuer_keypair
        .sign_wrapped(
            envelope.family().schema(),
            &chio_core::canonical::CanonicalBytes::from_serializable(&envelope.signing_body())?,
        )?
        .to_hex();
    Ok(envelope)
}

pub fn inspect_financial_credential_signature(
    credential: &FinancialCredentialEnvelope,
    now: u64,
) -> Result<(), CredentialError> {
    credential.validate_contract()?;
    let issued_at = unix_from_rfc3339(&credential.issuance_date)?;
    let expires_at = unix_from_rfc3339(&credential.expiration_date)?;
    if now < issued_at {
        return Err(CredentialError::CredentialNotYetValid);
    }
    if now >= expires_at {
        return Err(CredentialError::CredentialExpired);
    }
    let issuer = DidChio::from_str(&credential.issuer)?;
    let signature = Signature::from_hex(&credential.proof.proof_value)?;
    if chio_core::crypto::verify_wrapped(
        &issuer.public_key(),
        credential.family().schema(),
        &credential.signing_body(),
        &signature,
    )
    .is_err()
    {
        return Err(CredentialError::InvalidCredentialSignature);
    }
    for source_proof in &credential.evidence.source_completeness_attestations {
        if source_proof.body.checkpoint_authority_key != source_proof.signer_key
            || !source_proof.verify_signature(&source_proof.signer_key)?
        {
            return Err(CredentialError::InvalidCredentialSignature);
        }
    }
    Ok(())
}

pub fn decode_financial_credential(
    bytes: &[u8],
) -> Result<FinancialCredentialEnvelope, CredentialError> {
    let value: serde_json::Value = chio_core::canonical::UntrustedJsonText::from_wire(
        bytes,
        MAX_FINANCIAL_PRESENTATION_BYTES,
    )?
    .decode_signed()?;
    preflight_financial_credential_value(&value)?;
    let credential: FinancialCredentialEnvelope = serde_json::from_value(value)
        .map_err(|error| invalid_financial_error(error.to_string()))?;
    credential.validate_contract()?;
    Ok(credential)
}

fn preflight_financial_credential_value(
    value: &serde_json::Value,
) -> Result<FinancialCredentialFamilyV1, CredentialError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_financial_error("financial credential must be an object"))?;
    let schema = object
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid_financial_error("financial credential schema is missing"))?;
    let expected_family = FinancialCredentialFamilyV1::from_schema(schema)
        .ok_or_else(|| CredentialError::UnsupportedFinancialCredentialSchema(schema.to_string()))?;
    let family = object
        .get("family")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid_financial_error("financial credential family is missing"))?;
    if family != expected_family.label() {
        return Err(CredentialError::FinancialCredentialSchemaFamilyMismatch {
            schema: schema.to_string(),
            family: family.to_string(),
        });
    }
    if expected_family == FinancialCredentialFamilyV1::SettlementReliability {
        return Err(CredentialError::FinancialReliabilityProofSubstrateUnavailable);
    }
    Ok(expected_family)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FinancialPassportCredentialFamily {
    Reputation,
    CreditScorecard,
    ExposureHistory,
    SettlementReliability,
    PremiumHistory,
    LossHistory,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinancialPassportManifestLeaf {
    pub credential_id: String,
    pub family: FinancialPassportCredentialFamily,
    pub credential_ref_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinancialPassportSourceManifest {
    pub schema: String,
    pub source_passport_id: String,
    pub issuer: String,
    pub subject: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub credential_count: u64,
    pub credential_root: String,
    pub merkle_roots: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enterprise_identity_provenance: Vec<EnterpriseIdentityProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_tier: Option<TrustTier>,
}

pub type SignedFinancialPassportSourceManifest =
    chio_core::receipt::lineage::SignedExportEnvelope<FinancialPassportSourceManifest>;

impl chio_core::receipt::lineage::SignedExportPayload for FinancialPassportSourceManifest {
    const SCHEMA_ID: &'static str = FINANCIAL_AGENT_PASSPORT_SOURCE_MANIFEST_SCHEMA_V1;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinancialPassportMembershipProof {
    pub leaf: FinancialPassportManifestLeaf,
    pub proof: chio_core::MerkleProof,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(
    tag = "kind",
    content = "credential",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum FinancialPassportCredential {
    Reputation(Box<ReputationCredential>),
    Financial(Box<FinancialCredentialEnvelope>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinancialPassportValidityWindow {
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinancialAgentPassport {
    pub schema: String,
    pub subject: String,
    pub credentials: Vec<FinancialPassportCredential>,
    pub merkle_roots: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enterprise_identity_provenance: Vec<EnterpriseIdentityProvenance>,
    pub issued_at: String,
    pub valid_until: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_tier: Option<TrustTier>,
    pub source_manifest: SignedFinancialPassportSourceManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PresentedFinancialAgentPassport {
    pub schema: String,
    pub source_manifest: SignedFinancialPassportSourceManifest,
    pub credentials: Vec<FinancialPassportCredential>,
    pub membership_proofs: Vec<FinancialPassportMembershipProof>,
    pub challenge_digest: String,
    pub presentation_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinancialPassportCredentialSelector {
    pub family: FinancialPassportCredentialFamily,
    pub credential_ref_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinancialPassportPresentationChallenge {
    pub schema: String,
    pub verifier: String,
    pub verifier_key_epoch: u64,
    pub challenge_id: String,
    pub nonce: String,
    pub issued_at: String,
    pub expires_at: String,
    pub source_passport_id: String,
    pub selectors: Vec<FinancialPassportCredentialSelector>,
    pub challenge_digest: String,
}

pub type SignedFinancialPassportPresentationChallenge =
    chio_core::receipt::lineage::SignedExportEnvelope<FinancialPassportPresentationChallenge>;

impl chio_core::receipt::lineage::SignedExportPayload for FinancialPassportPresentationChallenge {
    const SCHEMA_ID: &'static str = FINANCIAL_PASSPORT_PRESENTATION_CHALLENGE_SCHEMA_V1;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinancialPassportPresentationResponse {
    pub schema: String,
    pub challenge: SignedFinancialPassportPresentationChallenge,
    pub presentation: PresentedFinancialAgentPassport,
    pub proof: PresentationProof,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedFinancialPassportPresentationResponse<'a> {
    schema: &'a str,
    challenge: &'a SignedFinancialPassportPresentationChallenge,
    presentation: &'a PresentedFinancialAgentPassport,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FinancialPassportChallengeIdentity {
    pub verifier: String,
    pub challenge_id: String,
    pub nonce: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassportPresentationChallengeUseError {
    AlreadyUsed,
    Unavailable,
}

pub trait PassportPresentationChallengeUseStore {
    fn consume_once(
        &mut self,
        identity: &FinancialPassportChallengeIdentity,
    ) -> Result<(), PassportPresentationChallengeUseError>;
}

#[derive(Debug, Default)]
pub struct OfflinePassportPresentationChallengeUseStore {
    used_challenges: BTreeSet<FinancialPassportChallengeIdentity>,
}

impl PassportPresentationChallengeUseStore for OfflinePassportPresentationChallengeUseStore {
    fn consume_once(
        &mut self,
        identity: &FinancialPassportChallengeIdentity,
    ) -> Result<(), PassportPresentationChallengeUseError> {
        if self.used_challenges.insert(identity.clone()) {
            Ok(())
        } else {
            Err(PassportPresentationChallengeUseError::AlreadyUsed)
        }
    }
}

#[path = "financial/agent_passport.rs"]
mod financial_agent_passport;

use financial_agent_passport::validate_financial_agent_passport_contract;
pub use financial_agent_passport::{
    build_financial_agent_passport, build_presented_financial_agent_passport,
    create_financial_passport_presentation_challenge, inspect_financial_agent_passport,
    inspect_financial_passport_presentation_challenge, inspect_financial_passport_presentation_response,
    inspect_financial_passport_source_manifest_signature, inspect_presented_financial_agent_passport,
    issue_financial_passport_source_manifest, respond_to_financial_passport_presentation_challenge,
};

#[path = "financial/authority.rs"]
mod financial_authority;
pub use financial_authority::*;

pub fn decode_financial_agent_passport(bytes: &[u8]) -> Result<FinancialAgentPassport, CredentialError> {
    let value: serde_json::Value = chio_core::canonical::UntrustedJsonText::from_wire(
        bytes,
        MAX_FINANCIAL_PRESENTATION_BYTES,
    )?
    .decode_signed()?;
    let passport: FinancialAgentPassport = serde_json::from_value(value)
        .map_err(|error| invalid_financial_error(error.to_string()))?;
    validate_financial_agent_passport_contract(&passport)?;
    Ok(passport)
}

#[path = "financial/validation.rs"]
mod financial_validation;

use financial_validation::{
    invalid_financial, invalid_financial_error, validate_digest, validate_evidence_classes,
    validate_financial_evidence, validate_financial_subject, validate_text, validate_time,
};

#[cfg(test)]
#[path = "financial/tests.rs"]
mod financial_tests;

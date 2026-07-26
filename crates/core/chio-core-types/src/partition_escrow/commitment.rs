use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str;

use serde::{Deserialize, Serialize};

use super::artifact::{PartitionEscrowAllocationPlan, PartitionEscrowQuota};
use super::error::PartitionEscrowValidationError;
use super::validation::{validate_digest, validate_identifier, MAX_SAFE_JSON_INTEGER};
use crate::crypto::{Ed25519Backend, Keypair};
use crate::{
    canonical_json_bytes, sha256_hex, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};

pub const PARTITION_ESCROW_QUOTA_COMMITMENT_SCHEMA: &str =
    "chio.partition-escrow-quota-commitment.v1";
pub const PARTITION_ESCROW_QUOTA_COMMITMENT_SIGNATURE_DOMAIN: &str =
    "chio:partition-escrow-quota-commitment:v1";
pub const PARTITION_ESCROW_QUOTA_COMMITMENT_DIGEST_DOMAIN: &[u8] =
    b"chio.partition-escrow-quota-commitment-digest.v1\0";
pub const PARTITION_ESCROW_QUOTA_AUTHORITY_BINDING_DOMAIN: &[u8] =
    b"chio.partition-escrow-quota-authority-binding.v1\0";

/// Exact authenticated source facts that an allocation certificate authorizes.
///
/// This value is evidence, not authority. The kernel must derive it from one of
/// its sealed, profile-specific source verifiers before an escrow allocation can
/// become admission-capable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartitionEscrowQuotaSourceBinding {
    underlying_source_artifact_digest: String,
    source_trust_binding_digest: String,
    source_not_before: u64,
    source_expires_at: u64,
}

impl PartitionEscrowQuotaSourceBinding {
    pub fn new(
        underlying_source_artifact_digest: impl Into<String>,
        source_trust_binding_digest: impl Into<String>,
        source_not_before: u64,
        source_expires_at: u64,
    ) -> Result<Self, PartitionEscrowValidationError> {
        let binding = Self {
            underlying_source_artifact_digest: underlying_source_artifact_digest.into(),
            source_trust_binding_digest: source_trust_binding_digest.into(),
            source_not_before,
            source_expires_at,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), PartitionEscrowValidationError> {
        validate_digest(
            &self.underlying_source_artifact_digest,
            "underlying source artifact digest",
        )?;
        validate_digest(
            &self.source_trust_binding_digest,
            "source trust binding digest",
        )?;
        if self.source_not_before > MAX_SAFE_JSON_INTEGER
            || self.source_expires_at > MAX_SAFE_JSON_INTEGER
            || self.source_expires_at <= self.source_not_before
        {
            return Err(PartitionEscrowValidationError::InvalidTimeWindow);
        }
        Ok(())
    }

    pub fn underlying_source_artifact_digest(&self) -> &str {
        &self.underlying_source_artifact_digest
    }

    pub fn source_trust_binding_digest(&self) -> &str {
        &self.source_trust_binding_digest
    }

    pub const fn source_not_before(&self) -> u64 {
        self.source_not_before
    }

    pub const fn source_expires_at(&self) -> u64 {
        self.source_expires_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartitionEscrowQuotaCommitmentBody {
    schema: String,
    authority_domain: String,
    allocation_root_id: String,
    allocation_epoch: u64,
    quota: PartitionEscrowQuota,
    quota_key_digest: String,
    underlying_source_artifact_digest: String,
    source_trust_binding_digest: String,
    allocation_plan_digest: String,
    source_not_before: u64,
    source_expires_at: u64,
}

impl PartitionEscrowQuotaCommitmentBody {
    /// Build a certificate body from a complete validated plan and exact source
    /// binding. All plan fields are derived, so a caller cannot supply a quota,
    /// root, epoch, or plan digest independently.
    pub fn new(
        plan: &PartitionEscrowAllocationPlan,
        source: PartitionEscrowQuotaSourceBinding,
    ) -> Result<Self, PartitionEscrowValidationError> {
        plan.validate()?;
        source.validate()?;
        if plan.source_expires_at() != source.source_expires_at() {
            return Err(PartitionEscrowValidationError::QuotaAuthorityExpiryMismatch);
        }
        if plan.not_before() < source.source_not_before() {
            return Err(PartitionEscrowValidationError::AllocationPredatesQuotaAuthority);
        }
        let body = Self {
            schema: PARTITION_ESCROW_QUOTA_COMMITMENT_SCHEMA.to_string(),
            authority_domain: plan.authority_domain().to_string(),
            allocation_root_id: plan.allocation_root_id().to_string(),
            allocation_epoch: plan.allocation_epoch(),
            quota: plan.quota().clone(),
            quota_key_digest: plan.quota().key_digest()?,
            underlying_source_artifact_digest: source
                .underlying_source_artifact_digest()
                .to_string(),
            source_trust_binding_digest: source.source_trust_binding_digest().to_string(),
            allocation_plan_digest: plan.digest()?,
            source_not_before: source.source_not_before(),
            source_expires_at: source.source_expires_at(),
        };
        body.validate_structure()?;
        Ok(body)
    }

    pub fn validate_structure(&self) -> Result<(), PartitionEscrowValidationError> {
        if self.schema != PARTITION_ESCROW_QUOTA_COMMITMENT_SCHEMA {
            return Err(PartitionEscrowValidationError::InvalidSchema);
        }
        validate_identifier(&self.authority_domain, "authority domain")?;
        validate_identifier(&self.allocation_root_id, "allocation root id")?;
        if self.allocation_epoch == 0 || self.allocation_epoch > MAX_SAFE_JSON_INTEGER {
            return Err(PartitionEscrowValidationError::AllocationEpochMismatch);
        }
        self.quota.validate()?;
        validate_digest(&self.quota_key_digest, "quota key digest")?;
        if self.quota.key_digest()? != self.quota_key_digest {
            return Err(PartitionEscrowValidationError::QuotaMismatch);
        }
        validate_digest(
            &self.underlying_source_artifact_digest,
            "underlying source artifact digest",
        )?;
        validate_digest(
            &self.source_trust_binding_digest,
            "source trust binding digest",
        )?;
        validate_digest(&self.allocation_plan_digest, "allocation plan digest")?;
        if self.source_not_before > MAX_SAFE_JSON_INTEGER
            || self.source_expires_at > MAX_SAFE_JSON_INTEGER
            || self.source_expires_at <= self.source_not_before
        {
            return Err(PartitionEscrowValidationError::InvalidTimeWindow);
        }
        Ok(())
    }

    pub fn validate_at(&self, now: u64) -> Result<(), PartitionEscrowValidationError> {
        self.validate_structure()?;
        if now > MAX_SAFE_JSON_INTEGER {
            return Err(PartitionEscrowValidationError::InvalidTimeWindow);
        }
        if now < self.source_not_before {
            return Err(PartitionEscrowValidationError::NotYetValid);
        }
        if now >= self.source_expires_at {
            return Err(PartitionEscrowValidationError::Expired);
        }
        Ok(())
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn authority_domain(&self) -> &str {
        &self.authority_domain
    }

    pub fn allocation_root_id(&self) -> &str {
        &self.allocation_root_id
    }

    pub const fn allocation_epoch(&self) -> u64 {
        self.allocation_epoch
    }

    pub const fn quota(&self) -> &PartitionEscrowQuota {
        &self.quota
    }

    pub fn quota_key_digest(&self) -> &str {
        &self.quota_key_digest
    }

    pub fn underlying_source_artifact_digest(&self) -> &str {
        &self.underlying_source_artifact_digest
    }

    pub fn source_trust_binding_digest(&self) -> &str {
        &self.source_trust_binding_digest
    }

    pub fn allocation_plan_digest(&self) -> &str {
        &self.allocation_plan_digest
    }

    pub const fn source_not_before(&self) -> u64 {
        self.source_not_before
    }

    pub const fn source_expires_at(&self) -> u64 {
        self.source_expires_at
    }
}

/// Source-key authorization certificate over one exact source artifact and
/// complete allocation plan.
///
/// The type intentionally has no `Deserialize` implementation. Untrusted bytes
/// must pass through [`Self::from_canonical_json_bytes`]. A valid signature does
/// not prove source non-equivocation and does not confer admission authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPartitionEscrowQuotaCommitment {
    body: PartitionEscrowQuotaCommitmentBody,
    signer_key: PublicKey,
    algorithm: SigningAlgorithm,
    signature: Signature,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedPartitionEscrowQuotaCommitmentWire {
    body: PartitionEscrowQuotaCommitmentBody,
    signer_key: PublicKey,
    algorithm: SigningAlgorithm,
    signature: Signature,
}

impl SignedPartitionEscrowQuotaCommitment {
    pub fn sign(
        body: PartitionEscrowQuotaCommitmentBody,
        keypair: &Keypair,
    ) -> Result<Self, PartitionEscrowValidationError> {
        Self::sign_with_backend(body, &Ed25519Backend::new(keypair.clone()))
    }

    pub fn sign_with_backend(
        body: PartitionEscrowQuotaCommitmentBody,
        backend: &dyn SigningBackend,
    ) -> Result<Self, PartitionEscrowValidationError> {
        body.validate_structure()?;
        let outcome = backend
            .sign_bytes_with_identity(&commitment_signing_bytes(&body)?)
            .map_err(|error| PartitionEscrowValidationError::Signing(error.to_string()))?;
        if outcome.public_key.algorithm() != outcome.algorithm
            || outcome.signature.algorithm() != outcome.algorithm
        {
            return Err(PartitionEscrowValidationError::SignatureAlgorithmMismatch);
        }
        Ok(Self {
            body,
            signer_key: outcome.public_key,
            algorithm: outcome.algorithm,
            signature: outcome.signature,
        })
    }

    pub fn verify_signature(&self) -> Result<bool, PartitionEscrowValidationError> {
        self.body.validate_structure()?;
        if self.signer_key.algorithm() != self.algorithm
            || self.signature.algorithm() != self.algorithm
        {
            return Ok(false);
        }
        Ok(self
            .signer_key
            .verify(&commitment_signing_bytes(&self.body)?, &self.signature))
    }

    pub fn digest(&self) -> Result<String, PartitionEscrowValidationError> {
        let canonical = self.canonical_bytes()?;
        let mut input = Vec::with_capacity(
            PARTITION_ESCROW_QUOTA_COMMITMENT_DIGEST_DOMAIN.len() + canonical.len(),
        );
        input.extend_from_slice(PARTITION_ESCROW_QUOTA_COMMITMENT_DIGEST_DOMAIN);
        input.extend_from_slice(&canonical);
        Ok(sha256_hex(&input))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PartitionEscrowValidationError> {
        canonical_json_bytes(self)
            .map_err(|error| PartitionEscrowValidationError::Canonicalization(error.to_string()))
    }

    pub fn from_canonical_json_bytes(bytes: &[u8]) -> Result<Self, PartitionEscrowValidationError> {
        str::from_utf8(bytes)
            .map_err(|_| PartitionEscrowValidationError::InvalidEnvelopeEncoding)?;
        let wire: SignedPartitionEscrowQuotaCommitmentWire = serde_json::from_slice(bytes)
            .map_err(|error| PartitionEscrowValidationError::InvalidEnvelope(error.to_string()))?;
        let commitment = Self {
            body: wire.body,
            signer_key: wire.signer_key,
            algorithm: wire.algorithm,
            signature: wire.signature,
        };
        commitment.body.validate_structure()?;
        if commitment.canonical_bytes()?.as_slice() != bytes {
            return Err(PartitionEscrowValidationError::NonCanonicalEnvelope);
        }
        Ok(commitment)
    }

    pub const fn body(&self) -> &PartitionEscrowQuotaCommitmentBody {
        &self.body
    }

    pub const fn signer_key(&self) -> &PublicKey {
        &self.signer_key
    }

    pub const fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    pub const fn signature(&self) -> &Signature {
        &self.signature
    }
}

/// Cryptographically verified allocation certificate.
///
/// This result proves canonical structure, certificate freshness, and the
/// certificate signature only. It deliberately does not establish that the
/// referenced source artifact was authenticated, trusted, active, unrevoked,
/// or non-equivocating. Only a sealed kernel profile adapter may convert it to
/// admission-capable escrow authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPartitionEscrowQuotaCertificate {
    authority_domain: String,
    allocation_root_id: String,
    allocation_epoch: u64,
    quota: PartitionEscrowQuota,
    commitment_digest: String,
    underlying_source_artifact_digest: String,
    source_trust_binding_digest: String,
    source_not_before: u64,
    source_expires_at: u64,
    certificate_signer: PublicKey,
    allocation_plan_digest: String,
    verified_at: u64,
}

impl VerifiedPartitionEscrowQuotaCertificate {
    pub fn validate(&self) -> Result<(), PartitionEscrowValidationError> {
        validate_identifier(&self.authority_domain, "authority domain")?;
        validate_identifier(&self.allocation_root_id, "allocation root id")?;
        if self.allocation_epoch == 0 || self.allocation_epoch > MAX_SAFE_JSON_INTEGER {
            return Err(PartitionEscrowValidationError::AllocationEpochMismatch);
        }
        self.quota.validate()?;
        validate_digest(&self.commitment_digest, "quota commitment digest")?;
        validate_digest(
            &self.underlying_source_artifact_digest,
            "underlying source artifact digest",
        )?;
        validate_digest(
            &self.source_trust_binding_digest,
            "source trust binding digest",
        )?;
        validate_digest(&self.allocation_plan_digest, "allocation plan digest")?;
        if self.source_not_before > MAX_SAFE_JSON_INTEGER
            || self.source_expires_at > MAX_SAFE_JSON_INTEGER
            || self.source_expires_at <= self.source_not_before
            || self.verified_at < self.source_not_before
            || self.verified_at >= self.source_expires_at
        {
            return Err(PartitionEscrowValidationError::InvalidTimeWindow);
        }
        Ok(())
    }

    pub fn binding_digest(&self) -> Result<String, PartitionEscrowValidationError> {
        self.validate()?;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Binding<'a> {
            authority_domain: &'a str,
            allocation_root_id: &'a str,
            allocation_epoch: u64,
            quota: &'a PartitionEscrowQuota,
            commitment_digest: &'a str,
            underlying_source_artifact_digest: &'a str,
            source_trust_binding_digest: &'a str,
            source_not_before: u64,
            source_expires_at: u64,
            certificate_signer: &'a PublicKey,
            allocation_plan_digest: &'a str,
        }
        let canonical = canonical_json_bytes(&Binding {
            authority_domain: &self.authority_domain,
            allocation_root_id: &self.allocation_root_id,
            allocation_epoch: self.allocation_epoch,
            quota: &self.quota,
            commitment_digest: &self.commitment_digest,
            underlying_source_artifact_digest: &self.underlying_source_artifact_digest,
            source_trust_binding_digest: &self.source_trust_binding_digest,
            source_not_before: self.source_not_before,
            source_expires_at: self.source_expires_at,
            certificate_signer: &self.certificate_signer,
            allocation_plan_digest: &self.allocation_plan_digest,
        })
        .map_err(|error| PartitionEscrowValidationError::Canonicalization(error.to_string()))?;
        let mut input = Vec::with_capacity(
            PARTITION_ESCROW_QUOTA_AUTHORITY_BINDING_DOMAIN.len() + canonical.len(),
        );
        input.extend_from_slice(PARTITION_ESCROW_QUOTA_AUTHORITY_BINDING_DOMAIN);
        input.extend_from_slice(&canonical);
        Ok(sha256_hex(&input))
    }

    pub fn verify_commitment(
        &self,
        commitment: &SignedPartitionEscrowQuotaCommitment,
    ) -> Result<(), PartitionEscrowValidationError> {
        self.validate()?;
        commitment.body.validate_structure()?;
        let body = commitment.body();
        if body.authority_domain() != self.authority_domain {
            return Err(PartitionEscrowValidationError::AuthorityDomainMismatch);
        }
        if body.allocation_root_id() != self.allocation_root_id {
            return Err(PartitionEscrowValidationError::AllocationRootMismatch);
        }
        if body.allocation_epoch() != self.allocation_epoch {
            return Err(PartitionEscrowValidationError::AllocationEpochMismatch);
        }
        if body.quota() != &self.quota {
            return Err(PartitionEscrowValidationError::QuotaMismatch);
        }
        if body.underlying_source_artifact_digest() != self.underlying_source_artifact_digest {
            return Err(PartitionEscrowValidationError::UnderlyingSourceDigestMismatch);
        }
        if body.source_trust_binding_digest() != self.source_trust_binding_digest {
            return Err(PartitionEscrowValidationError::SourceTrustBindingMismatch);
        }
        if body.allocation_plan_digest() != self.allocation_plan_digest {
            return Err(PartitionEscrowValidationError::AllocationPlanDigestMismatch);
        }
        if body.source_not_before() != self.source_not_before
            || body.source_expires_at() != self.source_expires_at
        {
            return Err(PartitionEscrowValidationError::QuotaAuthorityExpiryMismatch);
        }
        if commitment.signer_key() != &self.certificate_signer {
            return Err(PartitionEscrowValidationError::SignerMismatch);
        }
        verify_commitment_signature(commitment)?;
        if commitment.digest()? != self.commitment_digest {
            return Err(PartitionEscrowValidationError::QuotaAuthorityDigestMismatch);
        }
        Ok(())
    }

    pub fn authority_domain(&self) -> &str {
        &self.authority_domain
    }

    pub fn allocation_root_id(&self) -> &str {
        &self.allocation_root_id
    }

    pub const fn allocation_epoch(&self) -> u64 {
        self.allocation_epoch
    }

    pub const fn quota(&self) -> &PartitionEscrowQuota {
        &self.quota
    }

    pub fn commitment_digest(&self) -> &str {
        &self.commitment_digest
    }

    pub fn underlying_source_artifact_digest(&self) -> &str {
        &self.underlying_source_artifact_digest
    }

    pub fn source_trust_binding_digest(&self) -> &str {
        &self.source_trust_binding_digest
    }

    pub const fn source_not_before(&self) -> u64 {
        self.source_not_before
    }

    pub const fn source_expires_at(&self) -> u64 {
        self.source_expires_at
    }

    pub const fn certificate_signer(&self) -> &PublicKey {
        &self.certificate_signer
    }

    pub fn allocation_plan_digest(&self) -> &str {
        &self.allocation_plan_digest
    }

    pub const fn verified_at(&self) -> u64 {
        self.verified_at
    }
}

pub fn verify_partition_escrow_quota_commitment(
    commitment: &SignedPartitionEscrowQuotaCommitment,
    now: u64,
) -> Result<VerifiedPartitionEscrowQuotaCertificate, PartitionEscrowValidationError> {
    commitment.body.validate_at(now)?;
    verify_commitment_signature(commitment)?;
    let body = commitment.body();
    let certificate = VerifiedPartitionEscrowQuotaCertificate {
        authority_domain: body.authority_domain().to_string(),
        allocation_root_id: body.allocation_root_id().to_string(),
        allocation_epoch: body.allocation_epoch(),
        quota: body.quota().clone(),
        commitment_digest: commitment.digest()?,
        underlying_source_artifact_digest: body.underlying_source_artifact_digest().to_string(),
        source_trust_binding_digest: body.source_trust_binding_digest().to_string(),
        source_not_before: body.source_not_before(),
        source_expires_at: body.source_expires_at(),
        certificate_signer: commitment.signer_key().clone(),
        allocation_plan_digest: body.allocation_plan_digest().to_string(),
        verified_at: now,
    };
    certificate.validate()?;
    Ok(certificate)
}

fn verify_commitment_signature(
    commitment: &SignedPartitionEscrowQuotaCommitment,
) -> Result<(), PartitionEscrowValidationError> {
    if commitment.signer_key().algorithm() != commitment.algorithm()
        || commitment.signature().algorithm() != commitment.algorithm()
    {
        return Err(PartitionEscrowValidationError::SignatureAlgorithmMismatch);
    }
    if !commitment.verify_signature()? {
        return Err(PartitionEscrowValidationError::SignatureInvalid);
    }
    Ok(())
}

fn commitment_signing_bytes(
    body: &PartitionEscrowQuotaCommitmentBody,
) -> Result<Vec<u8>, PartitionEscrowValidationError> {
    let canonical = canonical_json_bytes(body)
        .map_err(|error| PartitionEscrowValidationError::Canonicalization(error.to_string()))?;
    let mut bytes = Vec::with_capacity(
        PARTITION_ESCROW_QUOTA_COMMITMENT_SIGNATURE_DOMAIN.len() + 1 + canonical.len(),
    );
    bytes.extend_from_slice(PARTITION_ESCROW_QUOTA_COMMITMENT_SIGNATURE_DOMAIN.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

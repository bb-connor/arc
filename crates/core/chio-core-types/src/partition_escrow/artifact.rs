use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str;

use serde::{Deserialize, Serialize};

use super::commitment::VerifiedPartitionEscrowQuotaCertificate;
use super::error::PartitionEscrowValidationError;
use super::validation::{
    validate_allocations, validate_digest, validate_identifier, MAX_SAFE_JSON_INTEGER,
};
use crate::crypto::{Ed25519Backend, Keypair};
use crate::{
    canonical_json_bytes, sha256_hex, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};

pub const PARTITION_ESCROW_ALLOCATION_SET_SCHEMA: &str = "chio.partition-escrow-allocation-set.v1";
pub const PARTITION_ESCROW_ALLOCATION_SIGNATURE_DOMAIN: &str =
    "chio:partition-escrow-allocation-set:v1";
pub const PARTITION_ESCROW_ALLOCATION_SET_DIGEST_DOMAIN: &[u8] =
    b"chio.partition-escrow-allocation-set-digest.v1\0";
pub const PARTITION_ESCROW_ALLOCATION_PLAN_DIGEST_DOMAIN: &[u8] =
    b"chio.partition-escrow-allocation-plan.v1\0";
pub const PARTITION_ESCROW_QUOTA_DESCRIPTOR_DOMAIN: &[u8] =
    b"chio.partition-escrow-quota-descriptor.v1\0";
pub const PARTITION_ESCROW_QUOTA_KEY_DOMAIN: &[u8] = b"chio.partition-escrow-quota-key.v1\0";
pub const MAX_PARTITION_ESCROW_ALLOCATIONS: usize = 64;
pub const MAX_PARTITION_ESCROW_IDENTIFIER_BYTES: usize = 512;

const GRANT_INVOCATION_PROFILE: &str = "chio.grant-invocation.v1";
const AGGREGATE_CAPABILITY_INVOCATION_PROFILE: &str = "chio.aggregate-capability-invocation.v1";
const AGGREGATE_FAMILY_INVOCATION_PROFILE: &str = "chio.aggregate-family-invocation.v1";
const BROKER_CAPABILITY_EXECUTION_PROFILE: &str = "chio.broker-capability-execution.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartitionEscrowQuota {
    profile: String,
    owner_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grant_index: Option<u32>,
    max_invocations: u32,
}

impl PartitionEscrowQuota {
    pub fn new(
        profile: impl Into<String>,
        owner_id: impl Into<String>,
        grant_index: Option<u32>,
        max_invocations: u32,
    ) -> Result<Self, PartitionEscrowValidationError> {
        let quota = Self {
            profile: profile.into(),
            owner_id: owner_id.into(),
            grant_index,
            max_invocations,
        };
        quota.validate()?;
        Ok(quota)
    }

    pub fn validate(&self) -> Result<(), PartitionEscrowValidationError> {
        validate_identifier(&self.owner_id, "quota owner id")?;
        if matches!(
            self.profile.as_str(),
            AGGREGATE_FAMILY_INVOCATION_PROFILE | BROKER_CAPABILITY_EXECUTION_PROFILE
        ) {
            validate_digest(&self.owner_id, "derived quota owner id")?;
        }
        match self.profile.as_str() {
            GRANT_INVOCATION_PROFILE if self.grant_index.is_some() => Ok(()),
            AGGREGATE_CAPABILITY_INVOCATION_PROFILE
            | AGGREGATE_FAMILY_INVOCATION_PROFILE
            | BROKER_CAPABILITY_EXECUTION_PROFILE
                if self.grant_index.is_none() =>
            {
                Ok(())
            }
            GRANT_INVOCATION_PROFILE
            | AGGREGATE_CAPABILITY_INVOCATION_PROFILE
            | AGGREGATE_FAMILY_INVOCATION_PROFILE
            | BROKER_CAPABILITY_EXECUTION_PROFILE => {
                Err(PartitionEscrowValidationError::InvalidQuotaShape)
            }
            unknown => Err(PartitionEscrowValidationError::InvalidQuotaProfile(
                unknown.to_string(),
            )),
        }
    }

    pub fn descriptor_digest(&self) -> Result<String, PartitionEscrowValidationError> {
        self.validate()?;
        domain_separated_digest(PARTITION_ESCROW_QUOTA_DESCRIPTOR_DOMAIN, self)
    }

    /// Stable identity for one logical quota, excluding its signed maximum.
    pub fn key_digest(&self) -> Result<String, PartitionEscrowValidationError> {
        self.validate()?;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct QuotaKey<'a> {
            profile: &'a str,
            owner_id: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            grant_index: Option<u32>,
        }
        domain_separated_digest(
            PARTITION_ESCROW_QUOTA_KEY_DOMAIN,
            &QuotaKey {
                profile: &self.profile,
                owner_id: &self.owner_id,
                grant_index: self.grant_index,
            },
        )
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }

    pub const fn grant_index(&self) -> Option<u32> {
        self.grant_index
    }

    pub const fn max_invocations(&self) -> u32 {
        self.max_invocations
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartitionEscrowAllocation {
    partition_id: String,
    authority_id: String,
    allocated_invocations: u32,
}

impl PartitionEscrowAllocation {
    pub fn new(
        partition_id: impl Into<String>,
        authority_id: impl Into<String>,
        allocated_invocations: u32,
    ) -> Result<Self, PartitionEscrowValidationError> {
        let allocation = Self {
            partition_id: partition_id.into(),
            authority_id: authority_id.into(),
            allocated_invocations,
        };
        allocation.validate()?;
        Ok(allocation)
    }

    pub(super) fn validate(&self) -> Result<(), PartitionEscrowValidationError> {
        validate_identifier(&self.partition_id, "partition id")?;
        validate_identifier(&self.authority_id, "authority id")
    }

    pub fn partition_id(&self) -> &str {
        &self.partition_id
    }

    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    pub const fn allocated_invocations(&self) -> u32 {
        self.allocated_invocations
    }
}

/// Canonical complete-plan commitment carried by a source-key certificate.
///
/// The digest excludes the source artifact digest and all signatures to avoid
/// circularity. It commits to the complete allocation plan shared by every
/// partition authority. Kernel source binding is a separate admission step.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PartitionEscrowAllocationPlan {
    authority_domain: String,
    allocation_root_id: String,
    allocation_epoch: u64,
    quota: PartitionEscrowQuota,
    source_expires_at: u64,
    not_before: u64,
    expires_at: u64,
    allocations: Vec<PartitionEscrowAllocation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PartitionEscrowAllocationPlanBinding {
    authority_domain: String,
    allocation_root_id: String,
    allocation_epoch: u64,
    quota: PartitionEscrowQuota,
    source_expires_at: u64,
    not_before: u64,
    expires_at: u64,
}

impl PartitionEscrowAllocationPlanBinding {
    pub fn new(
        authority_domain: impl Into<String>,
        allocation_root_id: impl Into<String>,
        allocation_epoch: u64,
        quota: PartitionEscrowQuota,
        source_expires_at: u64,
        not_before: u64,
        expires_at: u64,
    ) -> Result<Self, PartitionEscrowValidationError> {
        let binding = Self {
            authority_domain: authority_domain.into(),
            allocation_root_id: allocation_root_id.into(),
            allocation_epoch,
            quota,
            source_expires_at,
            not_before,
            expires_at,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), PartitionEscrowValidationError> {
        validate_identifier(&self.authority_domain, "authority domain")?;
        validate_identifier(&self.allocation_root_id, "allocation root id")?;
        if self.allocation_epoch == 0 || self.allocation_epoch > MAX_SAFE_JSON_INTEGER {
            return Err(PartitionEscrowValidationError::AllocationEpochMismatch);
        }
        self.quota.validate()?;
        if self.source_expires_at == 0 || self.source_expires_at > MAX_SAFE_JSON_INTEGER {
            return Err(PartitionEscrowValidationError::InvalidTimeWindow);
        }
        if self.not_before > MAX_SAFE_JSON_INTEGER
            || self.expires_at > MAX_SAFE_JSON_INTEGER
            || self.expires_at <= self.not_before
        {
            return Err(PartitionEscrowValidationError::InvalidTimeWindow);
        }
        if self.expires_at > self.source_expires_at {
            return Err(PartitionEscrowValidationError::AllocationOutlivesQuotaAuthority);
        }
        Ok(())
    }
}

impl PartitionEscrowAllocationPlan {
    pub fn new(
        binding: PartitionEscrowAllocationPlanBinding,
        allocations: Vec<PartitionEscrowAllocation>,
    ) -> Result<Self, PartitionEscrowValidationError> {
        binding.validate()?;
        let plan = Self {
            authority_domain: binding.authority_domain,
            allocation_root_id: binding.allocation_root_id,
            allocation_epoch: binding.allocation_epoch,
            quota: binding.quota,
            source_expires_at: binding.source_expires_at,
            not_before: binding.not_before,
            expires_at: binding.expires_at,
            allocations,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), PartitionEscrowValidationError> {
        validate_identifier(&self.authority_domain, "authority domain")?;
        validate_identifier(&self.allocation_root_id, "allocation root id")?;
        if self.allocation_epoch == 0 || self.allocation_epoch > MAX_SAFE_JSON_INTEGER {
            return Err(PartitionEscrowValidationError::AllocationEpochMismatch);
        }
        self.quota.validate()?;
        if self.source_expires_at == 0 || self.source_expires_at > MAX_SAFE_JSON_INTEGER {
            return Err(PartitionEscrowValidationError::InvalidTimeWindow);
        }
        if self.not_before > MAX_SAFE_JSON_INTEGER
            || self.expires_at > MAX_SAFE_JSON_INTEGER
            || self.expires_at <= self.not_before
        {
            return Err(PartitionEscrowValidationError::InvalidTimeWindow);
        }
        if self.expires_at > self.source_expires_at {
            return Err(PartitionEscrowValidationError::AllocationOutlivesQuotaAuthority);
        }
        validate_allocations(&self.allocations, self.quota.max_invocations())
    }

    pub fn digest(&self) -> Result<String, PartitionEscrowValidationError> {
        self.validate()?;
        domain_separated_digest(PARTITION_ESCROW_ALLOCATION_PLAN_DIGEST_DOMAIN, self)
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

    pub const fn source_expires_at(&self) -> u64 {
        self.source_expires_at
    }

    pub const fn not_before(&self) -> u64 {
        self.not_before
    }

    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn allocations(&self) -> &[PartitionEscrowAllocation] {
        &self.allocations
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartitionEscrowAllocationSetBody {
    schema: String,
    authority_domain: String,
    allocation_root_id: String,
    allocation_epoch: u64,
    quota: PartitionEscrowQuota,
    quota_commitment_digest: String,
    quota_commitment_expires_at: u64,
    allocation_plan_digest: String,
    not_before: u64,
    expires_at: u64,
    allocations: Vec<PartitionEscrowAllocation>,
}

impl PartitionEscrowAllocationSetBody {
    pub fn new(
        quota_certificate: &VerifiedPartitionEscrowQuotaCertificate,
        not_before: u64,
        expires_at: u64,
        allocations: Vec<PartitionEscrowAllocation>,
    ) -> Result<Self, PartitionEscrowValidationError> {
        quota_certificate.validate()?;
        if not_before < quota_certificate.source_not_before() {
            return Err(PartitionEscrowValidationError::AllocationPredatesQuotaAuthority);
        }
        let plan = PartitionEscrowAllocationPlan::new(
            PartitionEscrowAllocationPlanBinding::new(
                quota_certificate.authority_domain(),
                quota_certificate.allocation_root_id(),
                quota_certificate.allocation_epoch(),
                quota_certificate.quota().clone(),
                quota_certificate.source_expires_at(),
                not_before,
                expires_at,
            )?,
            allocations,
        )?;
        let allocation_plan_digest = plan.digest()?;
        if allocation_plan_digest.as_str() != quota_certificate.allocation_plan_digest() {
            return Err(PartitionEscrowValidationError::AllocationPlanDigestMismatch);
        }
        let body = Self {
            schema: PARTITION_ESCROW_ALLOCATION_SET_SCHEMA.to_string(),
            authority_domain: plan.authority_domain,
            allocation_root_id: plan.allocation_root_id,
            allocation_epoch: plan.allocation_epoch,
            quota: plan.quota,
            quota_commitment_digest: quota_certificate.commitment_digest().to_string(),
            quota_commitment_expires_at: quota_certificate.source_expires_at(),
            allocation_plan_digest,
            not_before: plan.not_before,
            expires_at: plan.expires_at,
            allocations: plan.allocations,
        };
        body.validate_structure()?;
        Ok(body)
    }

    pub fn validate_structure(&self) -> Result<(), PartitionEscrowValidationError> {
        if self.schema != PARTITION_ESCROW_ALLOCATION_SET_SCHEMA {
            return Err(PartitionEscrowValidationError::InvalidSchema);
        }
        validate_digest(&self.quota_commitment_digest, "quota commitment digest")?;
        validate_digest(&self.allocation_plan_digest, "allocation plan digest")?;
        let plan = self.allocation_plan();
        plan.validate()?;
        if plan.digest()? != self.allocation_plan_digest {
            return Err(PartitionEscrowValidationError::AllocationPlanDigestMismatch);
        }
        Ok(())
    }

    pub fn validate_at(&self, now: u64) -> Result<(), PartitionEscrowValidationError> {
        self.validate_structure()?;
        if now > MAX_SAFE_JSON_INTEGER {
            return Err(PartitionEscrowValidationError::InvalidTimeWindow);
        }
        if now < self.not_before {
            return Err(PartitionEscrowValidationError::NotYetValid);
        }
        if now >= self.expires_at {
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

    pub fn quota_commitment_digest(&self) -> &str {
        &self.quota_commitment_digest
    }

    pub const fn quota_commitment_expires_at(&self) -> u64 {
        self.quota_commitment_expires_at
    }

    pub fn allocation_plan_digest(&self) -> &str {
        &self.allocation_plan_digest
    }

    pub fn computed_allocation_plan_digest(
        &self,
    ) -> Result<String, PartitionEscrowValidationError> {
        self.allocation_plan().digest()
    }

    pub const fn not_before(&self) -> u64 {
        self.not_before
    }

    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn allocations(&self) -> &[PartitionEscrowAllocation] {
        &self.allocations
    }

    fn allocation_plan(&self) -> PartitionEscrowAllocationPlan {
        PartitionEscrowAllocationPlan {
            authority_domain: self.authority_domain.clone(),
            allocation_root_id: self.allocation_root_id.clone(),
            allocation_epoch: self.allocation_epoch,
            quota: self.quota.clone(),
            source_expires_at: self.quota_commitment_expires_at,
            not_before: self.not_before,
            expires_at: self.expires_at,
            allocations: self.allocations.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedPartitionEscrowAllocationSet {
    body: PartitionEscrowAllocationSetBody,
    allocator_key: PublicKey,
    algorithm: SigningAlgorithm,
    signature: Signature,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedPartitionEscrowAllocationSetWire {
    body: PartitionEscrowAllocationSetBody,
    allocator_key: PublicKey,
    algorithm: SigningAlgorithm,
    signature: Signature,
}

impl SignedPartitionEscrowAllocationSet {
    pub fn sign(
        body: PartitionEscrowAllocationSetBody,
        keypair: &Keypair,
    ) -> Result<Self, PartitionEscrowValidationError> {
        Self::sign_with_backend(body, &Ed25519Backend::new(keypair.clone()))
    }

    pub fn sign_with_backend(
        body: PartitionEscrowAllocationSetBody,
        backend: &dyn SigningBackend,
    ) -> Result<Self, PartitionEscrowValidationError> {
        body.validate_structure()?;
        let outcome = backend
            .sign_bytes_with_identity(&allocation_signing_bytes(&body)?)
            .map_err(|error| PartitionEscrowValidationError::Signing(error.to_string()))?;
        if outcome.public_key.algorithm() != outcome.algorithm
            || outcome.signature.algorithm() != outcome.algorithm
        {
            return Err(PartitionEscrowValidationError::SignatureAlgorithmMismatch);
        }
        Ok(Self {
            body,
            allocator_key: outcome.public_key,
            algorithm: outcome.algorithm,
            signature: outcome.signature,
        })
    }

    pub fn verify_signature(&self) -> Result<bool, PartitionEscrowValidationError> {
        self.body.validate_structure()?;
        if self.allocator_key.algorithm() != self.algorithm
            || self.signature.algorithm() != self.algorithm
        {
            return Ok(false);
        }
        Ok(self
            .allocator_key
            .verify(&allocation_signing_bytes(&self.body)?, &self.signature))
    }

    pub fn digest(&self) -> Result<String, PartitionEscrowValidationError> {
        let canonical = self.canonical_bytes()?;
        let mut input = Vec::with_capacity(
            PARTITION_ESCROW_ALLOCATION_SET_DIGEST_DOMAIN.len() + canonical.len(),
        );
        input.extend_from_slice(PARTITION_ESCROW_ALLOCATION_SET_DIGEST_DOMAIN);
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
        let wire: SignedPartitionEscrowAllocationSetWire = serde_json::from_slice(bytes)
            .map_err(|error| PartitionEscrowValidationError::InvalidEnvelope(error.to_string()))?;
        let allocation_set = Self {
            body: wire.body,
            allocator_key: wire.allocator_key,
            algorithm: wire.algorithm,
            signature: wire.signature,
        };
        allocation_set.body.validate_structure()?;
        if allocation_set.canonical_bytes()?.as_slice() != bytes {
            return Err(PartitionEscrowValidationError::NonCanonicalEnvelope);
        }
        Ok(allocation_set)
    }

    pub const fn body(&self) -> &PartitionEscrowAllocationSetBody {
        &self.body
    }

    pub const fn allocator_key(&self) -> &PublicKey {
        &self.allocator_key
    }

    pub const fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    pub const fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, PartitionEscrowValidationError> {
        allocation_signing_bytes(&self.body)
    }
}

pub(super) fn allocation_signing_bytes(
    body: &PartitionEscrowAllocationSetBody,
) -> Result<Vec<u8>, PartitionEscrowValidationError> {
    let canonical = canonical_json_bytes(body)
        .map_err(|error| PartitionEscrowValidationError::Canonicalization(error.to_string()))?;
    let mut bytes = Vec::with_capacity(
        PARTITION_ESCROW_ALLOCATION_SIGNATURE_DOMAIN.len() + 1 + canonical.len(),
    );
    bytes.extend_from_slice(PARTITION_ESCROW_ALLOCATION_SIGNATURE_DOMAIN.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

fn domain_separated_digest(
    domain: &[u8],
    value: &impl Serialize,
) -> Result<String, PartitionEscrowValidationError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| PartitionEscrowValidationError::Canonicalization(error.to_string()))?;
    let mut input = Vec::with_capacity(domain.len() + canonical.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(&canonical);
    Ok(sha256_hex(&input))
}

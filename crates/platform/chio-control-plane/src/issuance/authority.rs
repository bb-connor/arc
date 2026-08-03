use std::path::{Path, PathBuf};

use chio_core::capability::{
    aggregate_budget::AggregateInvocationScope, attenuation::scope_hash,
    runtime_attestation::RuntimeAttestationEvidence, scope::ChioScope, token::CapabilityToken,
};
use chio_core::crypto::PublicKey;
use chio_core::SigningAlgorithm;
use chio_kernel::{
    CapabilityAuthority, CapabilityIssuanceContext, CapabilityLineageError, KernelError,
    ReceiptStoreError,
};
use chio_store_sqlite::SqliteReceiptStore;

use crate::policy::{ReputationIssuancePolicy, RuntimeAssuranceIssuancePolicy};

use super::attestation::verify_runtime_attestation_for_issuance;
use super::reputation::enforce_reputation_policy;
use super::scope::enforce_runtime_assurance_policy;
use super::util::unix_now;

pub fn wrap_capability_authority(
    inner: Box<dyn CapabilityAuthority>,
    issuance_policy: Option<ReputationIssuancePolicy>,
    runtime_assurance_policy: Option<RuntimeAssuranceIssuancePolicy>,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
) -> Result<Box<dyn CapabilityAuthority>, KernelError> {
    wrap_capability_authority_with_lineage_mode(
        inner,
        issuance_policy,
        runtime_assurance_policy,
        receipt_db_path,
        budget_db_path,
        true,
    )
}

pub(crate) fn wrap_capability_authority_with_deferred_lineage(
    inner: Box<dyn CapabilityAuthority>,
    issuance_policy: Option<ReputationIssuancePolicy>,
    runtime_assurance_policy: Option<RuntimeAssuranceIssuancePolicy>,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
) -> Result<Box<dyn CapabilityAuthority>, KernelError> {
    wrap_capability_authority_with_lineage_mode(
        inner,
        issuance_policy,
        runtime_assurance_policy,
        receipt_db_path,
        budget_db_path,
        false,
    )
}

fn wrap_capability_authority_with_lineage_mode(
    inner: Box<dyn CapabilityAuthority>,
    issuance_policy: Option<ReputationIssuancePolicy>,
    runtime_assurance_policy: Option<RuntimeAssuranceIssuancePolicy>,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    persist_lineage_immediately: bool,
) -> Result<Box<dyn CapabilityAuthority>, KernelError> {
    if let Some(path) = receipt_db_path {
        drop(
            SqliteReceiptStore::open_existing_strict(path)
                .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?,
        );
    }
    Ok(Box::new(PolicyBackedCapabilityAuthority {
        inner,
        issuance_policy,
        runtime_assurance_policy,
        receipt_db_path: receipt_db_path.map(Path::to_path_buf),
        budget_db_path: budget_db_path.map(Path::to_path_buf),
        persist_lineage_immediately,
    }))
}

struct PolicyBackedCapabilityAuthority {
    inner: Box<dyn CapabilityAuthority>,
    issuance_policy: Option<ReputationIssuancePolicy>,
    runtime_assurance_policy: Option<RuntimeAssuranceIssuancePolicy>,
    receipt_db_path: Option<PathBuf>,
    budget_db_path: Option<PathBuf>,
    persist_lineage_immediately: bool,
}

impl PolicyBackedCapabilityAuthority {
    fn issue_validated_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        runtime_attestation: Option<RuntimeAttestationEvidence>,
        security_context: Option<&CapabilityIssuanceContext>,
    ) -> Result<CapabilityToken, KernelError> {
        let now = unix_now();
        // Reputation integrity validation requires a trust set of kernel
        // signing keys. The inner authority (the local kernel) is the
        // canonical signer of issuance-context receipts, and its trusted
        // peers (federation/cross-kernel) extend that set. Without these, an
        // empty trust set silently filters every receipt as unsigned.
        let mut trusted_keys: Vec<String> = self
            .inner
            .trusted_public_keys()
            .into_iter()
            .map(|key| key.to_hex())
            .collect();
        trusted_keys.push(self.inner.authority_public_key().to_hex());
        let scope = apply_authoritative_issuance_policy(
            subject,
            scope,
            ttl_seconds,
            runtime_attestation.as_ref(),
            self.issuance_policy.as_ref(),
            self.runtime_assurance_policy.as_ref(),
            self.receipt_db_path.as_deref(),
            self.budget_db_path.as_deref(),
            &trusted_keys,
            now,
        )?;

        let expected_scope_hash = scope_hash(&scope).map_err(|error| {
            issuance_failure(format!("issued capability scope cannot be bound: {error}"))
        })?;
        let trusted_issuers = trusted_issuer_snapshot(self.inner.as_ref());
        let capability = match security_context {
            Some(context) => self.inner.issue_capability_with_security_context(
                subject,
                scope.clone(),
                ttl_seconds,
                runtime_attestation,
                context,
            )?,
            None => self
                .inner
                .issue_capability(subject, scope.clone(), ttl_seconds)?,
        };
        let issuance_validation_time = unix_now();
        validate_issued_capability(
            &capability,
            subject,
            &expected_scope_hash,
            ttl_seconds,
            &trusted_issuers,
            issuance_validation_time,
        )?;

        if self.persist_lineage_immediately {
            let Some(path) = self.receipt_db_path.as_deref() else {
                return Ok(capability);
            };
            let store = SqliteReceiptStore::open_existing_strict(path)
                .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
            if let Some(context) = security_context {
                store
                    .record_capability_snapshot_with_issuance_admission(
                        &context.tenant_id,
                        &context.lineage_id,
                        &capability,
                        None,
                    )
                    .map_err(contextual_persistence_error)?;
            } else if is_explicit_root_candidate(&capability) {
                store
                    .record_issued_aggregate_family_root(&capability, &trusted_issuers, unix_now())
                    .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
            } else {
                store
                    .record_capability_snapshot(&capability, None)
                    .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
            }
        }

        Ok(capability)
    }
}

/// Apply every authoritative issuance policy before any signing backend is
/// selected. Remote keyring issuance and local issuance call this same
/// transformation so neither path can bypass reputation, attestation trust,
/// runtime-assurance attenuation, or scope ceilings.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_authoritative_issuance_policy(
    subject: &PublicKey,
    scope: ChioScope,
    ttl_seconds: u64,
    runtime_attestation: Option<&RuntimeAttestationEvidence>,
    issuance_policy: Option<&ReputationIssuancePolicy>,
    runtime_assurance_policy: Option<&RuntimeAssuranceIssuancePolicy>,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    trusted_kernel_keys: &[String],
    now: u64,
) -> Result<ChioScope, KernelError> {
    let verified_runtime_attestation = verify_runtime_attestation_for_issuance(
        runtime_attestation,
        runtime_assurance_policy,
        now,
    )?;
    if let Some(policy) = issuance_policy {
        enforce_reputation_policy(
            subject,
            &scope,
            ttl_seconds,
            policy,
            receipt_db_path,
            budget_db_path,
            trusted_kernel_keys,
        )?;
    }
    match runtime_assurance_policy {
        Some(policy) => enforce_runtime_assurance_policy(
            &scope,
            ttl_seconds,
            policy,
            verified_runtime_attestation.as_ref(),
        ),
        None => Ok(scope),
    }
}

impl CapabilityAuthority for PolicyBackedCapabilityAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.inner.authority_public_key()
    }

    fn trusted_public_keys(&self) -> Vec<PublicKey> {
        self.inner.trusted_public_keys()
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError> {
        self.issue_validated_capability(subject, scope, ttl_seconds, None, None)
    }

    fn issue_capability_with_attestation(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        runtime_attestation: Option<RuntimeAttestationEvidence>,
    ) -> Result<CapabilityToken, KernelError> {
        self.issue_validated_capability(subject, scope, ttl_seconds, runtime_attestation, None)
    }

    fn issue_capability_with_security_context(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        runtime_attestation: Option<RuntimeAttestationEvidence>,
        security_context: &CapabilityIssuanceContext,
    ) -> Result<CapabilityToken, KernelError> {
        self.issue_validated_capability(
            subject,
            scope,
            ttl_seconds,
            runtime_attestation,
            Some(security_context),
        )
    }
}

fn contextual_persistence_error(error: CapabilityLineageError) -> KernelError {
    match error {
        CapabilityLineageError::ReceiptStore(ReceiptStoreError::Conflict(reason)) => {
            KernelError::CapabilityIssuanceDenied(reason)
        }
        other => KernelError::CapabilityIssuanceFailed(other.to_string()),
    }
}

fn is_explicit_root_candidate(capability: &CapabilityToken) -> bool {
    capability.delegation_chain.is_empty()
        && capability.scope.authorizes_delegation()
        && match capability.aggregate_invocation_budget.as_ref() {
            None => true,
            Some(budget) => budget.scope == AggregateInvocationScope::DelegationFamily,
        }
}

fn trusted_issuer_snapshot(authority: &dyn CapabilityAuthority) -> Vec<PublicKey> {
    let mut trusted_issuers = authority.trusted_public_keys();
    let current_authority = authority.authority_public_key();
    if !trusted_issuers.contains(&current_authority) {
        trusted_issuers.push(current_authority);
    }
    trusted_issuers
}

fn validate_issued_capability(
    capability: &CapabilityToken,
    expected_subject: &PublicKey,
    expected_scope_hash: &str,
    ttl_seconds: u64,
    trusted_issuers: &[PublicKey],
    issuance_validation_time: u64,
) -> Result<(), KernelError> {
    if &capability.subject != expected_subject {
        return Err(issuance_failure(
            "issued capability subject does not match the request",
        ));
    }

    let returned_scope_hash = scope_hash(&capability.scope).map_err(|error| {
        issuance_failure(format!("issued capability scope is invalid: {error}"))
    })?;
    if returned_scope_hash != expected_scope_hash {
        return Err(issuance_failure(
            "issued capability scope does not match the request",
        ));
    }

    if !capability.delegation_chain.is_empty() {
        return Err(issuance_failure(
            "direct issuance returned a delegated capability",
        ));
    }

    if !matches!(
        capability.expires_at.checked_sub(capability.issued_at),
        Some(lifetime) if lifetime > 0 && lifetime <= ttl_seconds
    ) {
        return Err(issuance_failure(
            "issued capability lifetime is outside the requested bound",
        ));
    }

    let declared_algorithm = capability.algorithm.unwrap_or(SigningAlgorithm::Ed25519);
    if declared_algorithm != capability.issuer.algorithm()
        || declared_algorithm != capability.signature.algorithm()
    {
        return Err(issuance_failure(
            "issued capability algorithm envelope is inconsistent",
        ));
    }

    if !trusted_issuers.contains(&capability.issuer) {
        return Err(issuance_failure(
            "issued capability signer is outside the trusted authority snapshot",
        ));
    }

    let verified = capability
        .verify_signature_at(issuance_validation_time)
        .map_err(|error| {
            issuance_failure(format!(
                "issued capability validity verification failed: {error}"
            ))
        })?;
    if !verified {
        return Err(issuance_failure(
            "issued capability signature verification failed",
        ));
    }

    Ok(())
}

fn issuance_failure(reason: impl Into<String>) -> KernelError {
    KernelError::CapabilityIssuanceFailed(reason.into())
}

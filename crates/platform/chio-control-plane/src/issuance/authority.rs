use chio_security_types::clock::{Clock, SystemClock};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chio_core::capability::{
    runtime_attestation::RuntimeAttestationEvidence, scope::ChioScope, token::CapabilityToken,
};
use chio_core::crypto::PublicKey;
use chio_kernel::{
    ensure_capability_issuance_supported, validate_issued_capability_response, CapabilityAuthority,
    KernelError,
};
use chio_store_sqlite::SqliteReceiptStore;

use crate::policy::{ReputationIssuancePolicy, RuntimeAssuranceIssuancePolicy};

use super::attestation::verify_runtime_attestation_for_issuance;
use super::reputation::{enforce_reputation_policy, ReputationInspectionContext};
use super::scope::enforce_runtime_assurance_policy;

pub fn wrap_capability_authority(
    inner: Box<dyn CapabilityAuthority>,
    issuance_policy: Option<ReputationIssuancePolicy>,
    runtime_assurance_policy: Option<RuntimeAssuranceIssuancePolicy>,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
) -> Box<dyn CapabilityAuthority> {
    wrap_capability_authority_with_clock(
        inner,
        issuance_policy,
        runtime_assurance_policy,
        receipt_db_path,
        budget_db_path,
        Arc::new(SystemClock),
    )
}

/// Wrap a service authority without introducing another time owner.
pub fn wrap_capability_authority_with_clock(
    inner: Box<dyn CapabilityAuthority>,
    issuance_policy: Option<ReputationIssuancePolicy>,
    runtime_assurance_policy: Option<RuntimeAssuranceIssuancePolicy>,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    clock: Arc<dyn Clock>,
) -> Box<dyn CapabilityAuthority> {
    wrap_capability_authority_with_lineage_mode(
        inner,
        issuance_policy,
        runtime_assurance_policy,
        receipt_db_path,
        budget_db_path,
        true,
        clock,
    )
}

pub(crate) fn wrap_capability_authority_with_deferred_lineage(
    inner: Box<dyn CapabilityAuthority>,
    issuance_policy: Option<ReputationIssuancePolicy>,
    runtime_assurance_policy: Option<RuntimeAssuranceIssuancePolicy>,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
) -> Box<dyn CapabilityAuthority> {
    wrap_capability_authority_with_lineage_mode(
        inner,
        issuance_policy,
        runtime_assurance_policy,
        receipt_db_path,
        budget_db_path,
        false,
        Arc::new(SystemClock),
    )
}

fn wrap_capability_authority_with_lineage_mode(
    inner: Box<dyn CapabilityAuthority>,
    issuance_policy: Option<ReputationIssuancePolicy>,
    runtime_assurance_policy: Option<RuntimeAssuranceIssuancePolicy>,
    receipt_db_path: Option<&Path>,
    budget_db_path: Option<&Path>,
    persist_lineage_immediately: bool,
    clock: Arc<dyn Clock>,
) -> Box<dyn CapabilityAuthority> {
    Box::new(PolicyBackedCapabilityAuthority {
        clock,
        inner,
        issuance_policy,
        runtime_assurance_policy,
        receipt_db_path: receipt_db_path.map(Path::to_path_buf),
        budget_db_path: budget_db_path.map(Path::to_path_buf),
        persist_lineage_immediately,
    })
}

struct PolicyBackedCapabilityAuthority {
    clock: Arc<dyn Clock>,
    inner: Box<dyn CapabilityAuthority>,
    issuance_policy: Option<ReputationIssuancePolicy>,
    runtime_assurance_policy: Option<RuntimeAssuranceIssuancePolicy>,
    receipt_db_path: Option<PathBuf>,
    budget_db_path: Option<PathBuf>,
    persist_lineage_immediately: bool,
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
        self.issue_capability_with_attestation(subject, scope, ttl_seconds, None)
    }

    fn issue_aggregate_family_root(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        max_invocations: u32,
    ) -> Result<CapabilityToken, KernelError> {
        self.issue(subject, scope, ttl_seconds, None, Some(max_invocations))
    }

    fn issue_capability_with_attestation(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        runtime_attestation: Option<RuntimeAttestationEvidence>,
    ) -> Result<CapabilityToken, KernelError> {
        self.issue(subject, scope, ttl_seconds, runtime_attestation, None)
    }
}

impl PolicyBackedCapabilityAuthority {
    fn issue(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        runtime_attestation: Option<RuntimeAttestationEvidence>,
        aggregate_family_limit: Option<u32>,
    ) -> Result<CapabilityToken, KernelError> {
        let clock_now = self.clock.unix_millis()?.as_secs();
        let mut scope = scope;
        let now = clock_now;
        let verified_runtime_attestation = verify_runtime_attestation_for_issuance(
            runtime_attestation.as_ref(),
            self.runtime_assurance_policy.as_ref(),
            now,
        )?;

        if let Some(policy) = &self.issuance_policy {
            // Reputation integrity validation requires a trust set of kernel
            // signing keys. The inner authority (the local kernel) is the
            // canonical signer of issuance-context receipts, and its trusted
            // peers (federation/cross-kernel) extend that set. Without these,
            // an empty trust set would silently filter every receipt as
            // unsigned (see chio-reputation::receipt_integrity_valid).
            let mut trusted_keys: Vec<String> = self
                .inner
                .trusted_public_keys()
                .into_iter()
                .map(|key| key.to_hex())
                .collect();
            trusted_keys.push(self.inner.authority_public_key().to_hex());
            enforce_reputation_policy(
                subject,
                &scope,
                ttl_seconds,
                policy,
                self.receipt_db_path.as_deref(),
                self.budget_db_path.as_deref(),
                ReputationInspectionContext {
                    clock: self.clock.clone(),
                    trusted_kernel_keys: &trusted_keys,
                    read_context: &chio_kernel::ReceiptReadContext::local_operator_admin_all(),
                },
            )?;
        }

        if let Some(policy) = &self.runtime_assurance_policy {
            scope = enforce_runtime_assurance_policy(
                &scope,
                ttl_seconds,
                policy,
                verified_runtime_attestation.as_ref(),
            )?;
        }

        ensure_capability_issuance_supported(&scope)?;

        let capability = match aggregate_family_limit {
            Some(limit) => {
                let capability = self.inner.issue_aggregate_family_root(
                    subject,
                    scope.clone(),
                    ttl_seconds,
                    limit,
                )?;
                chio_kernel::authority::validate_issued_aggregate_family_root_response(
                    &capability,
                    subject,
                    &scope,
                    ttl_seconds,
                    &self.inner.authority_public_key(),
                    limit,
                    self.clock.unix_millis()?,
                )?;
                capability
            }
            None => {
                let capability =
                    self.inner
                        .issue_capability(subject, scope.clone(), ttl_seconds)?;
                validate_issued_capability_response(
                    &capability,
                    subject,
                    &scope,
                    ttl_seconds,
                    &self.inner.authority_public_key(),
                    self.clock.unix_millis()?,
                )?;
                capability
            }
        };

        if self.persist_lineage_immediately {
            let Some(path) = self.receipt_db_path.as_deref() else {
                return Ok(capability);
            };
            let store = SqliteReceiptStore::open_with_clock(path, self.clock.clone())
                .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
            store
                .record_capability_snapshot(&capability, None)
                .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
        }

        Ok(capability)
    }
}

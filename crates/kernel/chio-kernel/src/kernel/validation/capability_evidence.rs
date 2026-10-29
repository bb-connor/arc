//! Shared full capability evidence verification with caller-owned clock selection.
use super::*;

/// Typed policy and operational failures from full capability verification.
pub(in crate::kernel) enum CapabilityPreAdmissionError {
    Preparation(String),
    IssuerLifecycle(KernelError),
    Issuance(KernelError),
    Verification(chio_kernel_core::CapabilityError),
}

impl CapabilityPreAdmissionError {
    pub(in crate::kernel) fn deny_reason(self) -> String {
        match self {
            Self::Preparation(reason) => reason,
            Self::IssuerLifecycle(error) => {
                format!("capability issuer lifecycle denied: {error}")
            }
            Self::Issuance(error) => error.to_string(),
            Self::Verification(error) => {
                chio_kernel_core::KernelCoreError::InvalidCapability(error).deny_reason()
            }
        }
    }
}

impl ChioKernel {
    pub(in crate::kernel) fn verify_capability_full_pre_admit_typed(
        &self,
        cap: &CapabilityToken,
        remote_kernel_id: Option<&str>,
        now: u64,
    ) -> Result<(), CapabilityPreAdmissionError> {
        self.verify_capability_full_typed_with_clock(cap, remote_kernel_id, now, |kernel| {
            // Sample after authority/lineage lookups, retaining the fresh
            // caller's admission floor and its owned clock refusal.
            let fresh_now = kernel
                .read_authority_time()
                .map_err(|error| KernelError::Clock(error).to_string())?
                .as_secs();
            Ok(chio_kernel_core::FixedClock::new(now.max(fresh_now)))
        })
    }

    pub(super) fn verify_capability_full_pre_admit_with_clock(
        &self,
        cap: &CapabilityToken,
        remote_kernel_id: Option<&str>,
        now: u64,
        verification_clock: impl FnOnce(&Self) -> Result<chio_kernel_core::FixedClock, String>,
    ) -> Result<(), String> {
        self.verify_capability_full_typed_with_clock(cap, remote_kernel_id, now, verification_clock)
            .map_err(CapabilityPreAdmissionError::deny_reason)
    }

    pub(super) fn verify_capability_full_typed_with_clock(
        &self,
        cap: &CapabilityToken,
        remote_kernel_id: Option<&str>,
        now: u64,
        verification_clock: impl FnOnce(&Self) -> Result<chio_kernel_core::FixedClock, String>,
    ) -> Result<(), CapabilityPreAdmissionError> {
        use CapabilityPreAdmissionError::{Issuance, IssuerLifecycle, Preparation, Verification};
        self.capability_authority
            .check_issuer_lifecycle(&cap.issuer, cap.issued_at, now)
            .map_err(IssuerLifecycle)?;
        let trusted = self.trusted_issuer_keys();
        let peer_profile = self
            .capability_negotiation_for_remote(remote_kernel_id, now)
            .map_err(Preparation)?;
        let trust_resolver = self.capability_trust_root_resolver_snapshot();
        let mut budgets = chio_kernel_core::NoopBudgetRegistry;
        let direct_root = self
            .negotiated_capability_root(cap, &peer_profile)
            .map_err(Preparation)?;
        let ancestors = self.signed_capability_ancestors(cap).map_err(Preparation)?;
        let root_delegator = self.delegation_root_subject(cap).map_err(Preparation)?;
        let clock = verification_clock(self).map_err(Preparation)?;

        chio_kernel_core::verify_capability_full_with_evidence(
            cap,
            &trusted,
            &clock,
            capability_crypto_floor(self.capability_crypto_floor),
            chio_kernel_core::CapabilityEvidenceContext {
                features: chio_kernel_core::CapabilityFeatureContext {
                    peer: &peer_profile,
                    direct_root: direct_root.as_ref(),
                    root_delegator: root_delegator.as_ref(),
                },
                ancestors: &ancestors,
            },
            &trust_resolver,
            &mut budgets,
        )
        .map_err(Verification)?;
        crate::ensure_capability_issuance_supported(&cap.scope).map_err(Issuance)?;
        Ok(())
    }
}

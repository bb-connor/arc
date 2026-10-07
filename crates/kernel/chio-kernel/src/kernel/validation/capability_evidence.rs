//! Shared full capability evidence verification with caller-owned clock selection.
use super::*;

impl ChioKernel {
    pub(super) fn verify_capability_full_pre_admit_with_clock(
        &self,
        cap: &CapabilityToken,
        remote_kernel_id: Option<&str>,
        now: u64,
        verification_clock: impl FnOnce(&Self) -> Result<chio_kernel_core::FixedClock, String>,
    ) -> Result<(), CapabilityPreAdmissionError> {
        use CapabilityPreAdmissionError::Preparation;
        self.check_capability_issuer_lifecycle(cap, now)
            .map_err(Preparation)?;
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
                },
                ancestors: &ancestors,
            },
            &trust_resolver,
            &mut budgets,
        )
        .map_err(CapabilityPreAdmissionError::Verification)?;
        crate::ensure_capability_issuance_supported(&cap.scope)
            .map_err(|error| Preparation(error.to_string()))?;
        Ok(())
    }
}

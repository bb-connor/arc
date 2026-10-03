//! Shared live issuer resolution for full and portable admission.
use super::*;

impl ChioKernel {
    pub fn capability_issuer_is_trusted(&self, issuer: &chio_core::PublicKey) -> bool {
        self.trusted_issuer_keys().contains(issuer)
    }

    /// Resolve explicit CA pins and the configured capability authority.
    /// The receipt signer has no implicit capability-issuing authority. The
    /// method is also used by the chio-kernel-core delegation path
    /// so the portable TCB verifier sees the same trust set as the
    /// inline check.
    pub(crate) fn trusted_issuer_keys(&self) -> Vec<chio_core::PublicKey> {
        let mut trusted = self.config.ca_public_keys.clone();
        for authority_pk in self.capability_authority.trusted_public_keys() {
            if !trusted.contains(&authority_pk) {
                trusted.push(authority_pk);
            }
        }
        trusted
    }

    pub(super) fn check_capability_issuer_lifecycle(
        &self,
        capability: &CapabilityToken,
        now: u64,
    ) -> Result<(), String> {
        self.capability_authority
            .check_issuer_lifecycle(&capability.issuer, capability.issued_at, now)
            .map_err(|error| format!("capability issuer lifecycle denied: {error}"))
    }
}

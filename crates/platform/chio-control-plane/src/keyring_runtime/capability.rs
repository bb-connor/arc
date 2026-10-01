//! Capability issuance and its original witnessed signing evidence.
use super::{CliError, KeyringRuntimeComposition};
use chio_core::capability::token::CapabilityToken;
use chio_kernel::{GovernedCapabilityAuthority, SystemCapabilityAuthorityClock};
use std::sync::Arc;

impl KeyringRuntimeComposition {
    /// Build an authority for an embedded host using this runtime's sole
    /// generation-fenced signer. Migration enforcement is checked here and
    /// before and after every signing operation through the returned authority.
    pub fn capability_authority(&self) -> Result<GovernedCapabilityAuthority, CliError> {
        self.ensure_bound_signing_topology()?;
        Ok(GovernedCapabilityAuthority::new(
            self.authority_backend.clone(),
            Arc::new(SystemCapabilityAuthorityClock),
        ))
    }

    /// Recover the exact evidence persisted when this capability was issued.
    /// This never signs again or substitutes a newer issuance time. A consumer
    /// verifies the result against its independently pinned key-log verifier.
    pub fn capability_signing_evidence(
        &self,
        capability: &CapabilityToken,
    ) -> Result<chio_keyring::KeyringSigningResult, CliError> {
        self.ensure_bound_signing_topology()?;
        capability.validate_schema()?;
        let bytes = chio_core::canonical_json_bytes(&capability.signing_body())?;
        self.router
            .persisted_signing_result_for_artifact(
                &capability.issuer,
                &bytes,
                &capability.signature,
            )
            .map_err(|error| CliError::cli_other_error(error.to_string()))
    }

    /// Export the contiguous update from a consumer's existing public-key-log
    /// pin. The receiving verifier authenticates the update before accepting it.
    pub fn key_log_synchronization_response(
        &self,
        base: Option<&chio_keyring::KeyLogPin>,
    ) -> Result<chio_keyring::KeyLogSyncResponse, CliError> {
        self.require_key_log_verification()?;
        self.store
            .synchronization_response(base)
            .map_err(|error| CliError::cli_other_error(error.to_string()))
    }
}

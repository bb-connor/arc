//! Bind issuer construction to one admitted authority view before persistence.

use super::super::registry_write_lane::RegistryOperationError;
use super::*;
use crate::trust_control::report_validation::{
    inspect_authority_state_blocking, load_authority_status_for_state,
};

const UNADMITTED_SIGNER: &str =
    "passport issuer signing key is not the admitted live authority head";

#[cfg(test)]
#[path = "issuer_authority/provisional_test_observer.rs"]
pub(crate) mod provisional_test_observer;

/// Metadata uses the already-selected key and performs no second key lookup.
pub(super) fn metadata(
    config: &TrustServiceConfig,
    signer: Option<&Keypair>,
) -> Result<Oid4vciCredentialIssuerMetadata, RegistryOperationError> {
    passport_credential_issuer_with(config, |_| {
        signer.cloned().ok_or_else(|| {
            CliError::cli_other_error("passport issuer has no selected signing key".to_string())
        })
    })
    .map_err(RegistryOperationError::configuration)
}

fn bind_signer(state: &TrustServiceState, key: &Keypair) -> Result<(), Response> {
    let status = load_authority_status_for_state(state)?;
    let selected = key.public_key().to_hex();
    if !status.configured
        || status.public_key.as_deref() != Some(selected.as_str())
        || !status
            .trusted_public_keys
            .iter()
            .any(|live| live == &selected)
    {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            UNADMITTED_SIGNER,
        ));
    }
    Ok(())
}

/// Call only inside an already-admitted fresh registry mutation callback.
/// Entitlement checks precede this operation. Its guard covers provisional
/// in-memory mutation and signing; the caller persists only after it succeeds.
pub(super) fn run<T>(
    state: &TrustServiceState,
    operation: impl FnOnce(&TrustServiceState, Option<&Keypair>) -> Result<T, RegistryOperationError>,
) -> Result<T, RegistryOperationError> {
    let unconfigured = state.config.authority_db_path.is_none()
        && state.config.authority_seed_path.is_none()
        && state.config.authority_keyring_config_path.is_none()
        && state.authority_keyring.is_none();
    if unconfigured {
        return operation(state, None);
    }
    // Keep the constructor's missing-advertise-url refusal before key lookup.
    if state.config.advertise_url.is_none() {
        metadata(&state.config, None)?;
    }
    // This read is existing-only and makes no authority write. Keeping it
    // before admission preserves the metadata configuration refusal class.
    let selected = crate::trust_control::config_and_public::resolve_public_registry_signing_key(
        &state.config,
        &state.finding_challenge_clock,
    )
    .map_err(RegistryOperationError::configuration)?;
    inspect_authority_state_blocking(state, |state| {
        bind_signer(state, &selected)?;
        let result =
            operation(state, Some(&selected)).map_err(RegistryOperationError::into_response)?;
        #[cfg(test)]
        provisional_test_observer::after_operation(state, &selected.public_key())?;
        bind_signer(state, &selected)?;
        Ok(result)
    })
    .map_err(RegistryOperationError::authority)
}

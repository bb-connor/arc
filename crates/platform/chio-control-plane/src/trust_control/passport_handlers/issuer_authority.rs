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

/// The admitted signing key and the did:chio issuers of its authority's live
/// key history.
pub(super) struct AdmittedIssuer {
    keypair: Keypair,
    trusted_issuers: BTreeSet<String>,
}

impl AdmittedIssuer {
    pub(super) fn portable_signer(&self) -> PortableIssuanceSigner<'_> {
        PortableIssuanceSigner {
            keypair: &self.keypair,
            trusted_issuers: &self.trusted_issuers,
        }
    }
}

/// The did:chio issuers of every key the admitted authority status lists as
/// live: the current head and rotated keys still inside their verification
/// window. A revoked or retired key is not live and is absent. An empty
/// history is refused.
pub(crate) fn trusted_issuers_from_authority_history(
    status: &TrustAuthorityStatus,
) -> Result<BTreeSet<String>, CliError> {
    let keys = status
        .trusted_public_keys
        .iter()
        .map(|key| PublicKey::from_hex(key))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(chio_credentials::trusted_issuers_from_keys(&keys)?)
}

/// Metadata uses the already-selected key and performs no second key lookup.
pub(super) fn metadata(
    config: &TrustServiceConfig,
    signer: Option<&AdmittedIssuer>,
) -> Result<Oid4vciCredentialIssuerMetadata, RegistryOperationError> {
    passport_credential_issuer_with(config, |_| {
        signer.map(|signer| signer.keypair.clone()).ok_or_else(|| {
            CliError::cli_other_error("passport issuer has no selected signing key".to_string())
        })
    })
    .map_err(RegistryOperationError::configuration)
}

fn bind_signer(state: &TrustServiceState, key: &Keypair) -> Result<TrustAuthorityStatus, Response> {
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
    Ok(status)
}

/// Call only inside an already-admitted fresh registry mutation callback.
/// Entitlement checks precede this operation. Its guard covers provisional
/// in-memory mutation and signing; the caller persists only after it succeeds.
pub(super) fn run<T>(
    state: &TrustServiceState,
    operation: impl FnOnce(
        &TrustServiceState,
        Option<&AdmittedIssuer>,
    ) -> Result<T, RegistryOperationError>,
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
        let status = bind_signer(state, &selected)?;
        let trusted_issuers = trusted_issuers_from_authority_history(&status).map_err(|error| {
            plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string())
        })?;
        let admitted = AdmittedIssuer {
            keypair: selected,
            trusted_issuers,
        };
        let result =
            operation(state, Some(&admitted)).map_err(RegistryOperationError::into_response)?;
        #[cfg(test)]
        provisional_test_observer::after_operation(state, &admitted.keypair.public_key())?;
        bind_signer(state, &admitted.keypair)?;
        Ok(result)
    })
    .map_err(RegistryOperationError::authority)
}

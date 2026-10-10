//! Existing-only authority reads for unauthenticated routes.
//!
//! Public metadata, discovery, health and code redemption inspect authority
//! material that an authenticated owner provisioned. They never create a
//! database, directory or signing seed, never commit an authority write and
//! never take the authority write lock. Absent material is refused.

use super::*;
use chio_security_types::clock::Clock;
use chio_store_sqlite::authority::{
    AuthorityInspectionError, AuthorityVerificationStatus, SqliteAuthorityInspection,
};

const UNINITIALIZED_AUTHORITY_DB: &str =
    "public authority inspection requires a configured authority whose database its owner has initialized";
const ABSENT_AUTHORITY_SEED: &str =
    "public authority inspection requires a configured authority signing seed that already exists";

fn inspection_error(error: AuthorityInspectionError) -> CliError {
    match error {
        AuthorityInspectionError::Uninitialized => {
            CliError::cli_other_error(UNINITIALIZED_AUTHORITY_DB.to_string())
        }
        AuthorityInspectionError::Store(error) => error.into(),
    }
}

fn inspect_authority_db(
    path: &Path,
    clock: &Arc<dyn Clock>,
    config: &TrustServiceConfig,
) -> Result<SqliteAuthorityInspection, CliError> {
    SqliteAuthorityInspection::open_existing_with_clock_and_replication_policy(
        path,
        Arc::clone(clock),
        config.authority_replication_clock_policy()?,
    )
    .map_err(inspection_error)
}

pub(crate) fn public_authority_verification_status(
    path: &Path,
    config: &TrustServiceConfig,
    clock: &Arc<dyn Clock>,
) -> Result<AuthorityVerificationStatus, CliError> {
    inspect_authority_db(path, clock, config)?
        .verification_status()
        .map_err(inspection_error)
}

pub(crate) fn public_replicated_authority_verification_status(
    path: &Path,
    config: &TrustServiceConfig,
    clock: &Arc<dyn Clock>,
) -> Result<AuthorityVerificationStatus, CliError> {
    inspect_authority_db(path, clock, config)?
        .replicated_verification_status()
        .map_err(inspection_error)
}

/// Authority status as `authority_status_for_config` reports it, read from
/// existing storage only.
pub(crate) fn public_authority_status(
    config: &TrustServiceConfig,
    clock: &Arc<dyn Clock>,
) -> Result<TrustAuthorityStatus, CliError> {
    match config.authority_db_path.as_deref() {
        Some(path) => {
            let status = public_authority_verification_status(path, config, clock)?.status;
            Ok(authority_status_response("sqlite".to_string(), status))
        }
        // Without a database the shared status reader only reads an existing seed.
        None => authority_status_for_config(config),
    }
}

pub(crate) fn resolve_public_oid4vp_verifier_trusted_public_keys(
    config: &TrustServiceConfig,
    clock: &Arc<dyn Clock>,
) -> Result<Vec<PublicKey>, CliError> {
    trusted_public_keys_from_status(&public_authority_status(config, clock)?)
}

/// The local signing key `resolve_oid4vp_verifier_signing_key` selects,
/// loaded only when it already exists.
pub(crate) fn resolve_public_authority_signing_key(
    config: &TrustServiceConfig,
    clock: &Arc<dyn Clock>,
) -> Result<Keypair, CliError> {
    if let Some(path) = config.authority_db_path.as_deref() {
        return inspect_authority_db(path, clock, config)?
            .local_keypair()
            .map_err(inspection_error);
    }
    let path = config.authority_seed_path.as_deref().ok_or_else(|| {
        CliError::cli_other_error(
            "OID4VP verifier requests require a configured authority signing seed".to_string(),
        )
    })?;
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(CliError::cli_other_error(ABSENT_AUTHORITY_SEED.to_string()))
        }
        _ => crate::load_existing_authority_keypair(path),
    }
}

/// The signer `load_behavioral_feed_signing_keypair` selects for public registry
/// documents, loaded only when it already exists.
pub(crate) fn resolve_public_registry_signing_key(
    config: &TrustServiceConfig,
    clock: &Arc<dyn Clock>,
) -> Result<Keypair, CliError> {
    match (
        config.authority_seed_path.as_deref(),
        config.authority_db_path.as_deref(),
    ) {
        (Some(_), Some(_)) => Err(CliError::cli_other_error(
            "behavioral feed export requires either --authority-seed-file or --authority-db, not both"
                .to_string(),
        )),
        (None, None) => Err(CliError::cli_other_error(
            "behavioral feed export requires --authority-seed-file or --authority-db so the export can be signed"
                .to_string(),
        )),
        _ => resolve_public_authority_signing_key(config, clock),
    }
}

/// Issuer metadata for unauthenticated readers, identical to
/// `configured_passport_credential_issuer` for provisioned authority material.
pub(crate) fn public_passport_credential_issuer(
    config: &TrustServiceConfig,
    clock: &Arc<dyn Clock>,
) -> Result<Oid4vciCredentialIssuerMetadata, CliError> {
    passport_credential_issuer_with(config, |config| {
        resolve_public_authority_signing_key(config, clock)
    })
}

/// Load existing custody only, then bind the actual signer to the exact
/// admitted live head. A former local seed cannot sign current trust documents.
pub(crate) fn resolve_public_authority_signing_key_for_status(
    config: &TrustServiceConfig,
    clock: &Arc<dyn Clock>,
    status: &TrustAuthorityStatus,
) -> Result<Keypair, CliError> {
    let key = resolve_public_authority_signing_key(config, clock)?;
    let public = key.public_key().to_hex();
    if status.public_key.as_deref() != Some(public.as_str())
        || !status.trusted_public_keys.contains(&public)
    {
        return Err(CliError::cli_other_error(
            "public discovery signer does not own the admitted live authority head".to_string(),
        ));
    }
    Ok(key)
}

pub(crate) fn public_passport_credential_issuer_with_status(
    config: &TrustServiceConfig,
    clock: &Arc<dyn Clock>,
    status: Option<&TrustAuthorityStatus>,
) -> Result<Oid4vciCredentialIssuerMetadata, CliError> {
    match status {
        Some(status) => passport_credential_issuer_with(config, |config| {
            resolve_public_authority_signing_key_for_status(config, clock, status)
        }),
        None => public_passport_credential_issuer(config, clock),
    }
}

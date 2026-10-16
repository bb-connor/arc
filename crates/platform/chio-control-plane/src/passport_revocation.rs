//! Durable passport revocation beside the passport lifecycle registry.
//!
//! Every passport revocation is recorded in a durable sparse-Merkle
//! revocation oracle kept next to the lifecycle registry file, before the
//! registry is written. Lifecycle resolutions consult the oracle, so a
//! passport revoked through any handle on the oracle file is denied without a
//! restart, and a failure between the two writes leaves the passport denied.

use std::path::{Path, PathBuf};

use chio_credentials::{
    AgentPassport, Oid4vciChioPassportStatusReference, PassportLifecycleRecord,
    PassportLifecycleResolution, PassportLifecycleState,
};
use chio_revocation_oracle::{
    passport_revocation_key, RevocationOracleError, SqliteRevocationOracle,
    SqliteRevocationOracleError,
};

use crate::passport_verifier::{PassportStatusRegistry, RegistryUpdateError};
use crate::CliError;

/// The durable revocation oracle kept beside a passport lifecycle registry:
/// `<registry file name>.revocations.sqlite3` in the same directory.
pub fn passport_revocation_oracle_path(registry: &Path) -> Result<PathBuf, CliError> {
    let name = registry
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            CliError::policy_error("passport lifecycle registry path has no UTF-8 file name")
        })?;
    Ok(registry.with_file_name(format!("{name}.revocations.sqlite3")))
}

fn open_passport_revocation_oracle(registry: &Path) -> Result<SqliteRevocationOracle, CliError> {
    SqliteRevocationOracle::open(&passport_revocation_oracle_path(registry)?).map_err(|error| {
        CliError::policy_error(format!("passport revocation oracle unavailable: {error}"))
    })
}

/// Revokes a passport in the lifecycle registry at `registry`, recording the
/// revocation in the durable oracle before the registry file is written.
pub fn revoke_passport_status(
    registry: &Path,
    passport_id: &str,
    reason: Option<&str>,
    revoked_at: Option<u64>,
) -> Result<PassportLifecycleRecord, RegistryUpdateError> {
    PassportStatusRegistry::update(registry, |lifecycle| {
        let record = lifecycle.revoke(passport_id, reason, revoked_at)?;
        let event = record
            .to_revocation_event()
            .map_err(|error| CliError::policy_error(error.to_string()))?
            .ok_or_else(|| CliError::policy_error("revoked passport produced no revocation"))?;
        match open_passport_revocation_oracle(registry)?
            .revoke(event.to_revocation_key(), event.revoked_at_unix_ms)
        {
            Ok(_)
            | Err(SqliteRevocationOracleError::Oracle(RevocationOracleError::AlreadyRevoked)) => {
                Ok(record)
            }
            Err(error) => Err(CliError::policy_error(format!(
                "passport revocation oracle refused `{passport_id}`: {error}"
            ))),
        }
    })
}

/// Refuses a lifecycle resolution that reports a passport the durable
/// revocation oracle beside `registry` holds as revoked in any other state.
pub fn check_passport_revocation(
    registry: &Path,
    resolution: &PassportLifecycleResolution,
) -> Result<(), CliError> {
    if resolution.state == PassportLifecycleState::Revoked {
        return Ok(());
    }
    let revoked = open_passport_revocation_oracle(registry)?
        .is_revoked(&passport_revocation_key(&resolution.passport_id))
        .map_err(|error| {
            CliError::policy_error(format!("passport revocation oracle unavailable: {error}"))
        })?;
    if revoked {
        return Err(CliError::policy_error(format!(
            "passport `{}` is revoked in the passport revocation oracle",
            resolution.passport_id
        )));
    }
    Ok(())
}

/// Builds the portable lifecycle reference for `passport` from the registry
/// loaded from `path`, refusing a passport the durable revocation oracle
/// beside `path` holds as revoked.
pub fn portable_passport_status_reference(
    path: &Path,
    registry: &PassportStatusRegistry,
    passport: &AgentPassport,
    at: u64,
) -> Result<Oid4vciChioPassportStatusReference, CliError> {
    let reference = registry.portable_status_reference_for_passport(passport, at)?;
    check_passport_revocation(path, &registry.resolve_for_passport(passport, at)?)?;
    Ok(reference)
}

#[cfg(test)]
#[path = "passport_revocation_tests.rs"]
mod tests;

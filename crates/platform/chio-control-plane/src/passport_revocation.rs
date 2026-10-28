//! Durable passport revocation beside the passport lifecycle registry.
//!
//! Every passport revocation is recorded in a durable sparse-Merkle
//! revocation oracle kept next to the lifecycle registry file, before the
//! registry is written: one leaf for the passport and one for each signed
//! credential it carries. Lifecycle resolutions consult the oracle, so a
//! passport revoked through any handle on the oracle file is denied without a
//! restart, and a failure between the two writes leaves the passport denied.

use std::path::{Path, PathBuf};

use chio_credentials::{
    passport_credential_digests, AgentPassport, Oid4vciChioPassportStatusReference,
    PassportLifecycleRecord, PassportLifecycleResolution, PassportLifecycleState,
};
use chio_revocation_oracle::{
    credential_revocation_key, passport_revocation_key, SqliteRevocationOracle,
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

pub(crate) fn open_passport_revocation_oracle(
    registry: &Path,
) -> Result<SqliteRevocationOracle, CliError> {
    SqliteRevocationOracle::open(&passport_revocation_oracle_path(registry)?).map_err(|error| {
        CliError::policy_error(format!("passport revocation oracle unavailable: {error}"))
    })
}

/// Revokes a passport in the lifecycle registry at `registry`, recording the
/// passport leaf and one credential leaf per credential digest in the durable
/// oracle, in one transaction, before the registry file is written. An
/// absent `revoked_at` is `now`; a revocation dated after `now` is refused
/// before anything is written.
pub fn revoke_passport_status(
    registry: &Path,
    passport_id: &str,
    reason: Option<&str>,
    revoked_at: Option<u64>,
    now: u64,
) -> Result<PassportLifecycleRecord, RegistryUpdateError> {
    let revoked_at = revoked_at.unwrap_or(now);
    if revoked_at > now {
        return Err(RegistryUpdateError::Refused(CliError::policy_error(format!(
            "passport `{passport_id}` cannot be revoked at {revoked_at}, after the current time {now}"
        ))));
    }
    PassportStatusRegistry::update(registry, |lifecycle| {
        let record = lifecycle.revoke(passport_id, reason, Some(revoked_at))?;
        let event = record
            .to_revocation_event()
            .map_err(|error| CliError::policy_error(error.to_string()))?
            .ok_or_else(|| CliError::policy_error("revoked passport produced no revocation"))?;
        let mut keys = vec![event.to_revocation_key()];
        keys.extend(
            record
                .credential_digests
                .iter()
                .map(|digest| credential_revocation_key(digest)),
        );
        open_passport_revocation_oracle(registry)?
            .transact(event.revoked_at_unix_ms, |txn| {
                for key in &keys {
                    txn.revoke(key)?;
                }
                Ok(())
            })
            .map_err(|error| {
                CliError::policy_error(format!(
                    "passport revocation oracle refused `{passport_id}`: {error}"
                ))
            })?;
        Ok(record)
    })
}

/// Refuses a lifecycle resolution that reports a passport, or any of the
/// credentials in `credential_digests`, the durable revocation oracle beside
/// `registry` holds as revoked, unless the resolution already reports the
/// passport revoked.
pub fn check_passport_revocation(
    registry: &Path,
    resolution: &PassportLifecycleResolution,
    credential_digests: &[String],
) -> Result<(), CliError> {
    if resolution.state == PassportLifecycleState::Revoked {
        return Ok(());
    }
    let oracle = open_passport_revocation_oracle(registry)?;
    let is_revoked = |key| {
        oracle.is_revoked(&key).map_err(|error| {
            CliError::policy_error(format!("passport revocation oracle unavailable: {error}"))
        })
    };
    if is_revoked(passport_revocation_key(&resolution.passport_id))? {
        return Err(CliError::policy_error(format!(
            "passport `{}` is revoked in the passport revocation oracle",
            resolution.passport_id
        )));
    }
    for digest in credential_digests {
        if is_revoked(credential_revocation_key(digest))? {
            return Err(CliError::policy_error(format!(
                "credential `{digest}` of passport `{}` is revoked in the passport revocation oracle",
                resolution.passport_id
            )));
        }
    }
    Ok(())
}

/// Refuses a lifecycle resolution of the presented `passport` when the
/// oracle beside `registry` holds the passport or any of its signed
/// credentials as revoked.
pub fn check_presented_passport_revocation(
    registry: &Path,
    resolution: &PassportLifecycleResolution,
    passport: &AgentPassport,
) -> Result<(), CliError> {
    let digests = passport_credential_digests(passport)
        .map_err(|error| CliError::policy_error(error.to_string()))?;
    check_passport_revocation(registry, resolution, &digests)
}

/// Refuses a lifecycle resolution of the passport registered under
/// `resolution.passport_id` when the oracle holds the passport or any
/// credential its registry record lists as revoked.
pub fn check_registered_passport_revocation(
    registry_path: &Path,
    registry: &PassportStatusRegistry,
    resolution: &PassportLifecycleResolution,
) -> Result<(), CliError> {
    let digests = registry
        .get(&resolution.passport_id)
        .map(|record| record.credential_digests.as_slice())
        .unwrap_or_default();
    check_passport_revocation(registry_path, resolution, digests)
}

/// Builds the portable lifecycle reference for `passport` from the registry
/// loaded from `path`, refusing a passport the durable revocation oracle
/// beside `path` holds as revoked, in whole or in any of its credentials.
pub fn portable_passport_status_reference(
    path: &Path,
    registry: &PassportStatusRegistry,
    passport: &AgentPassport,
    at: u64,
) -> Result<Oid4vciChioPassportStatusReference, CliError> {
    let reference = registry.portable_status_reference_for_passport(passport, at)?;
    check_presented_passport_revocation(
        path,
        &registry.resolve_for_passport(passport, at)?,
        passport,
    )?;
    Ok(reference)
}

#[cfg(test)]
#[path = "passport_revocation_tests.rs"]
mod tests;

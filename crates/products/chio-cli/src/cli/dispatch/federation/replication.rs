//! Operator-only provisioning. These commands have no peer-HTTP entrypoint.
use super::*;
use chio_kernel::authority::replication::{AuthorityReplicationAnchor, MAX_AUTHORITY_WIRE_BYTES};
use chio_store_sqlite::SqliteCapabilityAuthority;
use std::io::{Read, Write};

pub(super) fn initialize(
    database: &std::path::Path,
    stream: &str,
    out: &std::path::Path,
    recovery_public_key: Option<&str>,
) -> Result<(), CliError> {
    let recovery = recovery_public_key
        .map(chio_core::PublicKey::from_hex)
        .transpose()?;
    if recovery.as_ref().is_some_and(|key| {
        key.algorithm() != chio_core::SigningAlgorithm::Ed25519 || key.is_weak_ed25519()
    }) {
        return Err(CliError::cli_other_error(
            "recovery root must be strong Ed25519",
        ));
    }
    // Refuse accidental replacement of a previously distributed checkpoint.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)?;
    let result = (|| {
        let authority = SqliteCapabilityAuthority::open(database)?;
        let anchor = authority.initialize_replication_with_recovery(stream, recovery.as_ref())?;
        file.write_all(&serde_json::to_vec_pretty(&anchor)?)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        println!("{}", anchor.commitment()?);
        Ok(())
    })();
    if result.is_err() {
        drop(file);
        let _ = std::fs::remove_file(out);
    }
    result
}

fn report(status: chio_kernel::AuthorityStatus) {
    println!(
        "{}",
        serde_json::json!({
            "publicKey": status.public_key.to_hex(),
            "generation": status.generation,
            "changedAt": status.rotated_at,
            "liveIssuers": status.trusted_public_keys.iter().map(chio_core::PublicKey::to_hex).collect::<Vec<_>>(),
        })
    );
}

fn existing(database: &std::path::Path) -> Result<SqliteCapabilityAuthority, CliError> {
    let metadata = std::fs::symlink_metadata(database)?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(CliError::cli_other_error(
            "issuer lifecycle requires an existing authority database",
        ));
    }
    SqliteCapabilityAuthority::open(database).map_err(Into::into)
}

pub(super) fn rotate(database: &std::path::Path, deadline: Option<u64>) -> Result<(), CliError> {
    let authority = existing(database)?;
    let status = match deadline {
        Some(deadline) => authority.rotate_with_verification_deadline(deadline)?,
        None => authority.rotate()?,
    };
    report(status);
    Ok(())
}

pub(super) fn retire(database: &std::path::Path, issuer: &str) -> Result<(), CliError> {
    let issuer = chio_core::PublicKey::from_hex(issuer)?;
    report(existing(database)?.retire_issuer(&issuer)?);
    Ok(())
}

pub(super) fn revoke(database: &std::path::Path, issuer: &str) -> Result<(), CliError> {
    let issuer = chio_core::PublicKey::from_hex(issuer)?;
    report(existing(database)?.revoke_issuer(&issuer)?);
    Ok(())
}

pub(super) fn recover(
    database: &std::path::Path,
    recovery_key: &std::path::Path,
) -> Result<(), CliError> {
    let recovery = chio_control_plane::load_existing_authority_keypair(recovery_key)?;
    report(existing(database)?.recover_authority(&recovery)?);
    Ok(())
}

pub(super) fn pin(
    database: &std::path::Path,
    path: &std::path::Path,
    expected: &str,
) -> Result<(), CliError> {
    let mut bytes = Vec::new();
    let read_limit = u64::try_from(MAX_AUTHORITY_WIRE_BYTES + 1)
        .map_err(|_| CliError::cli_other_error("authority input bound exceeds reader range"))?;
    std::fs::File::open(path)?
        .take(read_limit)
        .read_to_end(&mut bytes)?;
    let anchor: AuthorityReplicationAnchor =
        chio_core::canonical::UntrustedJsonText::from_wire(&bytes, MAX_AUTHORITY_WIRE_BYTES)?
            .decode_signed()?;
    // The operator obtains this digest separately from the authenticated source.
    if anchor.commitment()? != expected {
        return Err(CliError::cli_other_error(
            "authority checkpoint differs from the operator-pinned digest",
        ));
    }
    SqliteCapabilityAuthority::open(database)?.pin_replication_anchor(&anchor)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    #[test]
    fn kg2_issuer_cli_rotates_retires_revokes_and_recovers() -> TestResult {
        let root = chio_test_support::private_tempdir()?;
        let database = root.path().join("authority.db");
        let key_file = root.path().join("recovery.key");
        let recovery = chio_control_plane::load_or_create_authority_keypair(&key_file)?;
        initialize(
            &database,
            "recoverable-cli",
            &root.path().join("anchor.json"),
            Some(&recovery.public_key().to_hex()),
        )?;
        let authority = SqliteCapabilityAuthority::open(&database)?;
        let old = authority.status()?.public_key;
        rotate(&database, None)?;
        retire(&database, &old.to_hex())?;
        revoke(&database, &old.to_hex())?;
        let wrong_file = root.path().join("wrong.key");
        chio_control_plane::load_or_create_authority_keypair(&wrong_file)?;
        assert!(
            matches!(recover(&database, &wrong_file), Err(CliError::AuthorityStore(chio_kernel::AuthorityStoreError::Fence(message))) if message == "lifecycle signer does not own the required authority")
        );
        recover(&database, &key_file)?;
        let status = authority.status()?;
        assert_eq!(status.generation, 5);
        assert_eq!(status.trusted_public_keys, vec![status.public_key]);
        let missing = root.path().join("missing.db");
        assert!(
            matches!(rotate(&missing, None), Err(CliError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound)
        );
        assert!(!missing.exists());
        Ok(())
    }
    #[test]
    fn authority_replication_cli_pins_checkpoint_without_private_custody() -> TestResult {
        let root = chio_test_support::private_tempdir()?;
        let source = root.path().join("source.db");
        let target = root.path().join("follower.db");
        let path = root.path().join("anchor.json");
        initialize(&source, "cluster-identity", &path, None)?;
        assert!(initialize(&source, "cluster-identity", &path, None).is_err());
        let authority = SqliteCapabilityAuthority::open(&source)?;
        let digest = authority.replication_anchor()?.commitment()?;
        assert!(pin(&target, &path, &"00".repeat(32)).is_err());
        assert!(!target.exists(), "invalid pin must not create a database");
        pin(&target, &path, &digest)?;
        pin(&target, &path, &digest)?;
        let follower = SqliteCapabilityAuthority::open(&target)?;
        assert_eq!(authority.snapshot()?, follower.snapshot()?);
        assert_ne!(
            authority.local_keypair()?.seed_hex(),
            follower.local_keypair()?.seed_hex()
        );
        assert!(follower.current_keypair().is_err());
        Ok(())
    }
    #[test]
    fn authority_replication_cli_rejects_duplicate_keys_before_store_open() -> TestResult {
        let root = chio_test_support::private_tempdir()?;
        let source = SqliteCapabilityAuthority::open(root.path().join("source.db"))?;
        let anchor = source.initialize_replication("duplicate-key-control")?;
        let encoded = serde_json::to_string(&anchor)?;
        let fields = encoded.strip_prefix('{').ok_or("anchor is not an object")?;
        // Keep every required field and the correct operator digest. A parser
        // that silently accepts this duplicate would otherwise install the pin.
        let duplicate = format!(
            "{{\"schema\":{},{}",
            serde_json::to_string(&anchor.schema)?,
            fields
        );
        let path = root.path().join("bad.json");
        std::fs::write(&path, duplicate)?;
        let target = root.path().join("follower.db");
        assert!(matches!(
            pin(&target, &path, &anchor.commitment()?),
            Err(CliError::SignedJson(_))
        ));
        assert!(!target.exists());
        Ok(())
    }
}

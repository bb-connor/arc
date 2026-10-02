//! Operator-only provisioning. These commands have no peer-HTTP entrypoint.
use super::*;
use chio_kernel::authority::replication::{AuthorityReplicationAnchor, MAX_AUTHORITY_WIRE_BYTES};
use chio_store_sqlite::SqliteCapabilityAuthority;
use std::io::{Read, Write};

pub(super) fn initialize(
    database: &std::path::Path,
    stream: &str,
    out: &std::path::Path,
) -> Result<(), CliError> {
    // Refuse accidental replacement of a previously distributed checkpoint.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)?;
    let result = (|| {
        let authority = SqliteCapabilityAuthority::open(database)?;
        let anchor = authority.initialize_replication(stream)?;
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
    fn authority_replication_cli_pins_checkpoint_without_private_custody() -> TestResult {
        let root = tempfile::tempdir()?;
        let source = root.path().join("source.db");
        let target = root.path().join("follower.db");
        let path = root.path().join("anchor.json");
        initialize(&source, "cluster-identity", &path)?;
        assert!(initialize(&source, "cluster-identity", &path).is_err());
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
        let root = tempfile::tempdir()?;
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

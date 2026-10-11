//! Catalog identifiers are names, never output paths.
use super::{CliError, Path, PathBuf, ProofFixtureCatalog};

fn validate_id(id: &str) -> Result<(), CliError> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(CliError::cli_other_error(
            "invalid proof fixture catalog identifier",
        ));
    }
    Ok(())
}

pub(super) fn validate(catalog: &ProofFixtureCatalog) -> Result<(), CliError> {
    if catalog.fixtures.len() > crate::input::collection::MAX_ENTRIES {
        return Err(CliError::cli_other_error(
            "proof fixture catalog entry limit exceeded",
        ));
    }
    let mut names = std::collections::BTreeSet::new();
    for fixture in &catalog.fixtures {
        validate_id(&fixture.id)?;
        if !names.insert(fixture.id.to_ascii_lowercase()) {
            return Err(CliError::cli_other_error(
                "duplicate proof fixture catalog identifier",
            ));
        }
    }
    Ok(())
}

pub(in super::super) fn negative_destination(bundle: &Path, id: &str) -> Result<PathBuf, CliError> {
    validate_id(id)?;
    let destination = bundle.join("negatives/catalog").join(id);
    for path in [
        bundle.to_owned(),
        bundle.join("negatives"),
        bundle.join("negatives/catalog"),
        destination.clone(),
    ] {
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                return Err(CliError::cli_other_error(
                    "proof fixture output requires regular directories",
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(destination)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn untrusted_catalog_ids_cannot_delete_outside_the_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        let marker = victim.join("keep");
        std::fs::write(&marker, b"keep").unwrap();
        for id in ["../victim", "/victim", "a/b", "a\\b", ".", "..", ""] {
            assert!(negative_destination(dir.path(), id).is_err());
        }
        assert!(negative_destination(dir.path(), victim.to_str().unwrap()).is_err());
        assert_eq!(std::fs::read(marker).unwrap(), b"keep");
        assert_eq!(
            negative_destination(dir.path(), "valid-fixture_1").unwrap(),
            dir.path().join("negatives/catalog/valid-fixture_1")
        );
        let descriptor = serde_json::json!({"id":"same","kind":"negative-transaction-passport","path":"safe","description":"test"});
        let catalog = serde_json::json!({"schema":super::super::PROOF_FIXTURE_CATALOG_SCHEMA,"fixtures":[descriptor.clone(),descriptor]});
        assert!(super::super::parse_fixture_catalog(
            &serde_json::to_vec(&catalog).unwrap(),
            "test"
        )
        .err()
        .unwrap()
        .to_string()
        .contains("duplicate"));
    }
    #[cfg(unix)]
    #[test]
    fn output_parent_symlinks_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(dir.path(), dir.path().join("negatives")).unwrap();
        assert!(negative_destination(dir.path(), "safe-id")
            .unwrap_err()
            .to_string()
            .contains("regular directories"));
    }
}

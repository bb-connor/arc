use super::{read_utf8_json_file, RelaySigningKeyDocument};
use crate::CliError;
use chio_core::crypto::Keypair;
use serde::de::DeserializeOwned;
use std::path::Path;

pub(crate) fn read_json_documents_from_dir<T: DeserializeOwned>(
    dir: &Path,
    _label: &str,
    schema: &str,
) -> Result<Vec<T>, CliError> {
    let mut budget = crate::input::collection::Budget::default();
    let paths = crate::input::collection::directory(dir, &mut budget).map_err(|source| {
        CliError::with_public_source(
            &chio_errors::_generated::error_codes::CLI_IO,
            "Chio relay event directory read failed",
            source,
        )
    })?;
    let mut documents = Vec::new();
    for path in paths {
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let bytes = budget.read(&path)?;
        let json = std::str::from_utf8(&bytes).map_err(|source| {
            CliError::with_source(&chio_errors::_generated::error_codes::CLI_JSON, source)
        })?;
        let value: serde_json::Value = crate::input::text(json)?;
        if value.get("schema").and_then(|schema| schema.as_str()) != Some(schema) {
            continue;
        }
        let document = crate::input::project(value)?;
        documents.push(document);
    }
    Ok(documents)
}

pub(crate) fn read_json_file<T: DeserializeOwned>(path: &Path, label: &str) -> Result<T, CliError> {
    crate::input::text(&read_utf8_json_file(path, label)?)
        .map_err(|error| CliError::cli_other_error(format!("{label} {}: {error}", path.display())))
}

pub(crate) fn load_relay_signing_key(path: &Path) -> Result<(String, Keypair), CliError> {
    let document: RelaySigningKeyDocument =
        crate::input::private::read(path).map_err(|source| {
            CliError::with_public_source(
                &chio_errors::_generated::error_codes::CLI_OTHER,
                "Chio relay signing key rejected",
                source,
            )
        })?;
    if document.kernel_id.trim().is_empty() {
        return Err(CliError::cli_other_error(
            "Chio relay signing key: kernel id is empty",
        ));
    }
    let keypair = Keypair::from_seed_hex(document.seed_hex.as_str()).map_err(|source| {
        CliError::with_source(&chio_errors::_generated::error_codes::CLI_OTHER, source)
    })?;
    Ok((document.kernel_id, keypair))
}

pub(crate) fn unix_now_ms() -> Result<u64, CliError> {
    crate::input::time::millis()
}

#[cfg(test)]
mod tests {
    use super::{load_relay_signing_key, read_json_documents_from_dir};

    #[test]
    fn directory_read_errors_use_chio_boundary_label() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let missing = tempdir.path().join("missing");
        let error = read_json_documents_from_dir::<serde_json::Value>(
            &missing,
            "relay event",
            "chio.pheromone.relay-event.v1",
        )
        .expect_err("missing directory should fail")
        .report()
        .message;

        assert!(error.contains("Chio relay event dir"));
    }

    #[test]
    fn relay_signing_key_errors_use_chio_boundary_label() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let key_path = tempdir.path().join("relay-key.json");
        std::fs::write(&key_path, "{}").expect("write key");

        let error = match load_relay_signing_key(&key_path) {
            Ok(_) => panic!("malformed key should fail"),
            Err(error) => error.report().message,
        };

        assert!(error.contains("Chio relay signing key"));
    }
}

//! Real private config custody and original JSON refusal causes.
use super::*;
use crate::adapter_cause_tests::{assert_public_error, native_cause, TestResult, PRIVATE};
use chio_core_types::canonical::UntrustedJsonError;
use std::os::unix::fs::PermissionsExt;

fn private_config(bytes: &[u8]) -> TestResult<(tempfile::TempDir, PathBuf)> {
    let directory = crate::private_tempdir()?;
    let path = directory.path().join(format!("{PRIVATE}.json"));
    std::fs::write(&path, bytes)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok((directory, path))
}

#[test]
fn broker_native_cause_repository_missing_config() -> TestResult {
    let (directory, path) = private_config(b"{}")?;
    std::fs::remove_file(&path)?;
    let error = RepositoryHttpsConfig::load(&path)
        .err()
        .ok_or("missing private config loaded")?;
    assert_public_error(&error, "authorization_denied");
    assert_eq!(
        native_cause::<std::io::Error>(&error)?.kind(),
        std::io::ErrorKind::NotFound
    );
    let error = error.redacted();
    assert_public_error(&error, "authorization_denied");
    assert_eq!(
        native_cause::<std::io::Error>(&error)?.kind(),
        std::io::ErrorKind::NotFound
    );
    assert!(!directory.path().join("effects").exists());
    Ok(())
}

fn parse_failure(bytes: &[u8], native_code: &str, malformed: bool) -> TestResult {
    let (directory, path) = private_config(bytes)?;
    let error = RepositoryHttpsConfig::load(&path)
        .err()
        .ok_or("invalid private config loaded")?;
    assert_public_error(&error, "authorization_denied");
    assert_eq!(
        native_cause::<UntrustedJsonError>(&error)?.code(),
        native_code
    );
    if malformed {
        // decode_signed exposes its original core CanonicalJson failure; that
        // parser interface has already converted the Serde error to a String.
        assert!(matches!(
            native_cause::<chio_core_types::Error>(&error)?,
            chio_core_types::Error::CanonicalJson(_)
        ));
    }
    let error = error.redacted();
    assert_public_error(&error, "authorization_denied");
    assert_eq!(
        native_cause::<UntrustedJsonError>(&error)?.code(),
        native_code
    );
    if malformed {
        assert!(matches!(
            native_cause::<chio_core_types::Error>(&error)?,
            chio_core_types::Error::CanonicalJson(_)
        ));
    }
    assert!(!directory.path().join("effects").exists());
    Ok(())
}

#[test]
fn broker_native_cause_repository_malformed_config() -> TestResult {
    parse_failure(
        br#"{"private-adapter-credential":"#,
        "urn:chio:error:attest:signed-json-invalid-input",
        true,
    )
}

#[test]
fn broker_native_cause_repository_duplicate_config() -> TestResult {
    parse_failure(
        br#"{"private-adapter-credential":1,"private-adapter-credential":2}"#,
        "urn:chio:error:attest:signed-json-invalid-input",
        false,
    )
}

#[test]
fn broker_native_cause_repository_non_utf8_config() -> TestResult {
    parse_failure(&[0xff], "urn:chio:error:attest:signed-json-not-utf8", false)
}

#[test]
fn broker_native_cause_repository_healthy_config_control() -> TestResult {
    let bytes = br#"{"schema":"chio.repository-https-adapter.v1","bind":"127.0.0.1:12345","certificate_der":[1,2],"private_key_file":"/host/private-key","bearer_file":"/host/bearer","repository":{"executable":"/host/repository","executable_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"/host/state","configuration_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","timeout_ms":1000}}"#;
    let (directory, path) = private_config(bytes)?;
    let loaded = RepositoryHttpsConfig::load(&path)?;
    assert_eq!(loaded.schema, "chio.repository-https-adapter.v1");
    assert_eq!(loaded.repository.timeout_ms, 1000);
    assert_eq!(
        loaded.repository.executable,
        PathBuf::from("/host/repository")
    );
    assert!(!directory.path().join("effects").exists());
    Ok(())
}

#[test]
fn broker_native_cause_repository_insecure_file_control() -> TestResult {
    let (_directory, path) = private_config(b"{}")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    let error = RepositoryHttpsConfig::load(&path)
        .err()
        .ok_or("nonprivate config loaded")?;
    assert_public_error(&error, "authorization_denied");
    Ok(())
}

use super::*;

use chio_test_support::prelude::*;
use std::ffi::OsString;

const CREDENTIAL: &str = "chio-authority-seed";

fn credential() -> KeyRef {
    KeyRef::SystemdCredential {
        name: CREDENTIAL.to_owned(),
    }
}

fn custody_error(error: CliError) -> KeyCustodyError {
    match error {
        CliError::KeyCustody(error) => error,
        other => panic!("expected a key custody refusal, got {other}"),
    }
}

/// A credentials directory holding one private seed for `credential()`.
fn credentials_directory() -> (tempfile::TempDir, Keypair) {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let keypair = Keypair::generate();
    crate::write_authority_seed_file(&directory.path().join(CREDENTIAL), &keypair).test_unwrap();
    (directory, keypair)
}

#[test]
fn parses_credential_references_and_seed_paths() {
    assert_eq!(
        KeyRef::parse(Path::new("credential:chio-authority_seed.v1")).test_unwrap(),
        KeyRef::SystemdCredential {
            name: "chio-authority_seed.v1".to_owned()
        }
    );
    for path in [
        "/etc/chio/authority.seed",
        "authority.seed",
        "./credential:x",
    ] {
        assert_eq!(
            KeyRef::parse(Path::new(path)).test_unwrap(),
            KeyRef::File(PathBuf::from(path))
        );
    }
    let too_long = format!("credential:{}", "a".repeat(CREDENTIAL_NAME_MAX_BYTES + 1));
    for raw in [
        "credential:",
        "credential:.",
        "credential:..",
        "credential:../escape",
        "credential:a/b",
        "credential:a b",
        "credential:caf\u{e9}",
        too_long.as_str(),
    ] {
        assert_eq!(
            KeyRef::parse(Path::new(raw)),
            Err(KeyCustodyError::InvalidCredentialName),
            "{raw:?}"
        );
    }
}

#[test]
fn custody_policy_values_parse_strictly() {
    assert_eq!(
        CustodyPolicy::from_value(None),
        Ok(CustodyPolicy::AllowFiles)
    );
    assert_eq!(
        CustodyPolicy::from_value(Some(OsStr::new("development"))),
        Ok(CustodyPolicy::AllowFiles)
    );
    assert_eq!(
        CustodyPolicy::from_value(Some(OsStr::new("required"))),
        Ok(CustodyPolicy::RequireOsCustody)
    );
    for value in ["", "Required", "required ", "requried", "off"] {
        assert_eq!(
            CustodyPolicy::from_value(Some(OsStr::new(value))),
            Err(KeyCustodyError::InvalidPolicy),
            "{value:?}"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;

        assert_eq!(
            CustodyPolicy::from_value(Some(OsStr::from_bytes(b"requir\xffed"))),
            Err(KeyCustodyError::InvalidPolicy)
        );
    }
}

#[test]
fn required_custody_refuses_seed_files_before_reading_them() {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let seed = directory.path().join("authority.seed");
    crate::write_authority_seed_file(&seed, &Keypair::generate()).test_unwrap();

    for path in [seed, directory.path().join("missing.seed")] {
        let error =
            load_authority_keypair(&KeyRef::File(path), CustodyPolicy::RequireOsCustody, None)
                .test_unwrap_err();
        assert_eq!(custody_error(error), KeyCustodyError::NotOsCustody);
    }
}

#[test]
fn credential_without_credentials_directory_fails_closed() {
    for policy in [CustodyPolicy::AllowFiles, CustodyPolicy::RequireOsCustody] {
        let error = load_authority_keypair(&credential(), policy, None).test_unwrap_err();
        assert_eq!(
            custody_error(error),
            KeyCustodyError::CredentialsDirectoryUnset
        );
    }
    let relative = OsString::from("credentials");
    let error = load_authority_keypair(
        &credential(),
        CustodyPolicy::RequireOsCustody,
        Some(&relative),
    )
    .test_unwrap_err();
    assert_eq!(
        custody_error(error),
        KeyCustodyError::CredentialsDirectoryNotAbsolute
    );
}

#[test]
fn required_custody_loads_a_private_credential() {
    let (directory, expected) = credentials_directory();

    let loaded = load_authority_keypair(
        &credential(),
        CustodyPolicy::RequireOsCustody,
        Some(directory.path().as_os_str()),
    )
    .test_unwrap();

    assert_eq!(loaded.public_key(), expected.public_key());
}

#[test]
fn missing_credential_is_not_provisioned() {
    let directory = chio_test_support::private_tempdir().test_unwrap();

    let error = load_authority_keypair(
        &credential(),
        CustodyPolicy::RequireOsCustody,
        Some(directory.path().as_os_str()),
    )
    .test_unwrap_err();

    assert!(matches!(error, CliError::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound));
    assert!(!directory.path().join(CREDENTIAL).exists());
}

#[cfg(unix)]
#[test]
fn credential_outside_private_or_systemd_custody_is_refused() {
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    let (directory, _) = credentials_directory();
    let path = directory.path().join(CREDENTIAL);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).test_unwrap();
    let error = load_authority_keypair(
        &credential(),
        CustodyPolicy::RequireOsCustody,
        Some(directory.path().as_os_str()),
    )
    .test_unwrap_err();
    assert_eq!(
        custody_error(error),
        KeyCustodyError::CredentialCustodyRefused
    );

    let (linked, _) = credentials_directory();
    let target = linked.path().join("target.seed");
    fs::rename(linked.path().join(CREDENTIAL), &target).test_unwrap();
    symlink(&target, linked.path().join(CREDENTIAL)).test_unwrap();
    let error = load_authority_keypair(
        &credential(),
        CustodyPolicy::RequireOsCustody,
        Some(linked.path().as_os_str()),
    )
    .test_unwrap_err();
    assert_eq!(
        custody_error(error),
        KeyCustodyError::CredentialCustodyRefused
    );
}

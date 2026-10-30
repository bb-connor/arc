use super::*;

use chio_test_support::prelude::*;

const CREDENTIAL: &str = "chio-authority-seed";
const CREDENTIAL_REF: &str = "credential:chio-authority-seed";

fn custody(policy: CustodyPolicy, credentials_directory: Option<&Path>) -> SeedCustody {
    SeedCustody {
        policy,
        credentials_directory: credentials_directory.map(|path| path.as_os_str().to_owned()),
    }
}

fn custody_error(error: CliError) -> KeyCustodyError {
    match error {
        CliError::KeyCustody(error) => error,
        other => panic!("expected a key custody refusal, got {other}"),
    }
}

/// A credentials directory holding one private seed for `CREDENTIAL_REF`.
fn credentials_directory() -> (tempfile::TempDir, Keypair) {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let keypair = Keypair::generate();
    write_authority_seed_file(&directory.path().join(CREDENTIAL), &keypair).test_unwrap();
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
fn required_custody_refuses_seed_files_at_every_entry_point() {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let present = directory.path().join("authority.seed");
    let missing = directory.path().join("missing.seed");
    write_authority_seed_file(&present, &Keypair::generate()).test_unwrap();
    let before = fs::read(&present).test_unwrap();
    let required = custody(CustodyPolicy::RequireOsCustody, Some(directory.path()));

    for path in [&present, &missing] {
        let refusals = [
            required.load_existing(path).map(|_| ()),
            required.public_key(path).map(|_| ()),
            required.load_or_create(path).map(|_| ()),
            required.rotate(path).map(|_| ()),
            required.writable_seed_file(path).map(|_| ()),
        ];
        for refusal in refusals {
            assert_eq!(
                custody_error(refusal.test_unwrap_err()),
                KeyCustodyError::NotOsCustody
            );
        }
    }
    assert_eq!(fs::read(&present).test_unwrap(), before);
    assert!(!missing.exists());
}

#[test]
fn credential_references_are_never_written() {
    let (directory, expected) = credentials_directory();
    let seed = directory.path().join(CREDENTIAL);
    let before = fs::read(&seed).test_unwrap();
    let credential = Path::new(CREDENTIAL_REF);

    for policy in [CustodyPolicy::AllowFiles, CustodyPolicy::RequireOsCustody] {
        let custody = custody(policy, Some(directory.path()));
        assert_eq!(
            custody_error(custody.rotate(credential).test_unwrap_err()),
            KeyCustodyError::ReadOnlyCustody
        );
        assert_eq!(
            custody_error(custody.writable_seed_file(credential).test_unwrap_err()),
            KeyCustodyError::ReadOnlyCustody
        );
    }
    assert_eq!(fs::read(&seed).test_unwrap(), before);
    assert!(!credential.exists());

    let development = custody(CustodyPolicy::AllowFiles, Some(directory.path()));
    assert_eq!(
        development
            .load_or_create(credential)
            .test_unwrap()
            .public_key(),
        expected.public_key()
    );
    assert_eq!(
        development.public_key(credential).test_unwrap(),
        Some(expected.public_key())
    );
    assert_eq!(fs::read(&seed).test_unwrap(), before);
}

#[test]
fn missing_credential_is_never_provisioned() {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let development = custody(CustodyPolicy::AllowFiles, Some(directory.path()));
    let credential = Path::new(CREDENTIAL_REF);

    for error in [
        development
            .load_existing(credential)
            .map(|_| ())
            .test_unwrap_err(),
        development
            .load_or_create(credential)
            .map(|_| ())
            .test_unwrap_err(),
        development
            .public_key(credential)
            .map(|_| ())
            .test_unwrap_err(),
    ] {
        assert!(matches!(error, CliError::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound));
    }
    assert!(!directory.path().join(CREDENTIAL).exists());
    assert!(!credential.exists());
}

#[test]
fn credential_without_credentials_directory_fails_closed() {
    let credential = Path::new(CREDENTIAL_REF);
    for policy in [CustodyPolicy::AllowFiles, CustodyPolicy::RequireOsCustody] {
        let unset = custody(policy, None);
        for error in [
            unset
                .load_existing(credential)
                .map(|_| ())
                .test_unwrap_err(),
            unset
                .load_or_create(credential)
                .map(|_| ())
                .test_unwrap_err(),
            unset.public_key(credential).map(|_| ()).test_unwrap_err(),
        ] {
            assert_eq!(
                custody_error(error),
                KeyCustodyError::CredentialsDirectoryUnset
            );
        }
    }
    let relative = custody(
        CustodyPolicy::RequireOsCustody,
        Some(Path::new("credentials")),
    );
    assert_eq!(
        custody_error(relative.load_existing(credential).test_unwrap_err()),
        KeyCustodyError::CredentialsDirectoryNotAbsolute
    );
}

#[test]
fn development_custody_loads_a_private_credential() {
    let (directory, expected) = credentials_directory();

    let loaded = custody(CustodyPolicy::AllowFiles, Some(directory.path()))
        .load_existing(Path::new(CREDENTIAL_REF))
        .test_unwrap();

    assert_eq!(loaded.public_key(), expected.public_key());
}

/// A private file outside systemd's read-only credential mount is a plaintext
/// seed, so required custody refuses it.
#[test]
fn required_custody_refuses_a_private_credential_off_the_systemd_mount() {
    let (directory, _) = credentials_directory();

    let error = custody(CustodyPolicy::RequireOsCustody, Some(directory.path()))
        .load_existing(Path::new(CREDENTIAL_REF))
        .test_unwrap_err();

    assert_eq!(
        custody_error(error),
        KeyCustodyError::CredentialCustodyRefused
    );
}

#[cfg(unix)]
#[test]
fn credential_outside_private_or_systemd_custody_is_refused() {
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    let credential = Path::new(CREDENTIAL_REF);
    let (directory, _) = credentials_directory();
    fs::set_permissions(
        directory.path().join(CREDENTIAL),
        fs::Permissions::from_mode(0o644),
    )
    .test_unwrap();
    let error = custody(CustodyPolicy::AllowFiles, Some(directory.path()))
        .load_existing(credential)
        .test_unwrap_err();
    assert_eq!(
        custody_error(error),
        KeyCustodyError::CredentialCustodyRefused
    );

    let (linked, _) = credentials_directory();
    let target = linked.path().join("target.seed");
    fs::rename(linked.path().join(CREDENTIAL), &target).test_unwrap();
    symlink(&target, linked.path().join(CREDENTIAL)).test_unwrap();
    let error = custody(CustodyPolicy::AllowFiles, Some(linked.path()))
        .load_existing(credential)
        .test_unwrap_err();
    assert_eq!(
        custody_error(error),
        KeyCustodyError::CredentialCustodyRefused
    );
}

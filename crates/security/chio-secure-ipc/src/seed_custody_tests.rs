use super::*;

use chio_test_support::prelude::*;

const CREDENTIAL: &str = "chio-authority-seed";
const CREDENTIAL_REF: &str = "credential:chio-authority-seed";
const SEED: &[u8] = b"seed bytes\n";

fn source(policy: CustodyPolicy, credentials_directory: Option<&Path>) -> OsSeedSource {
    OsSeedSource::new(
        policy,
        credentials_directory.map(|path| path.as_os_str().to_owned()),
    )
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.mode(0o600);
    }
    let mut file = options.open(path).test_unwrap();
    std::io::Write::write_all(&mut file, bytes).test_unwrap();
}

/// A credentials directory holding one private seed for `CREDENTIAL_REF`.
fn credentials_directory() -> tempfile::TempDir {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    write_private(&directory.path().join(CREDENTIAL), SEED);
    directory
}

fn credential() -> KeyRef {
    KeyRef::SystemdCredential {
        name: CREDENTIAL.to_owned(),
    }
}

fn custody_error(error: SeedReadError) -> KeyCustodyError {
    match error {
        SeedReadError::Custody(error) => error,
        other => panic!("expected a key custody refusal, got {other}"),
    }
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
fn required_custody_refuses_seed_files() {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let seed = directory.path().join("authority.seed");
    write_private(&seed, SEED);
    let required = source(CustodyPolicy::RequireOsCustody, Some(directory.path()));

    assert_eq!(required.resolve(&seed), Err(KeyCustodyError::NotOsCustody));
    assert_eq!(
        custody_error(
            required
                .read_seed(&KeyRef::File(seed), 64)
                .map(|_| ())
                .test_unwrap_err()
        ),
        KeyCustodyError::NotOsCustody
    );
}

#[test]
fn credential_without_credentials_directory_fails_closed() {
    for policy in [CustodyPolicy::AllowFiles, CustodyPolicy::RequireOsCustody] {
        let error = source(policy, None)
            .read_seed(&credential(), 64)
            .map(|_| ())
            .test_unwrap_err();
        assert_eq!(
            custody_error(error),
            KeyCustodyError::CredentialsDirectoryUnset
        );
    }
    let error = source(
        CustodyPolicy::RequireOsCustody,
        Some(Path::new("credentials")),
    )
    .read_seed(&credential(), 64)
    .map(|_| ())
    .test_unwrap_err();
    assert_eq!(
        custody_error(error),
        KeyCustodyError::CredentialsDirectoryNotAbsolute
    );
}

#[test]
fn development_custody_reads_a_private_credential() {
    let directory = credentials_directory();
    let source = source(CustodyPolicy::AllowFiles, Some(directory.path()));

    let key = source.resolve(Path::new(CREDENTIAL_REF)).test_unwrap();

    assert_eq!(key, credential());
    assert_eq!(source.read_seed(&key, 64).test_unwrap().as_slice(), SEED);
}

/// A private file outside systemd's read-only credential mount is a plaintext
/// seed, so required custody refuses it.
#[test]
fn required_custody_refuses_a_private_credential_off_the_systemd_mount() {
    let directory = credentials_directory();

    let error = source(CustodyPolicy::RequireOsCustody, Some(directory.path()))
        .read_seed(&credential(), 64)
        .map(|_| ())
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

    let directory = credentials_directory();
    fs::set_permissions(
        directory.path().join(CREDENTIAL),
        fs::Permissions::from_mode(0o644),
    )
    .test_unwrap();
    let error = source(CustodyPolicy::AllowFiles, Some(directory.path()))
        .read_seed(&credential(), 64)
        .map(|_| ())
        .test_unwrap_err();
    assert_eq!(
        custody_error(error),
        KeyCustodyError::CredentialCustodyRefused
    );

    let linked = credentials_directory();
    let target = linked.path().join("target.seed");
    fs::rename(linked.path().join(CREDENTIAL), &target).test_unwrap();
    symlink(&target, linked.path().join(CREDENTIAL)).test_unwrap();
    let error = source(CustodyPolicy::AllowFiles, Some(linked.path()))
        .read_seed(&credential(), 64)
        .map(|_| ())
        .test_unwrap_err();
    assert_eq!(
        custody_error(error),
        KeyCustodyError::CredentialCustodyRefused
    );
}

#[cfg(unix)]
#[test]
fn private_file_reads_refuse_permissive_or_linked_files() {
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    let directory = chio_test_support::private_tempdir().test_unwrap();
    let seed = directory.path().join("authority.seed");
    let alias = directory.path().join("authority-alias.seed");
    write_private(&seed, SEED);
    assert_eq!(read_private_file(&seed, 64).test_unwrap().as_slice(), SEED);

    fs::set_permissions(&seed, fs::Permissions::from_mode(0o644)).test_unwrap();
    let error = read_private_file(&seed, 64).map(|_| ()).test_unwrap_err();
    assert!(error.to_string().contains("mode 0600"), "{error}");

    fs::set_permissions(&seed, fs::Permissions::from_mode(0o600)).test_unwrap();
    symlink(&seed, &alias).test_unwrap();
    let error = read_private_file(&alias, 64).map(|_| ()).test_unwrap_err();
    assert!(error.to_string().contains("regular file"), "{error}");
}

#[test]
fn private_file_reads_are_bounded_and_missing_files_are_not_found() {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let seed = directory.path().join("authority.seed");
    write_private(&seed, SEED);

    let error = read_private_file(&seed, SEED.len() - 1)
        .map(|_| ())
        .test_unwrap_err();
    assert!(error.to_string().contains("byte limit"), "{error}");

    let missing = read_private_file(&directory.path().join("missing.seed"), 64)
        .map(|_| ())
        .test_unwrap_err();
    assert!(
        matches!(missing, SeedReadError::Io(ref error) if error.kind() == std::io::ErrorKind::NotFound)
    );
}

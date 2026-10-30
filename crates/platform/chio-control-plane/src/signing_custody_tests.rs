use super::*;

use chio_secure_ipc::seed_custody::CustodyPolicy;
use chio_test_support::prelude::*;
use std::fs;

const CREDENTIAL: &str = "chio-authority-seed";
const CREDENTIAL_REF: &str = "credential:chio-authority-seed";

fn custody(
    policy: CustodyPolicy,
    credentials_directory: Option<&Path>,
) -> AuthoritySeeds<OsSeedSource> {
    AuthoritySeeds {
        source: OsSeedSource::new(
            policy,
            credentials_directory.map(|path| path.as_os_str().to_owned()),
        ),
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

#[test]
fn missing_seed_file_reads_as_absent_and_is_created_private() {
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let seed = directory.path().join("authority.seed");
    let development = custody(CustodyPolicy::AllowFiles, None);

    assert_eq!(development.public_key(&seed).test_unwrap(), None);
    let created = development.load_or_create(&seed).test_unwrap();
    assert_eq!(
        development.public_key(&seed).test_unwrap(),
        Some(created.public_key())
    );
    assert_eq!(
        development.load_or_create(&seed).test_unwrap().public_key(),
        created.public_key()
    );
}

#[cfg(unix)]
#[test]
fn plain_seed_reads_refuse_permissive_or_linked_seed_files() {
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    let directory = chio_test_support::private_tempdir().test_unwrap();
    let seed = directory.path().join("authority.seed");
    let alias = directory.path().join("authority-alias.seed");
    write_authority_seed_file(&seed, &Keypair::generate()).test_unwrap();
    let development = custody(CustodyPolicy::AllowFiles, None);

    fs::set_permissions(&seed, fs::Permissions::from_mode(0o644)).test_unwrap();
    let before = fs::read(&seed).test_unwrap();
    for error in [
        development.public_key(&seed).map(|_| ()).test_unwrap_err(),
        development
            .load_or_create(&seed)
            .map(|_| ())
            .test_unwrap_err(),
    ] {
        assert!(error.to_string().contains("mode 0600"), "{error}");
    }
    assert_eq!(fs::read(&seed).test_unwrap(), before);

    fs::set_permissions(&seed, fs::Permissions::from_mode(0o600)).test_unwrap();
    symlink(&seed, &alias).test_unwrap();
    for error in [
        development.public_key(&alias).map(|_| ()).test_unwrap_err(),
        development
            .load_or_create(&alias)
            .map(|_| ())
            .test_unwrap_err(),
    ] {
        assert!(error.to_string().contains("regular file"), "{error}");
    }
    assert_eq!(fs::read(&seed).test_unwrap(), before);
}

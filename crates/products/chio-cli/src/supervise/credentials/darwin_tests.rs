//! Exercise the actual credential loaders with native descriptor ACLs.

use super::{load_credential, CredentialError};
use crate::supervise::{DescriptorCredentialBinding, DescriptorCredentials};
use std::{
    fs::{OpenOptions, Permissions},
    io::{self, Write},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::Command,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    _directory: tempfile::TempDir,
    directory: PathBuf,
}

impl Fixture {
    fn new(entries: &[&str]) -> io::Result<Self> {
        let directory = tempfile::Builder::new()
            .permissions(Permissions::from_mode(0o700))
            .tempdir()?;
        let canonical = directory.path().canonicalize()?;
        let path = canonical.join("service-token");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(b"synthetic-credential\n")?;
        for entry in entries {
            install_acl(&path, entry)?;
        }
        let metadata = file.metadata()?;
        assert_eq!(metadata.mode() & 0o077, 0);
        assert_eq!(metadata.nlink(), 1);
        Ok(Self {
            _directory: directory,
            directory: canonical,
        })
    }

    fn descriptors(&self) -> Result<DescriptorCredentials, CredentialError> {
        let binding: DescriptorCredentialBinding = "service-token-fd=service-token".parse()?;
        DescriptorCredentials::load(Some(&self.directory), &[binding])
    }
}

fn install_acl(path: &Path, entry: &str) -> io::Result<()> {
    let result = Command::new("/bin/chmod")
        .args(["+a", entry])
        .arg(path)
        .output()?;
    if !result.status.success() {
        return Err(io::Error::other("native credential ACL fixture failed"));
    }
    Ok(())
}

#[test]
fn environment_loader_refuses_native_allow_acl() -> TestResult {
    for entry in ["everyone allow read", "everyone allow write"] {
        let fixture = Fixture::new(&[entry])?;
        assert!(matches!(
            load_credential(&fixture.directory, "service-token"),
            Err(CredentialError::Exposed(_))
        ));
    }
    Ok(())
}

#[test]
fn descriptor_loader_refuses_native_allow_acl() -> TestResult {
    for entry in ["everyone allow read", "everyone allow write"] {
        let fixture = Fixture::new(&[entry])?;
        assert!(matches!(
            fixture.descriptors(),
            Err(CredentialError::Unreadable { .. })
        ));
    }
    Ok(())
}

#[test]
fn environment_loader_accepts_native_deny_only_acl() -> TestResult {
    let fixture = Fixture::new(&["everyone deny write"])?;
    assert_eq!(
        load_credential(&fixture.directory, "service-token")?,
        "synthetic-credential"
    );
    Ok(())
}

#[test]
fn descriptor_loader_accepts_native_deny_only_acl() -> TestResult {
    let fixture = Fixture::new(&["everyone deny write"])?;
    fixture.descriptors()?;
    Ok(())
}

#[test]
fn environment_loader_refuses_allow_after_deny_acl() -> TestResult {
    let fixture = Fixture::new(&["everyone deny write", "everyone allow read"])?;
    assert!(matches!(
        load_credential(&fixture.directory, "service-token"),
        Err(CredentialError::Exposed(_))
    ));
    Ok(())
}

#[test]
fn descriptor_loader_refuses_allow_after_deny_acl() -> TestResult {
    let fixture = Fixture::new(&["everyone deny write", "everyone allow read"])?;
    assert!(matches!(
        fixture.descriptors(),
        Err(CredentialError::Unreadable { .. })
    ));
    Ok(())
}

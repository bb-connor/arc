//! Native ACL controls at persistent mobile-challenge custody boundaries.

use super::{MobileChallengeStore, SqliteMobileChallengeStore};
use std::{
    fs::{OpenOptions, Permissions},
    io,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::Command,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    _directory: tempfile::TempDir,
    directory: PathBuf,
    database: PathBuf,
}

impl Fixture {
    fn new() -> io::Result<Self> {
        let directory = tempfile::Builder::new()
            .permissions(Permissions::from_mode(0o700))
            .tempdir()?;
        let canonical = directory.path().canonicalize()?;
        let database = canonical.join("mobile-challenges.sqlite3");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&database)?;
        Ok(Self {
            _directory: directory,
            directory: canonical,
            database,
        })
    }

    fn open(&self) -> Result<SqliteMobileChallengeStore, super::MobileChallengeError> {
        SqliteMobileChallengeStore::open(&self.database)
    }
}

fn install_acl(path: &Path, entry: &str) -> io::Result<()> {
    let result = Command::new("/bin/chmod")
        .args(["+a", entry])
        .arg(path)
        .output()?;
    if !result.status.success() {
        return Err(io::Error::other("native mobile-store ACL fixture failed"));
    }
    assert_eq!(std::fs::metadata(path)?.mode() & 0o077, 0);
    Ok(())
}

#[test]
fn mobile_store_refuses_native_database_allow_acl() -> TestResult {
    for entry in ["everyone allow read", "everyone allow write"] {
        let fixture = Fixture::new()?;
        install_acl(&fixture.database, entry)?;
        assert!(fixture.open().is_err());
    }
    Ok(())
}

#[test]
fn mobile_store_refuses_native_parent_allow_acl() -> TestResult {
    let fixture = Fixture::new()?;
    install_acl(&fixture.directory, "everyone allow write")?;
    assert!(fixture.open().is_err());
    Ok(())
}

#[test]
fn mobile_store_rechecks_database_acl_before_mutation() -> TestResult {
    let fixture = Fixture::new()?;
    let store = fixture.open()?;
    assert_eq!(store.gc_expired(1_000)?, 0);
    install_acl(&fixture.database, "everyone allow write")?;
    assert!(store.gc_expired(1_001).is_err());
    Ok(())
}

#[test]
fn mobile_store_rechecks_parent_acl_before_mutation() -> TestResult {
    let fixture = Fixture::new()?;
    let store = fixture.open()?;
    assert_eq!(store.gc_expired(1_000)?, 0);
    install_acl(&fixture.directory, "everyone allow write")?;
    assert!(store.gc_expired(1_001).is_err());
    Ok(())
}

#[test]
fn mobile_store_accepts_private_native_custody() -> TestResult {
    let fixture = Fixture::new()?;
    assert_eq!(fixture.open()?.gc_expired(1_000)?, 0);
    Ok(())
}

#[test]
fn mobile_store_accepts_native_deny_execute_file_acl() -> TestResult {
    let fixture = Fixture::new()?;
    install_acl(&fixture.database, "everyone deny execute")?;
    assert_eq!(fixture.open()?.gc_expired(1_000)?, 0);
    Ok(())
}

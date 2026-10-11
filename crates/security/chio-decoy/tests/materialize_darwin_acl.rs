#![cfg(target_vendor = "apple")]

use chio_decoy::materialize::{
    FileMaterializer, MaterializationIdentity, MaterializationRequest, MaterializeError,
    OwnershipKey,
};
use std::{
    fs::{self, Permissions},
    io,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::Command,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    root: tempfile::TempDir,
    private: PathBuf,
}

impl Fixture {
    fn new(entries: &[&str]) -> io::Result<Self> {
        let root = tempfile::Builder::new()
            .permissions(Permissions::from_mode(0o700))
            .tempdir()?;
        let private = root.path().canonicalize()?.join("private");
        fs::create_dir(&private)?;
        fs::set_permissions(&private, Permissions::from_mode(0o700))?;
        let fixture = Self { root, private };
        for entry in entries {
            let result = Command::new("/bin/chmod")
                .args(["+a", entry])
                .arg(&fixture.private)
                .output()?;
            if !result.status.success() {
                return Err(io::Error::other(
                    "native decoy directory ACL fixture failed",
                ));
            }
        }
        assert_eq!(
            fs::metadata(&fixture.private)?.permissions().mode() & 0o7777,
            0o700
        );
        Ok(fixture)
    }

    fn materialize(&self) -> Result<(), MaterializeError> {
        let materializer =
            FileMaterializer::open(self.root.path(), OwnershipKey::from_bytes([23_u8; 32]))?;
        let identity = MaterializationIdentity {
            operation_id: "native-directory-custody".to_owned(),
            tenant_id: "native-test-tenant".to_owned(),
            artifact_id: "native-test-artifact".to_owned(),
            version_hash: [7_u8; 32],
        };
        let request = MaterializationRequest {
            identity: &identity,
            relative_path: Path::new("private/decoy.txt"),
            content: b"synthetic native directory custody fixture",
        };
        let first = materializer.materialize(&request)?;
        let replay = materializer.materialize(&request)?;
        assert_eq!(first, replay);
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Clear this owned fixture's deny entries before TempDir removes it.
        let _ = Command::new("/bin/chmod")
            .arg("-N")
            .arg(&self.private)
            .output();
    }
}

#[test]
fn materialization_refuses_private_directory_with_allow_acl() -> TestResult {
    let fixture = Fixture::new(&["everyone allow add_file"])?;
    assert!(matches!(
        fixture.materialize(),
        Err(MaterializeError::MetadataMismatch)
    ));
    assert!(!fixture.private.join("decoy.txt").exists());
    Ok(())
}

#[test]
fn materialization_refuses_allow_acl_after_deny_entry() -> TestResult {
    let fixture = Fixture::new(&["everyone deny delete", "everyone allow add_file"])?;
    assert!(matches!(
        fixture.materialize(),
        Err(MaterializeError::MetadataMismatch)
    ));
    assert!(!fixture.private.join("decoy.txt").exists());
    Ok(())
}

#[test]
fn materialization_accepts_private_directory_with_deny_only_acl() -> TestResult {
    let fixture = Fixture::new(&["everyone deny delete"])?;
    fixture.materialize()?;
    Ok(())
}

#[test]
fn materialization_accepts_private_directory_without_acl() -> TestResult {
    let fixture = Fixture::new(&[])?;
    fixture.materialize()?;
    Ok(())
}

//! Native controls at the resume-key file reader.

use super::read_resume_hmac_keyring_file;
use std::{
    fs::{OpenOptions, Permissions},
    io::{self, Write},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
    process::Command,
};

fn with_key_file(entries: &[&str], check: impl FnOnce(&Path)) -> io::Result<()> {
    let directory = tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o700))
        .tempdir()?;
    let path = directory.path().canonicalize()?.join("resume-key.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(b"synthetic-resume-key")?;
    for entry in entries {
        let result = Command::new("/bin/chmod")
            .args(["+a", entry])
            .arg(&path)
            .output()?;
        if !result.status.success() {
            return Err(io::Error::other("native resume-key ACL fixture failed"));
        }
    }
    let metadata = file.metadata()?;
    assert_eq!(metadata.mode() & 0o077, 0);
    assert_eq!(metadata.nlink(), 1);
    check(&path);
    Ok(())
}

#[test]
fn resume_reader_refuses_native_allow_acl() -> io::Result<()> {
    for entry in ["everyone allow read", "everyone allow write"] {
        with_key_file(&[entry], |path| {
            assert!(read_resume_hmac_keyring_file(path).is_err());
        })?;
    }
    Ok(())
}

#[test]
fn resume_reader_refuses_allow_after_deny_acl() -> io::Result<()> {
    with_key_file(&["everyone deny write", "everyone allow read"], |path| {
        assert!(read_resume_hmac_keyring_file(path).is_err());
    })
}

#[test]
fn resume_reader_accepts_native_deny_only_acl() -> io::Result<()> {
    with_key_file(&["everyone deny write"], |path| {
        let result = read_resume_hmac_keyring_file(path);
        assert!(matches!(result, Ok(bytes) if bytes.as_slice() == b"synthetic-resume-key"));
    })
}

#[test]
fn resume_reader_accepts_private_file_without_acl() -> io::Result<()> {
    with_key_file(&[], |path| {
        let result = read_resume_hmac_keyring_file(path);
        assert!(matches!(result, Ok(bytes) if bytes.as_slice() == b"synthetic-resume-key"));
    })
}

use crate::{
    darwin_descriptor_grants_extended_acl_authority, validate_custody_sensitive_file_security,
    validate_trusted_file_security, KeyringError,
};
use std::{
    fs::{File, OpenOptions, Permissions},
    io,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
    process::{Command, Stdio},
};

fn private_file() -> io::Result<(tempfile::TempDir, File, std::path::PathBuf)> {
    let directory = tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o700))
        .tempdir()?;
    let path = std::fs::canonicalize(directory.path())?.join("acl-custody.sqlite3");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    Ok((directory, file, path))
}

fn install_acl(path: &Path, ace: &str) -> io::Result<()> {
    let status = Command::new("/bin/chmod")
        .args(["+a", ace])
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(io::Error::other("could not install native Darwin test ACL"));
    }
    Ok(())
}

#[test]
fn native_darwin_allow_acl_rejects_private_file_custody() -> io::Result<()> {
    let (_directory, file, path) = private_file()?;
    install_acl(&path, "everyone allow write")?;
    let metadata = file.metadata()?;
    assert_eq!(metadata.permissions().mode() & 0o077, 0);
    assert!(darwin_descriptor_grants_extended_acl_authority(&file).map_err(io::Error::other)?);
    assert!(matches!(
        validate_trusted_file_security(&file, &metadata),
        Err(KeyringError::StateInvariant(_))
    ));
    assert!(matches!(
        validate_custody_sensitive_file_security(&file, &metadata),
        Err(KeyringError::StateInvariant(_))
    ));
    Ok(())
}

#[test]
fn native_darwin_deny_only_acl_accepts_private_file_custody() -> io::Result<()> {
    let (_directory, file, path) = private_file()?;
    install_acl(&path, "everyone deny write")?;
    let metadata = file.metadata()?;
    assert_eq!(metadata.permissions().mode() & 0o077, 0);
    assert!(!darwin_descriptor_grants_extended_acl_authority(&file).map_err(io::Error::other)?);
    validate_trusted_file_security(&file, &metadata).map_err(io::Error::other)?;
    validate_custody_sensitive_file_security(&file, &metadata).map_err(io::Error::other)?;
    Ok(())
}

#[test]
fn native_darwin_allow_after_deny_acl_rejects_private_file_custody() -> io::Result<()> {
    let (_directory, file, path) = private_file()?;
    install_acl(&path, "everyone deny write")?;
    install_acl(&path, "everyone allow read")?;
    let metadata = file.metadata()?;
    assert_eq!(metadata.permissions().mode() & 0o077, 0);
    assert!(darwin_descriptor_grants_extended_acl_authority(&file).map_err(io::Error::other)?);
    assert!(matches!(
        validate_trusted_file_security(&file, &metadata),
        Err(KeyringError::StateInvariant(_))
    ));
    Ok(())
}

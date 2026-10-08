use std::os::unix::fs::PermissionsExt as _;

#[cfg(any(target_os = "linux", target_os = "android"))]
use super::open_trusted_unix_directory_chain;
use super::{
    open_durable_sqlite_file, validate_custody_sensitive_file_security_values,
    validate_trusted_file_security_values, validate_trusted_parent_security,
};

fn private_tempdir() -> std::io::Result<tempfile::TempDir> {
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
}

const TRUSTED_FILE_REFUSAL: &str =
    "key-log database file must have trusted ownership, no untrusted write access or ACL, and one hard link";
const CUSTODY_FILE_REFUSAL: &str =
    "custody-sensitive input must have trusted ownership, no untrusted write access or ACL, and one hard link";
const RETAINED_IDENTITY_REFUSAL: &str =
    "key-log database descriptor identity changed or is hard-linked";
const TRUSTED_PARENT_REFUSAL: &str =
    "key-log database parent must be owned by the service or root and grant no untrusted write access or extended ACL";

fn refused_by(result: crate::Result<impl Sized>, rule: &str) -> bool {
    matches!(
        result,
        Err(crate::KeyringError::StateInvariant(message)) if message == rule
    )
}

#[test]
fn retained_sqlite_descriptor_detects_hardlinks_and_path_rebinding() -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let directory = private_tempdir()?;
    let trusted_directory = std::fs::canonicalize(directory.path())?;
    let database = trusted_directory.join("key-log.sqlite3");
    let hardlink = trusted_directory.join("key-log-hardlink.sqlite3");
    let displaced = trusted_directory.join("key-log-displaced.sqlite3");
    let retained =
        open_durable_sqlite_file(&database, true, true).map_err(std::io::Error::other)?;

    std::fs::hard_link(&database, &hardlink)?;
    assert!(refused_by(retained.validate(), RETAINED_IDENTITY_REFUSAL));
    std::fs::remove_file(&hardlink)?;
    assert!(retained.validate().is_ok());

    std::fs::rename(&database, &displaced)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&database)?;
    assert!(refused_by(retained.validate(), RETAINED_IDENTITY_REFUSAL));
    Ok(())
}

#[test]
fn trusted_parent_policy_rejects_foreign_owner_acl_and_mode_writes() {
    assert!(validate_trusted_parent_security(501, 501, 0o700, false, false).is_ok());
    assert!(validate_trusted_parent_security(0, 501, 0o755, false, false).is_ok());
    assert!(validate_trusted_parent_security(0, 501, 0o1777, false, true).is_ok());
    assert!(refused_by(
        validate_trusted_parent_security(502, 501, 0o700, false, false),
        TRUSTED_PARENT_REFUSAL
    ));
    assert!(refused_by(
        validate_trusted_parent_security(501, 501, 0o720, false, false),
        TRUSTED_PARENT_REFUSAL
    ));
    assert!(refused_by(
        validate_trusted_parent_security(501, 501, 0o1777, false, false),
        TRUSTED_PARENT_REFUSAL
    ));
    assert!(refused_by(
        validate_trusted_parent_security(501, 501, 0o700, true, false),
        TRUSTED_PARENT_REFUSAL
    ));
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn trusted_parent_policy_requires_private_child_below_system_temp_directory() -> std::io::Result<()>
{
    let directory = private_tempdir()?;
    let trusted_directory = std::fs::canonicalize(directory.path())?;

    let result = open_trusted_unix_directory_chain(&trusted_directory);
    assert!(result.is_ok(), "{result:?}");
    assert!(refused_by(
        open_trusted_unix_directory_chain(std::path::Path::new("/tmp")),
        TRUSTED_PARENT_REFUSAL
    ));
    Ok(())
}

#[test]
fn trusted_file_policy_rejects_group_or_world_access_foreign_owner_links_and_acl() {
    assert!(validate_trusted_file_security_values(501, 501, 0o100600, 1, false).is_ok());
    assert!(validate_trusted_file_security_values(501, 501, 0o100400, 1, false).is_ok());
    assert!(validate_trusted_file_security_values(0, 501, 0o100600, 1, false).is_ok());
    for mode in [
        0o100640, 0o100620, 0o100610, 0o100604, 0o100602, 0o100601, 0o100644, 0o100666,
    ] {
        assert!(
            refused_by(
                validate_trusted_file_security_values(501, 501, mode, 1, false),
                TRUSTED_FILE_REFUSAL
            ),
            "mode {mode:o} must be refused"
        );
    }
    assert!(refused_by(
        validate_trusted_file_security_values(502, 501, 0o100600, 1, false),
        TRUSTED_FILE_REFUSAL
    ));
    assert!(refused_by(
        validate_trusted_file_security_values(501, 501, 0o100600, 2, false),
        TRUSTED_FILE_REFUSAL
    ));
    assert!(refused_by(
        validate_trusted_file_security_values(501, 501, 0o100600, 1, true),
        TRUSTED_FILE_REFUSAL
    ));
}

#[test]
fn retained_sqlite_descriptor_rejects_group_or_world_access_to_the_database_file(
) -> std::io::Result<()> {
    let directory = private_tempdir()?;
    let trusted_directory = std::fs::canonicalize(directory.path())?;
    let database = trusted_directory.join("key-log.sqlite3");
    let retained =
        open_durable_sqlite_file(&database, true, true).map_err(std::io::Error::other)?;
    assert!(retained.validate().is_ok());

    for mode in [0o640, 0o604] {
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(mode))?;
        assert!(
            refused_by(retained.validate(), TRUSTED_FILE_REFUSAL),
            "mode {mode:o} must be refused"
        );
    }
    std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600))?;
    assert!(retained.validate().is_ok());
    Ok(())
}

#[test]
fn custody_sensitive_file_policy_rejects_foreign_owner_writes_links_and_acl() {
    assert!(validate_custody_sensitive_file_security_values(501, 501, 0o644, 1, false).is_ok());
    assert!(validate_custody_sensitive_file_security_values(0, 501, 0o644, 1, false).is_ok());
    assert!(refused_by(
        validate_custody_sensitive_file_security_values(502, 501, 0o644, 1, false),
        CUSTODY_FILE_REFUSAL
    ));
    assert!(refused_by(
        validate_custody_sensitive_file_security_values(501, 501, 0o664, 1, false),
        CUSTODY_FILE_REFUSAL
    ));
    assert!(refused_by(
        validate_custody_sensitive_file_security_values(501, 501, 0o644, 2, false),
        CUSTODY_FILE_REFUSAL
    ));
    assert!(refused_by(
        validate_custody_sensitive_file_security_values(501, 501, 0o644, 1, true),
        CUSTODY_FILE_REFUSAL
    ));
}

#[cfg(target_vendor = "apple")]
#[test]
fn apple_acl_policy_accepts_deny_only_and_rejects_allow_entries() {
    use super::apple_acl_tag_grants_additional_authority;

    assert!(!apple_acl_tag_grants_additional_authority(2));
    assert!(apple_acl_tag_grants_additional_authority(1));
    assert!(apple_acl_tag_grants_additional_authority(99));
}

#[cfg(target_vendor = "apple")]
#[test]
fn apple_acl_inspection_accepts_a_file_without_an_extended_acl() -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let directory = private_tempdir()?;
    let trusted_directory = std::fs::canonicalize(directory.path())?;
    let path = trusted_directory.join("no-extended-acl.sqlite3");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    let grants_additional_authority =
        super::trusted_file_has_extended_acl(&file).map_err(std::io::Error::other)?;
    assert!(!grants_additional_authority);
    Ok(())
}

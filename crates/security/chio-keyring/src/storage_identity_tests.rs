use std::os::unix::fs::PermissionsExt as _;

#[cfg(any(target_os = "linux", target_os = "android"))]
use super::open_trusted_unix_directory_chain;
use super::{
    open_durable_sqlite_file, validate_custody_sensitive_file_security_values,
    validate_trusted_file_security_values, validate_trusted_parent_security,
};

const PARENT_REFUSED: &str = "key-log database parent must be owned";
const FILE_REFUSED: &str = "key-log database file must have trusted ownership";
const CUSTODY_REFUSED: &str = "custody-sensitive input must have trusted ownership";
const IDENTITY_REFUSED: &str = "identity changed or is hard-linked";

fn assert_state_invariant<T: std::fmt::Debug>(result: crate::Result<T>, expected: &str) {
    match result {
        Err(crate::KeyringError::StateInvariant(message)) => assert!(
            message.contains(expected),
            "expected a refusal naming `{expected}`, got `{message}`"
        ),
        other => panic!("expected a refusal naming `{expected}`, got {other:?}"),
    }
}

fn private_tempdir() -> std::io::Result<tempfile::TempDir> {
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
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
    assert_state_invariant(retained.validate(), IDENTITY_REFUSED);
    std::fs::remove_file(&hardlink)?;
    assert!(retained.validate().is_ok());

    std::fs::rename(&database, &displaced)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&database)?;
    assert_state_invariant(retained.validate(), IDENTITY_REFUSED);
    Ok(())
}

#[test]
fn trusted_parent_policy_rejects_foreign_owner_acl_and_mode_writes() {
    assert!(validate_trusted_parent_security(501, 501, 0o700, false, false).is_ok());
    assert!(validate_trusted_parent_security(0, 501, 0o755, false, false).is_ok());
    assert!(validate_trusted_parent_security(0, 501, 0o1777, false, true).is_ok());
    assert_state_invariant(
        validate_trusted_parent_security(502, 501, 0o700, false, false),
        PARENT_REFUSED,
    );
    assert_state_invariant(
        validate_trusted_parent_security(501, 501, 0o720, false, false),
        PARENT_REFUSED,
    );
    assert_state_invariant(
        validate_trusted_parent_security(501, 501, 0o1777, false, false),
        PARENT_REFUSED,
    );
    assert_state_invariant(
        validate_trusted_parent_security(501, 501, 0o700, true, false),
        PARENT_REFUSED,
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn trusted_parent_policy_requires_private_child_below_system_temp_directory() -> std::io::Result<()>
{
    let directory = private_tempdir()?;
    let trusted_directory = std::fs::canonicalize(directory.path())?;

    let result = open_trusted_unix_directory_chain(&trusted_directory);
    assert!(result.is_ok(), "{result:?}");
    assert_state_invariant(
        open_trusted_unix_directory_chain(std::path::Path::new("/tmp")),
        PARENT_REFUSED,
    );
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
        assert_state_invariant(
            validate_trusted_file_security_values(501, 501, mode, 1, false),
            FILE_REFUSED,
        );
    }
    assert_state_invariant(
        validate_trusted_file_security_values(502, 501, 0o100600, 1, false),
        FILE_REFUSED,
    );
    assert_state_invariant(
        validate_trusted_file_security_values(501, 501, 0o100600, 2, false),
        FILE_REFUSED,
    );
    assert_state_invariant(
        validate_trusted_file_security_values(501, 501, 0o100600, 1, true),
        FILE_REFUSED,
    );
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
        assert_state_invariant(retained.validate(), FILE_REFUSED);
    }
    std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600))?;
    assert!(retained.validate().is_ok());
    Ok(())
}

#[test]
fn custody_sensitive_file_policy_rejects_foreign_owner_writes_links_and_acl() {
    assert!(validate_custody_sensitive_file_security_values(501, 501, 0o644, 1, false).is_ok());
    assert!(validate_custody_sensitive_file_security_values(0, 501, 0o644, 1, false).is_ok());
    assert_state_invariant(
        validate_custody_sensitive_file_security_values(502, 501, 0o644, 1, false),
        CUSTODY_REFUSED,
    );
    assert_state_invariant(
        validate_custody_sensitive_file_security_values(501, 501, 0o664, 1, false),
        CUSTODY_REFUSED,
    );
    assert_state_invariant(
        validate_custody_sensitive_file_security_values(501, 501, 0o644, 2, false),
        CUSTODY_REFUSED,
    );
    assert_state_invariant(
        validate_custody_sensitive_file_security_values(501, 501, 0o644, 1, true),
        CUSTODY_REFUSED,
    );
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

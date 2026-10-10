//! File custody controls exercise the public authority API before seed writes.
#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use chio_store_sqlite::SqliteCapabilityAuthority;
use rusqlite::Connection;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn private_directory() -> std::io::Result<tempfile::TempDir> {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    Ok(directory)
}

fn mode(path: &Path) -> std::io::Result<u32> {
    Ok(fs::symlink_metadata(path)?.mode() & 0o7777)
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[test]
fn creates_private_authority_under_standard_umask() -> TestResult {
    const CHILD_ROOT: &str = "CHIO_AUTHORITY_CUSTODY_UMASK_ROOT";
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let path = PathBuf::from(root).join("private/authority.db");
        let authority = SqliteCapabilityAuthority::open(&path)?;
        let keeper = Connection::open(&path)?;
        let _: i64 = keeper.query_row("SELECT generation FROM authority_state", [], |row| {
            row.get(0)
        })?;
        authority.rotate()?;
        assert_eq!(mode(path.parent().ok_or("missing parent")?)?, 0o700);
        for file in [&path, &sidecar(&path, "-wal"), &sidecar(&path, "-shm")] {
            assert_eq!(mode(file)?, 0o600, "insecure mode: {}", file.display());
            assert_eq!(fs::symlink_metadata(file)?.nlink(), 1);
        }
        let key = authority.local_keypair()?.public_key();
        drop(keeper);
        drop(authority);
        let reopened = SqliteCapabilityAuthority::open(&path)?;
        assert_eq!(reopened.local_keypair()?.public_key(), key);
        assert_eq!(reopened.status()?.generation, 2);
        return Ok(());
    }
    let root = private_directory()?;
    let output = Command::new("sh")
        .args(["-c", "umask 022\nexec \"$@\"", "chio-authority-custody"])
        .arg(std::env::current_exe()?)
        .args([
            "--exact",
            "creates_private_authority_under_standard_umask",
            "--nocapture",
        ])
        .env(CHILD_ROOT, root.path())
        .output()?;
    assert!(
        output.status.success(),
        "umask 022 subprocess failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn refuses_loose_database_before_writing_a_seed() -> TestResult {
    for permission in [0o644, 0o640, 0o660, 0o666] {
        let root = private_directory()?;
        let path = root.path().join("authority.db");
        fs::write(&path, [])?;
        fs::set_permissions(&path, fs::Permissions::from_mode(permission))?;
        assert!(
            SqliteCapabilityAuthority::open(&path).is_err(),
            "accepted database mode {permission:o}"
        );
        assert!(fs::read(&path)?.is_empty(), "refusal wrote a seed");
        assert_eq!(mode(&path)?, permission, "refusal repaired custody");
        assert!(!sidecar(&path, "-wal").exists());
        assert!(!sidecar(&path, "-shm").exists());
    }
    Ok(())
}

#[test]
fn refuses_unsafe_parent_before_creating_a_database() -> TestResult {
    for permission in [0o755, 0o750, 0o770, 0o777] {
        let root = private_directory()?;
        let parent = root.path().join("custody");
        fs::create_dir(&parent)?;
        fs::set_permissions(&parent, fs::Permissions::from_mode(permission))?;
        let path = parent.join("authority.db");
        assert!(
            SqliteCapabilityAuthority::open(&path).is_err(),
            "accepted parent mode {permission:o}"
        );
        assert!(!path.exists(), "refusal created a database");
        assert_eq!(mode(&parent)?, permission);
    }
    Ok(())
}

#[test]
fn refuses_replaceable_ancestor_even_when_immediate_parent_is_private() -> TestResult {
    let root = private_directory()?;
    let ancestor = root.path().join("replaceable");
    let parent = ancestor.join("private");
    fs::create_dir_all(&parent)?;
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o777))?;
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?;
    let path = parent.join("authority.db");
    assert!(SqliteCapabilityAuthority::open(&path).is_err());
    assert!(!path.exists());
    Ok(())
}

#[test]
fn refuses_symlinked_database_or_parent_without_touching_target() -> TestResult {
    let root = private_directory()?;
    let target = root.path().join("target.db");
    private_file(&target, &[])?;
    let alias = root.path().join("alias.db");
    symlink(&target, &alias)?;
    assert!(SqliteCapabilityAuthority::open(&alias).is_err());
    assert!(fs::read(&target)?.is_empty());

    let parent_alias = root.path().join("alias-directory");
    symlink(root.path(), &parent_alias)?;
    assert!(SqliteCapabilityAuthority::open(parent_alias.join("new.db")).is_err());
    assert!(!root.path().join("new.db").exists());
    Ok(())
}

#[test]
fn refuses_hardlinked_database_without_writing_a_seed() -> TestResult {
    let root = private_directory()?;
    let path = root.path().join("authority.db");
    private_file(&path, &[])?;
    fs::hard_link(&path, root.path().join("alias.db"))?;
    assert!(SqliteCapabilityAuthority::open(&path).is_err());
    assert!(fs::read(&path)?.is_empty());
    Ok(())
}

#[test]
fn refuses_unsafe_sidecars_before_bootstrap() -> TestResult {
    for suffix in ["-wal", "-shm", "-journal"] {
        for symlinked in [false, true] {
            let root = private_directory()?;
            let path = root.path().join("authority.db");
            private_file(&path, &[])?;
            let sidecar_path = sidecar(&path, suffix);
            let target = root.path().join("target");
            private_file(&target, b"untouched")?;
            if symlinked {
                symlink(&target, &sidecar_path)?;
            } else {
                fs::write(&sidecar_path, b"untouched")?;
                fs::set_permissions(&sidecar_path, fs::Permissions::from_mode(0o644))?;
            }
            assert!(
                SqliteCapabilityAuthority::open(&path).is_err(),
                "accepted unsafe {suffix}, symlinked={symlinked}"
            );
            assert!(fs::read(&path)?.is_empty(), "refusal wrote a seed");
            assert_eq!(fs::read(&sidecar_path)?, b"untouched");
            assert_eq!(fs::read(&target)?, b"untouched");
        }
    }
    Ok(())
}

#[test]
fn detects_database_replacement_before_read_or_rotation() -> TestResult {
    let root = private_directory()?;
    let path = root.path().join("authority.db");
    let authority = SqliteCapabilityAuthority::open(&path)?;
    fs::rename(&path, root.path().join("original.db"))?;
    private_file(&path, &[])?;
    assert!(authority.status().is_err());
    assert!(authority.local_keypair().is_err());
    assert!(authority.rotate().is_err());
    assert!(
        fs::read(&path)?.is_empty(),
        "rotation wrote into replacement"
    );
    Ok(())
}

#[test]
fn rejects_custody_drift_before_reopen_rotation_or_replication() -> TestResult {
    let root = private_directory()?;
    let path = root.path().join("authority.db");
    let authority = SqliteCapabilityAuthority::open(&path)?;
    authority.initialize_replication("custody-test")?;
    let original = fs::read(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    assert!(SqliteCapabilityAuthority::open(&path).is_err());
    assert!(authority.rotate().is_err());
    assert!(authority.signed_snapshot().is_err());
    assert_eq!(fs::read(&path)?, original);
    Ok(())
}

#[test]
fn decodes_local_sqlite_uri_once_and_keeps_backing_store_private() -> TestResult {
    let root = private_directory()?;
    let uri = format!(
        "file://localhost{}/private%20dir/authority%23one.db?mode=rwc&cache=private",
        root.path().display()
    );
    let authority = SqliteCapabilityAuthority::open(&uri)?;
    let path = root.path().join("private dir/authority#one.db");
    assert_eq!(mode(path.parent().ok_or("missing parent")?)?, 0o700);
    assert_eq!(mode(&path)?, 0o600);
    let reopened = SqliteCapabilityAuthority::open(&path)?;
    assert_eq!(
        reopened.local_keypair()?.public_key(),
        authority.local_keypair()?.public_key()
    );
    Ok(())
}

#[test]
fn rejects_ambiguous_or_unsafe_sqlite_uri_options_without_files() -> TestResult {
    for suffix in [
        "?mode=memory",
        "?mode=ro",
        "?mode=rwc&mode=ro",
        "?nolock=1",
        "?immutable=1",
        "?vfs=unix-none",
        "?mode=rwc&unknown=value",
        "?%6eolock=1",
        "?mode=rwc%00",
        "?mode=%GG",
        "#fragment",
    ] {
        let root = private_directory()?;
        let path = root.path().join("authority.db");
        let uri = format!("file:{}{suffix}", path.display());
        assert!(
            SqliteCapabilityAuthority::open(&uri).is_err(),
            "accepted {suffix}"
        );
        assert!(!path.exists(), "rejected URI created a database: {suffix}");
    }
    for uri in [
        ":memory:",
        "file::memory:",
        "file:",
        "file://remote/authority.db",
    ] {
        assert!(SqliteCapabilityAuthority::open(uri).is_err());
    }
    Ok(())
}

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn temporary_for(directory: &Path, nonce: &str) -> PathBuf {
    directory.join(format!(".registry.json.{nonce}.tmp"))
}

fn fail_at(stage: ReplaceStage) -> impl Fn(ReplaceStage) -> std::io::Result<()> {
    move |at| {
        if at == stage {
            Err(std::io::Error::other(format!("injected {stage:?} failure")))
        } else {
            Ok(())
        }
    }
}

#[test]
fn a_held_lock_makes_a_second_writer_busy_until_it_is_dropped() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("registry.json");
    let held = RegistryFile::lock(&path)?;
    assert!(matches!(
        RegistryFile::lock(&path),
        Err(RegistryFileError::Busy)
    ));
    drop(held);
    let file = RegistryFile::lock(&path)?;
    file.replace(b"{}")?;
    assert_eq!(fs::read(&path)?, b"{}");
    Ok(())
}

#[test]
fn directory_aliases_of_one_registry_share_its_lock() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let real = directory.path().join("real");
    let path = real.join("registry.json");
    fs::create_dir_all(real.join("nested"))?;
    symlink(&real, directory.path().join("alias"))?;
    let aliases = [
        directory.path().join("alias").join("registry.json"),
        real.join("nested").join("..").join("registry.json"),
        real.join(".").join("registry.json"),
    ];
    for alias in aliases {
        let held = RegistryFile::lock(&alias)?;
        assert_eq!(
            held.destination(),
            fs::canonicalize(&real)?.join("registry.json").as_path()
        );
        assert!(
            matches!(RegistryFile::lock(&path), Err(RegistryFileError::Busy)),
            "{}",
            alias.display()
        );
    }
    Ok(())
}

#[test]
fn a_registry_path_that_is_a_symbolic_link_is_refused() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let target = directory.path().join("target.json");
    fs::write(&target, b"keep")?;
    let link = directory.path().join("registry.json");
    symlink(&target, &link)?;

    assert!(matches!(
        RegistryFile::lock(&link),
        Err(RegistryFileError::SymlinkDestination(destination))
            if destination == fs::canonicalize(directory.path())?.join("registry.json")
    ));
    assert_eq!(fs::read(&target)?, b"keep");
    assert!(fs::symlink_metadata(&link)?.file_type().is_symlink());
    Ok(())
}

#[test]
fn a_lock_file_that_is_shared_or_linked_is_refused() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("registry.json");
    drop(RegistryFile::lock(&path)?);
    let lock = directory.path().join(".registry.json.lock");
    assert!(lock.is_file(), "the writer lock lives beside the registry");

    fs::set_permissions(&lock, fs::Permissions::from_mode(0o644))?;
    assert!(matches!(
        RegistryFile::lock(&path),
        Err(RegistryFileError::LockNotPrivate(_))
    ));
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600))?;

    let second_name = directory.path().join("second-name.lock");
    fs::hard_link(&lock, &second_name)?;
    assert!(matches!(
        RegistryFile::lock(&path),
        Err(RegistryFileError::LockNotPrivate(_))
    ));
    fs::remove_file(&second_name)?;

    drop(RegistryFile::lock(&path)?);
    Ok(())
}

#[test]
fn exclusive_create_refuses_a_planted_temporary_and_leaves_it_alone() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("registry.json");
    fs::write(&path, b"before")?;
    let victim = directory.path().join("victim");
    fs::write(&victim, b"keep")?;
    let planted = temporary_for(directory.path(), "fixed");
    for plant_symlink in [true, false] {
        if plant_symlink {
            symlink(&victim, &planted)?;
        } else {
            fs::remove_file(&planted)?;
            fs::write(&planted, b"other writer")?;
        }
        let error = replace_with(&path, b"after", "fixed", &|_| Ok(()))
            .err()
            .ok_or("a planted temporary name must be refused")?;
        assert!(matches!(
            error,
            RegistryFileError::Io(ref io) if io.kind() == std::io::ErrorKind::AlreadyExists
        ));
        assert_eq!(fs::read(&victim)?, b"keep");
        assert_eq!(fs::read(&path)?, b"before");
    }
    Ok(())
}

#[test]
fn failure_before_the_rename_preserves_prior_bytes_and_removes_its_temporary() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("registry.json");
    fs::write(&path, b"before")?;

    let error = replace_with(
        &path,
        b"after",
        "fixed",
        &fail_at(ReplaceStage::BeforeRename),
    )
    .err()
    .ok_or("injected pre-commit failure must surface")?;
    assert!(matches!(
        error,
        RegistryFileError::Io(ref io) if io.to_string() == "injected BeforeRename failure"
    ));
    assert_eq!(fs::read(&path)?, b"before");
    assert!(!temporary_for(directory.path(), "fixed").exists());
    Ok(())
}

#[test]
fn failure_after_the_rename_is_distinct_and_the_new_file_is_in_place() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("registry.json");
    fs::write(&path, b"before")?;

    let error = replace_with(
        &path,
        b"after",
        "fixed",
        &fail_at(ReplaceStage::DirectorySync),
    )
    .err()
    .ok_or("injected post-commit failure must surface")?;
    assert!(matches!(
        error,
        RegistryFileError::PersistedWithoutDurability(ref io)
            if io.to_string() == "injected DirectorySync failure"
    ));
    assert_eq!(fs::read(&path)?, b"after");
    assert!(!temporary_for(directory.path(), "fixed").exists());
    Ok(())
}

#[test]
fn a_replacement_is_never_more_permissive_than_the_file_it_replaces() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("registry.json");
    let file = RegistryFile::lock(&path)?;
    file.replace(b"first")?;
    assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
    file.replace(b"second")?;
    assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o400);
    assert_eq!(fs::read(&path)?, b"second");
    Ok(())
}

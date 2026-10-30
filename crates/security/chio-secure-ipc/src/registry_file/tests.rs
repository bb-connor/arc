#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write as _};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::{Command, Stdio};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Names the registry the child-process holder locks.
const HOLDER_REGISTRY: &str = "CHIO_TEST_REGISTRY_FILE_LOCK_HOLDER";
const HOLDER_READY: &str = "registry-file-lock-held";

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

/// Run as a child process by `another_process_holding_the_lock_makes_writers_busy`:
/// takes the lock of the registry named by the environment, reports it, and
/// holds it until its standard input closes. Without that environment it
/// does nothing.
#[test]
fn registry_lock_holder_for_child_process() -> TestResult {
    let Some(path) = std::env::var_os(HOLDER_REGISTRY) else {
        return Ok(());
    };
    let _lock = RegistryFile::lock(Path::new(&path))?;
    let mut stdout = std::io::stdout();
    writeln!(stdout, "{HOLDER_READY}")?;
    stdout.flush()?;
    let mut released = Vec::new();
    std::io::stdin().read_to_end(&mut released)?;
    Ok(())
}

#[test]
fn another_process_holding_the_lock_makes_writers_busy() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("registry.json");
    let mut holder = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "registry_file::tests::registry_lock_holder_for_child_process",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(HOLDER_REGISTRY, &path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let output = holder.stdout.take().ok_or("holder stdout")?;
    let mut lines = BufReader::new(output).lines();
    loop {
        let line = lines
            .next()
            .ok_or("the holder exited before taking the lock")??;
        if line.contains(HOLDER_READY) {
            break;
        }
    }

    assert!(matches!(
        RegistryFile::lock(&path),
        Err(RegistryFileError::Busy)
    ));

    drop(holder.stdin.take());
    assert!(holder.wait()?.success());
    RegistryFile::lock(&path)?.replace(b"{}")?;
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
fn exclusive_create_refuses_a_symlink_planted_at_the_attempted_temporary() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("registry.json");
    fs::write(&path, b"before")?;
    let victim = directory.path().join("victim");
    fs::write(&victim, b"keep")?;
    let planted = temporary_for(directory.path(), "fixed");
    symlink(&victim, &planted)?;

    let error = replace_with(&path, b"after", "fixed", &|_| Ok(()))
        .err()
        .ok_or("a planted temporary name must be refused")?;
    assert!(matches!(
        error,
        RegistryFileError::Io(ref io) if io.kind() == std::io::ErrorKind::AlreadyExists
    ));
    assert_eq!(fs::read(&victim)?, b"keep");
    assert_eq!(fs::read_link(&planted)?, victim);
    assert_eq!(fs::read(&path)?, b"before");
    Ok(())
}

#[test]
fn exclusive_create_refuses_a_regular_file_collision_without_clobbering_it() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("registry.json");
    fs::write(&path, b"before")?;
    let planted = temporary_for(directory.path(), "fixed");
    fs::write(&planted, b"other writer")?;

    let error = replace_with(&path, b"after", "fixed", &|_| Ok(()))
        .err()
        .ok_or("a colliding temporary name must be refused")?;
    assert!(matches!(
        error,
        RegistryFileError::Io(ref io) if io.kind() == std::io::ErrorKind::AlreadyExists
    ));
    assert_eq!(fs::read(&planted)?, b"other writer");
    assert_eq!(fs::read(&path)?, b"before");
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn rename_failure_removes_only_its_own_temporary_and_reports_the_os_error() -> TestResult {
    const EISDIR: i32 = 21;
    let directory = chio_test_support::private_tempdir()?;
    // A directory at the destination makes the rename fail regardless of the
    // caller's privileges.
    let path = directory.path().join("registry.json");
    fs::create_dir(&path)?;
    fs::write(path.join("occupant"), b"keep")?;
    let bystander = temporary_for(directory.path(), "bystander");
    fs::write(&bystander, b"other writer")?;

    let error = replace_with(&path, b"after", "fixed", &|_| Ok(()))
        .err()
        .ok_or("renaming a file over a directory must fail")?;
    assert!(matches!(
        error,
        RegistryFileError::Io(ref io) if io.raw_os_error() == Some(EISDIR)
    ));
    assert_eq!(fs::read(path.join("occupant"))?, b"keep");
    assert_eq!(fs::read(&bystander)?, b"other writer");
    assert_eq!(fs::read_dir(directory.path())?.count(), 2);
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

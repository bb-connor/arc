use super::*;
use std::fs;
use std::os::unix::fs::{symlink, DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[path = "tests/cursor.rs"]
mod cursor;
#[path = "tests/location.rs"]
mod location;
#[path = "tests/provision.rs"]
mod provision;
#[path = "tests/reclaim.rs"]
mod reclaim;
fn require_refusal<T>(
    outcome: Result<T, SnapshotBackingError>,
    expected: SnapshotCustodyRefusal,
) -> TestResult {
    match outcome {
        Err(SnapshotBackingError::Refused(actual)) => assert_eq!(actual, expected),
        Err(actual) => return Err(format!("expected {expected:?}, got {actual:?}").into()),
        Ok(_) => return Err(format!("expected {expected:?}, but custody was accepted").into()),
    }
    Ok(())
}

fn require_unusable<T>(
    outcome: Result<T, SnapshotBackingError>,
    expected: SnapshotLocationRefusal,
) -> TestResult {
    match outcome {
        Err(SnapshotBackingError::Unusable(actual)) => assert_eq!(actual, expected),
        Err(actual) => return Err(format!("expected {expected:?}, got {actual:?}").into()),
        Ok(_) => return Err(format!("expected {expected:?}, but the location was used").into()),
    }
    Ok(())
}

/// Diagnostic bound on waiting for another thread or process. A regression
/// fails the test instead of hanging it; it is not a timing claim.
const HANG: std::time::Duration = std::time::Duration::from_secs(300);

/// A child process that is killed and reaped if the test ends first.
struct Reaped(std::process::Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Wait, within `HANG`, until `child` prints a line containing `marker`.
fn await_marker(child: &mut std::process::Child, marker: &'static str) -> TestResult {
    use std::io::BufRead;
    let stdout = child.stdout.take().ok_or("the child has no piped stdout")?;
    let (seen, seen_by) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let found = std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
            .any(|line| line.contains(marker));
        let _ = seen.send(found);
    });
    match seen_by.recv_timeout(HANG) {
        Ok(true) => Ok(()),
        Ok(false) => Err(format!("the child exited before printing {marker}").into()),
        Err(_) => Err(format!("the child did not print {marker} within the hang bound").into()),
    }
}

/// Run `command` to completion within `HANG`; otherwise kill and reap it.
fn output_within_hang(
    command: &mut std::process::Command,
) -> Result<(std::process::ExitStatus, String, String), Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut child = Reaped(
        command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?,
    );
    let drain = |stream: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut text = String::new();
            if let Some(mut stream) = stream {
                let _ = stream.read_to_string(&mut text);
            }
            text
        })
    };
    let stdout = drain(
        child
            .0
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let stderr = drain(
        child
            .0
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let deadline = std::time::Instant::now() + HANG;
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            return Err("the child did not finish within the hang bound".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let stdout = stdout.join().map_err(|_| "stdout reader panicked")?;
    let stderr = stderr.join().map_err(|_| "stderr reader panicked")?;
    Ok((status, stdout, stderr))
}

/// Retry, a bounded number of times, while another provisioner holds the
/// shared `/tmp` parent lock, as the service retries a contended attempt.
fn uncontended<T>(
    mut attempt: impl FnMut() -> Result<T, SnapshotBackingError>,
) -> Result<T, SnapshotBackingError> {
    for _ in 0..100_000 {
        match attempt() {
            Err(SnapshotBackingError::Unusable(SnapshotLocationRefusal::Contended)) => {
                std::thread::yield_now();
            }
            outcome => return outcome,
        }
    }
    attempt()
}

fn private_tempdir() -> std::io::Result<tempfile::TempDir> {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
}

/// Entries of `base` other than its snapshot parent, plus the snapshot
/// directories inside that parent. Empty once every custody is released.
fn custody_entries(base: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let parent = base.join(super::reclaim::PARENT_NAME);
    let mut entries = Vec::new();
    for entry in fs::read_dir(base)? {
        let path = entry?.path();
        if path != parent {
            entries.push(path);
        }
    }
    if parent.exists() {
        for entry in fs::read_dir(&parent)? {
            let path = entry?.path();
            if path.file_name() != Some(std::ffi::OsStr::new("reclaim-cursor")) {
                entries.push(path);
            }
        }
    }
    entries.sort();
    Ok(entries)
}

#[test]
fn creates_real_sqlite_backing_with_checked_borrows() -> TestResult {
    let mut backing = uncontended(|| SnapshotFileBacking::create(None))?;
    backing.checked_connection_mut()?.execute_batch(
        "CREATE TABLE probe(value TEXT NOT NULL); INSERT INTO probe VALUES('authenticated');",
    )?;
    let connection = backing.checked_connection()?;
    let value: String = connection.query_row("SELECT value FROM probe", [], |row| row.get(0))?;
    assert_eq!(value, "authenticated");
    backing.validate_connection(connection)?;
    backing.close()?;
    Ok(())
}

#[test]
fn private_named_file_uses_memory_journal_and_memory_temp_store() -> TestResult {
    let root = private_tempdir()?;
    let backing = SnapshotFileBacking::create_in(root.path())?;
    assert_eq!(
        fs::symlink_metadata(&backing.custody.directory.path)?.mode() & 0o7777,
        0o700
    );
    assert_eq!(
        fs::symlink_metadata(&backing.custody.database_path)?.mode() & 0o7777,
        0o600
    );
    let connection = backing.checked_connection()?;
    let journal: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    assert_eq!(journal, "memory");
    let temp_store: i64 = connection.query_row("PRAGMA temp_store", [], |row| row.get(0))?;
    assert_eq!(temp_store, 2);
    connection.execute_batch("CREATE TABLE probe(value); BEGIN; INSERT INTO probe VALUES(1);")?;
    assert_eq!(fs::read_dir(&backing.custody.directory.path)?.count(), 1);
    connection.execute_batch("ROLLBACK;")?;
    backing.close()?;
    assert_eq!(
        custody_entries(root.path())?,
        Vec::<std::path::PathBuf>::new()
    );
    Ok(())
}

#[test]
fn replaced_private_parent_refuses_checked_connection() -> TestResult {
    let root = private_tempdir()?;
    let backing = SnapshotFileBacking::create_in(root.path())?;
    let moved = root.path().join("original-directory");
    fs::rename(&backing.custody.directory.path, &moved)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&backing.custody.directory.path)?;
    fs::write(
        &backing.custody.database_path,
        b"replacement must remain untouched",
    )?;
    require_refusal(
        backing.checked_connection(),
        SnapshotCustodyRefusal::DirectoryIdentity,
    )?;
    Ok(())
}

#[test]
fn replaced_file_path_refuses_checked_connection() -> TestResult {
    let root = private_tempdir()?;
    let backing = SnapshotFileBacking::create_in(root.path())?;
    fs::rename(
        &backing.custody.database_path,
        backing.custody.directory.path.join("original.sqlite3"),
    )?;
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&backing.custody.database_path)?;
    require_refusal(
        backing.checked_connection(),
        SnapshotCustodyRefusal::FileIdentity,
    )?;
    Ok(())
}

#[test]
fn leaf_symlink_refuses_checked_connection() -> TestResult {
    let root = private_tempdir()?;
    let backing = SnapshotFileBacking::create_in(root.path())?;
    let original = backing.custody.directory.path.join("original.sqlite3");
    fs::rename(&backing.custody.database_path, &original)?;
    symlink(&original, &backing.custody.database_path)?;
    require_refusal(
        backing.checked_connection(),
        SnapshotCustodyRefusal::PrivateFile,
    )?;
    Ok(())
}

#[test]
fn hardlinked_backing_file_refuses_checked_connection() -> TestResult {
    let root = private_tempdir()?;
    let backing = SnapshotFileBacking::create_in(root.path())?;
    fs::hard_link(
        &backing.custody.database_path,
        root.path().join("leaked.sqlite3"),
    )?;
    require_refusal(
        backing.checked_connection(),
        SnapshotCustodyRefusal::PrivateFile,
    )?;
    Ok(())
}

#[test]
fn relaxed_directory_permissions_refuse_checked_connection() -> TestResult {
    let root = private_tempdir()?;
    let backing = SnapshotFileBacking::create_in(root.path())?;
    fs::set_permissions(
        &backing.custody.directory.path,
        fs::Permissions::from_mode(0o750),
    )?;
    require_refusal(
        backing.checked_connection(),
        SnapshotCustodyRefusal::PrivateDirectory,
    )?;
    Ok(())
}

#[test]
fn relaxed_file_permissions_refuse_checked_connection() -> TestResult {
    let root = private_tempdir()?;
    let backing = SnapshotFileBacking::create_in(root.path())?;
    fs::set_permissions(
        &backing.custody.database_path,
        fs::Permissions::from_mode(0o640),
    )?;
    require_refusal(
        backing.checked_connection(),
        SnapshotCustodyRefusal::PrivateFile,
    )?;
    Ok(())
}

#[test]
fn foreign_sqlite_descriptor_is_refused() -> TestResult {
    let root = private_tempdir()?;
    let backing = SnapshotFileBacking::create_in(root.path())?;
    let foreign = Connection::open(root.path().join("foreign.sqlite3"))?;
    require_refusal(
        backing.validate_connection(&foreign),
        SnapshotCustodyRefusal::DescriptorIdentity,
    )?;
    Ok(())
}

#[test]
fn memory_sqlite_descriptor_is_refused() -> TestResult {
    let root = private_tempdir()?;
    let backing = SnapshotFileBacking::create_in(root.path())?;
    assert!(matches!(
        backing.validate_connection(&Connection::open_in_memory()?),
        Err(SnapshotBackingError::Descriptor(
            SqliteFileIdentityInspectionError::Validation(_)
        ))
    ));
    Ok(())
}

#[test]
fn symlink_parent_is_refused_during_provisioning() -> TestResult {
    let root = private_tempdir()?;
    let alias = root.path().join("alias");
    symlink(root.path(), &alias)?;
    let error = SnapshotFileBacking::create_in(&alias)
        .err()
        .ok_or("symlink parent was accepted")?;
    assert!(
        matches!(error, SnapshotBackingError::Io(ref source) if source.raw_os_error() == Some(rustix::io::Errno::NOTDIR.raw_os_error()))
    );
    Ok(())
}

#[test]
fn writable_nonsticky_parent_is_refused_during_provisioning() -> TestResult {
    let root = private_tempdir()?;
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777))?;
    require_refusal(
        SnapshotFileBacking::create_in(root.path()),
        SnapshotCustodyRefusal::UnsafeAncestor,
    )?;
    Ok(())
}

#[test]
fn cleanup_preserves_replaced_private_parent() -> TestResult {
    let root = private_tempdir()?;
    let backing = SnapshotFileBacking::create_in(root.path())?;
    let replacement = backing.custody.directory.path.clone();
    fs::rename(&replacement, root.path().join("original-directory"))?;
    fs::DirBuilder::new().mode(0o700).create(&replacement)?;
    let replacement_file = replacement.join("snapshot.sqlite3");
    fs::write(&replacement_file, b"replacement must survive cleanup")?;
    let result = backing.close();
    require_refusal(result, SnapshotCustodyRefusal::DirectoryIdentity)?;
    assert_eq!(
        fs::read(&replacement_file)?,
        b"replacement must survive cleanup"
    );
    Ok(())
}

#[test]
fn cleanup_preserves_replaced_file() -> TestResult {
    let root = private_tempdir()?;
    let backing = SnapshotFileBacking::create_in(root.path())?;
    let replacement_file = backing.custody.database_path.clone();
    fs::rename(
        &replacement_file,
        backing.custody.directory.path.join("original.sqlite3"),
    )?;
    fs::write(&replacement_file, b"replacement must survive cleanup")?;
    fs::set_permissions(&replacement_file, fs::Permissions::from_mode(0o600))?;
    let result = backing.close();
    require_refusal(result, SnapshotCustodyRefusal::FileIdentity)?;
    assert_eq!(
        fs::read(&replacement_file)?,
        b"replacement must survive cleanup"
    );
    Ok(())
}

#[test]
fn transient_leaf_swap_after_validation_refuses_actual_sqlite_descriptor() -> TestResult {
    let root = private_tempdir()?;
    let backing = SnapshotFileBacking::create_in(root.path())?;
    backing.custody.validate_filesystem()?;
    let original = backing.custody.directory.path.join("original.sqlite3");
    fs::rename(&backing.custody.database_path, &original)?;
    let raced = Connection::open(&backing.custody.database_path)?;
    raced.execute_batch(
        "CREATE TABLE foreign_probe(value); INSERT INTO foreign_probe VALUES(41);",
    )?;
    let moved_replacement = root.path().join("replacement.sqlite3");
    fs::rename(&backing.custody.database_path, &moved_replacement)?;
    fs::rename(&original, &backing.custody.database_path)?;
    // The configured path and held directory/file now pass again. Only the
    // descriptor opened during the substitution names the foreign database.
    backing.custody.validate_filesystem()?;
    let before = fs::read(&moved_replacement)?;
    require_refusal(
        backing.validate_connection(&raced),
        SnapshotCustodyRefusal::DescriptorIdentity,
    )?;
    assert_eq!(fs::read(&moved_replacement)?, before);
    let value: i64 = raced.query_row("SELECT value FROM foreign_probe", [], |row| row.get(0))?;
    assert_eq!(value, 41);
    backing.close()?;
    Ok(())
}

#[test]
fn transient_parent_swap_after_validation_refuses_actual_sqlite_descriptor() -> TestResult {
    let root = private_tempdir()?;
    let backing = SnapshotFileBacking::create_in(root.path())?;
    backing.custody.validate_filesystem()?;
    let original = root.path().join("original-directory");
    fs::rename(&backing.custody.directory.path, &original)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&backing.custody.directory.path)?;
    let raced = Connection::open(&backing.custody.database_path)?;
    raced.execute_batch(
        "CREATE TABLE foreign_probe(value); INSERT INTO foreign_probe VALUES(42);",
    )?;
    let moved_replacement = root.path().join("replacement-directory");
    fs::rename(&backing.custody.directory.path, &moved_replacement)?;
    fs::rename(&original, &backing.custody.directory.path)?;
    backing.custody.validate_filesystem()?;
    let foreign_path = moved_replacement.join("snapshot.sqlite3");
    let before = fs::read(&foreign_path)?;
    require_refusal(
        backing.validate_connection(&raced),
        SnapshotCustodyRefusal::DescriptorIdentity,
    )?;
    assert_eq!(fs::read(&foreign_path)?, before);
    backing.close()?;
    Ok(())
}

#[test]
fn drop_removes_healthy_custody_with_an_open_transaction() -> TestResult {
    let root = private_tempdir()?;
    let backing = SnapshotFileBacking::create_in(root.path())?;
    backing
        .checked_connection()?
        .execute_batch("CREATE TABLE probe(value); BEGIN; INSERT INTO probe VALUES(1);")?;
    drop(backing);
    assert_eq!(
        custody_entries(root.path())?,
        Vec::<std::path::PathBuf>::new()
    );
    Ok(())
}

#[test]
fn drop_preserves_substituted_parent() -> TestResult {
    let root = private_tempdir()?;
    let backing = SnapshotFileBacking::create_in(root.path())?;
    let replacement = backing.custody.directory.path.clone();
    fs::rename(&replacement, root.path().join("original-directory"))?;
    fs::DirBuilder::new().mode(0o700).create(&replacement)?;
    let replacement_file = replacement.join("snapshot.sqlite3");
    fs::write(&replacement_file, b"drop must preserve this file")?;
    drop(backing);
    assert_eq!(
        fs::read(&replacement_file)?,
        b"drop must preserve this file"
    );
    Ok(())
}

#[test]
fn cleanup_preserves_symlink_and_its_target() -> TestResult {
    let root = private_tempdir()?;
    let backing = SnapshotFileBacking::create_in(root.path())?;
    let replacement = backing.custody.database_path.clone();
    fs::rename(
        &replacement,
        backing.custody.directory.path.join("original.sqlite3"),
    )?;
    let target = root.path().join("external-target");
    fs::write(&target, b"symlink target must survive")?;
    symlink(&target, &replacement)?;
    require_refusal(backing.close(), SnapshotCustodyRefusal::PrivateFile)?;
    assert!(fs::symlink_metadata(&replacement)?.file_type().is_symlink());
    assert_eq!(fs::read(&target)?, b"symlink target must survive");
    Ok(())
}

#[test]
fn altered_memory_temp_store_is_refused_on_next_borrow() -> TestResult {
    let root = private_tempdir()?;
    let backing = SnapshotFileBacking::create_in(root.path())?;
    let connection = backing.checked_connection()?;
    connection.execute_batch("PRAGMA temp_store=FILE;")?;
    require_refusal(
        backing.checked_connection(),
        SnapshotCustodyRefusal::MemorySettings,
    )?;
    connection.execute_batch("PRAGMA temp_store=MEMORY;")?;
    backing.close()?;
    Ok(())
}

#[test]
fn unexpected_sidecar_refuses_borrow_and_cleanup() -> TestResult {
    let root = private_tempdir()?;
    let backing = SnapshotFileBacking::create_in(root.path())?;
    let sidecar = backing.custody.directory.path.join("snapshot.sqlite3-wal");
    fs::write(&sidecar, b"unexpected object must survive")?;
    require_refusal(
        backing.checked_connection(),
        SnapshotCustodyRefusal::UnexpectedSidecar,
    )?;
    require_refusal(backing.close(), SnapshotCustodyRefusal::UnexpectedSidecar)?;
    assert_eq!(fs::read(&sidecar)?, b"unexpected object must survive");
    Ok(())
}

#[test]
fn relative_and_uri_parents_are_refused_without_provisioning() -> TestResult {
    for (parent, reason) in [
        (".", SnapshotCustodyRefusal::AbsoluteParent),
        (
            "file:/tmp?mode=memory",
            SnapshotCustodyRefusal::AbsoluteParent,
        ),
        ("/tmp/../tmp", SnapshotCustodyRefusal::NormalizedParent),
    ] {
        require_refusal(SnapshotFileBacking::create_in(Path::new(parent)), reason)?;
    }
    Ok(())
}

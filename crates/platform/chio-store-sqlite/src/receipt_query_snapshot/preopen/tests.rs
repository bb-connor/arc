//! The data directory derived before the receipt database opens must be the
//! one SQLite reports once it has opened it, and a database SQLite backs by no
//! file must have none.
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::super::{ReceiptQuerySnapshotConfig, ReceiptQuerySnapshotState, ReceiptQuerySnapshots};
use super::{data_directory, reclaim_abandoned_snapshots, Location};
use crate::receipt_store::SqliteReceiptStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PARENT_NAME: &str = "chio-receipt-snapshots-v2";
const RELATIVE_PROBE: &str = "receipt_query_snapshot::preopen::tests::relative_names_probe";
const RELATIVE_PROBE_ENV: &str = "CHIO_SNAPSHOT_RELATIVE_NAMES_PROBE";
const RELATIVE_RESOLVED: &str = "chio_snapshot_relative_names_resolved";
/// Diagnostic bound on waiting for another process; not a timing claim.
const HANG: Duration = Duration::from_secs(300);

fn private_root() -> std::io::Result<tempfile::TempDir> {
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
}

fn private_directory(path: &Path) -> std::io::Result<()> {
    std::fs::DirBuilder::new().mode(0o700).create(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// The main database file SQLite reports for `configured`, as bytes so that a
/// non-UTF-8 name survives; empty when no file backs the database. Opens, and
/// so may create, the database.
fn sqlite_file(configured: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let connection = rusqlite::Connection::open(configured)?;
    let file = connection.query_row(
        "SELECT file FROM pragma_database_list WHERE name = 'main'",
        [],
        |row| Ok(row.get_ref(0)?.as_bytes().map(<[u8]>::to_vec)),
    )??;
    Ok(file)
}

/// Derive first, as the hook does before the store opens; then let SQLite
/// open the same name and compare directories.
fn assert_equivalent(configured: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let derived = data_directory(configured);
    let file = sqlite_file(configured)?;
    let reported = Path::new(OsStr::from_bytes(&file))
        .parent()
        .ok_or("SQLite reported no file")?
        .to_path_buf();
    assert_eq!(
        derived,
        Location::Directory(reported.clone()),
        "{configured:?}"
    );
    Ok(reported)
}

/// `%`-encode every byte a URI filename cannot carry literally.
fn uri_path(path: &Path) -> String {
    let mut encoded = String::new();
    for &byte in path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || b"/-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[test]
fn absolute_paths_resolve_to_the_directory_sqlite_reports() -> TestResult {
    let root = private_root()?;
    let real = std::fs::canonicalize(root.path())?;
    let existing = root.path().join("existing.db");
    rusqlite::Connection::open(&existing)?;
    assert_eq!(assert_equivalent(&existing)?, real);
    // A database that does not exist yet resolves to its existing parent.
    assert_eq!(assert_equivalent(&root.path().join("missing.db"))?, real);
    // A plain name keeps `#` and `?`; only URIs give them meaning.
    assert_eq!(assert_equivalent(&root.path().join("odd#name?.db"))?, real);
    Ok(())
}

#[test]
fn links_resolve_as_sqlite_resolves_them() -> TestResult {
    let root = private_root()?;
    let real = root.path().join("real");
    private_directory(&real)?;
    let real = std::fs::canonicalize(&real)?;
    rusqlite::Connection::open(real.join("live.db"))?;
    let other = root.path().join("other");
    private_directory(&other)?;
    symlink(real.join("live.db"), other.join("link.db"))?;
    assert_eq!(assert_equivalent(&other.join("link.db"))?, real);
    let alias = root.path().join("alias");
    symlink(&real, &alias)?;
    assert_eq!(assert_equivalent(&alias.join("live.db"))?, real);
    assert_eq!(assert_equivalent(&alias.join("missing.db"))?, real);
    Ok(())
}

#[test]
fn file_uris_resolve_to_the_directory_sqlite_reports() -> TestResult {
    let root = private_root()?;
    let directory = root.path().join("a b%c#d?e");
    private_directory(&directory)?;
    let real = std::fs::canonicalize(&directory)?;
    let encoded = uri_path(&directory);
    for uri in [
        format!("file:{encoded}/one.db"),
        format!("file:{encoded}/two.db?cache=private"),
        format!("file:{encoded}/three.db?mode=rwc#section"),
        format!("file://{encoded}/four.db"),
        format!("file://localhost{encoded}/five.db#"),
        // SQLite matches keys and values exactly: these name files.
        format!("file:{encoded}/six.db?MODE=memory"),
        format!("file:{encoded}/seven.db?VFS=memdb"),
    ] {
        assert_eq!(assert_equivalent(Path::new(&uri))?, real, "{uri}");
    }
    Ok(())
}

#[test]
fn non_utf8_paths_are_preserved() -> TestResult {
    let root = private_root()?;
    let directory = root.path().join(OsStr::from_bytes(b"data-\xff"));
    private_directory(&directory)?;
    let real = std::fs::canonicalize(&directory)?;
    let configured = directory.join("live.db");
    assert_eq!(assert_equivalent(&configured)?, real);
    assert_eq!(assert_equivalent(&configured)?, real);
    // The same directory through a URI with an escaped non-UTF-8 byte.
    let uri = format!("file:{}/uri.db", uri_path(&directory));
    assert_eq!(assert_equivalent(Path::new(&uri))?, real);
    Ok(())
}

/// Entries of the working directory, to show that SQLite created no file.
fn listing(directory: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut entries = std::fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort();
    Ok(entries)
}

#[test]
#[ignore = "invoked in a separate process with an isolated working directory"]
fn relative_names_probe() -> TestResult {
    if std::env::var_os(RELATIVE_PROBE_ENV).is_none() {
        return Err("run only by the relative name test".into());
    }
    let working = std::fs::canonicalize(std::env::current_dir()?)?;
    let sub = std::fs::canonicalize(working.join("sub"))?;
    // Names SQLite opens as files, resolved against the working directory.
    for (configured, expected) in [
        ("live.db", &working),
        ("sub/live.db", &sub),
        ("./sub/../sub/other.db", &sub),
        ("file:uri.db", &working),
        ("file:sub/uri.db?cache=private#section", &sub),
        // Only lowercase `:memory:` is special to SQLite.
        (":MEMORY:", &working),
        ("file::MEMORY:", &working),
        ("file:upper.db?MODE=memory", &working),
    ] {
        assert_eq!(assert_equivalent(Path::new(configured))?, *expected);
    }
    // Names SQLite backs by no file: none appears, and none is derived.
    for configured in [
        ":memory:",
        "",
        "file::memory:",
        "file::memory:?cache=shared",
        "file:shared?mode=memory&cache=shared",
        "file:escaped-key?%6Dode=memory",
        "file:escaped-value?mode=%6Demory",
        "file:",
        "file:?cache=shared",
        "file://",
        "file://localhost",
    ] {
        let before = listing(&working)?;
        assert_eq!(
            sqlite_file(Path::new(configured))?,
            Vec::<u8>::new(),
            "{configured:?}"
        );
        assert_eq!(listing(&working)?, before, "{configured:?} created a file");
        assert_eq!(
            data_directory(Path::new(configured)),
            Location::NoFile,
            "{configured:?}"
        );
    }
    // Names SQLite refuses to open are not resolved either.
    for configured in [
        "file:rejected.db?mode=MEMORY",
        "file://LOCALHOST/tmp/rejected.db",
        "file://localhost?cache=shared",
    ] {
        assert!(
            rusqlite::Connection::open(configured).is_err(),
            "{configured}"
        );
        assert_eq!(
            data_directory(Path::new(configured)),
            Location::Unsupported,
            "{configured}"
        );
    }
    println!("{RELATIVE_RESOLVED}");
    Ok(())
}

#[test]
fn relative_and_memory_names_match_sqlite_in_an_isolated_working_directory() -> TestResult {
    let root = private_root()?;
    private_directory(&root.path().join("sub"))?;
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            RELATIVE_PROBE,
            "--test-threads=1",
            "--nocapture",
        ])
        .env(RELATIVE_PROBE_ENV, "1")
        .current_dir(root.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + HANG;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("the relative name probe did not finish within the hang bound".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let output = child.wait_with_output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        status.success() && stdout.contains(RELATIVE_RESOLVED),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn forms_that_are_not_resolved_exactly_are_refused() -> TestResult {
    let root = private_root()?;
    let base = uri_path(root.path());
    let mut refused = [
        format!("file://example.com{base}/x.db"),
        format!("file://LOCALHOST{base}/x.db"),
        format!("file:{base}/x%zz.db"),
        format!("file:{base}/x%00y.db"),
        format!("file:{base}/x.db?vfs=unix-none"),
        format!("file:{base}/x.db?vfs=memdb"),
        format!("file:{base}/x.db?%76fs=unix"),
        format!("file:{base}/x.db?%zz=1"),
        format!("file:{base}/x.db?mode=MEMORY"),
        format!("file:{base}/x.db?mode=rw&mode=memory"),
        format!("file:{base}/x.db?cache=%00"),
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect::<Vec<_>>();
    refused.push(PathBuf::from(OsStr::from_bytes(b"file:/tmp/\xff.db")));
    // A dangling link, and a directory named as the database.
    let dangling = root.path().join("dangling.db");
    symlink(root.path().join("nowhere/x.db"), &dangling)?;
    refused.push(dangling);
    refused.push(root.path().to_path_buf());
    for configured in refused {
        assert_eq!(
            data_directory(&configured),
            Location::Unsupported,
            "{configured:?}"
        );
    }
    Ok(())
}

#[test]
fn a_missing_data_directory_is_absent_and_never_created() -> TestResult {
    let root = private_root()?;
    let missing = root.path().join("not-yet");
    assert_eq!(data_directory(&missing.join("live.db")), Location::Absent);
    reclaim_abandoned_snapshots(&missing.join("live.db"));
    assert!(!missing.exists());
    Ok(())
}

/// A snapshot directory with a database file and no owner.
fn abandoned_directory(parent: &Path) -> std::io::Result<PathBuf> {
    let path = parent.join(uuid::Uuid::now_v7().hyphenated().to_string());
    private_directory(&path)?;
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path.join("snapshot.sqlite3"))?;
    Ok(path)
}

#[test]
fn reclamation_runs_only_where_the_path_resolves_and_never_opens_the_database() -> TestResult {
    let root = private_root()?;
    let data = root.path().join("data");
    private_directory(&data)?;
    let parent = data.join(PARENT_NAME);
    private_directory(&parent)?;
    let abandoned = abandoned_directory(&parent)?;
    let encoded = uri_path(&data);
    for configured in [
        format!("file:{encoded}/live.db?mode=memory"),
        format!("file://elsewhere{encoded}/live.db"),
        format!("file:{encoded}/live.db?vfs=unix-none"),
        format!("file:{encoded}/live%zz.db"),
        ":memory:".to_string(),
    ] {
        reclaim_abandoned_snapshots(Path::new(&configured));
        assert!(abandoned.exists(), "{configured} reclaimed");
    }
    // SQLite treats an uppercase key as unknown and opens the file.
    reclaim_abandoned_snapshots(Path::new(&format!("file:{encoded}/live.db?MODE=memory")));
    assert!(!abandoned.exists());
    let abandoned = abandoned_directory(&parent)?;
    reclaim_abandoned_snapshots(&data.join("live.db"));
    assert!(!abandoned.exists());
    // Reclamation never opened, created or wrote the receipt database.
    for name in ["live.db", "live.db-wal", "live.db-shm", "live.db-journal"] {
        assert!(!data.join(name).exists(), "{name}");
    }
    Ok(())
}

/// A snapshot service serving the receipt store opened at `configured`.
fn ready_service(configured: &Path) -> Result<ReceiptQuerySnapshots, Box<dyn std::error::Error>> {
    let store = std::sync::Arc::new(SqliteReceiptStore::open(configured)?);
    let service = ReceiptQuerySnapshots::start(
        store,
        ReceiptQuerySnapshotConfig {
            extension_tick: Duration::from_millis(20),
            invalid_retry_backoff: Duration::from_millis(20),
            walker_busy_timeout: Duration::from_millis(50),
            ..ReceiptQuerySnapshotConfig::default()
        },
    )?;
    let deadline = Instant::now() + HANG;
    loop {
        let state = service.status().state;
        if state == ReceiptQuerySnapshotState::Ready {
            return Ok(service);
        }
        if Instant::now() >= deadline {
            service.shutdown();
            return Err(format!("the snapshot service was not ready: {state:?}").into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Snapshot databases in the snapshot parent of `directory`.
fn snapshot_databases(directory: &Path) -> std::io::Result<Vec<PathBuf>> {
    let entries = match std::fs::read_dir(directory.join(PARENT_NAME)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut databases = Vec::new();
    for entry in entries {
        let database = entry?.path().join("snapshot.sqlite3");
        if database.is_file() {
            databases.push(database);
        }
    }
    Ok(databases)
}

#[test]
fn a_store_under_a_non_utf8_directory_keeps_its_snapshot_there() -> TestResult {
    let root = private_root()?;
    let directory = root.path().join(OsStr::from_bytes(b"receipts-\xfe\xff"));
    private_directory(&directory)?;
    let service = ready_service(&directory.join("live.db"))?;
    let databases = snapshot_databases(&directory)?;
    service.shutdown();
    assert_eq!(
        databases.len(),
        1,
        "the snapshot was provisioned outside the store's directory: {databases:?}"
    );
    Ok(())
}

#[test]
fn the_walker_provisions_where_the_hook_reclaims() -> TestResult {
    let root = private_root()?;
    let plain = root.path().join("plain");
    private_directory(&plain)?;
    let real = root.path().join("real");
    private_directory(&real)?;
    rusqlite::Connection::open(real.join("live.db"))?;
    let other = root.path().join("other");
    private_directory(&other)?;
    symlink(real.join("live.db"), other.join("link.db"))?;
    let uri = root.path().join("uri");
    private_directory(&uri)?;
    let uri = uri.to_str().ok_or("the temporary root is not UTF-8")?;
    let non_utf8 = root.path().join(OsStr::from_bytes(b"data-\xff"));
    private_directory(&non_utf8)?;
    for configured in [
        plain.join("live.db"),
        other.join("link.db"),
        PathBuf::from(format!("file:{uri}/live.db?cache=private#section")),
        non_utf8.join("live.db"),
    ] {
        // Derived before the store opens, as the hook runs.
        let Location::Directory(expected) = data_directory(&configured) else {
            return Err(format!("{configured:?} did not resolve").into());
        };
        let service = ready_service(&configured)?;
        let databases = snapshot_databases(&expected)?;
        service.shutdown();
        assert_eq!(
            databases.len(),
            1,
            "{configured:?}: the walker did not provision in {expected:?}"
        );
    }
    Ok(())
}

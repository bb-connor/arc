//! Where the service keeps its snapshot, and what it reclaims when it starts.
use std::fs::File;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chio_kernel::receipt_query::ReceiptQuerySnapshotError;
use chio_kernel::ReceiptStoreError;
use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};
use rustix::fs::{flock, FlockOperation};

use super::super::db::{SnapshotDb, SnapshotDbError};
use super::super::service::{ReceiptQuerySnapshotState, ReceiptQuerySnapshots};
use super::super::walk::WalkError;
use super::service::{config, ready, wait_for};
use super::support::Fixture;
use crate::receipt_store::test_hooks::FAIL_SEED_PATH_MARKER;
use crate::receipt_store::SqliteReceiptStore;

const PARENT_NAME: &str = "chio-receipt-snapshots-v2";

const KILLED_OWNER_BASE: &str = "CHIO_SNAPSHOT_KILLED_OWNER_BASE";
const KILLED_OWNER_SELECTOR: &str =
    "receipt_query_snapshot_backing::tests::reclaim::killed_owner_probe";
const OWNER_PROVISIONED: &str = "chio_snapshot_owner_provisioned";

fn data_directory(fixture: &Fixture) -> &Path {
    fixture
        .live
        .parent()
        .expect("the live receipt database has a directory")
}

/// Every snapshot database under `base`, at any custody depth, found without
/// following links.
fn snapshot_databases(base: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![(base.to_path_buf(), 0_u8)];
    while let Some((directory, depth)) = pending.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() && depth < 3 {
                pending.push((path, depth + 1));
            } else if metadata.is_file()
                && path.file_name() == Some(std::ffi::OsStr::new("snapshot.sqlite3"))
            {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// Diagnostic bound on waiting for another process; not a timing claim.
const HANG: Duration = Duration::from_secs(300);

/// A child process that is killed and reaped if the test ends first.
struct Reaped(std::process::Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start `count` owner processes, one after another, each provisioning under
/// `base` while the earlier ones are alive; then kill them all with SIGKILL.
fn kill_owners_in(base: &Path, count: usize) {
    use std::io::BufRead;
    let mut owners = Vec::new();
    for _ in 0..count {
        let mut owner = Reaped(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    KILLED_OWNER_SELECTOR,
                    "--test-threads=1",
                    "--nocapture",
                ])
                .env(KILLED_OWNER_BASE, base)
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let stdout = owner.0.stdout.take().unwrap();
        owners.push(owner);
        let (seen, seen_by) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let found = std::io::BufReader::new(stdout)
                .lines()
                .map_while(Result::ok)
                .any(|line| line.contains(OWNER_PROVISIONED));
            let _ = seen.send(found);
        });
        assert_eq!(
            seen_by.recv_timeout(HANG),
            Ok(true),
            "an owner did not report provisioning within the hang bound"
        );
    }
    for owner in &mut owners {
        owner.0.kill().unwrap();
        let status = owner.0.wait().unwrap();
        assert_eq!(
            status.signal(),
            Some(rustix::process::Signal::KILL.as_raw()),
            "the owner must die by SIGKILL after provisioning: {status:?}"
        );
    }
}

#[test]
fn the_snapshot_database_lives_under_the_receipt_store_data_directory() {
    let fixture = Fixture::new(0);
    let service = ready(&fixture, config());
    let databases = snapshot_databases(data_directory(&fixture));
    assert_eq!(databases.len(), 1, "{databases:?}");
    service.shutdown();
}

#[test]
fn startup_reclaims_snapshots_of_killed_owners_in_the_data_directory() {
    let fixture = Fixture::new(0);
    // The owners provision with the strict generic custody, which requires a
    // private base.
    std::fs::set_permissions(
        data_directory(&fixture),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    kill_owners_in(data_directory(&fixture), 2);
    let leftovers = snapshot_databases(data_directory(&fixture));
    assert_eq!(leftovers.len(), 2, "{leftovers:?}");

    let service = ready(&fixture, config());
    let databases = snapshot_databases(data_directory(&fixture));
    assert_eq!(
        databases.len(),
        1,
        "only the service's own snapshot may remain once it serves: {databases:?}"
    );
    assert!(leftovers
        .iter()
        .all(|leftover| !databases.contains(leftover)));
    service.shutdown();
}

#[test]
fn snapshots_of_killed_owners_are_reclaimed_while_the_writer_seed_is_unavailable() {
    let directory = tempfile::Builder::new()
        .prefix(FAIL_SEED_PATH_MARKER)
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    kill_owners_in(directory.path(), 2);
    let leftovers = snapshot_databases(directory.path());
    assert_eq!(leftovers.len(), 2, "{leftovers:?}");

    let store = Arc::new(SqliteReceiptStore::open(directory.path().join("live.db")).unwrap());
    let service = ReceiptQuerySnapshots::start(store, config()).unwrap();
    // The walker reports the failed seed only from inside its seed wait, so
    // this state is observed after any cleanup that runs before that wait.
    wait_for(
        &service,
        "the failed writer seed",
        |state| matches!(state, ReceiptQuerySnapshotState::Invalid { reason } if reason.contains("seed")),
    );
    let remaining = snapshot_databases(directory.path());
    assert_eq!(
        remaining,
        Vec::<PathBuf>::new(),
        "a writer that never seeds must not keep killed owners' snapshots"
    );
    service.shutdown();
}

fn private_directory(path: &Path) {
    std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// A snapshot directory with a database file and no owner.
fn abandoned_directory(parent: &Path) -> PathBuf {
    let path = parent.join(uuid::Uuid::now_v7().hyphenated().to_string());
    private_directory(&path);
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path.join("snapshot.sqlite3"))
        .unwrap();
    path
}

/// Hold the lifetime lock of `directory`, as its live owner does.
fn hold_lock(directory: &Path) -> File {
    let handle = File::open(directory).unwrap();
    flock(&handle, FlockOperation::NonBlockingLockExclusive).unwrap();
    handle
}

/// Wait for an effect, never for a duration.
fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn parent_lock_contention_is_a_retried_unavailable_outcome() {
    let fixture = Fixture::new(0);
    let parent = data_directory(&fixture).join(PARENT_NAME);
    private_directory(&parent);
    let holder = hold_lock(&parent);
    let error = match SnapshotDb::open_private(&fixture.store, 1 << 24) {
        Ok(_) => panic!("a contended snapshot parent was used"),
        Err(error) => error,
    };
    assert!(
        matches!(
            &error,
            SnapshotDbError::Store(ReceiptStoreError::QuerySnapshot(
                ReceiptQuerySnapshotError::Unavailable(_)
            ))
        ),
        "{error:?}"
    );
    assert!(matches!(WalkError::from(error), WalkError::Unavailable(_)));
    flock(&holder, FlockOperation::Unlock).unwrap();
    assert!(SnapshotDb::open_private(&fixture.store, 1 << 24).is_ok());
}

#[test]
fn the_data_directory_is_where_sqlite_resolved_the_store() {
    let root = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let real = root.path().join("real");
    private_directory(&real);
    let link = root.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let store = Arc::new(SqliteReceiptStore::open(link.join("live.db")).unwrap());
    let service = ReceiptQuerySnapshots::start(store, config()).unwrap();
    wait_for(&service, "ready", |state| {
        *state == ReceiptQuerySnapshotState::Ready
    });
    let databases = snapshot_databases(&real);
    assert_eq!(databases.len(), 1, "{databases:?}");
    assert!(databases[0].starts_with(real.join(PARENT_NAME)));
    assert!(std::fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
    service.shutdown();
}

/// Wall time that moves only when a test moves it.
struct SteppedClock(AtomicU64);

impl Clock for SteppedClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let millis = self.0.load(Ordering::SeqCst);
        Ok(ClockReading::new(
            UnixMillis::new(millis),
            MonotonicInstant::from_nanos(millis.saturating_mul(1_000_000)),
        ))
    }
}

#[test]
fn reclamation_continues_on_the_store_clock_while_the_writer_never_seeds() {
    let directory = tempfile::Builder::new()
        .prefix(FAIL_SEED_PATH_MARKER)
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let parent = directory.path().join(PARENT_NAME);
    private_directory(&parent);
    let created: Vec<PathBuf> = (0..40).map(|_| abandoned_directory(&parent)).collect();
    // The first 17 snapshot directories the kernel lists are live: one
    // attempt examines 16, so the first attempt reaches no abandoned one.
    let listed: Vec<PathBuf> = std::fs::read_dir(&parent)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| created.contains(path))
        .collect();
    let (head, dead) = listed.split_at(17);
    let _owners: Vec<File> = head.iter().map(|path| hold_lock(path)).collect();
    let remaining = || dead.iter().filter(|path| path.exists()).count();

    let clock = Arc::new(SteppedClock(AtomicU64::new(1_760_000_000_000)));
    let store = Arc::new(
        SqliteReceiptStore::open_with_clock(directory.path().join("live.db"), clock.clone())
            .unwrap(),
    );
    let service = ReceiptQuerySnapshots::start(store, config()).unwrap();
    wait_for(
        &service,
        "the failed writer seed",
        |state| matches!(state, ReceiptQuerySnapshotState::Invalid { reason } if reason.contains("seed")),
    );
    assert_eq!(
        remaining(),
        dead.len(),
        "the first attempt exceeded its bound"
    );

    // Each further attempt waits for the store clock, not for wall time. An
    // attempt is complete once it has persisted its new resume position.
    let cursor = parent.join("reclaim-cursor");
    let mut after_each = Vec::new();
    while remaining() > 0 {
        assert!(after_each.len() < 4, "no progress: {after_each:?}");
        let position = std::fs::read(&cursor).unwrap();
        clock.0.fetch_add(60_000, Ordering::SeqCst);
        wait_until("an attempt at the next store-clock interval", || {
            std::fs::read(&cursor).unwrap() != position
        });
        after_each.push(remaining());
    }
    // 16 examined per attempt: the 17th live directory and 15 abandoned ones,
    // then the last 8 abandoned ones.
    assert_eq!(after_each, vec![dead.len() - 15, 0]);
    assert!(head.iter().all(|path| path.exists()));
    service.shutdown();
}

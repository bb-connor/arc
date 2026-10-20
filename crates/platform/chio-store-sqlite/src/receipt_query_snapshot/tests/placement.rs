//! Where the service keeps its snapshot, and what it reclaims when it starts.
use std::fs::File;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};
use rustix::fs::{flock, FlockOperation};

use super::super::db::{SnapshotDb, SnapshotDbError};
use super::super::pass::build_snapshot;
use super::super::service::{ReceiptQuerySnapshotState, ReceiptQuerySnapshots};
use super::super::walk::{WalkError, WalkLimits};
use super::service::{config, ready, wait_for};
use super::support::{context, limits, target, Fixture};
use crate::receipt_store::test_hooks::FAIL_SEED_PATH_MARKER;
use crate::receipt_store::SqliteReceiptStore;

const PARENT_NAME: &str = "chio-receipt-snapshots";

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

const CONTENDED: &str =
    "receipt query snapshot location is unusable: another process holds the snapshot parent lock";

#[test]
fn parent_lock_contention_is_a_busy_outcome() {
    let fixture = Fixture::new(0);
    let parent = data_directory(&fixture).join(PARENT_NAME);
    private_directory(&parent);
    let holder = hold_lock(&parent);
    let error = match SnapshotDb::open_private(&fixture.store, 1 << 24) {
        Ok(_) => panic!("a contended snapshot parent was used"),
        Err(error) => error,
    };
    assert!(
        matches!(&error, SnapshotDbError::Contended(message) if message == CONTENDED),
        "{error:?}"
    );
    assert_eq!(WalkError::from(error), WalkError::Busy(CONTENDED.into()));
    flock(&holder, FlockOperation::Unlock).unwrap();
    assert!(SnapshotDb::open_private(&fixture.store, 1 << 24).is_ok());
}

/// A store in a private directory whose clock moves only when stepped.
fn stepped_store() -> (tempfile::TempDir, Arc<SteppedClock>, SqliteReceiptStore) {
    let directory = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let clock = Arc::new(SteppedClock(AtomicU64::new(1_760_000_000_000)));
    let store =
        SqliteReceiptStore::open_with_clock(directory.path().join("live.db"), clock.clone())
            .unwrap();
    private_directory(&directory.path().join(PARENT_NAME));
    (directory, clock, store)
}

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn a_build_waits_out_parent_lock_contention_until_cancelled() {
    let (directory, _clock, store) = stepped_store();
    let cancel = Arc::new(AtomicBool::new(false));
    let walk_limits = WalkLimits {
        busy_timeout: BUSY_TIMEOUT,
        ..limits()
    };
    let ctx = context(&store, &cancel, walk_limits);
    let contended = target(&ctx);
    let holder = hold_lock(&directory.path().join(PARENT_NAME));
    let outcome = std::thread::scope(|scope| {
        let builder =
            scope.spawn(|| build_snapshot(&ctx, contended, 1 << 24, &mut |_, _| {}).map(|_| ()));
        cancel.store(true, Ordering::SeqCst);
        builder.join().unwrap()
    });
    assert_eq!(outcome, Err(WalkError::Cancelled));
    assert_eq!(snapshot_databases(directory.path()), Vec::<PathBuf>::new());
    flock(&holder, FlockOperation::Unlock).unwrap();
    cancel.store(false, Ordering::SeqCst);
    let (db, _) = build_snapshot(&ctx, target(&ctx), 1 << 24, &mut |_, _| {}).unwrap();
    assert_eq!(snapshot_databases(directory.path()).len(), 1);
    drop(db);
}

/// Wall time scripted for the builder thread: its first read is `script[0]`,
/// its second releases `holder` and reads `script[1]`, and later ones read
/// `script[2]`. Every other thread reads `script[0]`.
struct ScriptedClock {
    builder: std::sync::Mutex<Option<std::thread::ThreadId>>,
    reads: std::sync::atomic::AtomicUsize,
    script: [u64; 3],
    holder: std::sync::Mutex<Option<File>>,
}

impl Clock for ScriptedClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let builder = *self.builder.lock().unwrap() == Some(std::thread::current().id());
        let millis = if builder {
            let read = self.reads.fetch_add(1, Ordering::SeqCst);
            if read == 1 {
                drop(self.holder.lock().unwrap().take());
            }
            self.script[read.min(2)]
        } else {
            self.script[0]
        };
        Ok(ClockReading::new(
            UnixMillis::new(millis),
            MonotonicInstant::from_nanos(millis.saturating_mul(1_000_000)),
        ))
    }
}

/// Build while the snapshot parent is locked; the lock is released at the
/// builder's second clock read. The outcome carries the number of snapshot
/// databases the built snapshot left in place.
fn build_released_by_the_clock(script: [u64; 3]) -> Result<usize, WalkError> {
    let directory = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let clock = Arc::new(ScriptedClock {
        builder: std::sync::Mutex::new(None),
        reads: std::sync::atomic::AtomicUsize::new(0),
        script,
        holder: std::sync::Mutex::new(None),
    });
    let store =
        SqliteReceiptStore::open_with_clock(directory.path().join("live.db"), clock.clone())
            .unwrap();
    let parent = directory.path().join(PARENT_NAME);
    private_directory(&parent);
    *clock.holder.lock().unwrap() = Some(hold_lock(&parent));
    let cancel = Arc::new(AtomicBool::new(false));
    let walk_limits = WalkLimits {
        busy_timeout: BUSY_TIMEOUT,
        ..limits()
    };
    let ctx = context(&store, &cancel, walk_limits);
    let contended = target(&ctx);
    let outcome = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                *clock.builder.lock().unwrap() = Some(std::thread::current().id());
                build_snapshot(&ctx, contended, 1 << 24, &mut |_, _| {})
                    .map(|_| snapshot_databases(directory.path()).len())
            })
            .join()
            .unwrap()
    });
    assert!(
        clock.holder.lock().unwrap().is_none(),
        "the lock was never released"
    );
    if outcome.is_err() {
        assert_eq!(snapshot_databases(directory.path()), Vec::<PathBuf>::new());
    }
    outcome
}

const START_MS: u64 = 1_760_000_000_000;

#[test]
fn a_parent_lock_released_after_the_deadline_is_not_retried() {
    let budget = u64::try_from(BUSY_TIMEOUT.as_millis()).unwrap();
    // Within budget before the backoff, past the deadline after it.
    let outcome =
        build_released_by_the_clock([START_MS, START_MS + budget - 1, START_MS + budget + 1]);
    assert_eq!(outcome, Err(WalkError::Unavailable(CONTENDED.into())));
}

#[test]
fn a_parent_lock_released_within_the_budget_is_provisioned() {
    let outcome = build_released_by_the_clock([START_MS, START_MS + 1_000, START_MS + 2_000]);
    assert_eq!(outcome, Ok(1));
}

#[test]
fn a_parent_lock_held_past_the_busy_timeout_is_unavailable() {
    let (directory, clock, store) = stepped_store();
    let cancel = Arc::new(AtomicBool::new(false));
    let walk_limits = WalkLimits {
        busy_timeout: BUSY_TIMEOUT,
        ..limits()
    };
    let ctx = context(&store, &cancel, walk_limits);
    let contended = target(&ctx);
    let _holder = hold_lock(&directory.path().join(PARENT_NAME));
    let step_ms = u64::try_from(BUSY_TIMEOUT.as_millis()).unwrap();
    let outcome = std::thread::scope(|scope| {
        let builder =
            scope.spawn(|| build_snapshot(&ctx, contended, 1 << 24, &mut |_, _| {}).map(|_| ()));
        // Past the diagnostic bound the build is cancelled, so a build
        // without a deadline ends as Cancelled.
        let bound = Instant::now() + Duration::from_secs(60);
        while !builder.is_finished() && Instant::now() < bound {
            clock.0.fetch_add(step_ms, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(10));
        }
        cancel.store(true, Ordering::SeqCst);
        builder.join().unwrap()
    });
    assert_eq!(outcome, Err(WalkError::Unavailable(CONTENDED.into())));
    assert_eq!(snapshot_databases(directory.path()), Vec::<PathBuf>::new());
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

//! Reclamation of snapshot custody whose owner died without unwinding.
use std::fs::File;
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::sync::mpsc;

use rustix::fs::{flock, FlockOperation};

use super::super::directory::pause;
use super::super::reclaim::PARENT_NAME;
use super::super::reclaim_abandoned;
use super::*;

const ATTEMPT_BASE: &str = "CHIO_SNAPSHOT_ATTEMPT_BASE";
const ATTEMPT_SELECTOR: &str =
    "receipt_query_snapshot_backing::tests::reclaim::provisioning_attempt_probe";
const ATTEMPT_COMPLETED: &str = "chio_snapshot_provisioning_attempt_completed";

pub(super) fn snapshot_parent(base: &Path) -> PathBuf {
    base.join(PARENT_NAME)
}

/// A snapshot directory with a database file and no owner, as a killed
/// owner leaves it.
pub(super) fn abandoned_directory(parent: &Path) -> std::io::Result<PathBuf> {
    let path = parent.join(uuid::Uuid::now_v7().hyphenated().to_string());
    fs::DirBuilder::new().mode(0o700).create(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path.join("snapshot.sqlite3"))?
        .write_all(b"abandoned snapshot")?;
    Ok(path)
}

/// Hold the lifetime lock of `directory`, as its live owner does.
pub(super) fn hold_lock(directory: &Path) -> std::io::Result<File> {
    let handle = File::open(directory)?;
    flock(&handle, FlockOperation::NonBlockingLockExclusive)?;
    Ok(handle)
}

const KILLED_OWNER_BASE: &str = "CHIO_SNAPSHOT_KILLED_OWNER_BASE";
const KILLED_OWNER_SELECTOR: &str =
    "receipt_query_snapshot_backing::tests::reclaim::killed_owner_probe";
const OWNER_PROVISIONED: &str = "chio_snapshot_owner_provisioned";
const FILL_BYTES: u64 = 262_144;

/// Every snapshot database under `base`, at any custody depth, found without
/// following links.
fn snapshot_databases(base: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let mut pending = vec![(base.to_path_buf(), 0_u8)];
    while let Some((directory, depth)) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
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
    Ok(found)
}

/// Start `count` owner processes, one after another, each provisioning under
/// `base` and staying alive; then kill them all with SIGKILL, so no
/// destructor runs, as after an OOM kill. Each owner provisions while the
/// earlier ones are alive, so none of them reclaims another.
fn kill_owners_in(base: &Path, count: usize) -> TestResult {
    // Any owner still running when this returns, by failure included, is
    // killed and reaped.
    let mut owners = Vec::new();
    for _ in 0..count {
        let owner = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--ignored",
                "--exact",
                KILLED_OWNER_SELECTOR,
                "--test-threads=1",
                "--nocapture",
            ])
            .env(KILLED_OWNER_BASE, base)
            .stdout(std::process::Stdio::piped())
            .spawn()?;
        owners.push(Reaped(owner));
        let owner = owners.last_mut().ok_or("owner")?;
        await_marker(&mut owner.0, OWNER_PROVISIONED)?;
    }
    for owner in &mut owners {
        owner.0.kill()?;
        let status = owner.0.wait()?;
        assert_eq!(
            status.signal(),
            Some(rustix::process::Signal::KILL.as_raw()),
            "the owner must die by SIGKILL after provisioning: {status:?}"
        );
    }
    Ok(())
}

#[test]
#[ignore = "invoked in a separate process by the killed-owner reclamation tests"]
fn killed_owner_probe() -> TestResult {
    let base = std::env::var_os(KILLED_OWNER_BASE).ok_or("owner base is required")?;
    let backing = SnapshotFileBacking::create_in(Path::new(&base))?;
    backing.checked_connection()?.execute_batch(&format!(
        "CREATE TABLE fill(value BLOB); INSERT INTO fill VALUES (zeroblob({FILL_BYTES}));"
    ))?;
    backing.checked_connection()?;
    println!("{OWNER_PROVISIONED}");
    // Stay alive, holding the snapshot, until the parent kills this process.
    loop {
        std::thread::park();
    }
}

#[test]
fn the_next_provisioning_reclaims_snapshots_of_killed_owners() -> TestResult {
    let root = private_tempdir()?;
    kill_owners_in(root.path(), 3)?;
    let leftovers = snapshot_databases(root.path())?;
    assert_eq!(leftovers.len(), 3, "{leftovers:?}");
    for leftover in &leftovers {
        assert!(fs::symlink_metadata(leftover)?.len() >= FILL_BYTES);
    }

    let backing = SnapshotFileBacking::create_in(root.path())?;
    assert_eq!(
        snapshot_databases(root.path())?,
        vec![backing.custody.database_path.clone()],
        "only the live snapshot may remain after the next provisioning"
    );
    backing.checked_connection()?;
    backing.close()?;
    assert_eq!(snapshot_databases(root.path())?, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
fn reclamation_leaves_live_foreign_and_invalid_entries_untouched() -> TestResult {
    let root = private_tempdir()?;
    let live = SnapshotFileBacking::create_in(root.path())?;
    live.checked_connection()?
        .execute_batch("CREATE TABLE probe(value); INSERT INTO probe VALUES (1);")?;
    let parent = snapshot_parent(root.path());
    kill_owners_in(root.path(), 1)?;
    let killed: Vec<PathBuf> = snapshot_databases(root.path())?
        .into_iter()
        .filter(|path| *path != live.custody.database_path)
        .collect();
    assert_eq!(killed.len(), 1, "{killed:?}");

    let foreign = parent.join("operator-notes");
    fs::DirBuilder::new().mode(0o700).create(&foreign)?;
    fs::write(foreign.join("snapshot.sqlite3"), b"foreign")?;
    let open_mode = abandoned_directory(&parent)?;
    fs::set_permissions(&open_mode, fs::Permissions::from_mode(0o755))?;
    let target = root.path().join("link-target");
    fs::DirBuilder::new().mode(0o700).create(&target)?;
    fs::write(target.join("snapshot.sqlite3"), b"link target")?;
    let linked = parent.join(uuid::Uuid::now_v7().hyphenated().to_string());
    symlink(&target, &linked)?;
    let other_version = parent.join("01234567-89ab-4def-8123-456789abcdef");
    fs::DirBuilder::new().mode(0o700).create(&other_version)?;
    fs::write(other_version.join("snapshot.sqlite3"), b"other version")?;
    let uppercase = parent.join(uuid::Uuid::now_v7().hyphenated().to_string().to_uppercase());
    fs::DirBuilder::new().mode(0o700).create(&uppercase)?;
    fs::write(uppercase.join("snapshot.sqlite3"), b"uppercase")?;
    let crowded = abandoned_directory(&parent)?;
    fs::write(crowded.join("operator-file"), b"unknown content")?;
    let legacy_beside = root.path().join(format!(
        "chio-receipt-snapshot-{}",
        uuid::Uuid::now_v7().hyphenated()
    ));
    fs::DirBuilder::new().mode(0o700).create(&legacy_beside)?;
    fs::write(legacy_beside.join("snapshot.sqlite3"), b"legacy")?;
    let legacy_inside = parent.join(format!(
        "chio-receipt-snapshot-{}",
        uuid::Uuid::now_v7().hyphenated()
    ));
    fs::DirBuilder::new().mode(0o700).create(&legacy_inside)?;
    fs::write(legacy_inside.join("snapshot.sqlite3"), b"legacy")?;

    let next = SnapshotFileBacking::create_in(root.path())?;
    let killed_directory = killed[0].parent().ok_or("killed owner directory")?;
    assert!(
        !killed_directory.exists(),
        "the killed owner's directory remains"
    );

    assert_eq!(fs::read(foreign.join("snapshot.sqlite3"))?, b"foreign");
    assert_eq!(fs::symlink_metadata(&open_mode)?.mode() & 0o7777, 0o755);
    assert_eq!(
        fs::read(open_mode.join("snapshot.sqlite3"))?,
        b"abandoned snapshot"
    );
    assert!(fs::symlink_metadata(&linked)?.file_type().is_symlink());
    assert_eq!(fs::read(target.join("snapshot.sqlite3"))?, b"link target");
    assert_eq!(
        fs::read(other_version.join("snapshot.sqlite3"))?,
        b"other version"
    );
    assert_eq!(fs::read(uppercase.join("snapshot.sqlite3"))?, b"uppercase");
    // An abandoned directory with unknown content loses only its known
    // snapshot leaves; the directory and the unknown file stay.
    assert_eq!(fs::read(crowded.join("operator-file"))?, b"unknown content");
    assert!(!crowded.join("snapshot.sqlite3").exists());
    assert_eq!(fs::read(legacy_beside.join("snapshot.sqlite3"))?, b"legacy");
    assert_eq!(fs::read(legacy_inside.join("snapshot.sqlite3"))?, b"legacy");

    let value: i64 =
        live.checked_connection()?
            .query_row("SELECT value FROM probe", [], |row| row.get(0))?;
    assert_eq!(value, 1);
    next.checked_connection()?;
    live.close()?;
    next.close()?;
    Ok(())
}

/// Sends the release when dropped, on success and on failure alike.
struct ReleaseOnDrop(Option<mpsc::Sender<()>>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        if let Some(release) = self.0.take() {
            let _ = release.send(());
        }
    }
}

#[test]
fn a_directory_published_before_its_lock_is_never_reclaimed() -> TestResult {
    let root = private_tempdir()?;
    let base = root.path().to_path_buf();
    let (reached, published) = mpsc::channel::<PathBuf>();
    let (release, released) = mpsc::channel::<()>();
    let (finished, outcome) = mpsc::channel();
    let provisioner = std::thread::spawn(move || {
        pause::on_this_thread(move |path| {
            let _ = reached.send(path.to_path_buf());
            let _ = released.recv_timeout(HANG);
        });
        let _ =
            finished.send(SnapshotFileBacking::create_in(&base).map_err(|error| error.to_string()));
    });
    // Releases the paused provisioner however this test ends.
    let release = ReleaseOnDrop(Some(release));
    let published = published
        .recv_timeout(HANG)
        .map_err(|_| "the provisioner never published its directory")?;
    assert!(fs::symlink_metadata(&published)?.is_dir());
    // While the new directory is unlocked, the parent lock is held: another
    // provisioner and a reclaimer are both refused, and the directory stays.
    require_unusable(
        SnapshotFileBacking::create_in(root.path()),
        SnapshotLocationRefusal::Contended,
    )?;
    require_unusable(
        reclaim_abandoned(Some(root.path())),
        SnapshotLocationRefusal::Contended,
    )?;
    assert!(fs::symlink_metadata(&published)?.is_dir());
    drop(release);
    let backing = outcome
        .recv_timeout(HANG)
        .map_err(|_| "the provisioner did not finish within the hang bound")??;
    provisioner.join().map_err(|_| "the provisioner panicked")?;
    assert_eq!(backing.custody.directory.path, published);
    let report = reclaim_abandoned(Some(root.path()))?;
    assert_eq!((report.reclaimed, report.live), (0, 1), "{report:?}");
    backing.checked_connection()?;
    backing.close()?;
    Ok(())
}

#[test]
fn parent_lock_contention_is_an_operational_refusal() -> TestResult {
    let root = private_tempdir()?;
    SnapshotFileBacking::create_in(root.path())?.close()?;
    let abandoned = abandoned_directory(&snapshot_parent(root.path()))?;
    let holder = hold_lock(&snapshot_parent(root.path()))?;
    let before = custody_entries(root.path())?;
    require_unusable(
        SnapshotFileBacking::create_in(root.path()),
        SnapshotLocationRefusal::Contended,
    )?;
    require_unusable(
        SnapshotFileBacking::create(Some(root.path())),
        SnapshotLocationRefusal::Contended,
    )?;
    require_unusable(
        reclaim_abandoned(Some(root.path())),
        SnapshotLocationRefusal::Contended,
    )?;
    assert_eq!(custody_entries(root.path())?, before);
    assert!(abandoned.exists());
    flock(&holder, FlockOperation::Unlock)?;
    SnapshotFileBacking::create_in(root.path())?.close()?;
    assert!(!abandoned.exists());
    Ok(())
}

#[test]
#[ignore = "invoked in a separate process by the reclamation progress test"]
fn provisioning_attempt_probe() -> TestResult {
    let base = std::env::var_os(ATTEMPT_BASE).ok_or("attempt base is required")?;
    SnapshotFileBacking::create_in(Path::new(&base))?.close()?;
    println!("{ATTEMPT_COMPLETED}");
    Ok(())
}

/// One provisioning attempt by a freshly started process.
fn attempt_in_new_process(base: &Path) -> TestResult {
    let (status, stdout, stderr) = output_within_hang(
        std::process::Command::new(std::env::current_exe()?)
            .args([
                "--ignored",
                "--exact",
                ATTEMPT_SELECTOR,
                "--test-threads=1",
                "--nocapture",
            ])
            .env(ATTEMPT_BASE, base),
    )?;
    assert!(
        status.success() && stdout.contains(ATTEMPT_COMPLETED),
        "the restarted attempt failed: {stdout}{stderr}"
    );
    Ok(())
}

#[test]
fn abandoned_directories_behind_more_entries_than_one_attempt_reads_are_reclaimed() -> TestResult {
    let root = private_tempdir()?;
    SnapshotFileBacking::create_in(root.path())?.close()?;
    let parent = snapshot_parent(root.path());
    let foreign: Vec<PathBuf> = (0..48)
        .map(|index| parent.join(format!("foreign-{index:03}")))
        .collect();
    for path in &foreign {
        fs::write(path, b"foreign")?;
    }
    let mut directories = Vec::new();
    for _ in 0..300 {
        directories.push(abandoned_directory(&parent)?);
    }
    // The last 20 snapshot directories the kernel lists are abandoned; every
    // one listed before them is live.
    let order = fs::read_dir(&parent)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    let listed: Vec<PathBuf> = order
        .iter()
        .filter(|path| directories.contains(path))
        .cloned()
        .collect();
    let (head, tail) = listed.split_at(listed.len() - 20);
    let dead = tail.to_vec();
    let first_dead = order
        .iter()
        .position(|path| *path == dead[0])
        .ok_or("listed")?;
    assert!(
        first_dead > 256,
        "the abandoned directories must follow more entries than one attempt reads"
    );
    let mut live = head
        .iter()
        .map(|path| Ok((path.clone(), hold_lock(path)?)))
        .collect::<std::io::Result<Vec<_>>>()?;

    let mut attempts = 0;
    while dead.iter().any(|path| path.exists()) {
        attempts += 1;
        assert!(attempts <= 64, "no progress after {attempts} attempts");
        // Alternate fresh descriptors in this process with restarted processes.
        if attempts % 2 == 0 {
            attempt_in_new_process(root.path())?;
        } else {
            SnapshotFileBacking::create_in(root.path())?.close()?;
        }
        if attempts == 1 {
            assert!(
                dead.iter().all(|path| path.exists()),
                "one attempt must stay within its bound"
            );
        }
        // Owners also exit between attempts, removing entries mid-traversal.
        if attempts % 3 == 0 {
            if let Some((path, lock)) = live.pop() {
                drop(lock);
                fs::remove_file(path.join("snapshot.sqlite3"))?;
                fs::remove_dir(&path)?;
            }
        }
    }
    assert!(attempts > 1);
    for (path, _) in &live {
        assert_eq!(
            fs::read(path.join("snapshot.sqlite3"))?,
            b"abandoned snapshot"
        );
    }
    for path in &foreign {
        assert_eq!(fs::read(path)?, b"foreign");
    }
    eprintln!(
        "reclaimed {} directories after {attempts} attempts",
        dead.len()
    );
    Ok(())
}

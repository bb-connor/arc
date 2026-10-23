//! Where snapshots are provisioned, and which locations are refused.
use std::path::PathBuf;

use super::super::reclaim::database_parent_name;
use super::super::reclaim::PARENT_NAME;
use super::super::reclaim_abandoned;
use super::reclaim::{abandoned_directory, hold_lock, snapshot_parent};
use super::*;

/// A data directory with exactly `mode` inside a private temporary root.
fn data_directory(mode: u32) -> Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
    let root = private_tempdir()?;
    let directory = root.path().join("data");
    fs::DirBuilder::new().mode(0o700).create(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(mode))?;
    Ok((root, directory))
}

#[test]
fn a_group_writable_data_directory_holds_healthy_snapshots() -> TestResult {
    for mode in [0o770, 0o775, 0o2775] {
        let (_root, directory) = data_directory(mode)?;
        SnapshotFileBacking::create(Some(&database(&directory)))?.close()?;
        let parent = snapshot_parent(&directory);
        // A set-group-ID data directory passes that bit to new directories;
        // the snapshot parent is still exactly 0700.
        assert_eq!(fs::symlink_metadata(&parent)?.mode() & 0o7777, 0o700);
        let abandoned = abandoned_directory(&parent)?;
        let backing = SnapshotFileBacking::create(Some(&database(&directory)))?;
        assert!(backing
            .custody
            .database_path
            .starts_with(snapshot_parent(&directory)));
        assert!(!abandoned.exists());
        backing
            .checked_connection()?
            .execute_batch("CREATE TABLE probe(value);")?;
        backing.checked_connection()?;
        // The strict generic custody still refuses the same directory.
        require_refusal(
            SnapshotFileBacking::create_in(&directory),
            SnapshotCustodyRefusal::UnsafeAncestor,
        )?;
        backing.close()?;
    }
    Ok(())
}

#[test]
fn a_sticky_world_writable_data_directory_holds_healthy_snapshots() -> TestResult {
    let (_root, directory) = data_directory(0o1777)?;
    let backing = SnapshotFileBacking::create(Some(&database(&directory)))?;
    backing.checked_connection()?;
    backing.close()?;
    Ok(())
}

#[test]
fn a_world_writable_data_directory_without_sticky_is_refused() -> TestResult {
    for mode in [0o777, 0o2777, 0o703] {
        let (_root, directory) = data_directory(mode)?;
        require_refusal(
            SnapshotFileBacking::create(Some(&database(&directory))),
            SnapshotCustodyRefusal::UnsafeAncestor,
        )?;
        require_refusal(
            reclaim_abandoned(Some(&database(&directory))),
            SnapshotCustodyRefusal::UnsafeAncestor,
        )?;
        assert_eq!(fs::read_dir(&directory)?.count(), 0);
    }
    Ok(())
}

#[test]
fn only_the_data_directory_itself_may_be_group_writable() -> TestResult {
    let root = private_tempdir()?;
    let shared = root.path().join("shared");
    fs::DirBuilder::new().mode(0o700).create(&shared)?;
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o775))?;
    let directory = shared.join("data");
    fs::DirBuilder::new().mode(0o700).create(&directory)?;
    require_refusal(
        SnapshotFileBacking::create(Some(&database(&directory))),
        SnapshotCustodyRefusal::UnsafeAncestor,
    )?;
    assert_eq!(fs::read_dir(&directory)?.count(), 0);
    Ok(())
}

#[test]
fn a_substituted_snapshot_parent_in_a_group_writable_data_directory_is_refused() -> TestResult {
    let (_root, directory) = data_directory(0o775)?;
    let backing = SnapshotFileBacking::create(Some(&database(&directory)))?;
    let parent = snapshot_parent(&directory);
    fs::rename(&parent, directory.join("moved-parent"))?;
    fs::DirBuilder::new().mode(0o700).create(&parent)?;
    fs::write(parent.join("replacement"), b"replacement")?;
    require_refusal(
        backing.checked_connection(),
        SnapshotCustodyRefusal::DirectoryIdentity,
    )?;
    drop(backing);
    assert_eq!(fs::read(parent.join("replacement"))?, b"replacement");
    Ok(())
}

#[test]
fn a_substituted_data_directory_is_refused() -> TestResult {
    let (root, directory) = data_directory(0o775)?;
    let backing = SnapshotFileBacking::create(Some(&database(&directory)))?;
    fs::rename(&directory, root.path().join("moved-data"))?;
    fs::DirBuilder::new().mode(0o700).create(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o775))?;
    require_refusal(
        backing.checked_connection(),
        SnapshotCustodyRefusal::DirectoryIdentity,
    )?;
    Ok(())
}

enum UnusableParent {
    OpenMode,
    Symlink,
    File,
}

#[test]
fn an_unusable_snapshot_parent_is_refused_and_left_untouched() -> TestResult {
    for case in [
        UnusableParent::OpenMode,
        UnusableParent::Symlink,
        UnusableParent::File,
    ] {
        let root = private_tempdir()?;
        let parent = snapshot_parent(root.path());
        let elsewhere = root.path().join("elsewhere");
        fs::DirBuilder::new().mode(0o700).create(&elsewhere)?;
        let abandoned = abandoned_directory(&elsewhere)?;
        match case {
            UnusableParent::OpenMode => {
                fs::DirBuilder::new().mode(0o700).create(&parent)?;
                fs::set_permissions(&parent, fs::Permissions::from_mode(0o755))?;
                fs::write(parent.join("inside"), b"inside")?;
            }
            UnusableParent::Symlink => symlink(&elsewhere, &parent)?,
            UnusableParent::File => fs::write(&parent, b"not a directory")?,
        }
        let before = fs::symlink_metadata(&parent)?;
        require_unusable(
            SnapshotFileBacking::create_in(root.path()),
            SnapshotLocationRefusal::ForeignParent,
        )?;
        require_unusable(
            SnapshotFileBacking::create(Some(&database(root.path()))),
            SnapshotLocationRefusal::ForeignParent,
        )?;
        require_unusable(
            reclaim_abandoned(Some(&database(root.path()))),
            SnapshotLocationRefusal::ForeignParent,
        )?;
        let after = fs::symlink_metadata(&parent)?;
        assert_eq!(
            (after.ino(), after.mode(), after.len()),
            (before.ino(), before.mode(), before.len())
        );
        assert!(abandoned.exists());
        match case {
            UnusableParent::OpenMode => assert_eq!(fs::read(parent.join("inside"))?, b"inside"),
            UnusableParent::Symlink => assert!(after.file_type().is_symlink()),
            UnusableParent::File => assert_eq!(fs::read(&parent)?, b"not a directory"),
        }
    }
    Ok(())
}

#[test]
fn without_a_data_directory_snapshots_use_a_per_user_parent_under_tmp() -> TestResult {
    let expected = Path::new("/tmp").join(format!(
        "{PARENT_NAME}-{}",
        rustix::process::geteuid().as_raw()
    ));
    let backing = uncontended(|| SnapshotFileBacking::create(None))?;
    assert_eq!(
        backing.custody.directory.path.parent(),
        Some(expected.as_path())
    );
    backing.checked_connection()?;
    backing.close()?;
    Ok(())
}

#[test]
fn snapshot_directories_of_earlier_builds_are_never_examined() -> TestResult {
    let name = format!(
        "chio-receipt-snapshot-{}",
        uuid::Uuid::now_v7().hyphenated()
    );
    let root = private_tempdir()?;
    // A data directory parent named without the user and database file.
    let unsuffixed = root.path().join(PARENT_NAME);
    fs::DirBuilder::new().mode(0o700).create(&unsuffixed)?;
    let unsuffixed_abandoned = abandoned_directory(&unsuffixed)?;
    let legacy = [Path::new("/tmp").join(&name), root.path().join(&name)];
    for directory in &legacy {
        fs::DirBuilder::new().mode(0o700).create(directory)?;
        fs::write(directory.join("snapshot.sqlite3"), b"earlier build")?;
    }
    uncontended(|| SnapshotFileBacking::create(None))?.close()?;
    uncontended(|| reclaim_abandoned(None))?;
    SnapshotFileBacking::create(Some(&database(root.path())))?.close()?;
    reclaim_abandoned(Some(&database(root.path())))?;
    for directory in &legacy {
        assert_eq!(
            fs::read(directory.join("snapshot.sqlite3"))?,
            b"earlier build"
        );
    }
    assert!(unsuffixed_abandoned.exists());
    // Remove only the directory this test created under /tmp.
    fs::remove_file(legacy[0].join("snapshot.sqlite3"))?;
    fs::remove_dir(&legacy[0])?;
    Ok(())
}

#[test]
fn the_data_directory_parent_name_is_pinned() {
    // The first 16 hex digits of SHA-256 of the database file name bytes.
    assert_eq!(
        database_parent_name(1000, std::ffi::OsStr::new("live.db")),
        "chio-receipt-snapshots-1000-c726577d9a0f3098"
    );
    assert_eq!(
        database_parent_name(1001, std::ffi::OsStr::new("other.db")),
        "chio-receipt-snapshots-1001-c3c5b7af3519ad9c"
    );
    // The digest covers the name's bytes, so a non-UTF-8 name has one too.
    use std::os::unix::ffi::OsStrExt;
    assert_eq!(
        database_parent_name(0, std::ffi::OsStr::from_bytes(b"\xff.db")),
        "chio-receipt-snapshots-0-c8c1483f29dd3e37"
    );
}

#[test]
fn two_databases_in_one_directory_do_not_contend() -> TestResult {
    let (_root, directory) = data_directory(0o700)?;
    let first = directory.join("first.db");
    let second = directory.join("second.db");
    SnapshotFileBacking::create(Some(&first))?.close()?;
    let holder = hold_lock(&snapshot_parent_of(&first))?;
    require_unusable(
        SnapshotFileBacking::create(Some(&first)),
        SnapshotLocationRefusal::Contended,
    )?;
    let backing = SnapshotFileBacking::create(Some(&second))?;
    assert!(backing
        .custody
        .database_path
        .starts_with(snapshot_parent_of(&second)));
    assert_ne!(snapshot_parent_of(&first), snapshot_parent_of(&second));
    reclaim_abandoned(Some(&second))?;
    backing.close()?;
    drop(holder);
    Ok(())
}

#[test]
fn foreign_parents_in_a_sticky_directory_block_only_their_own_name() -> TestResult {
    let (_root, directory) = data_directory(0o1777)?;
    let database = directory.join("live.db");
    let euid = rustix::process::geteuid().as_raw();
    // Parents this user does not hold as 0700: the shared unsuffixed name
    // and the name of another user for the same database file.
    let foreign = [
        directory.join(PARENT_NAME),
        directory.join(database_parent_name(
            euid.wrapping_add(1),
            std::ffi::OsStr::new("live.db"),
        )),
    ];
    for parent in &foreign {
        fs::DirBuilder::new().mode(0o700).create(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755))?;
        fs::write(parent.join("inside"), b"inside")?;
    }
    let backing = SnapshotFileBacking::create(Some(&database))?;
    assert!(backing
        .custody
        .database_path
        .starts_with(snapshot_parent_of(&database)));
    reclaim_abandoned(Some(&database))?;
    backing.close()?;
    for parent in &foreign {
        assert_eq!(fs::symlink_metadata(parent)?.mode() & 0o7777, 0o755);
        assert_eq!(fs::read(parent.join("inside"))?, b"inside");
    }
    // A parent squatted at this user's own name is still refused.
    let squatted = directory.join("squatted.db");
    let parent = snapshot_parent_of(&squatted);
    fs::DirBuilder::new().mode(0o700).create(&parent)?;
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755))?;
    require_unusable(
        SnapshotFileBacking::create(Some(&squatted)),
        SnapshotLocationRefusal::ForeignParent,
    )?;
    Ok(())
}

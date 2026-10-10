//! The persisted reclamation cursor.
use std::path::PathBuf;

use super::super::reclaim::fault;
use super::super::reclaim_abandoned;
use super::reclaim::{abandoned_directory, snapshot_parent};
use super::*;

fn cursor_path(base: &Path) -> PathBuf {
    snapshot_parent(base).join("reclaim-cursor")
}

/// A provisioned base whose snapshot parent holds one abandoned directory.
fn base_with_abandoned_directory(
) -> Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
    let root = private_tempdir()?;
    SnapshotFileBacking::create_in(root.path())?.close()?;
    let abandoned = abandoned_directory(&snapshot_parent(root.path()))?;
    Ok((root, abandoned))
}

fn assert_whole_private_cursor(base: &Path) -> TestResult {
    let metadata = fs::symlink_metadata(cursor_path(base))?;
    assert!(metadata.is_file());
    assert_eq!(metadata.len(), 8);
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    Ok(())
}

#[test]
fn the_cursor_is_a_private_file_holding_one_position() -> TestResult {
    let (root, abandoned) = base_with_abandoned_directory()?;
    SnapshotFileBacking::create_in(root.path())?.close()?;
    assert!(!abandoned.exists());
    assert_whole_private_cursor(root.path())
}

#[test]
fn a_position_the_kernel_refuses_or_any_other_position_wraps_to_the_beginning() -> TestResult {
    for position in [
        u64::MAX,
        0x8000_0000_0000_0000,
        0x7fff_ffff_ffff_ffff,
        0x0123_4567_89ab_cdef,
        1,
    ] {
        let (root, abandoned) = base_with_abandoned_directory()?;
        fs::write(cursor_path(root.path()), position.to_le_bytes())?;
        // An opaque position may resume past the directory; the scan then
        // reaches the end and the next attempt starts from the beginning.
        for _ in 0..2 {
            SnapshotFileBacking::create_in(root.path())?.close()?;
        }
        assert!(
            !abandoned.exists(),
            "position {position:#x} hid the abandoned directory"
        );
        assert_whole_private_cursor(root.path())?;
    }
    Ok(())
}

#[test]
fn a_partial_or_empty_cursor_restarts_from_the_beginning_and_is_rewritten() -> TestResult {
    for bytes in [&b""[..], &b"\x01\x02\x03"[..], &[0x7f_u8; 12][..]] {
        let (root, abandoned) = base_with_abandoned_directory()?;
        fs::write(cursor_path(root.path()), bytes)?;
        SnapshotFileBacking::create_in(root.path())?.close()?;
        assert!(!abandoned.exists(), "{bytes:?}");
        assert_whole_private_cursor(root.path())?;
    }
    Ok(())
}

#[test]
fn a_missing_cursor_restarts_from_the_beginning_and_is_recreated() -> TestResult {
    let (root, abandoned) = base_with_abandoned_directory()?;
    fs::remove_file(cursor_path(root.path()))?;
    SnapshotFileBacking::create_in(root.path())?.close()?;
    assert!(!abandoned.exists());
    assert_whole_private_cursor(root.path())
}

enum Unusable {
    Symlink,
    Directory,
    HardLinked,
    OpenMode,
    Fifo,
}

#[test]
fn an_unusable_cursor_is_refused_and_left_untouched() -> TestResult {
    for case in [
        Unusable::Symlink,
        Unusable::Directory,
        Unusable::HardLinked,
        Unusable::OpenMode,
        Unusable::Fifo,
    ] {
        let (root, abandoned) = base_with_abandoned_directory()?;
        let cursor = cursor_path(root.path());
        fs::remove_file(&cursor)?;
        let target = root.path().join("cursor-target");
        fs::write(&target, b"target content")?;
        match case {
            Unusable::Symlink => symlink(&target, &cursor)?,
            Unusable::Directory => {
                fs::DirBuilder::new().mode(0o700).create(&cursor)?;
                fs::write(cursor.join("inside"), b"inside")?;
            }
            Unusable::HardLinked => {
                fs::write(&cursor, [0_u8; 8])?;
                fs::set_permissions(&cursor, fs::Permissions::from_mode(0o600))?;
                fs::hard_link(&cursor, root.path().join("second-link"))?;
            }
            Unusable::OpenMode => {
                fs::write(&cursor, [0_u8; 8])?;
                fs::set_permissions(&cursor, fs::Permissions::from_mode(0o644))?;
            }
            Unusable::Fifo => rustix::fs::mknodat(
                rustix::fs::CWD,
                &cursor,
                rustix::fs::FileType::Fifo,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                0,
            )?,
        }
        let before = fs::symlink_metadata(&cursor)?;
        let entries = custody_entries(root.path())?;

        require_unusable(
            SnapshotFileBacking::create_in(root.path()),
            SnapshotLocationRefusal::UnusableCursor,
        )?;
        require_unusable(
            reclaim_abandoned(Some(root.path())),
            SnapshotLocationRefusal::UnusableCursor,
        )?;

        // Nothing was examined or created, and the cursor entry is unchanged.
        assert!(abandoned.exists());
        assert_eq!(custody_entries(root.path())?, entries);
        let after = fs::symlink_metadata(&cursor)?;
        assert_eq!(
            (after.ino(), after.mode(), after.nlink(), after.len()),
            (before.ino(), before.mode(), before.nlink(), before.len())
        );
        assert_eq!(fs::read(&target)?, b"target content");
        match case {
            Unusable::Directory => assert_eq!(fs::read(cursor.join("inside"))?, b"inside"),
            Unusable::HardLinked | Unusable::OpenMode => {
                assert_eq!(fs::read(&cursor)?, [0_u8; 8]);
            }
            Unusable::Symlink | Unusable::Fifo => {}
        }
    }
    Ok(())
}

fn require_no_space<T>(outcome: Result<T, SnapshotBackingError>) -> TestResult {
    match outcome {
        Err(SnapshotBackingError::Io(error))
            if error.raw_os_error() == Some(rustix::io::Errno::NOSPC.raw_os_error()) =>
        {
            Ok(())
        }
        Err(other) => Err(format!("expected ENOSPC, got {other:?}").into()),
        Ok(_) => Err("expected ENOSPC, but the attempt succeeded".into()),
    }
}

#[test]
fn a_failed_cursor_update_refuses_after_reclaiming_and_publishes_nothing() -> TestResult {
    let (root, abandoned) = base_with_abandoned_directory()?;
    let before = fs::read(cursor_path(root.path()))?;
    fault::fail_next_cursor_write(rustix::io::Errno::NOSPC.raw_os_error());
    require_no_space(SnapshotFileBacking::create_in(root.path()))?;
    // The abandoned directory was reclaimed before the update failed, the
    // refusal is explicit, and no snapshot directory was published.
    assert!(!abandoned.exists());
    assert_eq!(custody_entries(root.path())?, Vec::<PathBuf>::new());
    assert_eq!(fs::read(cursor_path(root.path()))?, before);

    let abandoned = abandoned_directory(&snapshot_parent(root.path()))?;
    fault::fail_next_cursor_write(rustix::io::Errno::NOSPC.raw_os_error());
    require_no_space(reclaim_abandoned(Some(root.path())))?;
    assert!(!abandoned.exists());
    assert_eq!(fs::read(cursor_path(root.path()))?, before);

    SnapshotFileBacking::create_in(root.path())?.close()?;
    assert_whole_private_cursor(root.path())
}

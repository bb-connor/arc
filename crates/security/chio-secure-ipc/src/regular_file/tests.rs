use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;

use super::OpenPolicy::{Authenticated, Private, Trusted};
use super::RegularFileError::{Exposed, ForeignOwner, Writable};
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const LIMIT: usize = 64;
const POLICIES: [OpenPolicy; 3] = [Authenticated, Trusted, Private];

fn private_file(directory: &Path, bytes: &[u8]) -> std::io::Result<std::path::PathBuf> {
    let path = directory.join("input.json");
    std::fs::write(&path, bytes)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(path)
}

#[test]
fn ownership_rules_by_policy() {
    const EUID: u32 = 1000;
    let cases = [
        (Trusted, EUID, 0o100644, None),
        (Trusted, 0, 0o100644, None),
        (Trusted, 0, 0o100444, None),
        (Trusted, 1001, 0o100644, Some(ForeignOwner { uid: 1001 })),
        (Trusted, 0, 0o100664, Some(Writable { mode: 0o664 })),
        (Trusted, EUID, 0o100646, Some(Writable { mode: 0o646 })),
        (Private, EUID, 0o100600, None),
        (Private, EUID, 0o100400, None),
        (Private, 0, 0o100600, Some(ForeignOwner { uid: 0 })),
        (Private, EUID, 0o100640, Some(Exposed { mode: 0o640 })),
        (Private, EUID, 0o100604, Some(Exposed { mode: 0o604 })),
        (Authenticated, EUID, 0o100666, None),
        (Authenticated, 1001, 0o100600, None),
        (Authenticated, 0, 0o100777, None),
        (Authenticated, 1001, 0o104755, None),
    ];
    for (policy, uid, mode, expected) in cases {
        assert_eq!(
            check_ownership(policy, uid, mode, EUID).err(),
            expected,
            "{policy:?} uid {uid} mode {mode:o}"
        );
    }
}

#[test]
fn a_file_at_the_ceiling_reads_whole_and_one_byte_more_is_too_large() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = private_file(directory.path(), &[b' '; LIMIT])?;
    for policy in POLICIES {
        assert_eq!(read_regular_file(&path, LIMIT, policy)?.len(), LIMIT);
        assert_eq!(
            read_regular_file(&path, LIMIT - 1, policy),
            Err(RegularFileError::TooLarge {
                max_bytes: LIMIT - 1
            })
        );
    }
    Ok(())
}

#[test]
fn symlink_directory_and_missing_paths_are_refused_under_every_policy() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = private_file(directory.path(), b"{}")?;
    let link = directory.path().join("link.json");
    std::os::unix::fs::symlink(&path, &link)?;
    let absent = directory.path().join("absent.json");
    for policy in POLICIES {
        let read = |path: &Path| read_regular_file(path, LIMIT, policy);
        assert_eq!(read(&link), Err(RegularFileError::SymbolicLink));
        assert_eq!(read(directory.path()), Err(RegularFileError::NotRegular));
        assert_eq!(read(&absent), Err(RegularFileError::Missing));
    }
    Ok(())
}

#[test]
fn fifo_without_a_writer_is_refused_without_blocking() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("input.fifo");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &path,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )?;
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let _ = sender.send(read_regular_file(&path, LIMIT, Authenticated));
    });
    let result = receiver.recv_timeout(std::time::Duration::from_secs(5))?;
    assert!(reader.join().is_ok(), "file reader panicked");
    assert_eq!(result, Err(RegularFileError::NotRegular));
    Ok(())
}

#[test]
fn io_errors_keep_their_kind() {
    let from = |kind: ErrorKind| RegularFileError::from(std::io::Error::from(kind));
    assert_eq!(
        from(ErrorKind::PermissionDenied),
        RegularFileError::Io(ErrorKind::PermissionDenied)
    );
    assert_eq!(from(ErrorKind::NotFound), RegularFileError::Missing);
}

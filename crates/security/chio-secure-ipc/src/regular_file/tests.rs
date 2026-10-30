use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;

use super::OpenPolicy::{Authenticated, Private, Trusted};
use super::RegularFileError::{Exposed, ForeignOwner, MultiplyLinked, Writable};
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
        (Trusted, EUID, 0o100644, 1, None),
        (Trusted, 0, 0o100644, 1, None),
        (Trusted, 0, 0o100444, 1, None),
        (Trusted, 1001, 0o100644, 1, Some(ForeignOwner { uid: 1001 })),
        (Trusted, 0, 0o100664, 1, Some(Writable { mode: 0o664 })),
        (Trusted, EUID, 0o100646, 1, Some(Writable { mode: 0o646 })),
        (Private, EUID, 0o100600, 1, None),
        (Private, EUID, 0o100400, 1, None),
        (Private, 0, 0o100600, 1, Some(ForeignOwner { uid: 0 })),
        (Private, EUID, 0o100640, 1, Some(Exposed { mode: 0o640 })),
        (Private, EUID, 0o100604, 1, Some(Exposed { mode: 0o604 })),
        (Private, EUID, 0o100700, 1, Some(Exposed { mode: 0o700 })),
        (Private, EUID, 0o104600, 1, Some(Exposed { mode: 0o4600 })),
        (Trusted, EUID, 0o100700, 1, None),
        (
            Private,
            EUID,
            0o100600,
            2,
            Some(MultiplyLinked { links: 2 }),
        ),
        (Trusted, EUID, 0o100644, 2, None),
        (Authenticated, EUID, 0o100600, 3, None),
        (Authenticated, EUID, 0o100666, 1, None),
        (Authenticated, 1001, 0o100600, 1, None),
        (Authenticated, 0, 0o100777, 1, None),
        (Authenticated, 1001, 0o104755, 1, None),
    ];
    for (policy, uid, mode, links, expected) in cases {
        assert_eq!(
            check_ownership(policy, uid, mode, links, EUID).err(),
            expected,
            "{policy:?} uid {uid} mode {mode:o} links {links}"
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
fn an_owner_executable_secret_is_refused_as_private() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = private_file(directory.path(), b"{}")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    assert_eq!(
        read_regular_file(&path, LIMIT, Private),
        Err(Exposed { mode: 0o700 })
    );
    Ok(())
}

fn streamed(bytes: &[u8]) -> std::io::Result<File> {
    use std::io::Write;
    let (reader, mut writer) = std::os::unix::net::UnixStream::pair()?;
    writer.write_all(bytes)?;
    Ok(File::from(std::os::fd::OwnedFd::from(reader)))
}

#[test]
fn an_unsized_stream_grows_its_buffer_up_to_the_ceiling() -> TestResult {
    assert_eq!(read_opened(streamed(&[b' '; LIMIT])?, LIMIT)?.len(), LIMIT);
    for len in [LIMIT + 1, LIMIT * 3] {
        assert_eq!(
            read_opened(streamed(&vec![b' '; len])?, LIMIT),
            Err(RegularFileError::TooLarge { max_bytes: LIMIT })
        );
    }
    Ok(())
}

#[test]
fn a_hard_linked_secret_is_refused_only_as_private() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = private_file(directory.path(), b"{}")?;
    std::fs::hard_link(&path, directory.path().join("second.json"))?;
    assert_eq!(
        read_regular_file(&path, LIMIT, Private),
        Err(MultiplyLinked { links: 2 })
    );
    assert_eq!(read_regular_file(&path, LIMIT, Trusted)?.as_slice(), b"{}");
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

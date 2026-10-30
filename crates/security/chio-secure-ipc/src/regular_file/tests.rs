use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const LIMIT: usize = 64;
const POLICIES: [OpenPolicy; 3] = [
    OpenPolicy::Authenticated,
    OpenPolicy::Trusted,
    OpenPolicy::Private,
];

fn file_with_mode(
    directory: &Path,
    bytes: &[u8],
    mode: u32,
) -> std::io::Result<std::path::PathBuf> {
    let path = directory.join("input.json");
    std::fs::write(&path, bytes)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
    Ok(path)
}

#[test]
fn ownership_rules_by_policy() {
    const EUID: u32 = 1000;
    let cases: [(OpenPolicy, u32, u32, Option<RegularFileError>); 15] = [
        (OpenPolicy::Trusted, EUID, 0o100644, None),
        (OpenPolicy::Trusted, 0, 0o100644, None),
        (OpenPolicy::Trusted, 0, 0o100444, None),
        (
            OpenPolicy::Trusted,
            1001,
            0o100644,
            Some(RegularFileError::ForeignOwner { uid: 1001 }),
        ),
        (
            OpenPolicy::Trusted,
            0,
            0o100664,
            Some(RegularFileError::Writable { mode: 0o664 }),
        ),
        (
            OpenPolicy::Trusted,
            EUID,
            0o100646,
            Some(RegularFileError::Writable { mode: 0o646 }),
        ),
        (OpenPolicy::Private, EUID, 0o100600, None),
        (OpenPolicy::Private, EUID, 0o100400, None),
        (
            OpenPolicy::Private,
            0,
            0o100600,
            Some(RegularFileError::ForeignOwner { uid: 0 }),
        ),
        (
            OpenPolicy::Private,
            EUID,
            0o100640,
            Some(RegularFileError::Exposed { mode: 0o640 }),
        ),
        (
            OpenPolicy::Private,
            EUID,
            0o100604,
            Some(RegularFileError::Exposed { mode: 0o604 }),
        ),
        (OpenPolicy::Authenticated, EUID, 0o100666, None),
        (OpenPolicy::Authenticated, 1001, 0o100600, None),
        (OpenPolicy::Authenticated, 0, 0o100777, None),
        (OpenPolicy::Authenticated, 1001, 0o104755, None),
    ];
    for (policy, uid, mode, expected) in cases {
        let actual = check_ownership(policy, uid, mode, EUID);
        let matched = match (&actual, &expected) {
            (Ok(()), None) => true,
            (
                Err(RegularFileError::ForeignOwner { uid: actual }),
                Some(RegularFileError::ForeignOwner { uid: expected }),
            ) => actual == expected,
            (
                Err(RegularFileError::Writable { mode: actual }),
                Some(RegularFileError::Writable { mode: expected }),
            )
            | (
                Err(RegularFileError::Exposed { mode: actual }),
                Some(RegularFileError::Exposed { mode: expected }),
            ) => actual == expected,
            _ => false,
        };
        assert!(
            matched,
            "{policy:?} uid {uid} mode {mode:o}: {actual:?}, want {expected:?}"
        );
    }
}

#[test]
fn a_file_at_the_ceiling_reads_whole_and_one_byte_more_is_too_large() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = file_with_mode(directory.path(), &[b' '; LIMIT], 0o600)?;
    for policy in POLICIES {
        assert_eq!(read_regular_file(&path, LIMIT, policy)?.len(), LIMIT);
        assert!(matches!(
            read_regular_file(&path, LIMIT - 1, policy),
            Err(RegularFileError::TooLarge { max_bytes }) if max_bytes == LIMIT - 1
        ));
    }
    assert!(matches!(
        read_regular_file(&path, 0, OpenPolicy::Authenticated),
        Err(RegularFileError::TooLarge { max_bytes: 0 })
    ));
    Ok(())
}

#[test]
fn symlink_directory_and_missing_paths_are_refused_under_every_policy() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = file_with_mode(directory.path(), b"{}", 0o600)?;
    let link = directory.path().join("link.json");
    std::os::unix::fs::symlink(&path, &link)?;
    for policy in POLICIES {
        assert!(matches!(
            read_regular_file(&link, LIMIT, policy),
            Err(RegularFileError::SymbolicLink)
        ));
        assert!(matches!(
            read_regular_file(directory.path(), LIMIT, policy),
            Err(RegularFileError::NotRegular)
        ));
        assert!(matches!(
            read_regular_file(&directory.path().join("absent.json"), LIMIT, policy),
            Err(RegularFileError::Missing)
        ));
    }
    assert_eq!(std::fs::read(path)?, b"{}");
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
        let _ = sender.send(read_regular_file(&path, LIMIT, OpenPolicy::Authenticated));
    });
    let result = receiver.recv_timeout(std::time::Duration::from_secs(5))?;
    assert!(reader.join().is_ok(), "file reader panicked");
    assert!(matches!(result, Err(RegularFileError::NotRegular)));
    Ok(())
}

#[test]
fn opened_file_modes_are_checked_against_the_policy() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = file_with_mode(directory.path(), b"{}", 0o644)?;
    assert_eq!(read_regular_file(&path, LIMIT, OpenPolicy::Trusted)?, b"{}");
    assert!(matches!(
        read_regular_file(&path, LIMIT, OpenPolicy::Private),
        Err(RegularFileError::Exposed { mode: 0o644 })
    ));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o620))?;
    assert!(matches!(
        read_regular_file(&path, LIMIT, OpenPolicy::Trusted),
        Err(RegularFileError::Writable { mode: 0o620 })
    ));
    assert_eq!(
        read_regular_file(&path, LIMIT, OpenPolicy::Authenticated)?,
        b"{}"
    );
    Ok(())
}

#[test]
fn io_errors_keep_their_kind() {
    assert!(matches!(
        RegularFileError::from(std::io::Error::from(ErrorKind::PermissionDenied)),
        RegularFileError::Io(ErrorKind::PermissionDenied)
    ));
    assert!(matches!(
        RegularFileError::from(std::io::Error::from(ErrorKind::NotFound)),
        RegularFileError::Missing
    ));
}

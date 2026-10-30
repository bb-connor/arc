use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const LIMIT: usize = 64;

fn private_file(directory: &Path, name: &str, bytes: &[u8]) -> std::io::Result<std::path::PathBuf> {
    let path = directory.join(name);
    std::fs::write(&path, bytes)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(path)
}

#[test]
fn regular_file_preserves_original_bytes() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let bytes = b"{ \"amount\":18446744073709551615 }\n";
    let path = private_file(directory.path(), "input.json", bytes)?;
    for policy in [FilePolicy::Private, FilePolicy::Trusted] {
        assert_eq!(read_regular(&path, policy, LIMIT)?, bytes);
    }
    Ok(())
}

#[test]
fn directory_is_refused_before_reading() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    assert!(matches!(
        read_regular(directory.path(), FilePolicy::Trusted, LIMIT),
        Err(RegularFileError::NotRegular)
    ));
    Ok(())
}

#[test]
fn symbolic_link_is_refused() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = private_file(directory.path(), "input.json", b"{}")?;
    let link = directory.path().join("link.json");
    std::os::unix::fs::symlink(&path, &link)?;
    assert!(matches!(
        read_regular(&link, FilePolicy::Trusted, LIMIT),
        Err(RegularFileError::Symlink)
    ));
    assert_eq!(std::fs::read(path)?, b"{}");
    Ok(())
}

#[test]
fn size_is_refused_one_byte_past_the_limit() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = private_file(directory.path(), "input.json", b"")?;
    std::fs::File::options()
        .write(true)
        .open(&path)?
        .set_len(u64::try_from(LIMIT)?)?;
    assert_eq!(
        read_regular(&path, FilePolicy::Trusted, LIMIT)?.len(),
        LIMIT
    );
    std::fs::File::options()
        .write(true)
        .open(&path)?
        .set_len(u64::try_from(LIMIT + 4096)?)?;
    assert!(matches!(
        read_regular(&path, FilePolicy::Trusted, LIMIT),
        Err(RegularFileError::TooLarge { max_bytes: LIMIT })
    ));
    assert!(matches!(
        read_regular(&path, FilePolicy::Trusted, 0),
        Err(RegularFileError::TooLarge { max_bytes: 0 })
    ));
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
        let _ = sender.send(read_regular(&path, FilePolicy::Trusted, LIMIT));
    });
    let result = receiver.recv_timeout(std::time::Duration::from_secs(5))?;
    assert!(reader.join().is_ok(), "file reader panicked");
    assert!(matches!(result, Err(RegularFileError::NotRegular)));
    Ok(())
}

#[test]
fn missing_file_is_not_found() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    assert!(matches!(
        read_regular(
            &directory.path().join("absent.json"),
            FilePolicy::Trusted,
            LIMIT
        ),
        Err(RegularFileError::Io(ErrorKind::NotFound))
    ));
    Ok(())
}

#[test]
fn trusted_policy_refuses_a_group_or_world_writable_file() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = private_file(directory.path(), "config.json", b"{}")?;
    for mode in [0o620, 0o602] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
        assert!(
            matches!(
                read_regular(&path, FilePolicy::Trusted, LIMIT),
                Err(RegularFileError::Writable)
            ),
            "{mode:o}"
        );
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    assert_eq!(read_regular(&path, FilePolicy::Trusted, LIMIT)?, b"{}");
    Ok(())
}

#[test]
fn private_policy_refuses_any_group_or_other_access() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = private_file(directory.path(), "secret", b"seed")?;
    for mode in [0o640, 0o604] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
        assert!(
            matches!(
                read_regular(&path, FilePolicy::Private, LIMIT),
                Err(RegularFileError::Exposed)
            ),
            "{mode:o}"
        );
    }
    Ok(())
}

#[test]
fn owner_rules_accept_root_only_for_trusted_files() {
    const EUID: u32 = 1000;
    assert!(check_policy(FilePolicy::Trusted, 0, 0o644, EUID).is_ok());
    assert!(check_policy(FilePolicy::Trusted, EUID, 0o644, EUID).is_ok());
    assert!(matches!(
        check_policy(FilePolicy::Trusted, 1001, 0o644, EUID),
        Err(RegularFileError::ForeignOwner)
    ));
    assert!(matches!(
        check_policy(FilePolicy::Private, 0, 0o600, EUID),
        Err(RegularFileError::ForeignOwner)
    ));
    assert!(check_policy(FilePolicy::Private, EUID, 0o600, EUID).is_ok());
    assert!(check_policy(FilePolicy::Private, EUID, 0o400, EUID).is_ok());
}

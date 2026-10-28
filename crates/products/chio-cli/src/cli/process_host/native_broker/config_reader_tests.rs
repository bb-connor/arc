use super::*;
use std::os::unix::fs::PermissionsExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn host_reader_signer_fifo_is_refused_without_blocking() -> TestResult {
    super::super::super::artifact_reader_tests::fifo_refusal(|path, _| {
        read_signer(path, &chio_core_types::Keypair::generate().public_key()).map(|_| ())
    })
}

#[test]
fn host_reader_signer_regular_seed_and_pin_controls() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("seed");
    let seed = "01".repeat(32);
    let key = chio_core_types::Keypair::from_seed_hex(&seed)?;
    std::fs::write(&path, format!("{seed}\n"))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    read_signer(&path, &key.public_key())?;
    let wrong = chio_core_types::Keypair::from_seed_hex(&"02".repeat(32))?;
    let Err(CliError::Chio(failure)) = read_signer(&path, &wrong.public_key()) else {
        return Err("wrong signing pin accepted or wrong refusal type".into());
    };
    assert_eq!(
        failure.message(),
        "process host: broker authority seed differs from the operator's signing-key pin"
    );
    std::fs::write(&path, format!("{seed}\n\n"))?;
    let Err(CliError::Chio(failure)) = read_signer(&path, &key.public_key()) else {
        return Err("oversized seed accepted or wrong refusal type".into());
    };
    assert_eq!(
        failure.message(),
        "process host: broker authority seed is oversized"
    );
    Ok(())
}

type MetadataHook = Box<dyn FnOnce(&Path) -> Result<(), CliError>>;

thread_local! {
    static AFTER_METADATA: std::cell::RefCell<Option<MetadataHook>> = const { std::cell::RefCell::new(None) };
}

pub(super) fn after_open_metadata(path: &Path) -> Result<(), CliError> {
    let hook = AFTER_METADATA.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(path)?;
    }
    Ok(())
}

struct MetadataGuard;

impl Drop for MetadataGuard {
    fn drop(&mut self) {
        AFTER_METADATA.with(|slot| slot.borrow_mut().take());
    }
}

#[test]
fn host_reader_signer_refuses_growth_after_metadata() -> TestResult {
    use std::io::Write;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("seed");
    let seed = "01".repeat(32);
    let key = chio_core_types::Keypair::from_seed_hex(&seed)?;
    std::fs::write(&path, format!("{seed}\n"))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let _guard = MetadataGuard;
    AFTER_METADATA.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(|path| {
            std::fs::OpenOptions::new()
                .append(true)
                .open(path)?
                .write_all(b"\n")?;
            Ok(())
        }));
    });
    let result = read_signer(&path, &key.public_key());
    assert!(AFTER_METADATA.with(|slot| slot.borrow().is_none()));
    let Err(CliError::Chio(failure)) = result else {
        return Err("seed growth beyond the read bound was accepted".into());
    };
    assert_eq!(
        failure.message(),
        "process host: broker authority seed is oversized"
    );
    Ok(())
}

#[test]
fn host_reader_signer_preserves_private_file_checks() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("seed");
    let alias = directory.path().join("alias");
    let seed = "01".repeat(32);
    let key = chio_core_types::Keypair::from_seed_hex(&seed)?;
    std::fs::write(&path, &seed)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    let Err(CliError::Chio(failure)) = read_signer(&path, &key.public_key()) else {
        return Err("nonprivate seed accepted".into());
    };
    assert_eq!(
        failure.message(),
        "process host: broker authority seed must be a private regular file owned by the host"
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    std::fs::hard_link(&path, &alias)?;
    let Err(CliError::Chio(failure)) = read_signer(&path, &key.public_key()) else {
        return Err("hardlinked seed accepted".into());
    };
    assert_eq!(
        failure.message(),
        "process host: broker authority seed must be a private regular file owned by the host"
    );
    std::fs::remove_file(&alias)?;
    std::os::unix::fs::symlink(&path, &alias)?;
    let Err(CliError::Io(failure)) = read_signer(&alias, &key.public_key()) else {
        return Err("symlink seed accepted".into());
    };
    assert_eq!(failure.raw_os_error(), Some(libc::ELOOP));
    read_signer(&path, &key.public_key())?;
    Ok(())
}

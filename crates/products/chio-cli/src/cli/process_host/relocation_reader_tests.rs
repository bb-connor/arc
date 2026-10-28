use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn canonical_tempdir() -> std::io::Result<tempfile::TempDir> {
    tempfile::tempdir_in(std::env::temp_dir().canonicalize()?)
}

#[test]
fn relocation_artifact_fifo_is_refused_without_blocking() -> TestResult {
    super::super::artifact_reader_tests::fifo_refusal(|path, _| digest(path).map(|_| ()))
}

#[test]
fn relocation_digest_accepts_regular_bytes_and_refuses_symlinks() -> TestResult {
    let directory = canonical_tempdir()?;
    let artifact = directory.path().join("artifact");
    let alias = directory.path().join("alias");
    std::fs::write(&artifact, b"abc")?;
    assert_eq!(
        digest(&artifact)?,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    std::os::unix::fs::symlink(&artifact, &alias)?;
    let Err(CliError::Io(error)) = digest(&alias) else {
        return Err("expected symlink open refusal".into());
    };
    assert_eq!(error.raw_os_error(), Some(libc::ELOOP));
    Ok(())
}

#[test]
fn relocation_digest_refuses_growth_and_truncation_after_handle_metadata() -> TestResult {
    for changed_length in [2, 4] {
        let directory = canonical_tempdir()?;
        let artifact = directory.path().join("artifact");
        std::fs::write(&artifact, b"abc")?;
        let file = crate::input::open_regular(&artifact)?;
        let expected = file.metadata()?.len();
        assert_eq!(expected, 3);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&artifact)?
            .set_len(changed_length)?;
        let Err(CliError::Io(error)) = digest_file(file, expected) else {
            return Err("expected changed relocation length refusal".into());
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "relocation file length changed while hashing"
        );
    }
    Ok(())
}

type BeforeDescend = Box<dyn FnOnce(&Path) -> Result<(), CliError>>;

thread_local! {
    static BEFORE_FILE_OPEN: std::cell::RefCell<Option<BeforeDescend>> = const { std::cell::RefCell::new(None) };
    static BEFORE_DESCEND: std::cell::RefCell<Option<BeforeDescend>> = const { std::cell::RefCell::new(None) };
}

pub(super) fn before_descend(path: &Path) -> Result<(), CliError> {
    let callback = BEFORE_DESCEND.with(|slot| slot.borrow_mut().take());
    if let Some(callback) = callback {
        callback(path)?;
    }
    Ok(())
}

pub(super) fn before_file_open(path: &Path) -> Result<(), CliError> {
    let callback = BEFORE_FILE_OPEN.with(|slot| slot.borrow_mut().take());
    if let Some(callback) = callback {
        callback(path)?;
    }
    Ok(())
}

struct DescendHook;

impl Drop for DescendHook {
    fn drop(&mut self) {
        BEFORE_FILE_OPEN.with(|slot| {
            slot.borrow_mut().take();
        });
        BEFORE_DESCEND.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

#[test]
fn relocation_walk_accepts_nested_regular_files() -> TestResult {
    let root = canonical_tempdir()?;
    std::fs::create_dir(root.path().join("nested"))?;
    std::fs::write(root.path().join("nested/artifact"), b"abc")?;
    let files = digests(root.path(), SidecarPolicy::Sealed)?;
    assert_eq!(files.len(), 1);
    assert_eq!(
        files.get("nested/artifact").map(String::as_str),
        Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    Ok(())
}

#[test]
fn relocation_walk_refuses_directory_replaced_by_symlink_before_descent() -> TestResult {
    let root = canonical_tempdir()?;
    let outside = canonical_tempdir()?;
    let moved = canonical_tempdir()?;
    std::fs::create_dir(root.path().join("nested"))?;
    std::fs::write(root.path().join("nested/artifact"), b"inside")?;
    std::fs::write(outside.path().join("artifact"), b"outside")?;
    let outside_path = outside.path().to_path_buf();
    let moved_path = moved.path().join("original");
    let _hook = DescendHook;
    BEFORE_DESCEND.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move |path| {
            std::fs::rename(path, &moved_path)?;
            std::os::unix::fs::symlink(&outside_path, path)?;
            Ok(())
        }))
    });
    let result = digests(root.path(), SidecarPolicy::Sealed);
    assert!(BEFORE_DESCEND.with(|slot| slot.borrow().is_none()));
    let Err(CliError::Chio(error)) = result else {
        return Err("directory replacement was followed or returned the wrong error type".into());
    };
    assert_eq!(
        error.message(),
        "process host: relocation directory is not a nonsymlink directory: nested"
    );
    assert_eq!(std::fs::read(outside.path().join("artifact"))?, b"outside");
    Ok(())
}

#[test]
fn relocation_walk_refuses_directory_replaced_by_regular_file() -> TestResult {
    let root = canonical_tempdir()?;
    let moved = canonical_tempdir()?;
    std::fs::create_dir(root.path().join("nested"))?;
    let moved_path = moved.path().join("original");
    let _hook = DescendHook;
    BEFORE_DESCEND.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move |path| {
            std::fs::rename(path, &moved_path)?;
            std::fs::write(path, b"not a directory")?;
            Ok(())
        }));
    });
    let Err(CliError::Chio(error)) = digests(root.path(), SidecarPolicy::Sealed) else {
        return Err("expected directory replacement refusal".into());
    };
    assert_eq!(
        error.message(),
        "process host: relocation directory is not a nonsymlink directory: nested"
    );
    Ok(())
}

#[test]
fn relocation_walk_preserves_root_exclusions_and_sidecar_policy() -> TestResult {
    let root = canonical_tempdir()?;
    std::fs::create_dir(root.path().join("run-sockets"))?;
    std::fs::create_dir(root.path().join("nested"))?;
    for name in [
        "host.lock",
        "relocation.json",
        "run-sockets/socket",
        "nested/host.lock",
        "authority.db",
    ] {
        std::fs::write(root.path().join(name), b"abc")?;
    }
    std::fs::write(root.path().join("authority.db-wal"), b"pending")?;
    let checkpointable = digests(root.path(), SidecarPolicy::Checkpointable)?;
    assert_eq!(
        checkpointable
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["authority.db", "nested/host.lock"]
    );
    assert_eq!(
        digests(root.path(), SidecarPolicy::CommittedImport)?,
        checkpointable
    );
    let Err(CliError::Chio(error)) = digests(root.path(), SidecarPolicy::Sealed) else {
        return Err("expected nonempty WAL refusal".into());
    };
    assert_eq!(
        error.message(),
        "process host: unverified SQLite sidecar: authority.db-wal"
    );
    std::fs::write(root.path().join("authority.db-wal"), b"")?;
    assert_eq!(digests(root.path(), SidecarPolicy::Sealed)?, checkpointable);
    Ok(())
}

#[test]
fn relocation_walk_refuses_static_symlinks() -> TestResult {
    let root = canonical_tempdir()?;
    let outside = canonical_tempdir()?;
    std::fs::write(outside.path().join("database"), b"outside")?;
    std::os::unix::fs::symlink(
        outside.path().join("database"),
        root.path().join("authority.db"),
    )?;
    let result = digests(root.path(), SidecarPolicy::Sealed);
    let Err(CliError::Chio(error)) = result else {
        return Err("expected sidecar database symlink refusal".into());
    };
    assert_eq!(
        error.message(),
        "process host: host state must not contain symlinks: authority.db"
    );
    Ok(())
}

#[test]
fn relocation_walk_refuses_symlinks_in_root_components() -> TestResult {
    let root = canonical_tempdir()?;
    let outside = canonical_tempdir()?;
    std::fs::create_dir(outside.path().join("inner"))?;
    std::fs::write(outside.path().join("inner/artifact"), b"outside")?;
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(outside.path(), &alias)?;
    let Err(CliError::Chio(error)) = digests(&alias.join("inner"), SidecarPolicy::Sealed) else {
        return Err("expected root component symlink refusal".into());
    };
    let label = alias
        .strip_prefix("/")?
        .to_str()
        .ok_or("fixture path is not UTF-8")?;
    assert_eq!(
        error.message(),
        format!("process host: relocation directory is not a nonsymlink directory: {label}")
    );
    Ok(())
}

#[test]
fn relocation_walk_refuses_parent_components() -> TestResult {
    let root = canonical_tempdir()?;
    let Err(CliError::Chio(error)) = digests(&root.path().join(".."), SidecarPolicy::Sealed) else {
        return Err("expected parent component refusal".into());
    };
    assert_eq!(
        error.message(),
        "process host: relocation root contains a parent or platform prefix component"
    );
    Ok(())
}

#[test]
fn relocation_walk_labels_file_replaced_by_symlink_before_open() -> TestResult {
    let root = canonical_tempdir()?;
    let outside = canonical_tempdir()?;
    std::fs::write(root.path().join("artifact"), b"inside")?;
    let outside_path = outside.path().join("artifact");
    std::fs::write(&outside_path, b"outside")?;
    let moved_path = outside.path().join("original");
    let _hook = DescendHook;
    BEFORE_FILE_OPEN.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move |path| {
            std::fs::rename(path, &moved_path)?;
            std::os::unix::fs::symlink(&outside_path, path)?;
            Ok(())
        }));
    });
    let result = digests(root.path(), SidecarPolicy::Sealed);
    assert!(BEFORE_FILE_OPEN.with(|slot| slot.borrow().is_none()));
    let Err(CliError::Chio(error)) = result else {
        return Err("expected labeled file symlink refusal".into());
    };
    assert_eq!(
        error.message(),
        "process host: host state must not contain symlinks: artifact"
    );
    assert_eq!(std::fs::read(outside.path().join("artifact"))?, b"outside");
    Ok(())
}

#[test]
fn relocation_walk_bounds_directory_depth() -> TestResult {
    let root = canonical_tempdir()?;
    let mut nested = root.path().to_path_buf();
    for _ in 0..64 {
        nested.push("d");
        std::fs::create_dir(&nested)?;
    }
    std::fs::write(nested.join("artifact"), b"abc")?;
    let files = digests(root.path(), SidecarPolicy::Sealed)?;
    assert_eq!(files.len(), 1);
    assert_eq!(
        files.values().next().map(String::as_str),
        Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    std::fs::create_dir(nested.join("too-deep"))?;
    let Err(CliError::Chio(error)) = digests(root.path(), SidecarPolicy::Sealed) else {
        return Err("expected relocation depth refusal".into());
    };
    assert_eq!(
        error.message(),
        "process host: relocation directory depth exceeds 64"
    );
    Ok(())
}

#[test]
fn relocation_walk_refuses_file_replaced_by_fifo_without_blocking() -> TestResult {
    use std::os::unix::fs::OpenOptionsExt;
    use std::time::Duration;

    let root = canonical_tempdir()?;
    let moved = canonical_tempdir()?;
    let artifact = root.path().join("artifact");
    std::fs::write(&artifact, b"inside")?;
    let root_path = root.path().to_path_buf();
    let moved_path = moved.path().join("original");
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let _hook = DescendHook;
        BEFORE_FILE_OPEN.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |path| {
                std::fs::rename(path, &moved_path)?;
                if !std::process::Command::new("mkfifo")
                    .arg(path)
                    .status()?
                    .success()
                {
                    return Err(error("fixture FIFO creation failed"));
                }
                Ok(())
            }));
        });
        let outcome = match digests(&root_path, SidecarPolicy::Sealed) {
            Err(CliError::Chio(error)) => Ok(error.message().to_owned()),
            other => Err(format!("expected typed nonregular refusal, got {other:?}")),
        };
        let _ = send.send(outcome);
    });
    let first = receive.recv_timeout(Duration::from_secs(5));
    let timely = first.is_ok();
    let unblock = if timely {
        None
    } else {
        Some(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&artifact)?,
        )
    };
    let outcome = match first {
        Ok(outcome) => outcome,
        Err(_) => receive.recv_timeout(Duration::from_secs(5))?,
    };
    worker.join().map_err(|_| "relocation reader panicked")?;
    drop(unblock);
    assert!(timely, "relocation walk blocked opening a replaced FIFO");
    assert_eq!(
        outcome,
        Ok("process host: host state contains a nonregular file: artifact".to_owned())
    );
    Ok(())
}

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn relocation_artifact_fifo_is_refused_without_blocking() -> TestResult {
    super::super::artifact_reader_tests::fifo_refusal(|path, _| digest(path).map(|_| ()))
}

#[test]
fn relocation_digest_accepts_regular_bytes_and_refuses_symlinks() -> TestResult {
    let directory = tempfile::tempdir()?;
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
        let directory = tempfile::tempdir()?;
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

thread_local! {
    static BEFORE_DESCEND: std::cell::RefCell<Option<Box<dyn FnOnce(&Path) -> Result<(), CliError>>>> = const { std::cell::RefCell::new(None) };
}

pub(super) fn before_descend(path: &Path) -> Result<(), CliError> {
    let callback = BEFORE_DESCEND.with(|slot| slot.borrow_mut().take());
    if let Some(callback) = callback { callback(path)?; }
    Ok(())
}

struct DescendHook;

impl Drop for DescendHook {
    fn drop(&mut self) { BEFORE_DESCEND.with(|slot| { slot.borrow_mut().take(); }); }
}

#[test]
fn relocation_walk_accepts_nested_regular_files() -> TestResult {
    let root = tempfile::tempdir()?;
    std::fs::create_dir(root.path().join("nested"))?;
    std::fs::write(root.path().join("nested/artifact"), b"abc")?;
    let files = digests(root.path(), SidecarPolicy::Sealed)?;
    assert_eq!(files.len(), 1);
    assert_eq!(files.get("nested/artifact").map(String::as_str), Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    Ok(())
}

#[test]
fn relocation_walk_refuses_directory_replaced_by_symlink_before_descent() -> TestResult {
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    let moved = tempfile::tempdir()?;
    std::fs::create_dir(root.path().join("nested"))?;
    std::fs::write(root.path().join("nested/artifact"), b"inside")?;
    std::fs::write(outside.path().join("artifact"), b"outside")?;
    let outside_path = outside.path().to_path_buf();
    let moved_path = moved.path().join("original");
    let _hook = DescendHook;
    BEFORE_DESCEND.with(|slot| *slot.borrow_mut() = Some(Box::new(move |path| {
        std::fs::rename(path, &moved_path)?;
        std::os::unix::fs::symlink(&outside_path, path)?;
        Ok(())
    })));
    let result = digests(root.path(), SidecarPolicy::Sealed);
    assert!(BEFORE_DESCEND.with(|slot| slot.borrow().is_none()));
    let Err(error) = result else { return Err("directory replacement was followed while hashing".into()); };
    assert_eq!(error.to_string(), "process host: relocation directory is not a nonsymlink directory: nested");
    assert_eq!(std::fs::read(outside.path().join("artifact"))?, b"outside");
    Ok(())
}

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

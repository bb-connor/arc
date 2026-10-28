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

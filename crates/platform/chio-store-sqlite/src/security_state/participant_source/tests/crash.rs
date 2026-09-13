use super::*;

#[test]
fn child_process_crash() -> TestResult {
    let Some(path) = std::env::var_os("CHIO_SECURITY_SOURCE_CRASH_FILE") else {
        return Ok(());
    };
    let source = SqliteSecurityParticipantSource::open(std::path::PathBuf::from(path))?;
    let expected = source.preview(&binding()?)?;
    source.seal_exact(&expected)?;
    Err("child did not reach the requested crash cutpoint".into())
}

#[test]
fn independent_process_crash_is_unsealed_before_commit_and_sealed_after_commit() -> TestResult {
    for stage in 1..=5 {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("security.db");
        drop(seed(&path)?);
        let source = SqliteSecurityParticipantSource::open(&path)?;
        let expected = source.preview(&binding()?)?;
        drop(source);
        let output = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "security_state::participant_source::tests::crash::child_process_crash",
                "--nocapture",
            ])
            .env("CHIO_SECURITY_SOURCE_CRASH_STAGE", stage.to_string())
            .env("CHIO_SECURITY_SOURCE_CRASH_FILE", &path)
            .current_dir(directory.path())
            .output()?;
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(
            output.status.signal(),
            Some(6),
            "child must abort at stage {stage}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reopened = SqliteSecurityParticipantSource::open(&path)?;
        assert_eq!(reopened.load_seal()?.is_some(), stage == 5);
        if stage < 5 {
            assert_eq!(reopened.preview(&binding()?)?, expected);
            let legacy = SqliteSecurityStateStore::open(&path)?;
            assert!(legacy.load(&key()?)?.is_some());
        } else {
            reopened.verify_seal(&expected)?;
            assert!(SqliteSecurityStateStore::open(&path).is_err());
        }
        reopened.seal_exact(&expected)?;
        reopened.verify_seal(&expected)?;
    }
    Ok(())
}

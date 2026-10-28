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
    let failure = match read_signer(&path, &wrong.public_key()) {
        Err(failure) => failure,
        Ok(_) => return Err("wrong signing pin accepted".into()),
    };
    assert!(failure
        .to_string()
        .contains("broker authority seed differs from the operator's signing-key pin"));
    std::fs::write(&path, format!("{seed}\n\n"))?;
    let failure = match read_signer(&path, &key.public_key()) {
        Err(failure) => failure,
        Ok(_) => return Err("oversized seed accepted".into()),
    };
    assert!(failure
        .to_string()
        .contains("broker authority seed is oversized"));
    Ok(())
}

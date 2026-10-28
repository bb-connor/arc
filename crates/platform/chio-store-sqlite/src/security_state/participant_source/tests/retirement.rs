use super::*;
use chio_security_types::ports::{PortError, PortErrorKind};

#[test]
fn sealed_source_refuses_legacy_writers_as_retired() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("security.db");
    let _store = seed(&path)?;
    super::super::ensure_legacy_writable(&Connection::open(&path)?)?;
    let source = SqliteSecurityParticipantSource::open(&path)?;
    let expected = source.preview(&binding()?)?;
    source.seal_exact(&expected)?;
    let refusal = super::super::ensure_legacy_writable(&Connection::open(&path)?)
        .err()
        .ok_or("sealed source accepted a legacy writer")?;
    assert_eq!(refusal, PortError::retired());
    assert_eq!(refusal.kind(), PortErrorKind::Conflict);
    assert!(refusal.is_retired());
    Ok(())
}

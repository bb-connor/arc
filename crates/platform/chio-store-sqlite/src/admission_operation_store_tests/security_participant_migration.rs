use std::cell::Cell;

use super::*;
#[cfg(unix)]
use crate::security_state::SqliteSecurityParticipantSource;

#[path = "security_participant_migration/barrier.rs"]
mod barrier;
#[cfg(unix)]
#[path = "security_participant_migration/cutpoints.rs"]
mod cutpoints;
#[cfg(unix)]
#[path = "security_participant_migration/integrity.rs"]
mod integrity;
#[cfg(unix)]
#[path = "security_participant_migration/lifecycle.rs"]
mod lifecycle;
#[cfg(unix)]
#[path = "security_participant_migration/owner_restart.rs"]
mod owner_restart;
#[cfg(unix)]
#[path = "security_participant_migration/source_integrity.rs"]
mod source_integrity;

thread_local! { static FAIL_AFTER: Cell<u8> = const { Cell::new(0) }; }

pub(crate) fn cutpoint(stage: u8) -> Result<(), AdmissionOperationStoreError> {
    if FAIL_AFTER.get() == stage {
        return Err(invariant("injected security destination cutpoint"));
    }
    crash_cutpoint(stage);
    Ok(())
}

pub(crate) fn crash_cutpoint(stage: u8) {
    if std::env::var("CHIO_SECURITY_DESTINATION_CRASH_STAGE")
        .ok()
        .as_deref()
        == Some(stage.to_string().as_str())
    {
        std::process::abort();
    }
}

#[cfg(unix)]
struct ResetCutpoint;
#[cfg(unix)]
impl Drop for ResetCutpoint {
    fn drop(&mut self) {
        FAIL_AFTER.set(0);
    }
}

#[cfg(unix)]
fn authority_id() -> AdmissionIdentifier {
    identifier("security_authority_id", "security-authority")
}

#[cfg(unix)]
fn source(fixture: &Fixture) -> AnchoredTestResult<SqliteSecurityParticipantSource> {
    let path = fixture._temp.path().join("security-source.db");
    drop(crate::security_state::seeded_security_history(&path)?);
    Ok(SqliteSecurityParticipantSource::open(path)?)
}

#[cfg(unix)]
fn pin(
    fixture: &Fixture,
    source: &SqliteSecurityParticipantSource,
) -> AnchoredTestResult<SecurityParticipantMigrationRecord> {
    Ok(fixture.store.expect_security_participant_source(
        &identifier("source_id", "private-source"),
        &authority_id(),
        source,
        &fixture.fence,
        now_ms(),
    )?)
}

#[cfg(unix)]
fn import(
    fixture: &Fixture,
    source: &SqliteSecurityParticipantSource,
    expected: &SecurityParticipantMigrationRecord,
) -> AnchoredTestResult<SecurityParticipantMigrationRecord> {
    Ok(fixture.store.import_security_participant_source(
        &authority_id(),
        expected.expectation_id(),
        source,
        &fixture.fence,
        now_ms(),
    )?)
}

#[cfg(unix)]
fn load(fixture: &Fixture) -> AnchoredTestResult<Option<SecurityParticipantMigrationRecord>> {
    Ok(fixture.store.load_security_participant_migration(
        &authority_id(),
        &fixture.fence,
        now_ms(),
    )?)
}

#[cfg(unix)]
fn global_count(fixture: &Fixture) -> AnchoredTestResult<i64> {
    Ok(fixture.store.connection()?.query_row(
        "SELECT COUNT(*) FROM authority_global_commits",
        [],
        |row| row.get(0),
    )?)
}

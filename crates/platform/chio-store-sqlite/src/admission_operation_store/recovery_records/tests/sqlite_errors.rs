//! SQLite failures reach the global chain as `SqliteServingOwnerError::Sqlite`,
//! never as integrity refusals.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rusqlite::ErrorCode;

use crate::serving_owner::SqliteServingOwnerError;

use super::super::history::stored_event_at;
use super::super::{projection_reference, RecordKind};
use super::fixture::{Ledger, TestResult};

const KEY: &str = "deployment:a";

/// Run `projection_reference` with a progress hook that lets `allowed` VM
/// steps run and interrupts the next one, then remove the hook.
fn interrupted_after(
    ledger: &Ledger,
    allowed: usize,
) -> Result<Result<String, SqliteServingOwnerError>, rusqlite::Error> {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    ledger.connection.progress_handler(
        1,
        Some(move || counter.fetch_add(1, Ordering::Relaxed) >= allowed),
    )?;
    let result = projection_reference(&ledger.connection, KEY, 1);
    ledger
        .connection
        .progress_handler(0, None::<fn() -> bool>)?;
    Ok(result)
}

/// VM steps the bounded event lookup alone takes.
fn event_lookup_steps(ledger: &Ledger) -> Result<usize, Box<dyn std::error::Error>> {
    let steps = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&steps);
    ledger.connection.progress_handler(
        1,
        Some(move || {
            counter.fetch_add(1, Ordering::Relaxed);
            false
        }),
    )?;
    let row = stored_event_at(&ledger.connection, KEY, 1);
    ledger
        .connection
        .progress_handler(0, None::<fn() -> bool>)?;
    row?.ok_or("event is absent")?;
    Ok(steps.load(Ordering::Relaxed))
}

fn assert_interrupted(result: Result<String, SqliteServingOwnerError>) {
    match result {
        Err(SqliteServingOwnerError::Sqlite(rusqlite::Error::SqliteFailure(
            error,
            Some(message),
        )))
        | Err(SqliteServingOwnerError::Sqlite(rusqlite::Error::SqlInputError {
            error,
            msg: message,
            ..
        })) => {
            assert_eq!(error.code, ErrorCode::OperationInterrupted);
            assert_eq!(error.extended_code, rusqlite::ffi::SQLITE_INTERRUPT);
            assert_eq!(message, "interrupted");
        }
        other => panic!("expected an interrupted SQLite query, got {other:?}"),
    }
}

#[test]
fn projection_reference_propagates_interrupts_from_both_of_its_queries() -> TestResult {
    let mut ledger = Ledger::new()?;
    let published = ledger.publish(KEY, RecordKind::Deployment, b"{}", None)?;
    let steps = event_lookup_steps(&ledger)?;
    assert!(steps > 0, "the progress hook observed no event lookup work");
    assert_interrupted(interrupted_after(&ledger, 0)?);
    assert_interrupted(interrupted_after(&ledger, steps)?);
    assert_eq!(
        interrupted_after(&ledger, usize::MAX)??,
        published.event_digest
    );
    assert_eq!(
        projection_reference(&ledger.connection, KEY, 1)?,
        published.event_digest
    );
    Ok(())
}

#[test]
fn projection_reference_refuses_an_out_of_range_version() -> TestResult {
    let mut ledger = Ledger::new()?;
    ledger.publish(KEY, RecordKind::Deployment, b"{}", None)?;
    for version in [0, 9_007_199_254_740_992] {
        match projection_reference(&ledger.connection, KEY, version) {
            Err(SqliteServingOwnerError::Invalid(detail)) => assert_eq!(
                detail,
                "recovery record projection reference version is out of range"
            ),
            other => panic!("expected an out of range refusal, got {other:?}"),
        }
    }
    Ok(())
}

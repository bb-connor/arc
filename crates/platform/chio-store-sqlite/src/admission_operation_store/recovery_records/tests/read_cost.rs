//! A current-record read seeks its row and latest event; it never walks the
//! record's history.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chio_kernel::admission_operation::AdmissionOperationStoreError;

use super::super::{load_record, verify_local_history, RecordKind};
use super::fixture::{Ledger, TestResult};

const KEY: &str = "workflow:history";

fn ledger_with_versions(versions: u32) -> Result<Ledger, Box<dyn std::error::Error>> {
    let mut ledger = Ledger::new()?;
    for version in 1..=versions {
        let payload = format!(r#"{{"v":"{version:03}"}}"#);
        ledger.publish(KEY, RecordKind::Workflow, payload.as_bytes(), None)?;
    }
    Ok(ledger)
}

/// SQLite virtual machine steps `work` takes on the ledger connection.
fn vm_steps<T>(
    ledger: &Ledger,
    work: impl FnOnce(&rusqlite::Connection) -> Result<T, AdmissionOperationStoreError>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let steps = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&steps);
    ledger.connection.progress_handler(
        1,
        Some(move || {
            counter.fetch_add(1, Ordering::Relaxed);
            false
        }),
    )?;
    let result = work(&ledger.connection);
    ledger
        .connection
        .progress_handler(0, None::<fn() -> bool>)?;
    result?;
    Ok(steps.load(Ordering::Relaxed))
}

#[test]
fn current_record_read_cost_is_independent_of_its_history_length() -> TestResult {
    let shallow = ledger_with_versions(2)?;
    let deep = ledger_with_versions(64)?;
    let read = |connection: &rusqlite::Connection| {
        load_record(connection, KEY)?
            .map(|record| record.version)
            .ok_or(AdmissionOperationStoreError::NotFound)
    };
    let shallow_read = vm_steps(&shallow, read)?;
    let deep_read = vm_steps(&deep, read)?;
    assert!(shallow_read > 0, "the progress hook observed no read work");
    assert_eq!(
        deep_read, shallow_read,
        "a 64-version read took {deep_read} steps against {shallow_read} for 2 versions"
    );
    let shallow_full = vm_steps(&shallow, verify_local_history)?;
    let deep_full = vm_steps(&deep, verify_local_history)?;
    assert!(
        deep_full > shallow_full,
        "the full verifier must walk the longer history: {deep_full} <= {shallow_full}"
    );
    Ok(())
}

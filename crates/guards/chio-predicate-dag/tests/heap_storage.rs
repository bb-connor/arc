#![cfg(feature = "alloc")]

mod common;

use chio_predicate_dag::{DagError, HeapScheduleStorage, Trit};
use common::{storage, tri_set};

const REFERENCE_MODEL: &[u8] = include_bytes!("fixtures/reference-model.cdm");

/// Runs on a default-size test thread: building the storage must never stage
/// the full op buffer on the stack.
#[test]
fn heap_storage_builds_on_a_default_test_thread() {
    let storage = HeapScheduleStorage::new();
    assert!(matches!(storage.schedule(), Err(DagError::NotValidated)));
}

#[test]
fn heap_storage_decodes_and_evaluates_like_schedule_storage() -> Result<(), DagError> {
    let mut heap = HeapScheduleStorage::new();
    let heap_thresholds = heap.decode(REFERENCE_MODEL)?;
    let heap_schedule = heap.schedule()?;

    let mut fixed = storage();
    let fixed_thresholds = fixed.decode(REFERENCE_MODEL)?;
    let fixed_schedule = fixed.schedule()?;

    assert_eq!(heap_thresholds, fixed_thresholds);
    assert_eq!(heap_schedule.op_count(), fixed_schedule.op_count());
    assert_eq!(heap_schedule.atom_count(), fixed_schedule.atom_count());
    assert_eq!(heap_schedule.rule_count(), fixed_schedule.rule_count());
    assert_eq!(
        heap_schedule.referenced_atoms(),
        fixed_schedule.referenced_atoms()
    );
    for trit in [Trit::False, Trit::Unknown, Trit::True] {
        let atoms = tri_set(&vec![trit; heap_schedule.atom_count()]);
        assert_eq!(
            heap_schedule.evaluate(&atoms, heap_schedule.op_count())?,
            fixed_schedule.evaluate(&atoms, fixed_schedule.op_count())?
        );
    }
    Ok(())
}

#[test]
fn a_failed_decode_invalidates_heap_storage() -> Result<(), DagError> {
    let mut heap = HeapScheduleStorage::new();
    heap.decode(REFERENCE_MODEL)?;
    assert!(heap.decode(b"CDM1").is_err());
    assert!(matches!(heap.schedule(), Err(DagError::NotValidated)));
    Ok(())
}

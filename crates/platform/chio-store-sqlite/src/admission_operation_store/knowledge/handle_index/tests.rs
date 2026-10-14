//! The entry bound is derived from the record bound, never chosen.
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn handle_index_entry_bound_is_the_record_bound_over_one_entry() -> TestResult {
    let handle = ArtifactHandleId::new(&"a".repeat(64))?;
    assert_eq!(protected::encode(&handle)?.len(), MIN_ENTRY_BYTES);
    assert_eq!(
        MAX_HANDLE_INDEX_ENTRIES,
        chio_kernel::recovery::MAX_RECOVERY_RECORD_BYTES / MIN_ENTRY_BYTES
    );
    // A full container already exceeds one record, so the canonical size
    // check refuses before the container bound can be reached.
    assert!(protected::encode(&vec![handle; MAX_HANDLE_INDEX_ENTRIES]).is_err());
    Ok(())
}

#[test]
fn handle_index_identities_are_exact_lowercase_digests() {
    assert!(is_hex_digest(&"0f".repeat(32)));
    assert!(!is_hex_digest(&"0F".repeat(32)));
    assert!(!is_hex_digest(&"0".repeat(63)));
    assert!(!is_hex_digest(&"0".repeat(65)));
}

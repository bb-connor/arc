//! Accepted durable updates must remain readable by the unchanged native decoder.
#![cfg(target_os = "linux")]
use super::*;

#[cfg(target_os = "linux")]
#[test]
fn active_resume_writer_accepts_exact_bound_and_refuses_overflow_before_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sessions.sqlite3");
    let _lease = acquire_test_session_store(&path);
    let keyring = test_resume_hmac_keyring();
    let mut record = sample_resume_record_with_keyring(&keyring);
    record.initialize_params = json!({"padding":""});
    record = sign_test_resume_record(record, &keyring);
    let overhead = serde_json::to_vec(&record).unwrap().len();
    record.initialize_params["padding"] = json!("x".repeat(MAX_SESSION_JSON_BYTES - overhead));
    record = sign_test_resume_record(record, &keyring);
    assert_eq!(
        serde_json::to_vec(&record).unwrap().len(),
        MAX_SESSION_JSON_BYTES
    );
    persist_active_session_record(&path, &record, &keyring, 11).unwrap();
    let previous = serde_json::to_vec(&record).unwrap();
    let mut overflow = record;
    overflow.resume_generation += 1;
    overflow.initialize_params["padding"] = json!(format!(
        "{}x",
        overflow.initialize_params["padding"].as_str().unwrap()
    ));
    overflow = sign_test_resume_record(overflow, &keyring);
    assert_eq!(
        serde_json::to_vec(&overflow).unwrap().len(),
        MAX_SESSION_JSON_BYTES + 1
    );
    let result = persist_active_session_record(&path, &overflow, &keyring, 11);
    assert!(
        result.is_err(),
        "durable update exceeded its strict reopen byte limit"
    );
    let reopened = load_active_session_records(&path, &keyring, 11).unwrap();
    assert!(reopened.invalid_session_ids.is_empty());
    assert_eq!(reopened.records.len(), 1);
    assert_eq!(serde_json::to_vec(&reopened.records[0]).unwrap(), previous);
}

#[cfg(target_os = "linux")]
#[test]
fn active_resume_writer_preserves_decoded_decimal_and_native_integer_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sessions.sqlite3");
    let _lease = acquire_test_session_store(&path);
    let keyring = test_resume_hmac_keyring();
    let mut record = sample_resume_record_with_keyring(&keyring);
    record.initialize_params = crate::input::document(
        br#"{"numbers":[0.50,21.0,1e-05,18446744073709551615]}"#,
        1024,
    )
    .unwrap();
    record = sign_test_resume_record(record, &keyring);
    persist_active_session_record(&path, &record, &keyring, 11).unwrap();
    let reopened = load_active_session_records(&path, &keyring, 11).unwrap();
    assert!(reopened.invalid_session_ids.is_empty());
    assert_eq!(reopened.records.len(), 1);
    assert_eq!(
        reopened.records[0].initialize_params,
        record.initialize_params
    );
    validate_resume_record_integrity_with_keyring(&keyring, &reopened.records[0], 11).unwrap();
    assert_eq!(
        reopened.records[0].initialize_params["numbers"][3].as_u64(),
        Some(u64::MAX)
    );
}

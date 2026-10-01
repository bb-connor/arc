use super::*;

#[cfg(target_os = "linux")]
#[tokio::test]
async fn failed_restoration_preserves_authenticated_session_bytes() {
    let (directory, path) = private_test_session_database("restore-failure");
    let lease = acquire_test_session_store(&path);
    let keyring = test_resume_hmac_keyring();
    let record = sample_resume_record_with_keyring(&keyring);
    persist_active_session_record(&path, &record, &keyring).expect("persist session");
    let sessions = RemoteSessionLedger::new(SessionLifecyclePolicy::from_env(), None, None)
        .expect("session ledger");
    let error = restore_persisted_sessions(&path, &keyring, &sessions, |_| {
        Err(CliError::cli_other_error("retained hold authority unavailable".to_owned()))
    }).await.expect_err("recovery outage must fail startup");
    assert!(error.to_string().contains("authority unavailable"));
    assert!(sessions.lookup(&record.session_id).await.is_none());
    let retained = load_active_session_records(&path, &keyring).expect("reload session");
    assert!(retained.invalid_session_ids.is_empty());
    assert_eq!(retained.records.len(), 1);
    assert_eq!(serde_json::to_vec(&retained.records[0]).expect("retained bytes"),
        serde_json::to_vec(&record).expect("original bytes"));

    // An intentional configuration change may leave the session inactive,
    // but it does not authorize deleting authenticated recovery material.
    restore_persisted_sessions(&path, &keyring, &sessions, |_| Ok(None))
        .await.expect("incompatible session remains inactive");
    assert!(sessions.lookup(&record.session_id).await.is_none());
    assert_eq!(load_active_session_records(&path, &keyring).expect("reload inactive session").records.len(), 1);
    drop(lease);
    std::fs::remove_dir_all(directory).expect("remove test session directory");
}

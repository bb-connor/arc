use super::*;


#[test]
fn sqlite_escalate_alert_survives_restart_and_rejects_rehashed_storage_tamper() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("effect-alerts.sqlite");
    let config = AlertOutboxConfig {
        base_retry_ms: 10,
        max_retry_ms: 100,
        max_attempts: 3,
    };
    let request = alert_request();
    let outbox = Arc::new(
        SqliteSiemOutbox::open(
            &path,
            vec![Arc::new(NoopAlertBackend) as Arc<dyn AlertBackend>],
            config,
        )
        .unwrap_or_else(|error| panic!("open alert outbox: {error}")),
    );
    let alert_store: Arc<dyn EscalateAlertStore> = outbox.clone();
    let backend: Arc<dyn ResponseEffectBackend> =
        Arc::new(EscalateAlertBackend::new(alert_store));
    let port = ActiveResponseEffectPort::from_backends(vec![backend])
        .unwrap_or_else(|error| panic!("SQLite alert router: {error}"));
    let result = port
        .execute(&request)
        .unwrap_or_else(|error| panic!("persist SQLite alert: {error}"));
    drop(port);
    drop(outbox);

    let reopened = Arc::new(
        SqliteSiemOutbox::open(
            &path,
            vec![Arc::new(NoopAlertBackend) as Arc<dyn AlertBackend>],
            config,
        )
        .unwrap_or_else(|error| panic!("reopen alert outbox: {error}")),
    );
    let alert_store: Arc<dyn EscalateAlertStore> = reopened.clone();
    let backend: Arc<dyn ResponseEffectBackend> =
        Arc::new(EscalateAlertBackend::new(alert_store));
    let restarted = ActiveResponseEffectPort::from_backends(vec![backend])
        .unwrap_or_else(|error| panic!("restarted alert router: {error}"));
    assert_eq!(
        restarted.load_result(&query(&request)),
        Ok(EffectExecutionStatus::Completed {
            result: result.clone()
        })
    );
    assert_eq!(restarted.execute(&request), Ok(result));

    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("open alert tamper connection: {error}"));
    let command_json: Vec<u8> = connection
        .query_row(
            "SELECT command_json FROM chio_security_alert_outbox",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("load stored alert command: {error}"));
    let mut stored_alert: SecurityAlert = serde_json::from_slice(&command_json)
        .unwrap_or_else(|error| panic!("decode stored alert command: {error}"));
    stored_alert.evidence_hash = Digest32::new([88_u8; 32]);
    let tampered_json = chio_core::canonical_json_bytes(&stored_alert)
        .unwrap_or_else(|error| panic!("canonical tampered alert: {error}"));
    let tampered_hash = chio_core::sha256(&tampered_json);
    connection
        .execute(
            "UPDATE chio_security_alert_outbox SET command_json = ?1, command_hash = ?2",
            rusqlite::params![tampered_json, tampered_hash.as_bytes().as_slice()],
        )
        .unwrap_or_else(|error| panic!("tamper alert outbox: {error}"));
    assert_eq!(
        require_error(restarted.load_result(&query(&request))).kind(),
        PortErrorKind::IntegrityFailure
    );
}

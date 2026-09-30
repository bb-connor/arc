use super::*;

#[derive(Clone)]
struct AuditTestClock(
    Arc<
        Mutex<
            Result<
                chio_security_types::clock::ClockReading,
                chio_security_types::clock::ClockError,
            >,
        >,
    >,
);
impl chio_security_types::clock::Clock for AuditTestClock {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        *self.0.lock().unwrap()
    }
}
fn audit_reading(seconds: u64, mono: u64) -> chio_security_types::clock::ClockReading {
    use chio_security_types::clock::{ClockReading, MonotonicInstant, UnixMillis};
    ClockReading::new(
        UnixMillis::new(seconds * 1_000),
        MonotonicInstant::from_nanos(mono),
    )
}
#[test]
fn clock_faults_and_restart_preserve_authorization_custody() {
    use chio_security_types::clock::ClockError;
    let key = Keypair::generate();
    let timestamp = now_secs();
    let authorization =
        make_authorization_receipt(&key, "cap", "auth", "session", "call", "fs/read_text_file");
    let shared = Arc::new(Mutex::new(MockStoreState::default()));
    shared
        .lock()
        .unwrap()
        .appended_receipts
        .push(authorization.clone());
    let mut entry = make_audit_entry("call", "session");
    entry.timestamp = timestamp.to_string();
    mark_entry_cryptographically_enforced(
        &mut entry,
        "cap",
        &authorization.id,
        "auth",
        "fs/read_text_file",
    );
    let request = AcpReceiptRequest {
        audit_entry: entry,
        tool_server: "proxy-server".into(),
        tool_name: "fs/read_text_file".into(),
    };
    let source = AuditTestClock(Arc::new(Mutex::new(Ok(audit_reading(timestamp, 2)))));
    let clock = AcpClock::new(Arc::new(source.clone()));
    clock.read().unwrap();
    let signer = KernelReceiptSigner::new(
        key.clone(),
        "proxy-server",
        Box::new(MockReceiptStore {
            state: shared.clone(),
            supports_checkpoints: false,
        }),
        0,
        clock,
    );
    for reading in [
        Err(ClockError::Unavailable),
        Ok(audit_reading(timestamp - 1, 3)),
        Ok(audit_reading(timestamp, 1)),
    ] {
        *source.0.lock().unwrap() = reading;
        assert!(matches!(
            signer.sign_acp_receipt(&request),
            Err(ReceiptSignError::Audit(AcpAuditError::Clock(_)))
        ));
    }
    // A fresh owner has no in-memory fence. Persisted audit time still rejects rollback.
    let restarted_source =
        AuditTestClock(Arc::new(Mutex::new(Ok(audit_reading(timestamp - 1, 1)))));
    let restarted = KernelReceiptSigner::new(
        key,
        "proxy-server",
        Box::new(MockReceiptStore {
            state: shared.clone(),
            supports_checkpoints: false,
        }),
        0,
        AcpClock::new(Arc::new(restarted_source)),
    );
    assert!(matches!(
        restarted.sign_acp_receipt(&request),
        Err(ReceiptSignError::Audit(AcpAuditError::Clock(
            ClockError::NotYetValid
        )))
    ));
    {
        let state = shared.lock().unwrap();
        assert_eq!(state.appended_receipts.len(), 1);
        assert!(state.consumed_authorization_receipts.is_empty());
    }
    *source.0.lock().unwrap() = Ok(audit_reading(timestamp + 1, 4));
    signer.sign_acp_receipt(&request).unwrap();
    assert_eq!(
        shared.lock().unwrap().consumed_authorization_receipts.len(),
        1
    );
}
#[test]
fn certificate_time_and_sequence_fail_closed() {
    use chio_security_types::clock::ClockError;
    let key = Keypair::generate();
    let receipt = make_receipt_for_session(
        &key,
        "session",
        "receipt",
        3,
        "fs/read_text_file",
        Decision::Allow,
        vec![],
    );
    let entries = [ComplianceReceiptEntry {
        receipt: receipt.clone(),
        seq: 1,
    }];
    let config = ComplianceConfig {
        trusted_kernel_keys: std::collections::BTreeSet::from([key.public_key().to_hex()]),
        ..ComplianceConfig::default()
    };
    let source = AuditTestClock(Arc::new(Mutex::new(Ok(audit_reading(3, 2)))));
    let clock = AcpClock::new(Arc::new(source.clone()));
    generate_compliance_certificate("session", &entries, &config, &key, &clock).unwrap();
    for observation in [
        Err(ClockError::Unavailable),
        Ok(audit_reading(2, 3)),
        Ok(audit_reading(3, 1)),
    ] {
        *source.0.lock().unwrap() = observation;
        assert!(matches!(
            generate_compliance_certificate("session", &entries, &config, &key, &clock),
            Err(ComplianceCertificateError::Audit(AcpAuditError::Clock(_)))
        ));
    }
    let fresh = AcpClock::new(Arc::new(AuditTestClock(Arc::new(Mutex::new(Ok(
        audit_reading(2, 1),
    ))))));
    assert!(matches!(
        generate_compliance_certificate("session", &entries, &config, &key, &fresh),
        Err(ComplianceCertificateError::Audit(AcpAuditError::Clock(
            ClockError::NotYetValid
        )))
    ));
    let overflow = [
        ComplianceReceiptEntry {
            receipt: receipt.clone(),
            seq: u64::MAX,
        },
        ComplianceReceiptEntry { receipt, seq: 0 },
    ];
    assert!(matches!(
        generate_compliance_certificate("session", &overflow, &config, &key, &clock),
        Err(ComplianceCertificateError::Audit(AcpAuditError::Clock(
            ClockError::Overflow
        )))
    ));
}

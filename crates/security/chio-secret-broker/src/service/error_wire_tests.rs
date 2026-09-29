//! Signed broker rejection codes and their IPC envelopes.
use super::*;
use chio_test_support::prelude::*;

#[test]
fn response_envelope_preserves_typed_json_and_clock_rejections() {
    use chio_core_types::canonical::UntrustedJsonError;
    use chio_security_types::clock::ClockError;
    for (error, local_code, wire_code) in [
        (
            BrokerError::UntrustedInput(UntrustedJsonError::NonCanonical),
            "urn:chio:error:attest:signed-json-noncanonical",
            "chio.broker.signed_json_noncanonical",
        ),
        (
            BrokerError::Clock(ClockError::Unavailable),
            "urn:chio:error:kernel:clock-unavailable",
            "chio.broker.clock_unavailable",
        ),
        (
            BrokerError::Clock(ClockError::WallClockRegression),
            "urn:chio:error:kernel:clock-wall-clock-regression",
            "chio.broker.clock_wall_clock_regression",
        ),
    ] {
        let rule = match &error {
            BrokerError::UntrustedInput(error) => error.code(),
            BrokerError::Clock(error) => error.code(),
            _ => panic!("fixture requires a typed rule"),
        };
        assert_eq!(rule, local_code);
        assert!(is_well_formed_broker_ipc_error_code(
            error.diagnostic_code()
        ));
        let execute_code = format!("chio.broker.{}", error.diagnostic_code());
        assert_eq!(execute_code, wire_code);
        assert!(
            !crate::protocol::is_well_formed_broker_execute_diagnostic_code(&format!(
                "chio.broker.{local_code}"
            ))
        );
        let failure = signed_ipc_execute_failure(&execute_code);
        let envelope = IpcResponse {
            operation: IpcOperation::Execute,
            accepted: false,
            response: canonical_json_bytes(&failure).test_expect("canonical failure"),
            error_code: Some(wire_code.to_string()),
        };
        validate_broker_ipc_response_envelope(IpcOperation::Execute, &envelope)
            .test_expect("typed rejection remains verifiable");
        assert_eq!(failure.receipt.body.diagnostic_code, wire_code);
        crate::receipt::verify_failure_receipt(
            &failure.receipt,
            &Keypair::from_seed(&[91; 32]).public_key(),
        )
        .test_expect("signed failure verifies");
    }
}

fn signed_ipc_execute_failure(diagnostic_code: &str) -> BrokerExecuteFailure {
    let receipt = sign_failure_receipt(
        BrokerFailureReceiptBody {
            schema: BROKER_FAILURE_RECEIPT_SCHEMA.to_string(),
            receipt_id: "broker-failure-terminal-ipc-validator".to_string(),
            issued_at_unix_seconds: 1,
            stage: BrokerFailureStage::Admission,
            outcome: BrokerFailureOutcome::Denied,
            diagnostic_code: diagnostic_code.to_string(),
            request_digest: "ab".repeat(32),
            capability_digest: None,
            attempt_id: None,
            invocation_id: None,
            hold_id: None,
            parent_capability_id: None,
            broker_capability_id: None,
            dispatch_knowledge: BrokerDispatchKnowledge::NotStarted,
        },
        &Ed25519Backend::new(Keypair::from_seed(&[91; 32])),
    )
    .test_expect("signed IPC execute failure");
    let receipt_reference = format!(
        "broker-failure-receipt-sha256-{}",
        failure_receipt_digest(&receipt).test_expect("failure receipt digest")
    );
    BrokerExecuteFailure {
        diagnostic_code: diagnostic_code.to_string(),
        receipt_reference,
        receipt,
    }
}

#[test]
fn response_envelope_accepts_exact_canonical_signed_execute_failure() {
    let failure = signed_ipc_execute_failure("chio.broker.authorization_denied");
    let response = IpcResponse {
        operation: IpcOperation::Execute,
        accepted: false,
        response: canonical_json_bytes(&failure).test_expect("canonical execute failure"),
        error_code: Some(failure.diagnostic_code.clone()),
    };

    validate_broker_ipc_response_envelope(IpcOperation::Execute, &response)
        .test_expect("signed execute denial envelope");
}

#[test]
fn response_envelope_rejects_malformed_or_tampered_execute_failures() {
    let diagnostic_code = "chio.broker.authorization_denied";
    let failure = signed_ipc_execute_failure(diagnostic_code);
    let envelope = |operation, failure: &BrokerExecuteFailure, error_code: &str| IpcResponse {
        operation,
        accepted: false,
        response: canonical_json_bytes(failure).test_expect("canonical execute failure"),
        error_code: Some(error_code.to_string()),
    };

    let mut diagnostic_rebound = failure.clone();
    diagnostic_rebound.diagnostic_code = "chio.broker.conflict".to_string();

    let mut signed_body_tampered = failure.clone();
    signed_body_tampered.diagnostic_code = "chio.broker.conflict".to_string();
    signed_body_tampered.receipt.body.diagnostic_code = "chio.broker.conflict".to_string();
    signed_body_tampered.receipt_reference = format!(
        "broker-failure-receipt-sha256-{}",
        failure_receipt_digest(&signed_body_tampered.receipt)
            .test_expect("tampered failure receipt digest")
    );

    let mut reference_tampered = failure.clone();
    reference_tampered.receipt_reference =
        format!("broker-failure-receipt-sha256-{}", "00".repeat(32));

    let malformed = IpcResponse {
        operation: IpcOperation::Execute,
        accepted: false,
        response: b"{}".to_vec(),
        error_code: Some(diagnostic_code.to_string()),
    };
    let noncanonical = IpcResponse {
        operation: IpcOperation::Execute,
        accepted: false,
        response: serde_json::to_vec_pretty(&failure).test_expect("noncanonical execute failure"),
        error_code: Some(diagnostic_code.to_string()),
    };
    let empty_execute_denial = IpcResponse {
        operation: IpcOperation::Execute,
        accepted: false,
        response: Vec::new(),
        error_code: Some(diagnostic_code.to_string()),
    };
    let wrong_domain_failure = signed_ipc_execute_failure("chio.kernel.authorization_denied");
    let candidates = [
        envelope(IpcOperation::Execute, &failure, "chio.broker.conflict"),
        envelope(
            IpcOperation::Execute,
            &diagnostic_rebound,
            "chio.broker.conflict",
        ),
        envelope(
            IpcOperation::Execute,
            &signed_body_tampered,
            "chio.broker.conflict",
        ),
        envelope(IpcOperation::Execute, &reference_tampered, diagnostic_code),
        envelope(IpcOperation::Status, &failure, diagnostic_code),
        envelope(
            IpcOperation::Execute,
            &wrong_domain_failure,
            "chio.kernel.authorization_denied",
        ),
        malformed,
        noncanonical,
        empty_execute_denial,
    ];

    for candidate in candidates {
        assert!(matches!(
            validate_broker_ipc_response_envelope(candidate.operation, &candidate),
            Err(BrokerError::Invariant(reason))
                if reason == "IPC handler returned an invalid response envelope"
        ));
    }
}

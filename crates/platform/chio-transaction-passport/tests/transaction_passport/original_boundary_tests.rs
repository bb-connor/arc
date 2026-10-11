use super::*;

#[test]
fn transaction_passport_rejects_invalid_evidence_graph_artifact() {
    let evidence_graph_bytes = b"not-json";
    let error = passport_error_for_evidence_graph(evidence_graph_bytes);

    assert!(matches!(
        &error,
        chio_transaction_passport::TransactionPassportError::Input(_)
    ));
    assert!(std::error::Error::source(&error).is_some());
}

#[test]
fn runtime_receipt_totality_rejects_unsigned_terminal_receipt() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_runtime_policy_required_claims(
        &mut bundle,
        vec!["claim.runtime.receipt_totality_complete"],
    );
    let policy_digest = bundle.passport.verifier_policy_sha256.clone();
    update_runtime_artifact(&mut bundle, "allow-receipt.json", |receipt| {
        receipt["policy_digest"] = Value::String(policy_digest);
        receipt["terminal_status"] = Value::String("denied_guard_request".to_string());
        receipt
            .as_object_mut()
            .test_expect("terminal receipt is object")
            .remove("execution_lease_ref");
        receipt
            .as_object_mut()
            .test_expect("terminal receipt is object")
            .remove("kernel_key");
        receipt
            .as_object_mut()
            .test_expect("terminal receipt is object")
            .remove("signature");
    });

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("unsigned terminal receipt must fail closed");
    assert!(matches!(
        &error,
        chio_transaction_passport::TransactionPassportError::Input(_)
    ));
    assert!(std::error::Error::source(&error).is_some());
}

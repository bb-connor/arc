//! Channel terminal receipts and constructors refuse substituted bindings and effects.

use super::*;

#[test]
fn channel_receipt_rejects_every_substituted_obligation_binding() -> TestResult<()> {
    let fixture = build_fixture(7, "obligation-substitution")?;
    let atom = fixture
        .base
        .atom
        .as_ref()
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    for (field, replacement) in [
        (
            "preActionAuthorityDigest",
            serde_json::Value::String(channel_digest("substituted-authority")),
        ),
        (
            "obligationId",
            serde_json::Value::String(channel_digest("substituted-obligation-id")),
        ),
        (
            "sourceReceiptDigest",
            serde_json::Value::String(channel_digest("substituted-receipt-digest")),
        ),
        (
            "amount",
            serde_json::json!({ "units": 8, "currency": "USD" }),
        ),
        (
            "originalCreditorId",
            serde_json::Value::String("substituted-creditor".to_owned()),
        ),
        (
            "debtorId",
            serde_json::Value::String("substituted-debtor".to_owned()),
        ),
    ] {
        let substituted = mutated_atom(atom, field, replacement)?;
        assert!(
            verify_channel_receipt_binding(
                fixture.base.receipt.receipt(),
                &fixture.base.receipt.receipt().kernel_key,
                &fixture.base.reservation,
                &fixture.base.open,
                Some(&substituted),
            )
            .is_err(),
            "substituted obligation field was accepted: {field}"
        );
    }
    Ok(())
}

#[test]
fn channel_terminal_constructor_rejects_receipt_and_tool_outcome_substitution() -> TestResult<()> {
    let fixture = build_fixture(7, "constructor-substitution")?;
    let alternate_receipt = build_advance_fixture(
        7,
        "constructor-substitution",
        "alternate",
        serde_json::json!({ "result": "ok" }),
        None,
    )
    .map_err(|error| std::io::Error::other(format!("alternate receipt: {error}")))?;
    assert!(VerifiedChannelTerminalProjectionV1::from_verified(
        &fixture.base.operation,
        &fixture.base.context,
        &alternate_receipt.receipt,
        &fixture.base.tool_outcome,
        &fixture.base.advance,
    )
    .is_err());

    let alternate_outcome = build_advance_fixture(
        7,
        "constructor-substitution",
        "outcome",
        serde_json::json!({ "result": "substituted" }),
        None,
    )
    .map_err(|error| std::io::Error::other(format!("alternate outcome: {error}")))?;
    assert!(VerifiedChannelTerminalProjectionV1::from_verified(
        &fixture.base.operation,
        &fixture.base.context,
        &fixture.base.receipt,
        &alternate_outcome.tool_outcome,
        &fixture.base.advance,
    )
    .is_err());

    Ok(())
}

#[test]
fn channel_authority_rejects_terminal_effect_substitution() -> TestResult<()> {
    let result = build_advance_fixture(
        7,
        "constructor-substitution",
        "primary",
        serde_json::json!({ "result": "ok" }),
        Some(serde_json::json!({ "outcome": "substituted" })),
    );
    assert_eq!(
        result.err().map(|error| error.to_string()).as_deref(),
        Some("channel authority verification failed")
    );
    Ok(())
}

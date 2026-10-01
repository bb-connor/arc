use super::support::*;

fn signed_metadata_receipt(
    metadata: serde_json::Value,
) -> Result<ChioReceipt, Box<dyn std::error::Error>> {
    let keypair = Keypair::from_seed(&[61; 32]);
    let mut body = sample_receipt().body();
    body.kernel_key = keypair.public_key();
    body.metadata = Some(metadata);
    Ok(ChioReceipt::sign(body, &keypair)?)
}

#[test]
fn stored_tool_json_rejects_duplicate_keys_and_precision_aliases(
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = signed_metadata_receipt(serde_json::json!({
        "retained": true,
        "threshold": 0.12345678901234568,
    }))?;
    let raw = String::from_utf8(canonical_json_bytes(&receipt)?)
        .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
    assert_eq!(
        decode_verified_chio_receipt(&raw, "test tool", Some(1))?.id,
        receipt.id
    );
    let id = format!("\"id\":\"{}\"", receipt.id);
    let shadowed_id = format!("\"id\":\"shadow\",{id}");
    for (original, replacement, cause) in [
        (id.as_str(), shadowed_id.as_str(), "duplicate object key"),
        (
            r#""retained":true"#,
            r#""retained":false,"retained":true"#,
            "duplicate object key",
        ),
        (
            "0.12345678901234568",
            "0.123456789012345678901",
            "loses precision or changes representation",
        ),
    ] {
        assert_eq!(raw.matches(original).count(), 1);
        let aliased = raw.replacen(original, replacement, 1);
        assert!(matches!(
            decode_verified_chio_receipt(&aliased, "test tool", Some(1)),
            Err(ReceiptStoreError::Conflict(reason))
                if reason.starts_with("test tool seq 1 failed to decode:") && reason.contains(cause)
        ));
    }
    Ok(())
}

#[test]
fn stored_child_json_rejects_duplicate_keys() -> Result<(), Box<dyn std::error::Error>> {
    let receipt = sample_child_receipt();
    let raw = String::from_utf8(canonical_json_bytes(&receipt)?)
        .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
    assert_eq!(
        decode_verified_child_receipt(&raw, "test child", Some(2))?.id,
        receipt.id
    );
    let original = r#""id":"child-rcpt-test-001""#;
    assert_eq!(raw.matches(original).count(), 1);
    let aliased = raw.replacen(original, r#""id":"shadow","id":"child-rcpt-test-001""#, 1);
    assert!(matches!(
        decode_verified_child_receipt(&aliased, "test child", Some(2)),
        Err(ReceiptStoreError::Conflict(reason))
            if reason.starts_with("test child seq 2 failed to decode:") && reason.contains("duplicate object key")
    ));
    Ok(())
}

#[test]
fn stored_financial_receipt_preserves_full_unsigned_domain(
) -> Result<(), Box<dyn std::error::Error>> {
    for amount in [(1_u64 << 53) + 1, 1_u64 << 63, u64::MAX] {
        let receipt = signed_metadata_receipt(serde_json::json!({
            "financial": FinancialReceiptMetadata {
                grant_index: 0,
                cost_charged: amount,
                currency: "USD".to_owned(),
                budget_remaining: 0,
                budget_total: u64::MAX,
                delegation_depth: 0,
                root_budget_holder: "legacy-holder".to_owned(),
                payment_reference: None,
                settlement_status: SettlementStatus::Settled,
                cost_breakdown: None,
                oracle_evidence: None,
                attempted_cost: Some(amount),
            }
        }))?;
        let raw = canonical_json_bytes(&receipt)?;
        let text = std::str::from_utf8(&raw)
            .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
        let restored = decode_verified_chio_receipt(text, "test financial", Some(3))?;
        assert_eq!(canonical_json_bytes(&restored)?, raw);
        assert_eq!(restored.signature, receipt.signature);
    }
    Ok(())
}

#[test]
fn stored_receipts_accept_both_historical_writer_encodings(
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = signed_metadata_receipt(serde_json::json!({
        "whole_float": 1.0,
        "negative_zero": -0.0,
        "large_float": 1e30,
        "tiny_float": 5e-324,
        "escaped": "a \\\" quoted number 0.123456789012345678901",
    }))?;
    for raw in [
        serde_json::to_string(&receipt)?,
        serde_json::to_string_pretty(&receipt)?,
    ] {
        let restored = decode_verified_chio_receipt(&raw, "historical tool", Some(4))?;
        assert_eq!(restored.signature, receipt.signature);
        assert_eq!(
            canonical_json_bytes(&restored)?,
            canonical_json_bytes(&receipt)?
        );
    }
    let child = sample_child_receipt();
    let raw = serde_json::to_string(&child)?;
    assert_eq!(
        decode_verified_child_receipt(&raw, "historical child", Some(5))?.signature,
        child.signature
    );
    Ok(())
}

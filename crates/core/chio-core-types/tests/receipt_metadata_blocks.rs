//! The `stream`, `acp` and `financial` signed metadata blocks: strict decoding and the
//! committed members of the ACP projection.

use std::cell::Cell;

use chio_core_types::receipt::economics::SettlementStatus;
use chio_core_types::receipt::metadata::{
    financial_settlement_projection, AcpReceiptFields, AcpReceiptProjection, FinancialBlock,
    FinancialSettlementProjection, MetadataOpenings, MetadataValue, PaymentAuthorizationErrorCode,
    StreamReceiptProjection,
};
use chio_core_types::rng::{Rng, RngError};
use chio_core_types::root_authority::SaltRef;
use chio_test_support::prelude::*;
use serde_json::{json, Value};

struct CountingRng(Cell<u64>);

impl Rng for CountingRng {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RngError> {
        let next = self.0.get().wrapping_add(1);
        self.0.set(next);
        for (index, byte) in dest.iter_mut().enumerate() {
            *byte = next.to_le_bytes()[index % 8] ^ u8::try_from(index % 256).unwrap_or(0);
        }
        Ok(())
    }
}

fn rng(seed: u64) -> CountingRng {
    CountingRng(Cell::new(seed))
}

fn charged() -> Value {
    json!({
        "grant_index": 0,
        "cost_charged": 125,
        "currency": "USD",
        "budget_remaining": 875,
        "budget_total": 1000,
        "delegation_depth": 1,
        "root_budget_holder": "holder-1",
        "payment_reference": "pay-1",
        "settlement_status": "settled",
        "attempted_cost": null
    })
}

fn retained() -> Value {
    json!({
        "payment_authorization_ambiguous": true,
        "payment_authorization_error_code": "outcome_unknown",
        "payment_attempt_reference": "attempt-op-1"
    })
}

fn with_financial(block: Value) -> Value {
    json!({ "financial": block })
}

#[test]
fn charged_receipt_with_accounting_fields_yields_charged() {
    let mut block = charged();
    if let Some(object) = block.as_object_mut() {
        object.remove("attempted_cost");
    }
    let metadata = with_financial(block);
    assert_eq!(
        financial_settlement_projection(Some(&metadata)).test_unwrap(),
        Some(FinancialSettlementProjection::Charged {
            cost_charged: 125,
            currency: "USD".to_owned(),
            settlement_status: SettlementStatus::Settled,
            payment_reference: Some("pay-1".to_owned()),
        })
    );
}

#[test]
fn retained_ambiguous_block_yields_retained_ambiguous() {
    let metadata = with_financial(retained());
    assert_eq!(
        financial_settlement_projection(Some(&metadata)).test_unwrap(),
        Some(FinancialSettlementProjection::RetainedAmbiguous {
            payment_authorization_error_code: PaymentAuthorizationErrorCode::OutcomeUnknown,
            payment_attempt_reference: "attempt-op-1".to_owned(),
        })
    );
}

#[test]
fn absent_financial_block_reads_as_no_settlement() {
    assert_eq!(financial_settlement_projection(None).test_unwrap(), None);
    let metadata = json!({ "other": {} });
    assert_eq!(
        financial_settlement_projection(Some(&metadata)).test_unwrap(),
        None
    );
}

#[test]
fn financial_block_with_unknown_member_refuses() {
    let mut block = charged();
    if let Some(object) = block.as_object_mut() {
        object.remove("attempted_cost");
        object.insert(
            "reported_cost_breakdown_raw".to_owned(),
            json!({"tokens": 3}),
        );
    }
    assert!(financial_settlement_projection(Some(&with_financial(block))).is_err());

    let mut block = retained();
    if let Some(object) = block.as_object_mut() {
        object.insert(
            "payment_authorization_evidence".to_owned(),
            json!({"rail": "x"}),
        );
    }
    assert!(FinancialBlock::from_metadata(Some(&with_financial(block))).is_err());
}

#[test]
fn mixed_or_incomplete_financial_blocks_refuse() {
    let mut mixed = charged();
    if let Some(object) = mixed.as_object_mut() {
        object.remove("attempted_cost");
        object.insert("payment_authorization_ambiguous".to_owned(), json!(true));
    }
    assert!(financial_settlement_projection(Some(&with_financial(mixed))).is_err());

    let mut not_ambiguous = retained();
    not_ambiguous["payment_authorization_ambiguous"] = json!(false);
    assert!(financial_settlement_projection(Some(&with_financial(not_ambiguous))).is_err());

    let mut no_reference = retained();
    no_reference["payment_attempt_reference"] = json!("");
    assert!(financial_settlement_projection(Some(&with_financial(no_reference))).is_err());

    let mut unknown_code = retained();
    unknown_code["payment_authorization_error_code"] = json!("timeout");
    assert!(financial_settlement_projection(Some(&with_financial(unknown_code))).is_err());

    assert!(financial_settlement_projection(Some(&with_financial(json!({})))).is_err());
    assert!(financial_settlement_projection(Some(&with_financial(json!(null)))).is_err());
}

#[test]
fn stream_projection_has_no_chunks_expected() {
    let metadata = json!({ "stream": { "chunks_received": 3, "total_bytes": 96 } });
    assert_eq!(
        StreamReceiptProjection::from_metadata(Some(&metadata)).test_unwrap(),
        Some(StreamReceiptProjection {
            chunks_received: 3,
            total_bytes: 96,
        })
    );
    let encoded = serde_json::to_value(StreamReceiptProjection {
        chunks_received: 3,
        total_bytes: 96,
    })
    .test_unwrap();
    assert_eq!(encoded, json!({ "chunks_received": 3, "total_bytes": 96 }));
    for extra in ["chunks_expected", "chunk_hashes"] {
        let mut block = json!({ "chunks_received": 3, "total_bytes": 96 });
        block[extra] = json!(3);
        let metadata = json!({ "stream": block });
        assert!(
            StreamReceiptProjection::from_metadata(Some(&metadata)).is_err(),
            "{extra}"
        );
    }
    assert!(StreamReceiptProjection::from_metadata(Some(&json!({
        "stream": { "chunks_received": 3 }
    })))
    .is_err());
    assert_eq!(
        StreamReceiptProjection::from_metadata(None).test_unwrap(),
        None
    );
}

const SESSION_ID: &str = "acp-session-1";

fn acp_fields() -> AcpReceiptFields<'static> {
    AcpReceiptFields {
        session_id: SESSION_ID,
        tool_call_id: "tool-call-raw-1",
        capability_id: Some("capability-raw-1"),
        authorization_receipt_id: Some("authorization-receipt-raw-1"),
        authorization_request_id: Some("authorization-request-raw-1"),
        authorization_tool_call_id: Some("authorization-tool-call-raw-1"),
        authorization_correlation_id: Some("authorization-correlation-raw-1"),
        authorization_operation: Some("fs/write_text_file"),
        authorization_resource: Some("/home/user/secret-plan.txt"),
        authorization_parameter_hash: Some("parameter-hash-raw-1"),
        enforcement_mode: "enforce",
    }
}

#[test]
fn acp_projection_carries_no_raw_member_but_the_session_id() {
    let fields = acp_fields();
    let (projection, openings) = AcpReceiptProjection::project(&fields, &rng(0)).test_unwrap();
    assert!(projection.matches(&fields, &openings));
    let encoded = serde_json::to_string(&projection).test_unwrap();
    assert!(encoded.contains(SESSION_ID));
    for raw in [
        "tool-call-raw-1",
        "capability-raw-1",
        "authorization-receipt-raw-1",
        "authorization-request-raw-1",
        "authorization-tool-call-raw-1",
        "authorization-correlation-raw-1",
        "fs/write_text_file",
        "secret-plan",
        "parameter-hash-raw-1",
        "\"enforce\"",
    ] {
        assert!(!encoded.contains(raw), "projection carries {raw}");
    }
    assert_eq!(openings.len(), 10);
    assert_eq!(
        projection
            .authorization_resource
            .as_ref()
            .test_unwrap()
            .salt_ref()
            .as_str(),
        "metadata.receipt_context.authorization_resource"
    );
    assert_eq!(
        projection.tool_call_id.salt_ref().as_str(),
        "metadata.acp.tool_call_id"
    );
    let decoded: AcpReceiptProjection = serde_json::from_str(&encoded).test_unwrap();
    assert_eq!(decoded, projection);
    let value: Value = serde_json::from_str(&encoded).test_unwrap();
    assert!(value.get("sessionId").is_some());
    assert!(value.get("toolCallId").is_some());
}

#[test]
fn acp_projection_omits_absent_optional_members() {
    let fields = AcpReceiptFields {
        capability_id: None,
        authorization_receipt_id: None,
        authorization_request_id: None,
        authorization_tool_call_id: None,
        authorization_correlation_id: None,
        authorization_operation: None,
        authorization_resource: None,
        authorization_parameter_hash: None,
        ..acp_fields()
    };
    let (projection, openings) = AcpReceiptProjection::project(&fields, &rng(0)).test_unwrap();
    assert_eq!(openings.len(), 2);
    assert!(projection.matches(&fields, &openings));
    let value = serde_json::to_value(&projection).test_unwrap();
    let mut keys: Vec<&str> = value
        .as_object()
        .test_unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["enforcementMode", "sessionId", "toolCallId"]);
}

#[test]
fn acp_projection_refuses_mismatched_missing_and_unused_openings() {
    let fields = acp_fields();
    let (projection, openings) = AcpReceiptProjection::project(&fields, &rng(0)).test_unwrap();
    let other = AcpReceiptFields {
        authorization_resource: Some("/home/user/other.txt"),
        ..acp_fields()
    };
    assert!(!projection.matches(&other, &openings));
    let other_session = AcpReceiptFields {
        session_id: "acp-session-2",
        ..acp_fields()
    };
    assert!(!projection.matches(&other_session, &openings));
    assert!(!projection.matches(&fields, &MetadataOpenings::new()));
    let (_, other_openings) = AcpReceiptProjection::project(&fields, &rng(1_000)).test_unwrap();
    assert!(!projection.matches(&fields, &other_openings));
    let mut padded = openings.clone();
    padded
        .commit_value(
            SaltRef::new("metadata.acp.unused").test_unwrap(),
            MetadataValue::from_json(&"unused").test_unwrap(),
            &rng(5_000),
        )
        .test_unwrap();
    assert!(!projection.matches(&fields, &padded));
}

#[test]
fn acp_projection_rejects_unknown_members() {
    let fields = acp_fields();
    let (projection, _) = AcpReceiptProjection::project(&fields, &rng(0)).test_unwrap();
    let mut value = serde_json::to_value(&projection).test_unwrap();
    value["authorizationResourceRaw"] = json!("/home/user/secret-plan.txt");
    assert!(serde_json::from_value::<AcpReceiptProjection>(value).is_err());
}

//! The `stream`, `acp` and `financial` signed metadata blocks: strict decoding and the
//! committed members of the ACP projection.

use std::cell::Cell;

use chio_core_types::receipt::economics::SettlementStatus;
use chio_core_types::receipt::metadata::{
    financial_settlement_projection, metadata_salt_ref, AcpReceiptFields, AcpReceiptProjection,
    FinancialBlock, FinancialSettlementProjection, MalformedFinancialMetadata,
    MetadataCommitmentError, MetadataCommitter, MetadataOpenings, MetadataValue,
    PaymentAuthorizationErrorCode, RetainedAmbiguousFinancialBlock, StreamReceiptProjection,
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

fn refusal(block: Value) -> String {
    match financial_settlement_projection(Some(&with_financial(block))) {
        Err(MalformedFinancialMetadata { detail }) => detail,
        Ok(projection) => panic!("malformed block decoded as {projection:?}"),
    }
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
    assert!(refusal(block).starts_with("unknown field `reported_cost_breakdown_raw`"));

    let mut block = retained();
    block["payment_authorization_evidence"] = json!({"rail": "x"});
    assert!(refusal(block).starts_with("unknown field `payment_authorization_evidence`"));
}

#[test]
fn mixed_or_incomplete_financial_blocks_refuse() {
    let mut mixed = retained();
    mixed["cost_charged"] = json!(125);
    assert!(refusal(mixed).starts_with("unknown field `cost_charged`"));

    let mut not_ambiguous = retained();
    not_ambiguous["payment_authorization_ambiguous"] = json!(false);
    assert_eq!(
        refusal(not_ambiguous),
        "payment_authorization_ambiguous must be true"
    );

    let mut no_reference = retained();
    no_reference["payment_attempt_reference"] = json!("");
    assert_eq!(
        refusal(no_reference),
        "payment_attempt_reference must not be empty"
    );

    let mut unknown_code = retained();
    unknown_code["payment_authorization_error_code"] = json!("timeout");
    assert!(refusal(unknown_code).starts_with("unknown variant `timeout`"));

    let mut no_currency = charged();
    if let Some(object) = no_currency.as_object_mut() {
        object.remove("currency");
    }
    assert_eq!(refusal(no_currency), "missing field `currency`");
    assert_eq!(
        refusal(json!(null)),
        "invalid type: null, expected struct ChargedFinancialBlock"
    );
}

#[test]
fn retained_ambiguous_decode_refuses_on_every_path() {
    let mut not_ambiguous = retained();
    not_ambiguous["payment_authorization_ambiguous"] = json!(false);
    let direct = serde_json::from_value::<RetainedAmbiguousFinancialBlock>(not_ambiguous.clone())
        .test_unwrap_err();
    assert_eq!(
        direct.to_string(),
        "payment_authorization_ambiguous must be true"
    );
    let block = serde_json::from_value::<FinancialBlock>(not_ambiguous).test_unwrap_err();
    assert_eq!(
        block.to_string(),
        "payment_authorization_ambiguous must be true"
    );
    let mut no_reference = retained();
    no_reference["payment_attempt_reference"] = json!("");
    let direct =
        serde_json::from_value::<RetainedAmbiguousFinancialBlock>(no_reference).test_unwrap_err();
    assert_eq!(
        direct.to_string(),
        "payment_attempt_reference must not be empty"
    );
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
        let error = StreamReceiptProjection::from_metadata(Some(&metadata)).test_unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with(&format!("unknown field `{extra}`")),
            "{error}"
        );
    }
    let missing = StreamReceiptProjection::from_metadata(Some(&json!({
        "stream": { "chunks_received": 3 }
    })))
    .test_unwrap_err();
    assert_eq!(missing.to_string(), "missing field `total_bytes`");
    assert_eq!(
        StreamReceiptProjection::from_metadata(None).test_unwrap(),
        None
    );
}

const SESSION_ID: &str = "acp-session-1";
const RESOURCE: &str = "/home/user/secret-plan.txt";

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
        authorization_resource: Some(RESOURCE),
        authorization_parameter_hash: Some("parameter-hash-raw-1"),
        enforcement_mode: "enforce",
    }
}

fn project(fields: &AcpReceiptFields<'_>, seed: u64) -> (AcpReceiptProjection, MetadataOpenings) {
    let rng = rng(seed);
    let mut committer = MetadataCommitter::project(&rng);
    let projection = AcpReceiptProjection::project_with(fields, &mut committer).test_unwrap();
    (projection, committer.into_openings())
}

/// The single-block receipt check: rebuild under `openings`, finish once, compare.
fn check(
    projection: &AcpReceiptProjection,
    fields: &AcpReceiptFields<'_>,
    openings: &MetadataOpenings,
) -> Result<bool, MetadataCommitmentError> {
    let mut committer = MetadataCommitter::verify(openings);
    let rebuilt = AcpReceiptProjection::project_with(fields, &mut committer)?;
    committer.finish()?;
    Ok(rebuilt == *projection)
}

fn salt_ref(text: &str) -> SaltRef {
    SaltRef::new(text).test_unwrap()
}

#[test]
fn acp_projection_carries_no_raw_member_but_the_session_id() {
    let fields = acp_fields();
    let (projection, openings) = project(&fields, 0);
    assert_eq!(check(&projection, &fields, &openings), Ok(true));
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
    assert_eq!(value.get("sessionId"), Some(&json!(SESSION_ID)));
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
    let (projection, openings) = project(&fields, 0);
    assert_eq!(openings.len(), 2);
    assert_eq!(check(&projection, &fields, &openings), Ok(true));
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
    let (projection, openings) = project(&fields, 0);
    let other = AcpReceiptFields {
        authorization_resource: Some("/home/user/other.txt"),
        ..acp_fields()
    };
    assert_eq!(
        check(&projection, &other, &openings),
        Err(MetadataCommitmentError::MetadataCommitmentMismatch {
            salt_ref: salt_ref("metadata.receipt_context.authorization_resource"),
        })
    );
    let other_session = AcpReceiptFields {
        session_id: "acp-session-2",
        ..acp_fields()
    };
    assert_eq!(check(&projection, &other_session, &openings), Ok(false));
    assert_eq!(
        check(&projection, &fields, &MetadataOpenings::new()),
        Err(MetadataCommitmentError::OpeningUnavailable {
            salt_ref: salt_ref("metadata.acp.tool_call_id"),
        })
    );
    let (_, other_openings) = project(&fields, 1_000);
    assert_eq!(check(&projection, &fields, &other_openings), Ok(false));
    let mut padded = openings.clone();
    padded
        .commit_value(
            salt_ref("metadata.acp.unused"),
            MetadataValue::from_json(&"unused").test_unwrap(),
            &rng(5_000),
        )
        .test_unwrap();
    assert_eq!(
        check(&projection, &fields, &padded),
        Err(MetadataCommitmentError::UnusedOpening {
            salt_ref: salt_ref("metadata.acp.unused"),
        })
    );
}

#[test]
fn acp_and_receipt_context_share_one_committer_and_one_finish() {
    let fields = acp_fields();
    let resource_ref = metadata_salt_ref("receipt_context", "authorization_resource").test_unwrap();
    let rng = rng(0);
    let mut committer = MetadataCommitter::project(&rng);
    let acp = AcpReceiptProjection::project_with(&fields, &mut committer).test_unwrap();
    let context_resource = committer
        .commit(resource_ref.clone(), &RESOURCE)
        .test_unwrap();
    assert_eq!(acp.authorization_resource.as_ref(), Some(&context_resource));
    let openings = committer.into_openings();
    assert_eq!(openings.len(), 10);

    let mut receipt = MetadataCommitter::verify(&openings);
    assert!(acp.matches_with(&fields, &mut receipt));
    assert_eq!(
        receipt.commit(resource_ref.clone(), &RESOURCE),
        Ok(context_resource.clone())
    );
    assert_eq!(receipt.finish(), Ok(()));

    let mut context_only = MetadataCommitter::verify(&openings);
    assert_eq!(
        context_only.commit(resource_ref, &RESOURCE),
        Ok(context_resource)
    );
    assert_eq!(
        context_only.finish(),
        Err(MetadataCommitmentError::UnusedOpening {
            salt_ref: salt_ref("metadata.acp.authorization_correlation_id"),
        })
    );
}

#[test]
fn acp_projection_rejects_unknown_members() {
    let fields = acp_fields();
    let (projection, _) = project(&fields, 0);
    let mut value = serde_json::to_value(&projection).test_unwrap();
    value["authorizationResourceRaw"] = json!(RESOURCE);
    let error = serde_json::from_value::<AcpReceiptProjection>(value).test_unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("unknown field `authorizationResourceRaw`"),
        "{error}"
    );
}

use super::support::*;
use chio_core_types::{
    receipt::{
        body::ChioReceipt,
        kinds::{BoundaryClass, ObservationOutcome, ReceiptKind, TrustLevel},
    },
    Signature,
};
use chio_test_support::prelude::*;
use chio_transaction_passport::TransactionPassportError;
use serde_json::Value;

const RECEIPT_PATH: &str = "receipts/receipt-agent-web-webhook-allow.json";

#[test]
fn unsupported_protocol_has_unsupported_class() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    replace_agent_web_json_artifact(&mut bundle, "mcp-manifest.json", |manifest| {
        manifest["source_protocol"] = Value::String("unregistered-protocol".to_string());
    });
    let error = verify_agent_web_interop(&bundle).test_expect_err("unknown protocol refuses");
    assert_eq!(
        error,
        TransactionPassportError::AgentWebUnsupported(
            "unsupported Agent Web source protocol: unregistered-protocol".to_string()
        )
    );
}

#[test]
fn unsupported_mcp_revision_has_unsupported_class() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    replace_agent_web_json_artifact(&mut bundle, "mcp-manifest.json", |manifest| {
        manifest["source_version"] = Value::String("2024-11-05".to_string());
    });
    let error =
        verify_agent_web_interop(&bundle).test_expect_err("unsupported MCP revision refuses");
    assert_eq!(
        error,
        TransactionPassportError::AgentWebUnsupported("unsupported MCP source version".to_string())
    );
}

#[test]
fn empty_protocol_keeps_claim_class() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    replace_agent_web_json_artifact(&mut bundle, "mcp-manifest.json", |manifest| {
        manifest["source_protocol"] = Value::String(String::new());
    });
    let error = verify_agent_web_interop(&bundle).test_expect_err("empty protocol refuses");
    assert_eq!(
        error,
        TransactionPassportError::AgentWebClaimFailed(
            "source_protocol must not be empty".to_string()
        )
    );
}

#[test]
fn non_draft_graphql_shape_keeps_claim_class() {
    let bundle = agent_web_bundle(AgentWebCase::GraphqlHttpDraftVersionMissing);
    let error =
        verify_agent_web_interop(&bundle).test_expect_err("non-draft GraphQL shape refuses");
    assert_eq!(
        error,
        TransactionPassportError::AgentWebClaimFailed(
            "GraphQL over HTTP version must be draft-labeled".to_string()
        )
    );
}

#[test]
fn signed_trace_observation_has_claim_class() {
    assert_non_mediated_receipt_refuses(
        ReceiptKind::TraceObservation,
        TrustLevel::Verified,
        BoundaryClass::DetectOnly,
        ObservationOutcome::Observed,
    );
}

#[test]
fn signed_advisory_evaluation_has_claim_class() {
    assert_non_mediated_receipt_refuses(
        ReceiptKind::AdvisoryEvaluation,
        TrustLevel::Advisory,
        BoundaryClass::AdvisoryOnly,
        ObservationOutcome::Evaluated,
    );
}

fn assert_non_mediated_receipt_refuses(
    kind: ReceiptKind,
    trust_level: TrustLevel,
    boundary: BoundaryClass,
    outcome: ObservationOutcome,
) {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    replace_agent_web_json_artifact(&mut bundle, RECEIPT_PATH, |value| {
        let receipt: ChioReceipt =
            serde_json::from_value(value.clone()).test_expect("receipt decodes");
        assert_receipt_crypto_valid(&receipt);
        let mut body = receipt.body();
        body.receipt_kind = kind;
        body.trust_level = trust_level;
        body.boundary_class = boundary;
        body.observation_outcome = Some(outcome);
        body.decision = None;
        body.validate_signable_semantics()
            .test_expect("receipt semantics are signable");
        let signed = ChioReceipt::sign(body, &agent_web_fixture_kernel_keypair())
            .test_expect("non-mediated receipt signs");
        assert_receipt_crypto_valid(&signed);
        *value = serde_json::to_value(signed).test_expect("receipt serializes");
    });
    let error = verify_agent_web_interop(&bundle).test_expect_err("non-mediated receipt refuses");
    assert_eq!(
        error,
        TransactionPassportError::AgentWebClaimFailed(
            "Agent Web receipt is not a mediated decision".to_string()
        )
    );
}

#[test]
fn invalid_receipt_signature_keeps_signature_class() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    replace_agent_web_json_artifact(&mut bundle, RECEIPT_PATH, |value| {
        let mut receipt: ChioReceipt =
            serde_json::from_value(value.clone()).test_expect("receipt decodes");
        assert_receipt_crypto_valid(&receipt);
        receipt.signature = Signature::from_hex(&"00".repeat(64)).test_expect("signature decodes");
        assert!(!receipt
            .verify_integrity_embedded_key()
            .test_expect("signature verification completes"));
        assert!(receipt
            .action
            .verify_hash()
            .test_expect("action hash verifies"));
        *value = serde_json::to_value(receipt).test_expect("receipt serializes");
    });
    let error = verify_agent_web_interop(&bundle).test_expect_err("invalid signature refuses");
    assert_eq!(
        error,
        TransactionPassportError::AgentWebSignatureInvalid(
            "Agent Web receipt signature invalid".to_string()
        )
    );
}

#[test]
fn supported_protocols_and_signed_mediated_receipt_verify() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    replace_agent_web_json_artifact(&mut bundle, RECEIPT_PATH, |value| {
        let receipt: ChioReceipt =
            serde_json::from_value(value.clone()).test_expect("receipt decodes");
        assert_receipt_crypto_valid(&receipt);
        let signed = ChioReceipt::sign(receipt.body(), &agent_web_fixture_kernel_keypair())
            .test_expect("mediated receipt signs");
        assert_receipt_crypto_valid(&signed);
        *value = serde_json::to_value(signed).test_expect("receipt serializes");
    });
    verify_agent_web_interop(&bundle)
        .test_expect("supported projections and mediated receipt verify");
}

fn assert_receipt_crypto_valid(receipt: &ChioReceipt) {
    assert!(receipt
        .verify_integrity_embedded_key()
        .test_expect("signature verifies"));
    assert!(receipt
        .action
        .verify_hash()
        .test_expect("action hash verifies"));
}

//! Offline PSP commerce order fixture shared by the commerce order suites.
use std::path::{Path, PathBuf};

use chio_core_types::crypto::{Keypair, PublicKey};
use chio_core_types::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
    kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel},
    metadata::ActorRef,
};
use chio_test_support::prelude::*;

pub(crate) fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|crates_dir| crates_dir.parent())
        .and_then(|workspace| workspace.parent())
        .test_expect("workspace root is parent of crates/platform/chio-commerce-order")
        .to_path_buf()
}

pub(crate) fn fixture_dir(case_name: &str) -> PathBuf {
    workspace_root().join(format!("fixtures/proof-room/commerce-payments/{case_name}"))
}

pub(crate) fn read_fixture(dir: &Path, name: &str) -> Vec<u8> {
    let case_path = dir.join(name);
    let path = if case_path.is_file() {
        case_path
    } else {
        fixture_dir("offline-psp-valid").join(name)
    };
    std::fs::read(path).test_expect("fixture file reads")
}

pub(crate) fn commerce_payment_signer_key() -> PublicKey {
    Keypair::from_seed(&[7u8; 32]).public_key()
}

pub(crate) fn commerce_provider_trust_signer_key() -> PublicKey {
    Keypair::from_seed(&[8u8; 32]).public_key()
}

pub(crate) fn commerce_provider_trust_signer() -> Keypair {
    Keypair::from_seed(&[8u8; 32])
}

pub(crate) fn commerce_event_authority_receipt_key() -> PublicKey {
    Keypair::from_seed(&[9u8; 32]).public_key()
}

pub(crate) fn commerce_event_authority_receipt_signer() -> Keypair {
    Keypair::from_seed(&[9u8; 32])
}

pub(crate) fn risk_comptroller_signer_key() -> PublicKey {
    PublicKey::from_hex("3f0dda81e6abbcc5f17c359df8517177769d2dfff3d4ce942e7ce9a82dfb0db2")
        .test_expect("enterprise risk comptroller signer key parses")
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    hex::encode(Sha256::digest(bytes))
}

pub(crate) fn mandate_protocol_payloads() -> Vec<chio_commerce_order::CommerceMandateProtocolPayload>
{
    [
        ("ap2", "checkout_mandate"),
        ("ap2", "payment_mandate"),
        ("acp-commerce", "delegated_payment_token"),
        ("x402", "payment_requirements"),
        ("chio", "authority_projection"),
    ]
    .into_iter()
    .map(
        |(protocol, purpose)| chio_commerce_order::CommerceMandateProtocolPayload {
            protocol: protocol.to_string(),
            purpose: purpose.to_string(),
            payload_bytes: mandate_protocol_payload_bytes(protocol, purpose),
        },
    )
    .collect()
}

pub(crate) fn mandate_protocol_payload_bytes(protocol: &str, purpose: &str) -> Vec<u8> {
    let payload = serde_json::json!({
        "schema": chio_commerce_order::COMMERCE_PROTOCOL_PAYLOAD_SCHEMA_ID,
        "protocol": protocol,
        "purpose": purpose,
        "order_id": "order-commerce-001",
        "amount_minor": 4200,
        "currency": "USD",
        "merchant_subject": "merchant:stripe:coffee-shop",
    });
    chio_core_types::canonical_json_bytes(&payload).test_expect("payload canonicalizes")
}

pub(crate) fn canonical_context_sha256(
    context: &chio_commerce_order::CommerceOrderContext,
) -> String {
    let canonical =
        chio_core_types::canonical_json_bytes(context).test_expect("order context canonicalizes");
    sha256_hex(&canonical)
}

pub(crate) fn load_bundle(case_name: &str) -> chio_commerce_order::CommerceOrderVerificationBundle {
    let dir = fixture_dir(case_name);
    let context_bytes = read_fixture(&dir, "order-context.json");
    let mut order_context: chio_commerce_order::CommerceOrderContext =
        serde_json::from_slice(&context_bytes).test_expect("order context parses");
    let event_log_bytes = read_fixture(&dir, "event-log.json");
    let provider_passport_bytes =
        signed_provider_trust_artifact_bytes(read_fixture(&dir, "provider-passport.json"));
    let reputation_snapshot_bytes =
        signed_provider_trust_artifact_bytes(read_fixture(&dir, "reputation-snapshot.json"));
    let federation_trust_bundle_bytes =
        signed_provider_trust_artifact_bytes(read_fixture(&dir, "federation-trust-bundle.json"));
    order_context.provider_passport_sha256 = sha256_hex(&provider_passport_bytes);
    order_context.reputation_snapshot_sha256 = sha256_hex(&reputation_snapshot_bytes);
    order_context.federation_trust_bundle_sha256 = sha256_hex(&federation_trust_bundle_bytes);

    chio_commerce_order::CommerceOrderVerificationBundle {
        order_context,
        event_log_bytes: event_log_bytes.clone(),
        event_authority_receipts: event_authority_receipt_artifacts(&event_log_bytes),
        payment_lifecycle_bytes: read_fixture(&dir, "payment-lifecycle.json"),
        mandate_ledger_bytes: read_fixture(&dir, "mandate-allowance-ledger.json"),
        provider_passport_bytes,
        reputation_snapshot_bytes,
        federation_trust_bundle_bytes,
        settlement_packet_bytes: read_fixture(&dir, "settlement-packet.json"),
        mandate_protocol_payloads: mandate_protocol_payloads(),
        risk_comptroller_report_bytes: None,
        escrow_ledger_bytes: None,
        verified_trust_market_context: None,
        trusted_event_authority_receipt_kernel_keys: vec![commerce_event_authority_receipt_key()],
        trusted_payment_signer_keys: vec![commerce_payment_signer_key()],
        trusted_provider_trust_signer_keys: vec![commerce_provider_trust_signer_key()],
        trusted_risk_comptroller_signer_keys: vec![risk_comptroller_signer_key()],
    }
}

pub(crate) fn event_authority_receipt_artifacts(
    event_log_bytes: &[u8],
) -> Vec<chio_commerce_order::CommerceEventAuthorityReceiptArtifact> {
    let event_log: serde_json::Value =
        serde_json::from_slice(event_log_bytes).test_expect("event log parses");
    let events = event_log["events"]
        .as_array()
        .test_expect("event log events array");
    events
        .iter()
        .map(event_authority_receipt_artifact)
        .collect()
}

pub(crate) fn event_authority_receipt_artifact(
    event: &serde_json::Value,
) -> chio_commerce_order::CommerceEventAuthorityReceiptArtifact {
    let receipt_ref = event["authority_receipt_ref"]
        .as_str()
        .test_expect("event authority receipt ref")
        .to_string();
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: receipt_ref.clone(),
            timestamp: 1_781_072_000,
            capability_id: format!("cap-{receipt_ref}"),
            tool_server: "chio-commerce-order-authority".to_string(),
            tool_name: event["transition"]
                .as_str()
                .test_expect("event transition")
                .to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "authority_receipt_ref": receipt_ref,
                "event_id": event["event_id"],
                "order_id": event["order_id"],
                "transition": event["transition"],
            }))
            .test_expect("authority receipt action hashes"),
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: vec![ActorRef {
                actor_id: event["actor"]
                    .as_str()
                    .test_expect("event actor")
                    .to_string(),
                actor_kind: Some("agent".to_string()),
            }],
            content_hash: event["event_sha256"]
                .as_str()
                .test_expect("event digest")
                .to_string(),
            policy_hash: sha256_hex(b"chio.commerce.event-authority.v1"),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: commerce_event_authority_receipt_key(),
            bbs_projection_version: None,
        },
        &commerce_event_authority_receipt_signer(),
    )
    .test_expect("authority receipt signs");
    chio_commerce_order::CommerceEventAuthorityReceiptArtifact {
        receipt_ref,
        schema: "chio.receipt.v1".to_string(),
        receipt_bytes: serde_json::to_vec(&receipt).test_expect("receipt JSON serializes"),
    }
}

pub(crate) fn signed_provider_trust_artifact_bytes(bytes: Vec<u8>) -> Vec<u8> {
    let mut value: serde_json::Value =
        serde_json::from_slice(&bytes).test_expect("provider trust artifact parses");
    sign_provider_trust_value(&mut value);
    serde_json::to_vec(&value).test_expect("provider trust artifact serializes")
}

pub(crate) fn sign_provider_trust_value(value: &mut serde_json::Value) {
    value
        .as_object_mut()
        .test_expect("provider trust artifact object")
        .remove("signature");
    let (signature, _) = commerce_provider_trust_signer()
        .sign_canonical(value)
        .test_expect("provider trust artifact signs");
    value["signature"] = serde_json::Value::String(signature.to_hex());
}

pub(crate) fn mutate_event_log(
    bundle: &mut chio_commerce_order::CommerceOrderVerificationBundle,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    mutate_event_log_with_sealing(bundle, mutate, true);
}

pub(crate) fn mutate_event_log_with_sealing(
    bundle: &mut chio_commerce_order::CommerceOrderVerificationBundle,
    mutate: impl FnOnce(&mut serde_json::Value),
    seal_events: bool,
) {
    let mut event_log: serde_json::Value =
        serde_json::from_slice(&bundle.event_log_bytes).test_expect("event log parses");
    mutate(&mut event_log);
    if seal_events {
        seal_event_log(&mut event_log, &bundle.order_context.agent_subject);
    }
    bundle.event_log_bytes = serde_json::to_vec(&event_log).test_expect("event log serializes");
    bundle.order_context.event_log_sha256 = sha256_hex(&bundle.event_log_bytes);
    if seal_events {
        bundle.event_authority_receipts =
            event_authority_receipt_artifacts(&bundle.event_log_bytes);
    }
}

pub(crate) fn seal_event_log(event_log: &mut serde_json::Value, default_actor: &str) {
    let events = event_log["events"]
        .as_array_mut()
        .test_expect("event log events array");
    for event in events {
        if event.get("actor").is_none() {
            event["actor"] = serde_json::Value::String(default_actor.to_string());
        }
        event
            .as_object_mut()
            .test_expect("event object")
            .remove("event_sha256");
        let canonical =
            chio_core_types::canonical_json_bytes(event).test_expect("event canonicalizes");
        event["event_sha256"] = serde_json::Value::String(sha256_hex(&canonical));
    }
}

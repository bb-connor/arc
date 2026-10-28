use crate::error::CommerceOrderError;
use crate::mandate::CommerceMandateLedger;
use crate::replay::{replay_event_log, CommerceEventLog};
use crate::settlement::validate_settlement_packet;
use crate::types::{
    CommerceEventAuthorityReceiptArtifact, CommerceOrderContext, CommercePaymentLifecycle,
    CommerceSettlementPacket,
};
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::body::{ChioReceipt, CHIO_RECEIPT_SCHEMA};
use chio_test_support::prelude::*;
use serde::de::DeserializeOwned;
use std::path::Path;

fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../fixtures/proof-room/commerce-payments/offline-psp-valid")
        .join(name);
    std::fs::read(path).test_expect("commerce fixture reads")
}

fn fixture<T: DeserializeOwned>(name: &str) -> T {
    serde_json::from_slice(&fixture_bytes(name)).test_expect("commerce fixture decodes")
}

struct ReceiptFixture {
    context: CommerceOrderContext,
    payment: CommercePaymentLifecycle,
    mandate: CommerceMandateLedger,
    settlement: CommerceSettlementPacket,
    events: CommerceEventLog,
    receipts: Vec<CommerceEventAuthorityReceiptArtifact>,
    signer: Keypair,
    first_receipt_ref: String,
    dispatch_event_sha256: String,
}

impl ReceiptFixture {
    fn load() -> Self {
        let event_json: serde_json::Value = fixture("event-log.json");
        let events = event_json["events"].as_array().test_expect("event list");
        let receipts = events
            .iter()
            .map(|event| {
                let receipt_ref = event["authority_receipt_ref"]
                    .as_str()
                    .test_expect("event receipt ref")
                    .to_owned();
                CommerceEventAuthorityReceiptArtifact {
                    receipt_bytes: fixture_bytes(&format!("authority-receipts/{receipt_ref}.json")),
                    receipt_ref,
                    schema: CHIO_RECEIPT_SCHEMA.to_owned(),
                }
            })
            .collect();
        let dispatch = events
            .iter()
            .find(|event| event["transition"] == "dispatch_settlement")
            .test_expect("settlement dispatch event");
        Self {
            context: fixture("order-context.json"),
            payment: fixture("payment-lifecycle.json"),
            mandate: fixture("mandate-allowance-ledger.json"),
            settlement: fixture("settlement-packet.json"),
            events: fixture("event-log.json"),
            receipts,
            signer: Keypair::from_seed(&[7_u8; 32]),
            first_receipt_ref: events[0]["authority_receipt_ref"]
                .as_str()
                .test_expect("first receipt ref")
                .to_owned(),
            dispatch_event_sha256: dispatch["event_sha256"]
                .as_str()
                .test_expect("dispatch event digest")
                .to_owned(),
        }
    }

    fn change_receipt(&mut self, receipt_ref: &str, invalidate_action_hash: bool) {
        let artifact = self
            .receipts
            .iter_mut()
            .find(|artifact| artifact.receipt_ref == receipt_ref)
            .test_expect("receipt artifact exists");
        let mut receipt: ChioReceipt =
            serde_json::from_slice(&artifact.receipt_bytes).test_expect("receipt decodes");
        assert_eq!(receipt.kernel_key, self.signer.public_key());
        if invalidate_action_hash {
            let mut body = receipt.body();
            body.action.parameter_hash = "00".repeat(32);
            receipt = ChioReceipt::sign(body, &self.signer).test_expect("receipt signs");
            assert!(receipt
                .verify_integrity_embedded_key()
                .test_expect("signature verifies"));
            assert!(!receipt
                .action
                .verify_hash()
                .test_expect("action hash checks"));
        } else {
            receipt.timestamp += 1;
            assert!(!receipt
                .verify_integrity_embedded_key()
                .test_expect("signature checks"));
            assert!(receipt
                .action
                .verify_hash()
                .test_expect("action hash verifies"));
        }
        artifact.receipt_bytes = serde_json::to_vec(&receipt).test_expect("receipt serializes");
    }

    fn replay(&self) -> Result<(), CommerceOrderError> {
        replay_event_log(
            &self.events,
            &self.context,
            &self.payment,
            &self.mandate,
            &self.receipts,
            &[self.signer.public_key()],
        )
        .map(|_| ())
    }

    fn settle(&self) -> Result<(), CommerceOrderError> {
        validate_settlement_packet(
            &self.context,
            &self.payment,
            &self.settlement,
            &self.receipts,
            &[self.signer.public_key()],
            Some(&self.settlement.dispatch_receipt_ref),
            Some(&self.dispatch_event_sha256),
        )
    }
}

#[test]
fn replay_action_hash_mismatch_uses_digest_class() {
    let mut fixture = ReceiptFixture::load();
    let receipt_ref = fixture.first_receipt_ref.clone();
    fixture.change_receipt(&receipt_ref, true);
    assert_eq!(
        fixture.replay(),
        Err(CommerceOrderError::ReplayDigestMismatch(format!(
            "authority receipt action hash invalid: {receipt_ref}"
        )))
    );
}

#[test]
fn settlement_action_hash_mismatch_uses_digest_class() {
    let mut fixture = ReceiptFixture::load();
    let receipt_ref = fixture.settlement.dispatch_receipt_ref.clone();
    fixture.change_receipt(&receipt_ref, true);
    assert_eq!(
        fixture.settle(),
        Err(CommerceOrderError::SettlementDigestMismatch(format!(
            "settlement dispatch receipt action hash invalid: {receipt_ref}"
        )))
    );
}

#[test]
fn replay_signature_failure_keeps_signature_class() {
    let mut fixture = ReceiptFixture::load();
    let receipt_ref = fixture.first_receipt_ref.clone();
    fixture.change_receipt(&receipt_ref, false);
    assert_eq!(
        fixture.replay(),
        Err(CommerceOrderError::ReplaySignatureInvalid(format!(
            "authority receipt signature invalid: {receipt_ref}"
        )))
    );
}

#[test]
fn settlement_signature_failure_keeps_signature_class() {
    let mut fixture = ReceiptFixture::load();
    let receipt_ref = fixture.settlement.dispatch_receipt_ref.clone();
    fixture.change_receipt(&receipt_ref, false);
    assert_eq!(
        fixture.settle(),
        Err(CommerceOrderError::SettlementSignatureInvalid(format!(
            "settlement dispatch receipt signature invalid: {receipt_ref}"
        )))
    );
}

#[test]
fn valid_authority_receipts_verify_for_replay_and_settlement() {
    let fixture = ReceiptFixture::load();
    assert_eq!(fixture.replay(), Ok(()));
    assert_eq!(fixture.settle(), Ok(()));
}

#[test]
fn replay_action_hash_encoding_error_keeps_failure_class() {
    let error = chio_core_types::error::Error::CanonicalJson("unsupported JSON number".to_owned());
    assert_eq!(
        crate::replay::action_hash_encoding_error("receipt-ref", error),
        CommerceOrderError::ReplayFailed(
            "authority receipt action hash invalid: receipt-ref: canonical JSON error: unsupported JSON number"
                .to_owned()
        )
    );
}

#[test]
fn settlement_action_hash_encoding_error_keeps_failure_class() {
    let error = chio_core_types::error::Error::CanonicalJson("unsupported JSON number".to_owned());
    assert_eq!(
        crate::settlement::action_hash_encoding_error("receipt-ref", error),
        CommerceOrderError::SettlementFailed(
            "settlement dispatch receipt action hash invalid: receipt-ref: canonical JSON error: unsupported JSON number"
                .to_owned()
        )
    );
}

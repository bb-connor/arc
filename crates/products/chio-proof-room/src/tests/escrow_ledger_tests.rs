use std::collections::BTreeMap;

use chio_commerce_order::{
    CommerceEscrowLedger, CommerceEscrowLeg, CommerceEscrowLegKind, CommerceEscrowStatus,
    CommerceOrderContext, COMMERCE_ESCROW_CUSTODY_ACCOUNT, COMMERCE_ESCROW_LEDGER_SCHEMA_ID,
};

use crate::{embedded_commerce_escrow_ledger_bytes, sha256_hex, ProofRoomEmbeddedEvidenceNode};

#[derive(Default)]
struct EmbeddedLedgers {
    nodes: Vec<ProofRoomEmbeddedEvidenceNode>,
    artifacts: BTreeMap<String, Vec<u8>>,
}

impl EmbeddedLedgers {
    fn add(&mut self, path: &str, ledger: &CommerceEscrowLedger) -> Vec<u8> {
        let bytes = ledger_bytes(ledger);
        let sha256 = sha256_hex(&bytes);
        self.nodes.push(ProofRoomEmbeddedEvidenceNode {
            id: sha256.clone(),
            role: "commerce-escrow-ledger".to_string(),
            schema: COMMERCE_ESCROW_LEDGER_SCHEMA_ID.to_string(),
            path: path.to_string(),
            sha256,
        });
        self.artifacts.insert(path.to_string(), bytes.clone());
        bytes
    }

    fn load(&self, context: &CommerceOrderContext) -> Result<Option<Vec<u8>>, String> {
        embedded_commerce_escrow_ledger_bytes(&self.nodes, &self.artifacts, context)
    }
}

fn ledger(status: CommerceEscrowStatus) -> CommerceEscrowLedger {
    let lock = CommerceEscrowLeg {
        kind: CommerceEscrowLegKind::Lock,
        from_account: "buyer:alice".to_string(),
        to_account: COMMERCE_ESCROW_CUSTODY_ACCOUNT.to_string(),
        amount_minor: 4200,
    };
    let legs = match status {
        CommerceEscrowStatus::Locked => vec![lock],
        CommerceEscrowStatus::Released => vec![
            lock,
            CommerceEscrowLeg {
                kind: CommerceEscrowLegKind::Release,
                from_account: COMMERCE_ESCROW_CUSTODY_ACCOUNT.to_string(),
                to_account: "merchant:coffee".to_string(),
                amount_minor: 4200,
            },
        ],
    };
    CommerceEscrowLedger {
        schema: COMMERCE_ESCROW_LEDGER_SCHEMA_ID.to_string(),
        order_id: "order-commerce-001".to_string(),
        currency: "USD".to_string(),
        depositor_account: "buyer:alice".to_string(),
        beneficiary_account: "merchant:coffee".to_string(),
        custody_account: COMMERCE_ESCROW_CUSTODY_ACCOUNT.to_string(),
        amount_minor: 4200,
        legs,
        status,
    }
}

fn ledger_bytes(ledger: &CommerceEscrowLedger) -> Vec<u8> {
    match chio_core_types::canonical_json_bytes(ledger) {
        Ok(bytes) => bytes,
        Err(error) => panic!("ledger canonicalizes: {error}"),
    }
}

fn digest(ledger: &CommerceEscrowLedger) -> String {
    match ledger.digest() {
        Ok(digest) => digest,
        Err(error) => panic!("ledger digest: {error}"),
    }
}

fn context(escrow_digest: Option<String>) -> CommerceOrderContext {
    let hex64 = "11".repeat(32);
    let value = serde_json::json!({
        "schema": chio_commerce_order::COMMERCE_ORDER_CONTEXT_SCHEMA_ID,
        "id": "ctx-1",
        "issued_at": "2026-06-25T00:00:00Z",
        "order_id": "order-commerce-001",
        "buyer_subject": "buyer:alice",
        "agent_subject": "agent:alice",
        "merchant_subject": "merchant:coffee",
        "intent_ref": "intent-1",
        "provider_admission_ref": "admission-1",
        "provider_passport_ref": "passport-1",
        "reputation_snapshot_ref": "reputation-1",
        "federation_trust_bundle_ref": "federation-1",
        "quote_id": "quote-1",
        "quote_amount_minor": 4200u64,
        "quote_currency": "USD",
        "quote_sha256": hex64,
        "settlement_packet_ref": "settlement-packet-1",
        "reconciliation_ref": "reconciliation-1",
        "event_log_sha256": hex64,
        "event_log_path": "event-log.json",
        "payment_lifecycle_sha256": hex64,
        "payment_lifecycle_path": "payment-lifecycle.json",
        "mandate_ledger_sha256": hex64,
        "mandate_ledger_path": "mandate-ledger.json",
        "provider_passport_sha256": hex64,
        "provider_passport_path": "provider-passport.json",
        "reputation_snapshot_sha256": hex64,
        "reputation_snapshot_path": "reputation-snapshot.json",
        "federation_trust_bundle_sha256": hex64,
        "federation_trust_bundle_path": "federation-trust-bundle.json",
        "settlement_packet_sha256": hex64,
        "settlement_packet_path": "settlement-packet.json",
        "current_state": "completed",
        "escrow_digest": escrow_digest,
    });
    match serde_json::from_value(value) {
        Ok(context) => context,
        Err(error) => panic!("order context: {error}"),
    }
}

#[test]
fn embedded_escrow_ledger_selects_the_pinned_node_from_locked_and_released() {
    let mut ledgers = EmbeddedLedgers::default();
    ledgers.add(
        "escrow-ledger-locked.json",
        &ledger(CommerceEscrowStatus::Locked),
    );
    let released = ledger(CommerceEscrowStatus::Released);
    let released_bytes = ledgers.add("escrow-ledger-released.json", &released);

    assert_eq!(
        ledgers.load(&context(Some(digest(&released)))),
        Ok(Some(released_bytes))
    );
}

#[test]
fn embedded_escrow_ledger_refuses_a_pin_no_node_matches() {
    let mut ledgers = EmbeddedLedgers::default();
    ledgers.add(
        "escrow-ledger-locked.json",
        &ledger(CommerceEscrowStatus::Locked),
    );
    let pinned = digest(&ledger(CommerceEscrowStatus::Released));

    assert_eq!(
        ledgers.load(&context(Some(pinned.clone()))),
        Err(format!(
            "no commerce escrow ledger matches pinned digest {pinned}"
        ))
    );
}

#[test]
fn embedded_escrow_ledger_refuses_two_nodes_with_the_pinned_digest() {
    let mut ledgers = EmbeddedLedgers::default();
    let released = ledger(CommerceEscrowStatus::Released);
    ledgers.add("escrow-ledger-a.json", &released);
    ledgers.add("escrow-ledger-b.json", &released);
    let pinned = digest(&released);

    assert_eq!(
        ledgers.load(&context(Some(pinned.clone()))),
        Err(format!(
            "multiple commerce escrow ledgers match pinned digest {pinned}"
        ))
    );
}

#[test]
fn embedded_escrow_ledger_loads_nothing_without_a_pin() {
    let mut ledgers = EmbeddedLedgers::default();
    ledgers.add(
        "escrow-ledger.json",
        &ledger(CommerceEscrowStatus::Released),
    );

    assert_eq!(ledgers.load(&context(None)), Ok(None));
}

#[test]
fn embedded_escrow_ledger_refuses_a_pin_without_a_node() {
    let pinned = digest(&ledger(CommerceEscrowStatus::Released));

    assert_eq!(
        EmbeddedLedgers::default().load(&context(Some(pinned.clone()))),
        Err(format!(
            "missing commerce escrow ledger for pinned digest {pinned}"
        ))
    );
}

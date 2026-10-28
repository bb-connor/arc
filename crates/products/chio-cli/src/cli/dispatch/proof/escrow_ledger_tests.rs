use super::*;
use chio_commerce_order::{
    CommerceEscrowLedger, CommerceEscrowLeg, CommerceEscrowLegKind, CommerceEscrowStatus,
    COMMERCE_ESCROW_CUSTODY_ACCOUNT, COMMERCE_ESCROW_LEDGER_SCHEMA_ID,
};
use chio_errors::_generated::error_codes::{
    TRANSACTION_ARTIFACT_HASH_MISMATCH, TRANSACTION_ARTIFACT_SCHEMA_INVALID,
    TRANSACTION_GRAPH_NOT_CLOSED,
};

const INTEGRITY: i32 = 20;
const SCHEMA: i32 = 30;
const LABEL: &str = "commerce";

struct LedgerBundle {
    dir: tempfile::TempDir,
    nodes: Vec<GraphArtifactNode>,
}

impl LedgerBundle {
    fn new() -> Self {
        match tempfile::tempdir() {
            Ok(dir) => Self {
                dir,
                nodes: Vec::new(),
            },
            Err(error) => panic!("tempdir: {error}"),
        }
    }

    fn write(&self, path: &str, bytes: &[u8]) {
        if let Err(error) = std::fs::write(self.dir.path().join(path), bytes) {
            panic!("write {path}: {error}");
        }
    }

    fn add_ledger(&mut self, path: &str, ledger: &CommerceEscrowLedger) -> Vec<u8> {
        let bytes = ledger_bytes(ledger);
        self.write(path, &bytes);
        self.add_node(path, COMMERCE_ESCROW_LEDGER_ROLE, COMMERCE_ESCROW_LEDGER_SCHEMA_ID, &bytes);
        bytes
    }

    fn add_node(&mut self, path: &str, role: &str, schema: &str, bytes: &[u8]) {
        let sha256 = chio_core::sha256_hex(bytes);
        self.nodes.push(GraphArtifactNode {
            id: Some(sha256.clone()),
            path: path.to_string(),
            role: role.to_string(),
            sha256: Some(sha256),
            schema: Some(schema.to_string()),
        });
    }

    fn load(&self, context: &chio_commerce_order::CommerceOrderContext) -> Result<Option<Vec<u8>>, CliError> {
        self.load_with(context, &mut crate::input::collection::Budget::default())
    }

    fn load_with(
        &self,
        context: &chio_commerce_order::CommerceOrderContext,
        budget: &mut crate::input::collection::Budget,
    ) -> Result<Option<Vec<u8>>, CliError> {
        load_commerce_escrow_ledger_bytes(self.dir.path(), budget, &self.nodes, context, LABEL)
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
    match chio_core::canonical_json_bytes(ledger) {
        Ok(bytes) => bytes,
        Err(error) => panic!("ledger bytes: {error}"),
    }
}

fn digest(ledger: &CommerceEscrowLedger) -> String {
    match ledger.digest() {
        Ok(digest) => digest,
        Err(error) => panic!("ledger digest: {error}"),
    }
}

fn context(escrow_digest: Option<String>) -> chio_commerce_order::CommerceOrderContext {
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
        "quote_sha256": "11".repeat(32),
        "settlement_packet_ref": "settlement-packet-1",
        "reconciliation_ref": "reconciliation-1",
        "event_log_sha256": "11".repeat(32),
        "event_log_path": "event-log.json",
        "payment_lifecycle_sha256": "11".repeat(32),
        "payment_lifecycle_path": "payment-lifecycle.json",
        "mandate_ledger_sha256": "11".repeat(32),
        "mandate_ledger_path": "mandate-ledger.json",
        "provider_passport_sha256": "11".repeat(32),
        "provider_passport_path": "provider-passport.json",
        "reputation_snapshot_sha256": "11".repeat(32),
        "reputation_snapshot_path": "reputation-snapshot.json",
        "federation_trust_bundle_sha256": "11".repeat(32),
        "federation_trust_bundle_path": "federation-trust-bundle.json",
        "settlement_packet_sha256": "11".repeat(32),
        "settlement_packet_path": "settlement-packet.json",
        "current_state": "completed",
        "escrow_digest": escrow_digest,
    });
    match serde_json::from_value(value) {
        Ok(context) => context,
        Err(error) => panic!("order context: {error}"),
    }
}

fn rejection(result: Result<Option<Vec<u8>>, CliError>) -> CliError {
    match result {
        Ok(loaded) => panic!("expected an escrow ledger refusal, loaded {loaded:?}"),
        Err(error) => error,
    }
}

fn assert_refusal(
    error: CliError,
    spec: &chio_errors::ErrorCodeSpec,
    exit_code: i32,
    message: &str,
) {
    assert_eq!(error.report().code, spec.urn, "{error}");
    assert_eq!(proof_verify_exit_code(&error), exit_code, "{error}");
    assert!(error.to_string().contains(message), "{error}");
}

#[test]
fn selects_the_pinned_ledger_from_a_graph_holding_locked_and_released_ledgers() {
    let mut bundle = LedgerBundle::new();
    bundle.add_ledger("escrow-ledger-locked.json", &ledger(CommerceEscrowStatus::Locked));
    let released = ledger(CommerceEscrowStatus::Released);
    let released_bytes = bundle.add_ledger("escrow-ledger-released.json", &released);
    let loaded = bundle.load(&context(Some(digest(&released))));
    assert_eq!(loaded.ok(), Some(Some(released_bytes)));
}

#[test]
fn refuses_a_pinned_digest_that_matches_no_ledger() {
    let mut bundle = LedgerBundle::new();
    bundle.add_ledger("escrow-ledger-locked.json", &ledger(CommerceEscrowStatus::Locked));
    let pinned = digest(&ledger(CommerceEscrowStatus::Released));
    let error = rejection(bundle.load(&context(Some(pinned.clone()))));
    assert_refusal(
        error,
        &TRANSACTION_ARTIFACT_HASH_MISMATCH,
        INTEGRITY,
        &format!("proof verify: no commerce escrow ledger matches pinned digest {pinned}"),
    );
}

#[test]
fn refuses_two_ledgers_with_the_pinned_digest() {
    let mut bundle = LedgerBundle::new();
    let released = ledger(CommerceEscrowStatus::Released);
    bundle.add_ledger("escrow-ledger-a.json", &released);
    bundle.add_ledger("escrow-ledger-b.json", &released);
    let pinned = digest(&released);
    let error = rejection(bundle.load(&context(Some(pinned.clone()))));
    assert_refusal(
        error,
        &TRANSACTION_ARTIFACT_SCHEMA_INVALID,
        SCHEMA,
        &format!("proof verify: multiple commerce escrow ledgers match pinned digest {pinned}"),
    );
}

#[test]
fn loads_nothing_without_a_pin_even_with_a_ledger_node() {
    let mut bundle = LedgerBundle::new();
    bundle.add_ledger("escrow-ledger.json", &ledger(CommerceEscrowStatus::Released));
    assert_eq!(bundle.load(&context(None)).ok(), Some(None));
}

#[test]
fn refuses_a_pinned_digest_without_a_ledger_node() {
    let bundle = LedgerBundle::new();
    let pinned = digest(&ledger(CommerceEscrowStatus::Released));
    let error = rejection(bundle.load(&context(Some(pinned.clone()))));
    assert_refusal(
        error,
        &TRANSACTION_GRAPH_NOT_CLOSED,
        INTEGRITY,
        &format!("proof verify: missing commerce escrow ledger for pinned digest {pinned}"),
    );
}

#[test]
fn refuses_ledger_bytes_that_disagree_with_the_graph_digest() {
    let mut bundle = LedgerBundle::new();
    let released = ledger(CommerceEscrowStatus::Released);
    bundle.add_ledger("escrow-ledger.json", &released);
    let mut padded = ledger_bytes(&released);
    padded.push(b'\n');
    bundle.write("escrow-ledger.json", &padded);
    let error = rejection(bundle.load(&context(Some(digest(&released)))));
    assert_refusal(
        error,
        &TRANSACTION_ARTIFACT_HASH_MISMATCH,
        INTEGRITY,
        "proof verify: commerce artifact digest mismatch for escrow-ledger.json",
    );
}

#[test]
fn refuses_a_ledger_node_with_another_schema() {
    let mut bundle = LedgerBundle::new();
    let released = ledger(CommerceEscrowStatus::Released);
    let bytes = ledger_bytes(&released);
    bundle.write("escrow-ledger.json", &bytes);
    bundle.add_node(
        "escrow-ledger.json",
        COMMERCE_ESCROW_LEDGER_ROLE,
        "chio.commerce.escrow-ledger.v2",
        &bytes,
    );
    let error = rejection(bundle.load(&context(Some(digest(&released)))));
    assert_refusal(
        error,
        &TRANSACTION_ARTIFACT_SCHEMA_INVALID,
        SCHEMA,
        "proof verify: unsupported commerce artifact schema for escrow-ledger.json: chio.commerce.escrow-ledger.v2",
    );
}

#[test]
fn charges_every_candidate_ledger_to_the_shared_collection_budget() {
    let mut bundle = LedgerBundle::new();
    let locked = bundle.add_ledger("escrow-ledger-locked.json", &ledger(CommerceEscrowStatus::Locked));
    let released = ledger(CommerceEscrowStatus::Released);
    bundle.add_ledger("escrow-ledger-released.json", &released);
    let mut budget = crate::input::collection::Budget::default();
    if let Err(error) = budget.charge(crate::input::collection::MAX_BYTES - locked.len()) {
        panic!("charge: {error}");
    }
    let error = rejection(bundle.load_with(&context(Some(digest(&released))), &mut budget));
    assert!(
        error.to_string().contains("artifact collection byte budget exhausted"),
        "{error}"
    );
}

//! Commerce bundles whose order context pins an escrow ledger.
use super::*;

const COMMERCE_ESCROW_LEDGER_ROLE: &str = "commerce-escrow-ledger";
const COMMERCE_ESCROW_LEDGER_PATH: &str = "escrow-ledger.json";

/// The escrow ledger bytes a pinned order context proves, read from the graph
/// node in the escrow ledger role. An order context without a pin has none.
pub(crate) fn pinned_escrow_ledger_bytes(
    bundle: &Path,
    evidence_graph: &serde_json::Value,
    order_context: &chio_commerce_order::CommerceOrderContext,
) -> Option<Vec<u8>> {
    order_context.escrow_digest.as_ref()?;
    let path = evidence_graph["nodes"]
        .as_array()
        .test_expect("graph nodes array")
        .iter()
        .find(|node| node["role"].as_str() == Some(COMMERCE_ESCROW_LEDGER_ROLE))
        .and_then(|node| node["path"].as_str())
        .test_expect("graph has the pinned escrow ledger node");
    Some(std::fs::read(bundle.join(path)).test_expect("read escrow ledger"))
}

/// The offline PSP commerce bundle with its completed order backed by a
/// released escrow ledger pinned in the order context. Without
/// `keep_ledger_node` the ledger node is dropped from the transaction evidence
/// graph after the bundle is sealed and the proof-room layer is removed, so
/// the transaction passport is verified directly and its pin has no ledger.
pub(crate) fn build_commerce_escrow_bundle(keep_ledger_node: bool) -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let bundle = tempdir.path().join("commerce-escrow");
    copy_dir_all(&source, &bundle).test_expect("copy commerce bundle");

    let order_context_path = bundle.join("order-context.json");
    let mut order_context: chio_commerce_order::CommerceOrderContext = serde_json::from_slice(
        &std::fs::read(&order_context_path).test_expect("read order context"),
    )
    .test_expect("order context parses");
    let ledger = released_escrow_ledger(&order_context);
    let ledger_path = bundle.join(COMMERCE_ESCROW_LEDGER_PATH);
    std::fs::write(
        &ledger_path,
        chio_core::canonical_json_bytes(&ledger).test_expect("escrow ledger bytes"),
    )
    .test_expect("write escrow ledger");
    order_context.escrow_digest = Some(ledger.digest().test_expect("escrow ledger digest"));
    write_json(
        &order_context_path,
        &serde_json::to_value(&order_context).test_expect("order context serializes"),
    );

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    let ledger_sha256 = sha256_file(&ledger_path);
    evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
        .push(serde_json::json!({
            "id": ledger_sha256,
            "schema": chio_commerce_order::COMMERCE_ESCROW_LEDGER_SCHEMA_ID,
            "path": COMMERCE_ESCROW_LEDGER_PATH,
            "sha256": ledger_sha256,
            "role": COMMERCE_ESCROW_LEDGER_ROLE,
        }));
    refresh_commerce_order_passport(&bundle, &mut evidence_graph);
    write_transaction_graph(&bundle, &mut evidence_graph);
    sync_proof_room_transaction_roots(&bundle);

    if !keep_ledger_node {
        evidence_graph["nodes"]
            .as_array_mut()
            .test_expect("graph nodes array")
            .retain(|node| node["role"].as_str() != Some(COMMERCE_ESCROW_LEDGER_ROLE));
        write_transaction_graph(&bundle, &mut evidence_graph);
        for directory in ["roots", "verifier", "ui"] {
            std::fs::remove_dir_all(bundle.join(directory))
                .test_expect("drop proof-room layer directory");
        }
        for file in ["manifest.json", "bundle-signature.dsse.json"] {
            std::fs::remove_file(bundle.join(file)).test_expect("drop proof-room layer file");
        }
    }

    (tempdir, bundle)
}

fn write_transaction_graph(bundle: &Path, evidence_graph: &mut serde_json::Value) {
    let evidence_graph_path = bundle.join("evidence-graph.json");
    refresh_evidence_graph_content_ids(bundle, evidence_graph);
    write_json(&evidence_graph_path, evidence_graph);
    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] =
        serde_json::Value::String(sha256_file(&evidence_graph_path));
    write_json(&passport_path, &passport);
}

fn released_escrow_ledger(
    order_context: &chio_commerce_order::CommerceOrderContext,
) -> chio_commerce_order::CommerceEscrowLedger {
    use chio_commerce_order::{CommerceEscrowLeg, CommerceEscrowLegKind};
    let custody = chio_commerce_order::COMMERCE_ESCROW_CUSTODY_ACCOUNT.to_string();
    chio_commerce_order::CommerceEscrowLedger {
        schema: chio_commerce_order::COMMERCE_ESCROW_LEDGER_SCHEMA_ID.to_string(),
        order_id: order_context.order_id.clone(),
        currency: order_context.quote_currency.clone(),
        depositor_account: order_context.buyer_subject.clone(),
        beneficiary_account: order_context.merchant_subject.clone(),
        custody_account: custody.clone(),
        amount_minor: order_context.quote_amount_minor,
        legs: vec![
            CommerceEscrowLeg {
                kind: CommerceEscrowLegKind::Lock,
                from_account: order_context.buyer_subject.clone(),
                to_account: custody.clone(),
                amount_minor: order_context.quote_amount_minor,
            },
            CommerceEscrowLeg {
                kind: CommerceEscrowLegKind::Release,
                from_account: custody,
                to_account: order_context.merchant_subject.clone(),
                amount_minor: order_context.quote_amount_minor,
            },
        ],
        status: chio_commerce_order::CommerceEscrowStatus::Released,
    }
}

//! Single-slash-lane conformance harness.
//!
//! The full enforceable slashing machinery is a later deliverable. This
//! harness is its standing invariant: it pins the CURRENT shape of slashing
//! so future growth has to stay GREEN against it. The slash machinery may
//! grow, but it must not grow a SECOND slash lane or a parallel slash
//! authority - doing so turns this harness RED.
//!
//! Invariant under test (single slash lane):
//!
//!   (a) A slash routes ONLY through the comptroller. The risk comptroller's
//!       `validate_risk_report` is the sole adjudicator of a reserve drawdown
//!       (`reserve_slash` / `market_slash`). A slash that tries to skip the
//!       comptroller's adjudication chain (no sanction bridge, no dual sanction
//!       reserve ledger, over the adjudicated limit, or relabeled as a payout)
//!       is rejected FAIL-CLOSED.
//!   (b) There is no second / parallel slash authority. The reserve-drawdown
//!       classifier and the market-slash sanction adjudicator are defined in
//!       exactly one crate, `chio-risk-comptroller` (grep-style structural
//!       assertion), and behaviorally the comptroller is the only surface that
//!       admits a slash (positive + negative cases below). Introducing a second
//!       lane (a new crate that classifies/adjudicates a reserve drawdown)
//!       fails the structural assertion.
//!   (c) Double-consumption and pre-observed/ordering protections hold: a
//!       reserve cannot be slashed twice on the same (reserve, claim), and a
//!       slash reversal cannot be enacted without a prior adjudicated slash.
//!
//! `freetier:global` pool isolation (the Sybil-ceiling term is never
//! capital) rides along inside the same single comptroller lane and
//! is not re-asserted here (covered by the comptroller's own suite).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use chio_risk_comptroller::{validate_risk_report, RiskComptrollerReport};
use chio_transaction_passport::TransactionPassport;
use serde_json::{json, Value};

/// Workspace root: the conformance crate manifest is at
/// `<root>/crates/tooling/chio-conformance`, so the root is three ancestors up.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root is three parents above the conformance crate")
        .to_path_buf()
}

fn enterprise_fixture(case: &str, file: &str) -> PathBuf {
    workspace_root()
        .join("fixtures/proof-room/enterprise-export")
        .join(case)
        .join(file)
}

fn read_report_value(case: &str) -> Value {
    let bytes = fs::read(enterprise_fixture(case, "risk-comptroller-report.json"))
        .expect("risk comptroller report fixture reads");
    serde_json::from_slice(&bytes).expect("risk comptroller report parses")
}

fn read_passport(case: &str) -> TransactionPassport {
    let bytes = fs::read(enterprise_fixture(case, "transaction-passport.json"))
        .expect("transaction passport fixture reads");
    serde_json::from_slice(&bytes).expect("transaction passport parses")
}

fn parse_report(value: Value) -> RiskComptrollerReport {
    serde_json::from_value(value).expect("risk comptroller report reparses")
}

/// A fully-valid sanction-backed `market_slash` report that
/// `validate_risk_report` accepts. Built from the `open-appeal-claim-payout`
/// fixture and reshaped into a clean market slash: the stale claim-payout
/// capital instruction is removed (a market slash has no claim-payout lane).
///
/// This is the canonical "the comptroller IS the slash lane" positive. The
/// slash-lane negatives below are minimal mutations of this base so the named
/// comptroller rejection is the sole cause of failure.
fn market_slash_report_base() -> Value {
    let mut report = read_report_value("open-appeal-claim-payout");
    report["coverage"]["covered_claim_ids"] = json!(["claim-risk-market-slash"]);
    report["appeals"][0]["claim_id"] = json!("claim-risk-market-slash");
    report["appeals"][0]["status"] = json!("resolved");
    report["reconciliation"]["consumed_reserve_units"] = json!(100);
    report["reconciliation"]["payout_units"] = json!(0);
    report["reconciliation"]["settlement_units"] = json!(0);
    report["reserve_ledger"] = json!([
        {
            "entry_id": "risk-ledger-market-slash",
            "receipt_ref": "approval-case",
            "lane": "market_slash",
            "reserve_ref": "reserve-enterprise-valid",
            "claim_id": "claim-risk-market-slash",
            "currency": "USD",
            "units": 100,
            "settlement_ref": "evidence-export-bundle",
            "sanction_bridge": {
                "bridge_id": "sanction-bridge-risk-market-slash",
                "authority_receipt_ref": "approval-case",
                "evidence_ref": "data-governance-report",
                "jurisdiction_ref": "approval-case",
                "sanction_subject": "did:chio:buyer-enterprise",
                "maximum_slash_units": 100
            }
        }
    ]);
    report["sanction_reserve_ledger"] = json!([
        {
            "entry_id": "sanction-ledger-market-slash",
            "bridge_id": "sanction-bridge-risk-market-slash",
            "lane": "market_slash",
            "receipt_ref": "approval-case",
            "reserve_ref": "reserve-enterprise-valid",
            "claim_id": "claim-risk-market-slash",
            "currency": "USD",
            "units": 100,
            "settlement_ref": "evidence-export-bundle",
            "authority_receipt_ref": "approval-case",
            "evidence_ref": "data-governance-report",
            "jurisdiction_ref": "approval-case"
        }
    ]);
    report
        .as_object_mut()
        .expect("risk report is object")
        .remove("capital_instructions");
    report
}

/// A fully-valid `reserve_slash` report (the second slash sub-kind). It routes
/// through the same single comptroller lane and carries no sanction bridge.
fn reserve_slash_report_base() -> Value {
    let mut report = read_report_value("open-appeal-claim-payout");
    report["coverage"]["covered_claim_ids"] = json!(["claim-enterprise-valid"]);
    report["appeals"][0]["status"] = json!("resolved");
    report["reconciliation"]["consumed_reserve_units"] = json!(600);
    report["reconciliation"]["payout_units"] = json!(0);
    report["reconciliation"]["settlement_units"] = json!(0);
    report["reserve_ledger"] = json!([
        {
            "entry_id": "risk-ledger-reserve-slash",
            "receipt_ref": "risk-receipt-reserve-slash",
            "lane": "reserve_slash",
            "reserve_ref": "reserve-enterprise-valid",
            "claim_id": "claim-enterprise-valid",
            "currency": "USD",
            "units": 600,
            "settlement_ref": "settlement-enterprise-valid"
        }
    ]);
    report
        .as_object_mut()
        .expect("risk report is object")
        .remove("capital_instructions");
    report
}

// ---------------------------------------------------------------------------
// (a) A slash routes ONLY through the comptroller. The comptroller adjudicates
//     a genuine slash (the lane is the gate), and every attempt to enact a
//     slash outside that adjudication fails closed.
// ---------------------------------------------------------------------------

#[test]
fn comptroller_adjudicates_a_genuine_market_slash() {
    // The lane is the gate: a sanction-backed market slash, fully adjudicated by
    // the comptroller, is admitted. This is the slash lane.
    let passport = read_passport("open-appeal-claim-payout");
    let report = parse_report(market_slash_report_base());
    validate_risk_report(&passport, &report)
        .expect("a sanction-backed market slash must be admitted by the comptroller lane");
}

#[test]
fn comptroller_adjudicates_a_genuine_reserve_slash() {
    // The same single lane also adjudicates the reserve-slash sub-kind. Both
    // slash kinds route through `validate_risk_report`; there is no separate
    // entry point for either.
    let passport = read_passport("open-appeal-claim-payout");
    let report = parse_report(reserve_slash_report_base());
    validate_risk_report(&passport, &report)
        .expect("a reserve slash must be admitted by the same comptroller lane");
}

#[test]
fn slash_without_comptroller_sanction_adjudication_is_rejected() {
    // A bare `market_slash` ledger row with NO sanction-bridge adjudication is a
    // slash that tries to skip the comptroller's authority/evidence/jurisdiction
    // chain. It must fail closed: you cannot enact a slash by simply dropping a
    // ledger row. (This is the curated `market-slash-facility-reserve` negative.)
    let passport = read_passport("market-slash-facility-reserve");
    let report = parse_report(read_report_value("market-slash-facility-reserve"));
    let error = validate_risk_report(&passport, &report)
        .expect_err("a market slash with no sanction bridge must fail closed");
    assert!(
        error
            .to_string()
            .contains("risk market slash requires sanction bridge"),
        "expected missing-sanction-bridge rejection, got: {error}"
    );
}

#[test]
fn market_slash_without_dual_sanction_reserve_ledger_is_rejected() {
    // A market slash must be doubly adjudicated by the comptroller: the reserve
    // ledger row AND the bound sanction reserve ledger. Dropping the second
    // ledger fails closed.
    let passport = read_passport("open-appeal-claim-payout");
    let mut report = market_slash_report_base();
    report["sanction_reserve_ledger"] = json!([]);
    let report = parse_report(report);
    let error = validate_risk_report(&passport, &report)
        .expect_err("a market slash with no sanction reserve ledger must fail closed");
    assert!(
        error
            .to_string()
            .contains("risk sanction reserve ledger missing"),
        "expected missing-sanction-reserve-ledger rejection, got: {error}"
    );
}

#[test]
fn slash_exceeding_the_adjudicated_limit_is_rejected() {
    // The comptroller bounds the slash by the sanction bridge's authorized
    // maximum. A slash larger than what the comptroller adjudicated fails
    // closed; there is no path that authorizes more than the adjudicated limit.
    let passport = read_passport("open-appeal-claim-payout");
    let mut report = market_slash_report_base();
    report["reserve_ledger"][0]["sanction_bridge"]["maximum_slash_units"] = json!(50);
    let report = parse_report(report);
    let error = validate_risk_report(&passport, &report)
        .expect_err("a slash above the adjudicated limit must fail closed");
    assert!(
        error
            .to_string()
            .contains("risk market slash exceeds sanction bridge"),
        "expected over-limit slash rejection, got: {error}"
    );
}

#[test]
fn slash_relabeled_as_a_payout_is_rejected() {
    // A slash cannot be smuggled through the payout reconciliation lane. A
    // `reserve_slash` consumes reserve but contributes ZERO payout units, so a
    // report that reconciles it as a claim payout fails closed. Slash and payout
    // are not fungible accounting; there is exactly one reserve-consumption lane.
    let passport = read_passport("open-appeal-claim-payout");
    let mut report = read_report_value("open-appeal-claim-payout");
    report["coverage"]["covered_claim_ids"] = json!(["claim-enterprise-valid"]);
    report["appeals"][0]["status"] = json!("resolved");
    report["reserve_ledger"][0]["lane"] = json!("reserve_slash");
    let entry = report["reserve_ledger"][0]
        .as_object_mut()
        .expect("reserve ledger entry is object");
    entry.remove("payer_subject");
    entry.remove("payee_subject");
    report
        .as_object_mut()
        .expect("risk report is object")
        .remove("capital_instructions");
    let report = parse_report(report);
    let error = validate_risk_report(&passport, &report)
        .expect_err("a slash reconciled as a payout must fail closed");
    assert!(
        error.to_string().contains("risk payout ledger mismatch"),
        "expected slash-as-payout rejection, got: {error}"
    );
}

// ---------------------------------------------------------------------------
// (b) No second / parallel slash authority. Structural (grep-style) assertion:
//     the reserve-drawdown classifier and the market-slash sanction adjudicator
//     are defined in exactly one crate, chio-risk-comptroller. A second crate
//     introducing a parallel slash lane would fail this.
// ---------------------------------------------------------------------------

/// Collect every `.rs` file under a directory, skipping `target/` build trees.
fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().and_then(|name| name.to_str()) == Some("target") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    out
}

#[test]
fn there_is_no_second_slash_authority_in_the_workspace() {
    // Needles are assembled at runtime so this very test file (which is under
    // the scanned tree) never matches itself.
    let classifier_def = format!("{} is_terminal_reserve_consumption(", "fn");
    let sanction_adjudicator_def = format!("{} validate_risk_sanction_reserve_ledger", "fn");

    let crates_dir = workspace_root().join("crates");
    let sources = rust_sources(&crates_dir);
    assert!(
        !sources.is_empty(),
        "expected to scan the workspace crates for slash-authority definitions"
    );

    let mut classifier_sites = Vec::new();
    let mut sanction_adjudicator_sites = Vec::new();
    for path in &sources {
        let Ok(src) = fs::read_to_string(path) else {
            continue;
        };
        if src.contains(&classifier_def) {
            classifier_sites.push(path.clone());
        }
        if src.contains(&sanction_adjudicator_def) {
            sanction_adjudicator_sites.push(path.clone());
        }
    }

    // The reserve-drawdown classifier (the predicate that decides a ledger lane
    // consumes reserve, i.e. slashes capital) must be defined exactly once.
    assert_eq!(
        classifier_sites.len(),
        1,
        "the reserve-drawdown (slash) classifier must be defined exactly once; \
         a second definition means a parallel slash lane: {classifier_sites:?}"
    );
    assert!(
        classifier_sites[0]
            .to_string_lossy()
            .contains("chio-risk-comptroller"),
        "the reserve-drawdown (slash) classifier must live in the comptroller, found: {:?}",
        classifier_sites[0]
    );

    // The market-slash sanction adjudicator must live ONLY in the comptroller.
    assert!(
        !sanction_adjudicator_sites.is_empty(),
        "expected the comptroller to define the market-slash sanction adjudicator"
    );
    for site in &sanction_adjudicator_sites {
        assert!(
            site.to_string_lossy().contains("chio-risk-comptroller"),
            "the market-slash sanction adjudicator must live only in the comptroller; \
             a second site means a parallel slash authority: {site:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// (c) Double-consumption and pre-observed/ordering protections hold.
// ---------------------------------------------------------------------------

#[test]
fn slash_double_consumption_is_rejected() {
    // The same reserve cannot be slashed twice for the same claim: two terminal
    // `reserve_slash` rows on the same (reserve, claim) fail closed. This is the
    // double-consumption protection for the slash lane.
    let passport = read_passport("open-appeal-claim-payout");
    let mut report = read_report_value("open-appeal-claim-payout");
    report["coverage"]["covered_claim_ids"] = json!(["claim-enterprise-valid"]);
    report["appeals"][0]["status"] = json!("resolved");
    report["reconciliation"]["consumed_reserve_units"] = json!(200);
    report["reconciliation"]["payout_units"] = json!(0);
    report["reconciliation"]["settlement_units"] = json!(0);
    report["reserve_ledger"] = json!([
        {
            "entry_id": "risk-ledger-reserve-slash-a",
            "receipt_ref": "risk-receipt-reserve-slash-a",
            "lane": "reserve_slash",
            "reserve_ref": "reserve-enterprise-valid",
            "claim_id": "claim-enterprise-valid",
            "currency": "USD",
            "units": 100,
            "settlement_ref": "settlement-enterprise-valid"
        },
        {
            "entry_id": "risk-ledger-reserve-slash-b",
            "receipt_ref": "risk-receipt-reserve-slash-b",
            "lane": "reserve_slash",
            "reserve_ref": "reserve-enterprise-valid",
            "claim_id": "claim-enterprise-valid",
            "currency": "USD",
            "units": 100,
            "settlement_ref": "settlement-enterprise-valid"
        }
    ]);
    report
        .as_object_mut()
        .expect("risk report is object")
        .remove("capital_instructions");
    let report = parse_report(report);
    let error = validate_risk_report(&passport, &report)
        .expect_err("slashing the same reserve twice for one claim must fail closed");
    assert!(
        error
            .to_string()
            .contains("risk reserve double consumption"),
        "expected double-consumption rejection, got: {error}"
    );
}

#[test]
fn reverse_slash_without_a_prior_adjudicated_slash_is_rejected() {
    // Pre-observed / ordering protection: a slash REVERSAL cannot be enacted
    // unless a prior slash was adjudicated. A standalone `reverse_slash` with no
    // prior `reserve_slash` fails closed. (Curated `reverse-slash-without-prior-
    // penalty` negative.)
    let passport = read_passport("reverse-slash-without-prior-penalty");
    let report = parse_report(read_report_value("reverse-slash-without-prior-penalty"));
    let error = validate_risk_report(&passport, &report)
        .expect_err("a slash reversal with no prior slash must fail closed");
    assert!(
        error
            .to_string()
            .contains("risk reverse slash missing prior reserve slash"),
        "expected reverse-slash-without-prior rejection, got: {error}"
    );
}

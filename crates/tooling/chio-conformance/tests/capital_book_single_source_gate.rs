//! Single-source capital-book conformance harness.
//!
//! Threat / prudential rule: the Chio capital book is the source-of-funds truth
//! that attributes committed and disbursed funds to exactly one coherent capital
//! source. An auto-netting on-chain instrument would blend many facilities,
//! many reserve books, and many currencies into one book. The
//! prudential safeguard is the opposite: the capital book MUST be single-source
//! and fail closed. The production builder
//! (`build_capital_book_report_from_store`, reached here through the public
//! `build_signed_capital_book_report`) denies (HTTP 409 CONFLICT -> `CliError`)
//! whenever it is asked to span:
//!
//!   1. more than one current GRANTED facility (it will not blend live
//!      source-of-funds attribution across multiple active facilities),
//!   2. more than one current bond / reserve book (it will not blend multiple
//!      live reserve books into one deterministic capital source), or
//!   3. more than one currency (it does not auto-net live capital across
//!      currencies; per-currency segregation is the prudential safeguard).
//!
//! This harness stages a REAL [`SqliteReceiptStore`] with each adversarial
//! configuration and drives the REAL production builder, asserting the deny
//! fires fail-closed. It also pins the DO-NOT-WEAKEN invariant
//! ([`CapitalBookSupportBoundary::mixed_currency_netting_supported`] stays
//! `false`, books stay per-currency `mixed_currency_book`), and proves the
//! off-chain netted VIEW is a read-only projection that does NOT flip the
//! single-source rule: collapsing a mixed-currency book to one canonical
//! denomination leaves every prudential netting flag false.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_control_plane::trust_control::reports::build_signed_capital_book_report;
use chio_core::capability::runtime_attestation::RuntimeAssuranceTier;
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::Keypair;
use chio_core::receipt::lineage::SignedExportEnvelope;
use chio_credit::netting::{
    collapse_positions_to_canonical, CanonicalConversionRate, ExposureLedgerNettingRates,
};
use chio_kernel::{
    CapitalBookQuery, CapitalBookSupportBoundary, CreditBondArtifact, CreditBondDisposition,
    CreditBondLifecycleState, CreditBondPrerequisites, CreditBondReport, CreditBondSupportBoundary,
    CreditBondTerms, CreditFacilityArtifact, CreditFacilityCapitalSource,
    CreditFacilityDisposition, CreditFacilityLifecycleState, CreditFacilityPrerequisites,
    CreditFacilityReport, CreditFacilitySupportBoundary, CreditFacilityTerms, CreditScorecardBand,
    CreditScorecardConfidence, CreditScorecardSummary, CreditScorecardSupportBoundary,
    ExposureLedgerCurrencyPosition, ExposureLedgerQuery, ExposureLedgerSummary,
    ExposureLedgerSupportBoundary, SignedCreditBond, SignedCreditFacility,
    CREDIT_BOND_ARTIFACT_SCHEMA, CREDIT_BOND_REPORT_SCHEMA, CREDIT_FACILITY_ARTIFACT_SCHEMA,
    CREDIT_FACILITY_REPORT_SCHEMA,
};
use chio_store_sqlite::SqliteReceiptStore;
use std::path::{Path, PathBuf};

const SUBJECT: &str = "agent:capital-source-gate";

/// Far-future expiry (year 2100) so staged facilities and bonds stay ACTIVE
/// regardless of wall-clock time: an `Active` facility/bond whose `expires_at`
/// has passed is folded to `Expired` by the store, which would otherwise hide
/// it from the single-source count gates.
const FAR_FUTURE: u64 = 4_102_444_800;

fn monetary(units: u64, currency: &str) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: currency.to_string(),
    }
}

fn scorecard_summary() -> CreditScorecardSummary {
    CreditScorecardSummary {
        matching_receipts: 1,
        returned_receipts: 1,
        matching_decisions: 0,
        returned_decisions: 0,
        currencies: vec!["USD".to_string()],
        mixed_currency_book: false,
        confidence: CreditScorecardConfidence::High,
        band: CreditScorecardBand::Prime,
        overall_score: 0.95,
        anomaly_count: 0,
        probationary: false,
    }
}

/// An ACTIVE + GRANT facility whose `credit_limit` is denominated in
/// `currency`. The capital book counts it as a current granted facility and
/// folds `credit_limit.currency` into the single-coherent-currency check.
fn facility(facility_id: &str, currency: &str) -> SignedCreditFacility {
    let artifact = CreditFacilityArtifact {
        schema: CREDIT_FACILITY_ARTIFACT_SCHEMA.to_string(),
        facility_id: facility_id.to_string(),
        issued_at: 1_700_000_100,
        expires_at: FAR_FUTURE,
        lifecycle_state: CreditFacilityLifecycleState::Active,
        supersedes_facility_id: None,
        report: CreditFacilityReport {
            schema: CREDIT_FACILITY_REPORT_SCHEMA.to_string(),
            generated_at: 1_700_000_090,
            filters: ExposureLedgerQuery {
                agent_subject: Some(SUBJECT.to_string()),
                ..ExposureLedgerQuery::default()
            },
            scorecard: scorecard_summary(),
            disposition: CreditFacilityDisposition::Grant,
            prerequisites: CreditFacilityPrerequisites {
                minimum_runtime_assurance_tier: RuntimeAssuranceTier::Verified,
                runtime_assurance_met: true,
                certification_required: false,
                certification_met: true,
                manual_review_required: false,
            },
            support_boundary: CreditFacilitySupportBoundary::default(),
            terms: Some(CreditFacilityTerms {
                credit_limit: monetary(12_000, currency),
                utilization_ceiling_bps: 8_000,
                reserve_ratio_bps: 1_500,
                concentration_cap_bps: 3_000,
                ttl_seconds: 86_400,
                capital_source: CreditFacilityCapitalSource::OperatorInternal,
            }),
            findings: Vec::new(),
        },
    };
    SignedExportEnvelope::sign(artifact, &Keypair::generate()).unwrap()
}

/// A current (non-superseded) bond. When `terms_currency` is `Some`, the bond
/// carries reserve-book terms denominated in that currency; the capital book
/// folds every terms amount into the single-coherent-currency check.
fn bond(bond_id: &str, facility_id: &str, terms_currency: Option<&str>) -> SignedCreditBond {
    let terms = terms_currency.map(|currency| CreditBondTerms {
        facility_id: facility_id.to_string(),
        credit_limit: monetary(10_000, currency),
        collateral_amount: monetary(2_000, currency),
        reserve_requirement_amount: monetary(1_500, currency),
        outstanding_exposure_amount: monetary(1_000, currency),
        reserve_ratio_bps: 1_500,
        coverage_ratio_bps: 2_000,
        capital_source: CreditFacilityCapitalSource::OperatorInternal,
    });
    let artifact = CreditBondArtifact {
        schema: CREDIT_BOND_ARTIFACT_SCHEMA.to_string(),
        bond_id: bond_id.to_string(),
        issued_at: 1_700_000_200,
        expires_at: FAR_FUTURE,
        lifecycle_state: CreditBondLifecycleState::Active,
        supersedes_bond_id: None,
        report: CreditBondReport {
            schema: CREDIT_BOND_REPORT_SCHEMA.to_string(),
            generated_at: 1_700_000_190,
            filters: ExposureLedgerQuery {
                agent_subject: Some(SUBJECT.to_string()),
                ..ExposureLedgerQuery::default()
            },
            exposure: ExposureLedgerSummary {
                matching_receipts: 0,
                returned_receipts: 0,
                matching_decisions: 0,
                returned_decisions: 0,
                active_decisions: 0,
                superseded_decisions: 0,
                actionable_receipts: 0,
                pending_settlement_receipts: 0,
                failed_settlement_receipts: 0,
                currencies: vec!["USD".to_string()],
                mixed_currency_book: false,
                truncated_receipts: false,
                truncated_decisions: false,
            },
            scorecard: scorecard_summary(),
            disposition: CreditBondDisposition::Lock,
            prerequisites: CreditBondPrerequisites {
                active_facility_required: true,
                active_facility_met: true,
                runtime_assurance_met: true,
                certification_required: false,
                certification_met: true,
                currency_coherent: true,
            },
            support_boundary: CreditBondSupportBoundary::default(),
            latest_facility_id: Some(facility_id.to_string()),
            terms,
            findings: Vec::new(),
        },
    };
    SignedExportEnvelope::sign(artifact, &Keypair::generate()).unwrap()
}

/// Open a fresh receipt store at `path`, record the supplied facilities and
/// bonds, and close it so the production builder can re-open the same file.
fn stage_store(path: &Path, facilities: &[SignedCreditFacility], bonds: &[SignedCreditBond]) {
    let mut store = SqliteReceiptStore::open(path).unwrap();
    for f in facilities {
        store.record_credit_facility(f).unwrap();
    }
    for b in bonds {
        store.record_credit_bond(b).unwrap();
    }
    drop(store);
}

fn query() -> CapitalBookQuery {
    CapitalBookQuery {
        agent_subject: Some(SUBJECT.to_string()),
        ..CapitalBookQuery::default()
    }
}

struct Staged {
    _dir: tempfile::TempDir,
    db_path: PathBuf,
}

fn staged(facilities: &[SignedCreditFacility], bonds: &[SignedCreditBond]) -> Staged {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("receipts.sqlite3");
    stage_store(&db_path, facilities, bonds);
    Staged { _dir: dir, db_path }
}

/// Drive the production builder with NO authority material. A single-source
/// book reaches the (then-failing) signing step; a multi-source book is denied
/// fail-closed BEFORE signing, so the returned error is the single-source deny
/// itself rather than the missing-authority error.
fn build_unsigned(staged: &Staged) -> Result<(), String> {
    build_signed_capital_book_report(&staged.db_path, None, None, &query())
        .map(|_| ())
        .map_err(|error| error.to_string())
}

// (a) SINGLE-SOURCE: more than one current granted facility is denied.
#[test]
fn capital_book_denies_more_than_one_active_granted_facility() {
    let staged = staged(&[facility("cfd-1", "USD"), facility("cfd-2", "USD")], &[]);
    let err = build_unsigned(&staged).expect_err(
        "capital book must deny a configuration that spans more than one active granted facility",
    );
    assert!(
        err.contains("one current granted facility") || err.contains("multiple active facilities"),
        "expected single-facility-source deny, got: {err}"
    );
}

// (a) SINGLE-SOURCE: more than one current bond / reserve book is denied.
#[test]
fn capital_book_denies_more_than_one_current_bond() {
    let staged = staged(
        &[],
        &[bond("cbd-1", "cfd-1", None), bond("cbd-2", "cfd-1", None)],
    );
    let err = build_unsigned(&staged)
        .expect_err("capital book must deny a configuration that spans more than one current bond");
    assert!(
        err.contains("one current bond posture") || err.contains("multiple live reserve books"),
        "expected single-bond-source deny, got: {err}"
    );
}

// (b) MIXED CURRENCY: a book that mixes currencies is denied (no auto-netting).
#[test]
fn capital_book_denies_mixed_currency_capital() {
    // One granted facility in USD, one bond whose reserve-book terms are in EUR:
    // a single facility and a single bond (neither count gate trips), but two
    // currencies, so the coherent-currency gate denies.
    let staged = staged(
        &[facility("cfd-1", "USD")],
        &[bond("cbd-1", "cfd-1", Some("EUR"))],
    );
    let err = build_unsigned(&staged).expect_err(
        "capital book must deny a mixed-currency configuration; Chio does not auto-net live capital across currencies",
    );
    assert!(
        err.contains("one coherent currency")
            || err.contains("does not auto-net live capital across currencies"),
        "expected mixed-currency deny, got: {err}"
    );

    // DO-NOT-WEAKEN: the prudential support-boundary flag stays default-false.
    // Mixed-currency capital allocation is not a supported capability.
    assert!(
        !CapitalBookSupportBoundary::default().mixed_currency_netting_supported,
        "mixed_currency_netting_supported must stay false (per-currency book is the safeguard)"
    );
}

// (b) POSITIVE CONTROL: a legitimate single facility + single bond + single
// currency passes the single-source gate, is signed, and stays per-currency.
#[test]
fn single_source_capital_book_is_admitted_and_stays_per_currency() {
    let staged = staged(
        &[facility("cfd-1", "USD")],
        &[bond("cbd-1", "cfd-1", Some("USD"))],
    );
    // Provide a throwaway authority seed so the admitted report is signed.
    let seed_path = staged._dir.path().join("authority-seed.hex");
    let signed =
        build_signed_capital_book_report(&staged.db_path, Some(&seed_path), None, &query())
            .expect("a single-source USD capital book must be admitted by the single-source gate");

    let report = &signed.body;
    assert_eq!(report.subject_key, SUBJECT);
    assert_eq!(
        report.summary.returned_facilities, 1,
        "exactly one facility backs the single-source book"
    );
    assert_eq!(
        report.summary.returned_bonds, 1,
        "exactly one bond backs the single-source book"
    );
    assert!(
        !report.summary.mixed_currency_book,
        "a single-currency book must report mixed_currency_book = false"
    );
    assert_eq!(report.summary.currencies, vec!["USD".to_string()]);
    assert!(
        !report.support_boundary.mixed_currency_netting_supported,
        "the admitted report must carry the prudential mixed_currency_netting flag false"
    );
    assert!(report.support_boundary.source_of_funds_authoritative);
}

// (c) READ-ONLY PROJECTION: the off-chain netted VIEW does NOT flip the
// single-source rule. Collapsing a mixed-currency book to one canonical
// denomination is a read-only projection: every prudential netting flag stays
// false and the capital-book support-boundary default is unchanged.
#[test]
fn netted_view_does_not_flip_single_source_rule() {
    let usd = ExposureLedgerCurrencyPosition {
        currency: "USD".to_string(),
        governed_max_exposure_units: 0,
        reserved_units: 100,
        settled_units: 0,
        pending_units: 0,
        failed_units: 0,
        provisional_loss_units: 0,
        recovered_units: 0,
        quoted_premium_units: 0,
        active_quoted_premium_units: 0,
    };
    let eur = ExposureLedgerCurrencyPosition {
        currency: "EUR".to_string(),
        reserved_units: 200,
        ..usd.clone()
    };
    let rates = ExposureLedgerNettingRates::new(vec![CanonicalConversionRate {
        currency: "EUR".to_string(),
        numerator: 11,
        denominator: 10,
    }]);

    let view = collapse_positions_to_canonical(&[usd, eur], &rates)
        .expect("a fully rated mixed-currency book must collapse");

    // The projection observes a mixed-currency book...
    assert!(
        view.mixed_currency_book,
        "the source book under the read-only projection is mixed-currency"
    );

    // ...yet it flips NONE of the three prudential netting flags, and needs no
    // on-chain instrument or new contract.
    let boundary = &view.support_boundary;
    assert!(boundary.read_only_projection);
    assert!(boundary.prudential_book_unchanged);
    assert!(!boundary.cross_currency_netting_supported);
    assert!(!boundary.capital_allocation_supported);
    assert!(!boundary.mixed_currency_netting_supported);
    assert!(!boundary.on_chain_instrument_required);
    assert!(!boundary.new_contract_required);

    // The netted view carries the flags straight off the prudential defaults,
    // proving the read-only collapse never weakened the single-source rule.
    assert_eq!(
        boundary.mixed_currency_netting_supported,
        CapitalBookSupportBoundary::default().mixed_currency_netting_supported
    );
    assert_eq!(
        boundary.cross_currency_netting_supported,
        ExposureLedgerSupportBoundary::default().cross_currency_netting_supported
    );
    assert_eq!(
        boundary.capital_allocation_supported,
        CreditScorecardSupportBoundary::default().capital_allocation_supported
    );
}

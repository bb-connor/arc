//! The invariants the comparison rests on, asserted without the bench script.

use chio_composed_baseline::harness::Runner;
use chio_composed_baseline::negative;
use chio_composed_baseline::properties;
use chio_composed_baseline::receiver::{BaselineProfile, DurabilityMode};
use chio_composed_baseline::scenario::Keys;
use chio_composed_baseline::substitution;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The twenty threat identifiers of the Chio negative corpus fixture.
const CHIO_THREAT_IDS: &[&str] = &[
    "PS-TH-01", "PS-TH-02", "PS-TH-03", "PS-TH-04", "PS-TH-05", "PS-TH-06", "PS-TH-07", "PS-TH-08",
    "PS-TH-09", "PS-TH-10", "PS-TH-11", "PS-TH-12", "PS-TH-13", "PS-TH-14", "PS-TH-15", "PS-TH-16",
    "PS-TH-17", "PS-TH-18", "PS-TH-19", "PS-TH-20",
];

fn work_dir(name: &str) -> Result<std::path::PathBuf, String> {
    let dir = std::env::temp_dir().join(format!("composed-baseline-test-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    Ok(dir)
}

#[test]
fn every_chio_threat_identifier_is_answered() -> TestResult {
    let dir = work_dir("threats")?;
    let keys = Keys::fixed();
    let composed = Runner::new(
        &keys,
        BaselineProfile::Composed,
        DurabilityMode::BeforeDispatch,
        &dir,
    );
    let hardened = Runner::new(
        &keys,
        BaselineProfile::Hardened,
        DurabilityMode::BeforeDispatch,
        &dir,
    );
    let results = negative::run(&composed, &hardened)?;
    for threat in CHIO_THREAT_IDS {
        assert!(
            results.iter().any(|result| result.threat_id == *threat),
            "the corpus does not answer {threat}"
        );
    }
    Ok(())
}

#[test]
fn the_null_case_is_admitted_under_both_wirings() -> TestResult {
    let dir = work_dir("null")?;
    let keys = Keys::fixed();
    let composed = Runner::new(
        &keys,
        BaselineProfile::Composed,
        DurabilityMode::BeforeDispatch,
        &dir,
    );
    let hardened = Runner::new(
        &keys,
        BaselineProfile::Hardened,
        DurabilityMode::BeforeDispatch,
        &dir,
    );
    let results = negative::run(&composed, &hardened)?;
    let null_case = results
        .iter()
        .find(|result| result.baseline_case_id == "unmodified-admissible-call")
        .ok_or("the corpus carries no null case")?;
    let composed_observed = null_case.composed.as_ref().ok_or("null case did not run")?;
    let hardened_observed = null_case.hardened.as_ref().ok_or("null case did not run")?;
    assert!(
        composed_observed.dispatched && hardened_observed.dispatched,
        "the null case must dispatch, or no denial in the corpus is attributable"
    );
    Ok(())
}

/// Three attacks survive the hardened wiring, and they are the three the
/// composition cannot reach by operator effort: a field it carries and never
/// compares, a validity window only the signer bounds, and an authorization
/// that is reusable because the replay table is keyed by a value the caller
/// chooses. If a change makes one of these deny, the comparison's central
/// result has moved and the paper's text must move with it.
#[test]
fn hardening_does_not_close_the_structural_gaps() -> TestResult {
    let dir = work_dir("structural")?;
    let keys = Keys::fixed();
    let composed = Runner::new(
        &keys,
        BaselineProfile::Composed,
        DurabilityMode::BeforeDispatch,
        &dir,
    );
    let hardened = Runner::new(
        &keys,
        BaselineProfile::Hardened,
        DurabilityMode::BeforeDispatch,
        &dir,
    );
    let results = negative::run(&composed, &hardened)?;
    let mut surviving: Vec<&str> = results
        .iter()
        .filter(|result| result.baseline_case_id != "unmodified-admissible-call")
        .filter(|result| {
            result
                .hardened
                .as_ref()
                .is_some_and(|observed| observed.dispatched)
        })
        .map(|result| result.baseline_case_id)
        .collect();
    surviving.sort_unstable();
    assert_eq!(
        surviving,
        vec![
            "authorization-replay-under-fresh-identifier",
            "signer-minted-decade-window",
            "unbound-resource-field",
        ]
    );
    Ok(())
}

/// Ten of the sixteen substitution rows have no carrier at all, and the five
/// the composition does notice are noticed identically under both wirings.
#[test]
fn the_substitution_corpus_covers_the_fifteen_binding_fields() -> TestResult {
    let dir = work_dir("substitution")?;
    let keys = Keys::fixed();
    let composed = Runner::new(
        &keys,
        BaselineProfile::Composed,
        DurabilityMode::BeforeDispatch,
        &dir,
    );
    let hardened = Runner::new(
        &keys,
        BaselineProfile::Hardened,
        DurabilityMode::BeforeDispatch,
        &dir,
    );
    let results = substitution::run(&composed, &hardened)?;
    assert_eq!(
        results.len(),
        16,
        "the signer list occupies two of the rows"
    );
    let fields: std::collections::BTreeSet<&str> = results
        .iter()
        .map(|result| {
            result
                .chio_field
                .split(',')
                .next()
                .unwrap_or(result.chio_field)
        })
        .collect();
    assert_eq!(fields.len(), 15);
    assert_eq!(
        results
            .iter()
            .filter(|result| result.noticed_composed)
            .count(),
        5
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.noticed_hardened)
            .count(),
        5
    );
    Ok(())
}

/// Admission binding fails under both wirings and single use holds only in a
/// weakened form under both, so neither is reachable by hardening. Receiver
/// locality and audience binding are reachable, and are the two the hardened
/// wiring holds.
#[test]
fn the_property_verdicts_are_what_the_paper_reports() -> TestResult {
    let dir = work_dir("properties")?;
    let keys = Keys::fixed();
    let composed = Runner::new(
        &keys,
        BaselineProfile::Composed,
        DurabilityMode::BeforeDispatch,
        &dir,
    );
    let hardened = Runner::new(
        &keys,
        BaselineProfile::Hardened,
        DurabilityMode::BeforeDispatch,
        &dir,
    );
    let negative_results = negative::run(&composed, &hardened)?;
    let properties = properties::evaluate(&negative_results)?;
    assert_eq!(properties.len(), 4);
    let verdicts: Vec<(&str, String, String)> = properties
        .iter()
        .map(|property| {
            (
                property.property,
                format!("{:?}", property.composed),
                format!("{:?}", property.hardened),
            )
        })
        .collect();
    assert_eq!(
        verdicts,
        vec![
            (
                "admission binding",
                "Fails".to_string(),
                "Fails".to_string()
            ),
            (
                "receiver locality",
                "Fails".to_string(),
                "Holds".to_string()
            ),
            (
                "single use",
                "HoldsWeakened".to_string(),
                "HoldsWeakened".to_string()
            ),
            ("audience binding", "Fails".to_string(), "Holds".to_string()),
        ]
    );
    Ok(())
}

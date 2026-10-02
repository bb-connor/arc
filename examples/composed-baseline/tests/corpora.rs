//! The invariants the comparison rests on, asserted without the bench script.

use chio_composed_baseline::carriers;
use chio_composed_baseline::harness::Runner;
use chio_composed_baseline::jose::CompactJws;
use chio_composed_baseline::negative;
use chio_composed_baseline::negative::CaseRole;
use chio_composed_baseline::properties;
use chio_composed_baseline::receiver::{
    BaselineProfile, DurabilityMode, PrivateProfile, DENIAL_CODES,
};
use chio_composed_baseline::scenario::{self, Keys};
use chio_composed_baseline::spec;
use chio_composed_baseline::substitution;
use serde_json::Value;
use std::collections::BTreeSet;

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

fn wirings<'a>(keys: &'a Keys, dir: &'a std::path::Path) -> (Runner<'a>, Runner<'a>) {
    (
        Runner::new(
            keys,
            BaselineProfile::Composed,
            DurabilityMode::BeforeDispatch,
            dir,
        ),
        Runner::new(
            keys,
            BaselineProfile::Hardened,
            DurabilityMode::BeforeDispatch,
            dir,
        ),
    )
}

#[test]
fn every_chio_threat_identifier_is_answered() -> TestResult {
    let dir = work_dir("threats")?;
    let keys = Keys::fixed();
    let (composed, hardened) = wirings(&keys, &dir);
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
    let (composed, hardened) = wirings(&keys, &dir);
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

/// Four attacks survive the hardened wiring, and each is a fact no field of the
/// four formats carries in a form the receiver can resolve: a version the
/// caller asserts, arguments no credential covers, an instance no scope names,
/// and a receiver-minted handle nothing consumes. If a change makes any of them
/// deny, or adds a fifth survivor, the comparison's central result has moved
/// and the paper's text must move with it.
#[test]
fn hardening_does_not_close_the_structural_gaps() -> TestResult {
    let dir = work_dir("structural")?;
    let keys = Keys::fixed();
    let (composed, hardened) = wirings(&keys, &dir);
    let results = negative::run(&composed, &hardened)?;
    let mut surviving: Vec<&str> = results
        .iter()
        .filter(|result| result.role == CaseRole::Attack)
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
            "arguments-differ-from-authorized-call",
            "asserted-version-matches-receiver-record",
            "call-unbound-to-its-resource",
            "task-handle-reused-across-calls",
        ]
    );
    Ok(())
}

/// Every denial either corpus produces is in the receiver's declared
/// vocabulary, at the step the vocabulary gives it. The path is numbered, so a
/// step that moves without the vocabulary moving with it is a defect.
#[test]
fn every_denial_is_in_the_declared_vocabulary() -> TestResult {
    let dir = work_dir("vocabulary")?;
    let keys = Keys::fixed();
    let (composed, hardened) = wirings(&keys, &dir);
    let mut observed: Vec<(String, u32)> = Vec::new();
    for result in negative::run(&composed, &hardened)? {
        for seen in [result.composed.as_ref(), result.hardened.as_ref()]
            .into_iter()
            .flatten()
        {
            if let (Some(code), Some(step)) = (seen.denial_code.as_ref(), seen.denial_step) {
                observed.push((code.clone(), step));
            }
        }
    }
    for row in substitution::run(&composed, &hardened)? {
        for variant in &row.variants {
            for seen in [&variant.composed, &variant.hardened] {
                if let (Some(code), Some(step)) = (seen.denial_code.as_ref(), seen.denial_step) {
                    observed.push((code.clone(), step));
                }
            }
        }
    }
    assert!(!observed.is_empty(), "neither corpus produced a denial");
    for (code, step) in observed {
        assert!(
            DENIAL_CODES
                .iter()
                .any(|(known, known_step)| *known == code && *known_step == step),
            "{code} at step {step} is not in the declared vocabulary"
        );
    }
    Ok(())
}

/// Eight of the sixteen substitution rows have no carrier anywhere in the four
/// formats, and a field with no carrier is never noticed.
#[test]
fn the_substitution_corpus_covers_the_fifteen_binding_fields() -> TestResult {
    let dir = work_dir("substitution")?;
    let keys = Keys::fixed();
    let (composed, hardened) = wirings(&keys, &dir);
    let results = substitution::run(&composed, &hardened)?;
    assert_eq!(
        results.len(),
        16,
        "the signer list occupies two of the rows"
    );
    let fields: BTreeSet<&str> = results
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
            .filter(|result| result.basis == substitution::NoticeBasis::NotCarried)
            .count(),
        8
    );
    for result in &results {
        if result.basis == substitution::NoticeBasis::NotCarried {
            assert!(
                result.carrier.is_none(),
                "{} has a carrier",
                result.chio_field
            );
            assert!(
                !result.noticed_composed && !result.noticed_hardened,
                "{} has no carrier and cannot be noticed",
                result.chio_field
            );
        } else {
            assert!(
                result.carrier.is_some(),
                "{} is carried and names no carrier",
                result.chio_field
            );
        }
    }
    assert_eq!(
        results
            .iter()
            .filter(|result| result.noticed_composed)
            .count(),
        3
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.noticed_hardened)
            .count(),
        6
    );
    Ok(())
}

/// Admission binding is the one property no wiring of these formats reaches.
/// Audience binding holds under both wirings; receiver locality and single use
/// are reached by hardening and not by the composed wiring.
#[test]
fn the_property_verdicts_are_what_the_paper_reports() -> TestResult {
    let dir = work_dir("properties")?;
    let keys = Keys::fixed();
    let (composed, hardened) = wirings(&keys, &dir);
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
                "Holds".to_string()
            ),
            ("audience binding", "Holds".to_string(), "Holds".to_string()),
        ]
    );
    Ok(())
}

/// Collect every path an object carries, stopping where one of the documents
/// declares the contents free-form.
fn paths(value: &Value, prefix: &str, slots: &[&str], found: &mut BTreeSet<String>) {
    match value {
        Value::Object(entries) => {
            for (key, child) in entries {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                found.insert(path.clone());
                if !slots.contains(&path.as_str()) {
                    paths(child, &path, slots, found);
                }
            }
        }
        Value::Array(items) => {
            let path = format!("{prefix}[]");
            for item in items {
                paths(item, &path, slots, found);
            }
        }
        _ => {}
    }
}

/// The request schema is not ours. Every path an admissible call serializes is
/// a field one of the published documents defines, or a slot one of them
/// declares free-form, and this test names any path that is neither. An
/// impossibility argued over a schema we wrote would be an argument about our
/// own file; this is what keeps it from being one.
#[test]
fn every_field_on_the_wire_is_defined_by_a_published_document() -> TestResult {
    let keys = Keys::fixed();
    let envelope = scenario::admissible(&keys, "wire-inventory")?;
    let slots: Vec<&str> = spec::FREE_FORM_SLOTS.iter().map(|slot| slot.path).collect();

    let mut found = BTreeSet::new();
    paths(
        &serde_json::to_value(&envelope.request)?,
        "",
        &slots,
        &mut found,
    );
    let known: BTreeSet<&str> = spec::REQUEST_FIELDS
        .iter()
        .map(|field| field.path)
        .collect();
    for path in &found {
        assert!(
            known.contains(path.as_str()),
            "no document in the set defines the request field {path}"
        );
    }
    for field in spec::REQUEST_FIELDS.iter().filter(|field| !field.optional) {
        assert!(
            found.contains(field.path),
            "the inventory names {}, which an admissible call does not carry",
            field.path
        );
    }

    let credential = envelope
        .credential
        .as_ref()
        .ok_or("an admissible call carries a credential")?;
    let mut credential_paths = BTreeSet::new();
    paths(
        &serde_json::to_value(credential)?,
        "",
        &slots,
        &mut credential_paths,
    );
    let credential_known: BTreeSet<&str> = spec::CREDENTIAL_FIELDS
        .iter()
        .map(|field| field.path)
        .collect();
    for path in &credential_paths {
        assert!(
            credential_known.contains(path.as_str()),
            "the token exchange response defines no member {path}"
        );
    }

    let compact = CompactJws::parse(&credential.access_token)?;
    let header: Value = serde_json::from_slice(&compact.header_bytes()?)?;
    let claims: Value = serde_json::from_slice(&compact.payload_bytes()?)?;
    let header_known: BTreeSet<&str> = spec::HEADER_FIELDS.iter().map(|field| field.path).collect();
    let claim_known: BTreeSet<&str> = spec::CLAIM_FIELDS.iter().map(|field| field.path).collect();
    let mut header_paths = BTreeSet::new();
    paths(&header, "", &slots, &mut header_paths);
    for path in &header_paths {
        assert!(
            header_known.contains(path.as_str()),
            "no document in the set defines the header parameter {path}"
        );
    }
    let mut claim_paths = BTreeSet::new();
    paths(&claims, "", &slots, &mut claim_paths);
    for path in &claim_paths {
        assert!(
            claim_known.contains(path.as_str()),
            "no document in the set defines the claim {path}"
        );
    }

    // Every metadata key an admissible call carries is one the protocol
    // reserves for itself, so the honest call invents no name either.
    let tool_call = envelope.tool_call().ok_or("the part carries a tool call")?;
    for key in tool_call.params.meta.keys() {
        assert!(
            spec::is_mcp_reserved_meta_key(key),
            "{key} is a name this deployment invented, not one the protocol defines"
        );
    }

    // Every document an inventory cites is one the run names.
    for field in spec::REQUEST_FIELDS
        .iter()
        .chain(spec::CREDENTIAL_FIELDS)
        .chain(spec::CLAIM_FIELDS)
        .chain(spec::HEADER_FIELDS)
    {
        assert!(
            spec::document(field.document).is_some(),
            "{} cites {}, which is not in the document list",
            field.path,
            field.document
        );
    }
    Ok(())
}

/// What an operator buys by agreeing a name for a fact the formats do not
/// carry. Unread, the invented key changes nothing. Read, it refuses a caller
/// that reports its stale view honestly. It still admits the caller that
/// asserts the version the receiver holds, because the value is written by the
/// caller into a slot no signature in the set covers.
#[test]
fn an_invented_field_does_not_reach_admission_binding() -> TestResult {
    let dir = work_dir("invention")?;
    let keys = Keys::fixed();
    let (composed, hardened) = wirings(&keys, &dir);
    let private = Runner::new(
        &keys,
        BaselineProfile::Hardened,
        DurabilityMode::BeforeDispatch,
        &dir,
    )
    .with_private_profile(PrivateProfile::agreement_version());
    let ledger = carriers::run(&composed, &hardened, &private)?;

    let witness = |id: &str| {
        ledger
            .witnesses
            .iter()
            .find(|witness| witness.witness_id == id)
            .ok_or_else(|| format!("the ledger did not drive {id}"))
    };

    for observation in &witness("invented-key-unread")?.observations {
        assert!(
            observation.observed.dispatched,
            "a name the receiver never agreed to read cannot deny anything, and {} denied",
            observation.wiring
        );
    }
    let honest = witness("invented-key-read-honest-caller")?;
    for observation in &honest.observations {
        assert!(
            !observation.observed.dispatched,
            "the agreed name must refuse a caller that reports a stale version"
        );
    }
    let chosen = witness("invented-key-value-chosen-by-caller")?;
    for observation in &chosen.observations {
        assert!(
            observation.observed.dispatched,
            "a value the caller chooses cannot bind the receiver's own record, and {} denied",
            observation.wiring
        );
    }

    // Every fact the ledger accounts for is one the substitution corpus found
    // no receiver-resolvable carrier for.
    let rows = substitution::run(&composed, &hardened)?;
    for entry in ledger.entries {
        let row = rows
            .iter()
            .find(|row| row.chio_field == entry.fact)
            .ok_or_else(|| format!("{} is not a field of the binding reference", entry.fact))?;
        assert!(
            matches!(
                row.basis,
                substitution::NoticeBasis::NotCarried
                    | substitution::NoticeBasis::CarriedWithoutReceiverReference
            ),
            "{} is resolvable and needs no invention",
            entry.fact
        );
        assert!(
            !entry.invention.is_empty(),
            "{} names no work an operator would have to do",
            entry.fact
        );
    }
    Ok(())
}

//! Contract tests for the `chio.decision-model-witness.v1` receipt-metadata
//! block: the typed decoder and `validate()`, the registered wire schema, and
//! the committed bytes as a function of the public tuple alone.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{fs, path::PathBuf};

use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};
use chio_core_types::receipt::metadata::{
    check_internal_receipt_metadata, metadata_key_spec, DecisionModelEvaluation,
    DecisionModelFallbackReason, DecisionModelOutcome, DecisionModelWitness, MetadataDisclosure,
    MetadataKeyOrigin, DECISION_MODEL_WITNESS_METADATA_KEY, DECISION_MODEL_WITNESS_SCHEMA,
    RECEIPT_METADATA_KEYS,
};
use chio_security_types::strict_serde::{DROPPED_INPUT, DUPLICATE_KEY};
use proptest::prelude::*;
use serde_json::{json, Value};

const OP_COUNT: u32 = 1_413;

const REASONS: [DecisionModelFallbackReason; 5] = [
    DecisionModelFallbackReason::EmptyProposal,
    DecisionModelFallbackReason::ProposalInfeasible,
    DecisionModelFallbackReason::ScorerError,
    DecisionModelFallbackReason::WorkExhausted,
    DecisionModelFallbackReason::PolicyUnavailable,
];

const OUTCOMES: [DecisionModelOutcome; 3] = [
    DecisionModelOutcome::Allow,
    DecisionModelOutcome::Hold,
    DecisionModelOutcome::Deny,
];

fn card() -> String {
    sha256_hex(b"decision-model-card")
}

fn artifact() -> String {
    sha256_hex(b"decision-model-artifact")
}

fn evaluated(outcome: DecisionModelOutcome) -> DecisionModelWitness {
    DecisionModelWitness::evaluated(card(), artifact(), outcome, OP_COUNT).unwrap()
}

fn fallback(reason: DecisionModelFallbackReason) -> DecisionModelWitness {
    DecisionModelWitness::fallback(card(), artifact(), reason).unwrap()
}

fn accepted() -> Vec<DecisionModelWitness> {
    OUTCOMES
        .into_iter()
        .map(evaluated)
        .chain(REASONS.into_iter().map(fallback))
        .collect()
}

fn schema() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-wire/v1/receipt/decision-model-witness.schema.json");
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn value(witness: &DecisionModelWitness) -> Value {
    serde_json::to_value(witness).unwrap()
}

fn with(mut instance: Value, field: &str, replacement: Value) -> Value {
    instance[field] = replacement;
    instance
}

fn without(mut instance: Value, field: &str) -> Value {
    instance.as_object_mut().unwrap().remove(field);
    instance
}

/// Each malformed D27 combination, as wire JSON.
fn malformed_combinations() -> Vec<(&'static str, Value)> {
    let evaluated_deny = value(&evaluated(DecisionModelOutcome::Deny));
    let scorer_error = value(&fallback(DecisionModelFallbackReason::ScorerError));
    vec![
        (
            "fallback without reason",
            without(scorer_error.clone(), "fallback_reason"),
        ),
        (
            "reason with evaluated",
            with(evaluated_deny, "fallback_reason", json!("scorer_error")),
        ),
        (
            "fallback with outcome allow",
            with(scorer_error.clone(), "outcome", json!("allow")),
        ),
        (
            "fallback with outcome hold",
            with(scorer_error.clone(), "outcome", json!("hold")),
        ),
        (
            "fallback with nonzero work_ops",
            with(scorer_error, "work_ops", json!(1)),
        ),
    ]
}

fn malformed_digests() -> Vec<(&'static str, Value)> {
    let base = value(&evaluated(DecisionModelOutcome::Allow));
    let mut cases = Vec::new();
    for field in ["model_card_digest", "artifact_digest"] {
        cases.push((
            "uppercase",
            with(base.clone(), field, json!(card().to_uppercase())),
        ));
        cases.push(("short", with(base.clone(), field, json!("ab".repeat(31)))));
        cases.push(("long", with(base.clone(), field, json!("ab".repeat(33)))));
        cases.push(("non-hex", with(base.clone(), field, json!("g".repeat(64)))));
    }
    cases
}

fn decoded(instance: &Value) -> Result<DecisionModelWitness, String> {
    let witness: DecisionModelWitness =
        serde_json::from_value(instance.clone()).map_err(|error| error.to_string())?;
    witness.validate().map_err(|error| error.to_string())?;
    Ok(witness)
}

#[test]
fn registry_carries_the_witness_key_once_as_committed_safe() {
    let matching: Vec<_> = RECEIPT_METADATA_KEYS
        .iter()
        .filter(|spec| spec.key == DECISION_MODEL_WITNESS_METADATA_KEY)
        .collect();
    assert_eq!(matching.len(), 1);
    let spec = metadata_key_spec(DECISION_MODEL_WITNESS_METADATA_KEY).unwrap();
    assert_eq!(spec.origin, MetadataKeyOrigin::ChioInternal);
    assert_eq!(spec.disclosure, MetadataDisclosure::CommittedSafe);
    assert_eq!(spec.schema, Some(DECISION_MODEL_WITNESS_SCHEMA));
    let metadata = json!({
        DECISION_MODEL_WITNESS_METADATA_KEY: value(&evaluated(DecisionModelOutcome::Allow)),
    });
    check_internal_receipt_metadata(&metadata).unwrap();
}

#[test]
fn accepted_shapes_validate_round_trip_and_match_the_schema() {
    let validator = jsonschema::validator_for(&schema()).unwrap();
    for witness in accepted() {
        witness.validate().unwrap();
        witness.validate_for_artifact(OP_COUNT).unwrap();
        let instance = value(&witness);
        if let Err(error) = validator.validate(&instance) {
            panic!("{instance} fails the schema: {error}");
        }
        assert_eq!(decoded(&instance).unwrap(), witness);
    }
}

#[test]
fn fallback_witness_pins_deny_zero_work_and_its_reason() {
    for reason in REASONS {
        let witness = fallback(reason);
        assert_eq!(witness.outcome, DecisionModelOutcome::Deny);
        assert_eq!(witness.evaluation, DecisionModelEvaluation::Fallback);
        assert_eq!(witness.fallback_reason, Some(reason));
        assert_eq!(witness.work_ops, 0);
    }
}

#[test]
fn malformed_combinations_are_refused_by_validate_and_the_schema() {
    let validator = jsonschema::validator_for(&schema()).unwrap();
    for (name, instance) in malformed_combinations() {
        assert!(decoded(&instance).is_err(), "validate accepted {name}");
        assert!(!validator.is_valid(&instance), "schema accepted {name}");
    }
}

#[test]
fn malformed_digests_are_refused_by_validate_and_the_schema() {
    let validator = jsonschema::validator_for(&schema()).unwrap();
    for (name, instance) in malformed_digests() {
        assert!(decoded(&instance).is_err(), "validate accepted {name}");
        assert!(!validator.is_valid(&instance), "schema accepted {name}");
    }
}

#[test]
fn constructors_refuse_malformed_digests() {
    let upper = card().to_uppercase();
    assert!(DecisionModelWitness::evaluated(
        upper.clone(),
        artifact(),
        DecisionModelOutcome::Allow,
        OP_COUNT
    )
    .is_err());
    assert!(DecisionModelWitness::fallback(
        card(),
        upper,
        DecisionModelFallbackReason::ScorerError
    )
    .is_err());
}

#[test]
fn unknown_fields_pinned_schema_and_null_reason_are_refused() {
    let validator = jsonschema::validator_for(&schema()).unwrap();
    let base = value(&evaluated(DecisionModelOutcome::Allow));
    let cases = [
        ("unknown field", with(base.clone(), "margin", json!(7))),
        (
            "other schema",
            with(
                base.clone(),
                "schema",
                json!("chio.decision-model-witness.v2"),
            ),
        ),
        (
            "null reason",
            with(base.clone(), "fallback_reason", Value::Null),
        ),
        (
            "unknown outcome",
            with(base.clone(), "outcome", json!("pending")),
        ),
        (
            "unknown evaluation",
            with(base.clone(), "evaluation", json!("clipped")),
        ),
        ("negative work", with(base.clone(), "work_ops", json!(-1))),
        (
            "work above u32",
            with(base.clone(), "work_ops", json!(u64::from(u32::MAX) + 1)),
        ),
        ("missing work", without(base, "work_ops")),
    ];
    for (name, instance) in cases {
        assert!(decoded(&instance).is_err(), "decode accepted {name}");
        assert!(!validator.is_valid(&instance), "schema accepted {name}");
    }
    let reason = value(&fallback(DecisionModelFallbackReason::ScorerError));
    let unknown_reason = with(reason, "fallback_reason", json!("timeout"));
    assert!(decoded(&unknown_reason).is_err());
    assert!(!validator.is_valid(&unknown_reason));
}

#[test]
fn repeated_keys_are_refused() {
    let raw = format!(
        r#"{{"schema":"{DECISION_MODEL_WITNESS_SCHEMA}","model_card_digest":"{c}","artifact_digest":"{a}","outcome":"allow","outcome":"deny","evaluation":"evaluated","work_ops":{OP_COUNT}}}"#,
        c = card(),
        a = artifact(),
    );
    let error = serde_json::from_str::<DecisionModelWitness>(&raw).unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with(&format!("{DUPLICATE_KEY}: \"outcome\"")),
        "{error}"
    );
}

/// A `null` `fallback_reason` decodes to `None`, which reserializes without
/// the member, so the lossless decoder refuses it as dropped input.
#[test]
fn null_fallback_reason_is_refused_as_dropped_input() {
    let instance = with(
        value(&evaluated(DecisionModelOutcome::Allow)),
        "fallback_reason",
        Value::Null,
    );
    let error = serde_json::from_value::<DecisionModelWitness>(instance).unwrap_err();
    assert_eq!(error.to_string(), DROPPED_INPUT);
}

#[test]
fn evaluated_work_must_equal_the_artifact_op_count() {
    let witness = evaluated(DecisionModelOutcome::Hold);
    witness.validate_for_artifact(OP_COUNT).unwrap();
    assert!(witness.validate_for_artifact(OP_COUNT + 1).is_err());
    assert!(witness.validate_for_artifact(OP_COUNT - 1).is_err());
    fallback(DecisionModelFallbackReason::WorkExhausted)
        .validate_for_artifact(OP_COUNT)
        .unwrap();
}

/// An evaluated deny and a `scorer_error` fallback deny differ in exactly
/// `evaluation`, `fallback_reason` and `work_ops`.
#[test]
fn evaluated_and_fallback_deny_differ_only_in_the_evaluation_fields() {
    let evaluated = value(&evaluated(DecisionModelOutcome::Deny));
    let fallback = value(&fallback(DecisionModelFallbackReason::ScorerError));
    let (evaluated, fallback) = (
        evaluated.as_object().unwrap(),
        fallback.as_object().unwrap(),
    );
    let mut differing: Vec<&str> = evaluated
        .keys()
        .chain(fallback.keys())
        .filter(|key| evaluated.get(*key) != fallback.get(*key))
        .map(String::as_str)
        .collect();
    differing.sort_unstable();
    differing.dedup();
    assert_eq!(differing, ["evaluation", "fallback_reason", "work_ops"]);
}

fn outcome_strategy() -> impl Strategy<Value = DecisionModelOutcome> {
    proptest::sample::select(OUTCOMES.to_vec())
}

fn reason_strategy() -> impl Strategy<Value = DecisionModelFallbackReason> {
    proptest::sample::select(REASONS.to_vec())
}

fn digest_strategy() -> impl Strategy<Value = String> {
    any::<[u8; 32]>().prop_map(|bytes| sha256_hex(&bytes))
}

proptest! {
    /// The committed bytes are a function of the public tuple: building the
    /// witness twice from one tuple gives byte-identical canonical JSON, and
    /// changing any tuple member changes them.
    #[test]
    fn committed_bytes_are_a_function_of_the_public_tuple(
        card in digest_strategy(),
        artifact in digest_strategy(),
        outcome in outcome_strategy(),
        reason in reason_strategy(),
        other_card in digest_strategy(),
    ) {
        let first = DecisionModelWitness::evaluated(card.clone(), artifact.clone(), outcome, OP_COUNT).unwrap();
        let second = DecisionModelWitness::evaluated(card.clone(), artifact.clone(), outcome, OP_COUNT).unwrap();
        prop_assert_eq!(canonical_json_bytes(&first).unwrap(), canonical_json_bytes(&second).unwrap());

        let first = DecisionModelWitness::fallback(card.clone(), artifact.clone(), reason).unwrap();
        let second = DecisionModelWitness::fallback(card.clone(), artifact.clone(), reason).unwrap();
        prop_assert_eq!(canonical_json_bytes(&first).unwrap(), canonical_json_bytes(&second).unwrap());

        prop_assume!(other_card != card);
        let other = DecisionModelWitness::fallback(other_card, artifact, reason).unwrap();
        prop_assert_ne!(canonical_json_bytes(&first).unwrap(), canonical_json_bytes(&other).unwrap());
    }
}

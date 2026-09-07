#[allow(
    clippy::clone_on_copy,
    clippy::derivable_impls,
    clippy::enum_variant_names,
    clippy::large_enum_variant,
    clippy::unwrap_used,
    dead_code,
    non_snake_case
)]
#[rustfmt::skip]
#[path = "../src/_generated/chio_wire_v1.rs"]
mod generated;

use chio_test_support::prelude::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::path::PathBuf;

fn fixture_payload(bytes: &[u8]) -> &[u8] {
    bytes.strip_suffix(b"\n").unwrap_or(bytes)
}

fn assert_generated_round_trip<T>(bytes: &[u8])
where
    T: DeserializeOwned + Serialize,
{
    let payload = fixture_payload(bytes);
    let source_text = std::str::from_utf8(payload).test_expect("security vector is UTF-8");
    let source_canonical = chio_core_types::canonical_json_bytes_from_str(source_text)
        .test_expect("source canonicalizes under strict RFC 8785 rules");
    assert_eq!(
        source_canonical.as_slice(),
        payload,
        "checked-in security vector is not exact RFC 8785 bytes"
    );

    let source: serde_json::Value =
        serde_json::from_slice(payload).test_expect("positive security vector parses");
    let decoded: T =
        serde_json::from_slice(payload).test_expect("generated Rust type decodes vector");
    let encoded_canonical =
        chio_core_types::canonical_json_bytes(&decoded).test_expect("generated type canonicalizes");
    assert_eq!(
        encoded_canonical.as_slice(),
        payload,
        "generated Rust type changed the exact RFC 8785 fixture bytes"
    );

    let mut unknown = source;
    unknown
        .as_object_mut()
        .test_expect("security vector is an object")
        .insert("unknown".to_string(), serde_json::Value::Bool(true));
    assert!(
        serde_json::from_value::<T>(unknown).is_err(),
        "generated Rust type accepted an unknown field"
    );
}

fn apply_json_mutation(value: &mut serde_json::Value, mutation: &serde_json::Value) {
    let path = mutation["path"]
        .as_str()
        .test_expect("mutation path is a string");
    let mut segments = path
        .strip_prefix('/')
        .test_expect("mutation path is absolute")
        .split('/')
        .peekable();
    let mut parent = value;
    while let Some(segment) = segments.next() {
        if segments.peek().is_none() {
            match mutation["op"]
                .as_str()
                .test_expect("mutation op is a string")
            {
                "add" | "replace" => {
                    if let Some(object) = parent.as_object_mut() {
                        object.insert(segment.to_string(), mutation["value"].clone());
                    } else {
                        parent
                            .as_array_mut()
                            .test_expect("mutation parent is an array")[segment
                            .parse::<usize>()
                            .test_expect("array path is an index")] = mutation["value"].clone();
                    }
                }
                "remove" => {
                    if let Some(object) = parent.as_object_mut() {
                        object.remove(segment).test_expect("mutation target exists");
                    } else {
                        parent
                            .as_array_mut()
                            .test_expect("mutation parent is an array")
                            .remove(
                                segment
                                    .parse::<usize>()
                                    .test_expect("array path is an index"),
                            );
                    }
                }
                operation => panic!("unsupported mutation operation {operation}"),
            }
            return;
        }
        parent = if parent.is_array() {
            parent
                .get_mut(
                    segment
                        .parse::<usize>()
                        .test_expect("array path is an index"),
                )
                .test_expect("mutation array element exists")
        } else {
            parent
                .get_mut(segment)
                .test_expect("mutation path segment exists")
        };
    }
    panic!("mutation path is empty");
}

#[test]
fn generated_active_defense_types_decode_reencode_and_reject() {
    assert_generated_round_trip::<
        generated::security_signed_security_event_envelope_v1::ChioSecurityEventBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/security-event-body-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security_correlated_finding_v1::ChioCorrelatedFindingV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/correlated-finding-v1.json"
    )));
    assert_generated_round_trip::<generated::security_response_plan_v1::ChioResponsePlanV1>(
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/bindings/vectors/security/active-defense/positive/response-plan-v1.json"
        )),
    );
    assert_generated_round_trip::<generated::security_response_plan_v1::ChioResponseEffectV1>(
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/bindings/vectors/security/active-defense/positive/response-effect-v1.json"
        )),
    );
    assert_generated_round_trip::<
        generated::security_response_state_transition_receipt_body_v1::ChioResponseStateTransitionReceiptBodyV1,
    >(
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/bindings/vectors/security/active-defense/positive/response-state-transition-receipt-body-v1.json"
        )),
    );
    assert_generated_round_trip::<
        generated::security_response_state_transition_receipt_body_v1::ChioResponseStateTransitionReceiptBodyV1,
    >(
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/bindings/vectors/security/active-defense/positive/response-state-transition-receipt-body-renewal-v1.json"
        )),
    );
    assert_generated_round_trip::<
        generated::security_effect_transition_receipt_body_v1::ChioEffectTransitionReceiptBodyV1,
    >(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/bindings/vectors/security/active-defense/positive/effect-transition-receipt-body-v1.json"
        )));
    assert_generated_round_trip::<
        generated::security_effect_transition_receipt_body_v1::ChioEffectTransitionReceiptBodyV1,
    >(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/bindings/vectors/security/active-defense/positive/effect-transition-receipt-body-legacy-v1.json"
        )));
    assert_generated_round_trip::<
        generated::security_detector_health_receipt_body_v1::ChioDetectorHealthReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/detector-health-receipt-body-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security_detector_health_receipt_body_v1::ChioDetectorHealthReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/detector-health-receipt-body-contradictory-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security_detector_health_receipt_body_v1::ChioDetectorHealthReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/detector-health-receipt-body-unknown-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security_flow_denial_receipt_body_v1::ChioFlowDenialReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/flow-denial-receipt-body-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security_declassification_consumption_receipt_body_v1::ChioDeclassificationConsumptionReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/declassification-consumption-receipt-body-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security_declassification_outcome_receipt_body_v1::ChioDeclassificationOutcomeReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/declassification-outcome-receipt-body-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security_tripwire_observation_receipt_body_v1::ChioTripwireObservationReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/tripwire-observation-receipt-body-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security_correlated_finding_receipt_body_v1::ChioCorrelatedFindingReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/correlated-finding-receipt-body-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security_response_plan_receipt_body_v1::ChioResponsePlanReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/response-plan-receipt-body-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security_response_plan_receipt_body_v1::ChioResponsePlanReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/response-plan-receipt-body-two-effects-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security_response_completion_receipt_body_v1::ChioResponseCompletionReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/response-completion-receipt-body-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security_response_completion_receipt_body_v1::ChioResponseCompletionReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/response-completion-receipt-body-failed-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security_response_completion_receipt_body_v1::ChioResponseCompletionReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/response-completion-receipt-body-failed-before-effect-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security_lift_rollback_completion_receipt_body_v1::ChioLiftOrRollbackCompletionReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/lift-rollback-completion-receipt-body-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security_lift_rollback_completion_receipt_body_v1::ChioLiftOrRollbackCompletionReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/lift-rollback-completion-receipt-body-nonreversible-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security_scheduler_health_receipt_body_v1::ChioSchedulerHealthReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/scheduler-health-receipt-body-v1.json"
    )));
}

#[test]
fn legacy_response_transition_canonical_digest_is_unchanged() {
    const LEGACY_CANONICAL_SHA256: &str =
        "61d86e22e586dc0477d95951bf895b269491352acc11dfe5b34a5bcdc177d2e8";
    let bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/response-state-transition-receipt-body-v1.json"
    ));
    let payload = fixture_payload(bytes);
    let source_text = std::str::from_utf8(payload).test_expect("legacy transition vector is UTF-8");
    let source_canonical = chio_core_types::canonical_json_bytes_from_str(source_text)
        .test_expect("legacy transition source canonicalizes under strict RFC 8785 rules");
    assert_eq!(source_canonical.as_slice(), payload);
    let decoded: generated::security_response_state_transition_receipt_body_v1::ChioResponseStateTransitionReceiptBodyV1 =
        serde_json::from_slice(payload).test_expect("legacy transition vector decodes");
    let decoded_canonical =
        chio_core_types::canonical_json_bytes(&decoded).test_expect("decoded body canonicalizes");
    assert_eq!(decoded_canonical.as_slice(), payload);
    assert_eq!(
        hex::encode(Sha256::digest(source_canonical)),
        LEGACY_CANONICAL_SHA256
    );
}

#[test]
fn active_defense_schema_and_semantics_reject_mutation_corpus() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let status = std::process::Command::new("python3")
        .arg(root.join("scripts/check-security-wire-vectors.py"))
        .status()
        .test_expect("security semantic checker runs");
    assert!(
        status.success(),
        "security semantic checker rejected corpus"
    );
}
#[test]
fn native_receipt_types_reject_unsafe_json_integers() {
    use chio_core_types::receipt::security::ActiveDefenseReceiptBody;

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let vector_dir = root.join("tests/bindings/vectors/security/active-defense");
    let corpus: serde_json::Value = serde_json::from_slice(
        &std::fs::read(vector_dir.join("receipt-body-mutations-v1.json"))
            .test_expect("receipt mutation corpus exists"),
    )
    .test_expect("receipt mutation corpus parses");
    let expected_kinds = [
        (
            "correlated_finding_receipt_unsafe_first_event_time",
            "correlated_finding",
        ),
        (
            "correlated_finding_receipt_unsafe_last_event_time",
            "correlated_finding",
        ),
        ("response_plan_receipt_unsafe_header_time", "response_plan"),
        ("response_plan_receipt_unsafe_expiry", "response_plan"),
        ("response_plan_receipt_unsafe_created_time", "response_plan"),
        (
            "response_state_transition_unsafe_generation",
            "response_state_transition",
        ),
        (
            "response_state_transition_unsafe_applying_lease",
            "response_state_transition",
        ),
        ("effect_transition_zero_generation", "effect_transition"),
        ("effect_transition_unsafe_generation", "effect_transition"),
        (
            "effect_transition_unsafe_fencing_token",
            "effect_transition",
        ),
        ("scheduler_health_unsafe_fencing_token", "scheduler_health"),
        ("scheduler_health_unsafe_first_failure", "scheduler_health"),
        ("scheduler_health_attempts_overflow_u32", "scheduler_health"),
    ];

    for (id, kind) in expected_kinds {
        let case = corpus["cases"]
            .as_array()
            .test_expect("receipt mutation cases are an array")
            .iter()
            .find(|case| case["id"] == id)
            .test_expect("unsafe integer mutation exists");
        let mut value: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                vector_dir.join(
                    case["base"]
                        .as_str()
                        .test_expect("mutation base is a string"),
                ),
            )
            .test_expect("receipt mutation base exists"),
        )
        .test_expect("receipt mutation base parses");
        apply_json_mutation(&mut value, &case["mutation"]);
        let tagged = serde_json::json!({"kind": kind, "body": value});
        assert!(
            serde_json::from_value::<ActiveDefenseReceiptBody>(tagged).is_err(),
            "native receipt type accepted unsafe integer mutation {id}"
        );
    }
}

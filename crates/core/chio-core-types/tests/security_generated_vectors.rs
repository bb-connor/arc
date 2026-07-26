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
fn generated_detector_health_type_rejects_mutation_corpus() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let vector_dir = root.join("tests/bindings/vectors/security/active-defense");
    let mutations: serde_json::Value = serde_json::from_slice(
        &std::fs::read(vector_dir.join("mutations-v1.json"))
            .test_expect("active-defense mutation corpus exists"),
    )
    .test_expect("active-defense mutation corpus parses");

    for case in mutations["cases"]
        .as_array()
        .test_expect("mutation corpus cases is an array")
    {
        let id = case["id"].as_str().test_expect("mutation id is a string");
        if !id.starts_with("detector_health_") {
            continue;
        }
        let base = case["base"]
            .as_str()
            .test_expect("mutation base is a string");
        let mut value: serde_json::Value = serde_json::from_slice(
            &std::fs::read(vector_dir.join(base)).test_expect("detector health base vector exists"),
        )
        .test_expect("detector health base vector parses");
        apply_json_mutation(&mut value, &case["mutation"]);
        let decoded = serde_json::from_value::<
            generated::security__detector_health_receipt_body_v1::ChioDetectorHealthReceiptBodyV1,
        >(value);
        assert!(
            decoded.is_err(),
            "generated Rust type accepted mutation {id}"
        );
    }
}

#[test]
fn generated_detector_health_type_rejects_invalid_serialization() {
    use generated::security__detector_health_receipt_body_v1::{
        ChioDetectorHealthReceiptBodyV1, GroupBinding, Time,
    };

    let bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/detector-health-receipt-body-v1.json"
    ));
    let unsafe_nonzero = std::num::NonZeroU64::new(9_007_199_254_740_992)
        .test_expect("unsafe portable time is nonzero");
    assert!(Time::try_from(unsafe_nonzero).is_err());
    assert!("9007199254740992".parse::<Time>().is_err());

    let mut unsafe_time: ChioDetectorHealthReceiptBodyV1 =
        serde_json::from_slice(bytes).test_expect("detector health vector decodes");
    // SAFETY: this test deliberately violates Time's private-field invariant to
    // verify that serialization independently fails closed.
    unsafe_time.header.occurred_at_unix_ms =
        unsafe { std::mem::transmute::<std::num::NonZeroU64, Time>(unsafe_nonzero) };
    assert!(
        serde_json::to_vec(&unsafe_time).is_err(),
        "generated Rust type serialized an unsafe detector time"
    );

    let mut invalid_cross_field: ChioDetectorHealthReceiptBodyV1 =
        serde_json::from_slice(bytes).test_expect("detector health vector decodes");
    invalid_cross_field.group_binding = GroupBinding::Unresolved;
    assert!(
        serde_json::to_vec(&invalid_cross_field).is_err(),
        "generated Rust type serialized unresolved committed knowledge"
    );
}

#[test]
fn generated_active_defense_integer_wrappers_fail_closed() {
    use generated::security__effect_transition_receipt_body_v1::{
        ChioEffectTransitionReceiptBodyV1, JsonSafePositiveInteger,
    };
    use generated::security__response_plan_receipt_body_v1::{ChioResponsePlanReceiptBodyV1, Time};

    let unsafe_nonzero = std::num::NonZeroU64::new(9_007_199_254_740_992)
        .test_expect("unsafe portable integer is nonzero");
    assert!(Time::try_from(unsafe_nonzero).is_err());
    assert!(JsonSafePositiveInteger::try_from(unsafe_nonzero).is_err());
    assert!("9007199254740992".parse::<Time>().is_err());
    assert!("9007199254740992"
        .parse::<JsonSafePositiveInteger>()
        .is_err());

    let response_bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/response-plan-receipt-body-v1.json"
    ));
    let mut unsafe_time: ChioResponsePlanReceiptBodyV1 =
        serde_json::from_slice(response_bytes).test_expect("response plan vector decodes");
    // SAFETY: this test deliberately violates Time's private-field invariant to
    // verify that serialization independently fails closed.
    unsafe_time.response.plan_expires_at_unix_ms =
        unsafe { std::mem::transmute::<std::num::NonZeroU64, Time>(unsafe_nonzero) };
    assert!(
        serde_json::to_vec(&unsafe_time).is_err(),
        "generated Rust type serialized an unsafe response time"
    );

    let effect_bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/effect-transition-receipt-body-v1.json"
    ));
    let mut unsafe_integer: ChioEffectTransitionReceiptBodyV1 =
        serde_json::from_slice(effect_bytes).test_expect("effect transition vector decodes");
    // SAFETY: this test deliberately violates the private wrapper invariant to
    // verify that serialization independently fails closed.
    unsafe_integer.scheduler_fencing_token = unsafe {
        std::mem::transmute::<std::num::NonZeroU64, JsonSafePositiveInteger>(unsafe_nonzero)
    };
    assert!(
        serde_json::to_vec(&unsafe_integer).is_err(),
        "generated Rust type serialized an unsafe fencing token"
    );
}

#[test]
fn generated_active_defense_types_decode_reencode_and_reject() {
    assert_generated_round_trip::<
        generated::security__security_event_body_v1::ChioSecurityEventBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/security-event-body-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security__correlated_finding_v1::ChioCorrelatedFindingV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/correlated-finding-v1.json"
    )));
    assert_generated_round_trip::<generated::security__response_plan_v1::ChioResponsePlanV1>(
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/bindings/vectors/security/active-defense/positive/response-plan-v1.json"
        )),
    );
    assert_generated_round_trip::<generated::security__response_effect_v1::ChioResponseEffectV1>(
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/bindings/vectors/security/active-defense/positive/response-effect-v1.json"
        )),
    );
    assert_generated_round_trip::<
        generated::security__response_state_transition_receipt_body_v1::ChioResponseStateTransitionReceiptBodyV1,
    >(
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/bindings/vectors/security/active-defense/positive/response-state-transition-receipt-body-v1.json"
        )),
    );
    assert_generated_round_trip::<
        generated::security__response_state_transition_receipt_body_v1::ChioResponseStateTransitionReceiptBodyV1,
    >(
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/bindings/vectors/security/active-defense/positive/response-state-transition-receipt-body-renewal-v1.json"
        )),
    );
    assert_generated_round_trip::<
        generated::security__effect_transition_receipt_body_v1::ChioEffectTransitionReceiptBodyV1,
    >(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/bindings/vectors/security/active-defense/positive/effect-transition-receipt-body-v1.json"
        )));
    assert_generated_round_trip::<
        generated::security__effect_transition_receipt_body_v1::ChioEffectTransitionReceiptBodyV1,
    >(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/bindings/vectors/security/active-defense/positive/effect-transition-receipt-body-legacy-v1.json"
        )));
    assert_generated_round_trip::<
        generated::security__detector_health_receipt_body_v1::ChioDetectorHealthReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/detector-health-receipt-body-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security__detector_health_receipt_body_v1::ChioDetectorHealthReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/detector-health-receipt-body-contradictory-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security__detector_health_receipt_body_v1::ChioDetectorHealthReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/detector-health-receipt-body-unknown-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security__flow_denial_receipt_body_v1::ChioFlowDenialReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/flow-denial-receipt-body-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security__declassification_consumption_receipt_body_v1::ChioDeclassificationConsumptionReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/declassification-consumption-receipt-body-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security__declassification_outcome_receipt_body_v1::ChioDeclassificationOutcomeReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/declassification-outcome-receipt-body-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security__tripwire_observation_receipt_body_v1::ChioTripwireObservationReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/tripwire-observation-receipt-body-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security__correlated_finding_receipt_body_v1::ChioCorrelatedFindingReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/correlated-finding-receipt-body-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security__response_plan_receipt_body_v1::ChioResponsePlanReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/response-plan-receipt-body-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security__response_plan_receipt_body_v1::ChioResponsePlanReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/response-plan-receipt-body-two-effects-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security__response_completion_receipt_body_v1::ChioResponseCompletionReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/response-completion-receipt-body-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security__response_completion_receipt_body_v1::ChioResponseCompletionReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/response-completion-receipt-body-failed-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security__response_completion_receipt_body_v1::ChioResponseCompletionReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/response-completion-receipt-body-failed-before-effect-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security__lift_rollback_completion_receipt_body_v1::ChioLiftOrRollbackCompletionReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/lift-rollback-completion-receipt-body-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security__lift_rollback_completion_receipt_body_v1::ChioLiftOrRollbackCompletionReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/lift-rollback-completion-receipt-body-nonreversible-v1.json"
    )));
    assert_generated_round_trip::<
        generated::security__scheduler_health_receipt_body_v1::ChioSchedulerHealthReceiptBodyV1,
    >(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/active-defense/positive/scheduler-health-receipt-body-v1.json"
    )));
}

fn generated_receipt_accepts(stem: &str, value: serde_json::Value) -> bool {
    match stem {
        "flow-denial-receipt-body-v1.json" => serde_json::from_value::<
            generated::security__flow_denial_receipt_body_v1::ChioFlowDenialReceiptBodyV1,
        >(value)
        .is_ok(),
        "declassification-consumption-receipt-body-v1.json" => serde_json::from_value::<
            generated::security__declassification_consumption_receipt_body_v1::ChioDeclassificationConsumptionReceiptBodyV1,
        >(value)
        .is_ok(),
        "declassification-outcome-receipt-body-v1.json" => serde_json::from_value::<
            generated::security__declassification_outcome_receipt_body_v1::ChioDeclassificationOutcomeReceiptBodyV1,
        >(value)
        .is_ok(),
        "tripwire-observation-receipt-body-v1.json" => serde_json::from_value::<
            generated::security__tripwire_observation_receipt_body_v1::ChioTripwireObservationReceiptBodyV1,
        >(value)
        .is_ok(),
        "correlated-finding-receipt-body-v1.json" => serde_json::from_value::<
            generated::security__correlated_finding_receipt_body_v1::ChioCorrelatedFindingReceiptBodyV1,
        >(value)
        .is_ok(),
        "response-plan-receipt-body-v1.json"
        | "response-plan-receipt-body-two-effects-v1.json" => serde_json::from_value::<
            generated::security__response_plan_receipt_body_v1::ChioResponsePlanReceiptBodyV1,
        >(value)
        .is_ok(),
        "response-state-transition-receipt-body-v1.json"
        | "response-state-transition-receipt-body-renewal-v1.json" => serde_json::from_value::<
            generated::security__response_state_transition_receipt_body_v1::ChioResponseStateTransitionReceiptBodyV1,
        >(value)
        .is_ok(),
        "effect-transition-receipt-body-v1.json"
        | "effect-transition-receipt-body-legacy-v1.json" => serde_json::from_value::<
            generated::security__effect_transition_receipt_body_v1::ChioEffectTransitionReceiptBodyV1,
        >(value)
        .is_ok(),
        "response-completion-receipt-body-v1.json"
        | "response-completion-receipt-body-failed-v1.json"
        | "response-completion-receipt-body-failed-before-effect-v1.json" => serde_json::from_value::<
            generated::security__response_completion_receipt_body_v1::ChioResponseCompletionReceiptBodyV1,
        >(value)
        .is_ok(),
        "lift-rollback-completion-receipt-body-v1.json"
        | "lift-rollback-completion-receipt-body-nonreversible-v1.json" => serde_json::from_value::<
            generated::security__lift_rollback_completion_receipt_body_v1::ChioLiftOrRollbackCompletionReceiptBodyV1,
        >(value)
        .is_ok(),
        "scheduler-health-receipt-body-v1.json" => serde_json::from_value::<
            generated::security__scheduler_health_receipt_body_v1::ChioSchedulerHealthReceiptBodyV1,
        >(value)
        .is_ok(),
        other => panic!("unknown receipt mutation base {other}"),
    }
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
    let decoded: generated::security__response_state_transition_receipt_body_v1::ChioResponseStateTransitionReceiptBodyV1 =
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
fn generated_receipt_types_cover_semantic_mutation_corpus() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let vector_dir = root.join("tests/bindings/vectors/security/active-defense");
    let status = std::process::Command::new("python3")
        .arg(root.join("scripts/check-security-wire-vectors.py"))
        .status()
        .test_expect("security semantic checker runs");
    assert!(
        status.success(),
        "security semantic checker rejected corpus"
    );
    let corpus: serde_json::Value = serde_json::from_slice(
        &std::fs::read(vector_dir.join("receipt-body-mutations-v1.json"))
            .test_expect("receipt mutation corpus exists"),
    )
    .test_expect("receipt mutation corpus parses");
    let mut generated_rejections = 0usize;
    let required_generated_rejections = [
        "correlated_finding_receipt_unsafe_first_event_time",
        "correlated_finding_receipt_unsafe_last_event_time",
        "response_plan_receipt_unsafe_header_time",
        "response_plan_receipt_unsafe_expiry",
        "response_plan_receipt_unsafe_created_time",
        "response_state_transition_unsafe_generation",
        "response_state_transition_unsafe_applying_lease",
        "effect_transition_zero_generation",
        "effect_transition_unsafe_generation",
        "effect_transition_unsafe_fencing_token",
        "scheduler_health_unsafe_first_failure",
        "scheduler_health_attempts_overflow_u32",
        "scheduler_health_unsafe_fencing_token",
    ];
    for case in corpus["cases"]
        .as_array()
        .test_expect("receipt mutation cases are an array")
    {
        let base = case["base"]
            .as_str()
            .test_expect("mutation base is a string");
        let stem = std::path::Path::new(base)
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .test_expect("mutation base has a UTF-8 file name");
        let mut value: serde_json::Value = serde_json::from_slice(
            &std::fs::read(vector_dir.join(base)).test_expect("receipt mutation base exists"),
        )
        .test_expect("receipt mutation base parses");
        apply_json_mutation(&mut value, &case["mutation"]);
        let accepted = generated_receipt_accepts(stem, value);
        let id = case["id"].as_str().test_expect("mutation id is a string");
        if required_generated_rejections.contains(&id) {
            assert!(
                !accepted,
                "generated Rust type accepted required integer mutation {}",
                case["id"]
            );
        }
        if !accepted {
            generated_rejections += 1;
        }
    }
    assert!(generated_rejections > 0);
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

#[test]
fn generated_protocol_types_preserve_approval_and_aggregate_budget_fields() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let vector_dir = root.join("tests/bindings/vectors/security/protocol-primitives");
    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(vector_dir.join("index.json"))
            .test_expect("protocol primitive vector index exists"),
    )
    .test_expect("protocol primitive vector index parses");
    let positives = index["positive"]
        .as_array()
        .test_expect("protocol positive inventory is an array");
    assert_eq!(positives.len(), 26);
    let mut identifiers = std::collections::BTreeSet::new();
    let mut files = std::collections::BTreeSet::new();
    for entry in positives {
        let identifier = entry["id"]
            .as_str()
            .test_expect("protocol positive ID is a string");
        let relative = entry["file"]
            .as_str()
            .test_expect("protocol positive file is a string");
        assert!(identifiers.insert(identifier));
        assert!(files.insert(relative));
        let bytes =
            std::fs::read(vector_dir.join(relative)).test_expect("protocol positive vector exists");
        assert_protocol_generated_round_trip(identifier, &bytes);
    }
}

fn assert_protocol_generated_round_trip(identifier: &str, bytes: &[u8]) {
    match identifier {
        "aggregate_root_commitment" => assert_generated_round_trip::<
            generated::capability__aggregate_budget_root_commitment::ChioAggregateBudgetRootCommitment,
        >(bytes),
        "aggregate_root_binding_body" => assert_generated_round_trip::<
            generated::capability__aggregate_budget_root_binding_body::ChioAggregateBudgetRootBindingBody,
        >(bytes),
        "aggregate_root_binding" => assert_generated_round_trip::<
            generated::capability__aggregate_budget_root_binding::ChioSignedAggregateBudgetRootBinding,
        >(bytes),
        "aggregate_invocation_budget" => assert_generated_round_trip::<
            generated::capability__aggregate_invocation_budget::ChioAggregateInvocationBudget,
        >(bytes),
        "capability_list_delegation_family" => assert_generated_round_trip::<
            generated::kernel__capability_list::ChioKernelMessageCapabilityList,
        >(bytes),
        "aggregate_family_preservation" => assert_generated_round_trip::<
            generated::capability__aggregate_family_preservation_evidence::ChioAggregateFamilyPreservationEvidence,
        >(bytes),
        "threshold_proposal_body" => assert_generated_round_trip::<
            generated::capability__threshold_approval_proposal_body::ChioThresholdApprovalProposalBody,
        >(bytes),
        "threshold_proposal" => assert_generated_round_trip::<
            generated::capability__threshold_approval_proposal::ChioSignedThresholdApprovalProposal,
        >(bytes),
        "governed_token_body_alice" | "governed_token_body_bob" => {
            assert_generated_round_trip::<
                generated::capability__governed_approval_token_body::ChioGovernedApprovalTokenBody,
            >(bytes)
        }
        "governed_token_alice" | "governed_token_bob" => assert_generated_round_trip::<
            generated::capability__governed_approval_token::ChioSignedGovernedApprovalToken,
        >(bytes),
        "tool_call_request_singular_approval" | "tool_call_request_list_approval" => {
            assert_generated_round_trip::<
                generated::agent__tool_call_request::ChioAgentMessageToolCallRequest,
            >(bytes)
        }
        "governed_active_response_intent" => {
            assert_generated_round_trip::<
                generated::capability__governed_transaction_intent::ChioGovernedTransactionIntent,
            >(bytes);
            let intent: generated::capability__governed_transaction_intent::ChioGovernedTransactionIntent =
                serde_json::from_slice(fixture_payload(bytes))
                    .test_expect("governed active-response intent decodes");
            assert!(matches!(
                intent,
                generated::capability__governed_transaction_intent::ChioGovernedTransactionIntent::ActiveResponsePlan { .. }
            ));
        }
        "tool_call_request_full_security" => {
            assert_generated_round_trip::<
                generated::agent__tool_call_request::ChioAgentMessageToolCallRequest,
            >(bytes);
            assert_full_security_request_fields(bytes);
        }
        "verified_approval_set" => assert_generated_round_trip::<
            generated::capability__verified_approval_set::ChioVerifiedThresholdApprovalSet,
        >(bytes),
        "admission_request_binding" => assert_generated_round_trip::<
            generated::trust_control__admission_request_binding::ChioAdmissionOperationRequestBindingProjection,
        >(bytes),
        "budget_admission_evidence" => assert_generated_round_trip::<
            generated::trust_control__budget_invocation_admission_evidence::ChioBudgetInvocationAdmissionEvidence,
        >(bytes),
        "budget_admission_evidence_partition_escrow" => assert_generated_round_trip::<
            generated::trust_control__budget_invocation_admission_evidence::ChioBudgetInvocationAdmissionEvidence,
        >(bytes),
        "admission_capture_metadata" => assert_generated_round_trip::<
            generated::trust_control__admission_capture_metadata::ChioAuthoritativeAdmissionCaptureReceiptProjection,
        >(bytes),
        "admission_capture_metadata_partition_escrow" => assert_generated_round_trip::<
            generated::trust_control__admission_capture_metadata::ChioAuthoritativeAdmissionCaptureReceiptProjection,
        >(bytes),
        "partition_escrow_quota_commitment" => assert_generated_round_trip::<
            generated::trust_control__partition_escrow_quota_commitment::ChioSignedPartitionEscrowQuotaCommitment,
        >(bytes),
        "partition_escrow_allocation_set" => assert_generated_round_trip::<
            generated::trust_control__partition_escrow_allocation_set::ChioSignedPartitionEscrowAllocationSet,
        >(bytes),
        "partition_escrow_admission_evidence" => assert_generated_round_trip::<
            generated::trust_control__partition_escrow_admission_evidence::ChioPartitionEscrowAdmissionEvidence,
        >(bytes),
        "partition_escrow_receipt_metadata" => assert_generated_round_trip::<
            generated::trust_control__partition_escrow_receipt_metadata::ChioPartitionEscrowFinancialReceiptMetadata,
        >(bytes),
        other => panic!("protocol positive inventory has no exact generated type for {other}"),
    }
}

fn assert_full_security_request_fields(bytes: &[u8]) {
    use generated::agent__tool_call_request::{
        ChioAgentMessageToolCallRequest, ChioGovernedTransactionIntent,
    };

    let request: ChioAgentMessageToolCallRequest = serde_json::from_slice(fixture_payload(bytes))
        .test_expect("full-security tool-call request decodes");
    assert!(request
        .capability_token
        .aggregate_invocation_budget
        .is_some());
    assert!(request.supplemental_authorization.is_some());
    assert!(matches!(
        request.governed_intent.as_ref(),
        Some(ChioGovernedTransactionIntent::ToolInvocation { .. })
    ));
    assert!(request.approval_token.is_none());
    assert_eq!(request.approval_tokens.len(), 2);
    assert!(request.threshold_approval_proposal.is_some());
    assert!(request.declassification_grant.is_some());
}

fn protocol_generated_accepts(identifier: &str, value: serde_json::Value) -> bool {
    match identifier {
        "aggregate_root_commitment" => serde_json::from_value::<
            generated::capability__aggregate_budget_root_commitment::ChioAggregateBudgetRootCommitment,
        >(value)
        .is_ok(),
        "aggregate_root_binding_body" => serde_json::from_value::<
            generated::capability__aggregate_budget_root_binding_body::ChioAggregateBudgetRootBindingBody,
        >(value)
        .is_ok(),
        "aggregate_root_binding" => serde_json::from_value::<
            generated::capability__aggregate_budget_root_binding::ChioSignedAggregateBudgetRootBinding,
        >(value)
        .is_ok(),
        "aggregate_invocation_budget" => serde_json::from_value::<
            generated::capability__aggregate_invocation_budget::ChioAggregateInvocationBudget,
        >(value)
        .is_ok(),
        "capability_list_delegation_family" => serde_json::from_value::<
            generated::kernel__capability_list::ChioKernelMessageCapabilityList,
        >(value)
        .is_ok(),
        "aggregate_family_preservation" => serde_json::from_value::<
            generated::capability__aggregate_family_preservation_evidence::ChioAggregateFamilyPreservationEvidence,
        >(value)
        .is_ok(),
        "threshold_proposal_body" => serde_json::from_value::<
            generated::capability__threshold_approval_proposal_body::ChioThresholdApprovalProposalBody,
        >(value)
        .is_ok(),
        "threshold_proposal" => serde_json::from_value::<
            generated::capability__threshold_approval_proposal::ChioSignedThresholdApprovalProposal,
        >(value)
        .is_ok(),
        "governed_token_body_alice" | "governed_token_body_bob" => serde_json::from_value::<
            generated::capability__governed_approval_token_body::ChioGovernedApprovalTokenBody,
        >(value)
        .is_ok(),
        "governed_token_alice" | "governed_token_bob" => serde_json::from_value::<
            generated::capability__governed_approval_token::ChioSignedGovernedApprovalToken,
        >(value)
        .is_ok(),
        "tool_call_request_singular_approval" | "tool_call_request_list_approval" => {
            serde_json::from_value::<
                generated::agent__tool_call_request::ChioAgentMessageToolCallRequest,
            >(value)
            .is_ok()
        }
        "governed_active_response_intent" => serde_json::from_value::<
            generated::capability__governed_transaction_intent::ChioGovernedTransactionIntent,
        >(value)
        .is_ok(),
        "tool_call_request_full_security" => serde_json::from_value::<
            generated::agent__tool_call_request::ChioAgentMessageToolCallRequest,
        >(value)
        .is_ok(),
        "verified_approval_set" => serde_json::from_value::<
            generated::capability__verified_approval_set::ChioVerifiedThresholdApprovalSet,
        >(value)
        .is_ok(),
        "admission_request_binding" => serde_json::from_value::<
            generated::trust_control__admission_request_binding::ChioAdmissionOperationRequestBindingProjection,
        >(value)
        .is_ok(),
        "budget_admission_evidence" => serde_json::from_value::<
            generated::trust_control__budget_invocation_admission_evidence::ChioBudgetInvocationAdmissionEvidence,
        >(value)
        .is_ok(),
        "budget_admission_evidence_partition_escrow" => serde_json::from_value::<
            generated::trust_control__budget_invocation_admission_evidence::ChioBudgetInvocationAdmissionEvidence,
        >(value)
        .is_ok(),
        "admission_capture_metadata" => serde_json::from_value::<
            generated::trust_control__admission_capture_metadata::ChioAuthoritativeAdmissionCaptureReceiptProjection,
        >(value)
        .is_ok(),
        "admission_capture_metadata_partition_escrow" => serde_json::from_value::<
            generated::trust_control__admission_capture_metadata::ChioAuthoritativeAdmissionCaptureReceiptProjection,
        >(value)
        .is_ok(),
        "partition_escrow_quota_commitment" => serde_json::from_value::<
            generated::trust_control__partition_escrow_quota_commitment::ChioSignedPartitionEscrowQuotaCommitment,
        >(value)
        .is_ok(),
        "partition_escrow_allocation_set" => serde_json::from_value::<
            generated::trust_control__partition_escrow_allocation_set::ChioSignedPartitionEscrowAllocationSet,
        >(value)
        .is_ok(),
        "partition_escrow_admission_evidence" => serde_json::from_value::<
            generated::trust_control__partition_escrow_admission_evidence::ChioPartitionEscrowAdmissionEvidence,
        >(value)
        .is_ok(),
        "partition_escrow_receipt_metadata" => serde_json::from_value::<
            generated::trust_control__partition_escrow_receipt_metadata::ChioPartitionEscrowFinancialReceiptMetadata,
        >(value)
        .is_ok(),
        other => panic!("protocol mutation base has no exact generated type for {other}"),
    }
}

#[test]
fn protocol_schema_and_generated_types_cover_exact_negative_corpus() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let vector_dir = root.join("tests/bindings/vectors/security/protocol-primitives");
    let status = std::process::Command::new("python3")
        .arg(root.join("scripts/check-protocol-primitives-vectors.py"))
        .status()
        .test_expect("protocol vector checker runs");
    assert!(status.success(), "protocol vector checker rejected corpus");
    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(vector_dir.join("index.json")).test_expect("protocol index exists"),
    )
    .test_expect("protocol index parses");
    let protocol_by_base: std::collections::BTreeMap<&str, (&str, &str)> = index["positive"]
        .as_array()
        .test_expect("positive inventory is an array")
        .iter()
        .map(|entry| {
            (
                entry["file"]
                    .as_str()
                    .test_expect("positive file is a string"),
                (
                    entry["id"].as_str().test_expect("positive ID is a string"),
                    entry["schema_id"]
                        .as_str()
                        .test_expect("positive schema ID is a string"),
                ),
            )
        })
        .collect();
    let direct = &index["negative"][0];
    let direct_schema_id = direct["schema_id"]
        .as_str()
        .test_expect("direct negative schema ID is a string");
    let direct_schema_path = protocol_schema_path(&root, direct_schema_id);
    let direct_schema: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&direct_schema_path).test_expect("direct negative schema exists"),
    )
    .test_expect("direct negative schema parses");
    let direct_value: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            vector_dir.join(
                direct["file"]
                    .as_str()
                    .test_expect("direct negative file is a string"),
            ),
        )
        .test_expect("direct negative vector exists"),
    )
    .test_expect("direct negative vector parses");
    assert!(
        chio_spec_validate::validate_value(
            &direct_schema_path,
            &direct_schema,
            std::path::Path::new("<direct-protocol-negative>"),
            &direct_value,
        )
        .is_err(),
        "authoritative schema accepted direct protocol negative"
    );
    let corpus: serde_json::Value = serde_json::from_slice(
        &std::fs::read(vector_dir.join("mutations-v1.json"))
            .test_expect("protocol mutation corpus exists"),
    )
    .test_expect("protocol mutation corpus parses");
    let cases = corpus["cases"]
        .as_array()
        .test_expect("protocol mutation cases are an array");
    assert_eq!(cases.len(), 43);
    let mut identifiers = std::collections::BTreeSet::new();
    let mut structural_rejections = 1usize;
    let mut semantic_rejections = 0usize;
    for case in cases {
        let case_id = case["id"].as_str().test_expect("mutation ID is a string");
        assert!(identifiers.insert(case_id));
        let base = case["base"]
            .as_str()
            .test_expect("mutation base is a string");
        let (generated_id, schema_id) = protocol_by_base
            .get(base)
            .test_expect("mutation base is in the positive inventory");
        let base_bytes = std::fs::read(vector_dir.join(base)).test_expect("mutation base exists");
        let mut value: serde_json::Value =
            serde_json::from_slice(&base_bytes).test_expect("mutation base parses");
        if case["mutation"]["op"] == "append_bytes" {
            let suffix = hex::decode(
                case["mutation"]["hex"]
                    .as_str()
                    .test_expect("byte mutation hex is a string"),
            )
            .test_expect("byte mutation hex decodes");
            let mut mutated_bytes = base_bytes;
            mutated_bytes.extend_from_slice(&suffix);
            value = serde_json::from_slice(&mutated_bytes)
                .test_expect("byte-mutated protocol vector parses");
            assert_ne!(
                chio_core_types::canonical_json_bytes(&value)
                    .test_expect("byte-mutated vector canonicalizes"),
                mutated_bytes,
                "append_bytes mutation remained canonical for {case_id}"
            );
        } else {
            apply_json_mutation(&mut value, &case["mutation"]);
        }
        let schema_path = protocol_schema_path(&root, schema_id);
        let schema: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&schema_path).test_expect("protocol mutation schema exists"),
        )
        .test_expect("protocol mutation schema parses");
        let schema_valid = chio_spec_validate::validate_value(
            &schema_path,
            &schema,
            std::path::Path::new("<protocol-mutation>"),
            &value,
        )
        .is_ok();
        assert_eq!(case["expected"]["json_parse_valid"], true);
        assert_eq!(case["expected"]["semantic_valid"], false);
        assert_eq!(
            schema_valid,
            case["expected"]["json_schema_valid"] == true,
            "authoritative schema classification drifted for {case_id}"
        );
        if case["expected"]["json_schema_valid"] == true {
            semantic_rejections += 1;
            assert!(
                protocol_generated_accepts(generated_id, value),
                "generated Rust type rejected schema-valid semantic mutation {case_id}"
            );
        } else {
            structural_rejections += 1;
        }
    }
    assert_eq!(structural_rejections, 16);
    assert_eq!(semantic_rejections, 28);
    assert_eq!(structural_rejections + semantic_rejections, 44);
}

fn protocol_schema_path(root: &std::path::Path, schema_id: &str) -> PathBuf {
    const WIRE_SCHEMA_BASE: &str = "https://chio.world/schemas/chio-wire/v1/";
    root.join("spec/schemas/chio-wire/v1").join(
        schema_id
            .strip_prefix(WIRE_SCHEMA_BASE)
            .test_expect("protocol schema ID uses the wire-schema base"),
    )
}

#[test]
fn authoritative_schema_rejects_both_approval_forms_vector() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let schema_path = root.join("spec/schemas/chio-wire/v1/agent/tool_call_request.schema.json");
    let schema: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&schema_path).test_expect("tool-call request schema exists"),
    )
    .test_expect("tool-call request schema parses");
    let instance: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/vectors/security/protocol-primitives/negative/tool-call-request-both-approval-forms-v1.json"
    )))
    .test_expect("negative tool-call request vector parses");

    assert!(
        chio_spec_validate::validate_value(
            &schema_path,
            &schema,
            std::path::Path::new("<both-approval-forms-vector>"),
            &instance,
        )
        .is_err(),
        "authoritative schema accepted both approval forms"
    );
}

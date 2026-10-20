//! Every lossless enum decodes only through its strict `Deserialize` impl,
//! so a member beside a unit variant tag refuses even on the direct
//! `Type::deserialize` path.

use chio_security_types::knowledge::ArtifactSinkV1;
use chio_security_types::ports::{
    EffectExecutionStatus, IssuanceFreezeOperationStatus, ResponseDispatchApproval,
};
use chio_security_types::strict_serde::{DROPPED_INPUT, DUPLICATE_KEY};
use chio_security_types::{
    DetectorGroupBindingEvidence, DetectorWatermarkEvidence, ResponseApprovalRequirement,
    ResponseRollbackOutcome,
};
use serde::Deserialize;
use serde_json::{json, Value};

// A macro, so each call names the concrete `Type::deserialize`: an inherent
// raw decoder on the type would take precedence over the strict trait impl.
macro_rules! assert_unit_refuses_padding {
    ($ty:ty, $unit:expr) => {{
        let unit: Value = $unit;
        let decoded = <$ty>::deserialize(unit.clone()).map_err(|error| error.to_string());
        let reencoded = decoded.ok().map(|typed| serde_json::to_value(typed).ok());
        assert_eq!(reencoded, Some(Some(unit.clone())), "{unit}");
        let mut padded = unit.clone();
        if let Some(members) = padded.as_object_mut() {
            members.insert("pad".to_string(), json!(0));
        }
        let refusal = <$ty>::deserialize(padded)
            .err()
            .map(|error| error.to_string());
        assert_eq!(refusal.as_deref(), Some(DROPPED_INPUT), "{unit}");
    }};
}

#[test]
fn every_security_lossless_enum_refuses_a_padded_unit_variant() {
    assert_unit_refuses_padding!(DetectorWatermarkEvidence, json!({"kind": "unknown"}));
    assert_unit_refuses_padding!(DetectorGroupBindingEvidence, json!({"kind": "unresolved"}));
    assert_unit_refuses_padding!(ArtifactSinkV1, json!({"kind": "agent"}));
    assert_unit_refuses_padding!(
        ResponseDispatchApproval,
        json!({"approval_mode": "automatic"})
    );
    assert_unit_refuses_padding!(EffectExecutionStatus, json!({"status": "not_executed"}));
    assert_unit_refuses_padding!(
        IssuanceFreezeOperationStatus,
        json!({"status": "not_executed"})
    );
    assert_unit_refuses_padding!(
        ResponseApprovalRequirement,
        json!({"approval_type": "automatic"})
    );
    assert_unit_refuses_padding!(ResponseRollbackOutcome, json!({"outcome": "requested"}));
}

// Both raw paths read the input before the derived decoder sees it, so a
// repeated key refuses instead of keeping the last value.
macro_rules! assert_raw_duplicate_refused {
    ($ty:ty, $text:expr, $key:expr) => {{
        let expected = format!("{}: {:?}", DUPLICATE_KEY, $key);
        let direct = <$ty>::deserialize(&mut serde_json::Deserializer::from_str($text))
            .err()
            .map(|error| error.to_string());
        assert!(
            direct
                .as_deref()
                .is_some_and(|error| error.starts_with(&expected)),
            "{direct:?}"
        );
        let decoded = serde_json::from_str::<$ty>($text)
            .err()
            .map(|error| error.to_string());
        assert!(
            decoded
                .as_deref()
                .is_some_and(|error| error.starts_with(&expected)),
            "{decoded:?}"
        );
    }};
}

#[test]
fn every_security_lossless_enum_refuses_a_raw_duplicate_key() {
    assert_raw_duplicate_refused!(
        DetectorWatermarkEvidence,
        r#"{"kind":"unknown","kind":"unknown"}"#,
        "kind"
    );
    assert_raw_duplicate_refused!(
        DetectorGroupBindingEvidence,
        r#"{"kind":"unresolved","kind":"unresolved"}"#,
        "kind"
    );
    assert_raw_duplicate_refused!(
        ArtifactSinkV1,
        r#"{"kind":"agent","kind":"archive"}"#,
        "kind"
    );
    assert_raw_duplicate_refused!(
        ResponseDispatchApproval,
        r#"{"approval_mode":"automatic","approval_mode":"automatic"}"#,
        "approval_mode"
    );
    assert_raw_duplicate_refused!(
        EffectExecutionStatus,
        r#"{"status":"not_executed","status":"unknown"}"#,
        "status"
    );
    assert_raw_duplicate_refused!(
        IssuanceFreezeOperationStatus,
        r#"{"status":"not_executed","status":"not_executed"}"#,
        "status"
    );
    assert_raw_duplicate_refused!(
        ResponseApprovalRequirement,
        r#"{"approval_type":"automatic","approval_type":"automatic"}"#,
        "approval_type"
    );
    assert_raw_duplicate_refused!(
        ResponseRollbackOutcome,
        r#"{"outcome":"requested","outcome":"requested"}"#,
        "outcome"
    );
}

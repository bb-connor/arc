use chio_security_types::knowledge::ArtifactSinkV1;
use chio_security_types::ports::{
    EffectExecutionStatus, IssuanceFreezeOperationStatus, ResponseDispatchApproval,
};
use chio_security_types::strict_serde::DROPPED_INPUT;
use chio_security_types::{
    DetectorGroupBindingEvidence, DetectorWatermarkEvidence, ResponseApprovalRequirement,
    ResponseRollbackOutcome,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Map, Value};

fn assert_strict_unit<T>(tag: &str, name: &str, expected: &T)
where
    T: DeserializeOwned + Serialize + PartialEq,
{
    let mut object = Map::new();
    object.insert(tag.into(), name.into());
    let canonical = Value::Object(object);
    let decoded = serde_json::from_value::<T>(canonical.clone())
        .unwrap_or_else(|error| panic!("{tag}={name} refused: {error}"));
    assert!(
        decoded == *expected,
        "{tag}={name} decoded to another variant"
    );
    let encoded = serde_json::to_value(&decoded)
        .unwrap_or_else(|error| panic!("{tag}={name} encoding failed: {error}"));
    assert_eq!(encoded, canonical);

    for pad in [json!(0), json!(null), json!({}), json!(name)] {
        let mut padded = canonical.clone();
        padded["pad"] = pad;
        let error = match serde_json::from_value::<T>(padded) {
            Ok(_) => panic!("padded {tag}={name} decoded"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), DROPPED_INPUT, "{tag}={name}");
    }
}

#[test]
fn detector_watermark_unknown_refuses_padding() {
    assert_strict_unit("kind", "unknown", &DetectorWatermarkEvidence::Unknown);
}

#[test]
fn detector_group_binding_unresolved_refuses_padding() {
    assert_strict_unit(
        "kind",
        "unresolved",
        &DetectorGroupBindingEvidence::Unresolved,
    );
}

#[test]
fn response_dispatch_approval_automatic_refuses_padding() {
    assert_strict_unit(
        "approval_mode",
        "automatic",
        &ResponseDispatchApproval::Automatic,
    );
}

#[test]
fn effect_execution_status_units_refuse_padding() {
    assert_strict_unit(
        "status",
        "not_executed",
        &EffectExecutionStatus::NotExecuted,
    );
    assert_strict_unit("status", "unknown", &EffectExecutionStatus::Unknown);
}

#[test]
fn issuance_freeze_operation_not_executed_refuses_padding() {
    assert_strict_unit(
        "status",
        "not_executed",
        &IssuanceFreezeOperationStatus::NotExecuted,
    );
}

#[test]
fn response_approval_requirement_automatic_refuses_padding() {
    assert_strict_unit(
        "approval_type",
        "automatic",
        &ResponseApprovalRequirement::Automatic,
    );
}

#[test]
fn response_rollback_outcome_requested_refuses_padding() {
    assert_strict_unit("outcome", "requested", &ResponseRollbackOutcome::Requested);
}

#[test]
fn artifact_sink_units_refuse_padding() {
    assert_strict_unit("kind", "agent", &ArtifactSinkV1::Agent);
    assert_strict_unit("kind", "archive", &ArtifactSinkV1::Archive);
}

#[test]
fn struct_variants_keep_their_unknown_field_refusal() {
    let error = match serde_json::from_value::<DetectorWatermarkEvidence>(
        json!({ "kind": "committed", "unix_ms": 7, "pad": 0 }),
    ) {
        Ok(evidence) => panic!("padded committed watermark decoded: {evidence:?}"),
        Err(error) => error,
    };
    assert_eq!(error.to_string(), "unknown field `pad`, expected `unix_ms`");
    assert_eq!(
        serde_json::from_value::<DetectorWatermarkEvidence>(
            json!({ "kind": "committed", "unix_ms": 7 })
        )
        .ok(),
        Some(DetectorWatermarkEvidence::Committed { unix_ms: 7 })
    );
}

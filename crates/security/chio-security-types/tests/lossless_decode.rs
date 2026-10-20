//! Every lossless enum decodes only through its strict `Deserialize` impl,
//! so a member beside a unit variant tag refuses even on the direct
//! `Type::deserialize` path.

use chio_security_types::knowledge::ArtifactSinkV1;
use chio_security_types::ports::{
    EffectExecutionStatus, IssuanceFreezeOperationStatus, ResponseDispatchApproval,
};
use chio_security_types::strict_serde::DROPPED_INPUT;
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

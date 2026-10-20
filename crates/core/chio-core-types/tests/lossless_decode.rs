//! Every lossless enum decodes only through its strict `Deserialize` impl,
//! so a member beside a unit variant tag refuses even on the direct
//! `Type::deserialize` path.

use chio_core_types::capability::scope::{Constraint, FindingSettlementSelector};
use chio_core_types::economic_continuity::EconomicActionAuthorizationV1;
use chio_security_types::strict_serde::DROPPED_INPUT;
use serde::Deserialize;
use serde_json::{json, Value};

// A macro, so each call names the concrete `Type::deserialize`: an inherent
// raw decoder on the type would take precedence over the strict trait impl.
macro_rules! assert_unit_refuses_member {
    ($ty:ty, $unit:expr, $member:expr) => {{
        let unit: Value = $unit;
        let decoded = <$ty>::deserialize(unit.clone()).map_err(|error| error.to_string());
        let reencoded = decoded.ok().map(|typed| serde_json::to_value(typed).ok());
        assert_eq!(reencoded, Some(Some(unit.clone())), "{unit}");
        let mut padded = unit.clone();
        if let Some(members) = padded.as_object_mut() {
            members.insert($member.to_string(), Value::Null);
        }
        let refusal = <$ty>::deserialize(padded)
            .err()
            .map(|error| error.to_string());
        assert_eq!(refusal.as_deref(), Some(DROPPED_INPUT), "{unit}");
    }};
}

#[test]
fn every_core_lossless_enum_refuses_a_padded_unit_variant() {
    assert_unit_refuses_member!(
        Constraint,
        json!({"type": "governed_intent_required"}),
        "value"
    );
    assert_unit_refuses_member!(
        FindingSettlementSelector,
        json!({"mode": "local_reversible_hold"}),
        "pad"
    );
    assert_unit_refuses_member!(
        EconomicActionAuthorizationV1,
        json!({"mode": "direct"}),
        "pad"
    );
}

//! Every lossless enum decodes only through its strict `Deserialize` impl,
//! so a member beside a unit variant tag refuses even on the direct
//! `Type::deserialize` path.

use chio_core_types::capability::scope::{Constraint, FindingSettlementSelector};
use chio_core_types::economic_continuity::EconomicActionAuthorizationV1;
use chio_security_types::strict_serde::{DROPPED_INPUT, DUPLICATE_KEY};
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
fn every_core_lossless_enum_refuses_a_raw_duplicate_key() {
    assert_raw_duplicate_refused!(
        Constraint,
        r#"{"type":"path_prefix","type":"domain_exact","value":"/a"}"#,
        "type"
    );
    assert_raw_duplicate_refused!(
        FindingSettlementSelector,
        r#"{"mode":"cross_org_escrow","settlement_profile_sha256":"a","settlement_profile_sha256":"b"}"#,
        "settlement_profile_sha256"
    );
    assert_raw_duplicate_refused!(
        EconomicActionAuthorizationV1,
        r#"{"mode":"direct","mode":"direct"}"#,
        "mode"
    );
}

#[test]
fn a_constraint_refuses_a_repeated_content_or_nested_key() {
    assert_raw_duplicate_refused!(
        Constraint,
        r#"{"type":"path_prefix","value":"/a","value":"/b"}"#,
        "value"
    );
    assert_raw_duplicate_refused!(
        Constraint,
        r#"{"type":"require_cumulative_approval_above","value":{"threshold":{"units":1,"units":2,"currency":"USD"},"approval_budget_id":"b","approval_budget_epoch":1}}"#,
        "units"
    );
    assert_raw_duplicate_refused!(
        Vec<Constraint>,
        r#"[{"type":"governed_intent_required"},{"type":"path_prefix","type":"domain_exact","value":"/a"}]"#,
        "type"
    );
}

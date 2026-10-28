//! `chio.revocation-entry.v1` decodes strictly: the closed kind and reason
//! sets, the per-kind value shape, and an id that its target derives.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core_types::root_authority::{
    RevocationEntry, RevocationReason, RevocationTarget, RevocationTargetKind,
    RootAuthorityShapeError,
};
use serde::Deserialize;
use serde_json::{json, Value};

fn entry() -> Value {
    serde_json::to_value(
        RevocationEntry::new(
            &RevocationTarget::capability("cap-fixture-1").unwrap(),
            1_792_234_800,
            RevocationReason::OperatorRequest,
        )
        .unwrap(),
    )
    .unwrap()
}

fn refused(value: Value) -> String {
    match RevocationEntry::deserialize(value) {
        Ok(_) => panic!("decoded an invalid revocation entry"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn an_entry_round_trips() {
    let value = entry();
    assert_eq!(
        value,
        json!({
            "schema": "chio.revocation-entry.v1",
            "entry_id": "rev_9381c386951ff33d55040e8c800dc291d1f0344ae9f3a17d8fa7db722508adc8",
            "target_kind": "capability_id",
            "target_value": "cap-fixture-1",
            "revoked_at": 1_792_234_800_u64,
            "reason": "operator_request",
        })
    );
    let decoded = RevocationEntry::deserialize(value).unwrap();
    assert_eq!(decoded.target_kind, RevocationTargetKind::CapabilityId);
}

#[test]
fn decode_refuses_unknown_members_kinds_and_reasons() {
    let mut extra = entry();
    extra["note"] = json!("free text");
    assert_eq!(
        refused(extra),
        "unknown field `note`, expected one of `schema`, `entry_id`, `target_kind`, `target_value`, `revoked_at`, `reason`"
    );
    let mut kind = entry();
    kind["target_kind"] = json!("operator_note");
    assert_eq!(
        refused(kind),
        "unknown variant `operator_note`, expected one of `capability_id`, `root_policy_rule`, `anchor_subject`, `tenant_tag`, `replay_key`"
    );
    let mut reason = entry();
    reason["reason"] = json!("because");
    assert_eq!(
        refused(reason),
        "unknown variant `because`, expected one of `operator_request`, `credential_compromise`, `principal_offboarded`, `tenant_offboarded`, `policy_withdrawn`, `incident_response`"
    );
}

#[test]
fn decode_refuses_an_id_its_target_does_not_derive() {
    let mut retargeted = entry();
    retargeted["target_value"] = json!("cap-fixture-2");
    assert_eq!(
        refused(retargeted),
        "`entry_id` is not the id derived from target_kind and target_value"
    );
    let mut rekinded = entry();
    rekinded["target_kind"] = json!("root_policy_rule");
    assert_eq!(
        refused(rekinded),
        "`entry_id` is not the id derived from target_kind and target_value"
    );
}

#[test]
fn decode_refuses_schema_time_and_value_shape() {
    let mut schema = entry();
    schema["schema"] = json!("chio.revocation-entry.v2");
    assert_eq!(
        refused(schema),
        "`schema` must be `chio.revocation-entry.v1`"
    );
    let mut zero = entry();
    zero["revoked_at"] = json!(0);
    assert_eq!(
        refused(zero),
        "`revoked_at` is 0, outside 1..=9223372036854775807"
    );
    assert_eq!(
        RevocationTarget::from_parts(RevocationTargetKind::TenantTag, &"A".repeat(64)),
        Err(RootAuthorityShapeError::Pattern {
            field: "target_value",
            expected: "64 lowercase hex",
        })
    );
    assert_eq!(
        RevocationTarget::capability(""),
        Err(RootAuthorityShapeError::Length {
            field: "target_value",
            min: 1,
            max: 512,
            actual: 0,
        })
    );
    assert_eq!(
        RevocationTarget::capability("cap\0fixture"),
        Err(RootAuthorityShapeError::Nul {
            field: "target_value"
        })
    );
}

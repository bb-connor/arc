use super::*;
use crate::recovery::vector_test_fixture::{authority_fixture, seed_wire, TestResult};
use chio_core_types::{canonical_json_bytes, recovery::decode_contract};
use serde_json::{json, Value};

/// Typed canonical workflow over the REC-0a vector. Serde omits skipped
/// `None` fields, so the wire is re-serialized through the typed record before
/// `decode_contract` compares canonical bytes.
fn workflow_wire() -> TestResult<Value> {
    let fixture = authority_fixture()?;
    let seed = seed_wire()?;
    let creation_seed = String::from_utf8(canonical_json_bytes(&seed)?)?;
    let wire = json!({
        "scope": fixture["action"]["scope"],
        "origin": fixture["action"]["origin"],
        "workflow_id": "workflow:contract",
        "step_id": "step:contract",
        "continuation_id": "continuation:contract",
        "revision": 1,
        "control": "active",
        "seed": seed,
        "creation_seed": creation_seed,
        "deployment_digest": vec![7_u8; 32],
        "created_by": "principal:contract",
        "effect_cardinality": 1,
        "action": null,
        "process_reservation": null,
        "selected": false,
        "review": null,
        "approval": null,
        "issuance": null,
        "signed_grant": null,
        "envelope": null,
        "admission": null,
        "admission_closed": false,
        "native_link": null,
        "captured": false,
        "captured_deployment": null,
        "historical_hold": null,
        "effect": {"kind": "never_admitted"},
        "release": {"kind": "not_available"},
        "original_flow": null,
        "reported_decision": null,
        "provider_finality": null,
        "provider_lookups": 0
    });
    let record: RecoveryWorkflowRecordV1 = serde_json::from_value(wire)?;
    Ok(serde_json::to_value(record)?)
}

#[test]
fn workflow_origin_survives_canonical_round_trip() -> TestResult {
    let wire = workflow_wire()?;
    let original: RecoveryOriginV1 = serde_json::from_value(wire["origin"].clone())?;
    let record: RecoveryWorkflowRecordV1 = decode_contract(&canonical_json_bytes(&wire)?)?;
    assert_eq!(record.origin, original);
    let decoded: RecoveryWorkflowRecordV1 = decode_contract(&canonical_json_bytes(&record)?)?;
    assert_eq!(decoded.origin, original);
    assert_eq!(decoded.seed.request_id, record.seed.request_id);
    assert_eq!(decoded.creation_seed, record.creation_seed);
    assert!(!decoded.captured);
    Ok(())
}

#[test]
fn missing_null_or_incomplete_origin_is_malformed() -> TestResult {
    let valid = workflow_wire()?;
    let _: RecoveryWorkflowRecordV1 = decode_contract(&canonical_json_bytes(&valid)?)?;
    for mutation in 0..3 {
        let mut changed = valid.clone();
        let fields = changed
            .as_object_mut()
            .ok_or("workflow must be an object")?;
        match mutation {
            0 => {
                fields.remove("origin");
            }
            1 => {
                fields.insert("origin".into(), Value::Null);
            }
            _ => {
                fields.insert("origin".into(), json!({"closure":"closure-only"}));
            }
        }
        assert!(matches!(
            decode_contract::<RecoveryWorkflowRecordV1>(&canonical_json_bytes(&changed)?),
            Err(ContractError::Malformed)
        ));
    }
    Ok(())
}

#[test]
fn approval_submission_and_storage_use_the_same_attestation_bound() -> TestResult {
    let fixture = authority_fixture()?;
    let attestation = fixture["coverage"][0].clone();
    for count in [1, MAX_RECOVERY_APPROVAL_ATTESTATIONS] {
        let approval = json!({
            "intent": fixture["approval_intent"],
            "coverage": vec![attestation.clone(); count]
        });
        let decoded: RecoveryApprovalSubmissionV1 =
            decode_contract(&canonical_json_bytes(&approval)?)?;
        assert_eq!(decoded.coverage.as_slice().len(), count);
        let mut workflow = workflow_wire()?;
        workflow["approval"] = approval;
        let retained: RecoveryWorkflowRecordV1 =
            decode_contract(&canonical_json_bytes(&workflow)?)?;
        assert_eq!(
            retained
                .approval
                .ok_or("retained approval missing")?
                .coverage
                .as_slice()
                .len(),
            count
        );
    }
    for (count, expected) in [
        (0, ContractError::Malformed),
        (
            MAX_RECOVERY_APPROVAL_ATTESTATIONS + 1,
            ContractError::Malformed,
        ),
    ] {
        let approval = json!({
            "intent": fixture["approval_intent"],
            "coverage": vec![attestation.clone(); count]
        });
        assert!(matches!(
            decode_contract::<RecoveryApprovalSubmissionV1>(&canonical_json_bytes(&approval)?),
            Err(error) if error == expected
        ));
        let mut workflow = workflow_wire()?;
        workflow["approval"] = approval;
        assert!(matches!(
            decode_contract::<RecoveryWorkflowRecordV1>(&canonical_json_bytes(&workflow)?),
            Err(error) if error == expected
        ));
    }
    Ok(())
}

#[test]
fn oversized_approval_refuses_at_the_contract_wire_preflight() -> TestResult {
    let fixture = authority_fixture()?;
    let approval = json!({
        "intent": fixture["approval_intent"],
        "coverage": vec![fixture["coverage"][0].clone(); 64]
    });
    let approval_bytes = canonical_json_bytes(&approval)?;
    assert!(approval_bytes.len() > MAX_RECOVERY_WIRE_BYTES);
    assert!(matches!(
        decode_contract::<RecoveryApprovalSubmissionV1>(&approval_bytes),
        Err(ContractError::LimitExceeded)
    ));
    let mut workflow = workflow_wire()?;
    workflow["approval"] = approval;
    let workflow_bytes = canonical_json_bytes(&workflow)?;
    assert!(workflow_bytes.len() > MAX_RECOVERY_WIRE_BYTES);
    assert!(matches!(
        decode_contract::<RecoveryWorkflowRecordV1>(&workflow_bytes),
        Err(ContractError::LimitExceeded)
    ));
    Ok(())
}

#[test]
fn workflow_grant_uses_the_current_recovery_envelope() -> TestResult {
    let fixture = authority_fixture()?;
    let mut workflow = workflow_wire()?;
    workflow["issuance"] = fixture["grant"]["body"].clone();
    workflow["signed_grant"] = fixture["grant"].clone();
    let record: RecoveryWorkflowRecordV1 = decode_contract(&canonical_json_bytes(&workflow)?)?;
    assert!(record.issuance.is_some());
    assert!(record.signed_grant.is_some());
    workflow["issuance"]["version"] = 2.into();
    assert!(matches!(
        decode_contract::<RecoveryWorkflowRecordV1>(&canonical_json_bytes(&workflow)?),
        Err(ContractError::Malformed)
    ));
    Ok(())
}

#[test]
fn quarantine_reason_accepts_only_frozen_verifier_or_signing_unavailability() -> TestResult {
    for (wire, reason) in [
        (
            "frozen_output_verifier_unavailable",
            RecoveryHistoricalHoldReasonV1::FrozenOutputVerifierUnavailable,
        ),
        (
            "frozen_signing_custody_unavailable",
            RecoveryHistoricalHoldReasonV1::FrozenSigningCustodyUnavailable,
        ),
    ] {
        assert_eq!(
            decode_contract::<RecoveryHistoricalHoldReasonV1>(&canonical_json_bytes(&wire)?)?,
            reason
        );
    }
    assert_eq!(
        decode_contract::<RecoveryHistoricalHoldReasonV1>(&canonical_json_bytes(
            &"legacy_deployment_unavailable"
        )?),
        Err(ContractError::Malformed)
    );
    Ok(())
}

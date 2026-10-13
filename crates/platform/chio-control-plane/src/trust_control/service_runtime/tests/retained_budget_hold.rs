use super::super::super::*;
use super::super::budget::{build_remote_budget_store, build_shared_remote_budget_store};
use super::support::{assert_json_post, StaticResponseServer};
use chio_kernel::admission_operation::StoreMutationFence;
use chio_kernel::budget_store::{BudgetHoldDispositionView, BudgetHoldSnapshot};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fence() -> StoreMutationFence {
    StoreMutationFence {
        store_uuid: "hold-recovery-store".to_owned(),
        lease_id: "current-owner".to_owned(),
        owner_epoch: 2,
    }
}

fn retained_hold() -> BudgetHoldSnapshot {
    BudgetHoldSnapshot {
        hold_id: "retained-hold".to_owned(),
        capability_id: "retained-capability".to_owned(),
        grant_index: 3,
        authorized_exposure_units: 100,
        remaining_exposure_units: 60,
        disposition: BudgetHoldDispositionView::Open,
        // A retained hold may legitimately predate the current serving lease.
        authority: Some(BudgetEventAuthority {
            authority_id: "hold-recovery-store".to_owned(),
            lease_id: "previous-owner".to_owned(),
            lease_epoch: 1,
        }),
    }
}

fn current_hold_value() -> serde_json::Value {
    serde_json::json!({
        "hold_id": "retained-hold",
        "capability_id": "retained-capability",
        "grant_index": 3,
        "authorized_exposure_units": 100,
        "remaining_exposure_units": 60,
        "disposition": "open",
        "authority": null
    })
}

const RESERVATION_FIELDS: [&str; 6] = [
    "reserved_until",
    "reserved_currency",
    "reserved_payment_reference",
    "reserved_budget_total",
    "reserved_delegation_depth",
    "reserved_root_budget_holder",
];

fn unexpected_reservation_field(field: &str) -> String {
    format!(
        "unknown field `{field}`, expected one of `hold_id`, `capability_id`, `grant_index`, `authorized_exposure_units`, `remaining_exposure_units`, `disposition`, `authority`"
    )
}

#[test]
fn retained_hold_wire_rejects_reservation_fields() -> TestResult {
    let _: RetainedBudgetHoldWire = serde_json::from_value(current_hold_value())?;
    for field in RESERVATION_FIELDS {
        let mut value = current_hold_value();
        value[field] = serde_json::Value::Null;
        let error = match serde_json::from_value::<RetainedBudgetHoldWire>(value) {
            Ok(_) => panic!("retained hold accepted unsupported field {field}"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), unexpected_reservation_field(field));
    }
    Ok(())
}

#[test]
fn remote_hold_lookup_rejects_reservation_fields() -> TestResult {
    for field in RESERVATION_FIELDS {
        let mut value = current_hold_value();
        value[field] = serde_json::Value::Null;
        let body = serde_json::to_string(&AdmissionAuthorityResponse::success(&Some(value))?)?;
        let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
        let store = build_shared_remote_budget_store(&server.url, "secret", fence())?;
        let message = match store.get_budget_hold("retained-hold") {
            Err(chio_kernel::BudgetStoreError::Invariant(message)) => message,
            other => panic!("unexpected retained hold response for {field}: {other:?}"),
        };
        assert_eq!(message, unexpected_reservation_field(field));
        assert_eq!(server.requests().len(), 1);
    }
    Ok(())
}

#[test]
fn fenced_hold_lookup_preserves_all_retained_fields() -> TestResult {
    let expected = retained_hold();
    let wire = RetainedBudgetHoldWire::from_core(expected.clone())?;
    let body = serde_json::to_string(&AdmissionAuthorityResponse::success(&Some(wire))?)?;
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let store = build_shared_remote_budget_store(&server.url, "secret", fence())?;
    let actual = store.get_budget_hold("retained-hold")?;
    assert_eq!(actual, Some(expected));
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_json_post(&requests[0], INTERNAL_ADMISSION_AUTHORITY_PATH, &[]);
    let request: AdmissionAuthorityRequest = serde_json::from_str(requests[0].body())?;
    assert_eq!(request.expected_fence, Some(fence()));
    assert_eq!(request.action, AdmissionAuthorityAction::LoadBudgetHold);
    assert_eq!(
        request.payload,
        serde_json::json!({"hold_id": "retained-hold"})
    );
    Ok(())
}

#[test]
fn only_an_authoritative_null_is_reported_as_absent() -> TestResult {
    let body = serde_json::to_string(&AdmissionAuthorityResponse::success(
        &None::<RetainedBudgetHoldWire>,
    )?)?;
    let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
    let store = build_shared_remote_budget_store(&server.url, "secret", fence())?;
    assert_eq!(store.get_budget_hold("retained-hold")?, None);
    // Unqualified clients must fail before issuing a request, not claim absence.
    let unqualified = build_remote_budget_store(&server.url, "secret")?;
    assert!(unqualified.get_budget_hold("retained-hold").is_err());
    assert_eq!(server.requests().len(), 1);
    Ok(())
}

#[test]
fn hold_lookup_rejects_unavailable_fenced_and_ambiguous_responses() -> TestResult {
    for code in [
        AdmissionAuthorityErrorCode::Unavailable,
        AdmissionAuthorityErrorCode::Fenced,
        AdmissionAuthorityErrorCode::Unsupported,
        AdmissionAuthorityErrorCode::NotFound,
    ] {
        let response = AdmissionAuthorityResponse::failure(code, "authority refused lookup");
        let body = serde_json::to_string(&response)?;
        let server = StaticResponseServer::spawn(200, &body, "application/json", 1);
        let store = build_shared_remote_budget_store(&server.url, "secret", fence())?;
        assert!(store.get_budget_hold("retained-hold").is_err());
    }
    let valid = serde_json::to_value(AdmissionAuthorityResponse::success(&Some(
        RetainedBudgetHoldWire::from_core(retained_hold())?,
    ))?)?;
    for mutation in [
        "identity",
        "exposure",
        "disposition",
        "schema",
        "both",
        "neither",
        "unknown",
    ] {
        let mut response = valid.clone();
        match mutation {
            "identity" => response["result"]["value"]["hold_id"] = "another-hold".into(),
            "exposure" => response["result"]["value"]["remaining_exposure_units"] = 101.into(),
            "disposition" => response["result"]["value"]["disposition"] = "missing".into(),
            "schema" => response["schema"] = "unknown".into(),
            "both" => {
                response["error"] = serde_json::json!({"code": "unavailable", "message": "failed"})
            }
            "neither" => response["result"] = serde_json::Value::Null,
            "unknown" => response["result"]["value"]["untrusted"] = true.into(),
            _ => unreachable!(),
        }
        let server = StaticResponseServer::spawn(
            200,
            &serde_json::to_string(&response)?,
            "application/json",
            1,
        );
        let store = build_shared_remote_budget_store(&server.url, "secret", fence())?;
        assert!(
            store.get_budget_hold("retained-hold").is_err(),
            "accepted {mutation}"
        );
    }
    Ok(())
}

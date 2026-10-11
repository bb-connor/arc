use super::*;
use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::scope::MonetaryAmount;

const DENIED: &[u8] = br#"{"delivery_status_denied":true,"finding_denial":{"code":"status_denied"},"pricing":{"failure":"authorization_exceeded","oracle_evidence":null,"reported_cost":{"currency":"USD","units":25}},"schema":"chio.kernel-terminal-snapshot.v1"}"#;
const ALLOWED: &[u8] = br#"{"delivery_status_denied":false,"finding_denial":null,"pricing":null,"schema":"chio.kernel-terminal-snapshot.v1"}"#;

fn allowed() -> delivery_contract::DeliveryEvaluation {
    delivery_contract::DeliveryEvaluation {
        digest_mismatched: false,
        reveal_check: None,
        denial: None,
    }
}

#[test]
fn terminal_snapshot_wire_preserves_denial_and_original_pricing(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut delivery = allowed();
    delivery.denial = Some(delivery_contract::finding_status_delivery_denial());
    let denial = FindingDenial::new(FindingDenialCode::StatusDenied, "private mutable detail");
    let pricing = DurablePaymentPricing {
        reported_cost: Some(MonetaryAmount {
            units: 25,
            currency: "USD".into(),
        }),
        oracle_evidence: None,
        failure: Some(super::super::payment_pricing::DurablePricingFailure::AuthorizationExceeded),
    };
    let prepared = DurableTerminalSnapshot::prepare(&delivery, Some(&denial), Some(pricing));
    assert_eq!(canonical_json_bytes(&prepared.canonical_value()?)?, DENIED);
    let retained: DurableTerminalSnapshot = serde_json::from_slice(DENIED)?;
    assert_eq!(canonical_json_bytes(&retained.canonical_value()?)?, DENIED);
    let mut replay = allowed();
    let restored = retained
        .restore_delivery(&mut replay)
        .ok_or("retained finding denial")?;
    assert_eq!(restored.code(), FindingDenialCode::StatusDenied);
    assert_eq!(
        replay.denial.ok_or("retained delivery denial")?.reason,
        crate::admission_operation::DeliveryDenialReason::FindingStatusChanged
    );
    assert_eq!(
        retained.pricing.ok_or("retained pricing")?.reported_cost,
        Some(MonetaryAmount {
            units: 25,
            currency: "USD".into()
        })
    );
    Ok(())
}

#[test]
fn terminal_snapshot_wire_keeps_null_option_fields_and_refuses_unknown_facts(
) -> Result<(), Box<dyn std::error::Error>> {
    let prepared = DurableTerminalSnapshot::prepare(&allowed(), None, None);
    assert_eq!(canonical_json_bytes(&prepared.canonical_value()?)?, ALLOWED);
    for (field, nested) in [("new_authority", false), ("new_authority", true)] {
        let mut value: serde_json::Value = serde_json::from_slice(DENIED)?;
        if nested {
            value["finding_denial"][field] = serde_json::json!(true);
        } else {
            value[field] = serde_json::json!(true);
        }
        match serde_json::from_value::<DurableTerminalSnapshot>(value) {
            Err(error) => {
                assert_eq!(error.classify(), serde_json::error::Category::Data);
                assert!(error
                    .to_string()
                    .starts_with("unknown field `new_authority`, expected "));
            }
            Ok(_) => panic!("terminal wire accepted unknown facts"),
        }
    }
    Ok(())
}

use chio_recovery_lab::{fixture::Case, plan, prepare_approved_offer, OperationState};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let case = Case::new()?;
    let initial = plan(&case.intent, &case.host)?;
    let offer = case.offer()?;
    let grant = case.grant(200)?;
    let prepared = prepare_approved_offer(&offer, &case.intent, &case.host, &grant, 151_000)?;
    let after_preparation = plan(&case.intent, &case.host)?;
    let mut unknown = case.host.clone();
    unknown.operation_state = OperationState::OutcomeUnknown;
    let mut denied = case.host.clone();
    denied.operation_state = OperationState::DeniedBeforeDispatch;
    let output = serde_json::json!({
        "scope": "Real Chio flow verification and preparation; no grant consumption or tool dispatch",
        "initial": initial,
        "approved_preparation": {
            "source_label": prepared.admission().source_label,
            "egress_source_label": prepared.admission().egress_source_label,
            "grant_id": prepared.declassification().map(|v| v.grant_id()),
            "dispatch_authorized": false
        },
        "subsequent_disclosure": after_preparation,
        "already_frozen_denial": plan(&case.intent, &denied)?,
        "unknown_operation": plan(&case.intent, &unknown)?
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

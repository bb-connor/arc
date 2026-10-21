use super::*;

#[test]
fn remote_output_withheld_preserves_the_typed_terminal_refusal() -> Result<(), serde_json::Error> {
    let wire: AdmissionAuthorityWireError = serde_json::from_value(serde_json::json!({
        "code": "output_withheld",
        "message": "retained output"
    }))?;
    assert_eq!(wire.code, AdmissionAuthorityErrorCode::OutputWithheld);
    assert_eq!(
        operation_error(RemoteAdmissionError::Authority(wire)),
        AdmissionOperationStoreError::KernelStopped
    );
    Ok(())
}

#[test]
fn pre_admission_stop_does_not_claim_retained_output() -> Result<(), serde_json::Error> {
    let wire: AdmissionAuthorityWireError = serde_json::from_value(serde_json::json!({
        "code": "stopped",
        "message": "admission stopped"
    }))?;
    assert_eq!(
        operation_error(RemoteAdmissionError::Authority(wire)),
        AdmissionOperationStoreError::Unavailable("admission stopped".into())
    );
    Ok(())
}

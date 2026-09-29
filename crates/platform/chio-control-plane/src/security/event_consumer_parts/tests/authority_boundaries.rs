use super::*;

#[test]
fn native_event_reader_rejects_duplicate_signed_fields_with_private_cause() -> Result<(), Box<dyn std::error::Error>> {
    use std::error::Error as _;
    let keypair = Keypair::from_seed(&[72_u8; 32]);
    let verifier = verifier(&keypair);
    let mut event = signed_event(&keypair);
    assert_eq!(verifier.verify(&event)?.event_id, event.event_id);
    let value: serde_json::Value = serde_json::from_slice(event.source_evidence.as_bytes())?;
    let (key, field) = value.as_object().ok_or("object")?.iter().next().ok_or("field")?;
    let mut wire = std::str::from_utf8(event.source_evidence.as_bytes())?.to_owned();
    wire.insert_str(1, &format!("{}:{},", serde_json::to_string(key)?, field));
    event.source_evidence = CanonicalBody::new(wire.into_bytes())?;
    let error = verifier.verify(&event).err().ok_or("accepted ambiguous signed event")?;
    assert_eq!(error.kind(), chio_security_types::ports::PortErrorKind::InvalidData);
    assert_eq!(error.code().as_str(), "urn:chio:error:attest:signed-json-invalid-input");
    assert!(error.source().and_then(|source| source.downcast_ref::<chio_core::canonical::UntrustedJsonError>()).is_some());
    assert!(!format!("{error:?}").contains("event-signed"));
    Ok(())
}

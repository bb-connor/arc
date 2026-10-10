use chio_security_types::ports::{
    BodyError, CanonicalBody, ClassificationPayload, MAX_CLASSIFICATION_PAYLOAD_BYTES,
};
use serde::Deserialize;

#[test]
fn delivered_payload_and_authority_body_have_distinct_limits() {
    let payload = ClassificationPayload::new(vec![b'x'; MAX_CLASSIFICATION_PAYLOAD_BYTES])
        .unwrap_or_else(|error| panic!("bounded output: {error}"));
    assert_eq!(payload.as_bytes().len(), MAX_CLASSIFICATION_PAYLOAD_BYTES);
    assert_eq!(
        ClassificationPayload::new(vec![0; MAX_CLASSIFICATION_PAYLOAD_BYTES + 1]),
        Err(BodyError::TooLarge)
    );
    assert_eq!(
        CanonicalBody::new(vec![0; 1_048_577]),
        Err(BodyError::TooLarge)
    );
}

#[test]
fn classification_payload_decode_enforces_its_allocation_bound() {
    // Exercise the sequence visitor without constructing a larger JSON string.
    let bytes = core::iter::repeat_n(0_u8, MAX_CLASSIFICATION_PAYLOAD_BYTES + 1);
    let deserializer = serde::de::value::SeqDeserializer::<_, serde::de::value::Error>::new(bytes);
    let result = ClassificationPayload::deserialize(deserializer);
    assert!(matches!(result, Err(error) if error.to_string().contains("item limit")));
    let small: ClassificationPayload = serde_json::from_str("[97,98,99]")
        .unwrap_or_else(|error| panic!("payload decode: {error}"));
    assert_eq!(small.as_bytes(), b"abc");
}

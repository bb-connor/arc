use chio_data_guards::{
    ClassifierIdentity, RegexStructuredClassifier, StructuredClassificationError,
    StructuredClassificationResult, StructuredClassifier,
};
use chio_security_types::ports::MAX_CLASSIFICATION_PAYLOAD_BYTES;

#[test]
fn classifier_and_result_share_the_bounded_payload_contract(
) -> Result<(), Box<dyn std::error::Error>> {
    let classifier = RegexStructuredClassifier::new("size", "1", vec![])?;
    let payload = vec![b'x'; MAX_CLASSIFICATION_PAYLOAD_BYTES];
    assert_eq!(
        classifier.classify(&payload)?.payload_len(),
        payload.len() as u64
    );
    let oversized = vec![b'x'; MAX_CLASSIFICATION_PAYLOAD_BYTES + 1];
    assert!(matches!(
        classifier.classify(&oversized),
        Err(StructuredClassificationError::PayloadTooLarge)
    ));
    assert!(matches!(
        StructuredClassificationResult::from_payload(
            ClassifierIdentity::new("size", "1")?,
            &oversized,
            vec![]
        ),
        Err(StructuredClassificationError::PayloadTooLarge)
    ));
    Ok(())
}

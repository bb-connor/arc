//! Broker wire bodies are byte arrays. Classify their actual HTTP bytes too.
use chio_data_guards::{
    RegexStructuredClassifier, StructuredClassificationError, StructuredClassificationFinding,
    StructuredClassificationResult, StructuredClassifier,
};

pub(super) struct BrokerBodyClassifier(pub RegexStructuredClassifier);

impl StructuredClassifier for BrokerBodyClassifier {
    fn classify(
        &self,
        payload: &[u8],
    ) -> Result<StructuredClassificationResult, StructuredClassificationError> {
        // The ordinary classifier applies its payload and finding ceilings to
        // the complete original envelope before we allocate a decoded body.
        let envelope = self.0.classify(payload)?;
        let value: serde_json::Value = crate::input::decode(
            payload,
            chio_security_types::ports::MAX_CLASSIFICATION_PAYLOAD_BYTES,
        )
        .map_err(|_| StructuredClassificationError::InvalidLocation)?;
        let field = if value.pointer("/request/body").is_some() {
            "/request/body"
        } else {
            "/body"
        };
        let body: Vec<u8> = serde_json::from_value(
            value
                .pointer(field)
                .ok_or(StructuredClassificationError::InvalidLocation)?
                .clone(),
        )
        .map_err(|_| StructuredClassificationError::InvalidLocation)?;
        let classified = self.0.classify(&body)?;
        let mut findings = envelope.findings().to_vec();
        for finding in classified.findings() {
            // A body offset is not an offset into the original JSON. Attribute
            // decoded-byte findings to the actual field of that signed input.
            findings.push(StructuredClassificationFinding::at_field_path(
                finding.classifier().id(),
                finding.classifier().version(),
                finding.category(),
                finding.confidence_basis_points(),
                field,
            )?);
        }
        StructuredClassificationResult::from_payload(envelope.identity().clone(), payload, findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_data_guards::{FindingLocation, RegexClassificationRule};
    use serde_json::json;

    #[test]
    fn large_broker_body_preserves_complete_classification_and_original_digest(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let classifier = BrokerBodyClassifier(RegexStructuredClassifier::new(
            "broker-body",
            "1",
            vec![RegexClassificationRule::new(
                "private",
                "PRIVATE_INPUT",
                10000,
            )?],
        )?);
        for output in ["x".repeat(500_000), "\0".repeat(79_000)] {
            let body = serde_json::to_vec(&json!({"output": output, "marker": "PRIVATE_INPUT"}))?;
            let envelope = chio_core_types::canonical_json_bytes(&json!({"body": body}))?;
            assert!(envelope.len() > 1_048_576);
            let payload = chio_security_types::ports::ClassificationPayload::new(envelope)?;
            let result = classifier.classify(payload.as_bytes())?;
            assert_eq!(
                result.payload_digest(),
                chio_core_types::sha256(payload.as_bytes()).as_bytes()
            );
            assert_eq!(result.payload_len(), payload.as_bytes().len() as u64);
            assert_eq!(result.findings().len(), 1);
            assert_eq!(
                result.findings()[0].location(),
                &FindingLocation::FieldPath("/body".into())
            );
        }
        let oversized =
            vec![b'x'; chio_security_types::ports::MAX_CLASSIFICATION_PAYLOAD_BYTES + 1];
        assert!(matches!(
            classifier.classify(&oversized),
            Err(StructuredClassificationError::PayloadTooLarge)
        ));
        Ok(())
    }

    #[test]
    fn request_and_response_body_findings_bind_the_original_envelope(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let classifier = BrokerBodyClassifier(RegexStructuredClassifier::new(
            "broker-body",
            "1",
            vec![RegexClassificationRule::new(
                "private",
                "PRIVATE_INPUT",
                10000,
            )?],
        )?);
        for (value, field) in [
            (
                json!({"request":{"body":b"PRIVATE_INPUT".to_vec()}}),
                "/request/body",
            ),
            (json!({"body":b"PRIVATE_INPUT".to_vec()}), "/body"),
        ] {
            let bytes = chio_core_types::canonical_json_bytes(&value)?;
            let result = classifier.classify(&bytes)?;
            assert_eq!(
                result.payload_digest(),
                chio_core_types::sha256(&bytes).as_bytes()
            );
            assert_eq!(result.findings().len(), 1);
            assert_eq!(result.findings()[0].category(), "private");
            assert_eq!(
                result.findings()[0].location(),
                &FindingLocation::FieldPath(field.into())
            );
        }
        assert!(classifier.classify(br#"{"body":[256]}"#).is_err());
        assert!(classifier.classify(br#"{"body":"encoded bytes"}"#).is_err());
        assert!(classifier.classify(br#"{}"#).is_err());
        for bytes in [
            br#"{"body":[],"body":[65]}"#.as_slice(),
            br#"{"request":{"body":[],"body":[65]}}"#,
        ] {
            assert!(matches!(
                classifier.classify(bytes),
                Err(StructuredClassificationError::InvalidLocation)
            ));
        }
        Ok(())
    }
}

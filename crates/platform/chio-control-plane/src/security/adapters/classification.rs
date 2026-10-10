use super::{
    Arc, BoundedVec, ByteRange, ClassificationFinding, ClassificationPort, ClassificationRequest,
    ClassificationResult, ClassifierId, ClassifierVersion, Digest32, FindingLocation, PortError,
    PortResult, RecordId, StructuredClassifier,
};

pub struct StructuredClassificationAdapter {
    classifier: Arc<dyn StructuredClassifier>,
}

impl StructuredClassificationAdapter {
    #[must_use]
    pub fn new(classifier: Arc<dyn StructuredClassifier>) -> Self {
        Self { classifier }
    }
}

impl ClassificationPort for StructuredClassificationAdapter {
    fn classify(&self, request: &ClassificationRequest) -> PortResult<ClassificationResult> {
        let actual_digest = chio_core::sha256(request.payload.as_bytes());
        if actual_digest.as_bytes() != request.payload_digest.as_bytes() {
            return Err(PortError::integrity_failure());
        }
        let result = self
            .classifier
            .classify(request.payload.as_bytes())
            .map_err(|_| PortError::unavailable())?;
        if result.payload_digest() != request.payload_digest.as_bytes()
            || result.payload_len()
                != u64::try_from(request.payload.as_bytes().len())
                    .map_err(|_| PortError::invalid_data())?
        {
            return Err(PortError::integrity_failure());
        }
        let classifier_id = ClassifierId::new(result.identity().id()).map_err(PortError::from)?;
        let classifier_version =
            ClassifierVersion::new(result.identity().version()).map_err(PortError::from)?;
        let findings = result
            .findings()
            .iter()
            .map(|finding| {
                let (byte_range, field_path) = match finding.location() {
                    FindingLocation::ByteRange { start, end } => (
                        Some(ByteRange {
                            start: *start,
                            end: *end,
                        }),
                        None,
                    ),
                    FindingLocation::FieldPath(path) => {
                        (None, Some(RecordId::new(path).map_err(PortError::from)?))
                    }
                };
                Ok(ClassificationFinding {
                    category: RecordId::new(finding.category()).map_err(PortError::from)?,
                    confidence_basis_points: finding.confidence_basis_points(),
                    byte_range,
                    field_path,
                })
            })
            .collect::<PortResult<Vec<_>>>()?;
        Ok(ClassificationResult {
            tenant_id: request.tenant_id.clone(),
            request_id: request.request_id.clone(),
            payload_digest: Digest32::new(*result.payload_digest()),
            classifier_id,
            classifier_version,
            findings: BoundedVec::new(findings).map_err(|_| PortError::invalid_data())?,
        })
    }
}

#[cfg(any(feature = "std", test))]
use crate::InformationFlowLattice;
use crate::LatticeError;
use alloc::collections::BTreeMap;
#[cfg(any(feature = "std", test))]
use chio_security_types::ports::{
    ClassificationFinding, ClassificationRequest, ClassificationResult,
};
use chio_security_types::ports::{
    ClassifierId, ClassifierVersion, Digest32, RecordId, RequestId, TenantId,
};
use chio_security_types::InformationLabel;
use core::fmt;
#[cfg(any(feature = "std", test))]
use sha2::{Digest as _, Sha256};

const MAX_CATEGORY_MAPPINGS: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CategoryLabelMap {
    classifier_id: ClassifierId,
    classifier_version: ClassifierVersion,
    labels: BTreeMap<RecordId, InformationLabel>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedClassification {
    tenant_id: TenantId,
    label: InformationLabel,
    classifier_id: ClassifierId,
    classifier_version: ClassifierVersion,
    finding_count: usize,
    request_id: RequestId,
    payload_digest: Digest32,
}

impl VerifiedClassification {
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn label(&self) -> &InformationLabel {
        &self.label
    }

    #[must_use]
    pub const fn classifier_id(&self) -> &ClassifierId {
        &self.classifier_id
    }

    #[must_use]
    pub const fn classifier_version(&self) -> &ClassifierVersion {
        &self.classifier_version
    }

    #[must_use]
    pub const fn finding_count(&self) -> usize {
        self.finding_count
    }

    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    #[must_use]
    pub const fn payload_digest(&self) -> Digest32 {
        self.payload_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClassificationMappingError {
    TooManyCategories,
    TopCategory(RecordId),
    ClassifierFailure,
    ClassifierIdentityMismatch,
    RequestBindingMismatch,
    UnknownCategory(RecordId),
    InvalidConfidence,
    MissingLocation,
    AmbiguousLocation,
    InvalidByteRange,
    InvalidFieldPath,
    InvalidJoin(LatticeError),
}

impl fmt::Display for ClassificationMappingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyCategories => formatter.write_str("category map exceeds its limit"),
            Self::TopCategory(category) => write!(formatter, "category `{category}` maps to top"),
            Self::ClassifierFailure => formatter.write_str("classifier evaluation failed"),
            Self::ClassifierIdentityMismatch => {
                formatter.write_str("classifier identity or version does not match policy")
            }
            Self::RequestBindingMismatch => {
                formatter.write_str("classification result does not match its request")
            }
            Self::UnknownCategory(category) => {
                write!(
                    formatter,
                    "classifier returned unknown category `{category}`"
                )
            }
            Self::InvalidConfidence => formatter.write_str("classifier confidence is invalid"),
            Self::MissingLocation => formatter.write_str("classification location is missing"),
            Self::AmbiguousLocation => formatter.write_str("classification has multiple locations"),
            Self::InvalidByteRange => formatter.write_str("classification byte range is invalid"),
            Self::InvalidFieldPath => formatter.write_str("classification field path is invalid"),
            Self::InvalidJoin(error) => {
                write!(formatter, "classification label join failed: {error}")
            }
        }
    }
}

impl core::error::Error for ClassificationMappingError {}

impl CategoryLabelMap {
    pub fn new(
        classifier_id: ClassifierId,
        classifier_version: ClassifierVersion,
        labels: BTreeMap<RecordId, InformationLabel>,
    ) -> Result<Self, ClassificationMappingError> {
        if labels.len() > MAX_CATEGORY_MAPPINGS {
            return Err(ClassificationMappingError::TooManyCategories);
        }
        if let Some((category, _)) = labels
            .iter()
            .find(|(_, label)| matches!(label, InformationLabel::Top))
        {
            return Err(ClassificationMappingError::TopCategory(category.clone()));
        }
        Ok(Self {
            classifier_id,
            classifier_version,
            labels,
        })
    }

    #[cfg(feature = "std")]
    pub fn classify(
        &self,
        classifier: &dyn chio_security_types::ports::ClassificationPort,
        request: &ClassificationRequest,
    ) -> Result<VerifiedClassification, ClassificationMappingError> {
        let result = classifier
            .classify(request)
            .map_err(|_| ClassificationMappingError::ClassifierFailure)?;
        self.verify_result(request, result)
    }

    #[cfg(any(feature = "std", test))]
    pub(crate) fn verify_result(
        &self,
        request: &ClassificationRequest,
        result: ClassificationResult,
    ) -> Result<VerifiedClassification, ClassificationMappingError> {
        let actual_payload_digest = Sha256::digest(request.payload.as_bytes());
        if &actual_payload_digest[..] != request.payload_digest.as_bytes() {
            return Err(ClassificationMappingError::RequestBindingMismatch);
        }
        if result.classifier_id != self.classifier_id
            || result.classifier_version != self.classifier_version
        {
            return Err(ClassificationMappingError::ClassifierIdentityMismatch);
        }
        if result.tenant_id != request.tenant_id
            || result.request_id != request.request_id
            || result.payload_digest != request.payload_digest
        {
            return Err(ClassificationMappingError::RequestBindingMismatch);
        }
        let mut label = InformationLabel::bottom();
        for finding in result.findings.as_slice() {
            validate_finding(finding, request.payload.as_bytes())?;
            let category_label = self.labels.get(&finding.category).ok_or_else(|| {
                ClassificationMappingError::UnknownCategory(finding.category.clone())
            })?;
            label = label
                .join(category_label)
                .map_err(ClassificationMappingError::InvalidJoin)?;
        }
        Ok(VerifiedClassification {
            tenant_id: result.tenant_id,
            label,
            classifier_id: result.classifier_id,
            classifier_version: result.classifier_version,
            finding_count: result.findings.len(),
            request_id: result.request_id,
            payload_digest: result.payload_digest,
        })
    }
}

#[cfg(any(feature = "std", test))]
fn validate_finding(
    finding: &ClassificationFinding,
    payload: &[u8],
) -> Result<(), ClassificationMappingError> {
    if finding.confidence_basis_points > 10_000 {
        return Err(ClassificationMappingError::InvalidConfidence);
    }
    match (&finding.byte_range, &finding.field_path) {
        (None, None) => Err(ClassificationMappingError::MissingLocation),
        (Some(_), Some(_)) => Err(ClassificationMappingError::AmbiguousLocation),
        (Some(range), None)
            if range.start >= range.end
                || usize::try_from(range.end).map_or(true, |end| end > payload.len()) =>
        {
            Err(ClassificationMappingError::InvalidByteRange)
        }
        (Some(_), None) => Ok(()),
        (None, Some(path)) => validate_field_path(payload, path.as_str()),
    }
}

#[cfg(any(feature = "std", test))]
fn validate_field_path(payload: &[u8], path: &str) -> Result<(), ClassificationMappingError> {
    if !path.starts_with('/') {
        return Err(ClassificationMappingError::InvalidFieldPath);
    }
    let document: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|_| ClassificationMappingError::InvalidFieldPath)?;
    document
        .pointer(path)
        .map(|_| ())
        .ok_or(ClassificationMappingError::InvalidFieldPath)
}

#[cfg(test)]
mod tests {
    use super::{CategoryLabelMap, ClassificationMappingError};
    use crate::InformationFlowLattice;
    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::format;
    use alloc::vec;
    use alloc::vec::Vec;
    use chio_security_types::ports::{
        BoundedVec, ByteRange, CanonicalBody, ClassificationFinding, ClassificationRequest,
        ClassificationResult, ClassifierId, ClassifierVersion, Digest32, RecordId, RequestId,
        TenantId,
    };
    use chio_security_types::{Compartment, InformationLabel, PrincipalId};
    use sha2::{Digest as _, Sha256};

    fn id(value: &str) -> RecordId {
        RecordId::new(value).unwrap_or_else(|error| panic!("record id: {error}"))
    }

    fn classifier_id() -> ClassifierId {
        ClassifierId::new("classifier.main")
            .unwrap_or_else(|error| panic!("classifier id: {error}"))
    }

    fn classifier_version() -> ClassifierVersion {
        ClassifierVersion::new("2026-07-12")
            .unwrap_or_else(|error| panic!("classifier version: {error}"))
    }

    fn principal(value: &str) -> PrincipalId {
        PrincipalId::new(value).unwrap_or_else(|error| panic!("principal id: {error}"))
    }

    fn compartment(value: &str) -> Compartment {
        Compartment::new(value).unwrap_or_else(|error| panic!("compartment: {error}"))
    }

    fn label(owner: &str, compartment_name: &str) -> InformationLabel {
        let owner = principal(owner);
        InformationLabel::try_known(
            BTreeMap::from([(owner.clone(), BTreeSet::from([owner]))]),
            BTreeSet::from([compartment(compartment_name)]),
        )
        .unwrap_or_else(|error| panic!("label: {error}"))
    }

    fn finding(category: &str) -> ClassificationFinding {
        ClassificationFinding {
            category: id(category),
            confidence_basis_points: 9_500,
            byte_range: Some(ByteRange { start: 0, end: 1 }),
            field_path: None,
        }
    }

    fn request(payload: &[u8]) -> ClassificationRequest {
        let payload_digest = Sha256::digest(payload);
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&payload_digest);
        ClassificationRequest {
            tenant_id: TenantId::new("tenant-a").unwrap_or_else(|error| panic!("tenant: {error}")),
            request_id: RequestId::new("classification-a")
                .unwrap_or_else(|error| panic!("request id: {error}")),
            payload: CanonicalBody::new(payload.to_vec())
                .unwrap_or_else(|error| panic!("payload: {error}")),
            payload_digest: Digest32::new(digest),
        }
    }

    fn result(
        request: &ClassificationRequest,
        findings: Vec<ClassificationFinding>,
    ) -> ClassificationResult {
        ClassificationResult {
            tenant_id: request.tenant_id.clone(),
            request_id: request.request_id.clone(),
            payload_digest: request.payload_digest,
            classifier_id: classifier_id(),
            classifier_version: classifier_version(),
            findings: BoundedVec::new(findings)
                .unwrap_or_else(|error| panic!("classification findings: {error}")),
        }
    }

    fn map(labels: BTreeMap<RecordId, InformationLabel>) -> CategoryLabelMap {
        CategoryLabelMap::new(classifier_id(), classifier_version(), labels)
            .unwrap_or_else(|error| panic!("category map: {error}"))
    }

    #[test]
    fn pii_phi_secret_and_tenant_categories_join_all_restrictions() {
        let labels = [
            ("pii", label("owner-pii", "personal-data")),
            ("phi", label("owner-phi", "health-data")),
            ("secret", label("owner-secret", "credential")),
            ("tenant.alpha", label("owner-tenant", "tenant-alpha")),
        ];
        let map = map(labels
            .iter()
            .map(|(category, label)| (id(category), label.clone()))
            .collect());
        let expected = labels
            .iter()
            .fold(InformationLabel::bottom(), |current, (_, label)| {
                current
                    .join(label)
                    .unwrap_or_else(|error| panic!("expected join: {error}"))
            });
        let request = request(b"test");
        let classified = map
            .verify_result(
                &request,
                result(
                    &request,
                    vec![
                        finding("pii"),
                        finding("phi"),
                        finding("secret"),
                        finding("tenant.alpha"),
                    ],
                ),
            )
            .unwrap_or_else(|error| panic!("classification: {error}"));
        assert_eq!(classified.label(), &expected);
        assert_eq!(classified.finding_count(), 4);
        assert_eq!(classified.classifier_id().as_str(), "classifier.main");
    }

    #[test]
    fn identity_request_and_payload_mismatch_deny() {
        let map = map(BTreeMap::new());
        let request = request(b"test");
        let mut wrong_identity = result(&request, vec![]);
        wrong_identity.classifier_version =
            ClassifierVersion::new("other").unwrap_or_else(|error| panic!("version: {error}"));
        assert_eq!(
            map.verify_result(&request, wrong_identity),
            Err(ClassificationMappingError::ClassifierIdentityMismatch)
        );
        let mut wrong_request = result(&request, vec![]);
        wrong_request.payload_digest = Digest32::new([8; 32]);
        assert_eq!(
            map.verify_result(&request, wrong_request),
            Err(ClassificationMappingError::RequestBindingMismatch)
        );

        let mut wrong_tenant = result(&request, vec![]);
        wrong_tenant.tenant_id =
            TenantId::new("tenant-b").unwrap_or_else(|error| panic!("tenant: {error}"));
        assert_eq!(
            map.verify_result(&request, wrong_tenant),
            Err(ClassificationMappingError::RequestBindingMismatch)
        );

        let mut false_digest_request = request.clone();
        false_digest_request.payload_digest = Digest32::new([8; 32]);
        assert_eq!(
            map.verify_result(&false_digest_request, result(&false_digest_request, vec![]),),
            Err(ClassificationMappingError::RequestBindingMismatch)
        );
    }

    #[test]
    fn unknown_category_and_malformed_findings_deny() {
        let map = map(BTreeMap::from([(
            id("pii"),
            label("owner-pii", "personal-data"),
        )]));
        let request = request(br#"{"patient":{"diagnosis":"x"}}"#);
        assert_eq!(
            map.verify_result(&request, result(&request, vec![finding("unknown")])),
            Err(ClassificationMappingError::UnknownCategory(id("unknown")))
        );

        let mut invalid_confidence = finding("pii");
        invalid_confidence.confidence_basis_points = 10_001;
        assert_eq!(
            map.verify_result(&request, result(&request, vec![invalid_confidence])),
            Err(ClassificationMappingError::InvalidConfidence)
        );
        let mut out_of_bounds = finding("pii");
        out_of_bounds.byte_range = Some(ByteRange { start: 0, end: 100 });
        assert_eq!(
            map.verify_result(&request, result(&request, vec![out_of_bounds])),
            Err(ClassificationMappingError::InvalidByteRange)
        );
        let mut missing_path = finding("pii");
        missing_path.byte_range = None;
        missing_path.field_path = Some(id("/patient/missing"));
        assert_eq!(
            map.verify_result(&request, result(&request, vec![missing_path])),
            Err(ClassificationMappingError::InvalidFieldPath)
        );
        let mut valid_path = finding("pii");
        valid_path.byte_range = None;
        valid_path.field_path = Some(id("/patient/diagnosis"));
        map.verify_result(&request, result(&request, vec![valid_path]))
            .unwrap_or_else(|error| panic!("field path: {error}"));
    }

    #[test]
    fn authenticated_empty_result_retains_request_and_classifier_binding() {
        let map = map(BTreeMap::new());
        let request = request(b"public");
        let classified = map
            .verify_result(&request, result(&request, vec![]))
            .unwrap_or_else(|error| panic!("classification: {error}"));
        assert_eq!(classified.label(), &InformationLabel::bottom());
        assert_eq!(classified.finding_count(), 0);
        assert_eq!(classified.request_id(), &request.request_id);
        assert_eq!(classified.tenant_id(), &request.tenant_id);
        assert_eq!(classified.payload_digest(), request.payload_digest);
    }

    #[cfg(feature = "std")]
    struct FixedClassifier {
        result: Result<ClassificationResult, chio_security_types::ports::PortError>,
    }

    #[cfg(feature = "std")]
    impl chio_security_types::ports::ClassificationPort for FixedClassifier {
        fn classify(
            &self,
            _: &ClassificationRequest,
        ) -> chio_security_types::ports::PortResult<ClassificationResult> {
            self.result.clone()
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn classifier_failure_cannot_collapse_to_authenticated_empty() {
        let map = map(BTreeMap::new());
        let request = request(b"public");
        let empty = FixedClassifier {
            result: Ok(result(&request, vec![])),
        };
        let verified = map
            .classify(&empty, &request)
            .unwrap_or_else(|error| panic!("empty classification: {error}"));
        assert_eq!(verified.finding_count(), 0);

        let failed = FixedClassifier {
            result: Err(chio_security_types::ports::PortError::unavailable()),
        };
        assert_eq!(
            map.classify(&failed, &request),
            Err(ClassificationMappingError::ClassifierFailure)
        );
    }

    #[test]
    fn category_map_is_bounded_and_rejects_top() {
        let too_many = (0_u16..257)
            .map(|value| (id(&format!("category-{value}")), InformationLabel::bottom()))
            .collect();
        assert_eq!(
            CategoryLabelMap::new(classifier_id(), classifier_version(), too_many),
            Err(ClassificationMappingError::TooManyCategories)
        );
        assert_eq!(
            CategoryLabelMap::new(
                classifier_id(),
                classifier_version(),
                BTreeMap::from([(id("unknown"), InformationLabel::Top)]),
            ),
            Err(ClassificationMappingError::TopCategory(id("unknown")))
        );
    }

    #[test]
    fn category_join_overflow_denies() {
        let labels = (0_u8..65)
            .map(|value| {
                (
                    id(&format!("category-{value}")),
                    label(&format!("owner-{value}"), "bounded"),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let map = map(labels);
        let request = request(&[b'a'; 65]);
        let findings = (0_u8..65)
            .map(|value| {
                let mut finding = finding(&format!("category-{value}"));
                finding.byte_range = Some(ByteRange {
                    start: u64::from(value),
                    end: u64::from(value) + 1,
                });
                finding
            })
            .collect();
        assert!(matches!(
            map.verify_result(&request, result(&request, findings)),
            Err(ClassificationMappingError::InvalidJoin(_))
        ));
    }
}

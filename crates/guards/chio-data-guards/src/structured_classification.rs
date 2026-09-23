use regex::bytes::{Regex, RegexBuilder};
use thiserror::Error;

const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_FIELD_PATH_BYTES: usize = 256;
const MAX_FINDINGS: usize = 256;
const MAX_RULES: usize = 256;
const MAX_PATTERN_BYTES: usize = 4_096;
const MAX_COMPILED_RULE_BYTES: usize = 65_536;
const MAX_PAYLOAD_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassifierIdentity {
    id: String,
    version: String,
}

impl ClassifierIdentity {
    pub fn new(
        id: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, StructuredClassificationError> {
        let id = id.into();
        let version = version.into();
        validate_identifier(&id)?;
        validate_identifier(&version)?;
        Ok(Self { id, version })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    #[must_use]
    pub fn version(&self) -> &str {
        self.version.as_str()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FindingLocation {
    ByteRange { start: u64, end: u64 },
    FieldPath(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructuredClassificationFinding {
    classifier: ClassifierIdentity,
    category: String,
    confidence_basis_points: u16,
    location: FindingLocation,
}

impl StructuredClassificationFinding {
    pub fn at_byte_range(
        classifier_id: impl Into<String>,
        classifier_version: impl Into<String>,
        category: impl Into<String>,
        confidence_basis_points: u16,
        start: u64,
        end: u64,
    ) -> Result<Self, StructuredClassificationError> {
        if start >= end {
            return Err(StructuredClassificationError::InvalidLocation);
        }
        Self::new(
            classifier_id,
            classifier_version,
            category,
            confidence_basis_points,
            FindingLocation::ByteRange { start, end },
        )
    }

    pub fn at_field_path(
        classifier_id: impl Into<String>,
        classifier_version: impl Into<String>,
        category: impl Into<String>,
        confidence_basis_points: u16,
        field_path: impl Into<String>,
    ) -> Result<Self, StructuredClassificationError> {
        let field_path = field_path.into();
        if !field_path.starts_with('/')
            || field_path.len() > MAX_FIELD_PATH_BYTES
            || field_path.trim() != field_path
            || field_path.chars().any(char::is_control)
        {
            return Err(StructuredClassificationError::InvalidLocation);
        }
        let mut characters = field_path.chars();
        while let Some(character) = characters.next() {
            if character == '~' && !matches!(characters.next(), Some('0' | '1')) {
                return Err(StructuredClassificationError::InvalidLocation);
            }
        }
        Self::new(
            classifier_id,
            classifier_version,
            category,
            confidence_basis_points,
            FindingLocation::FieldPath(field_path),
        )
    }

    fn new(
        classifier_id: impl Into<String>,
        classifier_version: impl Into<String>,
        category: impl Into<String>,
        confidence_basis_points: u16,
        location: FindingLocation,
    ) -> Result<Self, StructuredClassificationError> {
        if confidence_basis_points > 10_000 {
            return Err(StructuredClassificationError::InvalidConfidence);
        }
        let category = category.into();
        validate_identifier(&category)?;
        Ok(Self {
            classifier: ClassifierIdentity::new(classifier_id, classifier_version)?,
            category,
            confidence_basis_points,
            location,
        })
    }

    #[must_use]
    pub fn classifier(&self) -> &ClassifierIdentity {
        &self.classifier
    }

    #[must_use]
    pub fn category(&self) -> &str {
        self.category.as_str()
    }

    #[must_use]
    pub const fn confidence_basis_points(&self) -> u16 {
        self.confidence_basis_points
    }

    #[must_use]
    pub const fn location(&self) -> &FindingLocation {
        &self.location
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructuredClassificationResult {
    identity: ClassifierIdentity,
    payload_digest: [u8; 32],
    payload_len: u64,
    findings: Vec<StructuredClassificationFinding>,
}

impl StructuredClassificationResult {
    pub fn from_payload(
        identity: ClassifierIdentity,
        payload: &[u8],
        findings: Vec<StructuredClassificationFinding>,
    ) -> Result<Self, StructuredClassificationError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(StructuredClassificationError::PayloadTooLarge);
        }
        if findings.len() > MAX_FINDINGS {
            return Err(StructuredClassificationError::TooManyFindings);
        }
        if findings
            .iter()
            .any(|finding| finding.classifier != identity)
        {
            return Err(StructuredClassificationError::IdentityMismatch);
        }
        // All field findings bind this one payload. Decode it once instead of
        // repeating a potentially 1 MiB JSON allocation for each of 256 findings.
        let document = findings
            .iter()
            .any(|finding| matches!(finding.location, FindingLocation::FieldPath(_)))
            .then(|| serde_json::from_slice::<serde_json::Value>(payload))
            .transpose()
            .map_err(|_| StructuredClassificationError::InvalidLocation)?;
        for finding in &findings {
            validate_location(&finding.location, payload.len(), document.as_ref())?;
        }
        Ok(Self {
            identity,
            payload_digest: *chio_core::sha256(payload).as_bytes(),
            payload_len: u64::try_from(payload.len())
                .map_err(|_| StructuredClassificationError::PayloadTooLarge)?,
            findings,
        })
    }

    #[must_use]
    pub const fn identity(&self) -> &ClassifierIdentity {
        &self.identity
    }

    #[must_use]
    pub fn findings(&self) -> &[StructuredClassificationFinding] {
        self.findings.as_slice()
    }

    #[must_use]
    pub const fn payload_digest(&self) -> &[u8; 32] {
        &self.payload_digest
    }

    #[must_use]
    pub const fn payload_len(&self) -> u64 {
        self.payload_len
    }
}

pub trait StructuredClassifier: Send + Sync {
    fn classify(
        &self,
        payload: &[u8],
    ) -> Result<StructuredClassificationResult, StructuredClassificationError>;
}

#[derive(Clone, Debug)]
pub struct RegexClassificationRule {
    category: String,
    expression: Regex,
    confidence_basis_points: u16,
}

impl RegexClassificationRule {
    pub fn new(
        category: impl Into<String>,
        expression: &str,
        confidence_basis_points: u16,
    ) -> Result<Self, StructuredClassificationError> {
        let category = category.into();
        validate_identifier(&category)?;
        if confidence_basis_points > 10_000 {
            return Err(StructuredClassificationError::InvalidConfidence);
        }
        if expression.is_empty() || expression.len() > MAX_PATTERN_BYTES {
            return Err(StructuredClassificationError::InvalidPattern);
        }
        // Analyze consumed bytes, including contextual assertions such as word
        // boundaries that cannot be detected by matching only the empty input.
        // Match the byte regex engine's support for explicitly non-UTF-8 rules.
        let syntax = regex_syntax::ParserBuilder::new()
            .utf8(false)
            .build()
            .parse(expression)
            .map_err(|_| StructuredClassificationError::InvalidPattern)?;
        if syntax.properties().minimum_len() == Some(0) {
            return Err(StructuredClassificationError::InvalidPattern);
        }
        let expression = RegexBuilder::new(expression)
            .size_limit(MAX_COMPILED_RULE_BYTES)
            .dfa_size_limit(MAX_COMPILED_RULE_BYTES)
            .build()
            .map_err(|_| StructuredClassificationError::InvalidPattern)?;
        Ok(Self {
            category,
            expression,
            confidence_basis_points,
        })
    }
}

#[derive(Clone, Debug)]
pub struct RegexStructuredClassifier {
    identity: ClassifierIdentity,
    rules: Vec<RegexClassificationRule>,
}

impl RegexStructuredClassifier {
    pub fn new(
        classifier_id: impl Into<String>,
        classifier_version: impl Into<String>,
        rules: Vec<RegexClassificationRule>,
    ) -> Result<Self, StructuredClassificationError> {
        if rules.len() > MAX_RULES {
            return Err(StructuredClassificationError::TooManyRules);
        }
        Ok(Self {
            identity: ClassifierIdentity::new(classifier_id, classifier_version)?,
            rules,
        })
    }
}

impl StructuredClassifier for RegexStructuredClassifier {
    fn classify(
        &self,
        payload: &[u8],
    ) -> Result<StructuredClassificationResult, StructuredClassificationError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(StructuredClassificationError::PayloadTooLarge);
        }
        let mut findings = Vec::new();
        for rule in &self.rules {
            for matched in rule.expression.find_iter(payload) {
                if findings.len() == MAX_FINDINGS {
                    return Err(StructuredClassificationError::TooManyFindings);
                }
                findings.push(StructuredClassificationFinding::at_byte_range(
                    self.identity.id.clone(),
                    self.identity.version.clone(),
                    rule.category.clone(),
                    rule.confidence_basis_points,
                    u64::try_from(matched.start())
                        .map_err(|_| StructuredClassificationError::InvalidLocation)?,
                    u64::try_from(matched.end())
                        .map_err(|_| StructuredClassificationError::InvalidLocation)?,
                )?);
            }
        }
        StructuredClassificationResult::from_payload(self.identity.clone(), payload, findings)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StructuredClassificationError {
    #[error("classifier identifier is invalid")]
    InvalidIdentifier,
    #[error("classifier confidence is invalid")]
    InvalidConfidence,
    #[error("classifier pattern is invalid")]
    InvalidPattern,
    #[error("classification location is invalid")]
    InvalidLocation,
    #[error("classifier returned too many findings")]
    TooManyFindings,
    #[error("classifier has too many rules")]
    TooManyRules,
    #[error("classified representation exceeds the byte limit")]
    PayloadTooLarge,
    #[error("finding classifier identity does not match the result")]
    IdentityMismatch,
}

fn validate_identifier(value: &str) -> Result<(), StructuredClassificationError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(StructuredClassificationError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_location(
    location: &FindingLocation,
    payload_len: usize,
    document: Option<&serde_json::Value>,
) -> Result<(), StructuredClassificationError> {
    match location {
        FindingLocation::ByteRange { start, end } => {
            let start = usize::try_from(*start)
                .map_err(|_| StructuredClassificationError::InvalidLocation)?;
            let end = usize::try_from(*end)
                .map_err(|_| StructuredClassificationError::InvalidLocation)?;
            if start >= end || end > payload_len {
                return Err(StructuredClassificationError::InvalidLocation);
            }
            Ok(())
        }
        FindingLocation::FieldPath(path) => document
            .ok_or(StructuredClassificationError::InvalidLocation)?
            .pointer(path)
            .map(|_| ())
            .ok_or(StructuredClassificationError::InvalidLocation),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClassifierIdentity, FindingLocation, RegexClassificationRule, RegexStructuredClassifier,
        StructuredClassificationError, StructuredClassificationFinding,
        StructuredClassificationResult, StructuredClassifier,
    };

    #[test]
    fn regex_classifier_reports_typed_non_transforming_byte_ranges() {
        let classifier = RegexStructuredClassifier::new(
            "classifier.local",
            "2026-07-12",
            vec![
                RegexClassificationRule::new("pii.email", r"[a-z]+@[a-z]+\.[a-z]+", 9_900)
                    .unwrap_or_else(|error| panic!("email rule: {error}")),
                RegexClassificationRule::new("secret.token", r"sk-[a-z0-9]+", 10_000)
                    .unwrap_or_else(|error| panic!("secret rule: {error}")),
            ],
        )
        .unwrap_or_else(|error| panic!("classifier: {error}"));
        let payload = br#"{"email":"alice@example.com","token":"sk-abc123"}"#.to_vec();
        let unchanged = payload.clone();

        let result = classifier
            .classify(&payload)
            .unwrap_or_else(|error| panic!("classify: {error}"));

        assert_eq!(payload, unchanged);
        assert_eq!(result.identity().id(), "classifier.local");
        assert_eq!(result.identity().version(), "2026-07-12");
        assert_eq!(result.payload_len(), payload.len() as u64);
        assert_eq!(
            result.payload_digest(),
            chio_core::sha256(&payload).as_bytes()
        );
        assert_eq!(result.findings().len(), 2);
        assert_eq!(result.findings()[0].category(), "pii.email");
        assert_eq!(result.findings()[0].confidence_basis_points(), 9_900);
        assert!(matches!(
            result.findings()[0].location(),
            FindingLocation::ByteRange { start, end } if start < end
        ));
        assert_eq!(result.findings()[1].category(), "secret.token");
    }

    #[test]
    fn authenticated_empty_result_retains_classifier_identity() {
        let classifier = RegexStructuredClassifier::new(
            "classifier.local",
            "1",
            vec![RegexClassificationRule::new("pii.email", r"@", 8_000)
                .unwrap_or_else(|error| panic!("rule: {error}"))],
        )
        .unwrap_or_else(|error| panic!("classifier: {error}"));
        let result = classifier
            .classify(b"public")
            .unwrap_or_else(|error| panic!("classify: {error}"));
        assert!(result.findings().is_empty());
        assert_eq!(result.identity().id(), "classifier.local");
    }

    #[test]
    fn invalid_identity_rule_and_confidence_reject_at_load() {
        assert!(matches!(
            RegexStructuredClassifier::new(" classifier", "1", vec![]),
            Err(StructuredClassificationError::InvalidIdentifier)
        ));
        assert!(matches!(
            RegexClassificationRule::new("pii", "(", 8_000),
            Err(StructuredClassificationError::InvalidPattern)
        ));
        assert!(matches!(
            RegexClassificationRule::new("pii", "a", 10_001),
            Err(StructuredClassificationError::InvalidConfidence)
        ));
        let oversized_compiled_rule = "a?".repeat(2_000);
        assert!(matches!(
            RegexClassificationRule::new("pii", &oversized_compiled_rule, 8_000),
            Err(StructuredClassificationError::InvalidPattern)
        ));
        assert!(matches!(
            RegexClassificationRule::new("pii", "(?:a{1000}){1000}", 8_000),
            Err(StructuredClassificationError::InvalidPattern)
        ));
    }

    #[test]
    fn field_path_finding_is_validated_and_binds_identity() {
        let finding = StructuredClassificationFinding::at_field_path(
            "classifier.local",
            "1",
            "phi.diagnosis",
            9_000,
            "/patient/diagnosis",
        )
        .unwrap_or_else(|error| panic!("finding: {error}"));
        assert_eq!(finding.classifier().id(), "classifier.local");
        assert!(matches!(
            finding.location(),
            FindingLocation::FieldPath(path) if path == "/patient/diagnosis"
        ));
        assert_eq!(
            StructuredClassificationFinding::at_field_path(
                "classifier.local",
                "1",
                "phi.diagnosis",
                9_000,
                "",
            ),
            Err(StructuredClassificationError::InvalidLocation)
        );
    }

    #[test]
    fn nullable_regex_rules_reject_at_load_including_contextual_boundaries() {
        for pattern in [
            "a?",
            "a*",
            "^",
            "$",
            "(?:a|)",
            r"\b",
            r"\B",
            r"(?-u:\b)",
            r"(?-u:\B)",
            r"(?:\b|abc)",
            r"(?:a{0,2})",
        ] {
            assert!(
                matches!(
                    RegexClassificationRule::new("pii", pattern, 8_000),
                    Err(StructuredClassificationError::InvalidPattern)
                ),
                "accepted nullable pattern {pattern}"
            );
        }
    }

    #[test]
    fn consuming_regex_rules_retain_byte_matching_and_bounds() {
        for (pattern, payload, end) in [
            (r"\ba+\b", b"aaa".as_slice(), 3),
            (r"(?-u:\b)a", b"a".as_slice(), 1),
            (r"^(?:a|bc)$", b"bc".as_slice(), 2),
            (r"(?-u:\xFF)", &[255][..], 1),
        ] {
            let rule = RegexClassificationRule::new("pii", pattern, 8_000)
                .unwrap_or_else(|error| panic!("{pattern}: {error}"));
            let classifier = RegexStructuredClassifier::new("classifier.local", "1", vec![rule])
                .unwrap_or_else(|error| panic!("classifier: {error}"));
            let result = classifier
                .classify(payload)
                .unwrap_or_else(|error| panic!("classify: {error}"));
            assert_eq!(result.findings().len(), 1);
            assert_eq!(
                result.findings()[0].location(),
                &FindingLocation::ByteRange { start: 0, end }
            );
        }
    }

    #[test]
    fn field_path_constructor_rejects_non_pointer_syntax() {
        for path in [
            "patient.diagnosis",
            "patient/diagnosis",
            "/bad~",
            "/bad~2",
            "/bad~x/key",
        ] {
            assert_eq!(
                StructuredClassificationFinding::at_field_path(
                    "classifier.local",
                    "1",
                    "phi",
                    9_000,
                    path
                ),
                Err(StructuredClassificationError::InvalidLocation),
                "accepted {path}"
            );
        }
    }

    #[test]
    fn field_paths_preserve_escaped_and_empty_key_segments_and_check_existence_later() {
        let payload = br#"{"":{"":"value"},"a/b":{"~key":true}}"#;
        for path in ["/", "//", "/a~1b/~0key", "/missing"] {
            let finding = StructuredClassificationFinding::at_field_path(
                "classifier.local",
                "1",
                "phi",
                9_000,
                path,
            )
            .unwrap_or_else(|error| panic!("{path}: {error}"));
            let identity = ClassifierIdentity::new("classifier.local", "1")
                .unwrap_or_else(|error| panic!("identity: {error}"));
            let result =
                StructuredClassificationResult::from_payload(identity, payload, vec![finding]);
            if path == "/missing" {
                assert_eq!(result, Err(StructuredClassificationError::InvalidLocation));
            } else {
                assert!(result.is_ok(), "{path}: {result:?}");
            }
        }
    }

    struct FieldClassifier;

    impl StructuredClassifier for FieldClassifier {
        fn classify(
            &self,
            payload: &[u8],
        ) -> Result<StructuredClassificationResult, StructuredClassificationError> {
            let identity = ClassifierIdentity::new("classifier.external", "1")?;
            let finding = StructuredClassificationFinding::at_field_path(
                identity.id(),
                identity.version(),
                "phi.diagnosis",
                9_000,
                "/patient/diagnosis",
            )?;
            StructuredClassificationResult::from_payload(identity, payload, vec![finding])
        }
    }

    #[test]
    fn external_classifier_constructs_bounded_payload_bound_results() {
        let payload = br#"{"patient":{"diagnosis":"x"}}"#;
        let result = FieldClassifier
            .classify(payload)
            .unwrap_or_else(|error| panic!("classification: {error}"));
        assert_eq!(result.identity().id(), "classifier.external");
        assert_eq!(
            result.payload_digest(),
            chio_core::sha256(payload).as_bytes()
        );

        let identity = ClassifierIdentity::new("classifier.external", "1")
            .unwrap_or_else(|error| panic!("identity: {error}"));
        let out_of_bounds = StructuredClassificationFinding::at_byte_range(
            identity.id(),
            identity.version(),
            "pii",
            9_000,
            0,
            100,
        )
        .unwrap_or_else(|error| panic!("finding: {error}"));
        assert_eq!(
            StructuredClassificationResult::from_payload(
                identity.clone(),
                b"short",
                vec![out_of_bounds],
            ),
            Err(StructuredClassificationError::InvalidLocation)
        );
        let missing_path = StructuredClassificationFinding::at_field_path(
            identity.id(),
            identity.version(),
            "phi",
            9_000,
            "/patient/missing",
        )
        .unwrap_or_else(|error| panic!("finding: {error}"));
        assert_eq!(
            StructuredClassificationResult::from_payload(identity, payload, vec![missing_path]),
            Err(StructuredClassificationError::InvalidLocation)
        );
    }

    #[test]
    fn finding_limit_fails_closed() {
        let classifier = RegexStructuredClassifier::new(
            "classifier.local",
            "1",
            vec![RegexClassificationRule::new("secret", "a", 10_000)
                .unwrap_or_else(|error| panic!("rule: {error}"))],
        )
        .unwrap_or_else(|error| panic!("classifier: {error}"));
        assert_eq!(
            classifier.classify(&vec![b'a'; 257]),
            Err(StructuredClassificationError::TooManyFindings)
        );
    }

    #[test]
    fn unexpected_empty_runtime_match_cannot_become_authenticated_no_findings() {
        // Bypass the constructor only in this test to preserve the independent
        // runtime check against a future regression in load-time validation.
        let classifier = RegexStructuredClassifier::new(
            "classifier.local",
            "1",
            vec![RegexClassificationRule {
                category: "secret".to_owned(),
                expression: regex::bytes::Regex::new(r"\b")
                    .unwrap_or_else(|error| panic!("test regex: {error}")),
                confidence_basis_points: 10_000,
            }],
        )
        .unwrap_or_else(|error| panic!("classifier: {error}"));
        assert_eq!(
            classifier.classify(b"secret"),
            Err(StructuredClassificationError::InvalidLocation)
        );
    }
}

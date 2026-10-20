//! Typed rejections and their exit classes.

use std::fmt;

use chio_core_types::canonical::UntrustedJsonError;
use chio_errors::_generated::error_codes::{
    ATTEST_BUNDLE_ENVELOPE_INVALID, ATTEST_BUNDLE_EVIDENCE_INCONSISTENT,
    ATTEST_BUNDLE_FEATURE_UNSUPPORTED, ATTEST_BUNDLE_FILE_HASH_MISMATCH,
    ATTEST_BUNDLE_REQUIRED_COLUMN_UNVERIFIED, ATTEST_BUNDLE_SCHEMA_INVALID,
    ATTEST_BUNDLE_SIGNATURE_INVALID, ATTEST_BUNDLE_TRUST_INVALID, ATTEST_BUNDLE_TRUST_MISSING,
};
use chio_errors::ErrorCodeSpec;

/// Process exit code of a verification, shared with `chio proof verify`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitClass {
    Verified,
    Unclassified,
    Usage,
    RequiredColumn,
    Integrity,
    ParseOrSchema,
    NegativeCaseMismatch,
    VerifierContext,
}

impl ExitClass {
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::Verified => 0,
            Self::Unclassified => 1,
            Self::Usage => 2,
            Self::RequiredColumn => 10,
            Self::Integrity => 20,
            Self::ParseOrSchema => 30,
            Self::NegativeCaseMismatch => 40,
            Self::VerifierContext => 50,
        }
    }
}

/// What a rejection is about. Each kind carries exactly one registry code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleVerifyErrorKind {
    /// The bundle root cannot be read at all.
    Io,
    /// The export envelope is missing, malformed, wrongly signed or does not
    /// commit to the manifest and payload.
    EnvelopeInvalid,
    /// A listed file is missing, not a regular file, or differs from its
    /// manifest digest or length; or the inventory is not exact.
    FileHashMismatch,
    /// A receipt or checkpoint signature does not verify, or its signer is
    /// not pinned.
    SignatureInvalid,
    /// Signed parts of the bundle contradict each other: counts, scope,
    /// checkpoint chain, inclusion proofs, transparency or disclosure notice.
    EvidenceInconsistent,
    /// A file does not decode under its strict schema.
    SchemaInvalid,
    /// A file is not admissible signed JSON.
    SignedJson,
    /// The trust file fails to load.
    TrustInvalid,
    /// The bundle needs a key role the trust file leaves empty.
    TrustMissing,
    /// The bundle or the trust file asks for something this verifier does
    /// not support.
    FeatureUnsupported,
    /// A column the trust file requires is not `verified`.
    RequiredColumnUnverified,
}

/// A bundle verification rejection.
#[derive(Debug)]
pub struct BundleVerifyError {
    kind: BundleVerifyErrorKind,
    message: String,
    signed_json: Option<UntrustedJsonError>,
}

impl BundleVerifyError {
    pub fn new(kind: BundleVerifyErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            signed_json: None,
        }
    }

    pub fn io(message: impl Into<String>) -> Self {
        Self::new(BundleVerifyErrorKind::Io, message)
    }

    pub fn envelope(message: impl Into<String>) -> Self {
        Self::new(BundleVerifyErrorKind::EnvelopeInvalid, message)
    }

    pub fn file(message: impl Into<String>) -> Self {
        Self::new(BundleVerifyErrorKind::FileHashMismatch, message)
    }

    pub fn signature(message: impl Into<String>) -> Self {
        Self::new(BundleVerifyErrorKind::SignatureInvalid, message)
    }

    pub fn inconsistent(message: impl Into<String>) -> Self {
        Self::new(BundleVerifyErrorKind::EvidenceInconsistent, message)
    }

    pub fn schema(message: impl Into<String>) -> Self {
        Self::new(BundleVerifyErrorKind::SchemaInvalid, message)
    }

    pub fn trust_invalid(message: impl Into<String>) -> Self {
        Self::new(BundleVerifyErrorKind::TrustInvalid, message)
    }

    pub fn trust_missing(message: impl Into<String>) -> Self {
        Self::new(BundleVerifyErrorKind::TrustMissing, message)
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(BundleVerifyErrorKind::FeatureUnsupported, message)
    }

    pub fn required_column(message: impl Into<String>) -> Self {
        Self::new(BundleVerifyErrorKind::RequiredColumnUnverified, message)
    }

    /// A signed-JSON rejection of `what`, keeping the original rule.
    pub fn signed_json(what: &str, error: UntrustedJsonError) -> Self {
        Self {
            kind: BundleVerifyErrorKind::SignedJson,
            message: format!("{what}: {}", error.code()),
            signed_json: Some(error),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> BundleVerifyErrorKind {
        self.kind
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The signed-JSON rule behind a [`BundleVerifyErrorKind::SignedJson`].
    #[must_use]
    pub fn signed_json_source(&self) -> Option<&UntrustedJsonError> {
        self.signed_json.as_ref()
    }

    /// Consume the rejection, returning its signed-JSON rule when it has one.
    pub fn into_signed_json(self) -> Result<UntrustedJsonError, Self> {
        match self.signed_json {
            Some(error) => Ok(error),
            None => Err(self),
        }
    }

    /// The registry code, or `None` for an unclassified I/O failure and for a
    /// signed-JSON rejection, whose URN is [`Self::code_urn`].
    #[must_use]
    pub fn code(&self) -> Option<&'static ErrorCodeSpec> {
        match self.kind {
            BundleVerifyErrorKind::Io | BundleVerifyErrorKind::SignedJson => None,
            BundleVerifyErrorKind::EnvelopeInvalid => Some(&ATTEST_BUNDLE_ENVELOPE_INVALID),
            BundleVerifyErrorKind::FileHashMismatch => Some(&ATTEST_BUNDLE_FILE_HASH_MISMATCH),
            BundleVerifyErrorKind::SignatureInvalid => Some(&ATTEST_BUNDLE_SIGNATURE_INVALID),
            BundleVerifyErrorKind::EvidenceInconsistent => {
                Some(&ATTEST_BUNDLE_EVIDENCE_INCONSISTENT)
            }
            BundleVerifyErrorKind::SchemaInvalid => Some(&ATTEST_BUNDLE_SCHEMA_INVALID),
            BundleVerifyErrorKind::TrustInvalid => Some(&ATTEST_BUNDLE_TRUST_INVALID),
            BundleVerifyErrorKind::TrustMissing => Some(&ATTEST_BUNDLE_TRUST_MISSING),
            BundleVerifyErrorKind::FeatureUnsupported => Some(&ATTEST_BUNDLE_FEATURE_UNSUPPORTED),
            BundleVerifyErrorKind::RequiredColumnUnverified => {
                Some(&ATTEST_BUNDLE_REQUIRED_COLUMN_UNVERIFIED)
            }
        }
    }

    /// The registry URN this rejection reports, if any.
    #[must_use]
    pub fn code_urn(&self) -> Option<&'static str> {
        match &self.signed_json {
            Some(error) => Some(error.code()),
            None => self.code().map(|spec| spec.urn),
        }
    }

    /// The exit class, a function of the registry code alone.
    #[must_use]
    pub fn exit_class(&self) -> ExitClass {
        self.code_urn()
            .map_or(ExitClass::Unclassified, exit_class_for_urn)
    }
}

/// Exit class of a registry URN this verifier emits; any other URN is
/// unclassified.
#[must_use]
pub fn exit_class_for_urn(urn: &str) -> ExitClass {
    const BY_CODE: &[(&ErrorCodeSpec, ExitClass)] = &[
        (&ATTEST_BUNDLE_ENVELOPE_INVALID, ExitClass::Integrity),
        (&ATTEST_BUNDLE_FILE_HASH_MISMATCH, ExitClass::Integrity),
        (&ATTEST_BUNDLE_SIGNATURE_INVALID, ExitClass::Integrity),
        (&ATTEST_BUNDLE_EVIDENCE_INCONSISTENT, ExitClass::Integrity),
        (&ATTEST_BUNDLE_SCHEMA_INVALID, ExitClass::ParseOrSchema),
        (&ATTEST_BUNDLE_TRUST_INVALID, ExitClass::VerifierContext),
        (&ATTEST_BUNDLE_TRUST_MISSING, ExitClass::VerifierContext),
        (
            &ATTEST_BUNDLE_FEATURE_UNSUPPORTED,
            ExitClass::VerifierContext,
        ),
        (
            &ATTEST_BUNDLE_REQUIRED_COLUMN_UNVERIFIED,
            ExitClass::RequiredColumn,
        ),
    ];
    if let Some((_, class)) = BY_CODE.iter().find(|(spec, _)| spec.urn == urn) {
        return *class;
    }
    if urn.starts_with("urn:chio:error:attest:signed-json-") {
        return ExitClass::ParseOrSchema;
    }
    ExitClass::Unclassified
}

impl fmt::Display for BundleVerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for BundleVerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.signed_json
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}

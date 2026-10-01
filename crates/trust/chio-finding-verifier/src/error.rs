/// Terminal verifier failures: conditions under which no report draft can
/// be produced at all (facet-level failures are report content instead).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FindingVerifierError {
    #[error("raw finding exceeds the size bound")]
    RawTooLarge,
    #[error("raw finding is not strict canonical I-JSON")]
    RawNotCanonical(#[source] chio_core_types::canonical::SharedUntrustedJsonError),
    #[error("raw finding bytes are not the canonical serialization")]
    RawBytesNotCanonical,
    #[error("raw finding failed typed deserialization")]
    Deserialization(#[source] chio_core_types::canonical::SharedUntrustedJsonError),
    #[error("verifier profile envelope failed pinned verification")]
    ProfileInvalid,
    #[error("report evaluation is outside the Finding validity window")]
    FindingInactive,
    #[error("no admitted kernel keys configured")]
    NoAdmittedKernelKeys,
    #[error("runtime attestation and appraisal authorities must be independent")]
    AliasedRuntimeAssuranceAuthorities,
    #[error("verifier report and collateral authorities must be independent")]
    AliasedVerifierAndCollateralAuthorities,
    #[error("fee schedule and collateral authorities must be independent")]
    AliasedFeeScheduleAndCollateralAuthorities,
    #[error("verifier report and status operator authorities must be independent")]
    AliasedVerifierAndStatusOperatorAuthorities,
    #[error("verifier report and authority-status signers must be independent")]
    AliasedVerifierAndStatusAuthority,
    #[error("report body construction failed canonicalization")]
    Canonicalization(#[source] CanonicalizationCause),
    #[error("report profile does not match the profile used for evaluation")]
    ReportProfileMismatch,
    #[error("report signer does not match the pinned verifier authority")]
    ReportSignerMismatch,
    #[error("report evaluation is outside the profile-authorized signer window")]
    ReportSignerInactive,
    #[error("report signing failed")]
    ReportSigning,
}

/// Opaque formatting with native canonicalization/artifact causes available locally.
#[derive(Clone)]
pub struct CanonicalizationCause(std::sync::Arc<dyn std::error::Error + Send + Sync>);
impl std::fmt::Display for CanonicalizationCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("report canonicalization failed")
    }
}
impl std::fmt::Debug for CanonicalizationCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for CanonicalizationCause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
impl PartialEq for CanonicalizationCause {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for CanonicalizationCause {}
impl FindingVerifierError {
    pub(crate) fn canonicalization(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Canonicalization(CanonicalizationCause(std::sync::Arc::new(error)))
    }
}

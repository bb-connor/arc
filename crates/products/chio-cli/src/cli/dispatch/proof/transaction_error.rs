use super::*;
use chio_errors::_generated::error_codes::{
    TRANSACTION_ARTIFACT_HASH_MISMATCH, TRANSACTION_ARTIFACT_SCHEMA_INVALID,
    TRANSACTION_AUTHORIZATION_NOT_BOUND, TRANSACTION_BUYER_REVIEW_REJECTED,
    TRANSACTION_CLAIM_REJECTED, TRANSACTION_DISPUTE_UNBOUND, TRANSACTION_GRAPH_CYCLE,
    TRANSACTION_GRAPH_NOT_CLOSED, TRANSACTION_IDENTITY_NOT_BOUND,
    TRANSACTION_NEGATIVE_CASE_MISMATCH,
    TRANSACTION_PASSPORT_HASH_MISMATCH, TRANSACTION_PASSPORT_SCHEMA_UNSUPPORTED,
    TRANSACTION_SIGNATURE_INVALID, TRANSACTION_RECEIPT_UNCHECKPOINTED,
    TRANSACTION_REQUIRED_CLAIM_MISSING, TRANSACTION_RUNTIME_PROOF_REJECTED,
    TRANSACTION_SETTLEMENT_UNVERIFIED,
    TRANSACTION_TRANSPARENCY_PREVIEW_NOT_ALLOWED, TRANSACTION_VERIFIER_CONTEXT_INVALID,
    TRANSACTION_VERIFIER_FEATURE_UNSUPPORTED,
};
use chio_errors::ErrorCodeSpec;

const PROOF_VERIFY_EXIT_GENERIC: i32 = 1;
const PROOF_VERIFY_EXIT_REQUIRED_CLAIM_FAILED: i32 = 10;
const PROOF_VERIFY_EXIT_INTEGRITY_FAILURE: i32 = 20;
const PROOF_VERIFY_EXIT_PARSE_OR_SCHEMA_FAILURE: i32 = 30;
const PROOF_VERIFY_EXIT_NEGATIVE_DID_NOT_FAIL: i32 = 40;
const PROOF_VERIFY_EXIT_UNSUPPORTED_FEATURE: i32 = 50;

/// Every transaction registry code has exactly one exit class here, so a
/// rejection that carries one never exits with the generic code.
const PROOF_VERIFY_EXIT_BY_CODE: &[(&ErrorCodeSpec, i32)] = &[
    (
        &TRANSACTION_REQUIRED_CLAIM_MISSING,
        PROOF_VERIFY_EXIT_REQUIRED_CLAIM_FAILED,
    ),
    (
        &TRANSACTION_CLAIM_REJECTED,
        PROOF_VERIFY_EXIT_REQUIRED_CLAIM_FAILED,
    ),
    (
        &TRANSACTION_IDENTITY_NOT_BOUND,
        PROOF_VERIFY_EXIT_REQUIRED_CLAIM_FAILED,
    ),
    (
        &TRANSACTION_AUTHORIZATION_NOT_BOUND,
        PROOF_VERIFY_EXIT_REQUIRED_CLAIM_FAILED,
    ),
    (
        &TRANSACTION_RUNTIME_PROOF_REJECTED,
        PROOF_VERIFY_EXIT_REQUIRED_CLAIM_FAILED,
    ),
    (
        &TRANSACTION_SETTLEMENT_UNVERIFIED,
        PROOF_VERIFY_EXIT_REQUIRED_CLAIM_FAILED,
    ),
    (
        &TRANSACTION_DISPUTE_UNBOUND,
        PROOF_VERIFY_EXIT_REQUIRED_CLAIM_FAILED,
    ),
    (
        &TRANSACTION_TRANSPARENCY_PREVIEW_NOT_ALLOWED,
        PROOF_VERIFY_EXIT_REQUIRED_CLAIM_FAILED,
    ),
    (
        &TRANSACTION_BUYER_REVIEW_REJECTED,
        PROOF_VERIFY_EXIT_REQUIRED_CLAIM_FAILED,
    ),
    (
        &TRANSACTION_RECEIPT_UNCHECKPOINTED,
        PROOF_VERIFY_EXIT_REQUIRED_CLAIM_FAILED,
    ),
    (
        &TRANSACTION_PASSPORT_HASH_MISMATCH,
        PROOF_VERIFY_EXIT_INTEGRITY_FAILURE,
    ),
    (
        &TRANSACTION_ARTIFACT_HASH_MISMATCH,
        PROOF_VERIFY_EXIT_INTEGRITY_FAILURE,
    ),
    (
        &TRANSACTION_GRAPH_NOT_CLOSED,
        PROOF_VERIFY_EXIT_INTEGRITY_FAILURE,
    ),
    (&TRANSACTION_GRAPH_CYCLE, PROOF_VERIFY_EXIT_INTEGRITY_FAILURE),
    (
        &TRANSACTION_SIGNATURE_INVALID,
        PROOF_VERIFY_EXIT_INTEGRITY_FAILURE,
    ),
    (
        &TRANSACTION_PASSPORT_SCHEMA_UNSUPPORTED,
        PROOF_VERIFY_EXIT_PARSE_OR_SCHEMA_FAILURE,
    ),
    (
        &TRANSACTION_ARTIFACT_SCHEMA_INVALID,
        PROOF_VERIFY_EXIT_PARSE_OR_SCHEMA_FAILURE,
    ),
    (
        &TRANSACTION_NEGATIVE_CASE_MISMATCH,
        PROOF_VERIFY_EXIT_NEGATIVE_DID_NOT_FAIL,
    ),
    (
        &TRANSACTION_VERIFIER_FEATURE_UNSUPPORTED,
        PROOF_VERIFY_EXIT_UNSUPPORTED_FEATURE,
    ),
    (
        &TRANSACTION_VERIFIER_CONTEXT_INVALID,
        PROOF_VERIFY_EXIT_UNSUPPORTED_FEATURE,
    ),
];

/// The exit class is a function of the registry code alone; the message is
/// never read.
pub(super) fn proof_verify_exit_code(error: &CliError) -> i32 {
    proof_verify_registry_exit_code(error.report().code.as_str()).unwrap_or(PROOF_VERIFY_EXIT_GENERIC)
}

fn proof_verify_registry_exit_code(code: &str) -> Option<i32> {
    if let Some((_, exit_code)) = PROOF_VERIFY_EXIT_BY_CODE
        .iter()
        .find(|(spec, _)| code == spec.urn || code == spec.string_code)
    {
        return Some(*exit_code);
    }
    if code == "CHIO-CLI-JSON" || code.starts_with("urn:chio:error:attest:signed-json-") {
        return Some(PROOF_VERIFY_EXIT_PARSE_OR_SCHEMA_FAILURE);
    }
    None
}

pub(super) fn map_proof_error(
    error: chio_control_plane::transaction_passport::TransactionPassportError,
) -> CliError {
    use chio_control_plane::transaction_passport::TransactionPassportError as Error;

    let spec: &'static ErrorCodeSpec = match &error {
        Error::Input(_) => {
            return CliError::with_public_source(
                &TRANSACTION_PASSPORT_SCHEMA_UNSUPPORTED,
                "proof-room.schema-violation: artifact",
                error,
            );
        }
        Error::UnsupportedSchema(_) => &TRANSACTION_PASSPORT_SCHEMA_UNSUPPORTED,
        Error::EvidenceLimit
        | Error::InvalidPassportField { .. }
        | Error::InvalidPassportTimestamp { .. }
        | Error::InvalidPassportValidityWindow(_)
        | Error::InvalidEvidenceGraphDigest(_)
        | Error::InvalidClaimSetDigest(_)
        | Error::InvalidVerifierPolicyDigest(_)
        | Error::UnsafeEvidenceGraphPath(_)
        | Error::UnsafeClaimSetPath(_)
        | Error::UnsafeVerifierPolicyPath(_)
        | Error::UnsupportedEvidenceGraphSchema(_)
        | Error::InvalidVerifierPolicyArtifact(_)
        | Error::UnsupportedVerifierPolicySchema(_) => &TRANSACTION_ARTIFACT_SCHEMA_INVALID,
        Error::PassportNotYetValid { .. } | Error::PassportExpired { .. } => {
            &TRANSACTION_CLAIM_REJECTED
        }
        Error::MissingTrustedTransactionRootKeys => &TRANSACTION_VERIFIER_FEATURE_UNSUPPORTED,
        Error::UntrustedTransactionPassportSigner | Error::InvalidPassportSignature(_) => {
            &TRANSACTION_SIGNATURE_INVALID
        }
        Error::EvidenceGraphDigestMismatch { .. } | Error::VerifierPolicyDigestMismatch { .. } => {
            &TRANSACTION_PASSPORT_HASH_MISMATCH
        }
        Error::EvidenceGraphArtifactDigestMismatch { .. }
        | Error::EvidenceGraphBindingDigestMismatch(_)
        | Error::RuntimeArtifactDigestMismatch { .. }
        | Error::RuntimeSecurityDigestMismatch(_) => &TRANSACTION_ARTIFACT_HASH_MISMATCH,
        Error::EvidenceGraphBindingSignatureInvalid(_)
        | Error::RuntimeSecuritySignatureInvalid(_)
        | Error::EnterpriseExportSignatureInvalid(_)
        | Error::AgentWebSignatureInvalid(_)
        | Error::TrustMarketArtifactSignatureInvalid { .. }
        | Error::RiskComptrollerSignatureInvalid(_)
        | Error::CognitionMarketSignatureInvalid(_)
        | Error::CognitionMarketArtifactSignatureInvalid { .. } => &TRANSACTION_SIGNATURE_INVALID,
        Error::MissingEvidenceGraphArtifact(_) => &TRANSACTION_GRAPH_NOT_CLOSED,
        Error::InvalidEvidenceGraphArtifact(message) => evidence_graph_artifact_spec(message),
        Error::MissingExecutionLease
        | Error::MissingRuntimeArtifact(_)
        | Error::InvalidRuntimeArtifact { .. }
        | Error::RuntimeSecurityClaimFailed(_)
        | Error::AdvisoryEvidenceCannotAuthorize => &TRANSACTION_RUNTIME_PROOF_REJECTED,
        Error::MissingEnterpriseArtifact(_)
        | Error::MissingAgentWebArtifact(_)
        | Error::MissingTrustMarketArtifact(_)
        | Error::MissingCognitionMarketArtifact(_) => &TRANSACTION_CLAIM_REJECTED,
        Error::InvalidEnterpriseArtifact { .. }
        | Error::InvalidAgentWebArtifact { .. }
        | Error::InvalidTrustMarketArtifact { .. }
        | Error::InvalidCognitionMarketArtifact { .. } => &TRANSACTION_ARTIFACT_SCHEMA_INVALID,
        Error::EnterpriseExportClaimFailed(_)
        | Error::AgentWebClaimFailed(_)
        | Error::TrustMarketClaimFailed(_)
        | Error::RiskComptrollerClaimFailed(_)
        | Error::CognitionMarketClaimFailed(_) => &TRANSACTION_CLAIM_REJECTED,
        Error::EnterpriseExportDigestMismatch(_) | Error::AgentWebDigestMismatch(_) => {
            &TRANSACTION_ARTIFACT_HASH_MISMATCH
        }
        Error::EnterpriseExportMalformed(_) => &TRANSACTION_ARTIFACT_SCHEMA_INVALID,
        Error::EnterpriseExportUnsupported(_)
        | Error::AgentWebUnsupported(_)
        | Error::TrustMarketUnsupported(_) => &TRANSACTION_VERIFIER_FEATURE_UNSUPPORTED,
    };
    CliError::registry_error(spec, format!("proof verify: {error}"))
}

pub(super) fn map_commerce_proof_error(error: chio_commerce_order::CommerceOrderError) -> CliError {
    use chio_commerce_order::CommerceOrderError as Error;

    let spec: &'static ErrorCodeSpec = match &error {
        Error::Input(_) | Error::EvidenceLimit | Error::UnsupportedSchema { .. } => {
            &TRANSACTION_ARTIFACT_SCHEMA_INVALID
        }
        Error::InvalidArtifact { .. } => &TRANSACTION_ARTIFACT_SCHEMA_INVALID,
        Error::DigestMismatch { .. }
        | Error::ReplayDigestMismatch(_)
        | Error::PaymentDigestMismatch(_)
        | Error::MandateDigestMismatch(_)
        | Error::SettlementDigestMismatch(_) => &TRANSACTION_ARTIFACT_HASH_MISMATCH,
        Error::ReplaySignatureInvalid(_)
        | Error::PaymentSignatureInvalid(_)
        | Error::ProviderTrustSignatureInvalid(_)
        | Error::SettlementSignatureInvalid(_) => &TRANSACTION_SIGNATURE_INVALID,
        Error::ReplayFailed(message) | Error::SettlementFailed(message)
            if is_settlement_unverified_error(message) =>
        {
            &TRANSACTION_SETTLEMENT_UNVERIFIED
        }
        Error::ReplayFailed(_)
        | Error::PaymentFailed(_)
        | Error::MandateFailed(_)
        | Error::ProviderTrustFailed(_)
        | Error::SettlementFailed(_)
        | Error::CoverageFailed(_) => &TRANSACTION_CLAIM_REJECTED,
        Error::Escrow(escrow) => commerce_escrow_error_spec(escrow),
    };
    CliError::registry_error(spec, format!("proof verify: {error}"))
}

fn commerce_escrow_error_spec(
    error: &chio_commerce_order::CommerceEscrowError,
) -> &'static ErrorCodeSpec {
    use chio_commerce_order::CommerceEscrowError as Error;

    match error {
        Error::LedgerSchemaUnsupported(_)
        | Error::ReservationSchemaUnsupported(_)
        | Error::Canonicalization(_) => &TRANSACTION_ARTIFACT_SCHEMA_INVALID,
        Error::AcceptanceDigestMismatch => &TRANSACTION_ARTIFACT_HASH_MISMATCH,
        Error::OfferSignatureInvalid
        | Error::ReservationSignatureInvalid
        | Error::SettlementSignatureInvalid
        | Error::ExecutionSignatureInvalid => &TRANSACTION_SIGNATURE_INVALID,
        Error::AcceptStateNotAllowed(_)
        | Error::OfferOutsideValidityWindow
        | Error::OfferSelfIssued
        | Error::AcceptorNotSubject
        | Error::OfferLiabilityInvalid(_)
        | Error::LiabilityCurrencyMismatch
        | Error::LiabilityQuoteMismatch
        | Error::NoTrustedReservationAuthority
        | Error::ReservationSignerUntrusted
        | Error::ReservationIdEmpty
        | Error::ReservationUnbound(_)
        | Error::ReservationCurrencyMismatch
        | Error::ReservationUnderCollateralized
        | Error::DispatchFieldEmpty(_)
        | Error::DispatchStatusNotDispatched(_)
        | Error::DispatchIssuedAtInvalid
        | Error::SettlementSigningFailed(_)
        | Error::LedgerZeroAmount
        | Error::LedgerCustodyAccount(_)
        | Error::LedgerAccountsNotDistinct
        | Error::LedgerLegsNotCanonical
        | Error::LedgerNotLocked
        | Error::LedgerOrderBinding(_)
        | Error::LedgerMissing
        | Error::LedgerUnpinned
        | Error::LedgerPinnedBeforeAccept(_)
        | Error::LedgerStatusMismatch { .. }
        | Error::AcceptedContextUnbound
        | Error::NoTrustedSettlementAuthority
        | Error::SettlementSignerUntrusted
        | Error::SettlementPacketUnbound(_)
        | Error::ReleaseContextMismatch(_)
        | Error::ReleaseStateNotAllowed(_)
        | Error::NoTrustedExecutionAuthority
        | Error::ExecutionSignerUntrusted
        | Error::ExecutionInvalid(_)
        | Error::ExecutionActionNotRelease
        | Error::ExecutionNotMatched
        | Error::ExecutionUnbound(_)
        | Error::ExecutionAfterRelease(_) => &TRANSACTION_CLAIM_REJECTED,
    }
}

pub(super) fn map_public_settlement_proof_error(
    error: chio_web3::error::Web3ContractError,
) -> CliError {
    use chio_web3::error::Web3ContractError as Error;

    let spec: &'static ErrorCodeSpec = match &error {
        Error::UnsupportedSchema(_) | Error::MissingField(_) | Error::DuplicateValue(_) => {
            &TRANSACTION_ARTIFACT_SCHEMA_INVALID
        }
        Error::UnknownReference(_) => &TRANSACTION_GRAPH_NOT_CLOSED,
        Error::InvalidProof(message) if is_public_settlement_identity_not_bound_error(message) => {
            &TRANSACTION_IDENTITY_NOT_BOUND
        }
        Error::InvalidProof(message) if is_public_settlement_dispute_unbound_error(message) => {
            &TRANSACTION_DISPUTE_UNBOUND
        }
        Error::InvalidProof(message)
            if is_public_settlement_independent_head_missing_error(message) =>
        {
            &TRANSACTION_VERIFIER_FEATURE_UNSUPPORTED
        }
        Error::InvalidSettlement(message) if is_settlement_unverified_error(message) => {
            &TRANSACTION_SETTLEMENT_UNVERIFIED
        }
        Error::ProofDigestMismatch(_) | Error::SettlementDigestMismatch(_) => {
            &TRANSACTION_ARTIFACT_HASH_MISMATCH
        }
        Error::BindingSignatureInvalid(_)
        | Error::ProofSignatureInvalid(_)
        | Error::SettlementSignatureInvalid(_) => &TRANSACTION_SIGNATURE_INVALID,
        Error::InvalidBinding(_)
        | Error::InvalidProof(_)
        | Error::InvalidSettlement(_)
        | Error::InvalidQualificationCase(_) => &TRANSACTION_CLAIM_REJECTED,
    };
    CliError::registry_error(spec, format!("proof verify: {error}"))
}

pub(super) fn map_swarm_proof_error(
    error: chio_swarm_authority::SwarmAuthorityError,
) -> CliError {
    use chio_swarm_authority::SwarmAuthorityError as Error;

    let spec: &'static ErrorCodeSpec = match &error {
        Error::Rejected(_) => &TRANSACTION_CLAIM_REJECTED,
        Error::DigestMismatch(_) => &TRANSACTION_ARTIFACT_HASH_MISMATCH,
        Error::SignatureInvalid(_) => &TRANSACTION_SIGNATURE_INVALID,
        Error::UnsupportedSchema(_) | Error::Canonical(_) => &TRANSACTION_ARTIFACT_SCHEMA_INVALID,
        Error::Unsupported(_) => &TRANSACTION_VERIFIER_FEATURE_UNSUPPORTED,
    };
    CliError::registry_error(spec, format!("proof verify: {error}"))
}

pub(super) fn map_disclosure_lineage_proof_error(
    error: chio_selective_disclosure::DisclosureLineageError,
) -> CliError {
    use chio_selective_disclosure::DisclosureLineageError as Error;

    let spec: &'static ErrorCodeSpec = match &error {
        Error::InvalidArtifact(_) => &TRANSACTION_CLAIM_REJECTED,
        Error::DigestMismatch(_) => &TRANSACTION_ARTIFACT_HASH_MISMATCH,
        Error::SignatureInvalid(_) => &TRANSACTION_SIGNATURE_INVALID,
        Error::UnsupportedSchema(_) => &TRANSACTION_ARTIFACT_SCHEMA_INVALID,
        Error::Unsupported(_) => &TRANSACTION_VERIFIER_FEATURE_UNSUPPORTED,
    };
    CliError::registry_error(spec, format!("proof verify: {error}"))
}

/// A selective disclosure rejection keeps the caller's message; its code
/// comes from the variant alone.
pub(super) fn map_selective_disclosure_proof_error(
    error: &chio_selective_disclosure::SelectiveDisclosureError,
    message: String,
) -> CliError {
    CliError::registry_error(selective_disclosure_spec(error), message)
}

/// A crypto context rejection keeps the caller's message; its code comes
/// from the variant alone.
pub(super) fn map_crypto_context_proof_error(
    error: &chio_selective_disclosure::DisclosureCryptoContextError,
    message: String,
) -> CliError {
    use chio_selective_disclosure::DisclosureCryptoContextError as Error;

    let spec = match error {
        Error::SelectiveDisclosure(inner) => selective_disclosure_spec(inner),
        Error::InvalidContext(_) => &TRANSACTION_CLAIM_REJECTED,
    };
    CliError::registry_error(spec, message)
}

fn selective_disclosure_spec(
    error: &chio_selective_disclosure::SelectiveDisclosureError,
) -> &'static ErrorCodeSpec {
    use chio_selective_disclosure::SelectiveDisclosureError as Error;

    match error {
        Error::SignatureVerificationFailed | Error::ReceiptSignatureInvalid => {
            &TRANSACTION_SIGNATURE_INVALID
        }
        Error::ContentHashMismatch(_) | Error::TransparencyInclusionHashMismatch(_) => {
            &TRANSACTION_ARTIFACT_HASH_MISMATCH
        }
        Error::CanonicalJson(_)
        | Error::MalformedHexField { .. }
        | Error::DisclosureDuplicateIndex(_)
        | Error::DisclosureIndexOutOfRange(_)
        | Error::SchemaMismatch(_)
        | Error::Hex(_) => &TRANSACTION_ARTIFACT_SCHEMA_INVALID,
        Error::ProjectionVersionMismatch(_) => &TRANSACTION_VERIFIER_FEATURE_UNSUPPORTED,
        Error::SignedProjectionMismatch
        | Error::ProofVerificationFailed
        | Error::ReceiptBbsSignatureMissing
        | Error::ReceiptBbsBindingInvalid(_)
        | Error::ProjectionManifestInvalid(_)
        | Error::TransparencyInclusionInvalid(_)
        | Error::UnknownIssuer(_)
        | Error::IssuerKeyMismatch
        | Error::KeySeedTooShort
        | Error::Crypto(_) => &TRANSACTION_CLAIM_REJECTED,
    }
}

/// A runtime proof rejection is classed by its owner-defined rejection code.
pub(super) fn map_runtime_proof_error(error: chio_runtime_core::ChioRuntimeError) -> CliError {
    use chio_runtime_core::ChioRuntimeError as Error;

    let spec: &'static ErrorCodeSpec = match &error {
        Error::Rejected { code, .. } if is_runtime_hash_mismatch_code(code) => {
            &TRANSACTION_ARTIFACT_HASH_MISMATCH
        }
        Error::UntrustedInput(_) | Error::Json(_) | Error::Canonical(_) => {
            &TRANSACTION_ARTIFACT_SCHEMA_INVALID
        }
        Error::Clock(_)
        | Error::Rejected { .. }
        | Error::DuplicateAdmissionBundle
        | Error::Store(_)
        | Error::Io(_)
        | Error::Sqlite(_) => &TRANSACTION_RUNTIME_PROOF_REJECTED,
    };
    CliError::registry_error(spec, format!("proof verify: {error}"))
}

fn is_runtime_hash_mismatch_code(code: &str) -> bool {
    code.ends_with("_hash_mismatch") || code.ends_with("_digest_mismatch")
}

pub(super) fn required_claim_missing(message: impl Into<String>) -> CliError {
    CliError::registry_error(&TRANSACTION_REQUIRED_CLAIM_MISSING, message)
}

pub(super) fn claim_rejected(message: impl Into<String>) -> CliError {
    CliError::registry_error(&TRANSACTION_CLAIM_REJECTED, message)
}

pub(super) fn runtime_proof_rejected(message: impl Into<String>) -> CliError {
    CliError::registry_error(&TRANSACTION_RUNTIME_PROOF_REJECTED, message)
}

pub(super) fn artifact_digest_mismatch(message: impl Into<String>) -> CliError {
    CliError::registry_error(&TRANSACTION_ARTIFACT_HASH_MISMATCH, message)
}

pub(super) fn artifact_schema_invalid(message: impl Into<String>) -> CliError {
    CliError::registry_error(&TRANSACTION_ARTIFACT_SCHEMA_INVALID, message)
}

pub(super) fn graph_not_closed(message: impl Into<String>) -> CliError {
    CliError::registry_error(&TRANSACTION_GRAPH_NOT_CLOSED, message)
}

pub(super) fn verifier_feature_unsupported(message: impl Into<String>) -> CliError {
    CliError::registry_error(&TRANSACTION_VERIFIER_FEATURE_UNSUPPORTED, message)
}

pub(super) fn verifier_context_invalid(message: impl Into<String>) -> CliError {
    CliError::registry_error(&TRANSACTION_VERIFIER_CONTEXT_INVALID, message)
}

pub(super) fn authorization_not_bound(message: impl Into<String>) -> CliError {
    CliError::registry_error(&TRANSACTION_AUTHORIZATION_NOT_BOUND, message)
}

fn evidence_graph_artifact_spec(message: &str) -> &'static ErrorCodeSpec {
    if is_required_claim_missing_error(message) {
        &TRANSACTION_REQUIRED_CLAIM_MISSING
    } else if is_graph_cycle_error(message) {
        &TRANSACTION_GRAPH_CYCLE
    } else if is_graph_not_closed_error(message) {
        &TRANSACTION_GRAPH_NOT_CLOSED
    } else if is_authorization_not_bound_error(message) {
        &TRANSACTION_AUTHORIZATION_NOT_BOUND
    } else {
        &TRANSACTION_CLAIM_REJECTED
    }
}

fn is_public_settlement_identity_not_bound_error(message: &str) -> bool {
    message.starts_with("public settlement beneficiary identity binding ")
}

fn is_public_settlement_dispute_unbound_error(message: &str) -> bool {
    message.starts_with("public settlement dispute ")
}

fn is_public_settlement_independent_head_missing_error(message: &str) -> bool {
    message == "public settlement independent head missing"
}

fn is_settlement_unverified_error(message: &str) -> bool {
    message.starts_with("settlement event missing settlement packet evidence")
        || message == "public settlement finality requires successful settlement state"
}

pub(super) fn is_transparency_preview_not_allowed_code(code: &str) -> bool {
    code == "disclosure_context_transparency_state_insufficient"
}

fn is_authorization_not_bound_error(message: &str) -> bool {
    matches!(
        message.strip_prefix("minimal governed action evidence invalid: "),
        Some(
            "capability proof not valid at evidence graph issuance"
                | "capability proof expired before evidence graph issuance"
                | "capability proof does not match receipt capability"
                | "guard decision does not match capability proof"
                | "guard-to-receipt binding missing"
        )
    )
}

fn is_graph_not_closed_error(message: &str) -> bool {
    message.starts_with("unknown evidence graph edge source: ")
        || message.starts_with("unknown evidence graph edge target: ")
}

fn is_graph_cycle_error(message: &str) -> bool {
    message.starts_with("cyclic evidence graph: ")
}

fn is_required_claim_missing_error(message: &str) -> bool {
    message.starts_with("claim set missing required claim: ")
        || message.starts_with("claim set required claim was not verified: ")
}

#[cfg(test)]
#[path = "transaction_error_classes.rs"]
mod exit_classes;

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::ctx::TestUnwrapErr;
    use std::error::Error;

    #[test]
    fn schema_input_keeps_its_private_cause_and_stable_failure_code() {
        use chio_control_plane::transaction_passport::TransactionPassportError;
        let marker = "private-unsupported-role";
        let source = serde_json::from_str::<u64>(&format!("\"{marker}\""))
            .test_unwrap_err("string payload rejects an integer schema");
        let error = map_proof_error(TransactionPassportError::Input(
            chio_core::canonical::UntrustedJsonError::Decode(source).into(),
        ));
        assert_eq!(
            error.report().code,
            TRANSACTION_PASSPORT_SCHEMA_UNSUPPORTED.urn
        );
        assert_eq!(proof_verify_exit_code(&error), 30);
        assert!(!format!("{error:?} {error} {:?}", error.report()).contains(marker));
        let mut cause = error.source();
        let mut retained_owner = false;
        let mut retained_detail = false;
        while let Some(source) = cause {
            retained_owner |= source.downcast_ref::<TransactionPassportError>().is_some();
            retained_detail |= source.to_string().contains(marker);
            cause = source.source();
        }
        assert!(retained_owner);
        assert!(retained_detail);
    }

    #[test]
    fn every_transaction_registry_code_has_a_typed_exit() {
        for spec in chio_errors::_generated::error_codes::ERROR_CODES
            .iter()
            .filter(|spec| spec.domain == chio_errors::Domain::Transaction)
        {
            assert!(
                matches!(
                    proof_verify_registry_exit_code(spec.urn),
                    Some(10 | 20 | 30 | 40 | 50)
                ),
                "{} has no typed proof verify exit",
                spec.urn
            );
        }
    }

    fn assert_typed(error: CliError, spec: &ErrorCodeSpec, exit_code: i32) {
        assert_eq!(error.report().code, spec.urn, "{error}");
        assert_eq!(proof_verify_exit_code(&error), exit_code, "{error}");
    }

    #[test]
    fn family_error_variants_select_typed_codes() {
        use chio_control_plane::transaction_passport::TransactionPassportError;
        assert_typed(
            map_proof_error(TransactionPassportError::AgentWebClaimFailed(
                "missing external signature".to_string(),
            )),
            &TRANSACTION_CLAIM_REJECTED,
            10,
        );
        assert_typed(
            map_proof_error(TransactionPassportError::EnterpriseExportDigestMismatch(
                "export bundle digest mismatch".to_string(),
            )),
            &TRANSACTION_ARTIFACT_HASH_MISMATCH,
            20,
        );
        assert_typed(
            map_proof_error(TransactionPassportError::TrustMarketUnsupported(
                "guarantee type unsupported".to_string(),
            )),
            &TRANSACTION_VERIFIER_FEATURE_UNSUPPORTED,
            50,
        );
        assert_typed(
            map_commerce_proof_error(chio_commerce_order::CommerceOrderError::PaymentFailed(
                "payment merchant mismatch".to_string(),
            )),
            &TRANSACTION_CLAIM_REJECTED,
            10,
        );
        assert_typed(
            map_commerce_proof_error(
                chio_commerce_order::CommerceOrderError::ReplayDigestMismatch(
                    "commerce event digest mismatch: event-1".to_string(),
                ),
            ),
            &TRANSACTION_ARTIFACT_HASH_MISMATCH,
            20,
        );
        assert_typed(
            map_public_settlement_proof_error(chio_web3::error::Web3ContractError::MissingField(
                "public_settlement.commerce_order_id",
            )),
            &TRANSACTION_ARTIFACT_SCHEMA_INVALID,
            30,
        );
        assert_typed(
            map_public_settlement_proof_error(chio_web3::error::Web3ContractError::InvalidProof(
                "public settlement independent head missing".to_string(),
            )),
            &TRANSACTION_VERIFIER_FEATURE_UNSUPPORTED,
            50,
        );
        assert_typed(
            map_public_settlement_proof_error(
                chio_web3::error::Web3ContractError::SettlementDigestMismatch(
                    "public settlement independent head block hash mismatch".to_string(),
                ),
            ),
            &TRANSACTION_ARTIFACT_HASH_MISMATCH,
            20,
        );
        assert_typed(
            map_swarm_proof_error(chio_swarm_authority::SwarmAuthorityError::Unsupported(
                "unsupported swarm route-plan egress constraint: allow-private-network".to_string(),
            )),
            &TRANSACTION_VERIFIER_FEATURE_UNSUPPORTED,
            50,
        );
        assert_typed(
            map_disclosure_lineage_proof_error(
                chio_selective_disclosure::DisclosureLineageError::DigestMismatch(
                    "lineage frontier digest mismatch".to_string(),
                ),
            ),
            &TRANSACTION_ARTIFACT_HASH_MISMATCH,
            20,
        );
        assert_typed(
            claim_rejected("proof verify: disclosure crypto report projection manifest ref mismatch"),
            &TRANSACTION_CLAIM_REJECTED,
            10,
        );
    }

    #[test]
    fn split_family_sites_pin_their_exit() {
        use chio_control_plane::transaction_passport::TransactionPassportError as Passport;
        use chio_selective_disclosure::DisclosureLineageError as Lineage;
        let passport_cases = [
            (Passport::EnterpriseExportUnsupported("approval signature unsupported".into()), 50),
            (
                Passport::EnterpriseExportUnsupported(
                    "data governance retention class unsupported".into(),
                ),
                50,
            ),
            (Passport::EnterpriseExportMalformed("export bundle digest mismatch".into()), 30),
            (
                Passport::EnterpriseExportMalformed(
                    "approval case export bundle digest mismatch".into(),
                ),
                30,
            ),
            (
                Passport::AgentWebUnsupported("GraphQL subscription projection unsupported".into()),
                50,
            ),
            (Passport::AgentWebUnsupported("unsupported Agent Web digest algorithm".into()), 50),
            (
                Passport::AgentWebUnsupported("unsupported Agent Web signature algorithm".into()),
                50,
            ),
            (
                Passport::AgentWebDigestMismatch(
                    "Agent Web receipt action content digest mismatch".into(),
                ),
                20,
            ),
            (
                Passport::AgentWebDigestMismatch(
                    "Agent Web receipt action projection manifest digest mismatch".into(),
                ),
                20,
            ),
            (
                Passport::EvidenceGraphBindingDigestMismatch(
                    "minimal governed action evidence invalid: receipt policy digest mismatch"
                        .into(),
                ),
                20,
            ),
        ];
        for (error, exit_code) in passport_cases {
            let error = map_proof_error(error);
            assert_eq!(proof_verify_exit_code(&error), exit_code, "{error}");
        }
        let lineage_cases = [
            (Lineage::Unsupported("lineage subgraph signature unsupported".into()), 50),
            (
                Lineage::UnsupportedSchema("unsupported crypto context report schema".into()),
                30,
            ),
        ];
        for (error, exit_code) in lineage_cases {
            let error = map_disclosure_lineage_proof_error(error);
            assert_eq!(proof_verify_exit_code(&error), exit_code, "{error}");
        }
    }

    #[test]
    fn transparency_preview_matches_only_the_exact_check_code() {
        assert!(is_transparency_preview_not_allowed_code(
            "disclosure_context_transparency_state_insufficient"
        ));
        assert!(!is_transparency_preview_not_allowed_code(
            "x_disclosure_context_transparency_state_insufficient"
        ));
        assert!(!is_transparency_preview_not_allowed_code(
            "disclosure_context_nonce_replayed, disclosure_context_transparency_state_insufficient"
        ));
    }

    #[test]
    fn attacker_text_in_a_message_never_selects_the_code() {
        use chio_control_plane::transaction_passport::TransactionPassportError;
        assert_typed(
            map_proof_error(TransactionPassportError::AgentWebClaimFailed(
                "VC receipt ref is not bound: receipt-digest mismatch".to_string(),
            )),
            &TRANSACTION_CLAIM_REJECTED,
            10,
        );
        assert_typed(
            map_proof_error(TransactionPassportError::TrustMarketClaimFailed(
                "selected provider absent from discovery snapshot: provider unsupported"
                    .to_string(),
            )),
            &TRANSACTION_CLAIM_REJECTED,
            10,
        );
        assert_typed(
            map_swarm_proof_error(chio_swarm_authority::SwarmAuthorityError::Rejected(
                "swarm task is revoked: unsupported task hash mismatch".to_string(),
            )),
            &TRANSACTION_CLAIM_REJECTED,
            10,
        );
        assert_typed(
            map_disclosure_lineage_proof_error(
                chio_selective_disclosure::DisclosureLineageError::InvalidArtifact(
                    "unknown lineage root receipt: root-digest mismatch".to_string(),
                ),
            ),
            &TRANSACTION_CLAIM_REJECTED,
            10,
        );
        assert_typed(
            map_commerce_proof_error(chio_commerce_order::CommerceOrderError::MandateFailed(
                "mandate expired: mandate-digest mismatch unsupported".to_string(),
            )),
            &TRANSACTION_CLAIM_REJECTED,
            10,
        );
    }

    #[test]
    fn attacker_text_in_a_message_never_selects_exit_40() {
        let steered = claim_rejected(
            "proof verify: swarm task is revoked: proof-room.negative-case.unexpected-success \
             negative fixture release truth verified unexpectedly",
        );
        assert_typed(steered, &TRANSACTION_CLAIM_REJECTED, 10);
        let steered = runtime_proof_rejected(
            "proof-room.negative-case.failure-mismatch release truth verified unexpectedly",
        );
        assert_typed(steered, &TRANSACTION_RUNTIME_PROOF_REJECTED, 10);
        assert_typed(
            CliError::registry_error(
                &TRANSACTION_NEGATIVE_CASE_MISMATCH,
                "proof-room.negative-case.unexpected-success",
            ),
            &TRANSACTION_NEGATIVE_CASE_MISMATCH,
            40,
        );
    }
}

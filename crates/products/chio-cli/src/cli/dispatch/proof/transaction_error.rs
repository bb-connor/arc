use super::*;
use chio_errors::_generated::error_codes::{
    TRANSACTION_ARTIFACT_HASH_MISMATCH, TRANSACTION_ARTIFACT_SCHEMA_INVALID,
    TRANSACTION_AUTHORIZATION_NOT_BOUND, TRANSACTION_BUYER_REVIEW_REJECTED,
    TRANSACTION_CLAIM_REJECTED, TRANSACTION_DISPUTE_UNBOUND, TRANSACTION_GRAPH_CYCLE,
    TRANSACTION_GRAPH_NOT_CLOSED, TRANSACTION_IDENTITY_NOT_BOUND,
    TRANSACTION_PASSPORT_HASH_MISMATCH, TRANSACTION_PASSPORT_SCHEMA_UNSUPPORTED,
    TRANSACTION_SIGNATURE_INVALID, TRANSACTION_RECEIPT_UNCHECKPOINTED,
    TRANSACTION_REQUIRED_CLAIM_MISSING, TRANSACTION_RUNTIME_PROOF_REJECTED,
    TRANSACTION_SETTLEMENT_UNVERIFIED,
    TRANSACTION_TRANSPARENCY_PREVIEW_NOT_ALLOWED, TRANSACTION_VERIFIER_FEATURE_UNSUPPORTED,
};
use chio_errors::ErrorCodeSpec;

const PROOF_VERIFY_EXIT_GENERIC: i32 = 1;
const PROOF_VERIFY_EXIT_REQUIRED_CLAIM_FAILED: i32 = 10;
const PROOF_VERIFY_EXIT_INTEGRITY_FAILURE: i32 = 20;
const PROOF_VERIFY_EXIT_PARSE_OR_SCHEMA_FAILURE: i32 = 30;
const PROOF_VERIFY_EXIT_NEGATIVE_DID_NOT_FAIL: i32 = 40;
const PROOF_VERIFY_EXIT_UNSUPPORTED_FEATURE: i32 = 50;
const PROOF_VERIFY_EXIT_RELEASE_TRUTH_FAILURE: i32 = 60;

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
        &TRANSACTION_VERIFIER_FEATURE_UNSUPPORTED,
        PROOF_VERIFY_EXIT_UNSUPPORTED_FEATURE,
    ),
];

pub(super) fn proof_verify_exit_code(error: &CliError) -> i32 {
    let report = error.report();
    let message = report.message.as_str();
    if proof_verify_negative_did_not_fail(message) {
        return PROOF_VERIFY_EXIT_NEGATIVE_DID_NOT_FAIL;
    }
    if proof_verify_release_truth_failed(message) {
        return PROOF_VERIFY_EXIT_RELEASE_TRUTH_FAILURE;
    }
    if let Some(exit_code) = proof_verify_registry_exit_code(report.code.as_str()) {
        return exit_code;
    }
    if proof_verify_required_claim_failed(message) {
        return PROOF_VERIFY_EXIT_REQUIRED_CLAIM_FAILED;
    }
    if proof_verify_integrity_failed(message) {
        return PROOF_VERIFY_EXIT_INTEGRITY_FAILURE;
    }
    if proof_verify_parse_or_schema_failed(message) {
        return PROOF_VERIFY_EXIT_PARSE_OR_SCHEMA_FAILURE;
    }
    if proof_verify_unsupported_feature(message) {
        return PROOF_VERIFY_EXIT_UNSUPPORTED_FEATURE;
    }
    PROOF_VERIFY_EXIT_GENERIC
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

fn proof_verify_required_claim_failed(message: &str) -> bool {
    message.contains("required proof claim not verified")
        || message.contains("required proof claim family missing")
        || message.contains("required proof runtime authority missing")
        || message.contains("required delegation claim not verified")
        || message.contains("required commerce claim not verified")
        || message.contains("required disclosure lineage claim not verified")
        || message.contains("required swarm claim not verified")
        || message.contains("required public settlement claim not verified")
}

fn proof_verify_integrity_failed(message: &str) -> bool {
    is_digest_mismatch_error(message)
        || message.contains("proof-room.signature.")
        || message.contains("signature invalid")
        || message.contains("signature verification failed")
        || message.contains("manifest integrity")
}

fn proof_verify_parse_or_schema_failed(message: &str) -> bool {
    message.contains("unsupported transaction passport schema")
        || message.contains("unsupported verifier policy schema")
        || message.contains("unsupported evidence graph schema")
        || message.contains("unsupported required proof claim")
        || message.contains("proof-room.schema-violation")
        || message.contains("json error")
        || message.contains("missing field")
}

fn proof_verify_negative_did_not_fail(message: &str) -> bool {
    message.contains("proof-room.negative-case.unexpected-success")
        || message.contains("proof-room.negative-case.failure-mismatch")
        || (message.contains("negative fixture") && message.contains("verified unexpectedly"))
}

fn proof_verify_release_truth_failed(message: &str) -> bool {
    message.contains("release truth")
        || message.contains("package truth")
        || message.contains("release-truth")
        || message.contains("package-truth")
        || message.contains("chio.proof.release-truth.v1")
}

fn proof_verify_unsupported_feature(message: &str) -> bool {
    message.contains("unsupported proof feature")
        || message.contains("must pin trusted")
        || message.contains("missing disclosure crypto verification context")
        || message.contains("missing disclosure selective disclosure proof")
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
        Error::EvidenceGraphArtifactDigestMismatch { .. } => &TRANSACTION_ARTIFACT_HASH_MISMATCH,
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
        Error::InvalidEnterpriseArtifact { message, .. }
        | Error::InvalidAgentWebArtifact { message, .. }
        | Error::InvalidTrustMarketArtifact { message, .. }
        | Error::InvalidCognitionMarketArtifact { message, .. } => artifact_rejection_spec(message),
        Error::EnterpriseExportClaimFailed(message)
        | Error::AgentWebClaimFailed(message)
        | Error::RiskComptrollerClaimFailed(message)
        | Error::CognitionMarketClaimFailed(message) => claim_rejection_spec(message),
        Error::TrustMarketClaimFailed(message) => unsupported_or_claim_rejection_spec(message),
    };
    CliError::registry_error(spec, format!("proof verify: {error}"))
}

pub(super) fn map_commerce_proof_error(error: chio_commerce_order::CommerceOrderError) -> CliError {
    use chio_commerce_order::CommerceOrderError as Error;

    let spec: &'static ErrorCodeSpec = match &error {
        Error::Input(_) | Error::EvidenceLimit | Error::UnsupportedSchema { .. } => {
            &TRANSACTION_ARTIFACT_SCHEMA_INVALID
        }
        Error::InvalidArtifact { message, .. } => artifact_rejection_spec(message),
        Error::DigestMismatch { .. } => &TRANSACTION_ARTIFACT_HASH_MISMATCH,
        Error::ReplayFailed(message) | Error::SettlementFailed(message)
            if is_settlement_unverified_error(message) =>
        {
            &TRANSACTION_SETTLEMENT_UNVERIFIED
        }
        Error::ReplayFailed(message)
        | Error::PaymentFailed(message)
        | Error::MandateFailed(message)
        | Error::ProviderTrustFailed(message)
        | Error::SettlementFailed(message)
        | Error::CoverageFailed(message) => claim_rejection_spec(message),
    };
    CliError::registry_error(spec, format!("proof verify: {error}"))
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
        Error::InvalidBinding(message)
        | Error::InvalidProof(message)
        | Error::InvalidSettlement(message)
        | Error::InvalidQualificationCase(message) => claim_rejection_spec(message),
    };
    CliError::registry_error(spec, format!("proof verify: {error}"))
}

pub(super) fn map_swarm_proof_error(
    error: chio_swarm_authority::SwarmAuthorityError,
) -> CliError {
    use chio_swarm_authority::SwarmAuthorityError as Error;

    let spec: &'static ErrorCodeSpec = match &error {
        Error::Rejected(message) => unsupported_or_claim_rejection_spec(message),
        Error::Canonical(_) => &TRANSACTION_ARTIFACT_SCHEMA_INVALID,
    };
    CliError::registry_error(spec, format!("proof verify: {error}"))
}

/// A rejection raised while verifying a proof family's claims. The message
/// is preserved verbatim; only its registry code is selected here.
pub(super) fn family_claim_error(message: String) -> CliError {
    CliError::registry_error(claim_rejection_spec(&message), message)
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
        claim_rejection_spec(message)
    }
}

fn claim_rejection_spec(message: &str) -> &'static ErrorCodeSpec {
    if is_digest_mismatch_error(message) {
        &TRANSACTION_ARTIFACT_HASH_MISMATCH
    } else {
        &TRANSACTION_CLAIM_REJECTED
    }
}

fn artifact_rejection_spec(message: &str) -> &'static ErrorCodeSpec {
    if is_digest_mismatch_error(message) {
        &TRANSACTION_ARTIFACT_HASH_MISMATCH
    } else {
        &TRANSACTION_ARTIFACT_SCHEMA_INVALID
    }
}

fn unsupported_or_claim_rejection_spec(message: &str) -> &'static ErrorCodeSpec {
    if is_unsupported_feature_error(message) {
        &TRANSACTION_VERIFIER_FEATURE_UNSUPPORTED
    } else {
        claim_rejection_spec(message)
    }
}

fn is_digest_mismatch_error(message: &str) -> bool {
    message.contains("digest mismatch") || message.contains("hash mismatch")
}

fn is_unsupported_feature_error(message: &str) -> bool {
    message.starts_with("unsupported ") || message.ends_with(" unsupported")
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
    message.contains("settlement event missing settlement packet evidence")
        || message == "public settlement finality requires successful settlement state"
}

pub(super) fn is_transparency_preview_not_allowed_error(message: &str) -> bool {
    message.contains("disclosure_context_transparency_state_insufficient")
        || message.contains("context transparency state was weaker than the profile requirement")
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
                    Some(10 | 20 | 30 | 50)
                ),
                "{} has no typed proof verify exit",
                spec.urn
            );
        }
    }

    #[test]
    fn family_claim_failures_exit_with_typed_codes() {
        use chio_control_plane::transaction_passport::TransactionPassportError;
        let cases = [
            (
                map_proof_error(TransactionPassportError::AgentWebClaimFailed(
                    "missing external signature".to_string(),
                )),
                &TRANSACTION_CLAIM_REJECTED,
                10,
            ),
            (
                map_proof_error(TransactionPassportError::EnterpriseExportClaimFailed(
                    "export bundle digest mismatch".to_string(),
                )),
                &TRANSACTION_ARTIFACT_HASH_MISMATCH,
                20,
            ),
            (
                map_proof_error(TransactionPassportError::RiskComptrollerClaimFailed(
                    "risk exposure exceeds capital".to_string(),
                )),
                &TRANSACTION_CLAIM_REJECTED,
                10,
            ),
            (
                map_proof_error(TransactionPassportError::TrustMarketClaimFailed(
                    "guarantee type unsupported".to_string(),
                )),
                &TRANSACTION_VERIFIER_FEATURE_UNSUPPORTED,
                50,
            ),
            (
                map_commerce_proof_error(chio_commerce_order::CommerceOrderError::PaymentFailed(
                    "payment merchant mismatch".to_string(),
                )),
                &TRANSACTION_CLAIM_REJECTED,
                10,
            ),
            (
                map_public_settlement_proof_error(chio_web3::error::Web3ContractError::MissingField(
                    "public_settlement.commerce_order_id",
                )),
                &TRANSACTION_ARTIFACT_SCHEMA_INVALID,
                30,
            ),
            (
                map_public_settlement_proof_error(chio_web3::error::Web3ContractError::InvalidProof(
                    "public settlement independent head missing".to_string(),
                )),
                &TRANSACTION_VERIFIER_FEATURE_UNSUPPORTED,
                50,
            ),
            (
                map_swarm_proof_error(chio_swarm_authority::SwarmAuthorityError::Rejected(
                    "swarm task is revoked: task-child-a".to_string(),
                )),
                &TRANSACTION_CLAIM_REJECTED,
                10,
            ),
            (
                family_claim_error(
                    "proof verify: disclosure crypto report projection manifest ref mismatch"
                        .to_string(),
                ),
                &TRANSACTION_CLAIM_REJECTED,
                10,
            ),
        ];
        for (error, spec, exit_code) in cases {
            assert_eq!(error.report().code, spec.urn, "{error}");
            assert_eq!(proof_verify_exit_code(&error), exit_code, "{error}");
        }
    }
}

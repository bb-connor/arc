//! Every family error variant has one pinned exit class. Each `expected_*`
//! function matches its enum with no wildcard arm, so a new variant does not
//! compile until it is classified here.

use super::*;

const REQUIRED: i32 = 10;
const INTEGRITY: i32 = 20;
const SCHEMA: i32 = 30;
const UNSUPPORTED: i32 = 50;

fn json_error() -> serde_json::Error {
    serde_json::Error::io(std::io::Error::other("rejected input"))
}

fn text() -> String {
    "detail".to_string()
}

fn assert_classes<E: std::fmt::Display>(
    samples: Vec<E>,
    expected: fn(&E) -> i32,
    map: fn(E) -> CliError,
) {
    for sample in samples {
        let label = sample.to_string();
        let exit_code = expected(&sample);
        let error = map(sample);
        assert_eq!(proof_verify_exit_code(&error), exit_code, "{label}");
    }
}

fn expected_passport(
    error: &chio_control_plane::transaction_passport::TransactionPassportError,
) -> i32 {
    use chio_control_plane::transaction_passport::TransactionPassportError as E;
    match error {
        E::Input(_)
        | E::EvidenceLimit
        | E::UnsupportedSchema(_)
        | E::InvalidPassportField { .. }
        | E::InvalidPassportTimestamp { .. }
        | E::InvalidPassportValidityWindow(_)
        | E::InvalidEvidenceGraphDigest(_)
        | E::InvalidClaimSetDigest(_)
        | E::InvalidVerifierPolicyDigest(_)
        | E::UnsafeEvidenceGraphPath(_)
        | E::UnsafeClaimSetPath(_)
        | E::UnsafeVerifierPolicyPath(_)
        | E::UnsupportedEvidenceGraphSchema(_)
        | E::InvalidVerifierPolicyArtifact(_)
        | E::UnsupportedVerifierPolicySchema(_)
        | E::InvalidEnterpriseArtifact { .. }
        | E::InvalidAgentWebArtifact { .. }
        | E::InvalidTrustMarketArtifact { .. }
        | E::InvalidCognitionMarketArtifact { .. }
        | E::EnterpriseExportMalformed(_) => SCHEMA,
        E::PassportNotYetValid { .. }
        | E::PassportExpired { .. }
        | E::InvalidEvidenceGraphArtifact(_)
        | E::MissingExecutionLease
        | E::MissingRuntimeArtifact(_)
        | E::InvalidRuntimeArtifact { .. }
        | E::RuntimeSecurityClaimFailed(_)
        | E::AdvisoryEvidenceCannotAuthorize
        | E::MissingEnterpriseArtifact(_)
        | E::MissingAgentWebArtifact(_)
        | E::MissingTrustMarketArtifact(_)
        | E::MissingCognitionMarketArtifact(_)
        | E::EnterpriseExportClaimFailed(_)
        | E::AgentWebClaimFailed(_)
        | E::TrustMarketClaimFailed(_)
        | E::RiskComptrollerClaimFailed(_)
        | E::CognitionMarketClaimFailed(_) => REQUIRED,
        E::UntrustedTransactionPassportSigner
        | E::InvalidPassportSignature(_)
        | E::EvidenceGraphDigestMismatch { .. }
        | E::VerifierPolicyDigestMismatch { .. }
        | E::EvidenceGraphArtifactDigestMismatch { .. }
        | E::EvidenceGraphBindingDigestMismatch(_)
        | E::EvidenceGraphBindingSignatureInvalid(_)
        | E::MissingEvidenceGraphArtifact(_)
        | E::RuntimeArtifactDigestMismatch { .. }
        | E::RuntimeSecurityDigestMismatch(_)
        | E::RuntimeSecuritySignatureInvalid(_)
        | E::EnterpriseExportDigestMismatch(_)
        | E::EnterpriseExportSignatureInvalid(_)
        | E::AgentWebDigestMismatch(_)
        | E::AgentWebSignatureInvalid(_)
        | E::TrustMarketArtifactSignatureInvalid { .. }
        | E::RiskComptrollerSignatureInvalid(_)
        | E::CognitionMarketSignatureInvalid(_)
        | E::CognitionMarketArtifactSignatureInvalid { .. } => INTEGRITY,
        E::MissingTrustedTransactionRootKeys
        | E::EnterpriseExportUnsupported(_)
        | E::AgentWebUnsupported(_)
        | E::TrustMarketUnsupported(_) => UNSUPPORTED,
    }
}

#[test]
fn every_transaction_passport_variant_has_its_exit_class() {
    use chio_control_plane::transaction_passport::TransactionPassportError as E;
    let decode = json_error();
    let samples = vec![
        E::Input(chio_core::canonical::UntrustedJsonError::Decode(decode).into()),
        E::EvidenceLimit,
        E::UnsupportedSchema(text()),
        E::InvalidPassportField {
            field: text(),
            message: text(),
        },
        E::InvalidPassportTimestamp {
            field: text(),
            value: text(),
            message: text(),
        },
        E::InvalidPassportValidityWindow(text()),
        E::PassportNotYetValid {
            not_before: text(),
            now: text(),
        },
        E::PassportExpired {
            expires_at: text(),
            now: text(),
        },
        E::MissingTrustedTransactionRootKeys,
        E::UntrustedTransactionPassportSigner,
        E::InvalidPassportSignature(text()),
        E::InvalidEvidenceGraphDigest(text()),
        E::InvalidClaimSetDigest(text()),
        E::InvalidVerifierPolicyDigest(text()),
        E::UnsafeEvidenceGraphPath(text()),
        E::UnsafeClaimSetPath(text()),
        E::UnsafeVerifierPolicyPath(text()),
        E::InvalidEvidenceGraphArtifact(text()),
        E::EvidenceGraphBindingDigestMismatch(text()),
        E::EvidenceGraphBindingSignatureInvalid(text()),
        E::UnsupportedEvidenceGraphSchema(text()),
        E::MissingEvidenceGraphArtifact(text()),
        E::EvidenceGraphArtifactDigestMismatch {
            path: text(),
            expected: text(),
            actual: text(),
        },
        E::InvalidVerifierPolicyArtifact(text()),
        E::UnsupportedVerifierPolicySchema(text()),
        E::MissingExecutionLease,
        E::MissingRuntimeArtifact(text()),
        E::InvalidRuntimeArtifact {
            path: text(),
            message: text(),
        },
        E::RuntimeArtifactDigestMismatch {
            path: text(),
            message: text(),
        },
        E::RuntimeSecurityClaimFailed(text()),
        E::RuntimeSecurityDigestMismatch(text()),
        E::RuntimeSecuritySignatureInvalid(text()),
        E::MissingEnterpriseArtifact(text()),
        E::InvalidEnterpriseArtifact {
            path: text(),
            message: text(),
        },
        E::EnterpriseExportClaimFailed(text()),
        E::EnterpriseExportDigestMismatch(text()),
        E::EnterpriseExportSignatureInvalid(text()),
        E::EnterpriseExportMalformed(text()),
        E::EnterpriseExportUnsupported(text()),
        E::MissingAgentWebArtifact(text()),
        E::InvalidAgentWebArtifact {
            path: text(),
            message: text(),
        },
        E::AgentWebClaimFailed(text()),
        E::AgentWebDigestMismatch(text()),
        E::AgentWebSignatureInvalid(text()),
        E::AgentWebUnsupported(text()),
        E::MissingTrustMarketArtifact(text()),
        E::InvalidTrustMarketArtifact {
            path: text(),
            message: text(),
        },
        E::TrustMarketArtifactSignatureInvalid {
            path: text(),
            message: text(),
        },
        E::TrustMarketClaimFailed(text()),
        E::TrustMarketUnsupported(text()),
        E::RiskComptrollerClaimFailed(text()),
        E::RiskComptrollerSignatureInvalid(text()),
        E::MissingCognitionMarketArtifact(text()),
        E::InvalidCognitionMarketArtifact {
            path: text(),
            message: text(),
        },
        E::CognitionMarketClaimFailed(text()),
        E::CognitionMarketSignatureInvalid(text()),
        E::CognitionMarketArtifactSignatureInvalid {
            path: text(),
            message: text(),
        },
        E::AdvisoryEvidenceCannotAuthorize,
        E::EvidenceGraphDigestMismatch {
            expected: text(),
            actual: text(),
        },
        E::VerifierPolicyDigestMismatch {
            expected: text(),
            actual: text(),
        },
    ];
    assert_classes(samples, expected_passport, map_proof_error);
}

fn expected_commerce(error: &chio_commerce_order::CommerceOrderError) -> i32 {
    use chio_commerce_order::CommerceOrderError as E;
    match error {
        E::Input(_) | E::EvidenceLimit | E::UnsupportedSchema { .. } | E::InvalidArtifact { .. } => {
            SCHEMA
        }
        E::DigestMismatch { .. }
        | E::ReplayDigestMismatch(_)
        | E::ReplaySignatureInvalid(_)
        | E::PaymentDigestMismatch(_)
        | E::PaymentSignatureInvalid(_)
        | E::MandateDigestMismatch(_)
        | E::ProviderTrustSignatureInvalid(_)
        | E::SettlementDigestMismatch(_)
        | E::SettlementSignatureInvalid(_) => INTEGRITY,
        E::ReplayFailed(_)
        | E::PaymentFailed(_)
        | E::MandateFailed(_)
        | E::ProviderTrustFailed(_)
        | E::SettlementFailed(_)
        | E::CoverageFailed(_) => REQUIRED,
    }
}

#[test]
fn every_commerce_variant_has_its_exit_class() {
    use chio_commerce_order::CommerceOrderError as E;
    let decode = json_error();
    let samples = vec![
        E::Input(chio_core::canonical::UntrustedJsonError::Decode(decode).into()),
        E::EvidenceLimit,
        E::UnsupportedSchema {
            field: "field",
            schema: text(),
        },
        E::InvalidArtifact {
            field: "field",
            message: text(),
        },
        E::DigestMismatch {
            field: text(),
            expected: text(),
            actual: text(),
        },
        E::ReplayFailed(text()),
        E::ReplayDigestMismatch(text()),
        E::ReplaySignatureInvalid(text()),
        E::PaymentFailed(text()),
        E::PaymentDigestMismatch(text()),
        E::PaymentSignatureInvalid(text()),
        E::MandateFailed(text()),
        E::MandateDigestMismatch(text()),
        E::ProviderTrustFailed(text()),
        E::ProviderTrustSignatureInvalid(text()),
        E::SettlementFailed(text()),
        E::SettlementDigestMismatch(text()),
        E::SettlementSignatureInvalid(text()),
        E::CoverageFailed(text()),
    ];
    assert_classes(samples, expected_commerce, map_commerce_proof_error);
}

fn expected_web3(error: &chio_web3::error::Web3ContractError) -> i32 {
    use chio_web3::error::Web3ContractError as E;
    match error {
        E::UnsupportedSchema(_) | E::MissingField(_) | E::DuplicateValue(_) => SCHEMA,
        E::UnknownReference(_)
        | E::BindingSignatureInvalid(_)
        | E::ProofDigestMismatch(_)
        | E::SettlementDigestMismatch(_)
        | E::ProofSignatureInvalid(_)
        | E::SettlementSignatureInvalid(_) => INTEGRITY,
        E::InvalidBinding(_)
        | E::InvalidProof(_)
        | E::InvalidSettlement(_)
        | E::InvalidQualificationCase(_) => REQUIRED,
    }
}

#[test]
fn every_public_settlement_variant_has_its_exit_class() {
    use chio_web3::error::Web3ContractError as E;
    let samples = vec![
        E::UnsupportedSchema(text()),
        E::MissingField("field"),
        E::DuplicateValue(text()),
        E::UnknownReference(text()),
        E::InvalidBinding(text()),
        E::BindingSignatureInvalid(text()),
        E::InvalidProof(text()),
        E::InvalidSettlement(text()),
        E::ProofDigestMismatch(text()),
        E::SettlementDigestMismatch(text()),
        E::ProofSignatureInvalid(text()),
        E::SettlementSignatureInvalid(text()),
        E::InvalidQualificationCase(text()),
    ];
    assert_classes(samples, expected_web3, map_public_settlement_proof_error);
}

fn expected_swarm(error: &chio_swarm_authority::SwarmAuthorityError) -> i32 {
    use chio_swarm_authority::SwarmAuthorityError as E;
    match error {
        E::Rejected(_) => REQUIRED,
        E::DigestMismatch(_) | E::SignatureInvalid(_) => INTEGRITY,
        E::UnsupportedSchema(_) | E::Canonical(_) => SCHEMA,
        E::Unsupported(_) => UNSUPPORTED,
    }
}

#[test]
fn every_swarm_variant_has_its_exit_class() {
    use chio_swarm_authority::SwarmAuthorityError as E;
    let samples = vec![
        E::Rejected(text()),
        E::DigestMismatch(text()),
        E::SignatureInvalid(text()),
        E::UnsupportedSchema(text()),
        E::Unsupported(text()),
        E::Canonical(text()),
    ];
    assert_classes(samples, expected_swarm, map_swarm_proof_error);
}

fn expected_lineage(error: &chio_selective_disclosure::DisclosureLineageError) -> i32 {
    use chio_selective_disclosure::DisclosureLineageError as E;
    match error {
        E::InvalidArtifact(_) => REQUIRED,
        E::DigestMismatch(_) | E::SignatureInvalid(_) => INTEGRITY,
        E::UnsupportedSchema(_) => SCHEMA,
        E::Unsupported(_) => UNSUPPORTED,
    }
}

#[test]
fn every_disclosure_lineage_variant_has_its_exit_class() {
    use chio_selective_disclosure::DisclosureLineageError as E;
    let samples = vec![
        E::InvalidArtifact(text()),
        E::DigestMismatch(text()),
        E::SignatureInvalid(text()),
        E::UnsupportedSchema(text()),
        E::Unsupported(text()),
    ];
    assert_classes(samples, expected_lineage, map_disclosure_lineage_proof_error);
}

fn expected_selective_disclosure(
    error: &chio_selective_disclosure::SelectiveDisclosureError,
) -> i32 {
    use chio_selective_disclosure::SelectiveDisclosureError as E;
    match error {
        E::SignatureVerificationFailed
        | E::ReceiptSignatureInvalid
        | E::ContentHashMismatch(_)
        | E::TransparencyInclusionHashMismatch(_) => INTEGRITY,
        E::CanonicalJson(_)
        | E::MalformedHexField { .. }
        | E::DisclosureDuplicateIndex(_)
        | E::DisclosureIndexOutOfRange(_)
        | E::SchemaMismatch(_)
        | E::Hex(_) => SCHEMA,
        E::ProjectionVersionMismatch(_) => UNSUPPORTED,
        E::SignedProjectionMismatch
        | E::ProofVerificationFailed
        | E::ReceiptBbsSignatureMissing
        | E::ReceiptBbsBindingInvalid(_)
        | E::ProjectionManifestInvalid(_)
        | E::TransparencyInclusionInvalid(_)
        | E::UnknownIssuer(_)
        | E::IssuerKeyMismatch
        | E::KeySeedTooShort
        | E::Crypto(_) => REQUIRED,
    }
}

#[test]
fn every_selective_disclosure_variant_has_its_exit_class() {
    use chio_selective_disclosure::SelectiveDisclosureError as E;
    let samples = vec![
        E::CanonicalJson(text()),
        E::MalformedHexField {
            field: text(),
            reason: text(),
        },
        E::DisclosureDuplicateIndex(1),
        E::DisclosureIndexOutOfRange(1),
        E::SchemaMismatch(text()),
        E::ProjectionVersionMismatch(text()),
        E::SignedProjectionMismatch,
        E::SignatureVerificationFailed,
        E::ProofVerificationFailed,
        E::ReceiptSignatureInvalid,
        E::ReceiptBbsSignatureMissing,
        E::ReceiptBbsBindingInvalid(text()),
        E::ProjectionManifestInvalid(text()),
        E::TransparencyInclusionInvalid(text()),
        E::TransparencyInclusionHashMismatch(text()),
        E::ContentHashMismatch(text()),
        E::UnknownIssuer(text()),
        E::IssuerKeyMismatch,
        E::KeySeedTooShort,
        E::Hex(text()),
        E::Crypto(text()),
    ];
    assert_classes(samples, expected_selective_disclosure, |error| {
        let message = format!("proof verify: {error}");
        map_selective_disclosure_proof_error(&error, message)
    });
}

fn expected_crypto_context(error: &chio_selective_disclosure::DisclosureCryptoContextError) -> i32 {
    use chio_selective_disclosure::DisclosureCryptoContextError as E;
    match error {
        E::SelectiveDisclosure(inner) => expected_selective_disclosure(inner),
        E::InvalidContext(_) => REQUIRED,
    }
}

#[test]
fn every_crypto_context_variant_has_its_exit_class() {
    use chio_selective_disclosure::DisclosureCryptoContextError as E;
    use chio_selective_disclosure::SelectiveDisclosureError as Inner;
    let samples = vec![
        E::SelectiveDisclosure(Inner::SignatureVerificationFailed),
        E::SelectiveDisclosure(Inner::ProofVerificationFailed),
        E::InvalidContext(text()),
    ];
    assert_classes(samples, expected_crypto_context, |error| {
        let message = format!("proof verify: {error}");
        map_crypto_context_proof_error(&error, message)
    });
}

fn expected_runtime(error: &chio_runtime_core::ChioRuntimeError) -> i32 {
    use chio_runtime_core::ChioRuntimeError as E;
    match error {
        E::Rejected { code, .. }
            if code.ends_with("_hash_mismatch") || code.ends_with("_digest_mismatch") =>
        {
            INTEGRITY
        }
        E::UntrustedInput(_) | E::Json(_) | E::Canonical(_) => SCHEMA,
        E::Clock(_)
        | E::Rejected { .. }
        | E::DuplicateAdmissionBundle
        | E::Store(_)
        | E::Io(_)
        | E::Sqlite(_) => REQUIRED,
    }
}

#[test]
fn every_runtime_proof_variant_has_its_exit_class() {
    use chio_runtime_core::ChioRuntimeError as E;
    let samples = vec![
        E::Rejected {
            code: "runtime_proof_regeneration_report_hash_mismatch",
            detail: text(),
        },
        E::Rejected {
            code: "runtime_proof_regeneration_source_record_mismatch",
            detail: text(),
        },
        E::DuplicateAdmissionBundle,
        E::Store(text()),
        E::Io(std::io::Error::other("io")),
        E::Json(json_error()),
        E::Canonical(text()),
    ];
    assert_classes(samples, expected_runtime, map_runtime_proof_error);
}

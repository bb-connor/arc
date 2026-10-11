//! Adapt a verified bundle to command completion without flattening its error cause.
use crate::CliError;
use std::path::Path;

pub(super) fn verify_manifest(path: &Path) -> Result<(), CliError> {
    chio_proof_room::verify_proof_room_bundle(path)
        .map(|_verified| ())
        .map_err(command_error)
}

pub(super) fn capture_input(
    input: &Path,
) -> Result<(crate::input::snapshot::Snapshot, std::path::PathBuf), CliError> {
    let input = std::fs::canonicalize(input)?;
    let root = if input.is_dir() {
        input.as_path()
    } else {
        let parent = input
            .parent()
            .ok_or_else(|| CliError::cli_other_error("proof input has no parent"))?;
        if parent.file_name().and_then(|s| s.to_str()) == Some("roots") {
            parent
                .parent()
                .ok_or_else(|| CliError::cli_other_error("proof roots has no bundle"))?
        } else {
            parent
        }
    };
    let snapshot = crate::input::snapshot::Snapshot::capture(root)?;
    let relative = input.strip_prefix(root).map_err(|source| {
        CliError::with_source(&chio_errors::_generated::error_codes::CLI_IO, source)
    })?;
    let captured = snapshot.path().join(relative);
    Ok((snapshot, captured))
}

pub(super) fn command_error(error: chio_proof_room::ProofRoomError) -> CliError {
    use chio_errors::_generated::error_codes::*;
    use chio_proof_room::ProofRoomError;
    if let ProofRoomError::Input(source) = error {
        return source.into();
    }
    // Match only owner-defined prefixes. The remaining diagnostic can contain
    // rejected input and stays exclusively in the inspectable local source.
    if let Some(reason) = error.public_reason() {
        let spec = if reason == "proof-room.schema-violation: artifact" {
            &TRANSACTION_PASSPORT_SCHEMA_UNSUPPORTED
        } else {
            &TRANSACTION_RUNTIME_PROOF_REJECTED
        };
        return CliError::with_public_source(spec, reason, error);
    }
    let detail = match &error {
        ProofRoomError::Validation(message) => message.as_str(),
        _ => "",
    };
    let (spec, message) = if detail.starts_with("proof-room.schema-violation: manifest:") {
        (
            &TRANSACTION_PASSPORT_SCHEMA_UNSUPPORTED,
            "proof-room.schema-violation: manifest",
        )
    } else if detail.starts_with("proof-room.schema-violation: artifact") {
        (
            &TRANSACTION_PASSPORT_SCHEMA_UNSUPPORTED,
            "proof-room.schema-violation: artifact",
        )
    } else {
        match detail.split(':').next().unwrap_or("") {
            "proof-room.signature.signer-untrusted" => (
                &TRANSACTION_IDENTITY_NOT_BOUND,
                "proof-room.signature.signer-untrusted",
            ),
            "proof-room.signature.payload-hash-mismatch" => (
                &TRANSACTION_ARTIFACT_HASH_MISMATCH,
                "proof-room.signature.payload-hash-mismatch",
            ),
            "proof-room.report.hash-mismatch" => (
                &TRANSACTION_ARTIFACT_HASH_MISMATCH,
                "proof-room.report.hash-mismatch",
            ),
            "proof-room.report.mismatch" => (
                &TRANSACTION_RUNTIME_PROOF_REJECTED,
                "proof-room.report.mismatch",
            ),
            "proof-room.evidence-graph.authority-node-missing" => (
                &TRANSACTION_GRAPH_NOT_CLOSED,
                "proof-room.evidence-graph.authority-node-missing",
            ),
            "proof-room.artifact.unsafe-path" => (
                &TRANSACTION_GRAPH_NOT_CLOSED,
                "proof-room.artifact.unsafe-path",
            ),
            "proof-room.first-run.authority-evidence-missing" => (
                &ATTEST_PROVENANCE_MISSING,
                "proof-room.first-run.authority-evidence-missing",
            ),
            "proof-room.receipt-coverage.status-mismatch" => (
                &TRANSACTION_RUNTIME_PROOF_REJECTED,
                "proof-room.receipt-coverage.status-mismatch",
            ),
            "proof-room.negative-case.unexpected-success" => (
                &TRANSACTION_RUNTIME_PROOF_REJECTED,
                "proof-room.negative-case.unexpected-success",
            ),
            "proof-room.negative-case.failure-mismatch" => (
                &TRANSACTION_RUNTIME_PROOF_REJECTED,
                "proof-room.negative-case.failure-mismatch",
            ),
            "proof-room.schema-violation" => (
                &TRANSACTION_PASSPORT_SCHEMA_UNSUPPORTED,
                "proof-room.schema-violation",
            ),
            _ => (
                &TRANSACTION_RUNTIME_PROOF_REJECTED,
                "proof-room.verification.failed",
            ),
        }
    };
    CliError::with_public_source(spec, message, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::ctx::{TestUnwrap, TestUnwrapErr};
    use std::error::Error;
    #[test]
    fn public_proof_rejection_preserves_safe_reason_and_private_source() {
        let error = command_error(chio_proof_room::ProofRoomError::Validation(
            "proof-room.schema-violation: artifact: private-marker".into(),
        ));
        assert_eq!(
            error.report().message,
            "proof-room.schema-violation: artifact"
        );
        assert_eq!(super::super::proof_verify_exit_code(&error), 30);
        assert!(!format!("{error:?} {error} {:?}", error.report()).contains("private-marker"));
        assert!(error
            .source()
            .and_then(Error::source)
            .test_unwrap("proof rejection retains its local verification source")
            .downcast_ref::<chio_proof_room::ProofRoomError>()
            .is_some());
    }

    #[test]
    fn proof_diagnostics_never_publish_rejected_detail_or_source_debug() {
        use chio_proof_room::ProofRoomError;
        let marker = "private-rejected-payload";
        let schema_source = serde_json::from_str::<u64>(&format!("\"{marker}\""))
            .test_unwrap_err("string payload rejects an integer schema");
        let cases = [
            (
                ProofRoomError::Validation(format!(
                    "proof-room.evidence-graph.authority-node-missing: {marker}"
                )),
                "proof-room.evidence-graph.authority-node-missing",
            ),
            (
                ProofRoomError::Validation(format!("proof-room.report.mismatch: {marker}")),
                "proof-room.report.mismatch",
            ),
            (
                ProofRoomError::Validation(format!("proof-room.public-settlement-invalid: CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL eth_blockNumber rejected by HttpEgressContract: loopback egress target denied: {marker}")),
                "loopback egress target denied",
            ),
            (
                ProofRoomError::Validation(format!("proof-room.commerce-invalid: CHIO_COMMERCE_TRUSTED_PROVIDER_KEYS must pin trusted commerce provider keys: {marker}")),
                "proof-room.verification.failed",
            ),
            (
                ProofRoomError::Verification {
                    context: "proof-room.source-verifier.failed",
                    source: Box::new(chio_control_plane::transaction_passport::TransactionPassportError::Input(
                        chio_core::canonical::UntrustedJsonError::Decode(schema_source).into(),
                    )),
                },
                "proof-room.schema-violation: artifact",
            ),
        ];
        for (source, expected) in cases {
            let error = command_error(source);
            assert_eq!(error.report().message, expected);
            assert!(!format!("{error:?} {error} {:?}", error.report()).contains(marker));
            let source = error
                .source()
                .and_then(Error::source)
                .test_unwrap("proof rejection retains its local verification source");
            assert!(source.downcast_ref::<ProofRoomError>().is_some());
            let mut retained = Some(source);
            let mut found_private_detail = false;
            while let Some(cause) = retained {
                found_private_detail |= cause.to_string().contains(marker);
                retained = cause.source();
            }
            assert!(found_private_detail);
        }
    }
}

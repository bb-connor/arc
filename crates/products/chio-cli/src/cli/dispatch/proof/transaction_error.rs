use super::*;

pub(super) fn map_proof_error(
    error: chio_control_plane::transaction_passport::TransactionPassportError,
) -> CliError {
    use chio_control_plane::transaction_passport::TransactionPassportError;

    match error {
        TransactionPassportError::Input(_) => CliError::with_public_source(
            &TRANSACTION_PASSPORT_SCHEMA_UNSUPPORTED,
            "proof-room.schema-violation: artifact",
            error,
        ),
        TransactionPassportError::UnsupportedSchema(_) => CliError::registry_error(
            &TRANSACTION_PASSPORT_SCHEMA_UNSUPPORTED,
            format!("proof verify: {error}"),
        ),
        TransactionPassportError::EvidenceGraphDigestMismatch { .. }
        | TransactionPassportError::VerifierPolicyDigestMismatch { .. } => {
            CliError::registry_error(
                &TRANSACTION_PASSPORT_HASH_MISMATCH,
                format!("proof verify: {error}"),
            )
        }
        TransactionPassportError::EvidenceGraphArtifactDigestMismatch { .. } => {
            CliError::registry_error(
                &TRANSACTION_ARTIFACT_HASH_MISMATCH,
                format!("proof verify: {error}"),
            )
        }
        TransactionPassportError::MissingExecutionLease
        | TransactionPassportError::MissingRuntimeArtifact(_)
        | TransactionPassportError::InvalidRuntimeArtifact { .. }
        | TransactionPassportError::RuntimeSecurityClaimFailed(_)
        | TransactionPassportError::AdvisoryEvidenceCannotAuthorize => CliError::registry_error(
            &TRANSACTION_RUNTIME_PROOF_REJECTED,
            format!("proof verify: {error}"),
        ),
        TransactionPassportError::InvalidEvidenceGraphArtifact(ref message)
            if is_required_claim_missing_error(message) =>
        {
            CliError::registry_error(
                &TRANSACTION_REQUIRED_CLAIM_MISSING,
                format!("proof verify: {error}"),
            )
        }
        TransactionPassportError::InvalidEvidenceGraphArtifact(ref message)
            if is_graph_cycle_error(message) =>
        {
            CliError::registry_error(&TRANSACTION_GRAPH_CYCLE, format!("proof verify: {error}"))
        }
        TransactionPassportError::MissingEvidenceGraphArtifact(_) => CliError::registry_error(
            &TRANSACTION_GRAPH_NOT_CLOSED,
            format!("proof verify: {error}"),
        ),
        TransactionPassportError::InvalidEvidenceGraphArtifact(ref message)
            if is_graph_not_closed_error(message) =>
        {
            CliError::registry_error(
                &TRANSACTION_GRAPH_NOT_CLOSED,
                format!("proof verify: {error}"),
            )
        }
        TransactionPassportError::InvalidEvidenceGraphArtifact(ref message)
            if is_authorization_not_bound_error(message) =>
        {
            CliError::registry_error(
                &TRANSACTION_AUTHORIZATION_NOT_BOUND,
                format!("proof verify: {error}"),
            )
        }
        other => CliError::cli_other_error(format!("proof verify: {other}")),
    }
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
        assert_eq!(super::super::proof_verify_exit_code(&error), 30);
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
}

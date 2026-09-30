//! Verify one physical outcome and reuse its decoded payload in this read only.
use super::*;

// Private to this store. No verified state is cached or reused after this call.
pub(super) struct VerifiedProjection {
    pub(super) outcome: ToolOutcomeRecordV1,
    pub(super) evaluation: Option<PostReturnEvaluationRecordV1>,
    pub(super) raw: Option<RawInvocationOutcomeV1>,
    pub(super) has_resolved_output: bool,
}

pub(super) fn verify_outcome_projection(
    connection: &Connection,
    operation_id: &str,
) -> Result<(), ToolOutcomeStoreError> {
    load_verified_projection(connection, operation_id).map(|_| ())
}

pub(super) fn load_verified_projection(
    connection: &Connection,
    operation_id: &str,
) -> Result<VerifiedProjection, ToolOutcomeStoreError> {
    let outcome = load_outcome_connection(connection, operation_id)?
        .ok_or_else(|| invariant("tool outcome projection disappeared"))?;
    let operation_json: Vec<u8> = connection
        .query_row(
            "SELECT operation_json FROM admission_operations WHERE operation_id = ?1",
            [operation_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let persisted = chio_core::canonical::UntrustedJsonText::from_wire(&operation_json, 256 * 1024)
        .and_then(|input| input.decode_canonical())
        .map_err(|error| invariant(format!("admission operation decode failed: {error}")))?;
    let operation = AdmissionOperationV1::from_persisted(persisted)
        .map_err(|error| invariant(error.to_string()))?;
    if operation.tool_outcome_id() != Some(outcome.outcome_id()) {
        return Err(invariant(
            "tool outcome is not attached to its admission operation",
        ));
    }
    outcome
        .validate_against(&operation)
        .map_err(|error| invariant(error.to_string()))?;
    let raw = match load_blob_bytes_connection(connection, outcome.raw_output_digest())? {
        None => return Err(invariant("tool outcome canonical blob is absent")),
        Some(Some(bytes)) => Some(
            outcome
                .decode_canonical_bytes(&operation, &bytes)
                .map_err(|error| invariant(error.to_string()))?,
        ),
        // Retention preserves digest and size; there are no payload bytes to decode.
        Some(None) => None,
    };
    let returned_digest = returned_participant_digest(
        &outcome,
        outcome.raw_output_digest().as_str(),
        &encode_outcome(&outcome)?,
    )?;
    let stored_outcome_digest: String = connection
        .query_row(
            "SELECT participant_digest FROM tool_outcomes WHERE operation_id = ?1",
            [operation_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let evaluation = load_evaluation_connection(connection, operation_id)?;
    let (expected_outcome_digest, expected_evaluation_digest, mut expected_latest_digest) =
        if let Some(evaluation) = &evaluation {
            evaluation
                .validate_against(&operation, &outcome)
                .map_err(|error| invariant(error.to_string()))?;
            let outcome_json = encode_outcome(&outcome)?;
            let evaluation_json = encode_evaluation(evaluation)?;
            if outcome.version() > 1 {
                let digest = finalization_participant_digest(
                    &outcome,
                    evaluation,
                    &outcome_json,
                    &evaluation_json,
                )?;
                (digest.clone(), Some(digest.clone()), digest)
            } else {
                let evaluation_digest =
                    evaluation_participant_digest(evaluation, &evaluation_json)?;
                (
                    returned_digest.clone(),
                    Some(evaluation_digest.clone()),
                    evaluation_digest,
                )
            }
        } else {
            if outcome.version() != 1 {
                return Err(invariant(
                    "terminal tool outcome has no post-return evaluation",
                ));
            }
            (returned_digest.clone(), None, returned_digest)
        };
    if stored_outcome_digest != expected_outcome_digest {
        return Err(invariant(
            "tool outcome row has an invalid participant commitment",
        ));
    }
    let stored_evaluation_digest: Option<String> = connection
        .query_row(
            "SELECT participant_digest FROM post_return_evaluations WHERE operation_id = ?1",
            [operation_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if stored_evaluation_digest != expected_evaluation_digest {
        return Err(invariant(
            "post-return evaluation row has an invalid participant commitment",
        ));
    }
    if let Some(digest) = security_release::verify_projection(
        connection,
        &operation,
        &outcome,
        evaluation.as_ref(),
        raw.as_ref(),
    )? {
        expected_latest_digest = digest;
    }
    let latest: Option<String> = connection
        .query_row(
            r#"
            SELECT participant_digest FROM admission_operation_commits
            WHERE operation_id = ?1 AND participant_digest IS NOT NULL
            ORDER BY commit_sequence DESC LIMIT 1
            "#,
            [operation_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if latest.as_deref() != Some(expected_latest_digest.as_str()) {
        return Err(invariant(
            "tool outcome projection is not bound to the admission commit chain",
        ));
    }
    let resolved = load_resolved_blob_connection(connection, &outcome)?;
    if resolved.is_some() != outcome.resolved_output_ref().is_some() {
        return Err(invariant(
            "tool outcome resolved-output projection is incomplete",
        ));
    }
    Ok(VerifiedProjection {
        outcome,
        evaluation,
        raw,
        has_resolved_output: resolved.is_some(),
    })
}

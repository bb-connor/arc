//! Authenticate supported replay custody before clearing any raw envelope.
use super::*;
use chio_core::receipt::{body::ChioReceipt, decision::Decision};
use chio_kernel::admission_operation::{
    AdmissionReceiptMetadataV1, AdmissionTerminalReplay, RetainedToolAdmissionRequestV1,
    ADMISSION_RECEIPT_METADATA_KEY,
};
use chio_kernel::tool_outcome::PostReturnEvaluationStateV1;

pub(super) enum ReplayOwners {
    Qualified,
    Unsupported,
    OwnerBudget,
    ByteDeferred,
}

pub(super) fn qualified_replay_owners(
    transaction: &Transaction<'_>,
    raw: &RawInvocationOutcomeV1,
    digest: &AdmissionDigest,
    raw_size: u64,
    page: &mut ToolOutcomeCompactionPage,
    limits: ToolOutcomeCompactionLimits,
) -> Result<ReplayOwners, ToolOutcomeStoreError> {
    let count: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM tool_outcomes INDEXED BY tool_outcomes_raw_digest_owners WHERE raw_output_digest=?1",
        [digest.as_str()], |row| row.get(0),
    ).map_err(sqlite_error)?;
    let count = u64::try_from(count).map_err(|_| invariant("invalid raw-owner count"))?;
    let remaining = u64::try_from(limits.max_rows)
        .map_err(|_| invariant("invalid owner row ceiling"))?
        .saturating_sub(page.inspected_owner_rows);
    if count == 0 {
        return Err(invariant("selected raw envelope lost its owner"));
    }
    if count > remaining {
        return Ok(ReplayOwners::OwnerBudget);
    }
    let owners = {
        let mut statement = transaction.prepare(
            "SELECT operation_id FROM tool_outcomes INDEXED BY tool_outcomes_raw_digest_owners WHERE raw_output_digest=?1 ORDER BY operation_id LIMIT ?2",
        ).map_err(sqlite_error)?;
        let rows = statement
            .query_map(
                params![
                    digest.as_str(),
                    i64::try_from(remaining).map_err(|_| invariant("invalid owner ceiling"))?
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
    };
    for owner in owners {
        let verification_bytes = owner_verification_bytes(transaction, &owner, raw_size)?;
        let total = page
            .inspected_payload_bytes
            .checked_add(page.inspected_verification_bytes)
            .and_then(|bytes| bytes.checked_add(verification_bytes))
            .ok_or_else(|| invariant("verification byte count overflow"))?;
        if total > limits.max_payload_bytes {
            return Ok(ReplayOwners::ByteDeferred);
        }
        page.inspected_verification_bytes = page
            .inspected_verification_bytes
            .saturating_add(verification_bytes);
        page.inspected_owner_rows = page.inspected_owner_rows.saturating_add(1);
        let owner_id = AdmissionOperationId::from_persisted(owner.clone())
            .map_err(|error| invariant(error.to_string()))?;
        // Classify only a bounded envelope authenticated by its latest
        // commitment. Retaining unsupported bytes needs no sidecar payload.
        let envelope = authenticated_owner_envelope(transaction, &owner_id)?;
        if unsupported_owner_profile(&envelope) {
            return Ok(ReplayOwners::Unsupported);
        }
        require_no_unaccounted_sidecars(transaction, &owner_id)?;
        // The complete existing qualified reader still authorizes every erase
        // candidate; its additional profile sidecar payloads are now absent.
        let operation = load_operation_for_participant_tx(transaction, &owner_id)
            .map_err(admission_error)?
            .ok_or_else(|| invariant("retention owner disappeared"))?;
        if operation != envelope {
            return Err(invariant(
                "retention envelope changed within its transaction",
            ));
        }
        let request_bytes: Option<Vec<u8>> = transaction.query_row(
            "SELECT CASE WHEN length(request_json) BETWEEN 1 AND 262144 THEN request_json END FROM admission_operation_tool_requests WHERE operation_id=?1",
            [&owner],|row|row.get(0),
        ).optional().map_err(sqlite_error)?.flatten();
        let begin_digest: Option<String> = transaction.query_row(
            "SELECT participant_digest FROM admission_operation_commits WHERE operation_id=?1 AND mutation_kind='begin'",
            [&owner],|row|row.get(0),
        ).map_err(sqlite_error)?;
        let unprofiled = match request_bytes {
            Some(request_bytes) => {
                if begin_digest.as_deref() != Some(sha256_hex(&request_bytes).as_str()) {
                    return Err(invariant("retained request lost its begin commitment"));
                }
                let retained = RetainedToolAdmissionRequestV1::from_canonical_bytes(&request_bytes)
                    .map_err(admission_error)?;
                retained
                    .validate_binding(operation.binding())
                    .map_err(admission_error)?;
                if retained.native_security_authority_binding().is_some()
                    || !raw.matches_compacted_original_request(&retained)
                {
                    return Ok(ReplayOwners::Unsupported);
                }
                false
            }
            None if begin_digest.is_none() => true,
            None => return Err(invariant("committed original retained request disappeared")),
        };
        let projection = super::super::projection::load_verified_projection(transaction, &owner)?;
        if projection.raw.as_ref() != Some(raw)
            || !projection.has_resolved_output
            || !projection.evaluation.as_ref().is_some_and(|evaluation| {
                matches!(
                    evaluation.state(),
                    PostReturnEvaluationStateV1::Resolved { .. }
                )
            })
        {
            return Ok(ReplayOwners::Unsupported);
        }
        if unprofiled
            && !projection.evaluation.as_ref().is_some_and(|evaluation| {
                raw.matches_unprofiled_compacted_admission(&operation, evaluation)
            })
        {
            return Err(invariant("unprofiled retained raw request conflicts with its admission and frozen evaluation"));
        }
        let Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) = operation.terminal_replay()
        else {
            return Ok(ReplayOwners::Unsupported);
        };
        let receipt_bytes: Option<Vec<u8>> = transaction.query_row(
            "SELECT CASE WHEN length(record_json) BETWEEN 1 AND 1048576 THEN record_json END FROM admission_operation_terminal_records WHERE operation_id=?1 AND record_kind='receipt' AND record_id=?2",
            params![&owner,receipt_id.as_str()],|row|row.get(0),
        ).optional().map_err(sqlite_error)?.flatten();
        let Some(receipt_bytes) = receipt_bytes else {
            return Ok(ReplayOwners::Unsupported);
        };
        let receipt: ChioReceipt =
            chio_core::canonical::UntrustedJsonText::from_wire(&receipt_bytes, 1048576)
                .and_then(|input| input.decode_canonical())
                .map_err(|error| invariant(error.to_string()))?;
        // An unsupported or unverifiable receipt holds its raw bytes visibly;
        // no partial verification substitutes for the complete replay proof.
        if !raw.supports_compacted_value_receipt(&receipt)
            || !matches!(
                receipt.decision,
                Some(Decision::Allow | Decision::Incomplete { .. })
            )
        {
            return Ok(ReplayOwners::Unsupported);
        }
        let metadata: AdmissionReceiptMetadataV1 = serde_json::from_value(
            receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get(ADMISSION_RECEIPT_METADATA_KEY))
                .cloned()
                .ok_or_else(|| invariant("completed retention receipt lost admission metadata"))?,
        )
        .map_err(|error| invariant(error.to_string()))?;
        if metadata.projected_state != AdmissionOperationState::Completed
            || metadata.operation_id != owner_id
            || metadata.projected_operation_version != operation.version()
            || metadata.tool_outcome_id.as_ref() != Some(projection.outcome.outcome_id())
            || metadata.tool_outcome_version != Some(projection.outcome.version())
        {
            return Err(invariant(
                "completed retention receipt conflicts with its sealed owner",
            ));
        }
    }
    Ok(ReplayOwners::Qualified)
}

fn owner_verification_bytes(
    connection: &Connection,
    owner: &str,
    raw_size: u64,
) -> Result<u64, ToolOutcomeStoreError> {
    let size:i64 = connection.query_row(
        "SELECT length(a.operation_json)*3 + length(o.outcome_json) + COALESCE(length(e.evaluation_json),0)
           + ?2 + COALESCE(b.blob_size_bytes,0)
           + COALESCE((SELECT length(projection_json)+length(manifest_json) FROM admission_operation_terminal_projections WHERE operation_id=?1),0)
           + COALESCE((SELECT SUM(length(record_json))*2 FROM admission_operation_terminal_records WHERE operation_id=?1),0)
           + COALESCE((SELECT length(request_json) FROM admission_operation_tool_requests WHERE operation_id=?1),0)
         FROM admission_operations a JOIN tool_outcomes o ON o.operation_id=a.operation_id
         LEFT JOIN post_return_evaluations e ON e.operation_id=a.operation_id
         LEFT JOIN tool_outcome_blobs b ON b.digest=json_extract(o.outcome_json,'$.disposition.resolved_output.digest')
         WHERE a.operation_id=?1",
        params![owner,i64::try_from(raw_size).map_err(|_|invariant("invalid raw size"))?],|row|row.get(0),
    ).map_err(sqlite_error)?;
    u64::try_from(size).map_err(|_| invariant("invalid replay verification byte size"))
}
// Classification may retain an unsupported owner from its authenticated
// envelope. Only the later complete qualified reader can permit erasure.
fn authenticated_owner_envelope(
    connection: &Connection,
    owner: &AdmissionOperationId,
) -> Result<AdmissionOperationV1, ToolOutcomeStoreError> {
    let row: (Option<Vec<u8>>, String, i64, i64, String, i64) = connection.query_row(
        "SELECT CASE WHEN length(a.operation_json) BETWEEN 1 AND 262144 THEN a.operation_json END,
                a.state, a.terminal, a.version, c.operation_digest, c.operation_version
         FROM admission_operations a JOIN admission_operation_commits c
           ON c.commit_sequence=(SELECT MAX(commit_sequence) FROM admission_operation_commits WHERE operation_id=?1)
         WHERE a.operation_id=?1",
        [owner.as_str()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
    ).map_err(sqlite_error)?;
    let bytes = row
        .0
        .ok_or_else(|| invariant("retention operation envelope exceeds its bound"))?;
    let persisted = chio_core::canonical::UntrustedJsonText::from_wire(&bytes, 262144)
        .and_then(|input| input.decode_canonical())
        .map_err(|error| invariant(error.to_string()))?;
    let operation = AdmissionOperationV1::from_persisted(persisted)
        .map_err(|error| invariant(error.to_string()))?;
    if operation.binding().operation_id() != owner
        || operation.state() != AdmissionOperationState::Completed
        || row.1 != "completed"
        || row.2 != 1
        || u64::try_from(row.3).ok() != Some(operation.version())
        || row.3 != row.5
        || sha256_hex(&bytes) != row.4
    {
        return Err(invariant(
            "retention operation envelope conflicts with its latest commitment",
        ));
    }
    Ok(operation)
}

fn unsupported_owner_profile(operation: &AdmissionOperationV1) -> bool {
    let requirements = operation.binding().participant_requirements();
    requirements.payment
        || requirements.execution_nonce
        || requirements.outcome_eligibility
        || requirements.authorization_consumption
        || requirements.observation_attempt_zero
        || requirements.obligation
        || requirements.channel
        || requirements.credit_exposure
        || requirements.supplemental_authorization
        || operation.caller_dispatch_context_digest().is_some()
        || operation.execution_nonce_issuance_digest().is_some()
        || operation.execution_nonce_preflight_digest().is_some()
        || operation.native_dispatch_ledger_digest().is_some()
        || operation.runtime_participant_ledger_digest().is_some()
        || operation.governed_approval_ledger_digest().is_some()
        || operation.dpop_replay_ledger_digest().is_some()
}

fn require_no_unaccounted_sidecars(
    connection: &Connection,
    owner: &AdmissionOperationId,
) -> Result<(), ToolOutcomeStoreError> {
    // Fixed metadata probes, all under the surrounding SQL work guard. These
    // never select a sidecar payload. Unsupported owners were retained above;
    // a supported envelope with any unexpected physical sidecar is corruption.
    for table in [
        "admission_execution_nonce_issuances",
        "admission_execution_nonce_reservations",
        "admission_execution_nonce_transitions",
        "admission_operation_caller_contexts",
        "admission_operation_native_dispatch_ledger",
        "runtime_replay_claim_episodes",
        "runtime_replay_claim_releases",
        "runtime_replay_claim_resources",
        "governed_approval_replay_claim_episodes",
        "governed_approval_replay_claim_releases",
        "governed_approval_replay_claim_resources",
        "dpop_replay_claim_episodes",
        "dpop_replay_claim_releases",
        "dpop_replay_claim_resources",
        "admission_operation_authorization_consumptions",
        "admission_operation_observer_attempts",
        "credit_exposure_reservations",
        "credit_exposure_terminal_transitions",
        "obligation_atoms",
        "obligation_disposition_records",
        "obligation_settlement_lifecycle_records",
        "tool_outcome_security_releases",
    ] {
        let exists: bool = connection
            .query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE operation_id=?1)"),
                [owner.as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if exists {
            return Err(invariant(
                "retention owner has unexpected sidecar custody; payload bytes and cursor retained",
            ));
        }
    }
    Ok(())
}

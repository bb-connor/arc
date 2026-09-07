//! Bounded ownership evidence and physical cleanup ordered before issuance.

use super::*;
use crate::budget_store::NoncePreflightHoldState;

pub(in crate::admission_operation_store) fn verify(
    connection: &Connection,
    operation: &AdmissionOperationV1,
) -> Result<Option<(PreflightOwnership, NoncePreflightHoldState)>, AdmissionOperationStoreError> {
    let row = connection
        .query_row(
            "SELECT CASE WHEN length(ownership_json) BETWEEN 1 AND 4096 THEN ownership_json END,
         CASE WHEN length(operation_json) BETWEEN 1 AND 262144 THEN operation_json END,
         recorded_at_unix_ms,
         CASE WHEN length(budget_operation_id) <= 512 THEN budget_operation_id END,
         CASE WHEN length(hold_id) <= 512 THEN hold_id END
         FROM admission_nonce_preflight_holds WHERE operation_id = ?1",
            [operation.binding().operation_id().as_str()],
            |row| {
                Ok((
                    row.get::<_, Option<Vec<u8>>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((Some(bytes), Some(snapshot), at, Some(budget_id), Some(hold_id))) = row else {
        if row.is_some() || operation.execution_nonce_preflight_digest().is_some() {
            return Err(invariant(
                "nonce preflight ownership is missing or exceeds its storage bound",
            ));
        }
        return Ok(None);
    };
    let ownership: PreflightOwnership =
        serde_json::from_slice(&bytes).map_err(|error| invariant(error.to_string()))?;
    let at = stored_u64(at, "preflight_recorded_at")?;
    validate_trusted_time(at, "preflight_recorded_at")?;
    let identity =
        AdmissionNoncePreflightIdentityV1::for_operation(operation, ownership.grant_index)?;
    if ownership.schema != "chio.admission-nonce-preflight-ownership.v1"
        || &ownership.operation_id != operation.binding().operation_id()
        || &ownership.budget_operation_id != identity.budget_operation_id()
        || &ownership.hold_id != identity.hold_id()
        || &ownership.authorization_event_id != identity.authorization_event_id()
        || ownership.recorded_at_unix_ms != at
        || budget_id != identity.budget_operation_id().as_str()
        || hold_id != identity.hold_id().as_str()
        || canonical_json_bytes(&ownership).map_err(|error| invariant(error.to_string()))? != bytes
        || operation
            .execution_nonce_preflight_digest()
            .map(AdmissionDigest::as_str)
            != Some(sha256_hex(&bytes).as_str())
    {
        return Err(invariant(
            "nonce preflight ownership and parent binding disagree",
        ));
    }
    let prepared = AdmissionOperationV1::from_persisted(
        serde_json::from_slice::<PersistedAdmissionOperationV1>(&snapshot)
            .map_err(|error| invariant(error.to_string()))?,
    )?;
    if prepared.binding() != operation.binding()
        || prepared.state() != AdmissionOperationState::Prepared
        || prepared.attachments().len() != 1
        || prepared.execution_nonce_preflight_digest()
            != operation.execution_nonce_preflight_digest()
        || prepared.version() > operation.version()
        || encode_operation(&prepared)? != snapshot
    {
        return Err(invariant(
            "nonce preflight lost its exact Prepared snapshot",
        ));
    }
    let committed: bool = connection
        .query_row(
            "SELECT COUNT(*) = 1 FROM admission_operation_commits
         WHERE operation_id = ?1 AND operation_version = ?2 AND mutation_kind = 'compare_and_swap'
         AND participant_digest = ?3 AND operation_digest = ?4 AND recorded_at_unix_ms = ?5",
            params![
                operation.binding().operation_id().as_str(),
                sqlite_i64(prepared.version(), "preflight_version")?,
                commit_digest(&bytes, &snapshot, at)?,
                sha256_hex(&snapshot),
                sqlite_i64(at, "preflight_recorded_at")?
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !committed {
        return Err(invariant("nonce preflight lost its exact admission commit"));
    }
    let original = retained_request::load_retained_request_tx(connection, operation)?
        .ok_or_else(|| invariant("nonce preflight lost its retained original request"))?;
    if original
        .retained_matching_grant(ownership.grant_index as usize)
        .is_none()
    {
        return Err(invariant(
            "nonce preflight grant is absent from retained matching grants",
        ));
    }
    let cleaned = crate::budget_store::verify_preflight_hold(
        connection,
        operation,
        &identity,
        ownership.authorization_digest.as_str(),
    )
    .map_err(|error| invariant(error.to_string()))?;
    Ok(Some((ownership, cleaned)))
}

pub(in crate::admission_operation_store) fn verify_issued_cleanup(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    issued_version: Option<u64>,
) -> Result<(), AdmissionOperationStoreError> {
    let Some((_, cleaned)) = verify(connection, operation)? else {
        // Missing ownership can be decoded as history, never fresh authority.
        return if issued_version.is_some() {
            Ok(())
        } else {
            Err(invariant(
                "fresh nonce authority requires operation-owned preflight",
            ))
        };
    };
    let cleaned = match cleaned {
        NoncePreflightHoldState::ReversedAuthorized {
            global_commit_sequence,
        } => global_commit_sequence,
        NoncePreflightHoldState::Reserved => {
            return Err(invariant(
                "nonce issuance requires physical preflight reversal",
            ))
        }
        NoncePreflightHoldState::ReversedWithoutApproval => {
            return Err(invariant(
                "nonce preflight cleanup cannot substitute for required approval",
            ))
        }
    };
    if let Some(version) = issued_version {
        let ordered: bool = connection.query_row(
            "SELECT COUNT(*) = 1 FROM authority_global_commits AS global
             JOIN admission_operation_commits AS admission ON admission.commit_sequence = global.projection_sequence
             AND admission.operation_id = global.projection_key
             WHERE global.projection_kind = 'admission' AND admission.operation_id = ?1
             AND admission.operation_version = ?2 AND admission.mutation_kind = 'compare_and_swap'
             AND global.commit_sequence > ?3",
            params![operation.binding().operation_id().as_str(), sqlite_i64(version, "issued_version")?,
                sqlite_i64(cleaned, "preflight_cleanup_sequence")?], |row| row.get(0),
        ).map_err(sqlite_error)?;
        if !ordered {
            return Err(invariant(
                "nonce issuance preceded its durable preflight cleanup",
            ));
        }
    }
    Ok(())
}

pub(in crate::admission_operation_store) fn verify_ownership(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let orphan: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM admission_nonce_preflight_holds AS preflight
         WHERE NOT EXISTS(SELECT 1 FROM admission_operations AS operation WHERE operation.operation_id = preflight.operation_id))",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if orphan {
        return Err(invariant(
            "nonce preflight has no parent admission operation",
        ));
    }
    Ok(())
}

pub(super) fn commit_digest(
    bytes: &[u8],
    snapshot: &[u8],
    at: u64,
) -> Result<String, AdmissionOperationStoreError> {
    canonical_json_bytes(&serde_json::json!({
        "schema": "chio.admission-nonce-preflight-commit.v1",
        "ownership_digest": sha256_hex(bytes), "operation_digest": sha256_hex(snapshot), "recorded_at_unix_ms": at,
    })).map(|bytes| sha256_hex(&bytes)).map_err(|error| invariant(error.to_string()))
}

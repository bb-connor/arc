fn load_admission_event(
    transaction: &Transaction<'_>,
    operation_id: &str,
) -> Result<Option<StoredAdmissionEvent>, BudgetStoreError> {
    type StoredRow = (
        String,
        String,
        String,
        i64,
        Option<String>,
        Option<String>,
        Option<i64>,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<i64>,
        String,
        Option<String>,
        i64,
        i64,
        Option<i64>,
        Option<String>,
    );
    let row: Option<StoredRow> = transaction
        .query_row(
            r#"
            SELECT capture_event_id, hold_id, capability_id, grant_index,
                   authority_id, lease_id, lease_epoch, revocation_set_digest,
                   revocation_ids_json, artifact_digests_json,
                   aggregate_root_capability_id, aggregate_root_binding_digest,
                   last_observed_revocation_index, outcome, revoked_ids_json,
                   revocation_commit_index, authority_commit_index,
                   budget_commit_index, request_binding_hash
            FROM admission_capture_events WHERE operation_id = ?1
            "#,
            params![operation_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                    row.get(17)?,
                    row.get(18)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    let authority = stored_budget_authority(row.4, row.5, row.6)?;
    let request_binding_hash = row.18.ok_or_else(|| {
        BudgetStoreError::Invariant(
            "persisted admission capture omits request_binding_hash".to_string(),
        )
    })?;
    Ok(Some(StoredAdmissionEvent {
        request_binding_hash,
        capture_event_id: row.0,
        hold_id: row.1,
        capability_id: row.2,
        grant_index: row.3,
        authority,
        revocation_set_digest: row.7,
        revocation_ids_json: row.8,
        artifact_digests_json: row.9,
        aggregate_root_capability_id: row.10,
        aggregate_root_binding_digest: row.11,
        last_observed_revocation_index: row.12,
        outcome: row.13,
        revoked_ids_json: row.14,
        revocation_commit_index: row.15,
        authority_commit_index: row.16,
        budget_commit_index: row.17,
    }))
}

fn restore_admission_decision(
    transaction: &Transaction<'_>,
    request: &AdmissionCaptureRequest,
    stored: &StoredAdmissionEvent,
) -> Result<AdmissionCaptureDecision, AdmissionCaptureError> {
    validate_stored_admission_commit(transaction, request, stored)?;
    let revocation_commit_index = nonnegative_u64(
        stored.revocation_commit_index,
        "stored revocation commit index",
    )?;
    let authority_commit_index = nonnegative_u64(
        stored.authority_commit_index,
        "stored authority commit index",
    )?;
    match stored.outcome.as_str() {
        "captured" => {
            let budget =
                SqliteBudgetStore::capture_composite_invocation_reservations_in_transaction_unchecked(
                    transaction,
                    request.budget(),
                )?;
            let stored_budget_index = stored
                .budget_commit_index
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "captured admission event omitted budget commit index".to_string(),
                    )
                })
                .and_then(|value| nonnegative_budget_u64(value, "stored budget commit index"))?;
            if budget.metadata.budget_commit_index != Some(stored_budget_index)
                || stored.revoked_ids_json.is_some()
            {
                return Err(BudgetStoreError::Invariant(
                    "captured admission outcome diverged from budget event".to_string(),
                )
                .into());
            }
            let metadata = AdmissionCaptureMetadata::new(AdmissionCaptureMetadataInput {
                operation_id: request.operation_id().to_string(),
                checked_revocation_set_digest: stored.revocation_set_digest.clone(),
                aggregate_root_capability_id: stored.aggregate_root_capability_id.clone(),
                aggregate_root_binding_digest: stored.aggregate_root_binding_digest.clone(),
                budget_commit: budget.metadata.clone(),
                revocation_commit_index,
                authority_commit_index,
                leader_epoch: None,
            })?;
            Ok(AdmissionCaptureDecision::Captured {
                budget: Box::new(budget),
                metadata,
            })
        }
        "denied-revoked" => {
            if stored.budget_commit_index.is_some() {
                return Err(BudgetStoreError::Invariant(
                    "revoked admission denial unexpectedly has a budget commit".to_string(),
                )
                .into());
            }
            let revoked_ids_json = stored.revoked_ids_json.as_deref().ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "revoked admission denial omitted revoked IDs".to_string(),
                )
            })?;
            let revoked_ids =
                serde_json::from_str::<Vec<String>>(revoked_ids_json).map_err(|error| {
                    BudgetStoreError::Invariant(format!(
                        "persisted revoked admission IDs are malformed: {error}"
                    ))
                })?;
            let metadata = AdmissionCaptureMetadata::new(AdmissionCaptureMetadataInput {
                operation_id: request.operation_id().to_string(),
                checked_revocation_set_digest: stored.revocation_set_digest.clone(),
                aggregate_root_capability_id: stored.aggregate_root_capability_id.clone(),
                aggregate_root_binding_digest: stored.aggregate_root_binding_digest.clone(),
                budget_commit: denial_budget_metadata(request),
                revocation_commit_index,
                authority_commit_index,
                leader_epoch: None,
            })?;
            Ok(AdmissionCaptureDecision::Denied(
                AdmissionCaptureDenial::revoked(revoked_ids, metadata)?,
            ))
        }
        outcome => Err(BudgetStoreError::Invariant(format!(
            "unknown persisted admission outcome `{outcome}`"
        ))
        .into()),
    }
}

fn validate_stored_admission_commit(
    transaction: &Transaction<'_>,
    request: &AdmissionCaptureRequest,
    stored: &StoredAdmissionEvent,
) -> Result<(), BudgetStoreError> {
    type CommitRow = (
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        i64,
        Option<i64>,
    );
    let commit_index = nonnegative_budget_u64(
        stored.authority_commit_index,
        "stored authority commit index",
    )?;
    let row: CommitRow = transaction
        .query_row(
            r#"
            SELECT kind, operation_id, capture_event_id, capability_id,
                   revocation_commit_index, budget_commit_index
            FROM admission_authority_commits
            WHERE authority_commit_index = ?1
            "#,
            params![i64::try_from(commit_index).map_err(|_| {
                BudgetStoreError::Overflow(
                    "stored authority commit index exceeds SQLite integer".to_string(),
                )
            })?],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(
                "persisted admission outcome has no authority commit".to_string(),
            )
        })?;
    let expected_kind = match stored.outcome.as_str() {
        "captured" => "capture",
        "denied-revoked" => "capture-denied",
        other => {
            return Err(BudgetStoreError::Invariant(format!(
                "unknown persisted admission outcome `{other}`"
            )));
        }
    };
    if row.0 != expected_kind
        || row.1.as_deref() != Some(request.operation_id())
        || row.2.as_deref() != request.budget().event_id.as_deref()
        || row.3.as_deref() != Some(request.budget().capability_id.as_str())
        || row.4 != stored.revocation_commit_index
        || row.5 != stored.budget_commit_index
    {
        return Err(BudgetStoreError::Invariant(
            "persisted admission outcome diverged from its authority commit".to_string(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn persist_admission_event(
    transaction: &Transaction<'_>,
    request: &AdmissionCaptureRequest,
    outcome: &str,
    revoked_ids: Option<&[String]>,
    revocation_commit_index: u64,
    authority_commit_index: u64,
    budget_commit_index: Option<u64>,
    recorded_at: i64,
) -> Result<(), BudgetStoreError> {
    let hold_id = request.budget().hold_id.as_deref().ok_or_else(|| {
        BudgetStoreError::Invariant("admission capture requires hold_id".to_string())
    })?;
    let capture_event_id = request.budget().event_id.as_deref().ok_or_else(|| {
        BudgetStoreError::Invariant("admission capture requires event_id".to_string())
    })?;
    let revocation_ids_json =
        serde_json::to_string(request.revocation_set().ids()).map_err(|error| {
            BudgetStoreError::Invariant(format!("failed to encode revocation set: {error}"))
        })?;
    let artifact_digests_json = serde_json::to_string(request.authorization_artifact_digests())
        .map_err(|error| {
            BudgetStoreError::Invariant(format!(
                "failed to encode authorization artifacts: {error}"
            ))
        })?;
    let revoked_ids_json = revoked_ids
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| {
            BudgetStoreError::Invariant(format!("failed to encode revoked IDs: {error}"))
        })?;
    let (authority_id, lease_id, lease_epoch) =
        budget_authority_sql_parts(request.budget().authority.as_ref())?;
    let admission_operation = request
        .budget()
        .admission_operation
        .as_ref()
        .ok_or_else(|| {
            BudgetStoreError::Invariant(
                "admission capture requires an admission operation binding".to_string(),
            )
        })?;
    transaction.execute(
        r#"
        INSERT INTO admission_capture_events (
            operation_id, request_binding_hash, capture_event_id,
            hold_id, capability_id, grant_index,
            authority_id, lease_id, lease_epoch, revocation_set_digest,
            revocation_ids_json, artifact_digests_json,
            aggregate_root_capability_id, aggregate_root_binding_digest,
            last_observed_revocation_index, outcome, revoked_ids_json,
            revocation_commit_index, authority_commit_index,
            budget_commit_index, recorded_at
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
            ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19,
            ?20, ?21
        )
        "#,
        params![
            request.operation_id(),
            admission_operation.request_binding_hash(),
            capture_event_id,
            hold_id,
            request.budget().capability_id,
            i64::try_from(request.budget().grant_index).map_err(|_| {
                BudgetStoreError::Overflow("capture grant index exceeds SQLite integer".to_string())
            })?,
            authority_id,
            lease_id,
            lease_epoch,
            request.bound_revocation_set_digest(),
            revocation_ids_json,
            artifact_digests_json,
            request.aggregate_root_capability_id(),
            request.aggregate_root_binding_digest(),
            request
                .last_observed_revocation_index()
                .map(|value| i64::try_from(value).map_err(|_| {
                    BudgetStoreError::Overflow(
                        "last-observed revocation index exceeds SQLite integer".to_string(),
                    )
                }))
                .transpose()?,
            outcome,
            revoked_ids_json,
            i64::try_from(revocation_commit_index).map_err(|_| {
                BudgetStoreError::Overflow(
                    "revocation commit index exceeds SQLite integer".to_string(),
                )
            })?,
            i64::try_from(authority_commit_index).map_err(|_| {
                BudgetStoreError::Overflow(
                    "authority commit index exceeds SQLite integer".to_string(),
                )
            })?,
            budget_commit_index
                .map(|value| i64::try_from(value).map_err(|_| {
                    BudgetStoreError::Overflow(
                        "budget commit index exceeds SQLite integer".to_string(),
                    )
                }))
                .transpose()?,
            recorded_at,
        ],
    )?;
    Ok(())
}

fn denial_budget_metadata(request: &AdmissionCaptureRequest) -> BudgetCommitMetadata {
    BudgetCommitMetadata {
        authority: request.budget().authority.clone(),
        guarantee_level: BudgetGuaranteeLevel::SingleNodeAtomic,
        budget_profile: BudgetAuthorityProfile::AuthoritativeHoldEvent,
        metering_profile: BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
        budget_commit_index: None,
        event_id: request.budget().event_id.clone(),
    }
}

fn stored_budget_authority(
    authority_id: Option<String>,
    lease_id: Option<String>,
    lease_epoch: Option<i64>,
) -> Result<Option<BudgetEventAuthority>, BudgetStoreError> {
    match (authority_id, lease_id, lease_epoch) {
        (None, None, None) => Ok(None),
        (Some(authority_id), Some(lease_id), Some(lease_epoch)) => Ok(Some(BudgetEventAuthority {
            authority_id,
            lease_id,
            lease_epoch: nonnegative_budget_u64(lease_epoch, "stored lease epoch")?,
        })),
        _ => Err(BudgetStoreError::Invariant(
            "persisted budget authority tuple is incomplete".to_string(),
        )),
    }
}

type BudgetAuthoritySqlParts<'a> = (Option<&'a str>, Option<&'a str>, Option<i64>);

fn budget_authority_sql_parts(
    authority: Option<&BudgetEventAuthority>,
) -> Result<BudgetAuthoritySqlParts<'_>, BudgetStoreError> {
    match authority {
        Some(authority) => Ok((
            Some(authority.authority_id.as_str()),
            Some(authority.lease_id.as_str()),
            Some(i64::try_from(authority.lease_epoch).map_err(|_| {
                BudgetStoreError::Overflow("lease epoch exceeds SQLite integer".to_string())
            })?),
        )),
        None => Ok((None, None, None)),
    }
}

fn normalized_database_path(path: &Path) -> Result<PathBuf, AdmissionCaptureError> {
    if path == Path::new(":memory:") {
        return Err(AdmissionCaptureError::InvalidRequest(
            "combined admission authority requires a file-backed SQLite database".to_string(),
        ));
    }
    if path.as_os_str().is_empty() || path.file_name().is_none() {
        return Err(AdmissionCaptureError::InvalidRequest(
            "SQLite database path must name a file".to_string(),
        ));
    }
    if path.exists() {
        return fs::canonicalize(path)
            .map_err(RevocationStoreError::from)
            .map_err(AdmissionCaptureError::from);
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(RevocationStoreError::from)?
            .join(path)
    };
    let parent = absolute.parent().ok_or_else(|| {
        AdmissionCaptureError::InvalidRequest(
            "SQLite database path has no parent directory".to_string(),
        )
    })?;
    let normalized_parent = if parent.exists() {
        fs::canonicalize(parent).map_err(RevocationStoreError::from)?
    } else {
        lexical_normalize(parent)
    };
    let file_name = absolute.file_name().ok_or_else(|| {
        AdmissionCaptureError::InvalidRequest("SQLite database path must name a file".to_string())
    })?;
    Ok(normalized_parent.join(file_name))
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

fn validate_revocation_identifier(capability_id: &str) -> Result<(), RevocationStoreError> {
    if capability_id.is_empty()
        || capability_id.len() > MAX_ADMISSION_IDENTIFIER_BYTES
        || capability_id.bytes().any(|byte| byte == 0)
    {
        return Err(RevocationStoreError::Sync(
            "revocation capability ID is empty, oversized, or contains NUL".to_string(),
        ));
    }
    Ok(())
}

fn sqlite_i64(value: u64, label: &str) -> Result<i64, RevocationStoreError> {
    i64::try_from(value)
        .map_err(|_| RevocationStoreError::Sync(format!("{label} exceeds SQLite integer range")))
}

fn nonnegative_u64(value: i64, label: &str) -> Result<u64, RevocationStoreError> {
    u64::try_from(value).map_err(|_| RevocationStoreError::Sync(format!("{label} is negative")))
}

fn nonnegative_budget_u64(value: i64, label: &str) -> Result<u64, BudgetStoreError> {
    u64::try_from(value).map_err(|_| BudgetStoreError::Invariant(format!("{label} is negative")))
}

fn nonnegative_usize(value: i64, label: &str) -> Result<usize, BudgetStoreError> {
    usize::try_from(value)
        .map_err(|_| BudgetStoreError::Invariant(format!("{label} is negative or exceeds usize")))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::fs;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_kernel::budget_store::{
        AuthorizedBudgetHold, BudgetAdmissionOperationBinding, BudgetAuthorizeHoldDecision,
        BudgetCaptureInvocationRequest, BudgetEventAuthority, BudgetInvocationQuota,
        BudgetQuotaKey, BudgetQuotaProfile,
    };
    use chio_kernel::supplemental_quota::CanonicalRevocationSet;
    use chio_kernel::{
        AdmissionCaptureAuthority, AdmissionCaptureDecision, AdmissionCaptureError,
        AdmissionCaptureRequest, AdmissionCaptureRequestInput,
        CombinedAdmissionCaptureReceiptProjection, RevocationRecord, RevocationStore,
    };
    use rusqlite::{params, Connection};

    use super::*;
    use crate::budget_store::{SqliteBudgetStore, SqliteCompositeAuthorizeInput};
    use crate::revocation_store::SqliteRevocationStore;

    const LEAF_SET_DIGEST: &str =
        "baaba5816d4ef1572cfbb26a183f273ea200681234cdd767ab965b9efbaeb12f";
    const EXTENDED_SET_DIGEST: &str =
        "70dfdbd61b71e7d6c84b73ca6fc806bab383f2a0f25fc407afc3fd437a417ad7";

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    fn leaf_revocation_set() -> CanonicalRevocationSet {
        CanonicalRevocationSet::from_persisted_parts(
            vec!["leaf".to_string()],
            LEAF_SET_DIGEST.to_string(),
        )
        .expect("valid leaf revocation set")
    }

    fn extended_revocation_set() -> CanonicalRevocationSet {
        CanonicalRevocationSet::from_persisted_parts(
            vec![
                "broker-capability-1".to_string(),
                "leaf".to_string(),
                "parent".to_string(),
                "root".to_string(),
            ],
            EXTENDED_SET_DIGEST.to_string(),
        )
        .expect("valid extended revocation set")
    }

    fn admission_request_binding_hash() -> String {
        "33".repeat(32)
    }

    fn fenced_authority() -> BudgetEventAuthority {
        BudgetEventAuthority {
            authority_id: "admission-authority-1".to_string(),
            lease_id: "admission-authority-1#lease-1".to_string(),
            lease_epoch: 1,
        }
    }

    fn authorize_hold(
        path: &std::path::Path,
        artifacts: Vec<String>,
        operation_id: &str,
    ) -> AuthorizedBudgetHold {
        authorize_hold_with_authority(path, artifacts, operation_id, None)
    }

    fn authorize_hold_with_authority(
        path: &std::path::Path,
        artifacts: Vec<String>,
        operation_id: &str,
        authority: Option<BudgetEventAuthority>,
    ) -> AuthorizedBudgetHold {
        let store = SqliteBudgetStore::open(path).expect("open budget store");
        let key = BudgetQuotaKey::from_persisted_parts(
            BudgetQuotaProfile::GrantInvocation,
            "leaf".to_string(),
            Some(0),
        )
        .expect("quota key");
        let quota = BudgetInvocationQuota::from_persisted_parts(key, 2).expect("invocation quota");
        let decision = store
            .authorize_composite_hold(SqliteCompositeAuthorizeInput {
                operation_id: operation_id.to_string(),
                request_binding_hash: admission_request_binding_hash(),
                capability_id: "leaf".to_string(),
                grant_index: 0,
                requested_exposure_units: 100,
                max_cost_per_invocation: Some(100),
                max_total_cost_units: Some(1_000),
                hold_id: "hold-1".to_string(),
                event_id: "authorize-1".to_string(),
                authority,
                invocation_quotas: vec![quota],
                revocation_set: leaf_revocation_set(),
                authorization_artifact_digests: artifacts,
            })
            .expect("authorize composite hold");
        match decision {
            BudgetAuthorizeHoldDecision::Authorized(authorized) => authorized,
            BudgetAuthorizeHoldDecision::Denied(_) => panic!("composite hold was denied"),
        }
    }

    fn capture_request(
        operation_id: &str,
        event_id: &str,
        revocation_set: CanonicalRevocationSet,
        artifacts: Vec<String>,
        last_observed_revocation_index: Option<u64>,
    ) -> AdmissionCaptureRequest {
        capture_request_with_binding_hash(
            operation_id,
            event_id,
            revocation_set,
            artifacts,
            last_observed_revocation_index,
            admission_request_binding_hash(),
        )
    }

    fn capture_request_with_binding_hash(
        operation_id: &str,
        event_id: &str,
        revocation_set: CanonicalRevocationSet,
        artifacts: Vec<String>,
        last_observed_revocation_index: Option<u64>,
        request_binding_hash: String,
    ) -> AdmissionCaptureRequest {
        capture_request_with_binding_hash_and_authority(
            operation_id,
            event_id,
            revocation_set,
            artifacts,
            last_observed_revocation_index,
            request_binding_hash,
            None,
        )
    }

    fn capture_request_with_binding_hash_and_authority(
        operation_id: &str,
        event_id: &str,
        revocation_set: CanonicalRevocationSet,
        artifacts: Vec<String>,
        last_observed_revocation_index: Option<u64>,
        request_binding_hash: String,
        authority: Option<BudgetEventAuthority>,
    ) -> AdmissionCaptureRequest {
        AdmissionCaptureRequest::new(AdmissionCaptureRequestInput {
            operation_id: operation_id.to_string(),
            budget: BudgetCaptureInvocationRequest {
                capability_id: "leaf".to_string(),
                grant_index: 0,
                hold_id: Some("hold-1".to_string()),
                event_id: Some(event_id.to_string()),
                authority,
                admission_operation: Some(
                    BudgetAdmissionOperationBinding::new(
                        operation_id.to_string(),
                        request_binding_hash,
                    )
                    .expect("valid admission operation binding"),
                ),
            },
            revocation_set: revocation_set.clone(),
            bound_revocation_set_digest: revocation_set.digest().to_string(),
            authorization_artifact_digests: artifacts,
            aggregate_root_capability_id: None,
            aggregate_root_binding_digest: None,
            last_observed_revocation_index,
        })
        .expect("valid admission capture request")
    }

    fn quota_counts(path: &std::path::Path) -> (i64, i64) {
        Connection::open(path)
            .expect("open quota reader")
            .query_row(
                r#"
                SELECT reserved_invocations, captured_invocations
                FROM budget_invocation_quota_usage
                WHERE profile = 'chio.grant-invocation.v1'
                  AND owner_id = 'leaf'
                  AND grant_index_key = 0
                "#,
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("load quota counts")
    }

    fn combined_projection_bytes(
        request: &AdmissionCaptureRequest,
        authorized: &AuthorizedBudgetHold,
        decision: &AdmissionCaptureDecision,
    ) -> Vec<u8> {
        let AdmissionCaptureDecision::Captured { budget, metadata } = decision else {
            panic!("expected captured admission decision");
        };
        let projection = CombinedAdmissionCaptureReceiptProjection::from_capture(
            request, authorized, budget, metadata,
        )
        .expect("combined capture projection");
        chio_core::canonical::canonical_json_bytes(&projection)
            .expect("canonical combined capture projection")
    }

    #[test]
    fn captured_first_consumes_once_and_exact_retry_survives_revocation_and_restart() {
        let path = unique_db_path("chio-admission-captured-first");
        let artifacts = vec!["11".repeat(32)];
        authorize_hold(&path, artifacts.clone(), "operation-1");
        let request = capture_request(
            "operation-1",
            "capture-1",
            leaf_revocation_set(),
            artifacts,
            None,
        );

        let authority = SqliteAdmissionCaptureAuthority::open(&path).expect("open authority");
        let captured = authority
            .capture_admission(request.clone())
            .expect("capture admission");
        assert!(matches!(
            captured,
            AdmissionCaptureDecision::Captured { .. }
        ));
        assert_eq!(quota_counts(&path), (0, 1));
        assert_eq!(
            authority
                .capture_admission(request.clone())
                .expect("exact retry"),
            captured
        );
        assert!(!authority
            .revoke("leaf")
            .expect("route revocation")
            .was_present());
        assert_eq!(
            authority
                .capture_admission(request.clone())
                .expect("retry after revocation"),
            captured
        );
        drop(authority);

        let reopened = SqliteAdmissionCaptureAuthority::open(&path).expect("reopen authority");
        assert_eq!(
            reopened
                .capture_admission(request)
                .expect("retry after restart"),
            captured
        );
        assert_eq!(quota_counts(&path), (0, 1));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn combined_capture_projection_is_byte_identical_on_exact_retry_query_and_reopen() {
        let path = unique_db_path("chio-admission-capture-projection-replay");
        let artifacts = vec!["11".repeat(32)];
        let authority_identity = fenced_authority();
        let authorized = authorize_hold_with_authority(
            &path,
            artifacts.clone(),
            "operation-projection",
            Some(authority_identity.clone()),
        );
        let request = capture_request_with_binding_hash_and_authority(
            "operation-projection",
            "capture-projection",
            leaf_revocation_set(),
            artifacts,
            None,
            admission_request_binding_hash(),
            Some(authority_identity),
        );

        let authority = SqliteAdmissionCaptureAuthority::open(&path).expect("open authority");
        let first = authority
            .capture_admission(request.clone())
            .expect("first capture");
        let first_bytes = combined_projection_bytes(&request, &authorized, &first);
        let queried = authority
            .query_admission_capture(&request)
            .expect("query exact capture")
            .expect("persisted exact capture");
        assert_eq!(
            combined_projection_bytes(&request, &authorized, &queried),
            first_bytes
        );
        let retried = authority
            .capture_admission(request.clone())
            .expect("exact capture retry");
        assert_eq!(
            combined_projection_bytes(&request, &authorized, &retried),
            first_bytes
        );
        drop(authority);

        let reopened = SqliteAdmissionCaptureAuthority::open(&path).expect("reopen authority");
        let reopened_query = reopened
            .query_admission_capture(&request)
            .expect("query capture after reopen")
            .expect("persisted capture after reopen");
        let recovered_authorized = authorize_hold_with_authority(
            &path,
            vec!["11".repeat(32)],
            "operation-projection",
            Some(fenced_authority()),
        );
        assert_eq!(recovered_authorized, authorized);
        assert_eq!(
            combined_projection_bytes(&request, &recovered_authorized, &reopened_query),
            first_bytes
        );
        let reopened_retry = reopened
            .capture_admission(request.clone())
            .expect("retry capture after reopen");
        assert_eq!(
            combined_projection_bytes(&request, &authorized, &reopened_retry),
            first_bytes
        );
        assert_eq!(quota_counts(&path), (0, 1));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn combined_capture_requires_exact_persisted_admission_ownership() {
        let path = unique_db_path("chio-admission-operation-ownership");
        let artifacts = vec!["11".repeat(32)];
        authorize_hold(&path, artifacts.clone(), "operation-owner");
        let authority = SqliteAdmissionCaptureAuthority::open(&path).expect("open authority");

        let wrong_operation = capture_request(
            "operation-other",
            "capture-wrong-operation",
            leaf_revocation_set(),
            artifacts.clone(),
            None,
        );
        let error = authority
            .capture_admission(wrong_operation)
            .expect_err("a different operation must not capture the hold");
        assert!(error.to_string().contains("operation_id"), "{error}");

        let wrong_hash = capture_request_with_binding_hash(
            "operation-owner",
            "capture-wrong-hash",
            leaf_revocation_set(),
            artifacts.clone(),
            None,
            "44".repeat(32),
        );
        let error = authority
            .capture_admission(wrong_hash)
            .expect_err("a different request hash must not capture the hold");
        assert!(
            error.to_string().contains("request_binding_hash"),
            "{error}"
        );
        assert_eq!(quota_counts(&path), (1, 0));

        let exact = capture_request(
            "operation-owner",
            "capture-owned",
            leaf_revocation_set(),
            artifacts,
            None,
        );
        let captured = authority
            .capture_admission(exact.clone())
            .expect("capture with exact ownership");
        assert_eq!(
            authority
                .capture_admission(exact)
                .expect("exact ownership retry"),
            captured
        );
        let connection = Connection::open(&path).expect("open ownership reader");
        for table in [
            "budget_mutation_events",
            "budget_composite_mutation_snapshots",
            "admission_capture_events",
        ] {
            let sql = format!(
                "SELECT operation_id, request_binding_hash FROM {table} WHERE {} = ?1",
                if table == "admission_capture_events" {
                    "capture_event_id"
                } else {
                    "event_id"
                }
            );
            let owner = connection
                .query_row(&sql, params!["capture-owned"], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .expect("load persisted capture ownership");
            assert_eq!(
                owner,
                (
                    "operation-owner".to_string(),
                    admission_request_binding_hash()
                )
            );
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn revoked_first_denies_without_consuming_reserved_quota() {
        let path = unique_db_path("chio-admission-revoked-first");
        let artifacts = vec!["11".repeat(32)];
        authorize_hold(&path, artifacts.clone(), "operation-1");
        let authority = SqliteAdmissionCaptureAuthority::open(&path).expect("open authority");
        let write = authority.revoke("leaf").expect("route revocation");
        assert!(!write.was_present());
        let request = capture_request(
            "operation-1",
            "capture-1",
            leaf_revocation_set(),
            artifacts,
            Some(write.revocation_commit_index()),
        );

        let denied = authority
            .capture_admission(request.clone())
            .expect("deny admission");
        let AdmissionCaptureDecision::Denied(denial) = &denied else {
            panic!("expected revoked denial");
        };
        assert_eq!(denial.revoked_ids(), &["leaf".to_string()]);
        assert_eq!(quota_counts(&path), (1, 0));
        assert_eq!(
            authority
                .capture_admission(request.clone())
                .expect("exact retry"),
            denied
        );
        assert_eq!(quota_counts(&path), (1, 0));
        drop(authority);
        let reopened = SqliteAdmissionCaptureAuthority::open(&path).expect("reopen authority");
        assert_eq!(
            reopened
                .capture_admission(request)
                .expect("exact denial retry after restart"),
            denied
        );
        assert_eq!(quota_counts(&path), (1, 0));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn mismatched_bindings_and_ahead_head_mutate_nothing() {
        let path = unique_db_path("chio-admission-binding-mismatch");
        authorize_hold(&path, vec!["11".repeat(32)], "operation-binding");
        let authority = SqliteAdmissionCaptureAuthority::open(&path).expect("open authority");

        let artifact_mismatch = capture_request(
            "operation-binding",
            "capture-artifact",
            leaf_revocation_set(),
            vec!["22".repeat(32)],
            None,
        );
        assert!(matches!(
            authority.capture_admission(artifact_mismatch),
            Err(AdmissionCaptureError::BudgetStore(_))
        ));
        let set_mismatch = capture_request(
            "operation-binding",
            "capture-set",
            extended_revocation_set(),
            vec!["11".repeat(32)],
            None,
        );
        assert!(matches!(
            authority.capture_admission(set_mismatch),
            Err(AdmissionCaptureError::BudgetStore(_))
        ));
        let ahead = capture_request(
            "operation-binding",
            "capture-ahead",
            leaf_revocation_set(),
            vec!["11".repeat(32)],
            Some(1),
        );
        assert!(matches!(
            authority.capture_admission(ahead),
            Err(AdmissionCaptureError::InvalidRequest(_))
        ));
        assert_eq!(quota_counts(&path), (1, 0));
        let operation_count: i64 = Connection::open(&path)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM admission_capture_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(operation_count, 0);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn combined_mode_backfills_and_fences_ordinary_revocation_writers() {
        let path = unique_db_path("chio-admission-writer-fence");
        let ordinary = SqliteRevocationStore::open(&path).expect("open ordinary store");
        ordinary
            .upsert_revocation(&RevocationRecord {
                capability_id: "cap-b".to_string(),
                revoked_at: 20,
            })
            .expect("insert legacy revocation");
        ordinary
            .upsert_revocation(&RevocationRecord {
                capability_id: "cap-a".to_string(),
                revoked_at: 10,
            })
            .expect("insert legacy revocation");
        ordinary
            .upsert_revocation(&RevocationRecord {
                capability_id: "cap-c".to_string(),
                revoked_at: 20,
            })
            .expect("insert legacy revocation");

        let authority = SqliteAdmissionCaptureAuthority::open(&path).expect("open authority");
        let rows = Connection::open(&path)
            .unwrap()
            .prepare(
                "SELECT capability_id, revocation_commit_index FROM admission_revocation_commits ORDER BY revocation_commit_index",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![
                ("cap-a".to_string(), 1),
                ("cap-b".to_string(), 2),
                ("cap-c".to_string(), 3),
            ]
        );

        let managed = SqliteRevocationStore::open(&path).expect("open managed reader");
        assert!(managed
            .is_revoked("cap-a")
            .expect("read managed revocation"));
        assert!(managed.revoke("managed-write").is_err());
        assert!(ordinary.revoke("ordinary-write").is_err());
        assert!(ordinary
            .upsert_revocation(&RevocationRecord {
                capability_id: "cap-a".to_string(),
                revoked_at: 99,
            })
            .is_err());
        let direct = Connection::open(&path).unwrap().execute(
            "INSERT INTO revoked_capabilities (capability_id, revoked_at) VALUES (?1, ?2)",
            params!["direct-write", 30_i64],
        );
        assert!(direct.is_err());
        assert!(!authority
            .revoke("routed-write")
            .expect("routed write")
            .was_present());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn routed_revocation_upsert_preserves_timestamps_indices_and_exact_outcomes() {
        let path = unique_db_path("chio-admission-routed-upsert");
        let authority = SqliteAdmissionCaptureAuthority::open(&path).expect("open authority");
        let first_record = RevocationRecord {
            capability_id: "cap-import".to_string(),
            revoked_at: 10,
        };
        let first = authority
            .upsert_revocation(&first_record)
            .expect("insert timestamped revocation");
        assert!(!first.was_present());
        assert!(first.changed());
        assert_eq!(first.revoked_at(), 10);
        assert_eq!(first.revocation_commit_index(), 1);
        assert_eq!(
            authority
                .upsert_revocation(&first_record)
                .expect("exact first retry"),
            first
        );

        let advanced_record = RevocationRecord {
            capability_id: "cap-import".to_string(),
            revoked_at: 20,
        };
        let advanced = authority
            .upsert_revocation(&advanced_record)
            .expect("advance timestamp");
        assert!(advanced.was_present());
        assert!(advanced.changed());
        assert_eq!(advanced.revoked_at(), 20);
        assert_eq!(
            advanced.revocation_commit_index(),
            first.revocation_commit_index()
        );
        assert!(advanced.authority_commit_index() > first.authority_commit_index());

        let stale_record = RevocationRecord {
            capability_id: "cap-import".to_string(),
            revoked_at: 15,
        };
        let stale = authority
            .upsert_revocation(&stale_record)
            .expect("merge stale timestamp");
        assert!(stale.was_present());
        assert!(!stale.changed());
        assert_eq!(stale.revoked_at(), 20);
        assert_eq!(
            stale.revocation_commit_index(),
            first.revocation_commit_index()
        );
        assert!(stale.authority_commit_index() > advanced.authority_commit_index());
        assert_eq!(authority.revocation_head().unwrap(), 1);
        assert_eq!(authority.authority_head().unwrap(), 3);
        drop(authority);

        let reopened = SqliteAdmissionCaptureAuthority::open(&path).expect("reopen authority");
        assert_eq!(
            reopened
                .upsert_revocation(&first_record)
                .expect("retry old input after restart"),
            first
        );
        assert_eq!(
            reopened
                .upsert_revocation(&advanced_record)
                .expect("retry advanced input after restart"),
            advanced
        );
        assert_eq!(
            reopened
                .upsert_revocation(&stale_record)
                .expect("retry stale input after restart"),
            stale
        );
        let stored_at: i64 = Connection::open(&path)
            .unwrap()
            .query_row(
                "SELECT revoked_at FROM revoked_capabilities WHERE capability_id = 'cap-import'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_at, 20);
        assert_eq!(reopened.revocation_head().unwrap(), 1);
        assert_eq!(reopened.authority_head().unwrap(), 3);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn separate_database_paths_are_rejected_before_combined_mode_is_installed() {
        let budget_path = unique_db_path("chio-admission-budget-path");
        let revocation_path = unique_db_path("chio-admission-revocation-path");
        assert!(matches!(
            SqliteAdmissionCaptureAuthority::open_with_paths(&budget_path, &revocation_path),
            Err(AdmissionCaptureError::InvalidRequest(_))
        ));
        assert!(!budget_path.exists());
        assert!(!revocation_path.exists());
        assert!(matches!(
            SqliteAdmissionCaptureAuthority::open(":memory:"),
            Err(AdmissionCaptureError::InvalidRequest(_))
        ));
    }

    #[test]
    fn rolled_back_routed_write_restores_writer_fencing() {
        let path = unique_db_path("chio-admission-trigger-rollback");
        let authority = SqliteAdmissionCaptureAuthority::open(&path).expect("open authority");
        {
            let mut connection = authority.connection.lock().expect("lock authority");
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("begin routed write");
            transaction
                .execute_batch(REMOVE_REVOCATION_WRITE_GUARDS)
                .expect("remove guards inside transaction");
            transaction
                .execute(
                    "INSERT INTO revoked_capabilities (capability_id, revoked_at) VALUES ('rolled-back', 1)",
                    [],
                )
                .expect("stage revocation");
            transaction.rollback().expect("roll back staged write");
        }

        let direct = Connection::open(&path).unwrap().execute(
            "INSERT INTO revoked_capabilities (capability_id, revoked_at) VALUES ('bypass', 2)",
            [],
        );
        assert!(direct.is_err());
        assert!(!authority.is_revoked("rolled-back").unwrap());
        assert!(!authority.is_revoked("bypass").unwrap());
        assert!(authority.revoke("routed").unwrap().changed());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn concurrent_capture_and_revocation_linearize_without_partial_quota_mutation() {
        let path = unique_db_path("chio-admission-race");
        let artifacts = vec!["11".repeat(32)];
        authorize_hold(&path, artifacts.clone(), "operation-race");
        let first =
            Arc::new(SqliteAdmissionCaptureAuthority::open(&path).expect("open first authority"));
        let second =
            Arc::new(SqliteAdmissionCaptureAuthority::open(&path).expect("open second authority"));
        let request = capture_request(
            "operation-race",
            "capture-race",
            leaf_revocation_set(),
            artifacts,
            None,
        );
        let barrier = Arc::new(Barrier::new(3));
        let capture_thread = {
            let authority = Arc::clone(&first);
            let barrier = Arc::clone(&barrier);
            let request = request.clone();
            thread::spawn(move || {
                barrier.wait();
                authority.capture_admission(request)
            })
        };
        let revoke_thread = {
            let authority = Arc::clone(&second);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                authority.revoke("leaf")
            })
        };
        barrier.wait();
        let decision = capture_thread.join().expect("capture thread").unwrap();
        let write = revoke_thread.join().expect("revoke thread").unwrap();
        assert!(!write.was_present());
        match decision {
            AdmissionCaptureDecision::Captured { metadata, .. } => {
                assert_eq!(quota_counts(&path), (0, 1));
                assert_eq!(metadata.revocation_commit_index(), 0);
                assert!(metadata.authority_commit_index() < write.authority_commit_index());
            }
            AdmissionCaptureDecision::Denied(denial) => {
                assert_eq!(quota_counts(&path), (1, 0));
                assert_eq!(
                    denial.metadata().revocation_commit_index(),
                    write.revocation_commit_index()
                );
                assert!(
                    denial.metadata().authority_commit_index() > write.authority_commit_index()
                );
            }
        }
        let _ = fs::remove_file(path);
    }
}

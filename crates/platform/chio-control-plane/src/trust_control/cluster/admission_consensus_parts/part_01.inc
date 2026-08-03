use super::*;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

const CONSENSUS_SCHEMA_VERSION: i64 = 3;
const ADMISSION_MEMBERSHIP_DOMAIN: &[u8] = b"chio.admission-membership.v1\0";
const ADMISSION_PROJECTION_BASELINE_DOMAIN: &[u8] = b"chio.admission-projection-baseline.v1\0";
const ADMISSION_OPERATION_DOMAIN: &[u8] = b"chio.admission-consensus-operation.v1\0";
const ADMISSION_APPLIED_STATE_DOMAIN: &[u8] = b"chio.admission-applied-state.v2\0";
const ADMISSION_SECURITY_PROJECTION_DOMAIN: &[u8] = b"chio.admission-security-projection.v1\0";
const MAX_ADMISSION_GENESIS_ROWS: usize = 1_000_000;
const MAX_ADMISSION_GENESIS_CELLS: usize = 24_000_000;
const MAX_ADMISSION_GENESIS_CELL_BYTES: usize = 1024 * 1024;
const MAX_ADMISSION_GENESIS_BYTES: usize = 48 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
struct AdmissionGenesisTableSpec {
    name: &'static str,
    columns: &'static [(&'static str, AdmissionGenesisValueType)],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionSecurityProjection {
    tables: Vec<AdmissionSecurityTable>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionSecurityTable {
    name: String,
    columns: Vec<AdmissionGenesisColumn>,
    rows: Vec<Vec<AdmissionGenesisValue>>,
}

use AdmissionGenesisValueType::{
    Blob as GenesisBlob, Integer as GenesisInteger, Text as GenesisText,
};

const ADMISSION_GENESIS_TABLES: &[AdmissionGenesisTableSpec] = &[
    AdmissionGenesisTableSpec {
        name: "admission_authority_commits",
        columns: &[
            ("authority_commit_index", GenesisInteger),
            ("kind", GenesisText),
            ("operation_id", GenesisText),
            ("capture_event_id", GenesisText),
            ("capability_id", GenesisText),
            ("revocation_commit_index", GenesisInteger),
            ("budget_commit_index", GenesisInteger),
            ("recorded_at", GenesisInteger),
        ],
    },
    AdmissionGenesisTableSpec {
        name: "admission_authority_meta",
        columns: &[
            ("singleton", GenesisInteger),
            ("mode", GenesisText),
            ("authority_commit_index", GenesisInteger),
            ("revocation_commit_index", GenesisInteger),
        ],
    },
    AdmissionGenesisTableSpec {
        name: "admission_capture_events",
        columns: &[
            ("operation_id", GenesisText),
            ("request_binding_hash", GenesisText),
            ("capture_event_id", GenesisText),
            ("hold_id", GenesisText),
            ("capability_id", GenesisText),
            ("grant_index", GenesisInteger),
            ("authority_id", GenesisText),
            ("lease_id", GenesisText),
            ("lease_epoch", GenesisInteger),
            ("revocation_set_digest", GenesisText),
            ("revocation_ids_json", GenesisText),
            ("artifact_digests_json", GenesisText),
            ("aggregate_root_capability_id", GenesisText),
            ("aggregate_root_binding_digest", GenesisText),
            ("last_observed_revocation_index", GenesisInteger),
            ("outcome", GenesisText),
            ("revoked_ids_json", GenesisText),
            ("revocation_commit_index", GenesisInteger),
            ("authority_commit_index", GenesisInteger),
            ("budget_commit_index", GenesisInteger),
            ("recorded_at", GenesisInteger),
        ],
    },
    AdmissionGenesisTableSpec {
        name: "admission_revocation_commits",
        columns: &[
            ("capability_id", GenesisText),
            ("revoked_at", GenesisInteger),
            ("revocation_commit_index", GenesisInteger),
            ("authority_commit_index", GenesisInteger),
        ],
    },
    AdmissionGenesisTableSpec {
        name: "admission_revocation_upsert_events",
        columns: &[
            ("capability_id", GenesisText),
            ("requested_revoked_at", GenesisInteger),
            ("was_present", GenesisInteger),
            ("changed", GenesisInteger),
            ("effective_revoked_at", GenesisInteger),
            ("revocation_commit_index", GenesisInteger),
            ("authority_commit_index", GenesisInteger),
            ("recorded_at", GenesisInteger),
        ],
    },
    AdmissionGenesisTableSpec {
        name: "budget_authorization_claims",
        columns: &[
            ("hold_id", GenesisText),
            ("event_id", GenesisText),
            ("capability_id", GenesisText),
            ("grant_index", GenesisInteger),
            ("requested_exposure_units", GenesisInteger),
            ("max_invocations", GenesisInteger),
            ("max_exposure_per_invocation", GenesisInteger),
            ("max_total_exposure_units", GenesisInteger),
            ("authority_id", GenesisText),
            ("lease_id", GenesisText),
            ("lease_epoch", GenesisInteger),
            ("allowed", GenesisInteger),
            ("created_at", GenesisInteger),
        ],
    },
    AdmissionGenesisTableSpec {
        name: "budget_authorization_holds",
        columns: &[
            ("hold_id", GenesisText),
            ("operation_id", GenesisText),
            ("request_binding_hash", GenesisText),
            ("capability_id", GenesisText),
            ("grant_index", GenesisInteger),
            ("authorized_exposure_units", GenesisInteger),
            ("remaining_exposure_units", GenesisInteger),
            ("invocation_count_debited", GenesisInteger),
            ("disposition", GenesisText),
            ("authority_id", GenesisText),
            ("lease_id", GenesisText),
            ("lease_epoch", GenesisInteger),
            ("created_at", GenesisInteger),
            ("updated_at", GenesisInteger),
            ("reserved_until", GenesisInteger),
            ("reserved_currency", GenesisText),
            ("reserved_payment_reference", GenesisText),
            ("reserved_budget_total", GenesisInteger),
            ("reserved_delegation_depth", GenesisInteger),
            ("reserved_root_budget_holder", GenesisText),
        ],
    },
    AdmissionGenesisTableSpec {
        name: "budget_composite_authorization_artifacts",
        columns: &[
            ("hold_id", GenesisText),
            ("position", GenesisInteger),
            ("artifact_digest", GenesisText),
        ],
    },
    AdmissionGenesisTableSpec {
        name: "budget_composite_authorization_quotas",
        columns: &[
            ("hold_id", GenesisText),
            ("position", GenesisInteger),
            ("profile", GenesisText),
            ("owner_id", GenesisText),
            ("grant_index_key", GenesisInteger),
            ("max_invocations", GenesisInteger),
            ("reserved_invocations_after", GenesisInteger),
            ("captured_invocations_after", GenesisInteger),
        ],
    },
    AdmissionGenesisTableSpec {
        name: "budget_composite_partition_escrow_evidence",
        columns: &[
            ("hold_id", GenesisText),
            ("evidence_digest", GenesisText),
            ("canonical_evidence", GenesisBlob),
        ],
    },
    AdmissionGenesisTableSpec {
        name: "budget_composite_authorizations",
        columns: &[
            ("hold_id", GenesisText),
            ("event_id", GenesisText),
            ("operation_id", GenesisText),
            ("request_binding_hash", GenesisText),
            ("capability_id", GenesisText),
            ("grant_index", GenesisInteger),
            ("requested_exposure_units", GenesisInteger),
            ("max_cost_per_invocation", GenesisInteger),
            ("max_total_cost_units", GenesisInteger),
            ("authority_id", GenesisText),
            ("lease_id", GenesisText),
            ("lease_epoch", GenesisInteger),
            ("allowed", GenesisInteger),
            ("invocation_state", GenesisText),
            ("monetary_state", GenesisText),
            ("revocation_set_digest", GenesisText),
            ("revocation_ids_json", GenesisText),
            ("aggregate_root_capability_id", GenesisText),
            ("aggregate_root_binding_digest", GenesisText),
            ("committed_cost_units_after", GenesisInteger),
            ("invocation_count_after", GenesisInteger),
            ("event_seq", GenesisInteger),
            ("created_at", GenesisInteger),
        ],
    },
    AdmissionGenesisTableSpec {
        name: "budget_composite_holds",
        columns: &[
            ("hold_id", GenesisText),
            ("operation_id", GenesisText),
            ("request_binding_hash", GenesisText),
            ("invocation_state", GenesisText),
            ("monetary_state", GenesisText),
            ("revocation_set_digest", GenesisText),
            ("revocation_ids_json", GenesisText),
            ("remaining_exposure_units", GenesisInteger),
            ("updated_at", GenesisInteger),
        ],
    },
    AdmissionGenesisTableSpec {
        name: "budget_composite_managed_grants",
        columns: &[
            ("capability_id", GenesisText),
            ("grant_index", GenesisInteger),
            ("first_hold_id", GenesisText),
        ],
    },
    AdmissionGenesisTableSpec {
        name: "budget_composite_mutation_quota_snapshots",
        columns: &[
            ("event_id", GenesisText),
            ("position", GenesisInteger),
            ("profile", GenesisText),
            ("owner_id", GenesisText),
            ("grant_index_key", GenesisInteger),
            ("max_invocations", GenesisInteger),
            ("reserved_invocations_after", GenesisInteger),
            ("captured_invocations_after", GenesisInteger),
        ],
    },
    AdmissionGenesisTableSpec {
        name: "budget_composite_mutation_snapshots",
        columns: &[
            ("event_id", GenesisText),
            ("operation_id", GenesisText),
            ("request_binding_hash", GenesisText),
            ("invocation_state", GenesisText),
            ("monetary_state", GenesisText),
            ("revocation_set_digest", GenesisText),
            ("revocation_ids_json", GenesisText),
        ],
    },
    AdmissionGenesisTableSpec {
        name: "budget_invocation_quota_usage",
        columns: &[
            ("profile", GenesisText),
            ("owner_id", GenesisText),
            ("grant_index_key", GenesisInteger),
            ("max_invocations", GenesisInteger),
            ("reserved_invocations", GenesisInteger),
            ("captured_invocations", GenesisInteger),
            ("updated_at", GenesisInteger),
            ("seq", GenesisInteger),
        ],
    },
    AdmissionGenesisTableSpec {
        name: "budget_mutation_events",
        columns: &[
            ("event_id", GenesisText),
            ("hold_id", GenesisText),
            ("operation_id", GenesisText),
            ("request_binding_hash", GenesisText),
            ("capability_id", GenesisText),
            ("grant_index", GenesisInteger),
            ("kind", GenesisText),
            ("allowed", GenesisInteger),
            ("recorded_at", GenesisInteger),
            ("event_seq", GenesisInteger),
            ("usage_seq", GenesisInteger),
            ("exposure_units", GenesisInteger),
            ("realized_spend_units", GenesisInteger),
            ("max_invocations", GenesisInteger),
            ("max_exposure_per_invocation", GenesisInteger),
            ("max_total_exposure_units", GenesisInteger),
            ("invocation_count_after", GenesisInteger),
            ("total_cost_exposed_after", GenesisInteger),
            ("total_cost_realized_spend_after", GenesisInteger),
            ("authority_id", GenesisText),
            ("lease_id", GenesisText),
            ("lease_epoch", GenesisInteger),
        ],
    },
    AdmissionGenesisTableSpec {
        name: "capability_grant_budgets",
        columns: &[
            ("capability_id", GenesisText),
            ("grant_index", GenesisInteger),
            ("invocation_count", GenesisInteger),
            ("updated_at", GenesisInteger),
            ("seq", GenesisInteger),
            ("total_cost_exposed", GenesisInteger),
            ("total_cost_realized_spend", GenesisInteger),
        ],
    },
    AdmissionGenesisTableSpec {
        name: "revoked_capabilities",
        columns: &[
            ("capability_id", GenesisText),
            ("revoked_at", GenesisInteger),
        ],
    },
];

const ADMISSION_GENESIS_EXCLUDED_TABLES: &[&str] = &[
    "chio_store_schema_versions",
    "payment_journal",
    "budget_replication_meta",
    "budget_import_floors",
    "budget_ack_head_watermark",
    "budget_origin_ack_heads",
    "budget_abandoned_event_seqs",
    "budget_abandoned_event_ranges",
];

const ADMISSION_SECURITY_PROJECTION_EXCLUSIONS: &[(&str, &str)] = &[
    ("admission_authority_commits", "recorded_at"),
    ("admission_capture_events", "recorded_at"),
    ("admission_revocation_upsert_events", "recorded_at"),
    ("budget_authorization_claims", "created_at"),
    ("budget_authorization_holds", "created_at"),
    ("budget_authorization_holds", "updated_at"),
    ("budget_composite_authorizations", "created_at"),
    ("budget_composite_holds", "updated_at"),
    ("budget_invocation_quota_usage", "updated_at"),
    ("budget_mutation_events", "recorded_at"),
    ("capability_grant_budgets", "updated_at"),
];

#[derive(Debug, thiserror::Error)]
pub(crate) enum AdmissionConsensusError {
    #[error("admission consensus storage failed: {0}")]
    Storage(#[from] rusqlite::Error),

    #[error("admission consensus protocol violation: {0}")]
    Protocol(String),

    #[error("admission consensus command application failed: {0}")]
    Apply(String),

    #[error("admission consensus command rejected: {message}")]
    Rejected { status_code: u16, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdmissionConsensusRejectionEnvelope {
    admission_consensus_rejection: AdmissionConsensusRejection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdmissionConsensusRejection {
    status_code: u16,
    code: String,
    message: String,
}

#[derive(Debug, Clone)]
pub(crate) struct AdmissionConsensusStore {
    path: PathBuf,
    read_only: bool,
    database_identity_file:
        Option<Arc<chio_store_sqlite::durable_sqlite::DurableSqliteFile>>,
}

#[derive(Debug, Clone)]
struct CommittedAdmissionOperationSnapshot {
    meta: AdmissionConsensusMetaView,
    read_barrier: Option<AdmissionCommitProof>,
    entry: Option<AdmissionLogEntry>,
    result_commit_proof: Option<AdmissionCommitProof>,
    result_commit_target: Option<AdmissionLogEntry>,
    result: Option<AdmissionConsensusResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmissionElection {
    pub(crate) term: u64,
    pub(crate) candidate_id: String,
    pub(crate) last_log_index: u64,
    pub(crate) last_log_term: u64,
    pub(crate) commit_index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmissionMembership {
    members: Vec<String>,
    digest: String,
    baseline_digest: Option<String>,
    genesis_projection: Option<AdmissionGenesisProjection>,
    quorum_size: usize,
}

impl AdmissionMembership {
    #[cfg(test)]
    pub(crate) fn new(members: Vec<String>) -> Result<Self, AdmissionConsensusError> {
        Self::new_with_baseline(members, None)
    }

    fn new_with_baseline(
        mut members: Vec<String>,
        baseline_digest: Option<&str>,
    ) -> Result<Self, AdmissionConsensusError> {
        for member in &members {
            validate_node_id(member)?;
        }
        members.sort();
        if members.is_empty() {
            return Err(AdmissionConsensusError::Protocol(
                "admission membership must contain at least one node".to_string(),
            ));
        }
        if members.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(AdmissionConsensusError::Protocol(
                "admission membership contains a duplicate node".to_string(),
            ));
        }
        if baseline_digest.is_some_and(|digest| !is_lower_sha256(digest)) {
            return Err(AdmissionConsensusError::Protocol(
                "admission projection baseline digest is invalid".to_string(),
            ));
        }
        let canonical = match baseline_digest {
            Some(baseline_digest) => canonical_json_bytes(&json!({
                "baselineDigest": baseline_digest,
                "members": members,
            })),
            None => canonical_json_bytes(&members),
        }
        .map_err(|error| {
            AdmissionConsensusError::Protocol(format!(
                "admission membership canonicalization failed: {error}"
            ))
        })?;
        let mut preimage = Vec::with_capacity(ADMISSION_MEMBERSHIP_DOMAIN.len() + canonical.len());
        preimage.extend_from_slice(ADMISSION_MEMBERSHIP_DOMAIN);
        preimage.extend_from_slice(&canonical);
        let quorum_size = members.len() / 2 + 1;
        Ok(Self {
            members,
            digest: sha256_hex(&preimage),
            baseline_digest: baseline_digest.map(str::to_string),
            genesis_projection: None,
            quorum_size,
        })
    }

    fn new_with_genesis(
        members: Vec<String>,
        genesis_projection: AdmissionGenesisProjection,
    ) -> Result<Self, AdmissionConsensusError> {
        let baseline_digest = admission_genesis_projection_digest(&genesis_projection)?;
        let mut membership = Self::new_with_baseline(members, Some(&baseline_digest))?;
        membership.genesis_projection = Some(genesis_projection);
        Ok(membership)
    }

    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }

    fn quorum_size(&self) -> usize {
        self.quorum_size
    }

    fn contains(&self, node_id: &str) -> bool {
        self.members
            .binary_search_by(|member| member.as_str().cmp(node_id))
            .is_ok()
    }
}

impl AdmissionConsensusStore {
    pub(crate) fn open(path: impl AsRef<Path>) -> Result<Self, AdmissionConsensusError> {
        let path = path.as_ref().to_path_buf();
        if path.as_os_str().is_empty() || path == Path::new(":memory:") {
            return Err(AdmissionConsensusError::Protocol(
                "admission consensus requires a persistent SQLite file".to_string(),
            ));
        }
        let mut connection = Connection::open(&path)?;
        configure_connection(&connection)?;
        initialize_schema(&mut connection)?;
        Ok(Self {
            path,
            read_only: false,
            database_identity_file: None,
        })
    }

    pub(crate) fn open_existing(path: impl AsRef<Path>) -> Result<Self, AdmissionConsensusError> {
        let path = path.as_ref().to_path_buf();
        if path.as_os_str().is_empty() || path == Path::new(":memory:") {
            return Err(AdmissionConsensusError::Protocol(
                "admission consensus requires a persistent SQLite file".to_string(),
            ));
        }
        let connection = Connection::open(&path)?;
        configure_connection(&connection)?;
        load_meta(&connection)?;
        validate_consensus_result_schema(&connection)?;
        Ok(Self {
            path,
            read_only: false,
            database_identity_file: None,
        })
    }

    pub(crate) fn open_existing_read_only(
        path: impl AsRef<Path>,
    ) -> Result<Self, AdmissionConsensusError> {
        let path = path.as_ref().to_path_buf();
        validate_existing_consensus_file(&path)?;
        let directory = chio_store_sqlite::durable_sqlite::TrustedSqliteDirectory::open_for_database(
            &path,
        )
        .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
        let database_identity_file = directory
            .open_existing_database_read_only(&path)
            .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
        let connection = database_identity_file
            .open_read_only_connection()
            .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
        configure_read_only_consensus_connection(&connection)?;
        validate_read_only_consensus_connection(&connection)?;
        Ok(Self {
            path,
            read_only: true,
            database_identity_file: Some(database_identity_file),
        })
    }

    pub(crate) fn validate_integrity(&self) -> Result<(), AdmissionConsensusError> {
        let connection = self.connection()?;
        validate_integrity(&connection)
    }

    pub(crate) fn meta(&self) -> Result<AdmissionConsensusMetaView, AdmissionConsensusError> {
        let connection = self.connection()?;
        load_meta(&connection)
    }

    fn committed_operation_snapshot(
        &self,
        operation_id: &str,
    ) -> Result<CommittedAdmissionOperationSnapshot, AdmissionConsensusError> {
        validate_operation_id(operation_id)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        validate_integrity(&transaction)?;
        let meta = load_meta(&transaction)?;
        let read_barrier = if meta.commit_index == 0 {
            None
        } else {
            Some(load_commit_proof(&transaction, meta.commit_index)?.ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "admission committed read barrier proof is missing".to_string(),
                )
            })?)
        };
        let entry = load_entry_by_operation(&transaction, operation_id)?;
        if let Some(entry) = entry.as_ref() {
            validate_entry(entry)?;
        }
        let result = load_result(&transaction, operation_id)?;
        if let Some(result) = result.as_ref() {
            validate_canonical_json(&result.response_json, "admission persisted result")?;
            if sha256_hex(result.response_json.as_bytes()) != result.response_digest
                || !is_lower_sha256(&result.security_projection_digest)
                || entry.as_ref().is_none_or(|entry| {
                    entry.index != result.log_index || entry.operation_id != result.operation_id
                })
            {
                return Err(AdmissionConsensusError::Protocol(
                    "admission persisted result does not match its entry or digest".to_string(),
                ));
            }
        }
        let result_commit_proof = match entry.as_ref() {
            Some(entry) => load_commit_proof(&transaction, entry.index)?,
            None => None,
        };
        let result_commit_target = match result_commit_proof.as_ref() {
            Some(proof) => Some(
                load_entry(&transaction, proof.current_term_commit_index)?.ok_or_else(|| {
                    AdmissionConsensusError::Protocol(
                        "admission result commit proof target is missing".to_string(),
                    )
                })?,
            ),
            None => None,
        };
        transaction.rollback()?;
        Ok(CommittedAdmissionOperationSnapshot {
            meta,
            read_barrier,
            entry,
            result_commit_proof,
            result_commit_target,
            result,
        })
    }

    fn genesis_projection(
        &self,
    ) -> Result<Option<AdmissionGenesisProjection>, AdmissionConsensusError> {
        let connection = self.connection()?;
        load_genesis_projection(&connection)
    }

    pub(crate) fn bind_membership(
        &self,
        membership: &AdmissionMembership,
    ) -> Result<(), AdmissionConsensusError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        bind_membership(&transaction, membership)?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn validate_membership_proofs(
        &self,
        membership: &AdmissionMembership,
    ) -> Result<(), AdmissionConsensusError> {
        let connection = self.connection()?;
        let meta = load_meta(&connection)?;
        if meta.membership_digest.as_deref() != Some(membership.digest()) {
            return Err(AdmissionConsensusError::Protocol(
                "admission persisted membership differs from configured membership".to_string(),
            ));
        }
        if meta
            .voted_for
            .as_deref()
            .is_some_and(|candidate| !membership.contains(candidate))
        {
            return Err(AdmissionConsensusError::Protocol(
                "admission persisted vote is not a configured member".to_string(),
            ));
        }
        for index in 1..=meta.commit_index {
            let proof = load_commit_proof(&connection, index)?.ok_or_else(|| {
                AdmissionConsensusError::Protocol(format!(
                    "admission commit proof {index} is missing"
                ))
            })?;
            validate_commit_proof_for_membership(&proof, membership)?;
        }
        Ok(())
    }

    pub(crate) fn begin_election(
        &self,
        membership: &AdmissionMembership,
        candidate_id: &str,
    ) -> Result<AdmissionElection, AdmissionConsensusError> {
        validate_node_id(candidate_id)?;
        if !membership.contains(candidate_id) {
            return Err(AdmissionConsensusError::Protocol(
                "admission candidate is not a configured member".to_string(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_integrity(&transaction)?;
        let meta = bind_membership(&transaction, membership)?;
        let term = meta.current_term.checked_add(1).ok_or_else(|| {
            AdmissionConsensusError::Protocol("admission term overflow".to_string())
        })?;
        transaction.execute(
            r#"
            UPDATE admission_consensus_meta
            SET current_term = ?1, voted_for = ?2
            WHERE singleton = 1 AND current_term = ?3
            "#,
            params![
                sqlite_u64(term)?,
                candidate_id,
                sqlite_u64(meta.current_term)?
            ],
        )?;
        transaction.commit()?;
        Ok(AdmissionElection {
            term,
            candidate_id: candidate_id.to_string(),
            last_log_index: meta.last_log_index,
            last_log_term: meta.last_log_term,
            commit_index: meta.commit_index,
        })
    }

    pub(crate) fn request_vote(
        &self,
        membership: &AdmissionMembership,
        request: &AdmissionRequestVoteRequest,
    ) -> Result<AdmissionRequestVoteResponse, AdmissionConsensusError> {
        if request.protocol_version != ADMISSION_CONSENSUS_PROTOCOL_VERSION
            || request.membership_digest != membership.digest()
            || request.term > i64::MAX as u64
            || validate_node_id(&request.candidate_id).is_err()
            || !membership.contains(&request.candidate_id)
        {
            let connection = self.connection()?;
            let meta = load_meta(&connection)?;
            return Ok(vote_response(membership, meta.current_term, false));
        }
        self.observe_higher_term_for_membership(membership, request.term)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_integrity(&transaction)?;
        let meta = bind_membership(&transaction, membership)?;
        if request.term < meta.current_term {
            transaction.rollback()?;
            return Ok(vote_response(membership, meta.current_term, false));
        }
        let log_is_current = (request.last_log_term, request.last_log_index)
            >= (meta.last_log_term, meta.last_log_index);
        let commit_is_current = request.commit_index >= meta.commit_index;
        let vote_available = meta
            .voted_for
            .as_deref()
            .is_none_or(|candidate| candidate == request.candidate_id);
        let granted = log_is_current && commit_is_current && vote_available;
        if granted {
            transaction.execute(
                "UPDATE admission_consensus_meta SET voted_for = ?1 WHERE singleton = 1",
                params![request.candidate_id],
            )?;
        }
        transaction.commit()?;
        Ok(vote_response(membership, meta.current_term, granted))
    }

    pub(crate) fn build_entry<T: Serialize>(
        election: &AdmissionElection,
        operation_id: &str,
        command_kind: AdmissionCommandKind,
        command: &T,
    ) -> Result<AdmissionLogEntry, AdmissionConsensusError> {
        validate_operation_id(operation_id)?;
        let index = election.last_log_index.checked_add(1).ok_or_else(|| {
            AdmissionConsensusError::Protocol("admission log index overflow".to_string())
        })?;
        let command_bytes = canonical_json_bytes(command).map_err(|error| {
            AdmissionConsensusError::Protocol(format!(
                "admission command canonicalization failed: {error}"
            ))
        })?;
        let canonical_command = String::from_utf8(command_bytes.clone()).map_err(|_| {
            AdmissionConsensusError::Protocol(
                "admission canonical command was not UTF-8".to_string(),
            )
        })?;
        Ok(AdmissionLogEntry {
            index,
            leader_epoch: election.term,
            operation_id: operation_id.to_string(),
            command_kind,
            canonical_command,
            command_digest: sha256_hex(&command_bytes),
        })
    }

    pub(crate) fn append_local(
        &self,
        election: &AdmissionElection,
        entry: &AdmissionLogEntry,
    ) -> Result<(), AdmissionConsensusError> {
        validate_entry(entry)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let meta = load_meta(&transaction)?;
        if meta.current_term != election.term
            || meta.voted_for.as_deref() != Some(election.candidate_id.as_str())
            || entry.leader_epoch != election.term
        {
            return Err(AdmissionConsensusError::Protocol(
                "admission leader epoch changed before local append".to_string(),
            ));
        }
        if let Some(existing) = load_entry_by_operation(&transaction, &entry.operation_id)? {
            if existing == *entry {
                transaction.rollback()?;
                return Ok(());
            }
            return Err(AdmissionConsensusError::Protocol(format!(
                "admission operation `{}` was reused for a different log entry",
                entry.operation_id
            )));
        }
        if entry.index != checked_successor(meta.last_log_index, "admission local log index")? {
            return Err(AdmissionConsensusError::Protocol(
                "admission local append is not the next exact log index".to_string(),
            ));
        }
        insert_entry(&transaction, entry)?;
        update_log_head(&transaction, entry.index, entry.leader_epoch)?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn observe_higher_term(&self, term: u64) -> Result<(), AdmissionConsensusError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let meta = load_meta(&transaction)?;
        if term > meta.current_term {
            transaction.execute(
                r#"
                UPDATE admission_consensus_meta
                SET current_term = ?1, voted_for = NULL
                WHERE singleton = 1
                "#,
                params![sqlite_u64(term)?],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn observe_higher_term_for_membership(
        &self,
        membership: &AdmissionMembership,
        term: u64,
    ) -> Result<(), AdmissionConsensusError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let meta = bind_membership(&transaction, membership)?;
        if term > meta.current_term {
            transaction.execute(
                r#"
                UPDATE admission_consensus_meta
                SET current_term = ?1, voted_for = NULL
                WHERE singleton = 1
                "#,
                params![sqlite_u64(term)?],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn append_entries<F>(
        &self,
        membership: &AdmissionMembership,
        request: &AdmissionAppendEntriesRequest,
        mut apply: F,
    ) -> Result<AdmissionAppendEntriesResponse, AdmissionConsensusError>
    where
        F: FnMut(
            &Transaction<'_>,
            &AdmissionLogEntry,
            &AdmissionCommitProof,
        ) -> Result<String, String>,
    {
        if request.protocol_version != ADMISSION_CONSENSUS_PROTOCOL_VERSION
            || request.membership_digest != membership.digest()
            || request.term > i64::MAX as u64
            || validate_node_id(&request.leader_id).is_err()
            || !membership.contains(&request.leader_id)
        {
            let connection = self.connection()?;
            let meta = load_meta(&connection)?;
            return Ok(append_rejection(
                membership,
                &meta,
                "unsupported admission consensus protocol",
            ));
        }
        self.observe_higher_term_for_membership(membership, request.term)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_integrity(&transaction)?;
        let mut meta = bind_membership(&transaction, membership)?;
        if request.term < meta.current_term {
            transaction.rollback()?;
            return Ok(append_rejection(
                membership,
                &meta,
                "stale admission leader term",
            ));
        }
        transaction.execute_batch("SAVEPOINT chio_admission_append")?;
        if meta.voted_for.as_deref() != Some(request.leader_id.as_str()) {
            transaction.execute(
                "UPDATE admission_consensus_meta SET voted_for = ?1 WHERE singleton = 1",
                params![&request.leader_id],
            )?;
            meta.voted_for = Some(request.leader_id.clone());
        }
        if !previous_entry_matches(
            &transaction,
            request.previous_log_index,
            request.previous_log_term,
        )? {
            return reject_append_after_hard_state(
                transaction,
                membership,
                "admission previous log entry mismatch",
            );
        }
        if let Some(entry) = request.entry.as_ref() {
            if validate_entry(entry).is_err()
                || entry.leader_epoch > request.term
                || entry.index
                    != checked_successor(
                        request.previous_log_index,
                        "admission previous log index",
                    )?
            {
                return reject_append_after_hard_state(
                    transaction,
                    membership,
                    "invalid admission log entry",
                );
            }
            if let Some(existing) = load_entry(&transaction, entry.index)? {
                if existing != *entry {
                    if entry.index <= meta.commit_index || existing.leader_epoch >= request.term {
                        return reject_append_after_hard_state(
                            transaction,
                            membership,
                            "conflicting admission entry digest or identity",
                        );
                    }
                    transaction.execute(
                        "DELETE FROM admission_consensus_results WHERE log_index >= ?1",
                        params![sqlite_u64(entry.index)?],
                    )?;
                    transaction.execute(
                        "DELETE FROM admission_consensus_commits WHERE log_index >= ?1",
                        params![sqlite_u64(entry.index)?],
                    )?;
                    transaction.execute(
                        "DELETE FROM admission_consensus_log WHERE log_index >= ?1",
                        params![sqlite_u64(entry.index)?],
                    )?;
                    insert_entry(&transaction, entry)?;
                    update_log_head(&transaction, entry.index, entry.leader_epoch)?;
                    meta.last_log_index = entry.index;
                    meta.last_log_term = entry.leader_epoch;
                }
            } else {
                if entry.index
                    != checked_successor(meta.last_log_index, "admission follower log index")?
                    || load_entry_by_operation(&transaction, &entry.operation_id)?.is_some()
                {
                    return reject_append_after_hard_state(
                        transaction,
                        membership,
                        "admission entry is not the next unique log operation",
                    );
                }
                insert_entry(&transaction, entry)?;
                update_log_head(&transaction, entry.index, entry.leader_epoch)?;
                meta.last_log_index = entry.index;
                meta.last_log_term = entry.leader_epoch;
            }
        }
        if request.leader_commit < meta.commit_index || request.leader_commit > meta.last_log_index
        {
            return reject_append_after_hard_state(
                transaction,
                membership,
                "invalid admission leader commit index",
            );
        }
        if request.leader_commit > meta.commit_index {
            let Some(proof) = request.commit_proof.as_ref() else {
                return reject_append_after_hard_state(
                    transaction,
                    membership,
                    "admission commit proof is missing",
                );
            };
            if validate_commit_proof_for_membership(proof, membership).is_err()
                || proof.index != request.leader_commit
                || proof.index
                    != checked_successor(meta.commit_index, "admission follower commit index")?
                || proof.leader_epoch > request.term
                || load_entry(&transaction, proof.current_term_commit_index)?
                    .is_none_or(|entry| entry.leader_epoch != proof.leader_epoch)
                || load_entry(&transaction, proof.index)?
                    .is_none_or(|entry| entry.leader_epoch > proof.leader_epoch)
            {
                return reject_append_after_hard_state(
                    transaction,
                    membership,
                    "invalid admission commit proof",
                );
            }
            insert_commit_proof(&transaction, proof)?;
            transaction.execute(
                "UPDATE admission_consensus_meta SET commit_index = ?1 WHERE singleton = 1",
                params![sqlite_u64(request.leader_commit)?],
            )?;
            meta.commit_index = request.leader_commit;
        }
        transaction.execute_batch("RELEASE chio_admission_append")?;
        transaction.commit()?;
        let applied_index = self.apply_committed(&mut apply)?;
        let meta = self.meta()?;
        Ok(AdmissionAppendEntriesResponse {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            term: meta.current_term,
            accepted: true,
            match_index: meta.last_log_index,
            commit_index: meta.commit_index,
            applied_index,
            applied_state_digest: meta.applied_state_digest,
            rejection: None,
        })
    }

    pub(crate) fn commit_local<F>(
        &self,
        membership: &AdmissionMembership,
        election: &AdmissionElection,
        proof: &AdmissionCommitProof,
        mut apply: F,
    ) -> Result<AdmissionConsensusResult, AdmissionConsensusError>
    where
        F: FnMut(
            &Transaction<'_>,
            &AdmissionLogEntry,
            &AdmissionCommitProof,
        ) -> Result<String, String>,
    {
        validate_commit_proof_for_membership(proof, membership)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_integrity(&transaction)?;
        let meta = bind_membership(&transaction, membership)?;
        if meta.current_term != election.term
            || meta.voted_for.as_deref() != Some(election.candidate_id.as_str())
            || proof.leader_epoch != election.term
            || proof.leader_id != election.candidate_id
            || proof.index != checked_successor(meta.commit_index, "admission leader commit index")?
            || proof.index > meta.last_log_index
            || load_entry(&transaction, proof.current_term_commit_index)?
                .is_none_or(|entry| entry.leader_epoch != proof.leader_epoch)
        {
            return Err(AdmissionConsensusError::Protocol(
                "admission leader epoch changed before commit".to_string(),
            ));
        }
        let entry = load_entry(&transaction, proof.index)?.ok_or_else(|| {
            AdmissionConsensusError::Protocol("admission commit entry is missing".to_string())
        })?;
        if entry.leader_epoch > proof.leader_epoch {
            return Err(AdmissionConsensusError::Protocol(
                "admission commit term predates the log entry".to_string(),
            ));
        }
        insert_commit_proof(&transaction, proof)?;
        transaction.execute(
            "UPDATE admission_consensus_meta SET commit_index = ?1 WHERE singleton = 1",
            params![sqlite_u64(proof.index)?],
        )?;
        transaction.commit()?;
        self.apply_committed(&mut apply)?;
        self.result_for_operation(&entry.operation_id)?
            .ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "committed admission operation has no applied result".to_string(),
                )
            })
    }

    pub(crate) fn recheck_elected_epoch(
        &self,
        membership: &AdmissionMembership,
        election: &AdmissionElection,
    ) -> Result<bool, AdmissionConsensusError> {
        let meta = self.meta()?;
        Ok(meta.current_term == election.term
            && meta.membership_digest.as_deref() == Some(membership.digest())
            && meta.voted_for.as_deref() == Some(election.candidate_id.as_str()))
    }

    pub(crate) fn result_for_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<AdmissionConsensusResult>, AdmissionConsensusError> {
        let connection = self.connection()?;
        let Some(result) = load_result(&connection, operation_id)? else {
            return Ok(None);
        };
        validate_canonical_json(&result.response_json, "admission persisted result")?;
        if sha256_hex(result.response_json.as_bytes()) != result.response_digest
            || !is_lower_sha256(&result.security_projection_digest)
            || load_entry(&connection, result.log_index)?
                .is_none_or(|entry| entry.operation_id != result.operation_id)
        {
            return Err(AdmissionConsensusError::Protocol(
                "admission persisted result does not match its entry or digest".to_string(),
            ));
        }
        Ok(Some(result))
    }

    pub(crate) fn entry_for_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<AdmissionLogEntry>, AdmissionConsensusError> {
        validate_operation_id(operation_id)?;
        let connection = self.connection()?;
        load_entry_by_operation(&connection, operation_id)
    }

    fn entry_at(&self, index: u64) -> Result<AdmissionLogEntry, AdmissionConsensusError> {
        let connection = self.connection()?;
        load_entry(&connection, index)?.ok_or_else(|| {
            AdmissionConsensusError::Protocol(format!("admission log entry {index} is missing"))
        })
    }

    fn proof_at(&self, index: u64) -> Result<AdmissionCommitProof, AdmissionConsensusError> {
        let connection = self.connection()?;
        load_commit_proof(&connection, index)?.ok_or_else(|| {
            AdmissionConsensusError::Protocol(format!("admission commit proof {index} is missing"))
        })
    }

    pub(crate) fn snapshot(&self) -> Result<AdmissionConsensusSnapshot, AdmissionConsensusError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        validate_integrity(&transaction)?;
        let meta = load_meta(&transaction)?;
        if meta.last_applied != meta.commit_index {
            return Err(AdmissionConsensusError::Protocol(
                "admission consensus snapshot is temporarily unavailable until the committed prefix is fully applied"
                    .to_string(),
            ));
        }
        let genesis_projection = load_genesis_projection(&transaction)?;
        let entries = load_all_entries(&transaction)?;
        let commit_proofs = load_commit_proofs(&transaction)?;
        if commit_proofs
            .iter()
            .any(|proof| proof.current_term_commit_index > meta.commit_index)
        {
            return Err(AdmissionConsensusError::Protocol(
                "admission consensus snapshot is temporarily unavailable until its current-term commit target is durable"
                    .to_string(),
            ));
        }
        let results = load_results(&transaction)?;
        let snapshot = AdmissionConsensusSnapshot {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            meta,
            genesis_projection,
            entries,
            commit_proofs,
            results,
        };
        validate_snapshot(&snapshot)?;
        transaction.commit()?;
        Ok(snapshot)
    }

    pub(crate) fn install_snapshot<F>(
        &self,
        membership: &AdmissionMembership,
        snapshot: &AdmissionConsensusSnapshot,
        mut apply: F,
    ) -> Result<(), AdmissionConsensusError>
    where
        F: FnMut(
            &Transaction<'_>,
            &AdmissionLogEntry,
            &AdmissionCommitProof,
        ) -> Result<String, String>,
    {
        validate_snapshot_for_membership(snapshot, membership)?;
        self.observe_higher_term(snapshot.meta.current_term)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let local = load_meta(&transaction)?;
        if local.last_log_index != 0 || local.commit_index != 0 || local.last_applied != 0 {
            transaction.rollback()?;
            if snapshot.meta.current_term > local.current_term {
                self.observe_higher_term(snapshot.meta.current_term)?;
            }
            let existing = self.snapshot()?;
            let mut normalized = snapshot.clone();
            normalized.meta.current_term = existing.meta.current_term;
            normalized.meta.voted_for = existing.meta.voted_for.clone();
            if existing != normalized {
                return Err(AdmissionConsensusError::Protocol(
                    "admission snapshot cannot replace non-empty divergent state".to_string(),
                ));
            }
            return Ok(());
        }
        match snapshot.genesis_projection.as_ref() {
            Some(genesis) => {
                let local_genesis =
                    capture_admission_genesis_projection_from_connection(&transaction, |_| Ok(()))?;
                if local_genesis != *genesis {
                    if !admission_genesis_projection_is_empty(&local_genesis) {
                        return Err(AdmissionConsensusError::Protocol(
                            "admission snapshot cannot replace divergent authoritative genesis"
                                .to_string(),
                        ));
                    }
                    install_admission_genesis_projection(&transaction, genesis)?;
                }
                transaction.execute("DELETE FROM admission_consensus_genesis", [])?;
                persist_genesis_projection(&transaction, genesis)?;
            }
            None => {
                bind_membership(&transaction, membership)?;
            }
        }
        for entry in &snapshot.entries {
            insert_entry(&transaction, entry)?;
        }
        for proof in &snapshot.commit_proofs {
            insert_commit_proof(&transaction, proof)?;
        }
        let (next_term, next_vote) = if snapshot.meta.current_term > local.current_term {
            (snapshot.meta.current_term, None)
        } else {
            (local.current_term, local.voted_for.clone())
        };
        transaction.execute(
            r#"
            UPDATE admission_consensus_meta
            SET current_term = ?1,
                baseline_state_digest = ?2,
                membership_digest = ?3,
                voted_for = ?4,
                last_log_index = ?5,
                last_log_term = ?6,
                commit_index = ?7,
                last_applied = 0,
                applied_state_digest = ?8
            WHERE singleton = 1
            "#,
            params![
                sqlite_u64(next_term)?,
                snapshot.meta.baseline_state_digest,
                membership.digest(),
                next_vote,
                sqlite_u64(snapshot.meta.last_log_index)?,
                sqlite_u64(snapshot.meta.last_log_term)?,
                sqlite_u64(snapshot.meta.commit_index)?,
                initial_applied_state_digest(),
            ],
        )?;
        apply_committed_expected_in_transaction(&transaction, &snapshot.results, &mut apply)?;
        let installed = AdmissionConsensusSnapshot {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            meta: load_meta(&transaction)?,
            genesis_projection: load_genesis_projection(&transaction)?,
            entries: load_all_entries(&transaction)?,
            commit_proofs: load_commit_proofs(&transaction)?,
            results: load_results(&transaction)?,
        };
        validate_snapshot(&installed)?;
        let mut expected = snapshot.clone();
        expected.meta.current_term = next_term;
        expected.meta.voted_for = if snapshot.meta.current_term > local.current_term {
            None
        } else {
            local.voted_for
        };
        if installed != expected {
            return Err(AdmissionConsensusError::Protocol(
                "installed admission snapshot does not match its durable source".to_string(),
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn merge_committed_snapshot<F>(
        &self,
        membership: &AdmissionMembership,
        snapshot: &AdmissionConsensusSnapshot,
        mut apply: F,
    ) -> Result<bool, AdmissionConsensusError>
    where
        F: FnMut(
            &Transaction<'_>,
            &AdmissionLogEntry,
            &AdmissionCommitProof,
        ) -> Result<String, String>,
    {
        validate_snapshot_for_membership(snapshot, membership)?;
        self.observe_higher_term_for_membership(membership, snapshot.meta.current_term)?;
        if snapshot.meta.last_applied != snapshot.meta.commit_index {
            return Err(AdmissionConsensusError::Protocol(
                "admission catch-up snapshot has unapplied committed entries".to_string(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_integrity(&transaction)?;
        let local = bind_membership(&transaction, membership)?;
        let shared_commit_index = local.commit_index.min(snapshot.meta.commit_index);
        for index in 1..=shared_commit_index {
            let offset = usize_index(
                checked_predecessor(index, "admission catch-up prefix index")?,
                "admission catch-up prefix offset",
            )?;
            if load_entry(&transaction, index)?.as_ref() != snapshot.entries.get(offset)
                || load_commit_proof(&transaction, index)?.as_ref()
                    != snapshot.commit_proofs.get(offset)
            {
                return Err(AdmissionConsensusError::Protocol(format!(
                    "admission catch-up snapshot diverges at committed index {index}"
                )));
            }
        }
        let shared_applied_index = local.last_applied.min(snapshot.meta.last_applied);
        for index in 1..=shared_applied_index {
            let offset = usize_index(
                checked_predecessor(index, "admission catch-up result index")?,
                "admission catch-up result offset",
            )?;
            let expected = snapshot.results.get(offset).ok_or_else(|| {
                AdmissionConsensusError::Protocol(format!(
                    "admission catch-up snapshot omitted result {index}"
                ))
            })?;
            if load_result(&transaction, &expected.operation_id)?.as_ref() != Some(expected) {
                return Err(AdmissionConsensusError::Protocol(format!(
                    "admission catch-up result diverges at applied index {index}"
                )));
            }
        }
        if snapshot.meta.commit_index <= local.commit_index {
            let term_advanced = snapshot.meta.current_term > local.current_term;
            if term_advanced {
                transaction.execute(
                    r#"
                    UPDATE admission_consensus_meta
                    SET current_term = ?1, voted_for = NULL
                    WHERE singleton = 1 AND current_term < ?1
                    "#,
                    params![sqlite_u64(snapshot.meta.current_term)?],
                )?;
            }
            if snapshot.meta.commit_index == local.commit_index {
                apply_committed_expected_in_transaction(
                    &transaction,
                    &snapshot.results,
                    &mut apply,
                )?;
                for expected in &snapshot.results {
                    if load_result(&transaction, &expected.operation_id)?.as_ref() != Some(expected)
                    {
                        return Err(AdmissionConsensusError::Protocol(format!(
                            "admission catch-up result diverges at operation `{}`",
                            expected.operation_id
                        )));
                    }
                }
                transaction.commit()?;
            } else if term_advanced {
                transaction.commit()?;
            } else {
                transaction.rollback()?;
            }
            return Ok(false);
        }
        transaction.execute(
            "DELETE FROM admission_consensus_log WHERE log_index > ?1",
            params![sqlite_u64(local.commit_index)?],
        )?;
        for entry in snapshot
            .entries
            .iter()
            .take(usize_index(
                snapshot.meta.commit_index,
                "admission catch-up commit index",
            )?)
            .skip(usize_index(
                local.commit_index,
                "admission local commit index",
            )?)
        {
            insert_entry(&transaction, entry)?;
        }
        for proof in snapshot.commit_proofs.iter().skip(usize_index(
            local.commit_index,
            "admission local proof index",
        )?) {
            insert_commit_proof(&transaction, proof)?;
        }
        let committed_entry_offset = usize_index(
            checked_predecessor(
                snapshot.meta.commit_index,
                "admission catch-up commit index",
            )?,
            "admission catch-up committed entry offset",
        )?;
        let committed_term = snapshot
            .entries
            .get(committed_entry_offset)
            .ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "admission catch-up snapshot omitted its committed head".to_string(),
                )
            })?
            .leader_epoch;
        let next_term = local.current_term.max(snapshot.meta.current_term);
        let next_vote = if next_term == local.current_term {
            local.voted_for
        } else {
            None
        };
        transaction.execute(
            r#"
            UPDATE admission_consensus_meta
            SET current_term = ?1,
                voted_for = ?2,
                last_log_index = ?3,
                last_log_term = ?4,
                commit_index = ?3
            WHERE singleton = 1
            "#,
            params![
                sqlite_u64(next_term)?,
                next_vote,
                sqlite_u64(snapshot.meta.commit_index)?,
                sqlite_u64(committed_term)?,
            ],
        )?;
        apply_committed_expected_in_transaction(&transaction, &snapshot.results, &mut apply)?;
        for expected in &snapshot.results {
            if load_result(&transaction, &expected.operation_id)?.as_ref() != Some(expected) {
                return Err(AdmissionConsensusError::Protocol(format!(
                    "admission catch-up changed committed result `{}`",
                    expected.operation_id
                )));
            }
        }
        transaction.commit()?;
        Ok(true)
    }

    pub(crate) fn apply_committed<F>(&self, apply: &mut F) -> Result<u64, AdmissionConsensusError>
    where
        F: FnMut(
            &Transaction<'_>,
            &AdmissionLogEntry,
            &AdmissionCommitProof,
        ) -> Result<String, String>,
    {
        self.apply_committed_with_expected(None, apply)
    }

    fn apply_committed_with_expected<F>(
        &self,
        expected_results: Option<&[AdmissionConsensusResult]>,
        apply: &mut F,
    ) -> Result<u64, AdmissionConsensusError>
    where
        F: FnMut(
            &Transaction<'_>,
            &AdmissionLogEntry,
            &AdmissionCommitProof,
        ) -> Result<String, String>,
    {
        loop {
            let mut connection = self.connection()?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            validate_integrity(&transaction)?;
            let meta = load_meta(&transaction)?;
            if meta.last_applied >= meta.commit_index {
                transaction.rollback()?;
                return Ok(meta.last_applied);
            }
            let next = meta.last_applied.checked_add(1).ok_or_else(|| {
                AdmissionConsensusError::Protocol("admission applied index overflow".to_string())
            })?;
            let entry = load_entry(&transaction, next)?.ok_or_else(|| {
                AdmissionConsensusError::Protocol(format!(
                    "committed admission entry {next} is missing"
                ))
            })?;
            let proof = load_commit_proof(&transaction, next)?.ok_or_else(|| {
                AdmissionConsensusError::Protocol(format!(
                    "committed admission proof {next} is missing"
                ))
            })?;
            validate_commit_proof(&proof)?;
            if meta.membership_digest.as_deref() != Some(proof.membership_digest.as_str())
                || entry.leader_epoch > proof.leader_epoch
                || load_entry(&transaction, proof.current_term_commit_index)?
                    .is_none_or(|entry| entry.leader_epoch != proof.leader_epoch)
            {
                return Err(AdmissionConsensusError::Protocol(
                    "admission commit proof does not match persisted consensus state".to_string(),
                ));
            }
            let response_json =
                apply(&transaction, &entry, &proof).map_err(AdmissionConsensusError::Apply)?;
            validate_canonical_json(&response_json, "admission result")?;
            let response_digest = sha256_hex(response_json.as_bytes());
            let current = load_meta(&transaction)?;
            let security_projection_digest = if current.baseline_state_digest.is_some() {
                capture_admission_security_projection_digest_from_connection(&transaction)?
            } else {
                initial_security_projection_digest()
            };
            let result = AdmissionConsensusResult {
                operation_id: entry.operation_id.clone(),
                log_index: entry.index,
                response_digest,
                response_json,
                security_projection_digest,
            };
            if let Some(expected_results) = expected_results {
                let offset = usize_index(
                    checked_predecessor(next, "admission expected result index")?,
                    "admission expected result offset",
                )?;
                if expected_results.get(offset) != Some(&result) {
                    return Err(AdmissionConsensusError::Protocol(format!(
                        "admission replay result {next} differs from the authenticated snapshot"
                    )));
                }
            }
            if current.last_applied >= next {
                transaction.rollback()?;
                continue;
            }
            let previous = checked_predecessor(next, "admission applied index")?;
            if current.last_applied != previous || current.commit_index < next {
                return Err(AdmissionConsensusError::Protocol(
                    "admission apply order changed during deterministic replay".to_string(),
                ));
            }
            if let Some(existing) = load_result(&transaction, &entry.operation_id)? {
                if existing != result {
                    return Err(AdmissionConsensusError::Protocol(format!(
                        "admission operation `{}` replay changed its result",
                        entry.operation_id
                    )));
                }
            } else {
                transaction.execute(
                    r#"
                    INSERT INTO admission_consensus_results (
                        operation_id, log_index, response_json, response_digest,
                        security_projection_digest
                    ) VALUES (?1, ?2, ?3, ?4, ?5)
                    "#,
                    params![
                        &result.operation_id,
                        sqlite_u64(result.log_index)?,
                        &result.response_json,
                        &result.response_digest,
                        &result.security_projection_digest,
                    ],
                )?;
            }
            let applied_state_digest = next_applied_state_digest(
                &current.applied_state_digest,
                &result.response_digest,
                &result.security_projection_digest,
            )?;
            let updated = transaction.execute(
                r#"
                UPDATE admission_consensus_meta
                SET last_applied = ?1, applied_state_digest = ?2
                WHERE singleton = 1
                  AND last_applied = ?3
                  AND applied_state_digest = ?4
                  AND commit_index >= ?1
                "#,
                params![
                    sqlite_u64(next)?,
                    applied_state_digest,
                    sqlite_u64(previous)?,
                    current.applied_state_digest,
                ],
            )?;
            if updated != 1 {
                return Err(AdmissionConsensusError::Protocol(
                    "admission last-applied compare-and-swap failed".to_string(),
                ));
            }
            transaction.commit()?;
        }
    }

    fn connection(&self) -> Result<Connection, AdmissionConsensusError> {
        if self.read_only {
            let database_identity_file = self.database_identity_file.as_ref().ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "read-only admission consensus store omitted its retained file identity"
                        .to_string(),
                )
            })?;
            let connection = database_identity_file
                .open_read_only_connection()
                .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
            configure_read_only_consensus_connection(&connection)?;
            validate_read_only_consensus_connection(&connection)?;
            Ok(connection)
        } else {
            let connection = Connection::open(&self.path)?;
            configure_connection(&connection)?;
            Ok(connection)
        }
    }
}

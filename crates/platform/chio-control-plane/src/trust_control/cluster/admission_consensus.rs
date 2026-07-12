use super::*;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

const CONSENSUS_SCHEMA_VERSION: i64 = 2;
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

use AdmissionGenesisValueType::{Integer as GenesisInteger, Text as GenesisText};

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
        name: "budget_composite_authorizations",
        columns: &[
            ("hold_id", GenesisText),
            ("event_id", GenesisText),
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
        Ok(Self { path })
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
        Ok(Self { path })
    }

    pub(crate) fn validate_integrity(&self) -> Result<(), AdmissionConsensusError> {
        let connection = self.connection()?;
        validate_integrity(&connection)
    }

    pub(crate) fn meta(&self) -> Result<AdmissionConsensusMetaView, AdmissionConsensusError> {
        let connection = self.connection()?;
        load_meta(&connection)
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
        let connection = Connection::open(&self.path)?;
        configure_connection(&connection)?;
        Ok(connection)
    }
}

fn apply_committed_expected_in_transaction<F>(
    transaction: &Transaction<'_>,
    expected_results: &[AdmissionConsensusResult],
    apply: &mut F,
) -> Result<u64, AdmissionConsensusError>
where
    F: FnMut(&Transaction<'_>, &AdmissionLogEntry, &AdmissionCommitProof) -> Result<String, String>,
{
    loop {
        validate_integrity(transaction)?;
        let meta = load_meta(transaction)?;
        if meta.last_applied >= meta.commit_index {
            return Ok(meta.last_applied);
        }
        let next = meta.last_applied.checked_add(1).ok_or_else(|| {
            AdmissionConsensusError::Protocol("admission applied index overflow".to_string())
        })?;
        let entry = load_entry(transaction, next)?.ok_or_else(|| {
            AdmissionConsensusError::Protocol(format!(
                "committed admission entry {next} is missing"
            ))
        })?;
        let proof = load_commit_proof(transaction, next)?.ok_or_else(|| {
            AdmissionConsensusError::Protocol(format!(
                "committed admission proof {next} is missing"
            ))
        })?;
        validate_commit_proof(&proof)?;
        if meta.membership_digest.as_deref() != Some(proof.membership_digest.as_str())
            || entry.leader_epoch > proof.leader_epoch
            || load_entry(transaction, proof.current_term_commit_index)?
                .is_none_or(|entry| entry.leader_epoch != proof.leader_epoch)
        {
            return Err(AdmissionConsensusError::Protocol(
                "admission commit proof does not match persisted consensus state".to_string(),
            ));
        }
        let response_json =
            apply(transaction, &entry, &proof).map_err(AdmissionConsensusError::Apply)?;
        validate_canonical_json(&response_json, "admission result")?;
        let response_digest = sha256_hex(response_json.as_bytes());
        let current = load_meta(transaction)?;
        let security_projection_digest = if current.baseline_state_digest.is_some() {
            capture_admission_security_projection_digest_from_connection(transaction)?
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
        let offset = usize_index(
            checked_predecessor(next, "admission expected result index")?,
            "admission expected result offset",
        )?;
        if expected_results.get(offset) != Some(&result) {
            return Err(AdmissionConsensusError::Protocol(format!(
                "admission replay result {next} differs from the authenticated snapshot"
            )));
        }
        let previous = checked_predecessor(next, "admission applied index")?;
        if current.last_applied != previous || current.commit_index < next {
            return Err(AdmissionConsensusError::Protocol(
                "admission apply order changed during deterministic replay".to_string(),
            ));
        }
        if let Some(existing) = load_result(transaction, &entry.operation_id)? {
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
    }
}

pub(crate) async fn propose_admission_command<T: Serialize>(
    state: &TrustServiceState,
    operation_id: String,
    command_kind: AdmissionCommandKind,
    command: &T,
) -> Result<AdmissionConsensusResult, Response> {
    let command = serde_json::to_value(command).map_err(|error| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            &format!("admission command serialization failed: {error}"),
        )
    })?;
    let state = state.clone();
    let result = tokio::task::spawn_blocking(move || {
        propose_admission_command_blocking(&state, operation_id, command_kind, command)
    })
    .await
    .map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "admission consensus worker failed before completion",
        )
    })?
    .map_err(consensus_http_error)?;
    accepted_consensus_result(result).map_err(consensus_http_error)
}

pub(crate) fn initialize_admission_consensus(state: &TrustServiceState) -> Result<(), CliError> {
    if state.cluster.is_none() {
        return Ok(());
    }
    let (Some(budget_path), Some(revocation_path)) = (
        state.config.budget_db_path.as_deref(),
        state.config.revocation_db_path.as_deref(),
    ) else {
        return Ok(());
    };
    SqliteAdmissionCaptureAuthority::open_with_paths(budget_path, revocation_path)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let store = AdmissionConsensusStore::open(budget_path)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let (_, _, membership) =
        admission_members(state).map_err(|error| CliError::cli_other_error(error.to_string()))?;
    store
        .validate_integrity()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    store
        .bind_membership(&membership)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    store
        .validate_membership_proofs(&membership)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    store
        .apply_committed(&mut |transaction, entry, proof| {
            apply_admission_log_entry(&state.config, transaction, entry, proof)
        })
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(())
}

pub(crate) fn prepare_combined_capture_command(
    config: &TrustServiceConfig,
    request: CombinedAdmissionCaptureRequest,
) -> Result<ConsensusCombinedCaptureCommand, String> {
    let authority = request
        .budget_authority
        .as_ref()
        .ok_or_else(|| "combined capture requires the exact persisted authority".to_string())
        .and_then(budget_authority_from_view)?;
    let revocation_set = super::super::service_runtime::budget::canonical_revocation_set_from_view(
        &request.revocation_set,
    )
    .map_err(|error| error.to_string())?;
    let capture_request = AdmissionCaptureRequest::new(
        request.operation_id.clone(),
        BudgetCaptureInvocationRequest {
            capability_id: request.capability_id.clone(),
            grant_index: request.grant_index,
            hold_id: Some(request.hold_id.clone()),
            event_id: Some(request.event_id.clone()),
            authority: Some(authority),
        },
        revocation_set,
        request.bound_revocation_set_digest.clone(),
        request.authorization_artifact_digests.clone(),
        request.last_observed_revocation_index,
    )
    .map_err(|error| error.to_string())?;
    validate_persisted_capture_hold(
        config,
        &request.capability_id,
        request.grant_index,
        &request.hold_id,
        &request.event_id,
        request.budget_authority.as_ref(),
    )?;
    open_capture_authority(config)?
        .validate_capture_request(&capture_request)
        .map_err(|error| error.to_string())?;
    let path = config
        .budget_db_path
        .as_deref()
        .ok_or_else(|| "combined capture requires a budget database".to_string())?;
    drop(SqliteBudgetStore::open(path).map_err(|error| error.to_string())?);
    let connection = Connection::open(path).map_err(|error| error.to_string())?;
    let mut statement = connection
        .prepare(
            r#"
            SELECT profile, owner_id, grant_index_key, max_invocations
            FROM budget_composite_authorization_quotas
            WHERE hold_id = ?1
            ORDER BY position ASC
            "#,
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map(params![request.hold_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(|error| error.to_string())?;
    let mut invocation_quotas = Vec::new();
    for row in rows {
        let (profile, owner_id, grant_index, max_invocations) =
            row.map_err(|error| error.to_string())?;
        let profile = quota_profile_from_label(&profile)?;
        let grant_index = match profile {
            BudgetQuotaProfileView::GrantInvocation => Some(
                u32::try_from(grant_index)
                    .map_err(|_| "persisted grant quota index is invalid".to_string())?,
            ),
            _ if grant_index == -1 => None,
            _ => return Err("persisted aggregate quota carries a grant index".to_string()),
        };
        invocation_quotas.push(BudgetInvocationQuotaView {
            key: BudgetQuotaKeyView {
                profile,
                owner_id,
                grant_index,
            },
            max_invocations: u32::try_from(max_invocations)
                .map_err(|_| "persisted quota maximum is invalid".to_string())?,
        });
    }
    if invocation_quotas.is_empty() {
        return Err("combined capture hold has no persisted invocation quotas".to_string());
    }
    Ok(ConsensusCombinedCaptureCommand {
        request,
        invocation_quotas,
    })
}

fn validate_persisted_capture_hold(
    config: &TrustServiceConfig,
    capability_id: &str,
    grant_index: usize,
    hold_id: &str,
    event_id: &str,
    authority: Option<&BudgetMutationAuthorityView>,
) -> Result<(), String> {
    let authority = authority
        .ok_or_else(|| "capture requires the exact persisted authority".to_string())
        .and_then(budget_authority_from_view)?;
    let path = config
        .budget_db_path
        .as_deref()
        .ok_or_else(|| "capture requires a budget database".to_string())?;
    let store = SqliteBudgetStore::open(path).map_err(|error| error.to_string())?;
    if store
        .hold_authority(hold_id)
        .map_err(|error| error.to_string())?
        .as_ref()
        != Some(&authority)
    {
        return Err("capture authority does not match the persisted hold authority".to_string());
    }
    let connection = Connection::open(path).map_err(|error| error.to_string())?;
    let persisted = connection
        .query_row(
            r#"
            SELECT capability_id, grant_index, disposition
            FROM budget_authorization_holds
            WHERE hold_id = ?1
            "#,
            params![hold_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "capture hold does not exist".to_string())?;
    let event_exists = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM budget_mutation_events WHERE event_id = ?1)",
            params![event_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| error.to_string())?
        != 0;
    if event_exists {
        return Err("capture event ID is already owned by a persisted mutation".to_string());
    }
    let persisted_grant_index = usize::try_from(persisted.1)
        .map_err(|_| "capture hold grant index is invalid".to_string())?;
    if persisted.0 != capability_id || persisted_grant_index != grant_index || persisted.2 != "open"
    {
        return Err("capture request does not match an open persisted hold".to_string());
    }
    Ok(())
}

fn validate_composite_quota_maxima(
    config: &TrustServiceConfig,
    request: &CompositeBudgetAuthorizeRequest,
) -> Result<(), String> {
    let path = config
        .budget_db_path
        .as_deref()
        .ok_or_else(|| "composite authorize requires a budget database".to_string())?;
    drop(SqliteBudgetStore::open(path).map_err(|error| error.to_string())?);
    let connection = Connection::open(path).map_err(|error| error.to_string())?;
    let namespace_exists = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM budget_authorization_claims WHERE hold_id = ?1
                UNION ALL
                SELECT 1 FROM budget_authorization_holds WHERE hold_id = ?1
                UNION ALL
                SELECT 1 FROM budget_composite_authorizations
                WHERE hold_id = ?1 OR event_id = ?2
                UNION ALL
                SELECT 1 FROM budget_mutation_events WHERE event_id = ?2
                UNION ALL
                SELECT 1 FROM admission_capture_events WHERE capture_event_id = ?2
            )
            "#,
            params![request.hold_id, request.event_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| error.to_string())?
        != 0;
    if namespace_exists {
        return Err(
            "composite authorization hold or event namespace is already persisted".to_string(),
        );
    }
    for quota in &request.admission_evidence.invocation_quotas {
        let profile = match quota.key.profile {
            BudgetQuotaProfileView::GrantInvocation => "chio.grant-invocation.v1",
            BudgetQuotaProfileView::AggregateCapabilityInvocation => {
                "chio.aggregate-capability-invocation.v1"
            }
            BudgetQuotaProfileView::AggregateFamilyInvocation => {
                "chio.aggregate-family-invocation.v1"
            }
            BudgetQuotaProfileView::SupplementalBrokerExecution => {
                "chio.broker-capability-execution.v1"
            }
        };
        let grant_index = quota.key.grant_index.map_or(-1_i64, i64::from);
        let existing = connection
            .query_row(
                r#"
                SELECT max_invocations
                FROM budget_invocation_quota_usage
                WHERE profile = ?1 AND owner_id = ?2 AND grant_index_key = ?3
                "#,
                params![profile, quota.key.owner_id, grant_index],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if existing.is_some_and(|maximum| maximum != i64::from(quota.max_invocations)) {
            return Err(format!(
                "invocation quota `{profile}:{}` cannot change its persisted maximum",
                quota.key.owner_id
            ));
        }
    }
    Ok(())
}

fn propose_admission_command_blocking(
    state: &TrustServiceState,
    operation_id: String,
    command_kind: AdmissionCommandKind,
    command: Value,
) -> Result<AdmissionConsensusResult, AdmissionConsensusError> {
    let (self_url, _, membership) = admission_members(state)?;
    let request = AdmissionProposalRequest {
        operation_id: operation_id.clone(),
        command_kind,
        command: command.clone(),
    };
    let mut last_error = None;
    for coordinator in &membership.members {
        if coordinator == &self_url {
            match propose_admission_command_local(
                state,
                operation_id.clone(),
                command_kind,
                command.clone(),
            ) {
                Ok(result) => return Ok(result),
                Err(error) => last_error = Some(error),
            }
        } else if let Ok(client) = service_runtime::client::build_cluster_peer_client(
            coordinator,
            &state.config.service_token,
            &self_url,
        ) {
            if let Ok(result) = client.admission_proposal(&request) {
                return Ok(result);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        AdmissionConsensusError::Protocol(
            "admission consensus could not reach any configured proposal coordinator".to_string(),
        )
    }))
}

fn propose_admission_command_local(
    state: &TrustServiceState,
    operation_id: String,
    command_kind: AdmissionCommandKind,
    command: Value,
) -> Result<AdmissionConsensusResult, AdmissionConsensusError> {
    let (self_url, _, membership) = admission_members(state)?;
    let serializer = admission_proposal_serializer(&self_url);
    let _guard = match serializer.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    const MAX_ATTEMPTS: usize = 16;
    let retry_rank = membership
        .members
        .iter()
        .position(|member| member == &self_url)
        .unwrap_or(0);
    for attempt in 0..MAX_ATTEMPTS {
        match propose_admission_command_once(
            state,
            operation_id.clone(),
            command_kind,
            command.clone(),
        ) {
            Ok(result) => return Ok(result),
            Err(error) if attempt + 1 < MAX_ATTEMPTS && retryable_consensus_contention(&error) => {
                catch_up_admission_from_peers(state, &membership, &self_url)?;
                std::thread::sleep(consensus_retry_delay(&operation_id, attempt, retry_rank));
            }
            Err(error) => return Err(error),
        }
    }
    Err(AdmissionConsensusError::Protocol(
        "admission consensus exhausted bounded contention retries".to_string(),
    ))
}

fn admission_proposal_serializer(member_id: &str) -> Arc<Mutex<()>> {
    type SerializerRegistry = BTreeMap<String, std::sync::Weak<Mutex<()>>>;
    static SERIALIZERS: std::sync::OnceLock<Mutex<SerializerRegistry>> = std::sync::OnceLock::new();
    let registry = SERIALIZERS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut registry = match registry.lock() {
        Ok(registry) => registry,
        Err(poisoned) => poisoned.into_inner(),
    };
    registry.retain(|_, serializer| serializer.strong_count() != 0);
    if let Some(serializer) = registry.get(member_id).and_then(std::sync::Weak::upgrade) {
        return serializer;
    }
    let serializer = Arc::new(Mutex::new(()));
    registry.insert(member_id.to_string(), Arc::downgrade(&serializer));
    serializer
}

fn catch_up_admission_from_peers(
    state: &TrustServiceState,
    membership: &AdmissionMembership,
    self_url: &str,
) -> Result<bool, AdmissionConsensusError> {
    let store = configured_admission_consensus_store(&state.config)?;
    let mut snapshots = Vec::new();
    for peer in &membership.members {
        if peer == self_url {
            continue;
        }
        let Ok(client) = service_runtime::client::build_cluster_peer_client(
            peer,
            &state.config.service_token,
            self_url,
        ) else {
            continue;
        };
        let Ok(snapshot) = client.admission_snapshot() else {
            continue;
        };
        validate_snapshot_for_membership(&snapshot, membership)?;
        store.observe_higher_term(snapshot.meta.current_term)?;
        snapshots.push(snapshot);
    }
    for left in 0..snapshots.len() {
        for right in (left + 1)..snapshots.len() {
            let shared = usize_index(
                snapshots[left]
                    .meta
                    .commit_index
                    .min(snapshots[right].meta.commit_index),
                "admission peer snapshot overlap",
            )?;
            if snapshots[left].entries.get(..shared) != snapshots[right].entries.get(..shared)
                || snapshots[left].commit_proofs.get(..shared)
                    != snapshots[right].commit_proofs.get(..shared)
                || snapshots[left].results.get(..shared) != snapshots[right].results.get(..shared)
            {
                return Err(AdmissionConsensusError::Protocol(
                    "authenticated admission peer snapshots have conflicting committed prefixes"
                        .to_string(),
                ));
            }
        }
    }
    snapshots.sort_by(|left, right| {
        right
            .meta
            .commit_index
            .cmp(&left.meta.commit_index)
            .then_with(|| right.meta.current_term.cmp(&left.meta.current_term))
    });
    let mut advanced = false;
    for snapshot in snapshots {
        advanced |= store.merge_committed_snapshot(
            membership,
            &snapshot,
            |transaction, entry, proof| {
                apply_admission_log_entry(&state.config, transaction, entry, proof)
            },
        )?;
    }
    Ok(advanced)
}

fn retryable_consensus_contention(error: &AdmissionConsensusError) -> bool {
    let AdmissionConsensusError::Protocol(message) = error else {
        return false;
    };
    [
        "could not elect a majority leader",
        "lost quorum before commit",
        "leader epoch changed before commit",
        "leader epoch changed before local append",
        "reported a higher term",
        "returned another election term",
        "peer commit index is ahead of the elected leader",
        "majority apply acknowledgement was unavailable",
        "could not confirm one applied state on a majority",
    ]
    .iter()
    .any(|fragment| message.contains(fragment))
}

fn consensus_retry_delay(operation_id: &str, attempt: usize, member_rank: usize) -> Duration {
    let digest = sha256_hex(operation_id.as_bytes());
    let jitter = u64::from_str_radix(&digest[..2], 16).unwrap_or(0) % 7;
    let rank = u64::try_from(member_rank).unwrap_or(u64::MAX);
    let multiplier = 1_u64 << attempt.min(5);
    let base = rank.saturating_mul(40).saturating_add(4);
    Duration::from_millis(
        base.saturating_mul(multiplier)
            .saturating_add(jitter)
            .min(400),
    )
}

fn propose_admission_command_once(
    state: &TrustServiceState,
    operation_id: String,
    command_kind: AdmissionCommandKind,
    command: Value,
) -> Result<AdmissionConsensusResult, AdmissionConsensusError> {
    if command_kind == AdmissionCommandKind::LeadershipBarrier {
        return Err(AdmissionConsensusError::Protocol(
            "leadership barriers cannot be submitted externally".to_string(),
        ));
    }
    let operation_id = scoped_operation_id(command_kind, &operation_id)?;
    let store = configured_admission_consensus_store(&state.config)?;
    let (self_url, peers, membership) = admission_members(state)?;
    let mut apply =
        |transaction: &Transaction<'_>, entry: &AdmissionLogEntry, proof: &AdmissionCommitProof| {
            apply_admission_log_entry(&state.config, transaction, entry, proof)
        };
    store.apply_committed(&mut apply)?;
    let existing = store.entry_for_operation(&operation_id)?;
    if let Some(existing) = existing.as_ref() {
        ensure_operation_command_matches(existing, command_kind, &command)?;
    }
    let existing_result = store.result_for_operation(&operation_id)?;
    let quorum_size = membership.quorum_size();
    let election = store.begin_election(&membership, &self_url)?;
    let vote_request = AdmissionRequestVoteRequest {
        protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
        membership_digest: membership.digest().to_string(),
        term: election.term,
        candidate_id: self_url.clone(),
        last_log_index: election.last_log_index,
        last_log_term: election.last_log_term,
        commit_index: election.commit_index,
    };
    let mut votes = 1usize;
    for peer in &peers {
        let Ok(client) = service_runtime::client::build_cluster_peer_client(
            peer,
            &state.config.service_token,
            &self_url,
        ) else {
            continue;
        };
        let Ok(response) = client.admission_request_vote(&vote_request) else {
            continue;
        };
        if response.protocol_version != ADMISSION_CONSENSUS_PROTOCOL_VERSION
            || response.membership_digest != membership.digest()
        {
            continue;
        }
        if response.term > election.term {
            store.observe_higher_term(response.term)?;
            continue;
        }
        if response.term == election.term && response.vote_granted {
            votes = votes.checked_add(1).ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "admission election vote count overflow".to_string(),
                )
            })?;
        }
    }
    if votes < quorum_size || !store.recheck_elected_epoch(&membership, &election)? {
        return Err(AdmissionConsensusError::Protocol(
            "admission consensus could not elect a majority leader".to_string(),
        ));
    }
    if let Some(result) = existing_result {
        confirm_committed_state(
            state,
            &store,
            &membership,
            &election,
            &self_url,
            &peers,
            quorum_size,
        )?;
        return Ok(result);
    }
    let entry = if existing.is_some() {
        let barrier_scope = format!("{}:{}", membership.digest(), election.term);
        let barrier_operation_id =
            scoped_operation_id(AdmissionCommandKind::LeadershipBarrier, &barrier_scope)?;
        let barrier_command = json!({
            "membershipDigest": membership.digest(),
            "term": election.term,
        });
        AdmissionConsensusStore::build_entry(
            &election,
            &barrier_operation_id,
            AdmissionCommandKind::LeadershipBarrier,
            &barrier_command,
        )?
    } else {
        let prepared_command = prepare_command(&state.config, command_kind, command, &election)?;
        AdmissionConsensusStore::build_entry(
            &election,
            &operation_id,
            command_kind,
            &prepared_command,
        )?
    };
    store.append_local(&election, &entry)?;
    let committed = replicate_and_commit_entry(
        state,
        &store,
        &membership,
        &election,
        &self_url,
        &peers,
        quorum_size,
        &entry,
        &mut apply,
    )?;
    if existing.is_some() {
        return store.result_for_operation(&operation_id)?.ok_or_else(|| {
            AdmissionConsensusError::Protocol(
                "inherited admission operation was not committed by the current-term barrier"
                    .to_string(),
            )
        });
    }
    Ok(committed)
}

fn ensure_operation_command_matches(
    existing: &AdmissionLogEntry,
    command_kind: AdmissionCommandKind,
    command: &Value,
) -> Result<(), AdmissionConsensusError> {
    if existing.command_kind != command_kind {
        return Err(AdmissionConsensusError::Protocol(
            "admission operation was reused for another command kind".to_string(),
        ));
    }
    let persisted: Value = serde_json::from_str(&existing.canonical_command).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "persisted admission command is invalid: {error}"
        ))
    })?;
    let matches = match command_kind {
        AdmissionCommandKind::LeadershipBarrier => persisted == *command,
        AdmissionCommandKind::CompositeAuthorize => persisted.get("request") == Some(command),
        AdmissionCommandKind::Revoke => {
            let persisted: ConsensusRevocationCommand = serde_json::from_value(persisted.clone())
                .map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "persisted revocation command is invalid: {error}"
                ))
            })?;
            let requested: ConsensusRevocationProposal = serde_json::from_value(command.clone())
                .map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "requested revocation proposal is invalid: {error}"
                    ))
                })?;
            persisted.capability_id == requested.capability_id
        }
        AdmissionCommandKind::CaptureInvocations => persisted == *command,
        AdmissionCommandKind::ReverseExposure
        | AdmissionCommandKind::ReleaseExposure
        | AdmissionCommandKind::ReconcileSpend
        | AdmissionCommandKind::CaptureExposure => persisted == *command,
        AdmissionCommandKind::CombinedCapture => persisted.get("request") == Some(command),
    };
    if !matches {
        return Err(AdmissionConsensusError::Protocol(
            "admission operation retry changed its canonical command".to_string(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn confirm_committed_state(
    state: &TrustServiceState,
    store: &AdmissionConsensusStore,
    membership: &AdmissionMembership,
    election: &AdmissionElection,
    self_url: &str,
    peers: &[String],
    quorum_size: usize,
) -> Result<(), AdmissionConsensusError> {
    let local = store.meta()?;
    if local.commit_index == 0
        || local.last_applied != local.commit_index
        || !is_lower_sha256(&local.applied_state_digest)
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission retry has no complete committed state to confirm".to_string(),
        ));
    }
    let mut matching_nodes = 1usize;
    for peer in peers {
        let Ok(client) = service_runtime::client::build_cluster_peer_client(
            peer,
            &state.config.service_token,
            self_url,
        ) else {
            continue;
        };
        let Ok(response) =
            synchronize_peer_through(store, membership, election, &client, local.commit_index)
        else {
            continue;
        };
        if response.applied_index == local.last_applied
            && response.applied_state_digest == local.applied_state_digest
        {
            matching_nodes = matching_nodes.checked_add(1).ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "admission confirmation count overflow".to_string(),
                )
            })?;
        }
    }
    if matching_nodes < quorum_size || !store.recheck_elected_epoch(membership, election)? {
        return Err(AdmissionConsensusError::Protocol(
            "admission retry could not confirm one applied state on a majority".to_string(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn replicate_and_commit_entry<F>(
    state: &TrustServiceState,
    store: &AdmissionConsensusStore,
    membership: &AdmissionMembership,
    election: &AdmissionElection,
    self_url: &str,
    peers: &[String],
    quorum_size: usize,
    entry: &AdmissionLogEntry,
    apply: &mut F,
) -> Result<AdmissionConsensusResult, AdmissionConsensusError>
where
    F: FnMut(&Transaction<'_>, &AdmissionLogEntry, &AdmissionCommitProof) -> Result<String, String>,
{
    if entry.leader_epoch != election.term {
        return Err(AdmissionConsensusError::Protocol(
            "admission commit target was not created in the current leader term".to_string(),
        ));
    }
    let mut witnesses = vec![self_url.to_string()];
    for peer in peers {
        let Ok(client) = service_runtime::client::build_cluster_peer_client(
            peer,
            &state.config.service_token,
            self_url,
        ) else {
            continue;
        };
        let Ok(response) =
            synchronize_peer_through(store, membership, election, &client, entry.index)
        else {
            continue;
        };
        if response.match_index >= entry.index {
            witnesses.push(peer.clone());
        }
    }
    witnesses.sort();
    witnesses.dedup();
    if witnesses.len() < quorum_size || !store.recheck_elected_epoch(membership, election)? {
        return Err(AdmissionConsensusError::Protocol(
            "admission consensus lost quorum before commit".to_string(),
        ));
    }
    let first_uncommitted =
        checked_successor(store.meta()?.commit_index, "admission leader commit index")?;
    let mut target_result = None;
    for index in first_uncommitted..=entry.index {
        let proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            index,
            leader_epoch: election.term,
            current_term_commit_index: entry.index,
            leader_id: self_url.to_string(),
            quorum_size,
            witness_urls: witnesses.clone(),
        };
        let result = store.commit_local(membership, election, &proof, &mut *apply)?;
        if index == entry.index {
            target_result = Some(result);
        }
    }
    let committed_meta = store.meta()?;
    if committed_meta.last_applied != entry.index {
        return Err(AdmissionConsensusError::Protocol(
            "admission leader did not apply its committed prefix exactly".to_string(),
        ));
    }
    let mut applied_nodes = 1usize;
    for peer in peers {
        let Ok(client) = service_runtime::client::build_cluster_peer_client(
            peer,
            &state.config.service_token,
            self_url,
        ) else {
            continue;
        };
        let Ok(response) =
            synchronize_peer_through(store, membership, election, &client, entry.index)
        else {
            continue;
        };
        if response.applied_index == entry.index
            && response.applied_state_digest == committed_meta.applied_state_digest
        {
            applied_nodes = applied_nodes.checked_add(1).ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "admission applied acknowledgement count overflow".to_string(),
                )
            })?;
        }
    }
    if applied_nodes < quorum_size || !store.recheck_elected_epoch(membership, election)? {
        return Err(AdmissionConsensusError::Protocol(
            "admission commit was durable but a majority apply acknowledgement was unavailable"
                .to_string(),
        ));
    }
    target_result.ok_or_else(|| {
        AdmissionConsensusError::Protocol(
            "admission current-term commit target produced no result".to_string(),
        )
    })
}

fn synchronize_peer_through(
    store: &AdmissionConsensusStore,
    membership: &AdmissionMembership,
    election: &AdmissionElection,
    client: &TrustControlClient,
    target_index: u64,
) -> Result<AdmissionAppendEntriesResponse, AdmissionConsensusError> {
    let local = store.meta()?;
    if local.membership_digest.as_deref() != Some(membership.digest())
        || target_index == 0
        || target_index > local.last_log_index
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission peer synchronization target is outside the local log".to_string(),
        ));
    }
    let probe = send_peer_append_response(
        store,
        election,
        client,
        &AdmissionAppendEntriesRequest {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            term: election.term,
            leader_id: election.candidate_id.clone(),
            previous_log_index: 0,
            previous_log_term: 0,
            entry: None,
            leader_commit: 0,
            commit_proof: None,
        },
    )?;
    if probe.commit_index > local.commit_index || probe.match_index < probe.commit_index {
        return Err(AdmissionConsensusError::Protocol(
            "admission peer commit index is ahead of the elected leader".to_string(),
        ));
    }
    let follower_commit = probe.commit_index;
    let mut common_index = probe.match_index.min(target_index);
    loop {
        let previous_log_term = if common_index == 0 {
            0
        } else {
            store.entry_at(common_index)?.leader_epoch
        };
        let response = send_peer_append_response(
            store,
            election,
            client,
            &AdmissionAppendEntriesRequest {
                protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                membership_digest: membership.digest().to_string(),
                term: election.term,
                leader_id: election.candidate_id.clone(),
                previous_log_index: common_index,
                previous_log_term,
                entry: None,
                leader_commit: follower_commit,
                commit_proof: None,
            },
        )?;
        if response.accepted {
            break;
        }
        if common_index <= follower_commit {
            return Err(AdmissionConsensusError::Protocol(
                "admission peer diverges inside the committed prefix".to_string(),
            ));
        }
        common_index = common_index.checked_sub(1).ok_or_else(|| {
            AdmissionConsensusError::Protocol("admission log backtrack underflow".to_string())
        })?;
    }
    let first_missing_entry = common_index.checked_add(1).ok_or_else(|| {
        AdmissionConsensusError::Protocol("admission log index overflow".to_string())
    })?;
    for index in first_missing_entry..=target_index {
        let entry = store.entry_at(index)?;
        let (previous_log_index, previous_log_term) = previous_store_position(store, entry.index)?;
        send_peer_append(
            store,
            election,
            client,
            AdmissionAppendEntriesRequest {
                protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                membership_digest: membership.digest().to_string(),
                term: election.term,
                leader_id: election.candidate_id.clone(),
                previous_log_index,
                previous_log_term,
                entry: Some(entry),
                leader_commit: follower_commit,
                commit_proof: None,
            },
        )?;
    }
    let first_missing_commit = follower_commit.checked_add(1).ok_or_else(|| {
        AdmissionConsensusError::Protocol("admission commit index overflow".to_string())
    })?;
    for index in first_missing_commit..=local.commit_index {
        let entry = store.entry_at(index)?;
        let proof = store.proof_at(index)?;
        send_peer_append(
            store,
            election,
            client,
            AdmissionAppendEntriesRequest {
                protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                membership_digest: membership.digest().to_string(),
                term: election.term,
                leader_id: election.candidate_id.clone(),
                previous_log_index: entry.index,
                previous_log_term: entry.leader_epoch,
                entry: None,
                leader_commit: index,
                commit_proof: Some(proof),
            },
        )?;
    }
    let target = store.entry_at(target_index)?;
    send_peer_append(
        store,
        election,
        client,
        AdmissionAppendEntriesRequest {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            term: election.term,
            leader_id: election.candidate_id.clone(),
            previous_log_index: target.index,
            previous_log_term: target.leader_epoch,
            entry: None,
            leader_commit: local.commit_index,
            commit_proof: None,
        },
    )
}

fn send_peer_append(
    store: &AdmissionConsensusStore,
    election: &AdmissionElection,
    client: &TrustControlClient,
    request: AdmissionAppendEntriesRequest,
) -> Result<AdmissionAppendEntriesResponse, AdmissionConsensusError> {
    let response = send_peer_append_response(store, election, client, &request)?;
    if !response.accepted {
        return Err(AdmissionConsensusError::Protocol(
            response
                .rejection
                .clone()
                .unwrap_or_else(|| "admission peer rejected the append".to_string()),
        ));
    }
    Ok(response)
}

fn send_peer_append_response(
    store: &AdmissionConsensusStore,
    election: &AdmissionElection,
    client: &TrustControlClient,
    request: &AdmissionAppendEntriesRequest,
) -> Result<AdmissionAppendEntriesResponse, AdmissionConsensusError> {
    let response = client.admission_append_entries(request).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission peer append failed before acknowledgement: {error}"
        ))
    })?;
    if response.protocol_version != ADMISSION_CONSENSUS_PROTOCOL_VERSION {
        return Err(AdmissionConsensusError::Protocol(
            "admission peer append used an unsupported protocol".to_string(),
        ));
    }
    if response.membership_digest != request.membership_digest {
        return Err(AdmissionConsensusError::Protocol(
            "admission peer append membership digest changed".to_string(),
        ));
    }
    if !is_lower_sha256(&response.applied_state_digest) {
        return Err(AdmissionConsensusError::Protocol(
            "admission peer append returned an invalid applied-state digest".to_string(),
        ));
    }
    if response.term > election.term {
        store.observe_higher_term(response.term)?;
        return Err(AdmissionConsensusError::Protocol(
            "admission peer append reported a higher term".to_string(),
        ));
    }
    if response.term != election.term {
        return Err(AdmissionConsensusError::Protocol(
            "admission peer append returned another election term".to_string(),
        ));
    }
    Ok(response)
}

fn previous_store_position(
    store: &AdmissionConsensusStore,
    index: u64,
) -> Result<(u64, u64), AdmissionConsensusError> {
    let previous = index.checked_sub(1).ok_or_else(|| {
        AdmissionConsensusError::Protocol("admission log index underflow".to_string())
    })?;
    if previous == 0 {
        return Ok((0, 0));
    }
    let entry = store.entry_at(previous)?;
    Ok((entry.index, entry.leader_epoch))
}

fn prepare_command(
    config: &TrustServiceConfig,
    command_kind: AdmissionCommandKind,
    command: Value,
    election: &AdmissionElection,
) -> Result<Value, AdmissionConsensusError> {
    match command_kind {
        AdmissionCommandKind::LeadershipBarrier => Err(AdmissionConsensusError::Protocol(
            "leadership barriers cannot be submitted as external commands".to_string(),
        )),
        AdmissionCommandKind::CompositeAuthorize => {
            let request: CompositeBudgetAuthorizeRequest = serde_json::from_value(command)
                .map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "composite authorize command is invalid: {error}"
                    ))
                })?;
            let authority = BudgetMutationAuthorityView {
                authority_id: election.candidate_id.clone(),
                lease_id: format!("{}#admission-term-{}", election.candidate_id, election.term),
                lease_epoch: election.term,
            };
            super::super::budget_handlers::sqlite_composite_authorize_input(
                &request,
                budget_authority_from_view(&authority)
                    .map_err(AdmissionConsensusError::Protocol)?,
            )
            .map_err(|error| AdmissionConsensusError::Protocol(error.to_string()))?;
            validate_composite_quota_maxima(config, &request)
                .map_err(AdmissionConsensusError::Protocol)?;
            serde_json::to_value(ConsensusCompositeAuthorizeCommand { request, authority }).map_err(
                |error| {
                    AdmissionConsensusError::Protocol(format!(
                        "composite authorize command preparation failed: {error}"
                    ))
                },
            )
        }
        AdmissionCommandKind::CaptureInvocations => {
            let request: CaptureInvocationReservationsRequest = serde_json::from_value(command)
                .map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "invocation capture command is invalid: {error}"
                    ))
                })?;
            validate_persisted_capture_hold(
                config,
                &request.capability_id,
                request.grant_index,
                &request.hold_id,
                &request.event_id,
                request.budget_authority.as_ref(),
            )
            .map_err(AdmissionConsensusError::Protocol)?;
            serde_json::to_value(request).map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "invocation capture command preparation failed: {error}"
                ))
            })
        }
        AdmissionCommandKind::ReverseExposure => {
            let request: ReverseChargeCostRequest =
                serde_json::from_value(command).map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "reverse exposure command is invalid: {error}"
                    ))
                })?;
            let hold_id = request.hold_id.as_deref().ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "reverse exposure command requires hold_id".to_string(),
                )
            })?;
            let event_id = request.event_id.as_deref().ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "reverse exposure command requires event_id".to_string(),
                )
            })?;
            validate_persisted_capture_hold(
                config,
                &request.capability_id,
                request.grant_index,
                hold_id,
                event_id,
                request.budget_authority.as_ref(),
            )
            .map_err(AdmissionConsensusError::Protocol)?;
            serde_json::to_value(request).map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "reverse exposure command preparation failed: {error}"
                ))
            })
        }
        AdmissionCommandKind::ReleaseExposure
        | AdmissionCommandKind::ReconcileSpend
        | AdmissionCommandKind::CaptureExposure => {
            let request: ReduceChargeCostRequest =
                serde_json::from_value(command).map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "monetary transition command is invalid: {error}"
                    ))
                })?;
            let hold_id = request.hold_id.as_deref().ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "monetary transition command requires hold_id".to_string(),
                )
            })?;
            let event_id = request.event_id.as_deref().ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "monetary transition command requires event_id".to_string(),
                )
            })?;
            let shape_matches = match command_kind {
                AdmissionCommandKind::ReleaseExposure => {
                    request.exposure_units.is_none() && request.realized_spend_units.is_none()
                }
                AdmissionCommandKind::ReconcileSpend | AdmissionCommandKind::CaptureExposure => {
                    request
                        .exposure_units
                        .zip(request.realized_spend_units)
                        .is_some_and(|(exposure_units, realized_spend_units)| {
                            exposure_units.checked_sub(realized_spend_units)
                                == Some(request.cost_units)
                        })
                }
                _ => false,
            };
            if !shape_matches {
                return Err(AdmissionConsensusError::Protocol(
                    "monetary transition command fields contradict its kind".to_string(),
                ));
            }
            validate_persisted_capture_hold(
                config,
                &request.capability_id,
                request.grant_index,
                hold_id,
                event_id,
                request.budget_authority.as_ref(),
            )
            .map_err(AdmissionConsensusError::Protocol)?;
            serde_json::to_value(request).map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "monetary transition command preparation failed: {error}"
                ))
            })
        }
        AdmissionCommandKind::Revoke => {
            let request: ConsensusRevocationProposal =
                serde_json::from_value(command).map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "revocation proposal is invalid: {error}"
                    ))
                })?;
            if request.capability_id.is_empty()
                || request.capability_id.len() > 512
                || request.capability_id.bytes().any(|byte| byte == 0)
            {
                return Err(AdmissionConsensusError::Protocol(
                    "revocation proposal fields are invalid".to_string(),
                ));
            }
            let revoked_at = i64::try_from(unix_timestamp_now()).map_err(|_| {
                AdmissionConsensusError::Protocol(
                    "revocation timestamp exceeds the supported range".to_string(),
                )
            })?;
            serde_json::to_value(ConsensusRevocationCommand {
                capability_id: request.capability_id,
                revoked_at,
            })
            .map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "revocation command preparation failed: {error}"
                ))
            })
        }
        AdmissionCommandKind::CombinedCapture => {
            let request: CombinedAdmissionCaptureRequest = serde_json::from_value(command)
                .map_err(|error| {
                    AdmissionConsensusError::Protocol(format!(
                        "combined capture command is invalid: {error}"
                    ))
                })?;
            let prepared = prepare_combined_capture_command(config, request)
                .map_err(AdmissionConsensusError::Protocol)?;
            serde_json::to_value(prepared).map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "combined capture command preparation failed: {error}"
                ))
            })
        }
    }
}

fn admission_members(
    state: &TrustServiceState,
) -> Result<(String, Vec<String>, AdmissionMembership), AdmissionConsensusError> {
    let (self_url, peers, members) = admission_member_urls(state)?;
    let store = configured_admission_consensus_store(&state.config)?;
    let meta = store.meta()?;
    let genesis_projection = if let Some(digest) = meta.baseline_state_digest {
        let projection = store.genesis_projection()?.ok_or_else(|| {
            AdmissionConsensusError::Protocol(
                "admission consensus baseline has no persisted genesis projection".to_string(),
            )
        })?;
        if admission_genesis_projection_digest(&projection)? != digest {
            return Err(AdmissionConsensusError::Protocol(
                "admission persisted genesis projection does not match its baseline digest"
                    .to_string(),
            ));
        }
        projection
    } else if meta.membership_digest.is_none() {
        let path = state.config.budget_db_path.as_deref().ok_or_else(|| {
            AdmissionConsensusError::Protocol(
                "admission consensus requires a budget database".to_string(),
            )
        })?;
        capture_admission_genesis_projection(path)?
    } else {
        return Err(AdmissionConsensusError::Protocol(
            "admission bound membership has no genesis baseline".to_string(),
        ));
    };
    let membership = AdmissionMembership::new_with_genesis(members, genesis_projection)?;
    Ok((self_url, peers, membership))
}

fn admission_member_urls(
    state: &TrustServiceState,
) -> Result<(String, Vec<String>, Vec<String>), AdmissionConsensusError> {
    let cluster = state.cluster.as_ref().ok_or_else(|| {
        AdmissionConsensusError::Protocol(
            "HA admission consensus requires configured peers".to_string(),
        )
    })?;
    let guard = match cluster.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let mut peers = guard.peers.keys().cloned().collect::<Vec<_>>();
    peers.sort();
    peers.dedup();
    if peers.is_empty() {
        return Err(AdmissionConsensusError::Protocol(
            "HA admission consensus requires at least two configured nodes".to_string(),
        ));
    }
    let self_url = guard.self_url.clone();
    let mut members = peers.clone();
    members.push(self_url.clone());
    drop(guard);
    Ok((self_url, peers, members))
}

fn configured_admission_consensus_store(
    config: &TrustServiceConfig,
) -> Result<AdmissionConsensusStore, AdmissionConsensusError> {
    let budget_path = config.budget_db_path.as_deref().ok_or_else(|| {
        AdmissionConsensusError::Protocol(
            "admission consensus requires a budget database".to_string(),
        )
    })?;
    let revocation_path = config.revocation_db_path.as_deref().ok_or_else(|| {
        AdmissionConsensusError::Protocol(
            "admission consensus requires a revocation database".to_string(),
        )
    })?;
    let canonical_budget = std::fs::canonicalize(budget_path).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission budget database cannot be resolved: {error}"
        ))
    })?;
    let canonical_revocation = std::fs::canonicalize(revocation_path).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission revocation database cannot be resolved: {error}"
        ))
    })?;
    if canonical_budget != canonical_revocation {
        return Err(AdmissionConsensusError::Protocol(
            "admission consensus requires one shared budget and revocation database".to_string(),
        ));
    }
    AdmissionConsensusStore::open_existing(canonical_budget)
}

fn capture_admission_genesis_projection(
    path: &Path,
) -> Result<AdmissionGenesisProjection, AdmissionConsensusError> {
    let mut connection = Connection::open(path)?;
    configure_connection(&connection)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let projection =
        capture_admission_genesis_projection_from_connection(&transaction, |_| Ok(()))?;
    transaction.commit()?;
    Ok(projection)
}

fn capture_admission_genesis_projection_from_connection<F>(
    connection: &Connection,
    mut after_table: F,
) -> Result<AdmissionGenesisProjection, AdmissionConsensusError>
where
    F: FnMut(&str) -> Result<(), AdmissionConsensusError>,
{
    let existing_tables = {
        let mut statement = connection
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name ASC")?;
        let tables = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        tables
    };
    for name in &existing_tables {
        let known_authoritative = ADMISSION_GENESIS_TABLES
            .iter()
            .any(|table| table.name == name);
        let known_excluded = name.starts_with("sqlite_")
            || name.starts_with("admission_consensus_")
            || ADMISSION_GENESIS_EXCLUDED_TABLES
                .iter()
                .any(|excluded| excluded == name);
        if !known_authoritative && !known_excluded {
            return Err(AdmissionConsensusError::Protocol(format!(
                "admission genesis contains unknown table `{name}`"
            )));
        }
    }

    let mut tables = Vec::with_capacity(ADMISSION_GENESIS_TABLES.len());
    for spec in ADMISSION_GENESIS_TABLES {
        if !existing_tables.iter().any(|name| name == spec.name) {
            return Err(AdmissionConsensusError::Protocol(format!(
                "admission genesis is missing authoritative table `{}`",
                spec.name
            )));
        }
        validate_admission_genesis_table_schema(connection, spec)?;
        let select_columns = spec
            .columns
            .iter()
            .map(|(name, _)| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let mut statement =
            connection.prepare(&format!("SELECT {select_columns} FROM \"{}\"", spec.name))?;
        let mut rows = statement.query([])?;
        let mut encoded_rows = Vec::new();
        while let Some(row) = rows.next()? {
            let mut encoded = Vec::with_capacity(spec.columns.len());
            for (index, (_, expected_type)) in spec.columns.iter().enumerate() {
                let value = row.get_ref(index)?;
                let value = match value {
                    rusqlite::types::ValueRef::Null => AdmissionGenesisValue::Null,
                    rusqlite::types::ValueRef::Integer(value) => {
                        AdmissionGenesisValue::Integer(value)
                    }
                    rusqlite::types::ValueRef::Real(value) => {
                        AdmissionGenesisValue::RealBits(format!("{:016x}", value.to_bits()))
                    }
                    rusqlite::types::ValueRef::Text(value) => AdmissionGenesisValue::Text(
                        std::str::from_utf8(value)
                            .map_err(|_| {
                                AdmissionConsensusError::Protocol(format!(
                                    "admission genesis table `{}` contains invalid UTF-8 text",
                                    spec.name
                                ))
                            })?
                            .to_string(),
                    ),
                    rusqlite::types::ValueRef::Blob(value) => {
                        AdmissionGenesisValue::BlobHex(lower_hex(value))
                    }
                };
                if !admission_genesis_value_matches_type(&value, *expected_type) {
                    return Err(AdmissionConsensusError::Protocol(format!(
                        "admission genesis table `{}` contains a value with the wrong logical type",
                        spec.name
                    )));
                }
                encoded.push(value);
            }
            encoded_rows.push(encoded);
        }
        let mut keyed_rows = encoded_rows
            .into_iter()
            .map(|row| {
                canonical_json_bytes(&row)
                    .map(|key| (key, row))
                    .map_err(|error| {
                        AdmissionConsensusError::Protocol(format!(
                            "admission genesis row canonicalization failed: {error}"
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        keyed_rows.sort_by(|left, right| left.0.cmp(&right.0));
        tables.push(AdmissionGenesisTable {
            name: spec.name.to_string(),
            columns: spec
                .columns
                .iter()
                .map(|(name, value_type)| AdmissionGenesisColumn {
                    name: (*name).to_string(),
                    value_type: *value_type,
                })
                .collect(),
            rows: keyed_rows.into_iter().map(|(_, row)| row).collect(),
        });
        after_table(spec.name)?;
    }
    let projection = AdmissionGenesisProjection { tables };
    validate_admission_genesis_projection(&projection)?;
    Ok(projection)
}

fn validate_admission_genesis_table_schema(
    connection: &Connection,
    spec: &AdmissionGenesisTableSpec,
) -> Result<(), AdmissionConsensusError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info(\"{}\")", spec.name))?;
    let actual = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if actual.len() != spec.columns.len() {
        return Err(AdmissionConsensusError::Protocol(format!(
            "admission genesis table `{}` has extra or missing columns",
            spec.name
        )));
    }
    for (expected_name, expected_type) in spec.columns {
        let Some((_, declared_type)) = actual.iter().find(|(name, _)| name == expected_name) else {
            return Err(AdmissionConsensusError::Protocol(format!(
                "admission genesis table `{}` is missing column `{expected_name}`",
                spec.name
            )));
        };
        if sqlite_logical_value_type(declared_type).as_ref() != Some(expected_type) {
            return Err(AdmissionConsensusError::Protocol(format!(
                "admission genesis column `{}.{expected_name}` has an incompatible logical type",
                spec.name
            )));
        }
    }
    Ok(())
}

fn sqlite_logical_value_type(declared_type: &str) -> Option<AdmissionGenesisValueType> {
    let declared = declared_type.trim().to_ascii_uppercase();
    if declared.contains("INT") {
        Some(AdmissionGenesisValueType::Integer)
    } else if declared.contains("CHAR") || declared.contains("CLOB") || declared.contains("TEXT") {
        Some(AdmissionGenesisValueType::Text)
    } else if declared.contains("REAL") || declared.contains("FLOA") || declared.contains("DOUB") {
        Some(AdmissionGenesisValueType::Real)
    } else if declared.is_empty() || declared.contains("BLOB") {
        Some(AdmissionGenesisValueType::Blob)
    } else {
        None
    }
}

fn admission_genesis_value_matches_type(
    value: &AdmissionGenesisValue,
    expected: AdmissionGenesisValueType,
) -> bool {
    matches!(value, AdmissionGenesisValue::Null)
        || matches!(
            (value, expected),
            (
                AdmissionGenesisValue::Integer(_),
                AdmissionGenesisValueType::Integer
            ) | (
                AdmissionGenesisValue::RealBits(_),
                AdmissionGenesisValueType::Real
            ) | (
                AdmissionGenesisValue::Text(_),
                AdmissionGenesisValueType::Text
            ) | (
                AdmissionGenesisValue::BlobHex(_),
                AdmissionGenesisValueType::Blob
            )
        )
}

fn validate_admission_genesis_projection(
    projection: &AdmissionGenesisProjection,
) -> Result<(), AdmissionConsensusError> {
    if projection.tables.len() != ADMISSION_GENESIS_TABLES.len() {
        return Err(AdmissionConsensusError::Protocol(
            "admission genesis projection has extra or missing tables".to_string(),
        ));
    }
    let mut row_count = 0usize;
    let mut cell_count = 0usize;
    for (table, spec) in projection.tables.iter().zip(ADMISSION_GENESIS_TABLES) {
        if table.name != spec.name || table.columns.len() != spec.columns.len() {
            return Err(AdmissionConsensusError::Protocol(
                "admission genesis projection table schema is noncanonical".to_string(),
            ));
        }
        for (column, (expected_name, expected_type)) in table.columns.iter().zip(spec.columns) {
            if column.name != *expected_name || column.value_type != *expected_type {
                return Err(AdmissionConsensusError::Protocol(format!(
                    "admission genesis projection column `{}.{}` is noncanonical",
                    table.name, column.name
                )));
            }
        }
        row_count = row_count.checked_add(table.rows.len()).ok_or_else(|| {
            AdmissionConsensusError::Protocol("admission genesis row count overflow".to_string())
        })?;
        for row in &table.rows {
            if row.len() != table.columns.len() {
                return Err(AdmissionConsensusError::Protocol(format!(
                    "admission genesis table `{}` contains a partial row",
                    table.name
                )));
            }
            cell_count = cell_count.checked_add(row.len()).ok_or_else(|| {
                AdmissionConsensusError::Protocol(
                    "admission genesis cell count overflow".to_string(),
                )
            })?;
            for (value, column) in row.iter().zip(&table.columns) {
                if !admission_genesis_value_matches_type(value, column.value_type)
                    || admission_genesis_value_bytes(value) > MAX_ADMISSION_GENESIS_CELL_BYTES
                    || !admission_genesis_value_is_canonical(value)
                {
                    return Err(AdmissionConsensusError::Protocol(format!(
                        "admission genesis table `{}` contains an invalid typed value",
                        table.name
                    )));
                }
            }
        }
        let row_keys = table
            .rows
            .iter()
            .map(canonical_json_bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                AdmissionConsensusError::Protocol(format!(
                    "admission genesis row canonicalization failed: {error}"
                ))
            })?;
        if row_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(AdmissionConsensusError::Protocol(format!(
                "admission genesis table `{}` rows are unsorted or duplicated",
                table.name
            )));
        }
    }
    if row_count > MAX_ADMISSION_GENESIS_ROWS || cell_count > MAX_ADMISSION_GENESIS_CELLS {
        return Err(AdmissionConsensusError::Protocol(
            "admission genesis projection exceeds row or cell bounds".to_string(),
        ));
    }
    let canonical = canonical_json_bytes(projection).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission genesis projection canonicalization failed: {error}"
        ))
    })?;
    if canonical.len() > MAX_ADMISSION_GENESIS_BYTES {
        return Err(AdmissionConsensusError::Protocol(
            "admission genesis projection exceeds the encoded size bound".to_string(),
        ));
    }
    Ok(())
}

fn admission_genesis_value_bytes(value: &AdmissionGenesisValue) -> usize {
    match value {
        AdmissionGenesisValue::Null | AdmissionGenesisValue::Integer(_) => 0,
        AdmissionGenesisValue::RealBits(value)
        | AdmissionGenesisValue::Text(value)
        | AdmissionGenesisValue::BlobHex(value) => value.len(),
    }
}

fn admission_genesis_value_is_canonical(value: &AdmissionGenesisValue) -> bool {
    match value {
        AdmissionGenesisValue::RealBits(value) => value.len() == 16 && is_lower_hex(value),
        AdmissionGenesisValue::BlobHex(value) => value.len() % 2 == 0 && is_lower_hex(value),
        AdmissionGenesisValue::Null
        | AdmissionGenesisValue::Integer(_)
        | AdmissionGenesisValue::Text(_) => true,
    }
}

fn admission_genesis_projection_digest(
    projection: &AdmissionGenesisProjection,
) -> Result<String, AdmissionConsensusError> {
    validate_admission_genesis_projection(projection)?;
    let canonical = canonical_json_bytes(projection).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission genesis projection canonicalization failed: {error}"
        ))
    })?;
    let mut preimage =
        Vec::with_capacity(ADMISSION_PROJECTION_BASELINE_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(ADMISSION_PROJECTION_BASELINE_DOMAIN);
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}

fn capture_admission_security_projection_digest_from_connection(
    connection: &Connection,
) -> Result<String, AdmissionConsensusError> {
    let projection = capture_admission_genesis_projection_from_connection(connection, |_| Ok(()))?;
    admission_security_projection_digest(&projection)
}

fn admission_security_projection_digest(
    projection: &AdmissionGenesisProjection,
) -> Result<String, AdmissionConsensusError> {
    validate_admission_genesis_projection(projection)?;
    let mut tables = Vec::with_capacity(projection.tables.len());
    for table in &projection.tables {
        let included = table
            .columns
            .iter()
            .enumerate()
            .filter(|(_, column)| !admission_security_projection_ignores(&table.name, &column.name))
            .collect::<Vec<_>>();
        let columns = included
            .iter()
            .map(|(_, column)| (*column).clone())
            .collect::<Vec<_>>();
        let mut rows = table
            .rows
            .iter()
            .map(|row| {
                included
                    .iter()
                    .map(|(index, _)| row[*index].clone())
                    .collect::<Vec<_>>()
            })
            .map(|row| {
                canonical_json_bytes(&row)
                    .map(|key| (key, row))
                    .map_err(|error| {
                        AdmissionConsensusError::Protocol(format!(
                            "admission security projection row canonicalization failed: {error}"
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        tables.push(AdmissionSecurityTable {
            name: table.name.clone(),
            columns,
            rows: rows.into_iter().map(|(_, row)| row).collect(),
        });
    }
    let projection = AdmissionSecurityProjection { tables };
    let canonical = canonical_json_bytes(&projection).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission security projection canonicalization failed: {error}"
        ))
    })?;
    let mut preimage =
        Vec::with_capacity(ADMISSION_SECURITY_PROJECTION_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(ADMISSION_SECURITY_PROJECTION_DOMAIN);
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}

fn admission_security_projection_ignores(table: &str, column: &str) -> bool {
    ADMISSION_SECURITY_PROJECTION_EXCLUSIONS.contains(&(table, column))
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn admission_genesis_projection_is_empty(projection: &AdmissionGenesisProjection) -> bool {
    projection.tables.iter().all(|table| {
        if table.name == "admission_authority_meta" {
            table.rows
                == vec![vec![
                    AdmissionGenesisValue::Integer(1),
                    AdmissionGenesisValue::Text("combined-admission-capture-v1".to_string()),
                    AdmissionGenesisValue::Integer(0),
                    AdmissionGenesisValue::Integer(0),
                ]]
        } else {
            table.rows.is_empty()
        }
    })
}

fn install_admission_genesis_projection(
    transaction: &Transaction<'_>,
    projection: &AdmissionGenesisProjection,
) -> Result<(), AdmissionConsensusError> {
    validate_admission_genesis_projection(projection)?;
    transaction.execute_batch(
        r#"
        PRAGMA defer_foreign_keys = ON;
        DROP TRIGGER IF EXISTS admission_revocation_insert_requires_authority;
        "#,
    )?;
    for table in projection.tables.iter().rev() {
        transaction.execute(&format!("DELETE FROM \"{}\"", table.name), [])?;
    }
    for table in &projection.tables {
        if table.rows.is_empty() {
            continue;
        }
        let columns = table
            .columns
            .iter()
            .map(|column| format!("\"{}\"", column.name))
            .collect::<Vec<_>>()
            .join(", ");
        let placeholders = (1..=table.columns.len())
            .map(|index| format!("?{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "INSERT INTO \"{}\" ({columns}) VALUES ({placeholders})",
            table.name
        );
        for row in &table.rows {
            let values = row
                .iter()
                .map(admission_genesis_sql_value)
                .collect::<Result<Vec<_>, _>>()?;
            transaction.execute(&sql, rusqlite::params_from_iter(values))?;
        }
    }
    transaction.execute_batch(
        r#"
        CREATE TRIGGER IF NOT EXISTS admission_revocation_insert_requires_authority
        BEFORE INSERT ON revoked_capabilities
        BEGIN
            SELECT RAISE(ABORT, 'revocation write requires combined admission authority');
        END;
        "#,
    )?;
    normalize_admission_transport_cache(transaction)?;
    let foreign_key_violation = transaction
        .query_row("PRAGMA foreign_key_check", [], |row| {
            row.get::<_, String>(0)
        })
        .optional()?;
    if foreign_key_violation.is_some() {
        return Err(AdmissionConsensusError::Protocol(
            "admission genesis projection violates relational integrity".to_string(),
        ));
    }
    let installed = capture_admission_genesis_projection_from_connection(transaction, |_| Ok(()))?;
    if installed != *projection {
        return Err(AdmissionConsensusError::Protocol(
            "admission genesis projection was only partially installed".to_string(),
        ));
    }
    Ok(())
}

fn admission_genesis_sql_value(
    value: &AdmissionGenesisValue,
) -> Result<rusqlite::types::Value, AdmissionConsensusError> {
    Ok(match value {
        AdmissionGenesisValue::Null => rusqlite::types::Value::Null,
        AdmissionGenesisValue::Integer(value) => rusqlite::types::Value::Integer(*value),
        AdmissionGenesisValue::RealBits(value) => {
            let bits = u64::from_str_radix(value, 16).map_err(|_| {
                AdmissionConsensusError::Protocol(
                    "admission genesis real value has invalid bits".to_string(),
                )
            })?;
            rusqlite::types::Value::Real(f64::from_bits(bits))
        }
        AdmissionGenesisValue::Text(value) => rusqlite::types::Value::Text(value.clone()),
        AdmissionGenesisValue::BlobHex(value) => {
            rusqlite::types::Value::Blob(decode_lower_hex(value)?)
        }
    })
}

fn decode_lower_hex(value: &str) -> Result<Vec<u8>, AdmissionConsensusError> {
    if !value.len().is_multiple_of(2) || !is_lower_hex(value) {
        return Err(AdmissionConsensusError::Protocol(
            "admission genesis blob is not canonical lowercase hex".to_string(),
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| {
                AdmissionConsensusError::Protocol(
                    "admission genesis blob contains invalid hex".to_string(),
                )
            })?;
            u8::from_str_radix(text, 16).map_err(|_| {
                AdmissionConsensusError::Protocol(
                    "admission genesis blob contains invalid hex".to_string(),
                )
            })
        })
        .collect()
}

fn normalize_admission_transport_cache(
    transaction: &Transaction<'_>,
) -> Result<(), AdmissionConsensusError> {
    transaction.execute("DELETE FROM budget_import_floors", [])?;
    transaction.execute("DELETE FROM budget_origin_ack_heads", [])?;
    transaction.execute("DELETE FROM budget_abandoned_event_seqs", [])?;
    transaction.execute("DELETE FROM budget_abandoned_event_ranges", [])?;
    transaction.execute(
        "UPDATE budget_ack_head_watermark SET head_seq = 0 WHERE singleton = 1",
        [],
    )?;
    transaction.execute(
        r#"
        UPDATE budget_replication_meta
        SET next_seq = MAX(
            COALESCE((SELECT MAX(seq) FROM capability_grant_budgets), 0),
            COALESCE((SELECT MAX(event_seq) FROM budget_mutation_events), 0)
        )
        WHERE singleton = 1
        "#,
        [],
    )?;
    Ok(())
}

fn apply_admission_log_entry(
    _config: &TrustServiceConfig,
    transaction: &Transaction<'_>,
    entry: &AdmissionLogEntry,
    proof: &AdmissionCommitProof,
) -> Result<String, String> {
    if proof.index != entry.index || proof.leader_epoch < entry.leader_epoch {
        return Err("admission commit proof does not match the applied entry".to_string());
    }
    match entry.command_kind {
        AdmissionCommandKind::LeadershipBarrier => canonical_result(&json!({"committed": true})),
        AdmissionCommandKind::CompositeAuthorize => {
            apply_composite_authorize(transaction, entry, proof)
        }
        AdmissionCommandKind::CaptureInvocations => {
            apply_invocation_capture(transaction, entry, proof)
        }
        AdmissionCommandKind::ReverseExposure => apply_reverse_exposure(transaction, entry, proof),
        AdmissionCommandKind::ReleaseExposure => apply_reduce_exposure(
            transaction,
            entry,
            proof,
            AdmissionCommandKind::ReleaseExposure,
        ),
        AdmissionCommandKind::ReconcileSpend => apply_reduce_exposure(
            transaction,
            entry,
            proof,
            AdmissionCommandKind::ReconcileSpend,
        ),
        AdmissionCommandKind::CaptureExposure => apply_reduce_exposure(
            transaction,
            entry,
            proof,
            AdmissionCommandKind::CaptureExposure,
        ),
        AdmissionCommandKind::Revoke => apply_revocation(transaction, entry),
        AdmissionCommandKind::CombinedCapture => apply_combined_capture(transaction, entry, proof),
    }
}

fn apply_composite_authorize(
    transaction: &Transaction<'_>,
    entry: &AdmissionLogEntry,
    proof: &AdmissionCommitProof,
) -> Result<String, String> {
    let command: ConsensusCompositeAuthorizeCommand =
        serde_json::from_str(&entry.canonical_command).map_err(|error| error.to_string())?;
    let authority = budget_authority_from_view(&command.authority)?;
    let input = super::super::budget_handlers::sqlite_composite_authorize_input(
        &command.request,
        authority.clone(),
    )
    .map_err(|error| error.to_string())?;
    let decision =
        match SqliteBudgetStore::authorize_composite_hold_in_transaction(transaction, input) {
            Ok(decision) => decision,
            Err(error) => return frozen_budget_rejection(error),
        };
    let budget_seq = load_consensus_budget_event(transaction, &command.request.event_id)?.event_seq;
    let (metadata, commit) = consensus_budget_evidence(proof, &authority, budget_seq);
    let response = super::super::budget_handlers::composite_authorize_response_view(
        &command.request,
        decision,
        metadata,
        commit,
    )
    .map_err(|error| error.to_string())?;
    canonical_result(&response)
}

fn apply_invocation_capture(
    transaction: &Transaction<'_>,
    entry: &AdmissionLogEntry,
    proof: &AdmissionCommitProof,
) -> Result<String, String> {
    let request: CaptureInvocationReservationsRequest =
        serde_json::from_str(&entry.canonical_command).map_err(|error| error.to_string())?;
    let authority = request
        .budget_authority
        .as_ref()
        .ok_or_else(|| "invocation capture omitted its persisted authority".to_string())
        .and_then(budget_authority_from_view)?;
    let decision = match SqliteBudgetStore::capture_invocation_reservations_in_transaction(
        transaction,
        &BudgetCaptureInvocationRequest {
            capability_id: request.capability_id.clone(),
            grant_index: request.grant_index,
            hold_id: Some(request.hold_id.clone()),
            event_id: Some(request.event_id.clone()),
            authority: Some(authority.clone()),
        },
    ) {
        Ok(decision) => decision,
        Err(error) => return frozen_budget_rejection(error),
    };
    if decision.invocation_state != BudgetInvocationReservationState::Captured {
        return Err("invocation capture did not reach captured state".to_string());
    }
    let budget_seq = load_consensus_budget_event(transaction, &request.event_id)?.event_seq;
    let (metadata, commit) = consensus_budget_evidence(proof, &authority, budget_seq);
    let response = super::super::budget_handlers::invocation_capture_response_view(
        &request, decision, metadata, commit,
    )
    .map_err(|error| error.to_string())?;
    canonical_result(&response)
}

fn apply_reverse_exposure(
    transaction: &Transaction<'_>,
    entry: &AdmissionLogEntry,
    proof: &AdmissionCommitProof,
) -> Result<String, String> {
    let request: ReverseChargeCostRequest =
        serde_json::from_str(&entry.canonical_command).map_err(|error| error.to_string())?;
    let hold_id = request
        .hold_id
        .as_deref()
        .ok_or_else(|| "reverse exposure command omitted hold_id".to_string())?;
    let event_id = request
        .event_id
        .as_deref()
        .ok_or_else(|| "reverse exposure command omitted event_id".to_string())?;
    let authority = request
        .budget_authority
        .as_ref()
        .ok_or_else(|| "reverse exposure command omitted persisted authority".to_string())
        .and_then(budget_authority_from_view)?;
    let decision = match SqliteBudgetStore::reverse_composite_budget_hold_in_transaction(
        transaction,
        BudgetReverseHoldRequest {
            capability_id: request.capability_id.clone(),
            grant_index: request.grant_index,
            reversed_exposure_units: request.cost_units,
            hold_id: Some(hold_id.to_string()),
            event_id: Some(event_id.to_string()),
            authority: Some(authority.clone()),
        },
    ) {
        Ok(decision) => decision,
        Err(error) => return frozen_budget_rejection(error),
    };
    if decision.invocation_state != BudgetInvocationReservationState::Reversed {
        return Err("budget reverse did not reach reversed invocation state".to_string());
    }
    let event = load_consensus_budget_event(transaction, event_id)?;
    validate_consensus_budget_event(
        &event,
        BudgetMutationKind::ReverseInvocations,
        &request.capability_id,
        request.grant_index,
        hold_id,
        request.cost_units,
        0,
        &authority,
    )?;
    let (metadata, commit) = consensus_budget_evidence(proof, &authority, event.event_seq);
    canonical_result(&ReverseChargeCostResponse {
        capability_id: request.capability_id,
        grant_index: request.grant_index,
        invocation_count: Some(event.invocation_count_after),
        total_cost_exposed: Some(event.total_cost_exposed_after),
        total_cost_realized_spend: Some(event.total_cost_realized_spend_after),
        budget_authority: Some(metadata),
        budget_commit: Some(commit),
    })
}

fn apply_reduce_exposure(
    transaction: &Transaction<'_>,
    entry: &AdmissionLogEntry,
    proof: &AdmissionCommitProof,
    command_kind: AdmissionCommandKind,
) -> Result<String, String> {
    let request: ReduceChargeCostRequest =
        serde_json::from_str(&entry.canonical_command).map_err(|error| error.to_string())?;
    let hold_id = request
        .hold_id
        .as_deref()
        .ok_or_else(|| "monetary transition command omitted hold_id".to_string())?;
    let event_id = request
        .event_id
        .as_deref()
        .ok_or_else(|| "monetary transition command omitted event_id".to_string())?;
    let authority = request
        .budget_authority
        .as_ref()
        .ok_or_else(|| "monetary transition command omitted persisted authority".to_string())
        .and_then(budget_authority_from_view)?;
    let (mutation_kind, exposure_units, realized_spend_units) = match command_kind {
        AdmissionCommandKind::ReleaseExposure => {
            if let Err(error) = SqliteBudgetStore::release_composite_budget_hold_in_transaction(
                transaction,
                BudgetReleaseHoldRequest {
                    capability_id: request.capability_id.clone(),
                    grant_index: request.grant_index,
                    released_exposure_units: request.cost_units,
                    hold_id: Some(hold_id.to_string()),
                    event_id: Some(event_id.to_string()),
                    authority: Some(authority.clone()),
                },
            ) {
                return frozen_budget_rejection(error);
            }
            (BudgetMutationKind::ReleaseExposure, request.cost_units, 0)
        }
        AdmissionCommandKind::ReconcileSpend => {
            let exposure_units = request
                .exposure_units
                .ok_or_else(|| "reconcile command omitted exposure units".to_string())?;
            let realized_spend_units = request
                .realized_spend_units
                .ok_or_else(|| "reconcile command omitted realized spend".to_string())?;
            if let Err(error) = SqliteBudgetStore::settle_composite_budget_hold_in_transaction(
                transaction,
                BudgetReconcileHoldRequest {
                    capability_id: request.capability_id.clone(),
                    grant_index: request.grant_index,
                    exposed_cost_units: exposure_units,
                    realized_spend_units,
                    hold_id: Some(hold_id.to_string()),
                    event_id: Some(event_id.to_string()),
                    authority: Some(authority.clone()),
                },
                false,
            ) {
                return frozen_budget_rejection(error);
            }
            (
                BudgetMutationKind::ReconcileSpend,
                exposure_units,
                realized_spend_units,
            )
        }
        AdmissionCommandKind::CaptureExposure => {
            let exposure_units = request
                .exposure_units
                .ok_or_else(|| "capture command omitted exposure units".to_string())?;
            let realized_spend_units = request
                .realized_spend_units
                .ok_or_else(|| "capture command omitted realized spend".to_string())?;
            if exposure_units.checked_sub(realized_spend_units) != Some(request.cost_units) {
                return Err(
                    "capture command reduction does not match exposure minus spend".to_string(),
                );
            }
            let decision = match SqliteBudgetStore::settle_composite_budget_hold_in_transaction(
                transaction,
                BudgetReconcileHoldRequest {
                    capability_id: request.capability_id.clone(),
                    grant_index: request.grant_index,
                    exposed_cost_units: exposure_units,
                    realized_spend_units,
                    hold_id: Some(hold_id.to_string()),
                    event_id: Some(event_id.to_string()),
                    authority: Some(authority.clone()),
                },
                true,
            ) {
                Ok(decision) => decision,
                Err(error) => return frozen_budget_rejection(error),
            };
            if decision.monetary_state != BudgetMonetaryHoldState::Captured {
                return Err("monetary capture did not reach captured state".to_string());
            }
            (
                BudgetMutationKind::CaptureExposure,
                exposure_units,
                realized_spend_units,
            )
        }
        _ => return Err("unsupported monetary transition command".to_string()),
    };
    let event = load_consensus_budget_event(transaction, event_id)?;
    validate_consensus_budget_event(
        &event,
        mutation_kind,
        &request.capability_id,
        request.grant_index,
        hold_id,
        exposure_units,
        realized_spend_units,
        &authority,
    )?;
    let (metadata, commit) = consensus_budget_evidence(proof, &authority, event.event_seq);
    canonical_result(&ReduceChargeCostResponse {
        capability_id: request.capability_id,
        grant_index: request.grant_index,
        invocation_count: Some(event.invocation_count_after),
        total_cost_exposed: Some(event.total_cost_exposed_after),
        total_cost_realized_spend: Some(event.total_cost_realized_spend_after),
        released_exposure_units: Some(request.cost_units),
        budget_authority: Some(metadata),
        budget_commit: Some(commit),
    })
}

fn load_consensus_budget_event(
    transaction: &Transaction<'_>,
    event_id: &str,
) -> Result<BudgetMutationRecord, String> {
    SqliteBudgetStore::mutation_event_for_event_id_in_transaction(transaction, event_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("budget event `{event_id}` is not persisted"))
}

#[allow(clippy::too_many_arguments)]
fn validate_consensus_budget_event(
    event: &BudgetMutationRecord,
    kind: BudgetMutationKind,
    capability_id: &str,
    grant_index: usize,
    hold_id: &str,
    exposure_units: u64,
    realized_spend_units: u64,
    authority: &BudgetEventAuthority,
) -> Result<(), String> {
    if event.kind != kind
        || event.capability_id != capability_id
        || usize::try_from(event.grant_index).ok() != Some(grant_index)
        || event.hold_id.as_deref() != Some(hold_id)
        || event.exposure_units != exposure_units
        || event.realized_spend_units != realized_spend_units
        || event.authority.as_ref() != Some(authority)
        || event.usage_seq != Some(event.event_seq)
    {
        return Err(format!(
            "budget event `{}` does not match its consensus command",
            event.event_id
        ));
    }
    Ok(())
}

fn apply_revocation(
    transaction: &Transaction<'_>,
    entry: &AdmissionLogEntry,
) -> Result<String, String> {
    let command: ConsensusRevocationCommand =
        serde_json::from_str(&entry.canonical_command).map_err(|error| error.to_string())?;
    let outcome = SqliteAdmissionCaptureAuthority::upsert_revocation_in_transaction(
        transaction,
        &RevocationRecord {
            capability_id: command.capability_id.clone(),
            revoked_at: command.revoked_at,
        },
    )
    .map_err(|error| error.to_string())?;
    canonical_result(&RevokeCapabilityResponse {
        capability_id: command.capability_id,
        revoked: true,
        newly_revoked: !outcome.was_present(),
    })
}

fn apply_combined_capture(
    transaction: &Transaction<'_>,
    entry: &AdmissionLogEntry,
    proof: &AdmissionCommitProof,
) -> Result<String, String> {
    let command: ConsensusCombinedCaptureCommand =
        serde_json::from_str(&entry.canonical_command).map_err(|error| error.to_string())?;
    let authority = command
        .request
        .budget_authority
        .as_ref()
        .ok_or_else(|| "combined capture omitted its persisted authority".to_string())
        .and_then(budget_authority_from_view)?;
    let revocation_set = super::super::service_runtime::budget::canonical_revocation_set_from_view(
        &command.request.revocation_set,
    )
    .map_err(|error| error.to_string())?;
    let capture_request = AdmissionCaptureRequest::new(
        command.request.operation_id.clone(),
        BudgetCaptureInvocationRequest {
            capability_id: command.request.capability_id.clone(),
            grant_index: command.request.grant_index,
            hold_id: Some(command.request.hold_id.clone()),
            event_id: Some(command.request.event_id.clone()),
            authority: Some(authority.clone()),
        },
        revocation_set,
        command.request.bound_revocation_set_digest.clone(),
        command.request.authorization_artifact_digests.clone(),
        command.request.last_observed_revocation_index,
    )
    .map_err(|error| error.to_string())?;
    let decision = match SqliteAdmissionCaptureAuthority::capture_admission_in_transaction(
        transaction,
        capture_request,
    ) {
        Ok(decision) => decision,
        Err(error) => return frozen_capture_rejection(error),
    };
    let response = match decision {
        AdmissionCaptureDecision::Captured { budget, metadata } => {
            let budget_seq = budget.metadata.budget_commit_index.ok_or_else(|| {
                "combined capture result has no persisted budget sequence".to_string()
            })?;
            let (metadata_view, commit_view) =
                consensus_budget_evidence(proof, &authority, budget_seq);
            let budget_request = CaptureInvocationReservationsRequest {
                capability_id: command.request.capability_id.clone(),
                grant_index: command.request.grant_index,
                hold_id: command.request.hold_id.clone(),
                event_id: command.request.event_id.clone(),
                budget_authority: command.request.budget_authority.clone(),
            };
            let budget = super::super::budget_handlers::invocation_capture_response_view(
                &budget_request,
                *budget,
                metadata_view,
                commit_view,
            )
            .map_err(|error| error.to_string())?;
            CombinedAdmissionCaptureResponse {
                operation_id: command.request.operation_id.clone(),
                capability_id: command.request.capability_id.clone(),
                grant_index: command.request.grant_index,
                hold_id: command.request.hold_id.clone(),
                event_id: command.request.event_id.clone(),
                outcome: AdmissionCaptureOutcomeView::Captured,
                budget: Some(budget),
                revocation_set: command.request.revocation_set.clone(),
                revoked_capability_ids: Vec::new(),
                metadata: AdmissionCaptureMetadataView {
                    operation_id: command.request.operation_id.clone(),
                    hold_id: command.request.hold_id.clone(),
                    event_id: command.request.event_id.clone(),
                    checked_revocation_set_digest: metadata
                        .checked_revocation_set_digest()
                        .to_string(),
                    invocation_quotas: command.invocation_quotas.clone(),
                    authorization_artifact_digests: command
                        .request
                        .authorization_artifact_digests
                        .clone(),
                    budget_commit_index: metadata.budget_commit().budget_commit_index,
                    revocation_commit_index: metadata.revocation_commit_index(),
                    authority_commit_index: metadata.authority_commit_index(),
                    leader_epoch: Some(proof.leader_epoch),
                    guarantee_level: BudgetGuaranteeLevelView::HaLinearizable,
                    authority: command.request.budget_authority.clone(),
                },
            }
        }
        AdmissionCaptureDecision::Denied(denial) => CombinedAdmissionCaptureResponse {
            operation_id: command.request.operation_id.clone(),
            capability_id: command.request.capability_id.clone(),
            grant_index: command.request.grant_index,
            hold_id: command.request.hold_id.clone(),
            event_id: command.request.event_id.clone(),
            outcome: AdmissionCaptureOutcomeView::DeniedRevoked,
            budget: None,
            revocation_set: command.request.revocation_set.clone(),
            revoked_capability_ids: denial.revoked_ids().to_vec(),
            metadata: AdmissionCaptureMetadataView {
                operation_id: command.request.operation_id.clone(),
                hold_id: command.request.hold_id.clone(),
                event_id: command.request.event_id.clone(),
                checked_revocation_set_digest: denial
                    .metadata()
                    .checked_revocation_set_digest()
                    .to_string(),
                invocation_quotas: command.invocation_quotas,
                authorization_artifact_digests: command
                    .request
                    .authorization_artifact_digests
                    .clone(),
                budget_commit_index: denial.metadata().budget_commit().budget_commit_index,
                revocation_commit_index: denial.metadata().revocation_commit_index(),
                authority_commit_index: denial.metadata().authority_commit_index(),
                leader_epoch: Some(proof.leader_epoch),
                guarantee_level: BudgetGuaranteeLevelView::HaLinearizable,
                authority: command.request.budget_authority.clone(),
            },
        },
    };
    canonical_result(&response)
}

fn budget_authority_from_view(
    view: &BudgetMutationAuthorityView,
) -> Result<BudgetEventAuthority, String> {
    if view.authority_id.is_empty() || view.lease_id.is_empty() || view.lease_epoch == 0 {
        return Err("admission budget authority is incomplete".to_string());
    }
    Ok(BudgetEventAuthority {
        authority_id: view.authority_id.clone(),
        lease_id: view.lease_id.clone(),
        lease_epoch: view.lease_epoch,
    })
}

fn consensus_budget_evidence(
    proof: &AdmissionCommitProof,
    authority: &BudgetEventAuthority,
    budget_seq: u64,
) -> (BudgetAuthorityMetadataView, BudgetWriteCommitView) {
    let metadata = BudgetAuthorityMetadataView {
        authority_id: authority.authority_id.clone(),
        leader_url: proof.leader_id.clone(),
        budget_term: authority.lease_epoch,
        lease_id: authority.lease_id.clone(),
        lease_epoch: authority.lease_epoch,
        lease_expires_at: u64::MAX,
        lease_ttl_ms: u64::MAX,
        guarantee_level: "ha_linearizable".to_string(),
        budget_commit_index: Some(proof.index),
    };
    let commit = BudgetWriteCommitView {
        budget_seq,
        commit_index: proof.index,
        quorum_committed: true,
        quorum_size: proof.quorum_size,
        committed_nodes: proof.witness_urls.len(),
        witness_urls: proof.witness_urls.clone(),
        authority_id: authority.authority_id.clone(),
        budget_term: authority.lease_epoch,
        lease_id: authority.lease_id.clone(),
        lease_epoch: authority.lease_epoch,
    };
    (metadata, commit)
}

fn open_capture_authority(
    config: &TrustServiceConfig,
) -> Result<SqliteAdmissionCaptureAuthority, String> {
    let budget_path = config
        .budget_db_path
        .as_deref()
        .ok_or_else(|| "admission budget database is unavailable".to_string())?;
    let revocation_path = config
        .revocation_db_path
        .as_deref()
        .ok_or_else(|| "admission revocation database is unavailable".to_string())?;
    SqliteAdmissionCaptureAuthority::open_with_paths(budget_path, revocation_path)
        .map_err(|error| error.to_string())
}

fn canonical_result<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = canonical_json_bytes(value).map_err(|error| error.to_string())?;
    String::from_utf8(bytes).map_err(|_| "canonical admission result was not UTF-8".to_string())
}

fn canonical_rejection(status_code: u16, code: &str, message: String) -> Result<String, String> {
    canonical_result(&AdmissionConsensusRejectionEnvelope {
        admission_consensus_rejection: AdmissionConsensusRejection {
            status_code,
            code: code.to_string(),
            message,
        },
    })
}

fn frozen_budget_rejection(error: BudgetStoreError) -> Result<String, String> {
    match error {
        BudgetStoreError::Conflict(message) => canonical_rejection(
            StatusCode::CONFLICT.as_u16(),
            "budget_state_conflict",
            message,
        ),
        BudgetStoreError::Overflow(message) => canonical_rejection(
            StatusCode::CONFLICT.as_u16(),
            "budget_arithmetic_conflict",
            message,
        ),
        BudgetStoreError::Invariant(message) => Err(message),
        BudgetStoreError::Sqlite(error) => Err(error.to_string()),
        BudgetStoreError::Io(error) => Err(error.to_string()),
    }
}

fn frozen_capture_rejection(error: AdmissionCaptureError) -> Result<String, String> {
    match error {
        AdmissionCaptureError::InvalidRequest(message) => canonical_rejection(
            StatusCode::CONFLICT.as_u16(),
            "admission_capture_conflict",
            message,
        ),
        AdmissionCaptureError::BudgetStore(error) => frozen_budget_rejection(error),
        AdmissionCaptureError::RevocationStore(error) => Err(error.to_string()),
        AdmissionCaptureError::Unavailable(message) => Err(message),
    }
}

fn accepted_consensus_result(
    result: AdmissionConsensusResult,
) -> Result<AdmissionConsensusResult, AdmissionConsensusError> {
    let value: Value = serde_json::from_str(&result.response_json).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "committed admission result is invalid JSON: {error}"
        ))
    })?;
    if value.get("admissionConsensusRejection").is_none() {
        return Ok(result);
    }
    let envelope: AdmissionConsensusRejectionEnvelope =
        serde_json::from_value(value).map_err(|error| {
            AdmissionConsensusError::Protocol(format!(
                "committed admission rejection is malformed: {error}"
            ))
        })?;
    let rejection = envelope.admission_consensus_rejection;
    StatusCode::from_u16(rejection.status_code).map_err(|_| {
        AdmissionConsensusError::Protocol(
            "committed admission rejection has an invalid HTTP status".to_string(),
        )
    })?;
    Err(AdmissionConsensusError::Rejected {
        status_code: rejection.status_code,
        message: rejection.message,
    })
}

fn consensus_http_error(error: AdmissionConsensusError) -> Response {
    match error {
        AdmissionConsensusError::Protocol(message) => {
            plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &message)
        }
        AdmissionConsensusError::Storage(error) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!("admission consensus storage failed: {error}"),
        ),
        AdmissionConsensusError::Apply(message) => {
            plain_http_error(StatusCode::INTERNAL_SERVER_ERROR, &message)
        }
        AdmissionConsensusError::Rejected {
            status_code,
            message,
        } => plain_http_error(
            StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            &message,
        ),
    }
}

pub(crate) async fn handle_internal_admission_proposal(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<AdmissionProposalRequest>,
) -> Response {
    if let Err(response) = validate_consensus_body_digest(&headers, &request) {
        return response;
    }
    if let Err(response) =
        validate_cluster_peer_auth(&headers, &state.config, INTERNAL_ADMISSION_PROPOSAL_PATH)
    {
        return response;
    }
    if let Err(error) = admission_members(&state) {
        return consensus_http_error(error);
    }
    let result = tokio::task::spawn_blocking(move || {
        propose_admission_command_local(
            &state,
            request.operation_id,
            request.command_kind,
            request.command,
        )
    })
    .await;
    match result {
        Ok(Ok(result)) => Json(result).into_response(),
        Ok(Err(error)) => consensus_http_error(error),
        Err(_) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "admission proposal worker failed before completion",
        ),
    }
}

pub(crate) async fn handle_internal_admission_request_vote(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<AdmissionRequestVoteRequest>,
) -> Response {
    if let Err(response) = validate_consensus_body_digest(&headers, &request) {
        return response;
    }
    let peer = match validate_cluster_peer_auth(
        &headers,
        &state.config,
        INTERNAL_ADMISSION_REQUEST_VOTE_PATH,
    ) {
        Ok(peer) => peer,
        Err(response) => return response,
    };
    if peer.term != Some(request.term) || peer.node_id != request.candidate_id {
        return plain_http_error(
            StatusCode::UNAUTHORIZED,
            "admission vote identity or term does not match peer authentication",
        );
    }
    let membership = match admission_members(&state) {
        Ok((_, _, membership)) => membership,
        Err(error) => return consensus_http_error(error),
    };
    match configured_admission_consensus_store(&state.config)
        .and_then(|store| store.request_vote(&membership, &request))
    {
        Ok(response) => Json(response).into_response(),
        Err(error) => consensus_http_error(error),
    }
}

pub(crate) async fn handle_internal_admission_append_entries(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<AdmissionAppendEntriesRequest>,
) -> Response {
    if let Err(response) = validate_consensus_body_digest(&headers, &request) {
        return response;
    }
    let peer = match validate_cluster_peer_auth(
        &headers,
        &state.config,
        INTERNAL_ADMISSION_APPEND_ENTRIES_PATH,
    ) {
        Ok(peer) => peer,
        Err(response) => return response,
    };
    if peer.term != Some(request.term) || peer.node_id != request.leader_id {
        return plain_http_error(
            StatusCode::UNAUTHORIZED,
            "admission append identity or term does not match peer authentication",
        );
    }
    let config = state.config.clone();
    let membership = match admission_members(&state) {
        Ok((_, _, membership)) => membership,
        Err(error) => return consensus_http_error(error),
    };
    let result = tokio::task::spawn_blocking(move || {
        let store = configured_admission_consensus_store(&config)?;
        store.append_entries(&membership, &request, |transaction, entry, proof| {
            apply_admission_log_entry(&config, transaction, entry, proof)
        })
    })
    .await;
    match result {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(error)) => consensus_http_error(error),
        Err(_) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "admission append worker failed before completion",
        ),
    }
}

pub(crate) async fn handle_internal_admission_snapshot(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        validate_cluster_peer_auth(&headers, &state.config, INTERNAL_ADMISSION_SNAPSHOT_PATH)
    {
        return response;
    }
    let membership = match admission_members(&state) {
        Ok((_, _, membership)) => membership,
        Err(error) => return consensus_http_error(error),
    };
    match configured_admission_consensus_store(&state.config).and_then(|store| {
        store.bind_membership(&membership)?;
        store.snapshot()
    }) {
        Ok(snapshot) => Json(snapshot).into_response(),
        Err(error) => consensus_http_error(error),
    }
}

pub(crate) async fn handle_internal_admission_snapshot_install(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(snapshot): Json<AdmissionConsensusSnapshot>,
) -> Response {
    if let Err(response) = validate_consensus_body_digest(&headers, &snapshot) {
        return response;
    }
    let peer =
        match validate_cluster_peer_auth(&headers, &state.config, INTERNAL_ADMISSION_SNAPSHOT_PATH)
        {
            Ok(peer) => peer,
            Err(response) => return response,
        };
    if peer.term != Some(snapshot.meta.current_term)
        || snapshot.meta.voted_for.as_deref() != Some(peer.node_id.as_str())
    {
        return plain_http_error(
            StatusCode::UNAUTHORIZED,
            "admission snapshot leader or term does not match peer authentication",
        );
    }
    if snapshot.meta.current_term > i64::MAX as u64 {
        return consensus_http_error(AdmissionConsensusError::Protocol(
            "admission snapshot term exceeds the supported range".to_string(),
        ));
    }
    if let Err(error) = configured_admission_consensus_store(&state.config)
        .and_then(|store| store.observe_higher_term(snapshot.meta.current_term))
    {
        return consensus_http_error(error);
    }
    let config = state.config.clone();
    let membership = match admission_member_urls(&state).and_then(|(_, _, members)| match snapshot
        .genesis_projection
        .clone()
    {
        Some(genesis) => AdmissionMembership::new_with_genesis(members, genesis),
        None => AdmissionMembership::new_with_baseline(members, None),
    }) {
        Ok(membership) => membership,
        Err(error) => return consensus_http_error(error),
    };
    match tokio::task::spawn_blocking(move || {
        configured_admission_consensus_store(&config)?.install_snapshot(
            &membership,
            &snapshot,
            |transaction, entry, proof| {
                apply_admission_log_entry(&config, transaction, entry, proof)
            },
        )
    })
    .await
    {
        Ok(Ok(())) => Json(json!({"installed": true})).into_response(),
        Ok(Err(error)) => consensus_http_error(error),
        Err(_) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "admission snapshot install failed before completion",
        ),
    }
}

fn validate_consensus_body_digest<T: Serialize>(
    headers: &HeaderMap,
    body: &T,
) -> Result<(), Response> {
    let supplied = headers
        .get(CLUSTER_AUTH_BODY_DIGEST_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            plain_http_error(
                StatusCode::UNAUTHORIZED,
                "admission consensus request omitted its signed body digest",
            )
        })?;
    let canonical = canonical_json_bytes(body).map_err(|error| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            &format!("admission consensus body cannot be canonicalized: {error}"),
        )
    })?;
    let expected = sha256_hex(&canonical);
    if !bool::from(supplied.as_bytes().ct_eq(expected.as_bytes())) {
        return Err(plain_http_error(
            StatusCode::UNAUTHORIZED,
            "admission consensus body digest does not match the request",
        ));
    }
    Ok(())
}

fn configure_connection(connection: &Connection) -> Result<(), rusqlite::Error> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;",
    )
}

fn initialize_schema(connection: &mut Connection) -> Result<(), AdmissionConsensusError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS admission_consensus_meta (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            schema_version INTEGER NOT NULL CHECK (schema_version = 2),
            current_term INTEGER NOT NULL CHECK (current_term >= 0),
            baseline_state_digest TEXT
                CHECK (
                    baseline_state_digest IS NULL
                    OR (
                        length(baseline_state_digest) = 64
                        AND baseline_state_digest NOT GLOB '*[^0-9a-f]*'
                    )
                ),
            membership_digest TEXT
                CHECK (
                    membership_digest IS NULL
                    OR (
                        length(membership_digest) = 64
                        AND membership_digest NOT GLOB '*[^0-9a-f]*'
                    )
                ),
            voted_for TEXT,
            last_log_index INTEGER NOT NULL CHECK (last_log_index >= 0),
            last_log_term INTEGER NOT NULL CHECK (last_log_term >= 0),
            commit_index INTEGER NOT NULL CHECK (commit_index >= 0),
            last_applied INTEGER NOT NULL CHECK (last_applied >= 0),
            applied_state_digest TEXT NOT NULL
                CHECK (
                    length(applied_state_digest) = 64
                    AND applied_state_digest NOT GLOB '*[^0-9a-f]*'
                ),
            CHECK (last_applied <= commit_index),
            CHECK (commit_index <= last_log_index)
        );

        CREATE TABLE IF NOT EXISTS admission_consensus_log (
            log_index INTEGER PRIMARY KEY CHECK (log_index > 0),
            leader_epoch INTEGER NOT NULL CHECK (leader_epoch > 0),
            operation_id TEXT NOT NULL UNIQUE,
            command_kind TEXT NOT NULL CHECK (command_kind IN (
                'leadership_barrier', 'composite_authorize', 'capture_invocations',
                'reverse_exposure', 'release_exposure', 'reconcile_spend',
                'capture_exposure', 'revoke', 'combined_capture'
            )),
            canonical_command TEXT NOT NULL,
            command_digest TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS admission_consensus_commits (
            log_index INTEGER PRIMARY KEY REFERENCES admission_consensus_log(log_index),
            leader_epoch INTEGER NOT NULL CHECK (leader_epoch > 0),
            current_term_commit_index INTEGER NOT NULL
                CHECK (current_term_commit_index >= log_index),
            leader_id TEXT NOT NULL,
            membership_digest TEXT NOT NULL
                CHECK (
                    length(membership_digest) = 64
                    AND membership_digest NOT GLOB '*[^0-9a-f]*'
                ),
            quorum_size INTEGER NOT NULL CHECK (quorum_size > 0),
            witness_urls_json TEXT NOT NULL,
            protocol_version TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS admission_consensus_results (
            operation_id TEXT PRIMARY KEY REFERENCES admission_consensus_log(operation_id),
            log_index INTEGER NOT NULL UNIQUE REFERENCES admission_consensus_log(log_index),
            response_json TEXT NOT NULL,
            response_digest TEXT NOT NULL,
            security_projection_digest TEXT NOT NULL
                CHECK (
                    length(security_projection_digest) = 64
                    AND security_projection_digest NOT GLOB '*[^0-9a-f]*'
                )
        );

        CREATE TABLE IF NOT EXISTS admission_consensus_genesis (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            projection_json TEXT NOT NULL,
            projection_digest TEXT NOT NULL
                CHECK (
                    length(projection_digest) = 64
                    AND projection_digest NOT GLOB '*[^0-9a-f]*'
                )
        );
        "#,
    )?;
    let has_baseline = {
        let mut statement = transaction.prepare("PRAGMA table_info(admission_consensus_meta)")?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()?;
        columns
            .iter()
            .any(|column| column == "baseline_state_digest")
    };
    if !has_baseline {
        transaction.execute_batch(
            r#"
            ALTER TABLE admission_consensus_meta
            ADD COLUMN baseline_state_digest TEXT
                CHECK (
                    baseline_state_digest IS NULL
                    OR (
                        length(baseline_state_digest) = 64
                        AND baseline_state_digest NOT GLOB '*[^0-9a-f]*'
                    )
                );
            "#,
        )?;
    }
    transaction.execute(
        r#"
        INSERT OR IGNORE INTO admission_consensus_meta (
            singleton, schema_version, current_term, baseline_state_digest,
            membership_digest, voted_for,
            last_log_index, last_log_term, commit_index, last_applied,
            applied_state_digest
        ) VALUES (1, 2, 0, NULL, NULL, NULL, 0, 0, 0, 0, ?1)
        "#,
        params![initial_applied_state_digest()],
    )?;
    transaction.commit()?;
    load_meta(connection)?;
    validate_consensus_result_schema(connection)?;
    Ok(())
}

fn validate_consensus_result_schema(
    connection: &Connection,
) -> Result<(), AdmissionConsensusError> {
    let mut statement = connection.prepare("PRAGMA table_info(admission_consensus_results)")?;
    let columns = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if !columns.iter().any(|(name, value_type, not_null)| {
        name == "security_projection_digest"
            && value_type.eq_ignore_ascii_case("TEXT")
            && *not_null == 1
    }) {
        return Err(AdmissionConsensusError::Protocol(
            "admission consensus result schema does not provide the v2 security projection digest"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_integrity(connection: &Connection) -> Result<(), AdmissionConsensusError> {
    let meta = load_meta(connection)?;
    if meta
        .membership_digest
        .as_deref()
        .is_some_and(|digest| !is_lower_sha256(digest))
        || meta
            .baseline_state_digest
            .as_deref()
            .is_some_and(|digest| !is_lower_sha256(digest))
        || (meta.membership_digest.is_none() && meta.baseline_state_digest.is_some())
        || !is_lower_sha256(&meta.applied_state_digest)
        || meta.current_term < meta.last_log_term
        || meta
            .voted_for
            .as_deref()
            .is_some_and(|candidate| validate_node_id(candidate).is_err())
        || (meta.membership_digest.is_none()
            && (meta.current_term != 0 || meta.last_log_index != 0))
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission persisted membership binding is invalid".to_string(),
        ));
    }
    let genesis_projection = load_genesis_projection(connection)?;
    match (
        meta.baseline_state_digest.as_deref(),
        genesis_projection.as_ref(),
    ) {
        (Some(expected), Some(projection))
            if admission_genesis_projection_digest(projection)? == expected => {}
        (None, None) => {}
        _ => {
            return Err(AdmissionConsensusError::Protocol(
                "admission persisted genesis projection does not match its baseline".to_string(),
            ));
        }
    }
    let entries = load_all_entries(connection)?;
    if entries.len() != usize_index(meta.last_log_index, "admission last log index")? {
        return Err(AdmissionConsensusError::Protocol(
            "admission log is not contiguous".to_string(),
        ));
    }
    for (offset, entry) in entries.iter().enumerate() {
        if entry.index != one_based_offset(offset, "admission log offset")? {
            return Err(AdmissionConsensusError::Protocol(
                "admission log contains an index gap".to_string(),
            ));
        }
        validate_entry(entry)?;
    }
    if entries
        .windows(2)
        .any(|pair| pair[0].leader_epoch > pair[1].leader_epoch)
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission log terms are not monotonic".to_string(),
        ));
    }
    if let Some(last) = entries.last() {
        if last.index != meta.last_log_index || last.leader_epoch != meta.last_log_term {
            return Err(AdmissionConsensusError::Protocol(
                "admission persisted log head does not match the log".to_string(),
            ));
        }
    } else if meta.last_log_index != 0 || meta.last_log_term != 0 {
        return Err(AdmissionConsensusError::Protocol(
            "empty admission log has a nonzero head".to_string(),
        ));
    }
    for index in 1..=meta.commit_index {
        let proof = load_commit_proof(connection, index)?.ok_or_else(|| {
            AdmissionConsensusError::Protocol(format!("admission commit proof {index} is missing"))
        })?;
        validate_commit_proof(&proof)?;
        if meta.membership_digest.as_deref() != Some(proof.membership_digest.as_str()) {
            return Err(AdmissionConsensusError::Protocol(
                "admission commit proof membership differs from persisted state".to_string(),
            ));
        }
        if proof.leader_epoch > meta.current_term {
            return Err(AdmissionConsensusError::Protocol(
                "admission commit proof exceeds the persisted term".to_string(),
            ));
        }
        let entry = load_entry(connection, index)?.ok_or_else(|| {
            AdmissionConsensusError::Protocol(format!("admission entry {index} is missing"))
        })?;
        if entry.leader_epoch > proof.leader_epoch {
            return Err(AdmissionConsensusError::Protocol(
                "admission commit proof predates its log entry".to_string(),
            ));
        }
        if load_entry(connection, proof.current_term_commit_index)?
            .is_none_or(|entry| entry.leader_epoch != proof.leader_epoch)
        {
            return Err(AdmissionConsensusError::Protocol(
                "admission commit proof has no current-term commit target".to_string(),
            ));
        }
    }
    let results = load_results(connection)?;
    if results.len() != usize_index(meta.last_applied, "admission applied result index")? {
        return Err(AdmissionConsensusError::Protocol(
            "admission result coverage does not match last-applied".to_string(),
        ));
    }
    let mut applied_state_digest = initial_applied_state_digest();
    for (offset, result) in results.iter().enumerate() {
        let index = one_based_offset(offset, "admission result offset")?;
        let entry = load_entry(connection, index)?.ok_or_else(|| {
            AdmissionConsensusError::Protocol(format!("admission entry {index} is missing"))
        })?;
        validate_canonical_json(&result.response_json, "admission persisted result")?;
        if result.log_index != index
            || result.operation_id != entry.operation_id
            || sha256_hex(result.response_json.as_bytes()) != result.response_digest
            || !is_lower_sha256(&result.security_projection_digest)
        {
            return Err(AdmissionConsensusError::Protocol(format!(
                "admission result {index} does not match its entry or digest"
            )));
        }
        applied_state_digest = next_applied_state_digest(
            &applied_state_digest,
            &result.response_digest,
            &result.security_projection_digest,
        )?;
    }
    if meta.applied_state_digest != applied_state_digest {
        return Err(AdmissionConsensusError::Protocol(
            "admission applied-state digest does not match persisted results".to_string(),
        ));
    }
    let expected_security_projection = if meta.baseline_state_digest.is_none() {
        None
    } else if let Some(result) = results.last() {
        Some(result.security_projection_digest.clone())
    } else if let Some(genesis_projection) = genesis_projection.as_ref() {
        Some(admission_security_projection_digest(genesis_projection)?)
    } else {
        None
    };
    if let Some(expected) = expected_security_projection {
        let live = capture_admission_security_projection_digest_from_connection(connection)?;
        if live != expected {
            return Err(AdmissionConsensusError::Protocol(
                "admission live security projection differs from the committed result chain"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

fn load_meta(
    connection: &Connection,
) -> Result<AdmissionConsensusMetaView, AdmissionConsensusError> {
    let raw = connection.query_row(
        r#"
        SELECT current_term, baseline_state_digest, membership_digest, voted_for,
               last_log_index, last_log_term, commit_index, last_applied,
               applied_state_digest
        FROM admission_consensus_meta
        WHERE singleton = 1 AND schema_version = ?1
        "#,
        params![CONSENSUS_SCHEMA_VERSION],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, String>(8)?,
            ))
        },
    )?;
    Ok(AdmissionConsensusMetaView {
        current_term: nonnegative_u64(raw.0, "current term")?,
        baseline_state_digest: raw.1,
        membership_digest: raw.2,
        voted_for: raw.3,
        last_log_index: nonnegative_u64(raw.4, "last log index")?,
        last_log_term: nonnegative_u64(raw.5, "last log term")?,
        commit_index: nonnegative_u64(raw.6, "commit index")?,
        last_applied: nonnegative_u64(raw.7, "last applied")?,
        applied_state_digest: raw.8,
    })
}

fn load_genesis_projection(
    connection: &Connection,
) -> Result<Option<AdmissionGenesisProjection>, AdmissionConsensusError> {
    let stored = connection
        .query_row(
            r#"
            SELECT projection_json, projection_digest
            FROM admission_consensus_genesis
            WHERE singleton = 1
            "#,
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((projection_json, projection_digest)) = stored else {
        return Ok(None);
    };
    let projection: AdmissionGenesisProjection =
        serde_json::from_str(&projection_json).map_err(|error| {
            AdmissionConsensusError::Protocol(format!(
                "persisted admission genesis projection is invalid: {error}"
            ))
        })?;
    let canonical = canonical_json_bytes(&projection).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "persisted admission genesis projection cannot be canonicalized: {error}"
        ))
    })?;
    if canonical != projection_json.as_bytes()
        || admission_genesis_projection_digest(&projection)? != projection_digest
    {
        return Err(AdmissionConsensusError::Protocol(
            "persisted admission genesis projection or digest is noncanonical".to_string(),
        ));
    }
    Ok(Some(projection))
}

fn persist_genesis_projection(
    transaction: &Transaction<'_>,
    projection: &AdmissionGenesisProjection,
) -> Result<(), AdmissionConsensusError> {
    let projection_digest = admission_genesis_projection_digest(projection)?;
    let projection_json = String::from_utf8(canonical_json_bytes(projection).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission genesis projection cannot be canonicalized: {error}"
        ))
    })?)
    .map_err(|_| {
        AdmissionConsensusError::Protocol(
            "admission genesis projection canonical JSON is not UTF-8".to_string(),
        )
    })?;
    if let Some(existing) = load_genesis_projection(transaction)? {
        if existing != *projection {
            return Err(AdmissionConsensusError::Protocol(
                "admission genesis projection differs from persisted state".to_string(),
            ));
        }
        return Ok(());
    }
    transaction.execute(
        r#"
        INSERT INTO admission_consensus_genesis (
            singleton, projection_json, projection_digest
        ) VALUES (1, ?1, ?2)
        "#,
        params![projection_json, projection_digest],
    )?;
    Ok(())
}

fn bind_membership(
    transaction: &Transaction<'_>,
    membership: &AdmissionMembership,
) -> Result<AdmissionConsensusMetaView, AdmissionConsensusError> {
    let mut meta = load_meta(transaction)?;
    match meta.membership_digest.as_deref() {
        Some(digest)
            if digest == membership.digest()
                && meta.baseline_state_digest == membership.baseline_digest =>
        {
            if meta
                .voted_for
                .as_deref()
                .is_some_and(|candidate| !membership.contains(candidate))
            {
                return Err(AdmissionConsensusError::Protocol(
                    "admission persisted vote is not a configured member".to_string(),
                ));
            }
            match (
                membership.genesis_projection.as_ref(),
                load_genesis_projection(transaction)?,
            ) {
                (Some(expected), Some(persisted)) if *expected == persisted => {}
                (None, None) if membership.baseline_digest.is_none() => {}
                _ => {
                    return Err(AdmissionConsensusError::Protocol(
                        "admission membership genesis differs from persisted state".to_string(),
                    ));
                }
            }
            if membership.genesis_projection.is_some() {
                normalize_admission_transport_cache(transaction)?;
            }
            return Ok(meta);
        }
        Some(_) => {
            return Err(AdmissionConsensusError::Protocol(
                "admission consensus membership differs from persisted state".to_string(),
            ));
        }
        None => {}
    }
    match membership.genesis_projection.as_ref() {
        Some(projection) => {
            if membership.baseline_digest.as_deref()
                != Some(admission_genesis_projection_digest(projection)?.as_str())
            {
                return Err(AdmissionConsensusError::Protocol(
                    "admission membership baseline does not match its genesis projection"
                        .to_string(),
                ));
            }
            normalize_admission_transport_cache(transaction)?;
            persist_genesis_projection(transaction, projection)?;
        }
        None if membership.baseline_digest.is_none() => {}
        None => {
            return Err(AdmissionConsensusError::Protocol(
                "admission membership baseline omitted its genesis projection".to_string(),
            ));
        }
    }
    let updated = transaction.execute(
        r#"
        UPDATE admission_consensus_meta
        SET membership_digest = ?1, baseline_state_digest = ?2
        WHERE singleton = 1
          AND membership_digest IS NULL
          AND baseline_state_digest IS NULL
        "#,
        params![membership.digest(), membership.baseline_digest],
    )?;
    if updated != 1 {
        return Err(AdmissionConsensusError::Protocol(
            "admission membership binding changed concurrently".to_string(),
        ));
    }
    meta.membership_digest = Some(membership.digest().to_string());
    meta.baseline_state_digest = membership.baseline_digest.clone();
    Ok(meta)
}

fn vote_response(
    membership: &AdmissionMembership,
    term: u64,
    vote_granted: bool,
) -> AdmissionRequestVoteResponse {
    AdmissionRequestVoteResponse {
        protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
        membership_digest: membership.digest().to_string(),
        term,
        vote_granted,
    }
}

fn append_rejection(
    membership: &AdmissionMembership,
    meta: &AdmissionConsensusMetaView,
    rejection: &str,
) -> AdmissionAppendEntriesResponse {
    AdmissionAppendEntriesResponse {
        protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
        membership_digest: membership.digest().to_string(),
        term: meta.current_term,
        accepted: false,
        match_index: meta.last_log_index,
        commit_index: meta.commit_index,
        applied_index: meta.last_applied,
        applied_state_digest: meta.applied_state_digest.clone(),
        rejection: Some(rejection.to_string()),
    }
}

fn reject_append_after_hard_state(
    transaction: Transaction<'_>,
    membership: &AdmissionMembership,
    rejection: &str,
) -> Result<AdmissionAppendEntriesResponse, AdmissionConsensusError> {
    transaction
        .execute_batch("ROLLBACK TO chio_admission_append; RELEASE chio_admission_append")?;
    let durable = load_meta(&transaction)?;
    let response = append_rejection(membership, &durable, rejection);
    transaction.commit()?;
    Ok(response)
}

fn validate_node_id(value: &str) -> Result<(), AdmissionConsensusError> {
    if value.is_empty() || value.len() > 2048 || value.bytes().any(|byte| byte == 0) {
        return Err(AdmissionConsensusError::Protocol(
            "admission consensus node id is invalid".to_string(),
        ));
    }
    Ok(())
}

fn validate_operation_id(value: &str) -> Result<(), AdmissionConsensusError> {
    if value.is_empty() || value.len() > 512 || value.bytes().any(|byte| byte == 0) {
        return Err(AdmissionConsensusError::Protocol(
            "admission consensus operation id is invalid".to_string(),
        ));
    }
    Ok(())
}

fn scoped_operation_id(
    command_kind: AdmissionCommandKind,
    external_operation_id: &str,
) -> Result<String, AdmissionConsensusError> {
    validate_operation_id(external_operation_id)?;
    let canonical = canonical_json_bytes(&json!({
        "commandKind": command_kind_label(command_kind),
        "operationId": external_operation_id,
    }))
    .map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission operation scope canonicalization failed: {error}"
        ))
    })?;
    let mut preimage = Vec::with_capacity(ADMISSION_OPERATION_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(ADMISSION_OPERATION_DOMAIN);
    preimage.extend_from_slice(&canonical);
    Ok(sha256_hex(&preimage))
}

fn initial_applied_state_digest() -> String {
    sha256_hex(ADMISSION_APPLIED_STATE_DOMAIN)
}

fn initial_security_projection_digest() -> String {
    sha256_hex(ADMISSION_SECURITY_PROJECTION_DOMAIN)
}

fn next_applied_state_digest(
    previous_digest: &str,
    result_digest: &str,
    security_projection_digest: &str,
) -> Result<String, AdmissionConsensusError> {
    if !is_lower_sha256(previous_digest)
        || !is_lower_sha256(result_digest)
        || !is_lower_sha256(security_projection_digest)
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission applied-state digest input is invalid".to_string(),
        ));
    }
    let mut preimage = Vec::with_capacity(
        ADMISSION_APPLIED_STATE_DOMAIN.len()
            + previous_digest.len()
            + result_digest.len()
            + security_projection_digest.len(),
    );
    preimage.extend_from_slice(ADMISSION_APPLIED_STATE_DOMAIN);
    preimage.extend_from_slice(previous_digest.as_bytes());
    preimage.extend_from_slice(result_digest.as_bytes());
    preimage.extend_from_slice(security_projection_digest.as_bytes());
    Ok(sha256_hex(&preimage))
}

fn validate_entry(entry: &AdmissionLogEntry) -> Result<(), AdmissionConsensusError> {
    if entry.index == 0 || entry.leader_epoch == 0 {
        return Err(AdmissionConsensusError::Protocol(
            "admission log index and leader epoch must be positive".to_string(),
        ));
    }
    validate_operation_id(&entry.operation_id)?;
    validate_canonical_json(&entry.canonical_command, "admission command")?;
    if sha256_hex(entry.canonical_command.as_bytes()) != entry.command_digest {
        return Err(AdmissionConsensusError::Protocol(
            "admission command digest does not match canonical command bytes".to_string(),
        ));
    }
    Ok(())
}

fn validate_canonical_json(value: &str, label: &str) -> Result<(), AdmissionConsensusError> {
    let parsed: Value = serde_json::from_str(value).map_err(|error| {
        AdmissionConsensusError::Protocol(format!("{label} is not valid JSON: {error}"))
    })?;
    let canonical = canonical_json_bytes(&parsed).map_err(|error| {
        AdmissionConsensusError::Protocol(format!("{label} cannot be canonicalized: {error}"))
    })?;
    if canonical != value.as_bytes() {
        return Err(AdmissionConsensusError::Protocol(format!(
            "{label} is not canonical JSON"
        )));
    }
    Ok(())
}

fn validate_commit_proof(proof: &AdmissionCommitProof) -> Result<(), AdmissionConsensusError> {
    if proof.protocol_version != ADMISSION_CONSENSUS_PROTOCOL_VERSION
        || !is_lower_sha256(&proof.membership_digest)
        || proof.index == 0
        || proof.leader_epoch == 0
        || proof.current_term_commit_index < proof.index
        || proof.quorum_size == 0
        || proof.witness_urls.len() < proof.quorum_size
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission commit proof is incomplete".to_string(),
        ));
    }
    validate_node_id(&proof.leader_id)?;
    let unique = proof.witness_urls.iter().collect::<BTreeSet<_>>();
    if unique.len() != proof.witness_urls.len()
        || proof.witness_urls.windows(2).any(|pair| pair[0] >= pair[1])
        || !proof.witness_urls.iter().any(|url| url == &proof.leader_id)
        || proof
            .witness_urls
            .iter()
            .any(|url| validate_node_id(url).is_err())
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission commit proof witnesses are invalid".to_string(),
        ));
    }
    Ok(())
}

fn validate_commit_proof_for_membership(
    proof: &AdmissionCommitProof,
    membership: &AdmissionMembership,
) -> Result<(), AdmissionConsensusError> {
    validate_commit_proof(proof)?;
    if proof.membership_digest != membership.digest()
        || proof.quorum_size != membership.quorum_size()
        || proof
            .witness_urls
            .iter()
            .any(|witness| !membership.contains(witness))
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission commit proof does not match configured membership".to_string(),
        ));
    }
    Ok(())
}

fn validate_snapshot(snapshot: &AdmissionConsensusSnapshot) -> Result<(), AdmissionConsensusError> {
    if snapshot.protocol_version != ADMISSION_CONSENSUS_PROTOCOL_VERSION
        || snapshot
            .meta
            .membership_digest
            .as_deref()
            .is_none_or(|digest| !is_lower_sha256(digest))
        || !is_lower_sha256(&snapshot.meta.applied_state_digest)
        || snapshot.meta.current_term > i64::MAX as u64
        || snapshot.meta.current_term < snapshot.meta.last_log_term
        || snapshot.meta.last_applied != snapshot.meta.commit_index
        || snapshot.entries.len()
            != usize_index(snapshot.meta.last_log_index, "admission snapshot log index")?
        || snapshot.commit_proofs.len()
            != usize_index(
                snapshot.meta.commit_index,
                "admission snapshot commit index",
            )?
        || snapshot.results.len()
            != usize_index(
                snapshot.meta.last_applied,
                "admission snapshot applied index",
            )?
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission consensus snapshot metadata is inconsistent".to_string(),
        ));
    }
    match (
        snapshot.meta.baseline_state_digest.as_deref(),
        snapshot.genesis_projection.as_ref(),
    ) {
        (Some(expected), Some(projection))
            if admission_genesis_projection_digest(projection)? == expected => {}
        (None, None) => {}
        _ => {
            return Err(AdmissionConsensusError::Protocol(
                "admission consensus snapshot genesis is missing or corrupted".to_string(),
            ));
        }
    }
    for (offset, entry) in snapshot.entries.iter().enumerate() {
        validate_entry(entry)?;
        if entry.index != one_based_offset(offset, "admission snapshot log offset")? {
            return Err(AdmissionConsensusError::Protocol(
                "admission snapshot log is not contiguous".to_string(),
            ));
        }
    }
    if snapshot
        .entries
        .windows(2)
        .any(|pair| pair[0].leader_epoch > pair[1].leader_epoch)
        || snapshot
            .entries
            .last()
            .map_or(snapshot.meta.last_log_term != 0, |entry| {
                entry.leader_epoch != snapshot.meta.last_log_term
            })
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission snapshot log terms are inconsistent".to_string(),
        ));
    }
    for (offset, proof) in snapshot.commit_proofs.iter().enumerate() {
        validate_commit_proof(proof)?;
        if proof.index != one_based_offset(offset, "admission snapshot proof offset")? {
            return Err(AdmissionConsensusError::Protocol(
                "admission snapshot commit proofs are not exact and contiguous".to_string(),
            ));
        }
        if snapshot.meta.membership_digest.as_deref() != Some(proof.membership_digest.as_str()) {
            return Err(AdmissionConsensusError::Protocol(
                "admission snapshot proof membership does not match metadata".to_string(),
            ));
        }
        if proof.leader_epoch > snapshot.meta.current_term
            || proof.current_term_commit_index > snapshot.meta.commit_index
        {
            return Err(AdmissionConsensusError::Protocol(
                "admission snapshot proof exceeds the committed term or index".to_string(),
            ));
        }
        let entry_offset = usize_index(
            checked_predecessor(proof.index, "admission snapshot proof index")?,
            "admission snapshot proof offset",
        )?;
        if snapshot
            .entries
            .get(entry_offset)
            .is_none_or(|entry| entry.leader_epoch > proof.leader_epoch)
        {
            return Err(AdmissionConsensusError::Protocol(
                "admission snapshot proof does not match its entry".to_string(),
            ));
        }
        let current_term_offset = usize_index(
            checked_predecessor(
                proof.current_term_commit_index,
                "admission snapshot current-term commit index",
            )?,
            "admission snapshot current-term commit offset",
        )?;
        if snapshot
            .entries
            .get(current_term_offset)
            .is_none_or(|entry| entry.leader_epoch != proof.leader_epoch)
        {
            return Err(AdmissionConsensusError::Protocol(
                "admission snapshot proof has no current-term commit target".to_string(),
            ));
        }
    }
    let mut applied_state_digest = initial_applied_state_digest();
    for (offset, result) in snapshot.results.iter().enumerate() {
        validate_canonical_json(&result.response_json, "admission snapshot result")?;
        let expected_index = one_based_offset(offset, "admission snapshot result offset")?;
        let entry_offset = usize_index(
            checked_predecessor(result.log_index, "admission snapshot result index")?,
            "admission snapshot result offset",
        )?;
        if result.log_index != expected_index
            || sha256_hex(result.response_json.as_bytes()) != result.response_digest
            || !is_lower_sha256(&result.security_projection_digest)
            || snapshot
                .entries
                .get(entry_offset)
                .is_none_or(|entry| entry.operation_id != result.operation_id)
        {
            return Err(AdmissionConsensusError::Protocol(
                "admission snapshot result does not match its log entry".to_string(),
            ));
        }
        applied_state_digest = next_applied_state_digest(
            &applied_state_digest,
            &result.response_digest,
            &result.security_projection_digest,
        )?;
    }
    if snapshot.meta.applied_state_digest != applied_state_digest {
        return Err(AdmissionConsensusError::Protocol(
            "admission snapshot applied-state digest does not match its results".to_string(),
        ));
    }
    Ok(())
}

fn validate_snapshot_for_membership(
    snapshot: &AdmissionConsensusSnapshot,
    membership: &AdmissionMembership,
) -> Result<(), AdmissionConsensusError> {
    validate_snapshot(snapshot)?;
    if snapshot.meta.membership_digest.as_deref() != Some(membership.digest())
        || snapshot.meta.baseline_state_digest != membership.baseline_digest
        || snapshot.genesis_projection != membership.genesis_projection
        || snapshot
            .meta
            .voted_for
            .as_deref()
            .is_some_and(|candidate| !membership.contains(candidate))
    {
        return Err(AdmissionConsensusError::Protocol(
            "admission snapshot membership differs from configured membership".to_string(),
        ));
    }
    for proof in &snapshot.commit_proofs {
        validate_commit_proof_for_membership(proof, membership)?;
    }
    Ok(())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn previous_entry_matches(
    connection: &Connection,
    index: u64,
    term: u64,
) -> Result<bool, AdmissionConsensusError> {
    if index == 0 {
        return Ok(term == 0);
    }
    Ok(load_entry(connection, index)?.is_some_and(|entry| entry.leader_epoch == term))
}

fn insert_entry(
    transaction: &Transaction<'_>,
    entry: &AdmissionLogEntry,
) -> Result<(), AdmissionConsensusError> {
    transaction.execute(
        r#"
        INSERT INTO admission_consensus_log (
            log_index, leader_epoch, operation_id, command_kind,
            canonical_command, command_digest
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#,
        params![
            sqlite_u64(entry.index)?,
            sqlite_u64(entry.leader_epoch)?,
            entry.operation_id,
            command_kind_label(entry.command_kind),
            entry.canonical_command,
            entry.command_digest,
        ],
    )?;
    Ok(())
}

fn update_log_head(
    transaction: &Transaction<'_>,
    index: u64,
    term: u64,
) -> Result<(), AdmissionConsensusError> {
    transaction.execute(
        r#"
        UPDATE admission_consensus_meta
        SET last_log_index = ?1, last_log_term = ?2
        WHERE singleton = 1
        "#,
        params![sqlite_u64(index)?, sqlite_u64(term)?],
    )?;
    Ok(())
}

fn load_entry(
    connection: &Connection,
    index: u64,
) -> Result<Option<AdmissionLogEntry>, AdmissionConsensusError> {
    let raw = connection
        .query_row(
            r#"
            SELECT log_index, leader_epoch, operation_id, command_kind,
                   canonical_command, command_digest
            FROM admission_consensus_log
            WHERE log_index = ?1
            "#,
            params![sqlite_u64(index)?],
            read_entry_raw,
        )
        .optional()?;
    raw.map(entry_from_raw).transpose()
}

fn load_entry_by_operation(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<AdmissionLogEntry>, AdmissionConsensusError> {
    let raw = connection
        .query_row(
            r#"
            SELECT log_index, leader_epoch, operation_id, command_kind,
                   canonical_command, command_digest
            FROM admission_consensus_log
            WHERE operation_id = ?1
            "#,
            params![operation_id],
            read_entry_raw,
        )
        .optional()?;
    raw.map(entry_from_raw).transpose()
}

type EntryRaw = (i64, i64, String, String, String, String);

fn read_entry_raw(row: &rusqlite::Row<'_>) -> rusqlite::Result<EntryRaw> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

fn entry_from_raw(raw: EntryRaw) -> Result<AdmissionLogEntry, AdmissionConsensusError> {
    Ok(AdmissionLogEntry {
        index: nonnegative_u64(raw.0, "log index")?,
        leader_epoch: nonnegative_u64(raw.1, "leader epoch")?,
        operation_id: raw.2,
        command_kind: command_kind_from_label(&raw.3)?,
        canonical_command: raw.4,
        command_digest: raw.5,
    })
}

fn load_all_entries(
    connection: &Connection,
) -> Result<Vec<AdmissionLogEntry>, AdmissionConsensusError> {
    let mut statement = connection.prepare(
        r#"
        SELECT log_index, leader_epoch, operation_id, command_kind,
               canonical_command, command_digest
        FROM admission_consensus_log
        ORDER BY log_index ASC
        "#,
    )?;
    let rows = statement.query_map([], read_entry_raw)?;
    let mut entries = Vec::new();
    for row in rows {
        entries.push(entry_from_raw(row?)?);
    }
    Ok(entries)
}

fn insert_commit_proof(
    transaction: &Transaction<'_>,
    proof: &AdmissionCommitProof,
) -> Result<(), AdmissionConsensusError> {
    let witnesses = canonical_json_bytes(&proof.witness_urls).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission witness canonicalization failed: {error}"
        ))
    })?;
    let witnesses = String::from_utf8(witnesses).map_err(|_| {
        AdmissionConsensusError::Protocol("admission witness JSON was not UTF-8".to_string())
    })?;
    if let Some(existing) = load_commit_proof(transaction, proof.index)? {
        if existing != *proof {
            return Err(AdmissionConsensusError::Protocol(
                "admission commit proof conflicts with persisted evidence".to_string(),
            ));
        }
        return Ok(());
    }
    transaction.execute(
        r#"
        INSERT INTO admission_consensus_commits (
            log_index, leader_epoch, current_term_commit_index, leader_id,
            membership_digest, quorum_size, witness_urls_json, protocol_version
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
        params![
            sqlite_u64(proof.index)?,
            sqlite_u64(proof.leader_epoch)?,
            sqlite_u64(proof.current_term_commit_index)?,
            proof.leader_id,
            proof.membership_digest,
            sqlite_usize(proof.quorum_size)?,
            witnesses,
            proof.protocol_version,
        ],
    )?;
    Ok(())
}

fn load_commit_proof(
    connection: &Connection,
    index: u64,
) -> Result<Option<AdmissionCommitProof>, AdmissionConsensusError> {
    let raw = connection
        .query_row(
            r#"
            SELECT log_index, leader_epoch, current_term_commit_index, leader_id,
                   membership_digest, quorum_size, witness_urls_json, protocol_version
            FROM admission_consensus_commits
            WHERE log_index = ?1
            "#,
            params![sqlite_u64(index)?],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )
        .optional()?;
    raw.map(|raw| {
        let witness_urls = serde_json::from_str(&raw.6).map_err(|error| {
            AdmissionConsensusError::Protocol(format!(
                "persisted admission witnesses are invalid: {error}"
            ))
        })?;
        Ok(AdmissionCommitProof {
            protocol_version: raw.7,
            membership_digest: raw.4,
            index: nonnegative_u64(raw.0, "commit index")?,
            leader_epoch: nonnegative_u64(raw.1, "commit leader epoch")?,
            current_term_commit_index: nonnegative_u64(raw.2, "current-term commit index")?,
            leader_id: raw.3,
            quorum_size: nonnegative_usize(raw.5, "quorum size")?,
            witness_urls,
        })
    })
    .transpose()
}

fn load_commit_proofs(
    connection: &Connection,
) -> Result<Vec<AdmissionCommitProof>, AdmissionConsensusError> {
    let meta = load_meta(connection)?;
    (1..=meta.commit_index)
        .map(|index| {
            load_commit_proof(connection, index)?.ok_or_else(|| {
                AdmissionConsensusError::Protocol(format!(
                    "admission commit proof {index} is missing"
                ))
            })
        })
        .collect()
}

fn load_result(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<AdmissionConsensusResult>, AdmissionConsensusError> {
    let raw = connection
        .query_row(
            r#"
            SELECT operation_id, log_index, response_json, response_digest,
                   security_projection_digest
            FROM admission_consensus_results
            WHERE operation_id = ?1
            "#,
            params![operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    raw.map(|raw| {
        Ok(AdmissionConsensusResult {
            operation_id: raw.0,
            log_index: nonnegative_u64(raw.1, "result log index")?,
            response_json: raw.2,
            response_digest: raw.3,
            security_projection_digest: raw.4,
        })
    })
    .transpose()
}

fn load_results(
    connection: &Connection,
) -> Result<Vec<AdmissionConsensusResult>, AdmissionConsensusError> {
    let mut statement = connection.prepare(
        r#"
        SELECT operation_id, log_index, response_json, response_digest,
               security_projection_digest
        FROM admission_consensus_results
        ORDER BY log_index ASC
        "#,
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;
    let mut results = Vec::new();
    for row in rows {
        let raw = row?;
        results.push(AdmissionConsensusResult {
            operation_id: raw.0,
            log_index: nonnegative_u64(raw.1, "result log index")?,
            response_json: raw.2,
            response_digest: raw.3,
            security_projection_digest: raw.4,
        });
    }
    Ok(results)
}

fn command_kind_label(kind: AdmissionCommandKind) -> &'static str {
    match kind {
        AdmissionCommandKind::LeadershipBarrier => "leadership_barrier",
        AdmissionCommandKind::CompositeAuthorize => "composite_authorize",
        AdmissionCommandKind::CaptureInvocations => "capture_invocations",
        AdmissionCommandKind::ReverseExposure => "reverse_exposure",
        AdmissionCommandKind::ReleaseExposure => "release_exposure",
        AdmissionCommandKind::ReconcileSpend => "reconcile_spend",
        AdmissionCommandKind::CaptureExposure => "capture_exposure",
        AdmissionCommandKind::Revoke => "revoke",
        AdmissionCommandKind::CombinedCapture => "combined_capture",
    }
}

fn command_kind_from_label(value: &str) -> Result<AdmissionCommandKind, AdmissionConsensusError> {
    match value {
        "leadership_barrier" => Ok(AdmissionCommandKind::LeadershipBarrier),
        "composite_authorize" => Ok(AdmissionCommandKind::CompositeAuthorize),
        "capture_invocations" => Ok(AdmissionCommandKind::CaptureInvocations),
        "reverse_exposure" => Ok(AdmissionCommandKind::ReverseExposure),
        "release_exposure" => Ok(AdmissionCommandKind::ReleaseExposure),
        "reconcile_spend" => Ok(AdmissionCommandKind::ReconcileSpend),
        "capture_exposure" => Ok(AdmissionCommandKind::CaptureExposure),
        "revoke" => Ok(AdmissionCommandKind::Revoke),
        "combined_capture" => Ok(AdmissionCommandKind::CombinedCapture),
        _ => Err(AdmissionConsensusError::Protocol(format!(
            "unknown admission command kind `{value}`"
        ))),
    }
}

fn quota_profile_from_label(value: &str) -> Result<BudgetQuotaProfileView, String> {
    match value {
        "chio.grant-invocation.v1" => Ok(BudgetQuotaProfileView::GrantInvocation),
        "chio.aggregate-capability-invocation.v1" => {
            Ok(BudgetQuotaProfileView::AggregateCapabilityInvocation)
        }
        "chio.aggregate-family-invocation.v1" => {
            Ok(BudgetQuotaProfileView::AggregateFamilyInvocation)
        }
        "chio.broker-capability-execution.v1" => {
            Ok(BudgetQuotaProfileView::SupplementalBrokerExecution)
        }
        _ => Err(format!(
            "unknown persisted invocation quota profile `{value}`"
        )),
    }
}

fn sqlite_u64(value: u64) -> Result<i64, AdmissionConsensusError> {
    i64::try_from(value).map_err(|_| {
        AdmissionConsensusError::Protocol("admission integer exceeds SQLite range".to_string())
    })
}

fn sqlite_usize(value: usize) -> Result<i64, AdmissionConsensusError> {
    i64::try_from(value).map_err(|_| {
        AdmissionConsensusError::Protocol("admission count exceeds SQLite range".to_string())
    })
}

fn nonnegative_u64(value: i64, label: &str) -> Result<u64, AdmissionConsensusError> {
    u64::try_from(value)
        .map_err(|_| AdmissionConsensusError::Protocol(format!("persisted {label} is negative")))
}

fn nonnegative_usize(value: i64, label: &str) -> Result<usize, AdmissionConsensusError> {
    usize::try_from(value).map_err(|_| {
        AdmissionConsensusError::Protocol(format!("persisted {label} is negative or too large"))
    })
}

fn checked_successor(value: u64, label: &str) -> Result<u64, AdmissionConsensusError> {
    value
        .checked_add(1)
        .ok_or_else(|| AdmissionConsensusError::Protocol(format!("{label} overflow")))
}

fn checked_predecessor(value: u64, label: &str) -> Result<u64, AdmissionConsensusError> {
    value
        .checked_sub(1)
        .ok_or_else(|| AdmissionConsensusError::Protocol(format!("{label} underflow")))
}

fn one_based_offset(offset: usize, label: &str) -> Result<u64, AdmissionConsensusError> {
    let offset = u64::try_from(offset)
        .map_err(|_| AdmissionConsensusError::Protocol(format!("{label} exceeds u64")))?;
    checked_successor(offset, label)
}

fn usize_index(value: u64, label: &str) -> Result<usize, AdmissionConsensusError> {
    usize::try_from(value)
        .map_err(|_| AdmissionConsensusError::Protocol(format!("{label} exceeds usize")))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use serde::de::DeserializeOwned;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn membership() -> AdmissionMembership {
        AdmissionMembership::new(vec![
            "https://node-a".to_string(),
            "https://node-b".to_string(),
        ])
        .expect("membership")
    }

    fn three_member_membership() -> AdmissionMembership {
        AdmissionMembership::new(vec![
            "https://node-a".to_string(),
            "https://node-b".to_string(),
            "https://node-c".to_string(),
        ])
        .expect("three-member membership")
    }

    fn single_member() -> AdmissionMembership {
        AdmissionMembership::new(vec!["https://node-a".to_string()]).expect("single membership")
    }

    fn path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("chio-admission-consensus-{label}-{nonce}.db"))
    }

    #[test]
    fn election_term_and_vote_are_persisted_and_stale_terms_are_rejected() {
        let path = path("vote");
        let store = AdmissionConsensusStore::open(&path).expect("open consensus");
        let election = store
            .begin_election(&membership(), "https://node-a")
            .expect("elect");
        assert_eq!(election.term, 1);
        drop(store);

        let reopened = AdmissionConsensusStore::open(&path).expect("reopen consensus");
        assert_eq!(reopened.meta().expect("meta").current_term, 1);
        assert_eq!(
            reopened.meta().expect("meta").voted_for.as_deref(),
            Some("https://node-a")
        );
        let stale = reopened
            .request_vote(
                &membership(),
                &AdmissionRequestVoteRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: 0,
                    candidate_id: "https://node-b".to_string(),
                    last_log_index: 0,
                    last_log_term: 0,
                    commit_index: 0,
                },
            )
            .expect("stale vote response");
        assert!(!stale.vote_granted);
        assert_eq!(stale.term, 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn request_vote_persists_representable_higher_term_before_later_failure() {
        let path = path("vote-higher-term-failure");
        let store = AdmissionConsensusStore::open(&path).expect("open consensus");
        store
            .begin_election(&membership(), "https://node-a")
            .expect("initial election");
        Connection::open(&path)
            .expect("trigger connection")
            .execute_batch(
                r#"
                CREATE TRIGGER reject_admission_vote
                BEFORE UPDATE OF voted_for ON admission_consensus_meta
                WHEN NEW.voted_for IS NOT NULL
                BEGIN
                    SELECT RAISE(ABORT, 'injected vote persistence failure');
                END;
                "#,
            )
            .expect("install vote trigger");
        let request = AdmissionRequestVoteRequest {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership().digest().to_string(),
            term: 5,
            candidate_id: "https://node-b".to_string(),
            last_log_index: 0,
            last_log_term: 0,
            commit_index: 0,
        };
        store
            .request_vote(&membership(), &request)
            .expect_err("injected vote failure");
        let meta = store.meta().expect("meta after vote failure");
        assert_eq!(meta.current_term, 5);
        assert_eq!(meta.voted_for, None);
        Connection::open(&path)
            .expect("trigger connection")
            .execute_batch("DROP TRIGGER reject_admission_vote")
            .expect("drop vote trigger");

        let stale = store
            .request_vote(
                &membership(),
                &AdmissionRequestVoteRequest {
                    term: 4,
                    ..request.clone()
                },
            )
            .expect("stale vote response");
        assert!(!stale.vote_granted);
        assert_eq!(stale.term, 5);
        let unrepresentable = store
            .request_vote(
                &membership(),
                &AdmissionRequestVoteRequest {
                    term: u64::MAX,
                    ..request
                },
            )
            .expect("unrepresentable vote response");
        assert!(!unrepresentable.vote_granted);
        assert_eq!(unrepresentable.term, 5);
        assert_eq!(store.meta().expect("durable vote term").current_term, 5);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn operation_scope_separates_caller_events_revocations_and_barriers() {
        let external = "revocation:capability-a";
        let authorize = scoped_operation_id(AdmissionCommandKind::CompositeAuthorize, external)
            .expect("authorize scope");
        let revoke =
            scoped_operation_id(AdmissionCommandKind::Revoke, external).expect("revocation scope");
        let barrier = scoped_operation_id(AdmissionCommandKind::LeadershipBarrier, external)
            .expect("barrier scope");

        assert_ne!(authorize, revoke);
        assert_ne!(authorize, barrier);
        assert_ne!(revoke, barrier);
        assert!(is_lower_sha256(&authorize));
        assert!(is_lower_sha256(&revoke));
        assert!(is_lower_sha256(&barrier));
    }

    #[test]
    fn same_term_candidate_accepts_the_majority_leaders_log() {
        let path = path("same-term-step-down");
        let store = AdmissionConsensusStore::open(&path).expect("open consensus");
        let election = store
            .begin_election(&membership(), "https://node-b")
            .expect("begin competing election");
        let leader = AdmissionElection {
            candidate_id: "https://node-a".to_string(),
            ..election
        };
        let entry = entry(&leader, "operation-majority-leader");

        let response = store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: leader.term,
                    leader_id: leader.candidate_id.clone(),
                    previous_log_index: 0,
                    previous_log_term: 0,
                    entry: Some(entry.clone()),
                    leader_commit: 0,
                    commit_proof: None,
                },
                |_, _, _| Ok("{}".to_string()),
            )
            .expect("append from elected leader");

        assert!(response.accepted);
        assert_eq!(response.match_index, entry.index);
        assert_eq!(
            store.meta().expect("meta").voted_for.as_deref(),
            Some(leader.candidate_id.as_str())
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejected_higher_term_append_persists_term_but_no_leader_or_log_mutation() {
        let path = path("rejected-higher-term");
        let store = AdmissionConsensusStore::open(&path).expect("open consensus");
        store
            .begin_election(&membership(), "https://node-a")
            .expect("initial election");
        let rejected = store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: 5,
                    leader_id: "https://node-b".to_string(),
                    previous_log_index: 1,
                    previous_log_term: 4,
                    entry: None,
                    leader_commit: 0,
                    commit_proof: None,
                },
                |_, _, _| Ok("{}".to_string()),
            )
            .expect("higher-term rejection");
        assert!(!rejected.accepted);
        assert_eq!(rejected.term, 5);
        let meta = store.meta().expect("meta after rejection");
        assert_eq!(meta.current_term, 5);
        assert_eq!(meta.voted_for, None);
        assert_eq!(meta.last_log_index, 0);
        assert_eq!(meta.commit_index, 0);

        let stale = store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: 4,
                    leader_id: "https://node-a".to_string(),
                    previous_log_index: 0,
                    previous_log_term: 0,
                    entry: None,
                    leader_commit: 0,
                    commit_proof: None,
                },
                |_, _, _| Ok("{}".to_string()),
            )
            .expect("stale append rejection");
        assert!(!stale.accepted);
        assert_eq!(stale.term, 5);
        assert_eq!(store.meta().expect("durable term").current_term, 5);

        let oversized_previous = AdmissionAppendEntriesRequest {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership().digest().to_string(),
            term: 7,
            leader_id: "https://node-b".to_string(),
            previous_log_index: u64::try_from(i64::MAX).expect("i64 max") + 1,
            previous_log_term: 6,
            entry: None,
            leader_commit: 0,
            commit_proof: None,
        };
        store
            .append_entries(&membership(), &oversized_previous, |_, _, _| {
                Ok("{}".to_string())
            })
            .expect_err("oversized previous index");
        assert_eq!(
            store
                .meta()
                .expect("term after oversized index")
                .current_term,
            7
        );

        let election = AdmissionElection {
            term: 8,
            candidate_id: "https://node-a".to_string(),
            last_log_index: 0,
            last_log_term: 0,
            commit_index: 0,
        };
        let entry = entry(&election, "oversized-proof-target");
        let mut oversized_proof = proof(&entry);
        oversized_proof.current_term_commit_index = u64::try_from(i64::MAX).expect("i64 max") + 1;
        store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: 8,
                    leader_id: "https://node-a".to_string(),
                    previous_log_index: 0,
                    previous_log_term: 0,
                    entry: Some(entry),
                    leader_commit: 1,
                    commit_proof: Some(oversized_proof),
                },
                |_, _, _| Ok("{}".to_string()),
            )
            .expect_err("oversized proof target");
        let meta = store.meta().expect("term after oversized proof");
        assert_eq!(meta.current_term, 8);
        assert_eq!(meta.voted_for, None);
        assert_eq!(meta.last_log_index, 0);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn newer_leader_repairs_a_higher_term_uncommitted_follower_tail() {
        let path = path("repair-higher-term-tail");
        let store = AdmissionConsensusStore::open(&path).expect("open consensus");
        let stale_election = AdmissionElection {
            term: 3,
            candidate_id: "https://node-b".to_string(),
            last_log_index: 0,
            last_log_term: 0,
            commit_index: 0,
        };
        let stale_entry = entry(&stale_election, "operation-stale-tail");
        assert!(
            store
                .append_entries(
                    &membership(),
                    &AdmissionAppendEntriesRequest {
                        protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                        membership_digest: membership().digest().to_string(),
                        term: stale_election.term,
                        leader_id: stale_election.candidate_id,
                        previous_log_index: 0,
                        previous_log_term: 0,
                        entry: Some(stale_entry),
                        leader_commit: 0,
                        commit_proof: None,
                    },
                    |_, _, _| Ok("{}".to_string()),
                )
                .expect("append stale tail")
                .accepted
        );

        let winning_election = AdmissionElection {
            term: 4,
            candidate_id: "https://node-a".to_string(),
            last_log_index: 0,
            last_log_term: 0,
            commit_index: 0,
        };
        let replacement_entry = AdmissionLogEntry {
            leader_epoch: 2,
            ..entry(&winning_election, "operation-majority-tail")
        };
        let repaired = store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: winning_election.term,
                    leader_id: winning_election.candidate_id,
                    previous_log_index: 0,
                    previous_log_term: 0,
                    entry: Some(replacement_entry.clone()),
                    leader_commit: 0,
                    commit_proof: None,
                },
                |_, _, _| Ok("{}".to_string()),
            )
            .expect("repair follower tail");

        assert!(repaired.accepted);
        assert_eq!(store.entry_at(1).expect("replacement"), replacement_entry);
        assert!(store
            .entry_for_operation("operation-stale-tail")
            .expect("stale lookup")
            .is_none());

        let _ = std::fs::remove_file(path);
    }

    fn entry(election: &AdmissionElection, operation_id: &str) -> AdmissionLogEntry {
        AdmissionConsensusStore::build_entry(
            election,
            operation_id,
            AdmissionCommandKind::Revoke,
            &serde_json::json!({"capabilityId":"capability-a","revokedAt":7}),
        )
        .expect("entry")
    }

    fn proof(entry: &AdmissionLogEntry) -> AdmissionCommitProof {
        AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership().digest().to_string(),
            index: entry.index,
            leader_epoch: entry.leader_epoch,
            current_term_commit_index: entry.index,
            leader_id: "https://node-a".to_string(),
            quorum_size: 2,
            witness_urls: vec!["https://node-a".to_string(), "https://node-b".to_string()],
        }
    }

    const MERGE_RESULT_JSON: &str = "{\"merged\":true}";

    fn commit_merge_entry(store: &AdmissionConsensusStore, operation_id: &str) {
        let election = store
            .begin_election(&membership(), "https://node-a")
            .expect("merge election");
        let entry = entry(&election, operation_id);
        store.append_local(&election, &entry).expect("merge append");
        store
            .commit_local(&membership(), &election, &proof(&entry), |_, _, _| {
                Ok(MERGE_RESULT_JSON.to_string())
            })
            .expect("merge commit");
    }

    fn commit_merge_sequence(store: &AdmissionConsensusStore, operation_ids: &[&str]) {
        for operation_id in operation_ids {
            commit_merge_entry(store, operation_id);
        }
    }

    fn rewrite_snapshot_result(
        snapshot: &mut AdmissionConsensusSnapshot,
        offset: usize,
        response_json: &str,
    ) {
        let result = snapshot.results.get_mut(offset).expect("snapshot result");
        result.response_json = response_json.to_string();
        result.response_digest = sha256_hex(response_json.as_bytes());
        let mut applied_state_digest = initial_applied_state_digest();
        for result in &snapshot.results {
            applied_state_digest = next_applied_state_digest(
                &applied_state_digest,
                &result.response_digest,
                &result.security_projection_digest,
            )
            .expect("snapshot applied digest");
        }
        snapshot.meta.applied_state_digest = applied_state_digest;
    }

    fn assert_merge_rejected_without_mutation(
        target: &AdmissionConsensusStore,
        candidate: &AdmissionConsensusSnapshot,
    ) {
        validate_snapshot_for_membership(candidate, &membership()).expect("valid candidate");
        let before = target.snapshot().expect("target before rejected merge");
        let error = target
            .merge_committed_snapshot(&membership(), candidate, |_, _, _| {
                Ok(MERGE_RESULT_JSON.to_string())
            })
            .expect_err("divergent merge must reject");
        assert!(error.to_string().contains("diverge"));
        assert_eq!(
            target.snapshot().expect("target after rejected merge"),
            before
        );
    }

    #[test]
    fn merge_matching_equal_and_stale_snapshots_are_noops() {
        let target_path = path("merge-noop-target");
        let stale_path = path("merge-noop-stale");
        let target = AdmissionConsensusStore::open(&target_path).expect("target");
        let stale = AdmissionConsensusStore::open(&stale_path).expect("stale");
        commit_merge_sequence(&target, &["merge-noop-a", "merge-noop-b"]);
        commit_merge_sequence(&stale, &["merge-noop-a"]);
        let before = target.snapshot().expect("target snapshot");

        for candidate in [before.clone(), stale.snapshot().expect("stale snapshot")] {
            assert!(!target
                .merge_committed_snapshot(
                    &membership(),
                    &candidate,
                    |_, _, _| -> Result<_, String> {
                        panic!("an already-applied prefix must not replay")
                    },
                )
                .expect("matching snapshot no-op"));
            assert_eq!(target.snapshot().expect("unchanged target"), before);
        }

        let _ = std::fs::remove_file(target_path);
        let _ = std::fs::remove_file(stale_path);
    }

    #[test]
    fn merge_divergent_equal_and_stale_committed_components_reject_without_mutation() {
        let target_path = path("merge-divergent-target");
        let equal_entry_path = path("merge-divergent-equal-entry");
        let stale_entry_path = path("merge-divergent-stale-entry");
        let stale_path = path("merge-divergent-stale");
        let target = AdmissionConsensusStore::open(&target_path).expect("target");
        let equal_entry =
            AdmissionConsensusStore::open(&equal_entry_path).expect("equal entry source");
        let stale_entry =
            AdmissionConsensusStore::open(&stale_entry_path).expect("stale entry source");
        let stale = AdmissionConsensusStore::open(&stale_path).expect("stale source");
        commit_merge_sequence(&target, &["merge-shared-a", "merge-shared-b"]);
        commit_merge_sequence(&equal_entry, &["merge-other-a", "merge-shared-b"]);
        commit_merge_sequence(&stale_entry, &["merge-other-a"]);
        commit_merge_sequence(&stale, &["merge-shared-a"]);

        let equal = target.snapshot().expect("equal base");
        let stale = stale.snapshot().expect("stale base");
        let mut equal_proof = equal.clone();
        equal_proof.commit_proofs[0].leader_id = "https://node-b".to_string();
        let mut stale_proof = stale.clone();
        stale_proof.commit_proofs[0].leader_id = "https://node-b".to_string();
        let mut equal_result = equal;
        rewrite_snapshot_result(&mut equal_result, 0, "{\"merged\":false}");
        let mut stale_result = stale;
        rewrite_snapshot_result(&mut stale_result, 0, "{\"merged\":false}");

        for candidate in [
            equal_entry.snapshot().expect("equal entry divergence"),
            stale_entry.snapshot().expect("stale entry divergence"),
            equal_proof,
            stale_proof,
            equal_result,
            stale_result,
        ] {
            assert_merge_rejected_without_mutation(&target, &candidate);
        }

        let _ = std::fs::remove_file(target_path);
        let _ = std::fs::remove_file(equal_entry_path);
        let _ = std::fs::remove_file(stale_entry_path);
        let _ = std::fs::remove_file(stale_path);
    }

    #[test]
    fn merge_higher_snapshot_advances_only_the_missing_committed_prefix() {
        let source_path = path("merge-higher-source");
        let target_path = path("merge-higher-target");
        let source = AdmissionConsensusStore::open(&source_path).expect("source");
        let target = AdmissionConsensusStore::open(&target_path).expect("target");
        commit_merge_sequence(
            &source,
            &["merge-higher-a", "merge-higher-b", "merge-higher-c"],
        );
        commit_merge_sequence(&target, &["merge-higher-a"]);
        let source_snapshot = source.snapshot().expect("source snapshot");
        let applied = AtomicUsize::new(0);

        assert!(target
            .merge_committed_snapshot(&membership(), &source_snapshot, |_, _, _| {
                applied.fetch_add(1, Ordering::SeqCst);
                Ok(MERGE_RESULT_JSON.to_string())
            })
            .expect("advance committed prefix"));
        assert_eq!(applied.load(Ordering::SeqCst), 2);
        let merged = target.snapshot().expect("merged target");
        assert_same_committed_state(&merged, &source_snapshot);
        assert_eq!(merged.meta.current_term, source_snapshot.meta.current_term);
        assert_eq!(merged.meta.voted_for, None);

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn merge_higher_snapshot_discards_a_local_uncommitted_tail() {
        let source_path = path("merge-tail-source");
        let target_path = path("merge-tail-target");
        let source = AdmissionConsensusStore::open(&source_path).expect("source");
        let target = AdmissionConsensusStore::open(&target_path).expect("target");
        commit_merge_sequence(&source, &["merge-tail-shared", "merge-tail-source"]);
        commit_merge_sequence(&target, &["merge-tail-shared"]);
        let tail_election = target
            .begin_election(&membership(), "https://node-a")
            .expect("tail election");
        let tail = entry(&tail_election, "merge-tail-local");
        target
            .append_local(&tail_election, &tail)
            .expect("append uncommitted tail");

        assert!(target
            .merge_committed_snapshot(
                &membership(),
                &source.snapshot().expect("source snapshot"),
                |_, _, _| Ok(MERGE_RESULT_JSON.to_string()),
            )
            .expect("replace uncommitted tail"));
        assert!(target
            .entry_for_operation("merge-tail-local")
            .expect("tail lookup")
            .is_none());
        assert!(target
            .result_for_operation("merge-tail-source")
            .expect("source result lookup")
            .is_some());
        let meta = target.meta().expect("target meta");
        assert_eq!(meta.last_log_index, 2);
        assert_eq!(meta.commit_index, 2);
        assert_eq!(meta.last_applied, 2);

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn merge_replay_result_mismatch_restores_the_exact_pre_merge_state() {
        let source_path = path("merge-result-source");
        let target_path = path("merge-result-target");
        let source = AdmissionConsensusStore::open(&source_path).expect("source");
        let target = AdmissionConsensusStore::open(&target_path).expect("target");
        commit_merge_sequence(&source, &["merge-result-mismatch"]);
        let source_snapshot = source.snapshot().expect("source snapshot");
        target
            .bind_membership(&membership())
            .expect("bind target membership");
        let mut expected = target.snapshot().expect("target before merge");
        expected.meta.current_term = source_snapshot.meta.current_term;
        expected.meta.voted_for = None;

        for _attempt in 0..2 {
            let error = target
                .merge_committed_snapshot(&membership(), &source_snapshot, |_, _, _| {
                    Ok("{\"merged\":false}".to_string())
                })
                .expect_err("mismatched replay must reject");
            assert!(error.to_string().contains("authenticated snapshot"));
            assert_eq!(target.meta().expect("target meta").commit_index, 0);
            assert_eq!(target.meta().expect("target meta").last_applied, 0);
            assert!(target
                .result_for_operation("merge-result-mismatch")
                .expect("result lookup")
                .is_none());
            assert_eq!(
                target.snapshot().expect("target after rejected merge"),
                expected
            );
        }
        target
            .validate_integrity()
            .expect("restored state integrity");
        let applied = AtomicUsize::new(0);
        assert_eq!(
            target
                .apply_committed(&mut |_, _, _| {
                    applied.fetch_add(1, Ordering::SeqCst);
                    Ok("{\"unexpected\":true}".to_string())
                })
                .expect("plain replay after rejected merge"),
            0
        );
        assert_eq!(applied.load(Ordering::SeqCst), 0);

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn equal_merge_mismatch_preserves_replication_state_but_observes_higher_term() {
        let source_path = path("merge-equal-term-source");
        let target_path = path("merge-equal-term-target");
        let source = AdmissionConsensusStore::open(&source_path).expect("source");
        commit_merge_entry(&source, "merge-equal-term");
        let base_snapshot = source.snapshot().expect("base snapshot");
        let target = AdmissionConsensusStore::open(&target_path).expect("target");
        target
            .install_snapshot(&membership(), &base_snapshot, |_, _, _| {
                Ok(MERGE_RESULT_JSON.to_string())
            })
            .expect("seed target");
        let connection = Connection::open(&target_path).expect("target connection");
        connection
            .execute("DELETE FROM admission_consensus_results", [])
            .expect("remove applied result");
        connection
            .execute(
                r#"
                UPDATE admission_consensus_meta
                SET last_applied = 0, applied_state_digest = ?1
                WHERE singleton = 1
                "#,
                params![initial_applied_state_digest()],
            )
            .expect("rewind target apply state");
        drop(connection);
        source
            .begin_election(&membership(), "https://node-b")
            .expect("advance source term");
        let higher_snapshot = source.snapshot().expect("higher-term snapshot");
        let entry_before = target.entry_at(1).expect("target entry");
        let proof_before = target.proof_at(1).expect("target proof");

        let error = target
            .merge_committed_snapshot(&membership(), &higher_snapshot, |_, _, _| {
                Ok("{\"merged\":false}".to_string())
            })
            .expect_err("equal merge mismatch");
        assert!(error.to_string().contains("authenticated snapshot"));
        let meta = target.meta().expect("target meta");
        assert_eq!(meta.current_term, higher_snapshot.meta.current_term);
        assert_eq!(meta.voted_for, None);
        assert_eq!(meta.commit_index, 1);
        assert_eq!(meta.last_applied, 0);
        assert_eq!(target.entry_at(1).expect("target entry"), entry_before);
        assert_eq!(target.proof_at(1).expect("target proof"), proof_before);
        assert!(target
            .result_for_operation("merge-equal-term")
            .expect("result lookup")
            .is_none());

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn snapshot_rejects_a_proof_target_beyond_the_final_commit() {
        let source_path = path("snapshot-proof-beyond-commit");
        let source = AdmissionConsensusStore::open(&source_path).expect("source");
        commit_merge_sequence(&source, &["proof-committed"]);
        let meta = source.meta().expect("source meta");
        let election = AdmissionElection {
            term: meta.current_term,
            candidate_id: "https://node-a".to_string(),
            last_log_index: meta.last_log_index,
            last_log_term: meta.last_log_term,
            commit_index: meta.commit_index,
        };
        let uncommitted = entry(&election, "proof-uncommitted-target");
        source
            .append_local(&election, &uncommitted)
            .expect("append uncommitted proof target");
        let mut snapshot = source.snapshot().expect("valid source snapshot");
        snapshot.commit_proofs[0].current_term_commit_index = uncommitted.index;

        assert!(validate_snapshot(&snapshot).is_err());
        assert!(validate_snapshot_for_membership(&snapshot, &membership()).is_err());

        let _ = std::fs::remove_file(source_path);
    }

    #[test]
    fn snapshot_enforces_term_log_and_vote_invariants() {
        let source_path = path("snapshot-term-log-vote");
        let source = AdmissionConsensusStore::open(&source_path).expect("source");
        commit_merge_sequence(&source, &["snapshot-invariant-a", "snapshot-invariant-b"]);
        let snapshot = source.snapshot().expect("valid snapshot");

        let mut term_behind_log = snapshot.clone();
        term_behind_log.meta.current_term = term_behind_log.meta.last_log_term - 1;
        assert!(validate_snapshot(&term_behind_log).is_err());

        let mut wrong_log_head = snapshot.clone();
        wrong_log_head.meta.last_log_term += 1;
        wrong_log_head.meta.current_term = wrong_log_head.meta.last_log_term;
        assert!(validate_snapshot(&wrong_log_head).is_err());

        let mut decreasing_terms = snapshot.clone();
        decreasing_terms.entries[0].leader_epoch = decreasing_terms.entries[1].leader_epoch + 1;
        decreasing_terms.meta.current_term = decreasing_terms.entries[0].leader_epoch;
        assert!(validate_snapshot(&decreasing_terms).is_err());

        let mut outsider_vote = snapshot;
        outsider_vote.meta.voted_for = Some("https://node-c".to_string());
        validate_snapshot(&outsider_vote).expect("structurally valid outsider vote");
        assert!(validate_snapshot_for_membership(&outsider_vote, &membership()).is_err());

        let _ = std::fs::remove_file(source_path);
    }

    #[test]
    fn follower_accepts_one_exact_entry_but_never_applies_it_before_commit() {
        let path = path("append");
        let store = AdmissionConsensusStore::open(&path).expect("open consensus");
        let election = AdmissionElection {
            term: 3,
            candidate_id: "https://node-a".to_string(),
            last_log_index: 0,
            last_log_term: 0,
            commit_index: 0,
        };
        let entry = entry(&election, "operation-a");
        let applied = AtomicUsize::new(0);
        let append = store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: 3,
                    leader_id: "https://node-a".to_string(),
                    previous_log_index: 0,
                    previous_log_term: 0,
                    entry: Some(entry.clone()),
                    leader_commit: 0,
                    commit_proof: None,
                },
                |_, _, _| {
                    applied.fetch_add(1, Ordering::SeqCst);
                    Ok("{\"ok\":true}".to_string())
                },
            )
            .expect("append response");
        assert!(append.accepted);
        assert_eq!(append.applied_index, 0);
        assert_eq!(applied.load(Ordering::SeqCst), 0);
        let exact_retry = store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: 3,
                    leader_id: "https://node-a".to_string(),
                    previous_log_index: 0,
                    previous_log_term: 0,
                    entry: Some(entry.clone()),
                    leader_commit: 0,
                    commit_proof: None,
                },
                |_, _, _| Ok("{\"unexpected\":true}".to_string()),
            )
            .expect("exact append retry");
        assert!(exact_retry.accepted);
        assert_eq!(exact_retry.match_index, 1);
        assert_eq!(exact_retry.applied_index, 0);

        let mut conflicting = entry.clone();
        conflicting.operation_id = "operation-conflict".to_string();
        conflicting.canonical_command =
            "{\"capabilityId\":\"capability-b\",\"revokedAt\":7}".to_string();
        conflicting.command_digest = sha256_hex(conflicting.canonical_command.as_bytes());
        let rejected = store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: 3,
                    leader_id: "https://node-a".to_string(),
                    previous_log_index: 0,
                    previous_log_term: 0,
                    entry: Some(conflicting),
                    leader_commit: 0,
                    commit_proof: None,
                },
                |_, _, _| Ok("{\"ok\":true}".to_string()),
            )
            .expect("conflict response");
        assert!(!rejected.accepted);
        assert_eq!(store.meta().expect("meta").last_log_index, 1);
        assert_eq!(applied.load(Ordering::SeqCst), 0);

        let committed = store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: 3,
                    leader_id: "https://node-a".to_string(),
                    previous_log_index: 1,
                    previous_log_term: 3,
                    entry: None,
                    leader_commit: 1,
                    commit_proof: Some(proof(&entry)),
                },
                |_, _, _| {
                    applied.fetch_add(1, Ordering::SeqCst);
                    Ok("{\"ok\":true}".to_string())
                },
            )
            .expect("commit response");
        assert!(committed.accepted);
        assert_eq!(committed.applied_index, 1);
        assert_eq!(applied.load(Ordering::SeqCst), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mixed_version_peers_cannot_vote_or_witness_and_restart_snapshot_replays_exactly() {
        let source_path = path("snapshot-source");
        let target_path = path("snapshot-target");
        let source = AdmissionConsensusStore::open(&source_path).expect("source");
        let election = source
            .begin_election(&membership(), "https://node-a")
            .expect("election");
        let entry = entry(&election, "operation-snapshot");
        source
            .append_local(&election, &entry)
            .expect("append local");
        let mixed_vote = source
            .request_vote(
                &membership(),
                &AdmissionRequestVoteRequest {
                    protocol_version: "chio.admission-consensus.v0".to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: election.term + 1,
                    candidate_id: "https://old-node".to_string(),
                    last_log_index: entry.index,
                    last_log_term: entry.leader_epoch,
                    commit_index: 0,
                },
            )
            .expect("mixed vote");
        assert!(!mixed_vote.vote_granted);
        assert_eq!(source.meta().expect("meta").current_term, election.term);

        let result = source
            .commit_local(&membership(), &election, &proof(&entry), |_, _, _| {
                Ok("{\"outcome\":\"revoked\"}".to_string())
            })
            .expect("commit local");
        drop(source);
        let reopened = AdmissionConsensusStore::open(&source_path).expect("reopen");
        assert_eq!(reopened.meta().expect("meta").commit_index, 1);
        assert_eq!(reopened.meta().expect("meta").last_applied, 1);
        assert_eq!(
            reopened
                .result_for_operation("operation-snapshot")
                .expect("result"),
            Some(result)
        );
        let snapshot = reopened.snapshot().expect("snapshot");

        let target = AdmissionConsensusStore::open(&target_path).expect("target");
        target
            .install_snapshot(&membership(), &snapshot, |_, _, _| {
                Ok("{\"outcome\":\"revoked\"}".to_string())
            })
            .expect("install snapshot");
        let source_snapshot = snapshot.clone();
        let mut expected = snapshot;
        expected.meta.voted_for = None;
        assert_eq!(target.snapshot().expect("target snapshot"), expected);
        let installed = target.snapshot().expect("installed snapshot");
        target
            .install_snapshot(&membership(), &source_snapshot, |_, _, _| {
                panic!("an exact snapshot retry must not replay")
            })
            .expect("exact snapshot install retry");
        assert_eq!(
            target.snapshot().expect("retried target snapshot"),
            installed
        );

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn snapshot_rejects_proof_gaps_and_result_corruption() {
        let path = path("snapshot-integrity");
        let store = AdmissionConsensusStore::open(&path).expect("open consensus");
        for operation_id in ["operation-snapshot-a", "operation-snapshot-b"] {
            let election = store
                .begin_election(&membership(), "https://node-a")
                .expect("snapshot election");
            let entry = entry(&election, operation_id);
            store
                .append_local(&election, &entry)
                .expect("snapshot append");
            store
                .commit_local(&membership(), &election, &proof(&entry), |_, _, _| {
                    Ok(format!("{{\"operation\":\"{operation_id}\"}}"))
                })
                .expect("snapshot commit");
        }
        let snapshot = store.snapshot().expect("snapshot");

        let mut duplicate_proof = snapshot.clone();
        duplicate_proof.commit_proofs[1] = duplicate_proof.commit_proofs[0].clone();
        assert!(validate_snapshot(&duplicate_proof).is_err());

        let mut changed_body = snapshot.clone();
        changed_body.results[0].response_json = "{\"changed\":true}".to_string();
        assert!(validate_snapshot(&changed_body).is_err());

        let mut changed_digest = snapshot;
        changed_digest.results[0].response_digest = "11".repeat(32);
        assert!(validate_snapshot(&changed_digest).is_err());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn asymmetric_membership_digests_cannot_vote_in_the_same_log() {
        let b_path = path("asymmetric-b");
        let b = AdmissionConsensusStore::open(&b_path).expect("b");
        let full = AdmissionMembership::new(vec![
            "https://node-a".to_string(),
            "https://node-b".to_string(),
            "https://node-c".to_string(),
        ])
        .expect("full membership");
        let asymmetric = AdmissionMembership::new(vec![
            "https://node-a".to_string(),
            "https://node-b".to_string(),
        ])
        .expect("asymmetric membership");
        b.bind_membership(&full).expect("bind full membership");
        let a_vote = AdmissionRequestVoteRequest {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: asymmetric.digest().to_string(),
            term: 1,
            candidate_id: "https://node-a".to_string(),
            last_log_index: 0,
            last_log_term: 0,
            commit_index: 0,
        };
        assert!(
            !b.request_vote(&full, &a_vote)
                .expect("membership rejection")
                .vote_granted
        );
        assert_eq!(b.meta().expect("b meta").current_term, 0);
        drop(b);
        let reopened = AdmissionConsensusStore::open(&b_path).expect("reopen");
        assert!(matches!(
            reopened.request_vote(
                &asymmetric,
                &AdmissionRequestVoteRequest {
                    membership_digest: asymmetric.digest().to_string(),
                    ..a_vote
                }
            ),
            Err(AdmissionConsensusError::Protocol(_))
        ));
        let _ = std::fs::remove_file(b_path);
    }

    #[test]
    fn divergent_initial_projection_cannot_share_consensus_membership() {
        let clean_path = path("baseline-clean");
        let drifted_path = path("baseline-drifted");
        let clean_config = test_config(&clean_path);
        let drifted_config = test_config(&drifted_path);
        drop(open_capture_authority(&clean_config).expect("clean authority"));
        drop(open_capture_authority(&drifted_config).expect("drifted authority"));
        let clean_store = AdmissionConsensusStore::open(&clean_path).expect("clean consensus");
        let drifted_store =
            AdmissionConsensusStore::open(&drifted_path).expect("drifted consensus");
        SqliteBudgetStore::open(&drifted_path)
            .expect("drifted budget")
            .try_increment("capability-baseline-drift", 0, Some(3))
            .expect("seed drifted usage");
        let clean_projection =
            capture_admission_genesis_projection(&clean_path).expect("clean projection");
        let drifted_projection =
            capture_admission_genesis_projection(&drifted_path).expect("drifted projection");
        let clean_baseline =
            admission_genesis_projection_digest(&clean_projection).expect("clean baseline");
        let drifted_baseline =
            admission_genesis_projection_digest(&drifted_projection).expect("drifted baseline");
        assert_ne!(clean_baseline, drifted_baseline);
        let members = vec![
            "https://node-a".to_string(),
            "https://node-b".to_string(),
            "https://node-c".to_string(),
        ];
        let clean_membership =
            AdmissionMembership::new_with_genesis(members.clone(), clean_projection)
                .expect("clean membership");
        let drifted_membership = AdmissionMembership::new_with_genesis(members, drifted_projection)
            .expect("drifted membership");
        assert_ne!(clean_membership.digest(), drifted_membership.digest());
        clean_store
            .bind_membership(&clean_membership)
            .expect("bind clean membership");
        let response = drifted_store
            .request_vote(
                &drifted_membership,
                &AdmissionRequestVoteRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: clean_membership.digest().to_string(),
                    term: 1,
                    candidate_id: "https://node-a".to_string(),
                    last_log_index: 0,
                    last_log_term: 0,
                    commit_index: 0,
                },
            )
            .expect("drifted vote response");
        assert!(!response.vote_granted);
        assert_eq!(response.membership_digest, drifted_membership.digest());

        let _ = std::fs::remove_file(clean_path);
        let _ = std::fs::remove_file(drifted_path);
    }

    #[test]
    fn security_projection_excludes_only_qualified_clock_metadata() {
        assert_eq!(ADMISSION_SECURITY_PROJECTION_EXCLUSIONS.len(), 11);
        for (table, column) in ADMISSION_SECURITY_PROJECTION_EXCLUSIONS {
            let specification = ADMISSION_GENESIS_TABLES
                .iter()
                .find(|specification| specification.name == *table)
                .expect("excluded table exists");
            assert!(specification
                .columns
                .iter()
                .any(|(candidate, _)| candidate == column));
            assert!(admission_security_projection_ignores(table, column));
        }
        for specification in ADMISSION_GENESIS_TABLES {
            for (column, _) in specification.columns {
                assert_eq!(
                    admission_security_projection_ignores(specification.name, column),
                    ADMISSION_SECURITY_PROJECTION_EXCLUSIONS
                        .contains(&(specification.name, *column))
                );
            }
        }
        for column in ["revoked_at", "requested_revoked_at", "effective_revoked_at"] {
            assert!(!ADMISSION_GENESIS_TABLES.iter().any(|specification| {
                specification.columns.iter().any(|(candidate, _)| {
                    candidate == &column
                        && admission_security_projection_ignores(specification.name, candidate)
                })
            }));
        }
    }

    #[test]
    fn legacy_consensus_result_schema_fails_during_open() {
        let database_path = path("legacy-consensus-result-schema");
        let connection = Connection::open(&database_path).expect("legacy database");
        connection
            .execute_batch(
                r#"
                CREATE TABLE admission_consensus_meta (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
                    current_term INTEGER NOT NULL,
                    baseline_state_digest TEXT,
                    membership_digest TEXT,
                    voted_for TEXT,
                    last_log_index INTEGER NOT NULL,
                    last_log_term INTEGER NOT NULL,
                    commit_index INTEGER NOT NULL,
                    last_applied INTEGER NOT NULL,
                    applied_state_digest TEXT NOT NULL
                );
                CREATE TABLE admission_consensus_results (
                    operation_id TEXT PRIMARY KEY,
                    log_index INTEGER NOT NULL UNIQUE,
                    response_json TEXT NOT NULL,
                    response_digest TEXT NOT NULL
                );
                "#,
            )
            .expect("legacy schema");
        connection
            .execute(
                r#"
                INSERT INTO admission_consensus_meta (
                    singleton, schema_version, current_term, baseline_state_digest,
                    membership_digest, voted_for, last_log_index, last_log_term,
                    commit_index, last_applied, applied_state_digest
                ) VALUES (1, 1, 0, NULL, NULL, NULL, 0, 0, 0, 0, ?1)
                "#,
                params![initial_applied_state_digest()],
            )
            .expect("legacy meta");
        drop(connection);

        assert!(AdmissionConsensusStore::open(&database_path).is_err());

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn volatile_transport_cache_does_not_change_genesis_membership() {
        let clean_path = path("baseline-cache-clean");
        let cache_path = path("baseline-cache-drift");
        {
            let config = test_config(&clean_path);
            drop(open_capture_authority(&config).expect("capture authority"));
            drop(AdmissionConsensusStore::open(&clean_path).expect("consensus store"));
            SqliteBudgetStore::open(&clean_path)
                .expect("budget store")
                .try_increment("capability-cache-baseline", 0, Some(4))
                .expect("seed authoritative usage");
        }
        Connection::open(&clean_path)
            .expect("checkpoint database")
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("checkpoint clean database");
        std::fs::copy(&clean_path, &cache_path).expect("clone authoritative baseline");
        let cache = Connection::open(&cache_path).expect("cache database");
        cache
            .execute_batch(
                r#"
                UPDATE budget_replication_meta SET next_seq = 900 WHERE singleton = 1;
                INSERT INTO budget_import_floors (authority_id, floor_seq)
                VALUES ('https://history-only', 700);
                UPDATE budget_ack_head_watermark SET head_seq = 500 WHERE singleton = 1;
                INSERT INTO budget_origin_ack_heads (authority_id, head_seq)
                VALUES ('https://history-only', 500);
                INSERT INTO budget_abandoned_event_seqs (seq) VALUES (800);
                INSERT INTO budget_abandoned_event_ranges (start_seq, end_seq)
                VALUES (801, 899);
                "#,
            )
            .expect("seed volatile transport cache");

        let clean = capture_admission_genesis_projection(&clean_path).expect("clean genesis");
        let cache = capture_admission_genesis_projection(&cache_path).expect("cache genesis");
        assert_eq!(clean, cache);
        let members = vec![
            "https://node-a".to_string(),
            "https://node-b".to_string(),
            "https://node-c".to_string(),
        ];
        let clean_membership = AdmissionMembership::new_with_genesis(members.clone(), clean)
            .expect("clean membership");
        let cache_membership =
            AdmissionMembership::new_with_genesis(members, cache).expect("cache membership");
        assert_eq!(clean_membership.digest(), cache_membership.digest());

        let _ = std::fs::remove_file(clean_path);
        let _ = std::fs::remove_file(cache_path);
    }

    #[test]
    fn migrated_column_order_has_the_same_logical_genesis() {
        let clean_path = path("logical-schema-clean");
        let migrated_path = path("logical-schema-migrated");
        Connection::open(&migrated_path)
            .expect("migrated database")
            .execute_batch(
                r#"
                CREATE TABLE capability_grant_budgets (
                    capability_id TEXT NOT NULL,
                    grant_index INTEGER NOT NULL,
                    invocation_count INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    total_cost_exposed INTEGER NOT NULL DEFAULT 0,
                    total_cost_realized_spend INTEGER NOT NULL DEFAULT 0,
                    seq INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (capability_id, grant_index)
                );
                "#,
            )
            .expect("legacy physical column order");
        for database_path in [&clean_path, &migrated_path] {
            drop(
                open_capture_authority(&test_config(database_path)).expect("initialize authority"),
            );
            Connection::open(database_path)
                .expect("seed database")
                .execute(
                    r#"
                    INSERT INTO capability_grant_budgets (
                        capability_id, grant_index, invocation_count, updated_at, seq,
                        total_cost_exposed, total_cost_realized_spend
                    ) VALUES ('capability-logical-schema', 0, 2, 17, 4, 9, 3)
                    "#,
                    [],
                )
                .expect("seed logical row");
        }

        assert_eq!(
            capture_admission_genesis_projection(&clean_path).expect("clean genesis"),
            capture_admission_genesis_projection(&migrated_path).expect("migrated genesis")
        );

        let _ = std::fs::remove_file(clean_path);
        let _ = std::fs::remove_file(migrated_path);
    }

    #[test]
    fn genesis_capture_reads_one_atomic_sqlite_snapshot() {
        let database_path = path("atomic-genesis");
        drop(open_capture_authority(&test_config(&database_path)).expect("initialize authority"));
        Connection::open(&database_path)
            .expect("seed database")
            .execute(
                r#"
                INSERT INTO capability_grant_budgets (
                    capability_id, grant_index, invocation_count, updated_at, seq,
                    total_cost_exposed, total_cost_realized_spend
                ) VALUES ('capability-atomic-genesis', 0, 1, 1, 1, 0, 0)
                "#,
                [],
            )
            .expect("seed usage");

        let mut reader = Connection::open(&database_path).expect("reader");
        configure_connection(&reader).expect("reader pragmas");
        let transaction = reader
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .expect("reader transaction");
        let mut wrote = false;
        let projection =
            capture_admission_genesis_projection_from_connection(&transaction, |table_name| {
                if table_name == "admission_authority_meta" && !wrote {
                    Connection::open(&database_path)?.execute_batch(
                        r#"
                        PRAGMA journal_mode = WAL;
                        BEGIN IMMEDIATE;
                        UPDATE admission_authority_meta
                        SET authority_commit_index = 1 WHERE singleton = 1;
                        UPDATE capability_grant_budgets
                        SET invocation_count = 2 WHERE capability_id = 'capability-atomic-genesis';
                        COMMIT;
                        "#,
                    )?;
                    wrote = true;
                }
                Ok(())
            })
            .expect("atomic projection");
        transaction.commit().expect("reader commit");
        assert!(wrote);

        let authority_meta = projection
            .tables
            .iter()
            .find(|table| table.name == "admission_authority_meta")
            .expect("authority meta");
        let usage = projection
            .tables
            .iter()
            .find(|table| table.name == "capability_grant_budgets")
            .expect("budget usage");
        assert_eq!(authority_meta.rows[0][2], AdmissionGenesisValue::Integer(0));
        assert_eq!(usage.rows[0][2], AdmissionGenesisValue::Integer(1));

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn snapshot_seeds_fresh_replacement_from_nonempty_genesis() {
        let source_path = path("genesis-source");
        let target_path = path("genesis-target");
        for database_path in [&source_path, &target_path] {
            drop(
                open_capture_authority(&test_config(database_path))
                    .expect("initialize admission authority"),
            );
        }
        SqliteBudgetStore::open(&source_path)
            .expect("source budget store")
            .try_increment("capability-genesis", 0, Some(7))
            .expect("seed source genesis");

        let members = vec![
            "https://node-a".to_string(),
            "https://node-b".to_string(),
            "https://node-c".to_string(),
        ];
        let source_genesis =
            capture_admission_genesis_projection(&source_path).expect("source genesis");
        let source_membership =
            AdmissionMembership::new_with_genesis(members.clone(), source_genesis.clone())
                .expect("source membership");
        let source = AdmissionConsensusStore::open(&source_path).expect("source consensus");
        source
            .bind_membership(&source_membership)
            .expect("bind source membership");
        let election = source
            .begin_election(&source_membership, "https://node-a")
            .expect("source election");
        let entry = entry(&election, "replacement-replay");
        source
            .append_local(&election, &entry)
            .expect("source append");
        let commit_proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: source_membership.digest().to_string(),
            index: entry.index,
            leader_epoch: entry.leader_epoch,
            current_term_commit_index: entry.index,
            leader_id: election.candidate_id.clone(),
            quorum_size: 2,
            witness_urls: vec!["https://node-a".to_string(), "https://node-b".to_string()],
        };
        source
            .commit_local(&source_membership, &election, &commit_proof, |_, _, _| {
                Ok("{\"replayed\":true}".to_string())
            })
            .expect("source commit");
        let snapshot = source.snapshot().expect("source snapshot");

        let target_genesis =
            capture_admission_genesis_projection(&target_path).expect("empty target genesis");
        let target_membership = AdmissionMembership::new_with_genesis(members, target_genesis)
            .expect("target membership");
        let target = AdmissionConsensusStore::open(&target_path).expect("target consensus");
        target
            .bind_membership(&target_membership)
            .expect("bind initial target membership");
        let replayed = AtomicUsize::new(0);
        target
            .install_snapshot(&source_membership, &snapshot, |_, _, _| {
                replayed.fetch_add(1, Ordering::SeqCst);
                Ok("{\"replayed\":true}".to_string())
            })
            .expect("seed replacement from snapshot");
        assert_eq!(replayed.load(Ordering::SeqCst), 1);

        assert_eq!(
            capture_admission_genesis_projection(&target_path).expect("installed genesis"),
            source_genesis
        );
        assert_eq!(
            target.meta().expect("target meta").membership_digest,
            Some(source_membership.digest().to_string())
        );

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn partial_genesis_snapshot_is_rejected_before_target_mutation() {
        let source_path = path("partial-genesis-source");
        let target_path = path("partial-genesis-target");
        for database_path in [&source_path, &target_path] {
            drop(
                open_capture_authority(&test_config(database_path))
                    .expect("initialize admission authority"),
            );
        }
        SqliteBudgetStore::open(&source_path)
            .expect("source budget store")
            .try_increment("capability-partial-genesis", 0, Some(3))
            .expect("seed source genesis");
        let members = vec!["https://node-a".to_string(), "https://node-b".to_string()];
        let source_genesis =
            capture_admission_genesis_projection(&source_path).expect("source genesis");
        let source_membership = AdmissionMembership::new_with_genesis(members, source_genesis)
            .expect("source membership");
        let source = AdmissionConsensusStore::open(&source_path).expect("source store");
        source
            .bind_membership(&source_membership)
            .expect("bind source");
        let mut snapshot = source.snapshot().expect("snapshot");
        snapshot
            .genesis_projection
            .as_mut()
            .expect("snapshot genesis")
            .tables
            .pop();

        let target_before =
            capture_admission_genesis_projection(&target_path).expect("target before");
        let target = AdmissionConsensusStore::open(&target_path).expect("target store");
        assert!(target
            .install_snapshot(&source_membership, &snapshot, |_, _, _| {
                Ok("{}".to_string())
            })
            .is_err());
        assert_eq!(
            capture_admission_genesis_projection(&target_path).expect("target after"),
            target_before
        );
        assert_eq!(target.meta().expect("target meta").commit_index, 0);

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn snapshot_install_preserves_monotonic_node_local_term_and_vote() {
        let source_path = path("snapshot-hard-state-source");
        let retained_path = path("snapshot-hard-state-retained");
        let advanced_path = path("snapshot-hard-state-advanced");
        let membership = membership();
        let source = AdmissionConsensusStore::open(&source_path).expect("source");
        source.bind_membership(&membership).expect("bind source");
        source
            .begin_election(&membership, "https://node-a")
            .expect("source term one");
        let lower_snapshot = source.snapshot().expect("lower snapshot");

        let retained = AdmissionConsensusStore::open(&retained_path).expect("retained target");
        retained
            .bind_membership(&membership)
            .expect("bind retained target");
        retained
            .begin_election(&membership, "https://node-a")
            .expect("retained term one");
        retained
            .begin_election(&membership, "https://node-b")
            .expect("retained term two");
        retained
            .install_snapshot(&membership, &lower_snapshot, |_, _, _| Ok("{}".to_string()))
            .expect("install lower-term snapshot");
        let retained_meta = retained.meta().expect("retained meta");
        assert_eq!(retained_meta.current_term, 2);
        assert_eq!(retained_meta.voted_for.as_deref(), Some("https://node-b"));
        assert_eq!(retained_meta.last_log_index, 0);
        let retained_after_first_install = retained.snapshot().expect("retained snapshot");
        retained
            .install_snapshot(&membership, &lower_snapshot, |_, _, _| Ok("{}".to_string()))
            .expect("retry lower-term snapshot install");
        assert_eq!(
            retained.snapshot().expect("retained retry snapshot"),
            retained_after_first_install
        );

        source
            .begin_election(&membership, "https://node-b")
            .expect("source term two");
        source
            .begin_election(&membership, "https://node-a")
            .expect("source term three");
        let higher_snapshot = source.snapshot().expect("higher snapshot");
        let advanced = AdmissionConsensusStore::open(&advanced_path).expect("advanced target");
        advanced
            .bind_membership(&membership)
            .expect("bind advanced target");
        advanced
            .begin_election(&membership, "https://node-a")
            .expect("advanced term one");
        advanced
            .begin_election(&membership, "https://node-b")
            .expect("advanced term two");
        advanced
            .install_snapshot(
                &membership,
                &higher_snapshot,
                |_, _, _| Ok("{}".to_string()),
            )
            .expect("install higher-term snapshot");
        let advanced_meta = advanced.meta().expect("advanced meta");
        assert_eq!(advanced_meta.current_term, 3);
        assert_eq!(advanced_meta.voted_for, None);
        assert_eq!(advanced_meta.last_log_index, 0);

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(retained_path);
        let _ = std::fs::remove_file(advanced_path);
    }

    #[test]
    fn bound_apply_rolls_back_authoritative_mutation_before_result_persistence() {
        let database_path = path("atomic-apply-rollback");
        drop(open_capture_authority(&test_config(&database_path)).expect("initialize authority"));
        let genesis =
            capture_admission_genesis_projection(&database_path).expect("capture genesis");
        let membership = AdmissionMembership::new_with_genesis(
            vec!["https://node-a".to_string(), "https://node-b".to_string()],
            genesis,
        )
        .expect("membership");
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus store");
        store.bind_membership(&membership).expect("bind membership");
        let election = store
            .begin_election(&membership, "https://node-a")
            .expect("election");
        let entry = entry(&election, "atomic-apply-rollback");
        store.append_local(&election, &entry).expect("append");
        let commit_proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            index: entry.index,
            leader_epoch: entry.leader_epoch,
            current_term_commit_index: entry.index,
            leader_id: election.candidate_id.clone(),
            quorum_size: 2,
            witness_urls: vec!["https://node-a".to_string(), "https://node-b".to_string()],
        };

        let error = store
            .commit_local(
                &membership,
                &election,
                &commit_proof,
                |transaction, _, _| {
                    SqliteAdmissionCaptureAuthority::upsert_revocation_in_transaction(
                        transaction,
                        &RevocationRecord {
                            capability_id: "capability-atomic-rollback".to_string(),
                            revoked_at: 1,
                        },
                    )
                    .map_err(|error| error.to_string())?;
                    Err("injected failure before result persistence".to_string())
                },
            )
            .expect_err("apply failure");
        assert!(error.to_string().contains("injected failure"));
        let connection = Connection::open(&database_path).expect("inspect database");
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM revoked_capabilities WHERE capability_id = ?1",
                params!["capability-atomic-rollback"],
                |row| row.get(0),
            )
            .expect("rolled-back row count");
        assert_eq!(count, 0);
        assert_eq!(store.meta().expect("meta").commit_index, 1);
        assert_eq!(store.meta().expect("meta").last_applied, 0);
        assert!(store
            .result_for_operation("atomic-apply-rollback")
            .expect("result lookup")
            .is_none());
        store
            .validate_integrity()
            .expect("rolled-back unapplied state is valid");

        store
            .apply_committed(&mut |transaction, _, _| {
                SqliteAdmissionCaptureAuthority::upsert_revocation_in_transaction(
                    transaction,
                    &RevocationRecord {
                        capability_id: "capability-atomic-rollback".to_string(),
                        revoked_at: 1,
                    },
                )
                .map_err(|error| error.to_string())?;
                Ok("{\"applied\":true}".to_string())
            })
            .expect("replay apply");
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM revoked_capabilities WHERE capability_id = ?1",
                params!["capability-atomic-rollback"],
                |row| row.get(0),
            )
            .expect("committed row count");
        assert_eq!(count, 1);
        assert_eq!(store.meta().expect("meta").last_applied, 1);
        assert!(store
            .result_for_operation("atomic-apply-rollback")
            .expect("result lookup")
            .is_some());
        store.validate_integrity().expect("atomic replay is valid");

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn authenticated_result_mismatch_rolls_back_successful_authoritative_mutation() {
        let source_path = path("atomic-expected-source");
        let target_path = path("atomic-expected-target");
        for database_path in [&source_path, &target_path] {
            drop(
                open_capture_authority(&test_config(database_path)).expect("initialize authority"),
            );
        }
        let genesis = capture_admission_genesis_projection(&source_path).expect("source genesis");
        assert_eq!(
            capture_admission_genesis_projection(&target_path).expect("target genesis"),
            genesis
        );
        let membership = AdmissionMembership::new_with_genesis(
            vec!["https://node-a".to_string(), "https://node-b".to_string()],
            genesis,
        )
        .expect("membership");
        let source = AdmissionConsensusStore::open(&source_path).expect("source store");
        source.bind_membership(&membership).expect("bind source");
        let election = source
            .begin_election(&membership, "https://node-a")
            .expect("source election");
        let entry = entry(&election, "atomic-authenticated-mismatch");
        source
            .append_local(&election, &entry)
            .expect("source append");
        let commit_proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            index: entry.index,
            leader_epoch: entry.leader_epoch,
            current_term_commit_index: entry.index,
            leader_id: election.candidate_id.clone(),
            quorum_size: 2,
            witness_urls: vec!["https://node-a".to_string(), "https://node-b".to_string()],
        };
        source
            .commit_local(
                &membership,
                &election,
                &commit_proof,
                |transaction, _, _| {
                    SqliteAdmissionCaptureAuthority::upsert_revocation_in_transaction(
                        transaction,
                        &RevocationRecord {
                            capability_id: "capability-authenticated-mismatch".to_string(),
                            revoked_at: 1,
                        },
                    )
                    .map_err(|error| error.to_string())?;
                    Ok("{\"source\":true}".to_string())
                },
            )
            .expect("source commit");
        let snapshot = source.snapshot().expect("authenticated snapshot");

        let target = AdmissionConsensusStore::open(&target_path).expect("target store");
        target.bind_membership(&membership).expect("bind target");
        let before = target.snapshot().expect("target before install");
        let error = target
            .install_snapshot(&membership, &snapshot, |transaction, _, _| {
                SqliteAdmissionCaptureAuthority::upsert_revocation_in_transaction(
                    transaction,
                    &RevocationRecord {
                        capability_id: "capability-authenticated-mismatch".to_string(),
                        revoked_at: 1,
                    },
                )
                .map_err(|error| error.to_string())?;
                Ok("{\"target\":true}".to_string())
            })
            .expect_err("authenticated replay mismatch");
        assert!(error.to_string().contains("authenticated snapshot"));
        let connection = Connection::open(&target_path).expect("inspect target");
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM revoked_capabilities WHERE capability_id = ?1",
                params!["capability-authenticated-mismatch"],
                |row| row.get(0),
            )
            .expect("rolled-back mutation count");
        assert_eq!(count, 0);
        let meta = target.meta().expect("target meta");
        assert_eq!(meta.current_term, snapshot.meta.current_term);
        assert_eq!(meta.voted_for, None);
        assert_eq!(meta.commit_index, 0);
        assert_eq!(meta.last_applied, 0);
        assert!(target
            .result_for_operation("atomic-authenticated-mismatch")
            .expect("result lookup")
            .is_none());
        target
            .validate_integrity()
            .expect("mismatched replay left no projection drift");
        drop(connection);
        drop(target);

        let reopened = AdmissionConsensusStore::open(&target_path).expect("reopen target");
        let mut expected = before;
        expected.meta.current_term = snapshot.meta.current_term;
        expected.meta.voted_for = None;
        assert_eq!(reopened.snapshot().expect("target after restart"), expected);
        let replayed = AtomicUsize::new(0);
        assert_eq!(
            reopened
                .apply_committed(&mut |_, _, _| {
                    replayed.fetch_add(1, Ordering::SeqCst);
                    Ok("{\"unexpected\":true}".to_string())
                })
                .expect("plain replay after restart"),
            0
        );
        assert_eq!(replayed.load(Ordering::SeqCst), 0);

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
    }

    #[test]
    fn concurrent_unrelated_projection_write_cannot_be_blessed() {
        let database_path = path("atomic-apply-concurrent-write");
        drop(open_capture_authority(&test_config(&database_path)).expect("initialize authority"));
        let genesis =
            capture_admission_genesis_projection(&database_path).expect("capture genesis");
        let membership = AdmissionMembership::new_with_genesis(
            vec!["https://node-a".to_string(), "https://node-b".to_string()],
            genesis,
        )
        .expect("membership");
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus store");
        store.bind_membership(&membership).expect("bind membership");
        let election = store
            .begin_election(&membership, "https://node-a")
            .expect("election");
        let entry = entry(&election, "atomic-apply-concurrent-write");
        store.append_local(&election, &entry).expect("append");
        let commit_proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            index: entry.index,
            leader_epoch: entry.leader_epoch,
            current_term_commit_index: entry.index,
            leader_id: election.candidate_id.clone(),
            quorum_size: 2,
            witness_urls: vec!["https://node-a".to_string(), "https://node-b".to_string()],
        };

        store
            .commit_local(&membership, &election, &commit_proof, |_, _, _| {
                let path = database_path.clone();
                let write = std::thread::spawn(move || {
                    let connection = Connection::open(path)?;
                    connection.busy_timeout(std::time::Duration::from_millis(50))?;
                    connection.execute(
                        r#"
                            INSERT INTO capability_grant_budgets (
                                capability_id, grant_index, invocation_count,
                                updated_at, seq, total_cost_exposed,
                                total_cost_realized_spend
                            ) VALUES (?1, 0, 1, 1, 1, 0, 0)
                            "#,
                        params!["capability-concurrent-drift"],
                    )
                })
                .join()
                .expect("concurrent writer thread");
                assert!(matches!(
                    write,
                    Err(rusqlite::Error::SqliteFailure(ref failure, _))
                        if matches!(
                            failure.code,
                            rusqlite::ErrorCode::DatabaseBusy
                                | rusqlite::ErrorCode::DatabaseLocked
                        )
                ));
                Ok("{\"applied\":true}".to_string())
            })
            .expect("atomic commit");

        let connection = Connection::open(&database_path).expect("inspect database");
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM capability_grant_budgets WHERE capability_id = ?1",
                params!["capability-concurrent-drift"],
                |row| row.get(0),
            )
            .expect("unrelated row count");
        assert_eq!(count, 0);
        assert_eq!(store.meta().expect("meta").last_applied, 1);
        store
            .validate_integrity()
            .expect("concurrent write was not blessed");

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn live_security_projection_drift_is_rejected_but_timestamp_drift_is_ignored() {
        let database_path = path("bound-genesis-integrity");
        drop(open_capture_authority(&test_config(&database_path)).expect("initialize authority"));
        let genesis =
            capture_admission_genesis_projection(&database_path).expect("capture genesis");
        let membership = AdmissionMembership::new_with_genesis(
            vec!["https://node-a".to_string(), "https://node-b".to_string()],
            genesis,
        )
        .expect("membership");
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus store");
        store.bind_membership(&membership).expect("bind membership");

        let election = store
            .begin_election(&membership, "https://node-a")
            .expect("election");
        let entry = entry(&election, "post-genesis-operation");
        store.append_local(&election, &entry).expect("append");
        let commit_proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            index: entry.index,
            leader_epoch: entry.leader_epoch,
            current_term_commit_index: entry.index,
            leader_id: election.candidate_id.clone(),
            quorum_size: 2,
            witness_urls: vec!["https://node-a".to_string(), "https://node-b".to_string()],
        };
        store
            .commit_local(
                &membership,
                &election,
                &commit_proof,
                |transaction, _, _| {
                    transaction
                        .execute(
                            r#"
                        INSERT INTO capability_grant_budgets (
                            capability_id, grant_index, invocation_count,
                            updated_at, seq, total_cost_exposed,
                            total_cost_realized_spend
                        ) VALUES (?1, 0, 2, 1, 1, 0, 0)
                        "#,
                            params!["capability-after-genesis"],
                        )
                        .map_err(|error| error.to_string())?;
                    Ok("{\"applied\":true}".to_string())
                },
            )
            .expect("commit post-genesis mutation");
        store
            .validate_integrity()
            .expect("consensus-applied projection is valid");

        let tamper = Connection::open(&database_path).expect("tamper connection");
        tamper
            .execute(
                r#"
                UPDATE capability_grant_budgets
                SET updated_at = updated_at + 100
                WHERE capability_id = 'capability-after-genesis'
                "#,
                [],
            )
            .expect("change nondeterministic timestamp");
        store
            .validate_integrity()
            .expect("timestamp-only drift is outside the security projection");
        tamper
            .execute(
                r#"
                UPDATE capability_grant_budgets
                SET invocation_count = invocation_count + 1
                WHERE capability_id = 'capability-after-genesis'
                "#,
                [],
            )
            .expect("tamper security projection");
        assert!(matches!(
            store.validate_integrity(),
            Err(AdmissionConsensusError::Protocol(message))
                if message.contains("security projection")
        ));

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn bound_genesis_record_is_revalidated() {
        let database_path = path("bound-genesis-record-integrity");
        drop(open_capture_authority(&test_config(&database_path)).expect("initialize authority"));
        let genesis =
            capture_admission_genesis_projection(&database_path).expect("capture genesis");
        let membership = AdmissionMembership::new_with_genesis(
            vec!["https://node-a".to_string(), "https://node-b".to_string()],
            genesis,
        )
        .expect("membership");
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus store");
        store.bind_membership(&membership).expect("bind membership");

        Connection::open(&database_path)
            .expect("tamper connection")
            .execute(
                "UPDATE admission_consensus_genesis SET projection_json = '{}' WHERE singleton = 1",
                [],
            )
            .expect("tamper persisted genesis");
        assert!(store.validate_integrity().is_err());

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn quorum_loss_after_election_leaves_projections_unchanged() {
        let a_path = path("quorum-loss-a");
        let b_path = path("quorum-loss-b");
        let a = AdmissionConsensusStore::open(&a_path).expect("a");
        let b = AdmissionConsensusStore::open(&b_path).expect("b");
        let election = a
            .begin_election(&membership(), "https://node-a")
            .expect("election");
        assert!(
            b.request_vote(
                &membership(),
                &AdmissionRequestVoteRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: election.term,
                    candidate_id: election.candidate_id.clone(),
                    last_log_index: election.last_log_index,
                    last_log_term: election.last_log_term,
                    commit_index: election.commit_index,
                }
            )
            .expect("vote")
            .vote_granted
        );
        let entry = entry(&election, "operation-quorum-loss");
        a.append_local(&election, &entry).expect("local append");
        let applied = AtomicUsize::new(0);
        let invalid_proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership().digest().to_string(),
            index: entry.index,
            leader_epoch: entry.leader_epoch,
            current_term_commit_index: entry.index,
            leader_id: election.candidate_id.clone(),
            quorum_size: 2,
            witness_urls: vec![election.candidate_id.clone()],
        };
        assert!(a
            .commit_local(&membership(), &election, &invalid_proof, |_, _, _| {
                applied.fetch_add(1, Ordering::SeqCst);
                Ok("{\"ok\":true}".to_string())
            })
            .is_err());
        let outsider_proof = AdmissionCommitProof {
            witness_urls: vec![election.candidate_id.clone(), "https://node-c".to_string()],
            ..invalid_proof
        };
        assert!(a
            .commit_local(&membership(), &election, &outsider_proof, |_, _, _| {
                applied.fetch_add(1, Ordering::SeqCst);
                Ok("{\"ok\":true}".to_string())
            })
            .is_err());
        assert_eq!(a.meta().expect("meta").commit_index, 0);
        assert_eq!(a.meta().expect("meta").last_applied, 0);
        assert_eq!(applied.load(Ordering::SeqCst), 0);

        let _ = std::fs::remove_file(a_path);
        let _ = std::fs::remove_file(b_path);
    }

    #[test]
    fn leader_change_requires_a_current_term_entry_before_committing_the_replicated_tail() {
        let a_path = path("leader-change-a");
        let b_path = path("leader-change-b");
        let a = AdmissionConsensusStore::open(&a_path).expect("a");
        let b = AdmissionConsensusStore::open(&b_path).expect("b");
        let first = a
            .begin_election(&membership(), "https://node-a")
            .expect("first election");
        let old_entry = entry(&first, "operation-old-uncommitted");
        a.append_local(&first, &old_entry)
            .expect("append old locally");
        assert!(
            b.append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: first.term,
                    leader_id: first.candidate_id.clone(),
                    previous_log_index: 0,
                    previous_log_term: 0,
                    entry: Some(old_entry.clone()),
                    leader_commit: 0,
                    commit_proof: None,
                },
                |_, _, _| Ok("{\"old\":true}".to_string()),
            )
            .expect("replicate old")
            .accepted
        );

        let second = b
            .begin_election(&membership(), "https://node-b")
            .expect("second election");
        assert!(
            a.request_vote(
                &membership(),
                &AdmissionRequestVoteRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: second.term,
                    candidate_id: second.candidate_id.clone(),
                    last_log_index: second.last_log_index,
                    last_log_term: second.last_log_term,
                    commit_index: second.commit_index,
                }
            )
            .expect("a votes b")
            .vote_granted
        );
        let old_proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership().digest().to_string(),
            index: old_entry.index,
            leader_epoch: second.term,
            current_term_commit_index: old_entry.index,
            leader_id: second.candidate_id.clone(),
            quorum_size: 2,
            witness_urls: vec!["https://node-a".to_string(), "https://node-b".to_string()],
        };
        assert!(b
            .commit_local(&membership(), &second, &old_proof, |_, _, _| {
                Ok("{\"old\":true}".to_string())
            })
            .is_err());
        assert_eq!(b.meta().expect("uncommitted meta").commit_index, 0);

        let new_entry = AdmissionConsensusStore::build_entry(
            &second,
            "operation-new-leader",
            AdmissionCommandKind::Revoke,
            &serde_json::json!({"capabilityId":"capability-new","revokedAt":9}),
        )
        .expect("new entry");
        b.append_local(&second, &new_entry).expect("append new");
        let replace = AdmissionAppendEntriesRequest {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership().digest().to_string(),
            term: second.term,
            leader_id: second.candidate_id.clone(),
            previous_log_index: old_entry.index,
            previous_log_term: old_entry.leader_epoch,
            entry: Some(new_entry.clone()),
            leader_commit: 0,
            commit_proof: None,
        };
        assert!(
            a.append_entries(&membership(), &replace, |_, _, _| Ok(
                "{\"new\":true}".to_string()
            ))
            .expect("replace tail")
            .accepted
        );
        let old_proof = AdmissionCommitProof {
            current_term_commit_index: new_entry.index,
            ..old_proof
        };
        b.commit_local(&membership(), &second, &old_proof, |_, _, _| {
            Ok("{\"old\":true}".to_string())
        })
        .expect("commit inherited entry after current-term replication");
        assert!(
            a.append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: second.term,
                    leader_id: second.candidate_id.clone(),
                    previous_log_index: new_entry.index,
                    previous_log_term: new_entry.leader_epoch,
                    entry: None,
                    leader_commit: old_entry.index,
                    commit_proof: Some(old_proof),
                },
                |_, _, _| Ok("{\"old\":true}".to_string()),
            )
            .expect("apply inherited entry after current-term replication")
            .accepted
        );
        let proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership().digest().to_string(),
            index: new_entry.index,
            leader_epoch: new_entry.leader_epoch,
            current_term_commit_index: new_entry.index,
            leader_id: second.candidate_id.clone(),
            quorum_size: 2,
            witness_urls: vec!["https://node-a".to_string(), "https://node-b".to_string()],
        };
        b.commit_local(&membership(), &second, &proof, |_, _, _| {
            Ok("{\"new\":true}".to_string())
        })
        .expect("commit new");
        assert!(
            a.append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: second.term,
                    leader_id: second.candidate_id.clone(),
                    previous_log_index: new_entry.index,
                    previous_log_term: new_entry.leader_epoch,
                    entry: None,
                    leader_commit: new_entry.index,
                    commit_proof: Some(proof),
                },
                |_, _, _| Ok("{\"new\":true}".to_string()),
            )
            .expect("apply new")
            .accepted
        );
        assert!(a
            .result_for_operation("operation-old-uncommitted")
            .expect("old result")
            .is_some());
        assert!(b
            .result_for_operation("operation-old-uncommitted")
            .expect("old result")
            .is_some());
        assert!(a
            .result_for_operation("operation-new-leader")
            .expect("new result")
            .is_some());

        let _ = std::fs::remove_file(a_path);
        let _ = std::fs::remove_file(b_path);
    }

    #[test]
    fn new_leader_relays_historical_commit_proofs_to_a_lagging_follower() {
        let source_path = path("historical-proof-source");
        let follower_path = path("historical-proof-follower");
        let source = AdmissionConsensusStore::open(&source_path).expect("source");
        let follower = AdmissionConsensusStore::open(&follower_path).expect("follower");
        let membership = three_member_membership();

        let first = source
            .begin_election(&membership, "https://node-a")
            .expect("first election");
        let old_entry = entry(&first, "operation-historical-proof");
        source.append_local(&first, &old_entry).expect("old append");
        let old_proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            index: old_entry.index,
            leader_epoch: first.term,
            current_term_commit_index: old_entry.index,
            leader_id: first.candidate_id.clone(),
            quorum_size: 2,
            witness_urls: vec!["https://node-a".to_string(), "https://node-b".to_string()],
        };
        source
            .commit_local(&membership, &first, &old_proof, |_, _, _| {
                Ok("{\"old\":true}".to_string())
            })
            .expect("old commit");

        let second = source
            .begin_election(&membership, "https://node-b")
            .expect("second election");
        let current_entry = entry(&second, "operation-current-proof");
        source
            .append_local(&second, &current_entry)
            .expect("current append");
        for entry in [&old_entry, &current_entry] {
            let previous_log_index = entry.index.checked_sub(1).expect("previous index");
            let previous_log_term = if previous_log_index == 0 {
                0
            } else {
                old_entry.leader_epoch
            };
            assert!(
                follower
                    .append_entries(
                        &membership,
                        &AdmissionAppendEntriesRequest {
                            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                            membership_digest: membership.digest().to_string(),
                            term: second.term,
                            leader_id: second.candidate_id.clone(),
                            previous_log_index,
                            previous_log_term,
                            entry: Some(entry.clone()),
                            leader_commit: 0,
                            commit_proof: None,
                        },
                        |_, _, _| Ok("{}".to_string()),
                    )
                    .expect("follower append")
                    .accepted
            );
        }
        assert!(
            follower
                .append_entries(
                    &membership,
                    &AdmissionAppendEntriesRequest {
                        protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                        membership_digest: membership.digest().to_string(),
                        term: second.term,
                        leader_id: second.candidate_id,
                        previous_log_index: current_entry.index,
                        previous_log_term: current_entry.leader_epoch,
                        entry: None,
                        leader_commit: old_entry.index,
                        commit_proof: Some(old_proof),
                    },
                    |_, _, _| Ok("{\"old\":true}".to_string()),
                )
                .expect("historical proof relay")
                .accepted
        );
        assert_eq!(follower.meta().expect("follower meta").commit_index, 1);
        assert_eq!(follower.meta().expect("follower meta").last_applied, 1);

        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(follower_path);
    }

    fn clustered_test_config(
        database_path: &Path,
        self_url: &str,
        peer_urls: Vec<String>,
    ) -> TrustServiceConfig {
        let mut config = test_config(database_path);
        config.advertise_url = Some(self_url.to_string());
        config.peer_urls = peer_urls;
        config
    }

    fn clustered_test_state(
        config: TrustServiceConfig,
        local_addr: SocketAddr,
    ) -> TrustServiceState {
        let cluster = build_cluster_state(&config, local_addr).expect("cluster state");
        TrustServiceState {
            config,
            enterprise_provider_registry: None,
            verifier_policy_registry: None,
            federation_admission_rate_limiter: Arc::new(Mutex::new(
                FederationAdmissionRateLimiter::default(),
            )),
            cluster,
            cluster_progress: Some(Arc::new(ClusterProgress::new())),
        }
    }

    #[test]
    fn clustered_service_without_combined_authority_storage_starts_without_consensus() {
        let database_path = path("optional-consensus-storage");
        let mut config = clustered_test_config(
            &database_path,
            "http://127.0.0.1:38101",
            vec![
                "http://127.0.0.1:38102".to_string(),
                "http://127.0.0.1:38103".to_string(),
            ],
        );
        config.budget_db_path = None;
        config.revocation_db_path = None;
        let state = clustered_test_state(config, SocketAddr::from(([127, 0, 0, 1], 38101)));
        initialize_admission_consensus(&state).expect("optional consensus initialization");
        assert!(!database_path.exists());
    }

    fn consensus_test_router(state: TrustServiceState) -> axum::Router {
        axum::Router::new()
            .route(
                INTERNAL_ADMISSION_REQUEST_VOTE_PATH,
                axum::routing::post(handle_internal_admission_request_vote),
            )
            .route(
                INTERNAL_ADMISSION_APPEND_ENTRIES_PATH,
                axum::routing::post(handle_internal_admission_append_entries),
            )
            .route(
                INTERNAL_ADMISSION_PROPOSAL_PATH,
                axum::routing::post(handle_internal_admission_proposal),
            )
            .route(
                INTERNAL_ADMISSION_SNAPSHOT_PATH,
                axum::routing::get(handle_internal_admission_snapshot),
            )
            .with_state(state)
    }

    fn service_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer consensus-test-token"),
        );
        headers
    }

    async fn invoke_composite_authorize(
        state: TrustServiceState,
        request: CompositeBudgetAuthorizeRequest,
    ) -> Result<CompositeBudgetAuthorizeResponse, String> {
        let response =
            super::super::super::budget_handlers::handle_authorize_composite_budget_hold(
                State(state),
                service_headers(),
                Json(request),
            )
            .await;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .map_err(|error| error.to_string())?;
        if status != StatusCode::OK {
            return Err(format!(
                "{status}: {}",
                String::from_utf8_lossy(body.as_ref())
            ));
        }
        serde_json::from_slice(&body).map_err(|error| error.to_string())
    }

    async fn decode_http_response<T: DeserializeOwned>(response: Response) -> Result<T, String> {
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .map_err(|error| error.to_string())?;
        if status != StatusCode::OK {
            return Err(format!(
                "{status}: {}",
                String::from_utf8_lossy(body.as_ref())
            ));
        }
        serde_json::from_slice(&body).map_err(|error| error.to_string())
    }

    async fn invoke_reverse_exposure(
        state: TrustServiceState,
        request: ReverseChargeCostRequest,
    ) -> Result<ReverseChargeCostResponse, String> {
        decode_http_response(
            super::super::super::budget_handlers::handle_reverse_charge_cost(
                State(state),
                service_headers(),
                Json(request),
            )
            .await,
        )
        .await
    }

    async fn invoke_reduce_exposure(
        state: TrustServiceState,
        request: ReduceChargeCostRequest,
    ) -> Result<ReduceChargeCostResponse, String> {
        decode_http_response(
            super::super::super::budget_handlers::handle_reduce_charge_cost(
                State(state),
                service_headers(),
                Json(request),
            )
            .await,
        )
        .await
    }

    async fn invoke_capture_exposure(
        state: TrustServiceState,
        request: ReduceChargeCostRequest,
    ) -> Result<ReduceChargeCostResponse, String> {
        decode_http_response(
            super::super::super::budget_handlers::handle_capture_budget_hold(
                State(state),
                service_headers(),
                Json(request),
            )
            .await,
        )
        .await
    }

    async fn invoke_admission_command<T: Serialize>(
        state: &TrustServiceState,
        operation_id: &str,
        command_kind: AdmissionCommandKind,
        command: &T,
    ) -> Result<AdmissionConsensusResult, String> {
        match propose_admission_command(state, operation_id.to_string(), command_kind, command)
            .await
        {
            Ok(result) => Ok(result),
            Err(response) => {
                let status = response.status();
                let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                    .await
                    .map_err(|error| error.to_string())?;
                Err(format!(
                    "{status}: {}",
                    String::from_utf8_lossy(body.as_ref())
                ))
            }
        }
    }

    struct ThreeNodeCluster {
        paths: [PathBuf; 3],
        states: [TrustServiceState; 3],
        servers: [tokio::task::JoinHandle<()>; 3],
    }

    impl ThreeNodeCluster {
        async fn start(label: &str) -> Self {
            let paths = [
                path(&format!("{label}-a")),
                path(&format!("{label}-b")),
                path(&format!("{label}-c")),
            ];
            let listener_a = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("listener a");
            let listener_b = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("listener b");
            let listener_c = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("listener c");
            let addresses = [
                listener_a.local_addr().expect("address a"),
                listener_b.local_addr().expect("address b"),
                listener_c.local_addr().expect("address c"),
            ];
            let urls = addresses
                .iter()
                .map(|address| format!("http://{address}"))
                .collect::<Vec<_>>();
            let states = [
                clustered_test_state(
                    clustered_test_config(
                        &paths[0],
                        &urls[0],
                        vec![urls[1].clone(), urls[2].clone()],
                    ),
                    addresses[0],
                ),
                clustered_test_state(
                    clustered_test_config(
                        &paths[1],
                        &urls[1],
                        vec![urls[0].clone(), urls[2].clone()],
                    ),
                    addresses[1],
                ),
                clustered_test_state(
                    clustered_test_config(
                        &paths[2],
                        &urls[2],
                        vec![urls[0].clone(), urls[1].clone()],
                    ),
                    addresses[2],
                ),
            ];
            for state in &states {
                initialize_admission_consensus(state).expect("initialize consensus");
            }
            let state_a = states[0].clone();
            let state_b = states[1].clone();
            let state_c = states[2].clone();
            let servers = [
                tokio::spawn(async move {
                    axum::serve(listener_a, consensus_test_router(state_a))
                        .await
                        .expect("serve a");
                }),
                tokio::spawn(async move {
                    axum::serve(listener_b, consensus_test_router(state_b))
                        .await
                        .expect("serve b");
                }),
                tokio::spawn(async move {
                    axum::serve(listener_c, consensus_test_router(state_c))
                        .await
                        .expect("serve c");
                }),
            ];
            tokio::time::sleep(Duration::from_millis(10)).await;
            Self {
                paths,
                states,
                servers,
            }
        }

        fn snapshots(&self) -> [AdmissionConsensusSnapshot; 3] {
            std::array::from_fn(|index| {
                configured_admission_consensus_store(&self.states[index].config)
                    .expect("consensus store")
                    .snapshot()
                    .expect("consensus snapshot")
            })
        }

        async fn stop(self) {
            for server in self.servers {
                server.abort();
                let _ = server.await;
            }
            for path in self.paths {
                let _ = std::fs::remove_file(&path);
                let _ = std::fs::remove_file(format!("{}-wal", path.display()));
                let _ = std::fs::remove_file(format!("{}-shm", path.display()));
            }
        }
    }

    fn assert_same_committed_state(
        left: &AdmissionConsensusSnapshot,
        right: &AdmissionConsensusSnapshot,
    ) {
        assert_eq!(left.protocol_version, right.protocol_version);
        assert_eq!(left.meta.membership_digest, right.meta.membership_digest);
        assert_eq!(left.meta.last_log_index, right.meta.last_log_index);
        assert_eq!(left.meta.last_log_term, right.meta.last_log_term);
        assert_eq!(left.meta.commit_index, right.meta.commit_index);
        assert_eq!(left.meta.last_applied, right.meta.last_applied);
        assert_eq!(
            left.meta.applied_state_digest,
            right.meta.applied_state_digest
        );
        assert_eq!(left.entries, right.entries);
        assert_eq!(left.commit_proofs, right.commit_proofs);
        assert_eq!(left.results, right.results);
    }

    #[test]
    fn proposal_serializers_are_scoped_to_one_member() {
        let first = admission_proposal_serializer("https://node-a");
        let first_again = admission_proposal_serializer("https://node-a");
        let second = admission_proposal_serializer("https://node-b");
        assert!(Arc::ptr_eq(&first, &first_again));
        assert!(!Arc::ptr_eq(&first, &second));

        let _first_guard = first.lock().expect("first serializer");
        let (sent, received) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let _second_guard = second.lock().expect("second serializer");
            sent.send(()).expect("notify independent acquisition");
        });
        received
            .recv_timeout(Duration::from_millis(100))
            .expect("another member must not share the held serializer");
        worker.join().expect("serializer worker");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn remote_last_unit_race_converges_to_exactly_one_allow() {
        let cluster = ThreeNodeCluster::start("remote-last-unit").await;

        let first_request = composite_request(
            "capability-remote-last-unit",
            "hold-remote-a",
            "event-remote-a",
            1,
        );
        let second_request = composite_request(
            "capability-remote-last-unit",
            "hold-remote-b",
            "event-remote-b",
            1,
        );
        let (first, second) = tokio::join!(
            invoke_composite_authorize(cluster.states[1].clone(), first_request.clone()),
            invoke_composite_authorize(cluster.states[2].clone(), second_request.clone()),
        );
        let first = first.expect("first response");
        let second = second.expect("second response");
        assert_eq!(usize::from(first.allowed) + usize::from(second.allowed), 1);
        assert_eq!(first.invocation_count_after, 1);
        assert_eq!(second.invocation_count_after, 1);

        let snapshots = cluster.snapshots();
        assert_same_committed_state(&snapshots[0], &snapshots[1]);
        assert_same_committed_state(&snapshots[1], &snapshots[2]);
        assert_eq!(snapshots[0].meta.commit_index, 2);
        assert_eq!(snapshots[0].meta.last_applied, 2);
        assert_eq!(snapshots[0].results.len(), 2);

        cluster.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn remote_authorization_survives_coordinator_unavailability() {
        let cluster = ThreeNodeCluster::start("remote-coordinator-unavailable").await;
        let mut members = cluster
            .states
            .iter()
            .enumerate()
            .map(|(index, state)| {
                let (self_url, _, _) = admission_members(state).expect("member identity");
                (self_url, index)
            })
            .collect::<Vec<_>>();
        members.sort();
        let coordinator_index = members[0].1;
        cluster.servers[coordinator_index].abort();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let caller_index = members[1].1;
        let response = invoke_composite_authorize(
            cluster.states[caller_index].clone(),
            composite_request(
                "capability-coordinator-unavailable",
                "hold-coordinator-unavailable",
                "event-coordinator-unavailable",
                1,
            ),
        )
        .await
        .expect("fallback authorization");
        assert!(response.allowed);
        for (_, index) in members.iter().skip(1) {
            let snapshot = configured_admission_consensus_store(&cluster.states[*index].config)
                .expect("live consensus store")
                .snapshot()
                .expect("live consensus snapshot");
            assert_eq!(snapshot.meta.commit_index, 1);
            assert_eq!(snapshot.meta.last_applied, 1);
        }

        cluster.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn stale_survivor_forwards_to_fresh_quorum_after_coordinator_loss() {
        let mut cluster = ThreeNodeCluster::start("remote-stale-survivor").await;
        let mut members = cluster
            .states
            .iter()
            .enumerate()
            .map(|(index, state)| {
                let (self_url, _, _) = admission_members(state).expect("member identity");
                (self_url, index)
            })
            .collect::<Vec<_>>();
        members.sort();
        let coordinator_index = members[0].1;
        let fresh_survivor_index = members[1].1;
        let stale_survivor_index = members[2].1;
        let stale_address = members[2]
            .0
            .strip_prefix("http://")
            .expect("local member URL")
            .parse::<SocketAddr>()
            .expect("local member address");

        cluster.servers[stale_survivor_index].abort();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let first = invoke_composite_authorize(
            cluster.states[coordinator_index].clone(),
            composite_request(
                "capability-stale-survivor",
                "hold-before-coordinator-loss",
                "event-before-coordinator-loss",
                2,
            ),
        )
        .await
        .expect("initial quorum authorization");
        assert!(first.allowed);
        assert_eq!(
            configured_admission_consensus_store(&cluster.states[stale_survivor_index].config)
                .expect("stale store")
                .snapshot()
                .expect("stale snapshot")
                .meta
                .commit_index,
            0
        );

        cluster.servers[coordinator_index].abort();
        let stale_listener = tokio::net::TcpListener::bind(stale_address)
            .await
            .expect("restart stale survivor listener");
        let stale_state = cluster.states[stale_survivor_index].clone();
        cluster.servers[stale_survivor_index] = tokio::spawn(async move {
            axum::serve(stale_listener, consensus_test_router(stale_state))
                .await
                .expect("serve restarted stale survivor");
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        let second = invoke_composite_authorize(
            cluster.states[stale_survivor_index].clone(),
            composite_request(
                "capability-stale-survivor",
                "hold-after-coordinator-loss",
                "event-after-coordinator-loss",
                2,
            ),
        )
        .await
        .expect("fresh survivor forwarding");
        assert!(second.allowed);
        let fresh =
            configured_admission_consensus_store(&cluster.states[fresh_survivor_index].config)
                .expect("fresh survivor store")
                .snapshot()
                .expect("fresh survivor snapshot");
        let stale =
            configured_admission_consensus_store(&cluster.states[stale_survivor_index].config)
                .expect("recovered survivor store")
                .snapshot()
                .expect("recovered survivor snapshot");
        assert_same_committed_state(&fresh, &stale);
        assert_eq!(fresh.meta.commit_index, 2);

        cluster.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn cross_node_proposals_converge_after_preferred_coordinator_loss() {
        let cluster = ThreeNodeCluster::start("remote-competing-elections").await;
        let mut members = cluster
            .states
            .iter()
            .enumerate()
            .map(|(index, state)| {
                let (self_url, _, _) = admission_members(state).expect("member identity");
                (self_url, index)
            })
            .collect::<Vec<_>>();
        members.sort();
        cluster.servers[members[0].1].abort();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for (rank, (_, index)) in members.iter().skip(1).enumerate() {
            let state = cluster.states[*index].clone();
            let barrier = barrier.clone();
            workers.push(tokio::task::spawn_blocking(move || {
                barrier.wait();
                propose_admission_command_blocking(
                    &state,
                    format!("competing-election-{rank}"),
                    AdmissionCommandKind::Revoke,
                    serde_json::to_value(ConsensusRevocationProposal {
                        capability_id: format!("capability-competing-{rank}"),
                    })
                    .expect("serialize revocation"),
                )
            }));
        }
        barrier.wait();
        for worker in workers {
            worker
                .await
                .expect("proposal worker")
                .expect("competing proposal converges");
        }
        let left = configured_admission_consensus_store(&cluster.states[members[1].1].config)
            .expect("left store")
            .snapshot()
            .expect("left snapshot");
        let right = configured_admission_consensus_store(&cluster.states[members[2].1].config)
            .expect("right store")
            .snapshot()
            .expect("right snapshot");
        assert_same_committed_state(&left, &right);
        assert_eq!(left.meta.last_log_index, left.meta.commit_index);
        assert_eq!(left.meta.commit_index, left.meta.last_applied);
        assert_eq!(left.entries.len(), left.commit_proofs.len());
        assert_eq!(left.commit_proofs.len(), left.results.len());
        assert!(left.meta.current_term >= left.meta.last_log_term);
        assert!(right.meta.current_term >= right.meta.last_log_term);
        for snapshot in [&left, &right] {
            assert!(snapshot
                .meta
                .voted_for
                .as_ref()
                .is_none_or(|candidate| { members.iter().any(|(member, _)| member == candidate) }));
        }
        let committed_entries = left
            .entries
            .iter()
            .take(usize_index(left.meta.commit_index, "committed entry count").expect("count"))
            .collect::<Vec<_>>();
        assert_eq!(
            committed_entries
                .iter()
                .filter(|entry| entry.command_kind == AdmissionCommandKind::Revoke)
                .count(),
            2
        );
        assert!(committed_entries.iter().all(|entry| matches!(
            entry.command_kind,
            AdmissionCommandKind::Revoke | AdmissionCommandKind::LeadershipBarrier
        )));
        for proof in &left.commit_proofs {
            assert!(proof.current_term_commit_index <= left.meta.commit_index);
            let offset = usize_index(
                checked_predecessor(
                    proof.current_term_commit_index,
                    "current-term commit target",
                )
                .expect("target predecessor"),
                "current-term commit target offset",
            )
            .expect("target offset");
            assert_eq!(left.entries[offset].leader_epoch, proof.leader_epoch);
        }
        for rank in 0..2 {
            let operation_id = scoped_operation_id(
                AdmissionCommandKind::Revoke,
                &format!("competing-election-{rank}"),
            )
            .expect("scoped operation");
            assert_eq!(
                committed_entries
                    .iter()
                    .filter(|entry| entry.operation_id == operation_id)
                    .count(),
                1
            );
            assert!(left
                .results
                .iter()
                .any(|result| result.operation_id == operation_id));
        }
        for (_, index) in members.iter().skip(1) {
            let path = cluster.states[*index]
                .config
                .revocation_db_path
                .as_deref()
                .expect("revocation database");
            let connection = Connection::open(path).expect("revocation projection");
            for rank in 0..2 {
                assert_eq!(
                    connection
                        .query_row(
                            "SELECT COUNT(*) FROM revoked_capabilities WHERE capability_id = ?1",
                            params![format!("capability-competing-{rank}")],
                            |row| row.get::<_, i64>(0),
                        )
                        .expect("revocation count"),
                    1
                );
            }
        }

        cluster.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn remote_proposal_commits_through_the_preferred_coordinator() {
        let cluster = ThreeNodeCluster::start("remote-preferred-coordinator").await;
        let mut members = cluster
            .states
            .iter()
            .enumerate()
            .map(|(index, state)| {
                let (self_url, _, _) = admission_members(state).expect("member identity");
                (self_url, index)
            })
            .collect::<Vec<_>>();
        members.sort();
        let coordinator_url = members[0].0.clone();
        let caller_index = members[2].1;
        let response = invoke_composite_authorize(
            cluster.states[caller_index].clone(),
            composite_request(
                "capability-preferred-coordinator",
                "hold-preferred-coordinator",
                "event-preferred-coordinator",
                1,
            ),
        )
        .await
        .expect("coordinated authorization");
        assert!(response.allowed);
        let snapshot = configured_admission_consensus_store(&cluster.states[caller_index].config)
            .expect("consensus store")
            .snapshot()
            .expect("consensus snapshot");
        assert_eq!(snapshot.commit_proofs.len(), 1);
        assert_eq!(snapshot.commit_proofs[0].leader_id, coordinator_url);

        cluster.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn max_length_revocation_retry_reuses_the_original_entry_and_timestamp() {
        let cluster = ThreeNodeCluster::start("remote-revocation-response-loss").await;
        let capability_id = "r".repeat(512);
        let operation_id =
            super::super::authority_handlers::cluster_revocation_operation_id(&capability_id);
        assert!(operation_id.len() <= 512);
        let proposal = ConsensusRevocationProposal { capability_id };
        let first = invoke_admission_command(
            &cluster.states[0],
            &operation_id,
            AdmissionCommandKind::Revoke,
            &proposal,
        )
        .await
        .expect("initial revocation");
        let before = cluster.snapshots();
        let database_path = cluster.states[0]
            .config
            .revocation_db_path
            .as_deref()
            .expect("revocation database");
        let revoked_at_before: i64 = Connection::open(database_path)
            .expect("revocation connection")
            .query_row(
                "SELECT revoked_at FROM revoked_capabilities WHERE capability_id = ?1",
                params![&proposal.capability_id],
                |row| row.get(0),
            )
            .expect("persisted revocation timestamp");

        let retry = invoke_admission_command(
            &cluster.states[2],
            &operation_id,
            AdmissionCommandKind::Revoke,
            &proposal,
        )
        .await
        .expect("response-loss retry");
        assert_eq!(retry, first);
        let after = cluster.snapshots();
        for index in 0..after.len() {
            assert_eq!(after[index].entries, before[index].entries);
            assert_eq!(after[index].commit_proofs, before[index].commit_proofs);
            assert_eq!(after[index].results, before[index].results);
            assert_eq!(
                after[index].meta.last_log_index,
                before[index].meta.last_log_index
            );
            assert_eq!(
                after[index].meta.commit_index,
                before[index].meta.commit_index
            );
            assert_eq!(
                after[index].meta.last_applied,
                before[index].meta.last_applied
            );
        }
        let scoped = scoped_operation_id(AdmissionCommandKind::Revoke, &operation_id)
            .expect("scoped revocation operation");
        assert_eq!(
            after[0]
                .entries
                .iter()
                .filter(|entry| entry.operation_id == scoped)
                .count(),
            1
        );
        let revoked_at_after: i64 = Connection::open(database_path)
            .expect("revocation connection")
            .query_row(
                "SELECT revoked_at FROM revoked_capabilities WHERE capability_id = ?1",
                params![&proposal.capability_id],
                |row| row.get(0),
            )
            .expect("retried revocation timestamp");
        assert_eq!(revoked_at_after, revoked_at_before);

        cluster.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn remote_revocation_and_capture_race_has_one_durable_order() {
        let cluster = ThreeNodeCluster::start("remote-revocation-capture").await;
        let capability_id = "capability-remote-order";
        let authorization = invoke_composite_authorize(
            cluster.states[0].clone(),
            composite_request(
                capability_id,
                "hold-remote-order",
                "authorize-remote-order",
                1,
            ),
        )
        .await
        .expect("authorize response");
        assert!(authorization.allowed);

        let revocation_operation = "revocation:capability-remote-order";
        let revocation = ConsensusRevocationProposal {
            capability_id: capability_id.to_string(),
        };
        let capture_operation = "operation-remote-order";
        let capture_request =
            combined_request(&authorization, capture_operation, "capture-remote-order");

        let (revoke_result, capture_result) = tokio::join!(
            invoke_admission_command(
                &cluster.states[1],
                revocation_operation,
                AdmissionCommandKind::Revoke,
                &revocation,
            ),
            invoke_admission_command(
                &cluster.states[2],
                capture_operation,
                AdmissionCommandKind::CombinedCapture,
                &capture_request,
            ),
        );
        revoke_result.expect("revocation response");
        let capture_result = capture_result.expect("capture response");
        let capture_response: CombinedAdmissionCaptureResponse =
            serde_json::from_str(&capture_result.response_json).expect("capture result body");

        let snapshots = cluster.snapshots();
        assert_same_committed_state(&snapshots[0], &snapshots[1]);
        assert_same_committed_state(&snapshots[1], &snapshots[2]);
        assert_eq!(snapshots[0].meta.commit_index, 3);
        assert_eq!(snapshots[0].meta.last_applied, 3);
        assert_eq!(snapshots[0].results.len(), 3);
        let revocation_key =
            scoped_operation_id(AdmissionCommandKind::Revoke, revocation_operation)
                .expect("revocation key");
        let capture_key =
            scoped_operation_id(AdmissionCommandKind::CombinedCapture, capture_operation)
                .expect("capture key");
        let revocation_index = snapshots[0]
            .entries
            .iter()
            .find(|entry| entry.operation_id == revocation_key)
            .expect("revocation entry")
            .index;
        let capture_index = snapshots[0]
            .entries
            .iter()
            .find(|entry| entry.operation_id == capture_key)
            .expect("capture entry")
            .index;
        assert_ne!(revocation_index, capture_index);

        let expected_counts = if revocation_index < capture_index {
            assert_eq!(
                capture_response.outcome,
                AdmissionCaptureOutcomeView::DeniedRevoked
            );
            assert!(capture_response.budget.is_none());
            (1_i64, 0_i64)
        } else {
            assert_eq!(
                capture_response.outcome,
                AdmissionCaptureOutcomeView::Captured
            );
            assert_eq!(
                capture_response
                    .budget
                    .as_ref()
                    .expect("captured budget")
                    .invocation_count_after,
                1
            );
            (0_i64, 1_i64)
        };
        for path in &cluster.paths {
            let counts = Connection::open(path)
                .expect("open quota database")
                .query_row(
                    r#"
                    SELECT reserved_invocations, captured_invocations
                    FROM budget_invocation_quota_usage
                    WHERE profile = 'chio.grant-invocation.v1'
                      AND owner_id = ?1
                      AND grant_index_key = 0
                    "#,
                    params![capability_id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .expect("quota counts");
            assert_eq!(counts, expected_counts);
        }

        let retry = invoke_admission_command(
            &cluster.states[0],
            capture_operation,
            AdmissionCommandKind::CombinedCapture,
            &capture_request,
        )
        .await
        .expect("exact capture retry");
        assert_eq!(retry, capture_result);
        let retried_snapshots = cluster.snapshots();
        for index in 0..3 {
            assert_same_committed_state(&retried_snapshots[index], &snapshots[index]);
        }

        cluster.stop().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn remote_admission_authority_completes_every_monetary_transition() {
        let cluster = ThreeNodeCluster::start("remote-monetary-transitions").await;
        let capability_id = "capability-remote-monetary";
        let mut authorizations = Vec::new();
        for suffix in ["reverse", "release", "reconcile", "capture"] {
            let mut request = composite_request(
                capability_id,
                &format!("hold-remote-{suffix}"),
                &format!("authorize-remote-{suffix}"),
                8,
            );
            request.requested_exposure_units = 10;
            request.max_exposure_per_invocation = Some(10);
            request.max_total_exposure_units = Some(40);
            let authorization = invoke_composite_authorize(cluster.states[0].clone(), request)
                .await
                .expect("authorize monetary hold");
            assert!(authorization.allowed);
            authorizations.push(authorization);
        }

        let authority = |authorization: &CompositeBudgetAuthorizeResponse| {
            let authority = authorization
                .budget_authority
                .as_ref()
                .expect("persisted admission authority");
            BudgetMutationAuthorityView {
                authority_id: authority.authority_id.clone(),
                lease_id: authority.lease_id.clone(),
                lease_epoch: authority.lease_epoch,
            }
        };
        let missing_authority = super::super::super::budget_handlers::handle_reverse_charge_cost(
            State(cluster.states[1].clone()),
            service_headers(),
            Json(ReverseChargeCostRequest {
                capability_id: capability_id.to_string(),
                grant_index: 0,
                cost_units: 10,
                hold_id: Some(authorizations[0].hold_id.clone()),
                event_id: Some("reverse-remote-missing-authority".to_string()),
                budget_authority: None,
            }),
        )
        .await;
        assert_eq!(missing_authority.status(), StatusCode::BAD_REQUEST);
        let reverse = invoke_reverse_exposure(
            cluster.states[1].clone(),
            ReverseChargeCostRequest {
                capability_id: capability_id.to_string(),
                grant_index: 0,
                cost_units: 10,
                hold_id: Some(authorizations[0].hold_id.clone()),
                event_id: Some("reverse-remote-monetary".to_string()),
                budget_authority: Some(authority(&authorizations[0])),
            },
        )
        .await
        .expect("reverse exposure");
        assert_eq!(reverse.total_cost_exposed, Some(30));

        let invalid_release = ReduceChargeCostRequest {
            capability_id: capability_id.to_string(),
            grant_index: 0,
            cost_units: 11,
            exposure_units: None,
            realized_spend_units: None,
            hold_id: Some(authorizations[1].hold_id.clone()),
            event_id: Some("release-remote-conflict".to_string()),
            budget_authority: Some(authority(&authorizations[1])),
        };
        for state in [&cluster.states[2], &cluster.states[0]] {
            let response = super::super::super::budget_handlers::handle_reduce_charge_cost(
                State(state.clone()),
                service_headers(),
                Json(ReduceChargeCostRequest {
                    capability_id: invalid_release.capability_id.clone(),
                    grant_index: invalid_release.grant_index,
                    cost_units: invalid_release.cost_units,
                    exposure_units: invalid_release.exposure_units,
                    realized_spend_units: invalid_release.realized_spend_units,
                    hold_id: invalid_release.hold_id.clone(),
                    event_id: invalid_release.event_id.clone(),
                    budget_authority: invalid_release.budget_authority.clone(),
                }),
            )
            .await;
            assert_eq!(response.status(), StatusCode::CONFLICT);
        }
        let release = invoke_reduce_exposure(
            cluster.states[2].clone(),
            ReduceChargeCostRequest {
                capability_id: capability_id.to_string(),
                grant_index: 0,
                cost_units: 4,
                exposure_units: None,
                realized_spend_units: None,
                hold_id: Some(authorizations[1].hold_id.clone()),
                event_id: Some("release-remote-monetary".to_string()),
                budget_authority: Some(authority(&authorizations[1])),
            },
        )
        .await
        .expect("release exposure");
        assert_eq!(release.total_cost_exposed, Some(26));

        let contradictory_reconcile =
            super::super::super::budget_handlers::handle_reduce_charge_cost(
                State(cluster.states[0].clone()),
                service_headers(),
                Json(ReduceChargeCostRequest {
                    capability_id: capability_id.to_string(),
                    grant_index: 0,
                    cost_units: 4,
                    exposure_units: Some(10),
                    realized_spend_units: Some(9),
                    hold_id: Some(authorizations[2].hold_id.clone()),
                    event_id: Some("reconcile-remote-contradiction".to_string()),
                    budget_authority: Some(authority(&authorizations[2])),
                }),
            )
            .await;
        assert_eq!(contradictory_reconcile.status(), StatusCode::BAD_REQUEST);
        let reconcile = invoke_reduce_exposure(
            cluster.states[0].clone(),
            ReduceChargeCostRequest {
                capability_id: capability_id.to_string(),
                grant_index: 0,
                cost_units: 4,
                exposure_units: Some(10),
                realized_spend_units: Some(6),
                hold_id: Some(authorizations[2].hold_id.clone()),
                event_id: Some("reconcile-remote-monetary".to_string()),
                budget_authority: Some(authority(&authorizations[2])),
            },
        )
        .await
        .expect("reconcile exposure");
        assert_eq!(reconcile.total_cost_exposed, Some(16));
        assert_eq!(reconcile.total_cost_realized_spend, Some(6));

        let capture = invoke_capture_exposure(
            cluster.states[1].clone(),
            ReduceChargeCostRequest {
                capability_id: capability_id.to_string(),
                grant_index: 0,
                cost_units: 4,
                exposure_units: Some(10),
                realized_spend_units: Some(6),
                hold_id: Some(authorizations[3].hold_id.clone()),
                event_id: Some("capture-remote-monetary".to_string()),
                budget_authority: Some(authority(&authorizations[3])),
            },
        )
        .await
        .expect("capture exposure");
        assert_eq!(capture.total_cost_exposed, Some(6));
        assert_eq!(capture.total_cost_realized_spend, Some(12));
        for response in [release, reconcile, capture] {
            let commit = response.budget_commit.expect("consensus budget commit");
            assert!(commit.quorum_committed);
            assert_eq!(commit.quorum_size, 2);
            assert!(commit.commit_index >= commit.budget_seq);
        }
        let reverse_commit = reverse.budget_commit.expect("reverse consensus commit");
        assert!(reverse_commit.quorum_committed);

        let snapshots = cluster.snapshots();
        assert_same_committed_state(&snapshots[0], &snapshots[1]);
        assert_same_committed_state(&snapshots[1], &snapshots[2]);
        assert_eq!(snapshots[0].meta.commit_index, 9);
        assert_eq!(snapshots[0].meta.last_applied, 9);

        cluster.stop().await;
    }

    fn test_config(database_path: &Path) -> TrustServiceConfig {
        TrustServiceConfig {
            listen: "127.0.0.1:0".parse().expect("listen"),
            service_token: "consensus-test-token".to_string(),
            tenant_read_tokens: BTreeMap::new(),
            receipt_db_path: None,
            revocation_db_path: Some(database_path.to_path_buf()),
            authority_seed_path: None,
            authority_db_path: None,
            budget_db_path: Some(database_path.to_path_buf()),
            enterprise_providers_file: None,
            federation_policies_file: None,
            scim_lifecycle_file: None,
            verifier_policies_file: None,
            verifier_challenge_db_path: None,
            passport_statuses_file: None,
            passport_issuance_offers_file: None,
            certification_registry_file: None,
            certification_discovery_file: None,
            issuance_policy: None,
            runtime_assurance_policy: None,
            advertise_url: None,
            allow_local_peer_urls: true,
            certification_public_metadata_ttl_seconds: 300,
            peer_urls: Vec::new(),
            cluster_sync_interval: Duration::from_millis(50),
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        }
    }

    fn revocation_set(capability_id: &str) -> CanonicalRevocationSetView {
        let ids = vec![capability_id.to_string()];
        let canonical = canonical_json_bytes(&ids).expect("canonical revocation ids");
        let mut digest_input = b"chio.revocation-set.v1\0".to_vec();
        digest_input.extend_from_slice(&canonical);
        CanonicalRevocationSetView {
            ids,
            digest: sha256_hex(&digest_input),
        }
    }

    fn composite_request(
        capability_id: &str,
        hold_id: &str,
        event_id: &str,
        max_invocations: u32,
    ) -> CompositeBudgetAuthorizeRequest {
        CompositeBudgetAuthorizeRequest {
            capability_id: capability_id.to_string(),
            grant_index: 0,
            requested_exposure_units: 0,
            max_exposure_per_invocation: None,
            max_total_exposure_units: None,
            hold_id: hold_id.to_string(),
            event_id: event_id.to_string(),
            admission_evidence: BudgetInvocationAdmissionEvidenceView {
                invocation_quotas: vec![BudgetInvocationQuotaView {
                    key: BudgetQuotaKeyView {
                        profile: BudgetQuotaProfileView::GrantInvocation,
                        owner_id: capability_id.to_string(),
                        grant_index: Some(0),
                    },
                    max_invocations,
                }],
                revocation_set: revocation_set(capability_id),
                aggregate_binding_digest: None,
                supplemental_binding: Some(BudgetSupplementalQuotaBindingView {
                    artifact_digest: "aa".repeat(32),
                    verifier_id: "consensus-test-verifier".to_string(),
                    request_binding_hash: "bb".repeat(32),
                    negotiated_features_digest: "cc".repeat(32),
                }),
            },
        }
    }

    fn commit_state_machine_command<T: Serialize>(
        store: &AdmissionConsensusStore,
        config: &TrustServiceConfig,
        operation_id: &str,
        command_kind: AdmissionCommandKind,
        command: &T,
    ) -> AdmissionConsensusResult {
        let membership = single_member();
        let election = store
            .begin_election(&membership, "https://node-a")
            .expect("state machine election");
        let command = serde_json::to_value(command).expect("command value");
        let command =
            prepare_command(config, command_kind, command, &election).expect("prepare command");
        let entry =
            AdmissionConsensusStore::build_entry(&election, operation_id, command_kind, &command)
                .expect("state machine entry");
        store
            .append_local(&election, &entry)
            .expect("state machine append");
        let proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            index: entry.index,
            leader_epoch: entry.leader_epoch,
            current_term_commit_index: entry.index,
            leader_id: election.candidate_id.clone(),
            quorum_size: 1,
            witness_urls: vec![election.candidate_id.clone()],
        };
        store
            .commit_local(
                &membership,
                &election,
                &proof,
                |transaction, entry, proof| {
                    apply_admission_log_entry(config, transaction, entry, proof)
                },
            )
            .expect("state machine commit")
    }

    fn authorized_hold(
        store: &AdmissionConsensusStore,
        config: &TrustServiceConfig,
        capability_id: &str,
        hold_id: &str,
        event_id: &str,
        max_invocations: u32,
    ) -> CompositeBudgetAuthorizeResponse {
        let request = composite_request(capability_id, hold_id, event_id, max_invocations);
        let result = commit_state_machine_command(
            store,
            config,
            event_id,
            AdmissionCommandKind::CompositeAuthorize,
            &request,
        );
        serde_json::from_str(&result.response_json).expect("authorize response")
    }

    #[test]
    fn consensus_log_serializes_two_last_unit_authorizations_to_exactly_one_winner() {
        let database_path = path("last-unit");
        let config = test_config(&database_path);
        drop(open_capture_authority(&config).expect("combined authority"));
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus");

        let first = authorized_hold(
            &store,
            &config,
            "capability-last-unit",
            "hold-last-unit-a",
            "event-last-unit-a",
            1,
        );
        let second = authorized_hold(
            &store,
            &config,
            "capability-last-unit",
            "hold-last-unit-b",
            "event-last-unit-b",
            1,
        );
        assert!(first.allowed);
        assert!(!second.allowed);
        assert_eq!(first.invocation_count_after, 1);
        assert_eq!(second.invocation_count_after, 1);
        assert_eq!(store.meta().expect("meta").commit_index, 2);
        assert_eq!(store.meta().expect("meta").last_applied, 2);

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn changed_quota_maximum_is_rejected_before_consensus_commit() {
        let database_path = path("changed-maximum-preflight");
        let config = test_config(&database_path);
        drop(open_capture_authority(&config).expect("combined authority"));
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus");
        let authorization = authorized_hold(
            &store,
            &config,
            "capability-fixed-maximum",
            "hold-fixed-maximum-a",
            "authorize-fixed-maximum-a",
            1,
        );
        assert!(authorization.allowed);
        let election = store
            .begin_election(&single_member(), "https://node-a")
            .expect("second election");
        let changed = serde_json::to_value(composite_request(
            "capability-fixed-maximum",
            "hold-fixed-maximum-b",
            "authorize-fixed-maximum-b",
            2,
        ))
        .expect("changed command");

        assert!(prepare_command(
            &config,
            AdmissionCommandKind::CompositeAuthorize,
            changed,
            &election,
        )
        .is_err());
        assert_eq!(store.meta().expect("meta").last_log_index, 1);
        assert_eq!(store.meta().expect("meta").commit_index, 1);
        assert_eq!(store.meta().expect("meta").last_applied, 1);

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn denied_composite_hold_reserves_its_hold_namespace() {
        let database_path = path("denied-hold-namespace");
        let config = test_config(&database_path);
        drop(open_capture_authority(&config).expect("combined authority"));
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus");
        let denied = authorized_hold(
            &store,
            &config,
            "capability-denied-hold",
            "hold-denied-namespace",
            "authorize-denied-namespace",
            0,
        );
        assert!(!denied.allowed);
        let election = store
            .begin_election(&single_member(), "https://node-a")
            .expect("next election");
        let reused = serde_json::to_value(composite_request(
            "capability-denied-hold",
            "hold-denied-namespace",
            "authorize-denied-namespace-reused",
            0,
        ))
        .expect("reused command");
        assert!(prepare_command(
            &config,
            AdmissionCommandKind::CompositeAuthorize,
            reused,
            &election,
        )
        .is_err());
        assert_eq!(store.meta().expect("meta").last_log_index, 1);

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn single_quota_composite_authority_fences_legacy_increment() {
        let database_path = path("single-quota-fence");
        let config = test_config(&database_path);
        drop(open_capture_authority(&config).expect("combined authority"));
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus");
        let authorization = authorized_hold(
            &store,
            &config,
            "capability-single-quota-fence",
            "hold-single-quota-fence",
            "authorize-single-quota-fence",
            3,
        );
        assert!(authorization.allowed);
        let error = SqliteBudgetStore::open(&database_path)
            .expect("budget store")
            .try_increment("capability-single-quota-fence", 0, Some(3))
            .expect_err("legacy increment must be fenced");
        assert!(error
            .to_string()
            .contains("requires composite invocation admission"));
        assert_eq!(store.meta().expect("meta").last_applied, 1);

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn committed_conflict_is_frozen_as_rejection_and_does_not_block_later_entries() {
        let database_path = path("committed-conflict");
        let config = test_config(&database_path);
        drop(open_capture_authority(&config).expect("combined authority"));
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus");
        let membership = single_member();
        let first_election = store
            .begin_election(&membership, "https://node-a")
            .expect("first election");
        let first_request = composite_request(
            "capability-conflict-a",
            "hold-committed-conflict",
            "authorize-committed-conflict-a",
            2,
        );
        let second_request = composite_request(
            "capability-conflict-b",
            "hold-committed-conflict",
            "authorize-committed-conflict-b",
            2,
        );
        let first_command = prepare_command(
            &config,
            AdmissionCommandKind::CompositeAuthorize,
            serde_json::to_value(first_request).expect("first command"),
            &first_election,
        )
        .expect("first command preparation");
        let second_command = prepare_command(
            &config,
            AdmissionCommandKind::CompositeAuthorize,
            serde_json::to_value(second_request).expect("second command"),
            &first_election,
        )
        .expect("second command preparation");
        let first_entry = AdmissionConsensusStore::build_entry(
            &first_election,
            "operation-committed-conflict-a",
            AdmissionCommandKind::CompositeAuthorize,
            &first_command,
        )
        .expect("first entry");
        store
            .append_local(&first_election, &first_entry)
            .expect("first append");
        let first_proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            index: first_entry.index,
            leader_epoch: first_entry.leader_epoch,
            current_term_commit_index: first_entry.index,
            leader_id: first_election.candidate_id.clone(),
            quorum_size: 1,
            witness_urls: vec![first_election.candidate_id.clone()],
        };
        store
            .commit_local(
                &membership,
                &first_election,
                &first_proof,
                |transaction, entry, proof| {
                    apply_admission_log_entry(&config, transaction, entry, proof)
                },
            )
            .expect("first commit");

        let second_election = store
            .begin_election(&membership, "https://node-a")
            .expect("second election");
        let second_entry = AdmissionConsensusStore::build_entry(
            &second_election,
            "operation-committed-conflict-b",
            AdmissionCommandKind::CompositeAuthorize,
            &second_command,
        )
        .expect("second entry");
        store
            .append_local(&second_election, &second_entry)
            .expect("second append");
        let second_proof = AdmissionCommitProof {
            protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
            membership_digest: membership.digest().to_string(),
            index: second_entry.index,
            leader_epoch: second_entry.leader_epoch,
            current_term_commit_index: second_entry.index,
            leader_id: second_election.candidate_id.clone(),
            quorum_size: 1,
            witness_urls: vec![second_election.candidate_id.clone()],
        };
        let rejected = store
            .commit_local(
                &membership,
                &second_election,
                &second_proof,
                |transaction, entry, proof| {
                    apply_admission_log_entry(&config, transaction, entry, proof)
                },
            )
            .expect("committed conflict result");
        assert!(rejected
            .response_json
            .contains("admissionConsensusRejection"));
        assert_eq!(store.meta().expect("meta").last_applied, 2);

        let revocation = ConsensusRevocationProposal {
            capability_id: "capability-after-conflict".to_string(),
        };
        commit_state_machine_command(
            &store,
            &config,
            "revocation:capability-after-conflict",
            AdmissionCommandKind::Revoke,
            &revocation,
        );
        assert_eq!(store.meta().expect("meta").commit_index, 3);
        assert_eq!(store.meta().expect("meta").last_applied, 3);

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn response_loss_and_exact_retry_return_the_same_persisted_result_without_reapply() {
        let database_path = path("response-loss");
        let config = test_config(&database_path);
        drop(open_capture_authority(&config).expect("combined authority"));
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus");
        let response = authorized_hold(
            &store,
            &config,
            "capability-response-loss",
            "hold-response-loss",
            "event-response-loss",
            2,
        );
        let original = store
            .result_for_operation("event-response-loss")
            .expect("result")
            .expect("persisted result");
        drop(store);

        let reopened = AdmissionConsensusStore::open(&database_path).expect("reopen");
        let applied = AtomicUsize::new(0);
        reopened
            .apply_committed(&mut |_, _, _| {
                applied.fetch_add(1, Ordering::SeqCst);
                Ok("{\"wrong\":true}".to_string())
            })
            .expect("replay committed");
        assert_eq!(applied.load(Ordering::SeqCst), 0);
        let retry = reopened
            .result_for_operation("event-response-loss")
            .expect("retry result")
            .expect("retry persisted result");
        assert_eq!(retry, original);
        assert_eq!(
            serde_json::from_str::<CompositeBudgetAuthorizeResponse>(&retry.response_json)
                .expect("retry response")
                .allowed,
            response.allowed
        );
        let existing = reopened
            .snapshot()
            .expect("snapshot")
            .entries
            .into_iter()
            .next()
            .expect("entry");
        let changed = serde_json::to_value(composite_request(
            "capability-response-loss",
            "hold-response-loss",
            "event-response-loss",
            3,
        ))
        .expect("changed request");
        assert!(ensure_operation_command_matches(
            &existing,
            AdmissionCommandKind::CompositeAuthorize,
            &changed,
        )
        .is_err());

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn mismatched_capture_authority_is_rejected_before_log_append() {
        let database_path = path("capture-preflight");
        let config = test_config(&database_path);
        drop(open_capture_authority(&config).expect("combined authority"));
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus");
        let authorization = authorized_hold(
            &store,
            &config,
            "capability-capture-preflight",
            "hold-capture-preflight",
            "authorize-capture-preflight",
            1,
        );
        let election = store
            .begin_election(&single_member(), "https://node-a")
            .expect("capture election");
        let mut authority = authorization
            .budget_authority
            .as_ref()
            .expect("persisted authority")
            .clone();
        authority.lease_epoch = authority
            .lease_epoch
            .checked_add(1)
            .expect("test lease epoch");
        let request = CaptureInvocationReservationsRequest {
            capability_id: authorization.capability_id,
            grant_index: authorization.grant_index,
            hold_id: authorization.hold_id,
            event_id: "capture-preflight".to_string(),
            budget_authority: Some(BudgetMutationAuthorityView {
                authority_id: authority.authority_id,
                lease_id: authority.lease_id,
                lease_epoch: authority.lease_epoch,
            }),
        };
        let command = serde_json::to_value(request).expect("capture command");

        assert!(prepare_command(
            &config,
            AdmissionCommandKind::CaptureInvocations,
            command,
            &election,
        )
        .is_err());
        assert_eq!(store.meta().expect("meta").last_log_index, 1);
        assert_eq!(store.meta().expect("meta").commit_index, 1);

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn revocation_replay_after_projection_gap_is_result_stable() {
        let database_path = path("revocation-replay");
        let config = test_config(&database_path);
        drop(open_capture_authority(&config).expect("combined authority"));
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus");
        let command = ConsensusRevocationProposal {
            capability_id: "capability-replay".to_string(),
        };
        let original = commit_state_machine_command(
            &store,
            &config,
            "revocation:capability-replay",
            AdmissionCommandKind::Revoke,
            &command,
        );
        drop(store);
        let connection = Connection::open(&database_path).expect("database");
        connection
            .execute("DELETE FROM admission_consensus_results", [])
            .expect("delete result");
        connection
            .execute(
                r#"
                UPDATE admission_consensus_meta
                SET last_applied = 0, applied_state_digest = ?1
                WHERE singleton = 1
                "#,
                params![initial_applied_state_digest()],
            )
            .expect("rewind projection");
        drop(connection);

        let reopened = AdmissionConsensusStore::open(&database_path).expect("reopen");
        reopened
            .apply_committed(&mut |transaction, entry, proof| {
                apply_admission_log_entry(&config, transaction, entry, proof)
            })
            .expect("replay");
        let replayed = reopened
            .result_for_operation("revocation:capability-replay")
            .expect("result")
            .expect("replayed result");
        assert_eq!(replayed.response_json, original.response_json);

        let _ = std::fs::remove_file(database_path);
    }

    #[test]
    fn legacy_budget_ack_cannot_commit_an_admission_entry() {
        let database_path = path("legacy-ack");
        let store = AdmissionConsensusStore::open(&database_path).expect("consensus");
        let election = AdmissionElection {
            term: 4,
            candidate_id: "https://node-a".to_string(),
            last_log_index: 0,
            last_log_term: 0,
            commit_index: 0,
        };
        let entry = entry(&election, "operation-legacy-ack");
        store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: election.term,
                    leader_id: election.candidate_id.clone(),
                    previous_log_index: 0,
                    previous_log_term: 0,
                    entry: Some(entry.clone()),
                    leader_commit: 0,
                    commit_proof: None,
                },
                |_, _, _| Ok("{\"ok\":true}".to_string()),
            )
            .expect("append");
        let applied = AtomicUsize::new(0);
        let rejected = store
            .append_entries(
                &membership(),
                &AdmissionAppendEntriesRequest {
                    protocol_version: ADMISSION_CONSENSUS_PROTOCOL_VERSION.to_string(),
                    membership_digest: membership().digest().to_string(),
                    term: election.term,
                    leader_id: election.candidate_id.clone(),
                    previous_log_index: entry.index,
                    previous_log_term: entry.leader_epoch,
                    entry: None,
                    leader_commit: entry.index,
                    commit_proof: Some(AdmissionCommitProof {
                        protocol_version: "ha_quorum_commit".to_string(),
                        membership_digest: membership().digest().to_string(),
                        index: entry.index,
                        leader_epoch: entry.leader_epoch,
                        current_term_commit_index: entry.index,
                        leader_id: election.candidate_id,
                        quorum_size: 2,
                        witness_urls: vec![
                            "https://node-a".to_string(),
                            "https://node-b".to_string(),
                        ],
                    }),
                },
                |_, _, _| {
                    applied.fetch_add(1, Ordering::SeqCst);
                    Ok("{\"ok\":true}".to_string())
                },
            )
            .expect("legacy commit response");
        assert!(!rejected.accepted);
        assert_eq!(store.meta().expect("meta").commit_index, 0);
        assert_eq!(applied.load(Ordering::SeqCst), 0);

        let _ = std::fs::remove_file(database_path);
    }

    fn combined_request(
        authorization: &CompositeBudgetAuthorizeResponse,
        operation_id: &str,
        event_id: &str,
    ) -> CombinedAdmissionCaptureRequest {
        let authority = authorization
            .budget_authority
            .as_ref()
            .expect("authorize authority");
        CombinedAdmissionCaptureRequest {
            operation_id: operation_id.to_string(),
            capability_id: authorization.capability_id.clone(),
            grant_index: authorization.grant_index,
            hold_id: authorization.hold_id.clone(),
            event_id: event_id.to_string(),
            budget_authority: Some(BudgetMutationAuthorityView {
                authority_id: authority.authority_id.clone(),
                lease_id: authority.lease_id.clone(),
                lease_epoch: authority.lease_epoch,
            }),
            revocation_set: authorization.admission_evidence.revocation_set.clone(),
            bound_revocation_set_digest: authorization
                .admission_evidence
                .revocation_set
                .digest
                .clone(),
            authorization_artifact_digests: authorization
                .admission_evidence
                .supplemental_binding
                .as_ref()
                .map(|binding| vec![binding.artifact_digest.clone()])
                .unwrap_or_default(),
            last_observed_revocation_index: Some(0),
        }
    }

    #[test]
    fn revocation_and_combined_capture_have_one_consensus_order() {
        let revoked_first_path = path("revoked-first");
        let revoked_first_config = test_config(&revoked_first_path);
        drop(open_capture_authority(&revoked_first_config).expect("authority"));
        let revoked_first_store =
            AdmissionConsensusStore::open(&revoked_first_path).expect("consensus");
        let authorization = authorized_hold(
            &revoked_first_store,
            &revoked_first_config,
            "capability-revoked-first",
            "hold-revoked-first",
            "authorize-revoked-first",
            1,
        );
        let revocation = ConsensusRevocationProposal {
            capability_id: authorization.capability_id.clone(),
        };
        commit_state_machine_command(
            &revoked_first_store,
            &revoked_first_config,
            "revocation:capability-revoked-first",
            AdmissionCommandKind::Revoke,
            &revocation,
        );
        let request = combined_request(
            &authorization,
            "operation-revoked-first",
            "capture-revoked-first",
        );
        let denied = commit_state_machine_command(
            &revoked_first_store,
            &revoked_first_config,
            "operation-revoked-first",
            AdmissionCommandKind::CombinedCapture,
            &request,
        );
        let denied: CombinedAdmissionCaptureResponse =
            serde_json::from_str(&denied.response_json).expect("denied response");
        assert_eq!(denied.outcome, AdmissionCaptureOutcomeView::DeniedRevoked);
        assert!(denied.budget.is_none());
        assert_eq!(
            denied.revoked_capability_ids,
            vec!["capability-revoked-first".to_string()]
        );

        let captured_first_path = path("captured-first");
        let captured_first_config = test_config(&captured_first_path);
        drop(open_capture_authority(&captured_first_config).expect("authority"));
        let captured_first_store =
            AdmissionConsensusStore::open(&captured_first_path).expect("consensus");
        let authorization = authorized_hold(
            &captured_first_store,
            &captured_first_config,
            "capability-captured-first",
            "hold-captured-first",
            "authorize-captured-first",
            1,
        );
        let request = combined_request(
            &authorization,
            "operation-captured-first",
            "capture-captured-first",
        );
        let captured = commit_state_machine_command(
            &captured_first_store,
            &captured_first_config,
            "operation-captured-first",
            AdmissionCommandKind::CombinedCapture,
            &request,
        );
        let captured_response: CombinedAdmissionCaptureResponse =
            serde_json::from_str(&captured.response_json).expect("captured response");
        assert_eq!(
            captured_response.outcome,
            AdmissionCaptureOutcomeView::Captured
        );
        assert_eq!(
            captured_response
                .budget
                .as_ref()
                .expect("captured budget")
                .invocation_count_after,
            1
        );
        let revocation = ConsensusRevocationProposal {
            capability_id: authorization.capability_id.clone(),
        };
        commit_state_machine_command(
            &captured_first_store,
            &captured_first_config,
            "revocation:capability-captured-first",
            AdmissionCommandKind::Revoke,
            &revocation,
        );
        let reopened = AdmissionConsensusStore::open(&captured_first_path).expect("reopen");
        assert_eq!(
            reopened
                .result_for_operation("operation-captured-first")
                .expect("retry result")
                .expect("persisted retry"),
            captured
        );
        let budget_store = SqliteBudgetStore::open(&captured_first_path).expect("budget store");
        assert_eq!(
            budget_store
                .get_usage("capability-captured-first", 0)
                .expect("usage")
                .expect("usage row")
                .invocation_count,
            1
        );

        let _ = std::fs::remove_file(revoked_first_path);
        let _ = std::fs::remove_file(captured_first_path);
    }
}

use std::sync::{Arc, Mutex, MutexGuard};

use chio_core::canonical::canonical_json_bytes;
use chio_core::{sha256_hex, StoreMutationFence};
use chio_fiscal::{
    FiscalAuthorityState, FiscalCharterRegistry, FiscalGenesisPolicy, FiscalProposalAdmissionState,
    FiscalProposalAdmissionStatus, VerifiedFiscalActivation, VerifiedFiscalApproval,
    VerifiedFiscalCharter, VerifiedFiscalContinuityAdvance, VerifiedFiscalContinuityCheckpoint,
    VerifiedFiscalProposal, VerifiedFiscalRuntimeReadiness, VerifiedFiscalSchedule,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::Serialize;

use crate::serving_owner::{SqliteServingOwner, SqliteServingOwnerError};

const FISCAL_STORE_SCHEMA_KEY: &str = "fiscal";
pub(crate) const FISCAL_STORE_SUPPORTED_SCHEMA_VERSION: i32 = 2;
const FISCAL_STORE_SCHEMA: &str = include_str!("fiscal_store.sql");
const FISCAL_GENESIS_PROJECTION_KEY: &str = "authority";
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, thiserror::Error)]
pub enum FiscalStoreError {
    #[error("fiscal store is unavailable: {0}")]
    Unavailable(String),
    #[error("fiscal store mutation was fenced")]
    Fenced,
    #[error("fiscal store record was not found")]
    NotFound,
    #[error("fiscal store record conflicts with retained state")]
    Conflict,
    #[error("fiscal store invariant failed: {0}")]
    Invariant(String),
    #[error("fiscal store durable outcome is unknown: {0}")]
    OutcomeUnknown(String),
    #[error(transparent)]
    Fiscal(#[from] chio_fiscal::FiscalError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FiscalStageStatus {
    DbStaged,
    FiscalAnchorAdvanced,
    DbFinalized,
    Discarded,
}

impl FiscalStageStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DbStaged => "db_staged",
            Self::FiscalAnchorAdvanced => "fiscal_anchor_advanced",
            Self::DbFinalized => "db_finalized",
            Self::Discarded => "discarded",
        }
    }

    fn parse(value: &str) -> Result<Self, FiscalStoreError> {
        match value {
            "db_staged" => Ok(Self::DbStaged),
            "fiscal_anchor_advanced" => Ok(Self::FiscalAnchorAdvanced),
            "db_finalized" => Ok(Self::DbFinalized),
            "discarded" => Ok(Self::Discarded),
            _ => Err(invariant("fiscal stage status is invalid")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiscalStagedTransitionRecord {
    pub transition_id: String,
    pub current_checkpoint_digest: String,
    pub next_checkpoint_digest: String,
    pub proof_json: Vec<u8>,
    pub status: FiscalStageStatus,
    pub stage_version: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FiscalProjectionCommit<'a> {
    format: &'static str,
    projection_key: &'a str,
    projection_sequence: u64,
    mutation_kind: &'a str,
    snapshot_digest: &'a str,
    previous_commit_digest: &'a str,
    store_uuid: &'a str,
    store_lease_id: &'a str,
    store_owner_epoch: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FiscalGenesisSnapshot<'a> {
    policy: &'a FiscalGenesisPolicy,
    authority: &'a FiscalAuthorityState,
    charter_digest: &'a str,
    readiness_digest: &'a str,
    checkpoint_digest: &'a str,
}

#[derive(Clone)]
pub struct SqliteFiscalStore {
    connection: Arc<Mutex<Connection>>,
    serving_owner: Arc<SqliteServingOwner>,
}

impl SqliteFiscalStore {
    pub(crate) fn open_alongside(
        connection: Arc<Mutex<Connection>>,
        serving_owner: Arc<SqliteServingOwner>,
    ) -> Self {
        Self {
            connection,
            serving_owner,
        }
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, FiscalStoreError> {
        self.connection
            .lock()
            .map_err(|_| invariant("fiscal store lock is poisoned"))
    }

    fn begin_read<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<Transaction<'a>, FiscalStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        verify_owner(&transaction, &self.serving_owner, None)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(map_owner_error)?;
        verify_fiscal_sql_invariants(&transaction)?;
        Ok(transaction)
    }

    fn begin_write<'a>(
        &self,
        connection: &'a mut Connection,
        fence: &StoreMutationFence,
    ) -> Result<Transaction<'a>, FiscalStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        verify_owner(&transaction, &self.serving_owner, Some(fence))?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(map_owner_error)?;
        verify_fiscal_sql_invariants(&transaction)?;
        Ok(transaction)
    }

    fn commit_write(&self, transaction: Transaction<'_>) -> Result<(), FiscalStoreError> {
        transaction.commit().map_err(|error| {
            map_owner_error(self.serving_owner.outcome_unknown(format!(
                "sqlite fiscal store commit outcome is unknown: {error}"
            )))
        })
    }

    fn sync_after_write(&self, connection: &Connection) -> Result<(), FiscalStoreError> {
        self.serving_owner
            .sync_authority_anchor(connection)
            .map_err(map_owner_error)
    }

    pub fn initialize_genesis(
        &self,
        policy: &FiscalGenesisPolicy,
        authority: &FiscalAuthorityState,
        charter: &VerifiedFiscalCharter,
        readiness: &VerifiedFiscalRuntimeReadiness,
        checkpoint: &VerifiedFiscalContinuityCheckpoint,
        fence: &StoreMutationFence,
    ) -> Result<(), FiscalStoreError> {
        policy.validate(charter)?;
        authority.validate()?;
        if checkpoint.body().continuity_sequence != 0
            || authority.finalized_checkpoint_digest != checkpoint.digest()
            || authority.genesis_policy_id != policy.policy_id
            || authority.genesis_policy_digest != policy.digest()?
            || authority.current_charter_id != charter.body().charter_id
            || authority.current_charter_digest != charter.digest()
            || checkpoint.body().runtime_readiness_digest != readiness.digest()
        {
            return Err(invariant("fiscal genesis bindings do not match"));
        }
        let policy_json = canonical_json_bytes(policy).map_err(canonical_error)?;
        let authority_json = canonical_json_bytes(authority).map_err(canonical_error)?;
        let charter_json = charter.canonical_bytes()?;
        let readiness_json = readiness.canonical_bytes()?;
        let registry_json = readiness.runtime_registry().canonical_bytes()?;
        let checkpoint_json = checkpoint.canonical_bytes()?;
        let snapshot_digest = canonical_digest(&FiscalGenesisSnapshot {
            policy,
            authority,
            charter_digest: charter.digest(),
            readiness_digest: readiness.digest(),
            checkpoint_digest: checkpoint.digest(),
        })?;

        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        if transaction
            .query_row(
                "SELECT state_json FROM fiscal_authority_state WHERE singleton = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(sqlite_error)?
            .is_some()
        {
            verify_exact_genesis(
                &transaction,
                &policy_json,
                &authority_json,
                &charter_json,
                &readiness_json,
                &registry_json,
                &checkpoint_json,
                policy,
                charter,
                readiness,
                checkpoint,
            )?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        }

        transaction
            .execute(
                "INSERT INTO fiscal_genesis_policies (policy_id, policy_digest, policy_json) VALUES (?1, ?2, ?3)",
                params![&policy.policy_id, policy.digest()?, &policy_json],
            )
            .map_err(sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO fiscal_charters (charter_id, charter_digest, charter_sequence, lifecycle_state, signed_json) VALUES (?1, ?2, ?3, 'pinned', ?4)",
                params![
                    &charter.body().charter_id,
                    charter.digest(),
                    sqlite_i64(charter.body().sequence, "charter sequence")?,
                    &charter_json,
                ],
            )
            .map_err(sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO fiscal_runtime_readiness (readiness_id, readiness_digest, readiness_sequence, registry_json, signed_json) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    &readiness.body().readiness_id,
                    readiness.digest(),
                    sqlite_i64(readiness.body().readiness_sequence, "readiness sequence")?,
                    &registry_json,
                    &readiness_json,
                ],
            )
            .map_err(sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO fiscal_continuity_checkpoints (checkpoint_digest, continuity_sequence, status, signed_json) VALUES (?1, 0, 'finalized', ?2)",
                params![checkpoint.digest(), &checkpoint_json],
            )
            .map_err(sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO fiscal_authority_state (singleton, state_json, finalized_checkpoint_digest, state_version) VALUES (1, ?1, ?2, 1)",
                params![&authority_json, checkpoint.digest()],
            )
            .map_err(sqlite_error)?;
        append_projection_commit(
            &transaction,
            &self.serving_owner,
            FISCAL_GENESIS_PROJECTION_KEY,
            1,
            "initialize_genesis",
            &snapshot_digest,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)
    }

    pub fn persist_proposal(
        &self,
        proposal: &VerifiedFiscalProposal,
        fence: &StoreMutationFence,
    ) -> Result<(), FiscalStoreError> {
        let json = canonical_json_bytes(proposal.signed()).map_err(canonical_error)?;
        self.persist_immutable_artifact(
            "fiscal_proposals",
            "proposal_id",
            &proposal.body().proposal_id,
            "proposal_digest",
            proposal.digest(),
            &json,
            "persist_proposal",
            fence,
        )
    }

    pub fn persist_charter(
        &self,
        charter: &VerifiedFiscalCharter,
        fence: &StoreMutationFence,
    ) -> Result<(), FiscalStoreError> {
        let json = charter.canonical_bytes()?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        if let Some((digest, stored)) = transaction
            .query_row(
                "SELECT charter_digest, signed_json FROM fiscal_charters WHERE charter_id = ?1",
                [&charter.body().charter_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?
        {
            if digest != charter.digest() || stored != json {
                return Err(FiscalStoreError::Conflict);
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        }
        transaction
            .execute(
                "INSERT INTO fiscal_charters (charter_id, charter_digest, charter_sequence, lifecycle_state, signed_json) VALUES (?1, ?2, ?3, 'proposed', ?4)",
                params![
                    &charter.body().charter_id,
                    charter.digest(),
                    sqlite_i64(charter.body().sequence, "charter sequence")?,
                    &json,
                ],
            )
            .map_err(sqlite_error)?;
        let projection_key = format!("charter:{}", charter.body().charter_id);
        append_projection_commit(
            &transaction,
            &self.serving_owner,
            &projection_key,
            1,
            "persist_fiscal_charter",
            charter.digest(),
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)
    }

    pub fn persist_schedule(
        &self,
        schedule: &VerifiedFiscalSchedule,
        fence: &StoreMutationFence,
    ) -> Result<(), FiscalStoreError> {
        let json = schedule.canonical_bytes()?;
        let digest = sha256_hex(&json);
        let domain_json = String::from_utf8(
            canonical_json_bytes(&schedule.body().domain).map_err(canonical_error)?,
        )
        .map_err(|error| invariant(format!("fiscal domain encoding is not UTF-8: {error}")))?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        if let Some((stored_digest, stored)) = transaction
            .query_row(
                "SELECT schedule_digest, signed_json FROM fiscal_schedules WHERE schedule_id = ?1",
                [&schedule.body().schedule_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?
        {
            if stored_digest != digest || stored != json {
                return Err(FiscalStoreError::Conflict);
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        }
        transaction
            .execute(
                "INSERT INTO fiscal_schedules (schedule_id, schedule_digest, domain_json, schedule_sequence, lifecycle_state, signed_json) VALUES (?1, ?2, ?3, ?4, 'staged', ?5)",
                params![
                    &schedule.body().schedule_id,
                    &digest,
                    &domain_json,
                    sqlite_i64(schedule.body().sequence, "schedule sequence")?,
                    &json,
                ],
            )
            .map_err(sqlite_error)?;
        let projection_key = format!("schedule:{}", schedule.body().schedule_id);
        append_projection_commit(
            &transaction,
            &self.serving_owner,
            &projection_key,
            1,
            "persist_fiscal_schedule",
            &digest,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)
    }

    pub fn persist_runtime_readiness(
        &self,
        readiness: &VerifiedFiscalRuntimeReadiness,
        fence: &StoreMutationFence,
    ) -> Result<(), FiscalStoreError> {
        let signed_json = readiness.canonical_bytes()?;
        let registry_json = readiness.runtime_registry().canonical_bytes()?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        if let Some((digest, stored_registry, stored_signed)) = transaction
            .query_row(
                "SELECT readiness_digest, registry_json, signed_json FROM fiscal_runtime_readiness WHERE readiness_id = ?1",
                [&readiness.body().readiness_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?
        {
            if digest != readiness.digest()
                || stored_registry != registry_json
                || stored_signed != signed_json
            {
                return Err(FiscalStoreError::Conflict);
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        }
        transaction
            .execute(
                "INSERT INTO fiscal_runtime_readiness (readiness_id, readiness_digest, readiness_sequence, registry_json, signed_json) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    &readiness.body().readiness_id,
                    readiness.digest(),
                    sqlite_i64(readiness.body().readiness_sequence, "readiness sequence")?,
                    &registry_json,
                    &signed_json,
                ],
            )
            .map_err(sqlite_error)?;
        let projection_key = format!("readiness:{}", readiness.body().readiness_id);
        append_projection_commit(
            &transaction,
            &self.serving_owner,
            &projection_key,
            1,
            "persist_fiscal_readiness",
            readiness.digest(),
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)
    }

    pub fn persist_approval(
        &self,
        approval: &VerifiedFiscalApproval,
        fence: &StoreMutationFence,
    ) -> Result<(), FiscalStoreError> {
        let json = canonical_json_bytes(approval.signed()).map_err(canonical_error)?;
        self.persist_immutable_artifact(
            "fiscal_approvals",
            "approval_id",
            &approval.body().approval_id,
            "approval_digest",
            approval.digest(),
            &json,
            "persist_approval",
            fence,
        )
    }

    pub fn persist_activation(
        &self,
        activation: &VerifiedFiscalActivation,
        fence: &StoreMutationFence,
    ) -> Result<(), FiscalStoreError> {
        let json = canonical_json_bytes(activation.signed()).map_err(canonical_error)?;
        self.persist_immutable_artifact(
            "fiscal_activations",
            "activation_id",
            &activation.body().activation_id,
            "activation_digest",
            activation.digest(),
            &json,
            "persist_activation",
            fence,
        )
    }

    pub fn bind_legacy_fee_schedule(
        &self,
        legacy_schedule_id: &str,
        schedule: &VerifiedFiscalSchedule,
        fence: &StoreMutationFence,
    ) -> Result<(), FiscalStoreError> {
        if legacy_schedule_id.is_empty() {
            return Err(invariant("legacy fee schedule id is empty"));
        }
        let schedule_json = schedule.canonical_bytes()?;
        let schedule_digest = sha256_hex(&schedule_json);
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        let retained = transaction
            .query_row(
                "SELECT fiscal_schedule_id, fiscal_schedule_digest FROM fiscal_legacy_fee_schedule_bindings WHERE legacy_schedule_id = ?1",
                [legacy_schedule_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        if let Some((schedule_id, digest)) = retained {
            if schedule_id != schedule.body().schedule_id || digest != schedule_digest {
                return Err(FiscalStoreError::Conflict);
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        }
        let exact_schedule = transaction
            .query_row(
                "SELECT schedule_digest = ?1 AND signed_json = ?2 FROM fiscal_schedules WHERE schedule_id = ?3",
                params![&schedule_digest, &schedule_json, &schedule.body().schedule_id],
                |row| row.get::<_, bool>(0),
            )
            .optional()
            .map_err(sqlite_error)?
            .unwrap_or(false);
        if !exact_schedule {
            return Err(FiscalStoreError::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO fiscal_legacy_fee_schedule_bindings (legacy_schedule_id, fiscal_schedule_id, fiscal_schedule_digest) VALUES (?1, ?2, ?3)",
                params![legacy_schedule_id, &schedule.body().schedule_id, &schedule_digest],
            )
            .map_err(sqlite_error)?;
        let projection_key = format!("legacy-fee:{legacy_schedule_id}");
        append_projection_commit(
            &transaction,
            &self.serving_owner,
            &projection_key,
            1,
            "bind_legacy_fee_schedule",
            &schedule_digest,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_immutable_artifact(
        &self,
        table: &str,
        id_column: &str,
        id: &str,
        digest_column: &str,
        digest: &str,
        json: &[u8],
        mutation_kind: &str,
        fence: &StoreMutationFence,
    ) -> Result<(), FiscalStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        let sql =
            format!("SELECT {digest_column}, signed_json FROM {table} WHERE {id_column} = ?1");
        if let Some((stored_digest, stored_json)) = transaction
            .query_row(&sql, [id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .optional()
            .map_err(sqlite_error)?
        {
            if stored_digest != digest || stored_json != json {
                return Err(FiscalStoreError::Conflict);
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        }
        let insert = format!(
            "INSERT INTO {table} ({id_column}, {digest_column}, signed_json) VALUES (?1, ?2, ?3)"
        );
        transaction
            .execute(&insert, params![id, digest, json])
            .map_err(sqlite_error)?;
        let projection_key = format!("artifact:{id}");
        append_projection_commit(
            &transaction,
            &self.serving_owner,
            &projection_key,
            1,
            mutation_kind,
            digest,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)
    }

    pub fn persist_admission_state(
        &self,
        state: &FiscalProposalAdmissionState,
        expected_version: Option<u64>,
        fence: &StoreMutationFence,
    ) -> Result<(), FiscalStoreError> {
        let state_json = canonical_json_bytes(state).map_err(canonical_error)?;
        let id = &state.signed_admission.body.admission_id;
        let status = match state.status {
            FiscalProposalAdmissionStatus::Admitted => "admitted",
            FiscalProposalAdmissionStatus::Activated => "activated",
        };
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        let changed = match expected_version {
            None => transaction.execute(
                "INSERT INTO fiscal_proposal_admissions (admission_id, admission_digest, admitted_at, status, state_version, state_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    id,
                    &state.admission_digest,
                    sqlite_i64(state.signed_admission.body.admitted_at, "admitted_at")?,
                    status,
                    sqlite_i64(state.version, "admission state version")?,
                    &state_json,
                ],
            ),
            Some(version) => transaction.execute(
                "UPDATE fiscal_proposal_admissions SET status = ?1, state_version = ?2, state_json = ?3 WHERE admission_id = ?4 AND admission_digest = ?5 AND state_version = ?6",
                params![
                    status,
                    sqlite_i64(state.version, "admission state version")?,
                    &state_json,
                    id,
                    &state.admission_digest,
                    sqlite_i64(version, "expected admission state version")?,
                ],
            ),
        }
        .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(FiscalStoreError::Conflict);
        }
        let projection_key = format!("admission:{id}");
        append_projection_commit(
            &transaction,
            &self.serving_owner,
            &projection_key,
            state.version,
            "persist_admission_state",
            &sha256_hex(&state_json),
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)
    }

    pub fn stage_advance(
        &self,
        advance: &VerifiedFiscalContinuityAdvance,
        next_authority: &FiscalAuthorityState,
        fence: &StoreMutationFence,
    ) -> Result<FiscalStagedTransitionRecord, FiscalStoreError> {
        next_authority.validate()?;
        if next_authority.finalized_checkpoint_digest != advance.next().digest() {
            return Err(invariant("staged authority does not match next checkpoint"));
        }
        let transition_id = advance
            .next()
            .body()
            .staged_transition
            .as_ref()
            .map(|transition| transition.transition_id.clone())
            .unwrap_or_else(|| sha256_hex(advance.canonical_proof_bytes()));
        let record = FiscalStagedTransitionRecord {
            transition_id,
            current_checkpoint_digest: advance.current().digest().to_owned(),
            next_checkpoint_digest: advance.next().digest().to_owned(),
            proof_json: advance.canonical_proof_bytes().to_vec(),
            status: FiscalStageStatus::DbStaged,
            stage_version: 1,
        };
        let checkpoint_json = advance.next().canonical_bytes()?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        match load_transition(&transaction, &record.transition_id) {
            Ok(existing) => {
                let stored_checkpoint = transaction
                    .query_row(
                        "SELECT signed_json FROM fiscal_continuity_checkpoints WHERE checkpoint_digest = ?1",
                        [&record.next_checkpoint_digest],
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .optional()
                    .map_err(sqlite_error)?;
                if existing.current_checkpoint_digest != record.current_checkpoint_digest
                    || existing.next_checkpoint_digest != record.next_checkpoint_digest
                    || existing.proof_json != record.proof_json
                    || stored_checkpoint.as_deref() != Some(checkpoint_json.as_slice())
                {
                    return Err(FiscalStoreError::Conflict);
                }
                transaction.commit().map_err(sqlite_error)?;
                return Ok(existing);
            }
            Err(FiscalStoreError::NotFound) => {}
            Err(error) => return Err(error),
        }
        let current: String = transaction
            .query_row(
                "SELECT finalized_checkpoint_digest FROM fiscal_authority_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?
            .ok_or(FiscalStoreError::NotFound)?;
        if current != record.current_checkpoint_digest {
            return Err(FiscalStoreError::Conflict);
        }
        let readiness_present = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM fiscal_runtime_readiness WHERE readiness_digest = ?1)",
                [&advance.next().body().runtime_readiness_digest],
                |row| row.get::<_, bool>(0),
            )
            .map_err(sqlite_error)?;
        let charter_present = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM fiscal_charters WHERE charter_id = ?1 AND charter_digest = ?2)",
                params![
                    &advance.next().body().pinned_charter_id,
                    &advance.next().body().pinned_charter_digest,
                ],
                |row| row.get::<_, bool>(0),
            )
            .map_err(sqlite_error)?;
        if !readiness_present || !charter_present {
            return Err(invariant(
                "staged fiscal checkpoint references an unavailable charter or readiness record",
            ));
        }
        for head in advance
            .next()
            .body()
            .domains
            .iter()
            .flat_map(|state| [state.active.as_ref(), state.last_known_good.as_ref()])
            .flatten()
        {
            let present = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM fiscal_schedules WHERE schedule_id = ?1 AND schedule_digest = ?2 AND schedule_sequence = ?3)",
                    params![
                        &head.schedule_id,
                        &head.schedule_digest,
                        sqlite_i64(head.sequence, "schedule head sequence")?,
                    ],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(sqlite_error)?;
            if !present {
                return Err(invariant(
                    "staged fiscal checkpoint references an unavailable schedule",
                ));
            }
        }
        transaction
            .execute(
                "INSERT INTO fiscal_continuity_checkpoints (checkpoint_digest, continuity_sequence, status, signed_json) VALUES (?1, ?2, 'staged', ?3)",
                params![
                    &record.next_checkpoint_digest,
                    sqlite_i64(advance.next().body().continuity_sequence, "continuity sequence")?,
                    &checkpoint_json,
                ],
            )
            .map_err(sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO fiscal_staged_transitions (transition_id, current_checkpoint_digest, next_checkpoint_digest, proof_json, status, stage_version) VALUES (?1, ?2, ?3, ?4, ?5, 1)",
                params![
                    &record.transition_id,
                    &record.current_checkpoint_digest,
                    &record.next_checkpoint_digest,
                    &record.proof_json,
                    record.status.as_str(),
                ],
            )
            .map_err(sqlite_error)?;
        let projection_key = format!("transition:{}", record.transition_id);
        append_projection_commit(
            &transaction,
            &self.serving_owner,
            &projection_key,
            1,
            "stage_fiscal_advance",
            &sha256_hex(&record.proof_json),
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(record)
    }

    pub fn mark_anchor_advanced(
        &self,
        transition_id: &str,
        acknowledged: &VerifiedFiscalContinuityCheckpoint,
        fence: &StoreMutationFence,
    ) -> Result<FiscalStagedTransitionRecord, FiscalStoreError> {
        self.transition_status_update(
            transition_id,
            FiscalStageStatus::DbStaged,
            FiscalStageStatus::FiscalAnchorAdvanced,
            Some(acknowledged),
            fence,
        )
    }

    pub fn discard_unanchored_stage(
        &self,
        transition_id: &str,
        fence: &StoreMutationFence,
    ) -> Result<FiscalStagedTransitionRecord, FiscalStoreError> {
        self.transition_status_update(
            transition_id,
            FiscalStageStatus::DbStaged,
            FiscalStageStatus::Discarded,
            None,
            fence,
        )
    }

    pub fn finalize_advance(
        &self,
        transition_id: &str,
        acknowledged: &VerifiedFiscalContinuityCheckpoint,
        authority: &FiscalAuthorityState,
        fence: &StoreMutationFence,
    ) -> Result<FiscalStagedTransitionRecord, FiscalStoreError> {
        authority.validate()?;
        if authority.finalized_checkpoint_digest != acknowledged.digest() {
            return Err(invariant(
                "finalized authority does not match anchor acknowledgement",
            ));
        }
        let acknowledged_json = acknowledged.canonical_bytes()?;
        let authority_json = canonical_json_bytes(authority).map_err(canonical_error)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        let mut record = load_transition(&transaction, transition_id)?;
        verify_acknowledgement(&transaction, &record, acknowledged, &acknowledged_json)?;
        if record.status == FiscalStageStatus::DbFinalized {
            let stored: Vec<u8> = transaction
                .query_row(
                    "SELECT state_json FROM fiscal_authority_state WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            if stored != authority_json {
                return Err(FiscalStoreError::Conflict);
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(record);
        }
        if record.status != FiscalStageStatus::FiscalAnchorAdvanced {
            return Err(FiscalStoreError::Conflict);
        }
        let next_version = record
            .stage_version
            .checked_add(1)
            .ok_or_else(|| invariant("fiscal stage version overflowed"))?;
        let updated = transaction
            .execute(
                "UPDATE fiscal_staged_transitions SET status = 'db_finalized', stage_version = ?1 WHERE transition_id = ?2 AND status = 'fiscal_anchor_advanced' AND stage_version = ?3",
                params![
                    sqlite_i64(next_version, "fiscal stage version")?,
                    transition_id,
                    sqlite_i64(record.stage_version, "fiscal stage version")?,
                ],
            )
            .map_err(sqlite_error)?;
        let checkpoint_updated = transaction
            .execute(
                "UPDATE fiscal_continuity_checkpoints SET status = 'finalized' WHERE checkpoint_digest = ?1 AND status = 'staged' AND signed_json = ?2",
                params![acknowledged.digest(), &acknowledged_json],
            )
            .map_err(sqlite_error)?;
        let authority_updated = transaction
            .execute(
                "UPDATE fiscal_authority_state SET state_json = ?1, finalized_checkpoint_digest = ?2, state_version = state_version + 1 WHERE singleton = 1 AND finalized_checkpoint_digest = ?3",
                params![
                    &authority_json,
                    acknowledged.digest(),
                    &record.current_checkpoint_digest,
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 || checkpoint_updated != 1 || authority_updated != 1 {
            return Err(FiscalStoreError::Conflict);
        }
        record.status = FiscalStageStatus::DbFinalized;
        record.stage_version = next_version;
        let projection_key = format!("transition:{transition_id}");
        append_projection_commit(
            &transaction,
            &self.serving_owner,
            &projection_key,
            next_version,
            "finalize_fiscal_advance",
            acknowledged.digest(),
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(record)
    }

    pub fn load_authority_state(&self) -> Result<FiscalAuthorityState, FiscalStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let json = transaction
            .query_row(
                "SELECT state_json FROM fiscal_authority_state WHERE singleton = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(sqlite_error)?
            .ok_or(FiscalStoreError::NotFound)?;
        let state: FiscalAuthorityState = serde_json::from_slice(&json)
            .map_err(|error| invariant(format!("stored fiscal authority is invalid: {error}")))?;
        state.validate()?;
        if canonical_json_bytes(&state).map_err(canonical_error)? != json {
            return Err(invariant("stored fiscal authority is not canonical"));
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(state)
    }

    pub fn load_transition(
        &self,
        transition_id: &str,
    ) -> Result<FiscalStagedTransitionRecord, FiscalStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let record = load_transition(&transaction, transition_id)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(record)
    }

    pub fn load_open_transition(
        &self,
    ) -> Result<Option<FiscalStagedTransitionRecord>, FiscalStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let transition_id = transaction
            .query_row(
                "SELECT transition_id FROM fiscal_staged_transitions WHERE status IN ('db_staged', 'fiscal_anchor_advanced')",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        let record = transition_id
            .as_deref()
            .map(|id| load_transition(&transaction, id))
            .transpose()?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(record)
    }

    pub fn load_checkpoint(
        &self,
        checkpoint_digest: &str,
        policy: &FiscalGenesisPolicy,
        charters: &FiscalCharterRegistry,
    ) -> Result<VerifiedFiscalContinuityCheckpoint, FiscalStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let json = transaction
            .query_row(
                "SELECT signed_json FROM fiscal_continuity_checkpoints WHERE checkpoint_digest = ?1",
                [checkpoint_digest],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(sqlite_error)?
            .ok_or(FiscalStoreError::NotFound)?;
        let checkpoint =
            VerifiedFiscalContinuityCheckpoint::from_canonical_bytes(&json, policy, charters)?;
        if checkpoint.digest() != checkpoint_digest {
            return Err(invariant("stored fiscal checkpoint digest is inconsistent"));
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(checkpoint)
    }

    fn transition_status_update(
        &self,
        transition_id: &str,
        expected: FiscalStageStatus,
        next: FiscalStageStatus,
        acknowledged: Option<&VerifiedFiscalContinuityCheckpoint>,
        fence: &StoreMutationFence,
    ) -> Result<FiscalStagedTransitionRecord, FiscalStoreError> {
        let acknowledged_json = acknowledged
            .map(VerifiedFiscalContinuityCheckpoint::canonical_bytes)
            .transpose()?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        let mut record = load_transition(&transaction, transition_id)?;
        if let (Some(checkpoint), Some(json)) = (acknowledged, acknowledged_json.as_deref()) {
            verify_acknowledgement(&transaction, &record, checkpoint, json)?;
        }
        if record.status == next {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(record);
        }
        if record.status != expected {
            return Err(FiscalStoreError::Conflict);
        }
        let next_version = record
            .stage_version
            .checked_add(1)
            .ok_or_else(|| invariant("fiscal stage version overflowed"))?;
        let updated = transaction
            .execute(
                "UPDATE fiscal_staged_transitions SET status = ?1, stage_version = ?2 WHERE transition_id = ?3 AND status = ?4 AND stage_version = ?5",
                params![
                    next.as_str(),
                    sqlite_i64(next_version, "fiscal stage version")?,
                    transition_id,
                    expected.as_str(),
                    sqlite_i64(record.stage_version, "fiscal stage version")?,
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(FiscalStoreError::Conflict);
        }
        record.status = next;
        record.stage_version = next_version;
        let projection_key = format!("transition:{transition_id}");
        append_projection_commit(
            &transaction,
            &self.serving_owner,
            &projection_key,
            next_version,
            "advance_fiscal_stage",
            &record.next_checkpoint_digest,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(record)
    }
}

pub(crate) fn initialize_fiscal_schema(
    connection: &mut Connection,
) -> Result<(), FiscalStoreError> {
    let on_disk = crate::check_schema_version(
        connection,
        FISCAL_STORE_SCHEMA_KEY,
        FISCAL_STORE_SUPPORTED_SCHEMA_VERSION,
        &["fiscal_authority_state", "capability_grant_budgets"],
    )
    .map_err(|error| invariant(error.to_string()))?;
    if on_disk == FISCAL_STORE_SUPPORTED_SCHEMA_VERSION {
        return verify_fiscal_sql_invariants(connection);
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(FISCAL_STORE_SCHEMA)
        .map_err(sqlite_error)?;
    crate::stamp_schema_version(
        &transaction,
        FISCAL_STORE_SCHEMA_KEY,
        FISCAL_STORE_SUPPORTED_SCHEMA_VERSION,
    )
    .map_err(|error| invariant(error.to_string()))?;
    verify_fiscal_sql_invariants(&transaction)?;
    transaction.commit().map_err(sqlite_error)
}

pub(crate) fn verify_fiscal_sql_invariants(
    connection: &Connection,
) -> Result<(), FiscalStoreError> {
    let invalid = connection
        .query_row(
            r#"
            SELECT
                EXISTS(
                    SELECT 1 FROM fiscal_authority_state AS authority
                    WHERE NOT EXISTS(
                        SELECT 1 FROM fiscal_continuity_checkpoints AS checkpoint
                        WHERE checkpoint.checkpoint_digest = authority.finalized_checkpoint_digest
                          AND checkpoint.status = 'finalized'
                    )
                )
                OR EXISTS(
                    SELECT 1 FROM fiscal_staged_transitions AS stage
                    WHERE NOT EXISTS(
                        SELECT 1 FROM fiscal_projection_commits AS commit_record
                        WHERE commit_record.projection_key = 'transition:' || stage.transition_id
                          AND commit_record.projection_sequence = stage.stage_version
                    )
                      OR NOT EXISTS(
                        SELECT 1 FROM fiscal_continuity_checkpoints AS checkpoint
                        WHERE checkpoint.checkpoint_digest = stage.next_checkpoint_digest
                          AND (
                            (stage.status = 'db_finalized' AND checkpoint.status = 'finalized')
                            OR (stage.status <> 'db_finalized' AND checkpoint.status = 'staged')
                          )
                    )
                      OR NOT EXISTS(
                        SELECT 1 FROM fiscal_authority_state AS authority
                        WHERE (
                            stage.status = 'db_finalized'
                            AND authority.finalized_checkpoint_digest = stage.next_checkpoint_digest
                        ) OR (
                            stage.status <> 'db_finalized'
                            AND authority.finalized_checkpoint_digest = stage.current_checkpoint_digest
                        )
                    )
                )
                OR EXISTS(
                    SELECT 1 FROM fiscal_proposal_admissions AS admission
                    WHERE NOT EXISTS(
                        SELECT 1 FROM fiscal_projection_commits AS commit_record
                        WHERE commit_record.projection_key = 'admission:' || admission.admission_id
                          AND commit_record.projection_sequence = admission.state_version
                    )
                )
                OR EXISTS(
                    SELECT 1 FROM fiscal_projection_commits AS commit_record
                    WHERE commit_record.projection_sequence > 1
                      AND NOT EXISTS(
                        SELECT 1 FROM fiscal_projection_commits AS previous
                        WHERE previous.projection_key = commit_record.projection_key
                          AND previous.projection_sequence = commit_record.projection_sequence - 1
                          AND previous.commit_digest = commit_record.previous_commit_digest
                    )
                )
                OR EXISTS(
                    SELECT 1 FROM fiscal_projection_commits
                    WHERE projection_sequence = 1 AND previous_commit_digest <> ?1
                )
            "#,
            [ZERO_DIGEST],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if invalid {
        Err(invariant("fiscal store projection is inconsistent"))
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_exact_genesis(
    transaction: &Transaction<'_>,
    policy_json: &[u8],
    authority_json: &[u8],
    charter_json: &[u8],
    readiness_json: &[u8],
    registry_json: &[u8],
    checkpoint_json: &[u8],
    policy: &FiscalGenesisPolicy,
    charter: &VerifiedFiscalCharter,
    readiness: &VerifiedFiscalRuntimeReadiness,
    checkpoint: &VerifiedFiscalContinuityCheckpoint,
) -> Result<(), FiscalStoreError> {
    let exact = transaction
        .query_row(
            r#"
            SELECT
                (SELECT policy_json FROM fiscal_genesis_policies WHERE policy_id = ?1) = ?2
                AND (SELECT state_json FROM fiscal_authority_state WHERE singleton = 1) = ?3
                AND (SELECT signed_json FROM fiscal_charters WHERE charter_id = ?4) = ?5
                AND (SELECT signed_json FROM fiscal_runtime_readiness WHERE readiness_id = ?6) = ?7
                AND (SELECT registry_json FROM fiscal_runtime_readiness WHERE readiness_id = ?6) = ?8
                AND (SELECT signed_json FROM fiscal_continuity_checkpoints WHERE checkpoint_digest = ?9) = ?10
            "#,
            params![
                &policy.policy_id,
                policy_json,
                authority_json,
                &charter.body().charter_id,
                charter_json,
                &readiness.body().readiness_id,
                readiness_json,
                registry_json,
                checkpoint.digest(),
                checkpoint_json,
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    if exact {
        Ok(())
    } else {
        Err(FiscalStoreError::Conflict)
    }
}

fn verify_acknowledgement(
    transaction: &Transaction<'_>,
    record: &FiscalStagedTransitionRecord,
    checkpoint: &VerifiedFiscalContinuityCheckpoint,
    canonical: &[u8],
) -> Result<(), FiscalStoreError> {
    if checkpoint.digest() != record.next_checkpoint_digest {
        return Err(FiscalStoreError::Conflict);
    }
    let stored = transaction
        .query_row(
            "SELECT signed_json FROM fiscal_continuity_checkpoints WHERE checkpoint_digest = ?1",
            [&record.next_checkpoint_digest],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or(FiscalStoreError::NotFound)?;
    if stored != canonical {
        return Err(FiscalStoreError::Conflict);
    }
    Ok(())
}

fn load_transition(
    transaction: &Transaction<'_>,
    transition_id: &str,
) -> Result<FiscalStagedTransitionRecord, FiscalStoreError> {
    transaction
        .query_row(
            "SELECT transition_id, current_checkpoint_digest, next_checkpoint_digest, proof_json, status, stage_version FROM fiscal_staged_transitions WHERE transition_id = ?1",
            [transition_id],
            |row| {
                let status = row.get::<_, String>(4)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    status,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or(FiscalStoreError::NotFound)
        .and_then(|row| {
            Ok(FiscalStagedTransitionRecord {
                transition_id: row.0,
                current_checkpoint_digest: row.1,
                next_checkpoint_digest: row.2,
                proof_json: row.3,
                status: FiscalStageStatus::parse(&row.4)?,
                stage_version: read_u64(row.5, "fiscal stage version")?,
            })
        })
}

fn append_projection_commit(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    projection_key: &str,
    projection_sequence: u64,
    mutation_kind: &str,
    snapshot_digest: &str,
) -> Result<(), FiscalStoreError> {
    let previous = if projection_sequence == 1 {
        ZERO_DIGEST.to_owned()
    } else {
        transaction
            .query_row(
                "SELECT commit_digest FROM fiscal_projection_commits WHERE projection_key = ?1 AND projection_sequence = ?2",
                params![projection_key, sqlite_i64(projection_sequence - 1, "previous fiscal projection sequence")?],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(sqlite_error)?
            .ok_or_else(|| invariant("previous fiscal projection commit is absent"))?
    };
    let commit_digest = canonical_digest(&FiscalProjectionCommit {
        format: "chio.sqlite-fiscal-projection-commit.v1",
        projection_key,
        projection_sequence,
        mutation_kind,
        snapshot_digest,
        previous_commit_digest: &previous,
        store_uuid: &owner.fence.store_uuid,
        store_lease_id: &owner.fence.lease_id,
        store_owner_epoch: owner.fence.owner_epoch,
    })?;
    transaction
        .execute(
            "INSERT INTO fiscal_projection_commits (projection_key, projection_sequence, mutation_kind, snapshot_digest, previous_commit_digest, commit_digest, store_uuid, store_lease_id, store_owner_epoch) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                projection_key,
                sqlite_i64(projection_sequence, "fiscal projection sequence")?,
                mutation_kind,
                snapshot_digest,
                &previous,
                &commit_digest,
                &owner.fence.store_uuid,
                &owner.fence.lease_id,
                sqlite_i64(owner.fence.owner_epoch, "store owner epoch")?,
            ],
        )
        .map_err(sqlite_error)?;
    owner
        .append_global_commit(
            transaction,
            mutation_kind,
            "fiscal",
            projection_key,
            projection_sequence,
        )
        .map_err(map_owner_error)
}

fn verify_owner(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    fence: Option<&StoreMutationFence>,
) -> Result<(), FiscalStoreError> {
    crate::admission_operation_store::verify_active_owner(transaction, owner, fence).map_err(
        |error| match error {
            chio_kernel::admission_operation::AdmissionOperationStoreError::Fenced => {
                FiscalStoreError::Fenced
            }
            other => FiscalStoreError::Unavailable(other.to_string()),
        },
    )
}

fn canonical_digest(value: &impl Serialize) -> Result<String, FiscalStoreError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(canonical_error)
}

fn canonical_error(error: impl std::fmt::Display) -> FiscalStoreError {
    invariant(format!("canonical fiscal encoding failed: {error}"))
}

fn sqlite_error(error: rusqlite::Error) -> FiscalStoreError {
    FiscalStoreError::Unavailable(error.to_string())
}

fn map_owner_error(error: SqliteServingOwnerError) -> FiscalStoreError {
    match error {
        SqliteServingOwnerError::OutcomeUnknown(detail) => FiscalStoreError::OutcomeUnknown(detail),
        other => FiscalStoreError::Unavailable(other.to_string()),
    }
}

fn invariant(detail: impl Into<String>) -> FiscalStoreError {
    FiscalStoreError::Invariant(detail.into())
}

fn sqlite_i64(value: u64, field: &str) -> Result<i64, FiscalStoreError> {
    i64::try_from(value).map_err(|_| invariant(format!("{field} exceeds SQLite INTEGER")))
}

fn read_u64(value: i64, field: &str) -> Result<u64, FiscalStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("{field} is negative")))
}

#[cfg(test)]
#[path = "fiscal_store_tests.rs"]
mod tests;

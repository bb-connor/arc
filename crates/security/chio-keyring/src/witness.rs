use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use chio_core_types::{canonical_json_bytes, Hash, SigningBackend};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::{
    verify_retained_history, verify_sync_update, KeyLogPolicy, KeyLogSyncResponse, KeyringError,
    Result, SignedKeyActivationCommit, SignedKeyLogCheckpoint, SignedKeyLogEvent, TrustedClock,
    WitnessId, WitnessSignature,
};

pub const CHECKPOINT_EQUIVOCATION_SCHEMA: &str = "chio.key-log.equivocation.v1";

const WITNESS_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS keyring_policy_binding (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    witness_roster_binding TEXT NOT NULL,
    recovery_policy_binding TEXT NOT NULL,
    artifact_time_policy_binding TEXT NOT NULL,
    auditor_policy_binding TEXT NOT NULL,
    configuration_binding TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS witness_events (
    sequence INTEGER PRIMARY KEY,
    canonical_envelope BLOB NOT NULL CHECK (length(canonical_envelope) <= 1048576)
);
CREATE TABLE IF NOT EXISTS witness_checkpoints (
    checkpoint_sequence INTEGER PRIMARY KEY,
    tree_size INTEGER NOT NULL UNIQUE,
    checkpoint_hash TEXT NOT NULL UNIQUE,
    root_hash TEXT NOT NULL,
    canonical_checkpoint BLOB NOT NULL CHECK (length(canonical_checkpoint) <= 1048576)
);
CREATE TABLE IF NOT EXISTS witness_activation_commits (
    signing_epoch INTEGER PRIMARY KEY,
    canonical_commit BLOB NOT NULL CHECK (length(canonical_commit) <= 1048576)
);
CREATE TABLE IF NOT EXISTS witness_decisions (
    checkpoint_sequence INTEGER PRIMARY KEY,
    tree_size INTEGER NOT NULL UNIQUE,
    checkpoint_hash TEXT NOT NULL UNIQUE,
    canonical_signature BLOB NOT NULL CHECK (length(canonical_signature) <= 1048576)
);
CREATE TABLE IF NOT EXISTS witness_pin (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    checkpoint_sequence INTEGER NOT NULL,
    tree_size INTEGER NOT NULL,
    checkpoint_hash TEXT NOT NULL,
    root_hash TEXT NOT NULL,
    signing_epoch INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS witness_conflicts (
    conflict_hash TEXT PRIMARY KEY,
    canonical_evidence BLOB NOT NULL CHECK (length(canonical_evidence) <= 1048576)
);
CREATE TABLE IF NOT EXISTS witness_gossip (
    checkpoint_hash TEXT NOT NULL,
    witness_id TEXT NOT NULL,
    checkpoint_sequence INTEGER NOT NULL CHECK (checkpoint_sequence >= 0),
    tree_size INTEGER NOT NULL CHECK (tree_size > 0),
    canonical_gossip BLOB NOT NULL CHECK (length(canonical_gossip) <= 1048576),
    PRIMARY KEY (checkpoint_hash, witness_id)
);
"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointConflictKind {
    CheckpointSequence,
    TreeSize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointEquivocationEvidence {
    pub schema: String,
    pub kind: CheckpointConflictKind,
    pub first: SignedKeyLogCheckpoint,
    pub conflicting: SignedKeyLogCheckpoint,
    pub detected_at: u64,
}

impl CheckpointEquivocationEvidence {
    pub fn evidence_hash(&self) -> Result<Hash> {
        Ok(chio_core_types::sha256(&canonical_json_bytes(self)?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointGossip {
    pub checkpoint: SignedKeyLogCheckpoint,
    pub witness_signature: WitnessSignature,
}

pub struct SqliteKeyLogWitness {
    connection: Mutex<Connection>,
    policy: KeyLogPolicy,
    witness_id: WitnessId,
    backend: Box<dyn SigningBackend>,
    clock: Arc<dyn TrustedClock>,
    storage_file: crate::DurableSqliteFile,
}

impl SqliteKeyLogWitness {
    #[must_use]
    pub fn witness_id(&self) -> &WitnessId {
        &self.witness_id
    }

    #[must_use]
    pub fn storage_identity(&self) -> Hash {
        self.storage_file.identity()
    }

    pub fn provision(
        path: impl AsRef<Path>,
        policy: KeyLogPolicy,
        witness_id: WitnessId,
        backend: Box<dyn SigningBackend>,
        clock: Arc<dyn TrustedClock>,
    ) -> Result<Self> {
        let path = path.as_ref();
        crate::provision_durable_sqlite_path(path)?;
        match Self::open(path, policy, witness_id, backend, clock) {
            Ok(witness) => Ok(witness),
            Err(error) => {
                let _ = std::fs::remove_file(path);
                Err(error)
            }
        }
    }

    pub fn open(
        path: impl AsRef<Path>,
        policy: KeyLogPolicy,
        witness_id: WitnessId,
        backend: Box<dyn SigningBackend>,
        clock: Arc<dyn TrustedClock>,
    ) -> Result<Self> {
        let configured = policy
            .witness_keys
            .get(&witness_id)
            .ok_or(KeyringError::InvalidSignature)?;
        if backend.public_key() != *configured || backend.algorithm() != configured.algorithm() {
            return Err(KeyringError::InvalidSignature);
        }
        let path = path.as_ref();
        crate::require_existing_durable_sqlite_path(path)?;
        let storage_file = crate::open_durable_sqlite_file(path, false, true)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        storage_file.validate_path_binding(path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;",
        )?;
        connection.execute_batch(WITNESS_SCHEMA)?;
        let durable_state_exists = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM witness_events UNION ALL SELECT 1 FROM witness_checkpoints UNION ALL SELECT 1 FROM witness_activation_commits UNION ALL SELECT 1 FROM witness_decisions UNION ALL SELECT 1 FROM witness_pin UNION ALL SELECT 1 FROM witness_conflicts UNION ALL SELECT 1 FROM witness_gossip LIMIT 1)",
            [],
            |row| row.get::<_, i64>(0),
        )? != 0;
        crate::persist_or_validate_policy_binding(&connection, &policy, durable_state_exists)?;
        let witness = Self {
            connection: Mutex::new(connection),
            policy,
            witness_id,
            backend,
            clock,
            storage_file,
        };
        witness.validate_startup()?;
        Ok(witness)
    }

    pub fn sign_candidate(
        &self,
        candidate: &SignedKeyLogCheckpoint,
        response: &KeyLogSyncResponse,
    ) -> Result<WitnessSignature> {
        candidate.verify_operator(&self.policy.operator_key)?;
        let now = self.clock.now()?;
        self.policy
            .validate_checkpoint_time(candidate.body.issued_at, now)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        response.validate_bounds()?;
        for checkpoint in &response.checkpoints {
            checkpoint.verify_operator(&self.policy.operator_key)?;
            self.policy
                .validate_checkpoint_time(checkpoint.body.issued_at, now)?;
        }
        if let Some((first, conflicting, kind)) = response_conflict(&transaction, response)? {
            persist_conflict(&transaction, &first, &conflicting, kind, now)?;
            transaction.commit()?;
            return Err(KeyringError::EquivocationDetected);
        }

        if let Some(existing) =
            decision_for_sequence(&transaction, candidate.body.checkpoint_sequence)?
        {
            let (checkpoint, signature) = existing;
            if checkpoint.checkpoint_hash()? == candidate.checkpoint_hash()? {
                signature.verify(candidate, &self.backend.public_key())?;
                let response_replays_candidate = response.activation_commits.is_empty()
                    && response
                        .checkpoints
                        .last()
                        .map(SignedKeyLogCheckpoint::checkpoint_hash)
                        .transpose()?
                        == Some(candidate.checkpoint_hash()?);
                if response_replays_candidate {
                    transaction.rollback()?;
                    return Ok(signature);
                }
                if !response.checkpoints.is_empty()
                    || !response.event_envelopes.is_empty()
                    || !response.activation_commits.is_empty()
                {
                    let retained_events = load_events(&transaction)?;
                    let retained_checkpoints = load_checkpoints(&transaction)?;
                    let retained_commits = load_commits(&transaction)?;
                    let verified = verify_sync_update(
                        &retained_events,
                        &retained_checkpoints,
                        &retained_commits,
                        response,
                        &self.policy,
                        now,
                        false,
                    )?;
                    persist_verified_log(&transaction, &verified)?;
                    persist_pin(&transaction, &verified.pin)?;
                    transaction.commit()?;
                    return Ok(signature);
                }
                transaction.rollback()?;
                return Ok(signature);
            }
            persist_conflict(
                &transaction,
                &checkpoint,
                candidate,
                CheckpointConflictKind::CheckpointSequence,
                now,
            )?;
            transaction.commit()?;
            return Err(KeyringError::EquivocationDetected);
        }
        if let Some(existing) =
            checkpoint_for_sequence(&transaction, candidate.body.checkpoint_sequence)?
        {
            if existing.checkpoint_hash()? != candidate.checkpoint_hash()? {
                persist_conflict(
                    &transaction,
                    &existing,
                    candidate,
                    CheckpointConflictKind::CheckpointSequence,
                    now,
                )?;
                transaction.commit()?;
                return Err(KeyringError::EquivocationDetected);
            }
        }
        if let Some(existing) = checkpoint_for_tree_size(&transaction, candidate.body.tree_size)? {
            if existing.checkpoint_hash()? != candidate.checkpoint_hash()? {
                persist_conflict(
                    &transaction,
                    &existing,
                    candidate,
                    CheckpointConflictKind::TreeSize,
                    now,
                )?;
                transaction.commit()?;
                return Err(KeyringError::EquivocationDetected);
            }
        }

        let retained_events = load_events(&transaction)?;
        let retained_checkpoints = load_checkpoints(&transaction)?;
        let retained_commits = load_commits(&transaction)?;
        let verified = verify_sync_update(
            &retained_events,
            &retained_checkpoints,
            &retained_commits,
            response,
            &self.policy,
            now,
            false,
        )?;
        let verified_candidate =
            verified
                .checkpoints
                .last()
                .ok_or(KeyringError::InvalidCheckpoint(
                    "witness candidate is absent",
                ))?;
        if verified_candidate.checkpoint_hash()? != candidate.checkpoint_hash()? {
            return Err(KeyringError::InvalidCheckpoint(
                "witness candidate is not the synchronization head",
            ));
        }

        let signature =
            WitnessSignature::sign(candidate, self.witness_id.clone(), self.backend.as_ref())?;
        persist_verified_log(&transaction, &verified)?;
        transaction.execute(
            "INSERT INTO witness_decisions (checkpoint_sequence, tree_size, checkpoint_hash, canonical_signature) VALUES (?1, ?2, ?3, ?4)",
            params![
                to_i64(candidate.body.checkpoint_sequence)?,
                to_i64(candidate.body.tree_size)?,
                candidate.checkpoint_hash()?.to_string(),
                canonical_json_bytes(&signature)?,
            ],
        )?;
        persist_pin(&transaction, &verified.pin)?;
        transaction.commit()?;
        Ok(signature)
    }

    pub fn import_gossip(&self, gossip: &CheckpointGossip) -> Result<()> {
        gossip
            .checkpoint
            .verify_operator(&self.policy.operator_key)?;
        let witness_key = self
            .policy
            .witness_keys
            .get(&gossip.witness_signature.witness_id)
            .ok_or(KeyringError::InvalidSignature)?;
        gossip
            .witness_signature
            .verify(&gossip.checkpoint, witness_key)?;
        let now = self.clock.now()?;
        self.policy
            .validate_checkpoint_time(gossip.checkpoint.body.issued_at, now)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) =
            checkpoint_for_sequence(&transaction, gossip.checkpoint.body.checkpoint_sequence)?
        {
            if existing.checkpoint_hash()? != gossip.checkpoint.checkpoint_hash()? {
                persist_conflict(
                    &transaction,
                    &existing,
                    &gossip.checkpoint,
                    CheckpointConflictKind::CheckpointSequence,
                    now,
                )?;
                transaction.commit()?;
                return Err(KeyringError::EquivocationDetected);
            }
        }
        if let Some(existing) = gossip_checkpoint_for_sequence(
            &transaction,
            gossip.checkpoint.body.checkpoint_sequence,
        )? {
            if existing.checkpoint_hash()? != gossip.checkpoint.checkpoint_hash()? {
                persist_conflict(
                    &transaction,
                    &existing,
                    &gossip.checkpoint,
                    CheckpointConflictKind::CheckpointSequence,
                    now,
                )?;
                transaction.commit()?;
                return Err(KeyringError::EquivocationDetected);
            }
        }
        if let Some(existing) =
            checkpoint_for_tree_size(&transaction, gossip.checkpoint.body.tree_size)?
        {
            if existing.checkpoint_hash()? != gossip.checkpoint.checkpoint_hash()? {
                persist_conflict(
                    &transaction,
                    &existing,
                    &gossip.checkpoint,
                    CheckpointConflictKind::TreeSize,
                    now,
                )?;
                transaction.commit()?;
                return Err(KeyringError::EquivocationDetected);
            }
        }
        if let Some(existing) =
            gossip_checkpoint_for_tree_size(&transaction, gossip.checkpoint.body.tree_size)?
        {
            if existing.checkpoint_hash()? != gossip.checkpoint.checkpoint_hash()? {
                persist_conflict(
                    &transaction,
                    &existing,
                    &gossip.checkpoint,
                    CheckpointConflictKind::TreeSize,
                    now,
                )?;
                transaction.commit()?;
                return Err(KeyringError::EquivocationDetected);
            }
        }
        persist_gossip(&transaction, gossip)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn gossip_observations(&self) -> Result<Vec<CheckpointGossip>> {
        load_gossip(&*self.connection()?)
    }

    pub fn service_gossip_observations(&self) -> Result<Vec<CheckpointGossip>> {
        let connection = self.connection()?;
        let mut observations = load_gossip(&connection)?;
        for sequence in load_decision_sequences(&connection)? {
            if let Some((checkpoint, witness_signature)) =
                decision_for_sequence(&connection, sequence)?
            {
                let gossip = CheckpointGossip {
                    checkpoint,
                    witness_signature,
                };
                if !observations.contains(&gossip) {
                    observations.push(gossip);
                }
            }
        }
        observations.sort_by(|left, right| {
            left.checkpoint
                .body
                .checkpoint_sequence
                .cmp(&right.checkpoint.body.checkpoint_sequence)
                .then_with(|| {
                    left.witness_signature
                        .witness_id
                        .cmp(&right.witness_signature.witness_id)
                })
        });
        Ok(observations)
    }

    pub fn pin(&self) -> Result<Option<crate::KeyLogPin>> {
        load_pin(&*self.connection()?)
    }

    pub fn conflicts(&self) -> Result<Vec<CheckpointEquivocationEvidence>> {
        load_conflicts(&*self.connection()?)
    }

    pub fn gossip_for_sequence(&self, sequence: u64) -> Result<Option<CheckpointGossip>> {
        Ok(decision_for_sequence(&*self.connection()?, sequence)?.map(
            |(checkpoint, witness_signature)| CheckpointGossip {
                checkpoint,
                witness_signature,
            },
        ))
    }

    fn validate_startup(&self) -> Result<()> {
        let connection = self.connection()?;
        let events = load_events(&connection)?;
        let checkpoints = load_checkpoints(&connection)?;
        let commits = load_commits(&connection)?;
        let pin = load_pin(&connection)?;
        validate_retained_gossip(&connection, &self.policy, self.clock.now()?)?;
        if events.is_empty() {
            if !checkpoints.is_empty()
                || !commits.is_empty()
                || pin.is_some()
                || decision_count(&connection)? != 0
            {
                return Err(KeyringError::StateInvariant(
                    "empty witness has retained verification state",
                ));
            }
            return Ok(());
        }
        let verified = verify_retained_history(
            &events,
            &checkpoints,
            &commits,
            &self.policy,
            self.clock.now()?,
            false,
        )?;
        if pin.as_ref() != Some(&verified.pin) {
            return Err(KeyringError::StateInvariant(
                "witness pin does not match retained history",
            ));
        }
        let decision_sequences = load_decision_sequences(&connection)?;
        if decision_sequences.last().copied() != Some(verified.pin.checkpoint_sequence) {
            return Err(KeyringError::StateInvariant(
                "witness pin has no corresponding decision",
            ));
        }
        for sequence in decision_sequences {
            let (checkpoint, signature) = decision_for_sequence(&connection, sequence)?.ok_or(
                KeyringError::StateInvariant("retained witness decision has no checkpoint"),
            )?;
            let checkpoint_index =
                usize::try_from(sequence).map_err(|_| KeyringError::NumericRange)?;
            let retained =
                verified
                    .checkpoints
                    .get(checkpoint_index)
                    .ok_or(KeyringError::StateInvariant(
                        "witness decision references a checkpoint outside retained history",
                    ))?;
            if checkpoint.checkpoint_hash()? != retained.checkpoint_hash()? {
                return Err(KeyringError::StateInvariant(
                    "witness decision conflicts with retained checkpoint",
                ));
            }
            signature.verify(&checkpoint, &self.backend.public_key())?;
        }
        Ok(())
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| KeyringError::Synchronization)?;
        self.storage_file.validate()?;
        Ok(connection)
    }
}

fn response_conflict(
    connection: &Connection,
    response: &KeyLogSyncResponse,
) -> Result<
    Option<(
        SignedKeyLogCheckpoint,
        SignedKeyLogCheckpoint,
        CheckpointConflictKind,
    )>,
> {
    let mut sequences = BTreeMap::new();
    let mut tree_sizes = BTreeMap::new();
    for checkpoint in &response.checkpoints {
        if let Some(first) =
            checkpoint_for_sequence(connection, checkpoint.body.checkpoint_sequence)?
        {
            if first.checkpoint_hash()? != checkpoint.checkpoint_hash()? {
                return Ok(Some((
                    first,
                    checkpoint.clone(),
                    CheckpointConflictKind::CheckpointSequence,
                )));
            }
        }
        if let Some(first) = checkpoint_for_tree_size(connection, checkpoint.body.tree_size)? {
            if first.checkpoint_hash()? != checkpoint.checkpoint_hash()? {
                return Ok(Some((
                    first,
                    checkpoint.clone(),
                    CheckpointConflictKind::TreeSize,
                )));
            }
        }
        if let Some(first) = sequences.insert(checkpoint.body.checkpoint_sequence, checkpoint) {
            if first.checkpoint_hash()? != checkpoint.checkpoint_hash()? {
                return Ok(Some((
                    first.clone(),
                    checkpoint.clone(),
                    CheckpointConflictKind::CheckpointSequence,
                )));
            }
        }
        if let Some(first) = tree_sizes.insert(checkpoint.body.tree_size, checkpoint) {
            if first.checkpoint_hash()? != checkpoint.checkpoint_hash()? {
                return Ok(Some((
                    first.clone(),
                    checkpoint.clone(),
                    CheckpointConflictKind::TreeSize,
                )));
            }
        }
    }
    Ok(None)
}

fn decision_count(connection: &Connection) -> Result<usize> {
    let count = connection.query_row("SELECT COUNT(*) FROM witness_decisions", [], |row| {
        row.get::<_, i64>(0)
    })?;
    usize::try_from(count).map_err(|_| KeyringError::NumericRange)
}

fn load_decision_sequences(connection: &Connection) -> Result<Vec<u64>> {
    let mut statement = connection.prepare(
        "SELECT checkpoint_sequence FROM witness_decisions ORDER BY checkpoint_sequence",
    )?;
    let rows = statement.query_map([], |row| row.get::<_, i64>(0))?;
    let mut sequences = Vec::new();
    for row in rows {
        sequences.push(from_i64(row?)?);
    }
    Ok(sequences)
}

fn persist_verified_log(
    connection: &Connection,
    verified: &crate::sync::VerifiedKeyLog,
) -> Result<()> {
    for event in &verified.events {
        connection.execute(
            "INSERT OR IGNORE INTO witness_events (sequence, canonical_envelope) VALUES (?1, ?2)",
            params![
                to_i64(event.body.sequence)?,
                event.canonical_envelope_bytes()?
            ],
        )?;
    }
    for checkpoint in &verified.checkpoints {
        connection.execute(
            "INSERT OR IGNORE INTO witness_checkpoints (checkpoint_sequence, tree_size, checkpoint_hash, root_hash, canonical_checkpoint) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                to_i64(checkpoint.body.checkpoint_sequence)?,
                to_i64(checkpoint.body.tree_size)?,
                checkpoint.checkpoint_hash()?.to_string(),
                checkpoint.body.root_hash.to_string(),
                canonical_json_bytes(checkpoint)?,
            ],
        )?;
    }
    for commit in &verified.activation_commits {
        connection.execute(
            "INSERT OR IGNORE INTO witness_activation_commits (signing_epoch, canonical_commit) VALUES (?1, ?2)",
            params![to_i64(commit.body.signing_epoch)?, commit.canonical_bytes()?],
        )?;
    }
    Ok(())
}

fn persist_pin(connection: &Connection, pin: &crate::KeyLogPin) -> Result<()> {
    connection.execute(
        "INSERT INTO witness_pin (singleton, checkpoint_sequence, tree_size, checkpoint_hash, root_hash, signing_epoch) VALUES (1, ?1, ?2, ?3, ?4, ?5) ON CONFLICT(singleton) DO UPDATE SET checkpoint_sequence = excluded.checkpoint_sequence, tree_size = excluded.tree_size, checkpoint_hash = excluded.checkpoint_hash, root_hash = excluded.root_hash, signing_epoch = excluded.signing_epoch",
        params![
            to_i64(pin.checkpoint_sequence)?,
            to_i64(pin.tree_size)?,
            pin.checkpoint_hash.to_string(),
            pin.root_hash.to_string(),
            to_i64(pin.signing_epoch)?,
        ],
    )?;
    Ok(())
}

fn persist_conflict(
    connection: &Connection,
    first: &SignedKeyLogCheckpoint,
    conflicting: &SignedKeyLogCheckpoint,
    kind: CheckpointConflictKind,
    detected_at: u64,
) -> Result<()> {
    let evidence = CheckpointEquivocationEvidence {
        schema: CHECKPOINT_EQUIVOCATION_SCHEMA.to_string(),
        kind,
        first: first.clone(),
        conflicting: conflicting.clone(),
        detected_at,
    };
    connection.execute(
        "INSERT OR IGNORE INTO witness_conflicts (conflict_hash, canonical_evidence) VALUES (?1, ?2)",
        params![
            evidence.evidence_hash()?.to_string(),
            canonical_json_bytes(&evidence)?,
        ],
    )?;
    Ok(())
}

fn load_events(connection: &Connection) -> Result<Vec<SignedKeyLogEvent>> {
    let mut statement = connection.prepare(
        "SELECT CASE WHEN length(canonical_envelope) <= 1048576 THEN canonical_envelope END FROM witness_events ORDER BY sequence",
    )?;
    let rows = statement.query_map([], |row| row.get::<_, Option<Vec<u8>>>(0))?;
    let mut events = Vec::new();
    for row in rows {
        let bytes = row?.ok_or(KeyringError::StateInvariant(
            "witness event exceeds byte limit",
        ))?;
        events.push(SignedKeyLogEvent::from_canonical_envelope_bytes(&bytes)?);
    }
    Ok(events)
}

fn load_checkpoints(connection: &Connection) -> Result<Vec<SignedKeyLogCheckpoint>> {
    let mut statement = connection.prepare(
        "SELECT CASE WHEN length(canonical_checkpoint) <= 1048576 THEN canonical_checkpoint END FROM witness_checkpoints ORDER BY checkpoint_sequence",
    )?;
    let rows = statement.query_map([], |row| row.get::<_, Option<Vec<u8>>>(0))?;
    let mut checkpoints = Vec::new();
    for row in rows {
        let bytes = row?.ok_or(KeyringError::StateInvariant(
            "witness checkpoint exceeds byte limit",
        ))?;
        checkpoints.push(SignedKeyLogCheckpoint::from_canonical_bytes(&bytes)?);
    }
    Ok(checkpoints)
}

fn load_commits(connection: &Connection) -> Result<Vec<SignedKeyActivationCommit>> {
    let mut statement = connection.prepare(
        "SELECT CASE WHEN length(canonical_commit) <= 1048576 THEN canonical_commit END FROM witness_activation_commits ORDER BY signing_epoch",
    )?;
    let rows = statement.query_map([], |row| row.get::<_, Option<Vec<u8>>>(0))?;
    let mut commits = Vec::new();
    for row in rows {
        let bytes = row?.ok_or(KeyringError::StateInvariant(
            "witness activation commit exceeds byte limit",
        ))?;
        commits.push(SignedKeyActivationCommit::from_canonical_bytes(&bytes)?);
    }
    Ok(commits)
}

fn checkpoint_for_sequence(
    connection: &Connection,
    sequence: u64,
) -> Result<Option<SignedKeyLogCheckpoint>> {
    bounded_checkpoint_query(
        connection,
        "SELECT CASE WHEN length(canonical_checkpoint) <= 1048576 THEN canonical_checkpoint END FROM witness_checkpoints WHERE checkpoint_sequence = ?1",
        to_i64(sequence)?,
    )
}

fn checkpoint_for_tree_size(
    connection: &Connection,
    tree_size: u64,
) -> Result<Option<SignedKeyLogCheckpoint>> {
    bounded_checkpoint_query(
        connection,
        "SELECT CASE WHEN length(canonical_checkpoint) <= 1048576 THEN canonical_checkpoint END FROM witness_checkpoints WHERE tree_size = ?1",
        to_i64(tree_size)?,
    )
}

fn gossip_checkpoint_for_sequence(
    connection: &Connection,
    sequence: u64,
) -> Result<Option<SignedKeyLogCheckpoint>> {
    gossip_checkpoint_query(
        connection,
        "SELECT CASE WHEN length(canonical_gossip) <= 1048576 THEN canonical_gossip END FROM witness_gossip WHERE checkpoint_sequence = ?1 ORDER BY checkpoint_hash, witness_id LIMIT 1",
        to_i64(sequence)?,
    )
}

fn gossip_checkpoint_for_tree_size(
    connection: &Connection,
    tree_size: u64,
) -> Result<Option<SignedKeyLogCheckpoint>> {
    gossip_checkpoint_query(
        connection,
        "SELECT CASE WHEN length(canonical_gossip) <= 1048576 THEN canonical_gossip END FROM witness_gossip WHERE tree_size = ?1 ORDER BY checkpoint_hash, witness_id LIMIT 1",
        to_i64(tree_size)?,
    )
}

fn gossip_checkpoint_query(
    connection: &Connection,
    sql: &str,
    value: i64,
) -> Result<Option<SignedKeyLogCheckpoint>> {
    connection
        .query_row(sql, [value], |row| row.get::<_, Option<Vec<u8>>>(0))
        .optional()?
        .flatten()
        .map(|bytes| {
            crate::from_bounded_json::<CheckpointGossip>(&bytes).map(|gossip| gossip.checkpoint)
        })
        .transpose()
}

fn persist_gossip(connection: &Connection, gossip: &CheckpointGossip) -> Result<()> {
    connection.execute(
        "INSERT OR IGNORE INTO witness_gossip (checkpoint_hash, witness_id, checkpoint_sequence, tree_size, canonical_gossip) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            gossip.checkpoint.checkpoint_hash()?.to_string(),
            gossip.witness_signature.witness_id.as_str(),
            to_i64(gossip.checkpoint.body.checkpoint_sequence)?,
            to_i64(gossip.checkpoint.body.tree_size)?,
            canonical_json_bytes(gossip)?,
        ],
    )?;
    Ok(())
}

fn load_gossip(connection: &Connection) -> Result<Vec<CheckpointGossip>> {
    let mut statement = connection.prepare(
        "SELECT CASE WHEN length(canonical_gossip) <= 1048576 THEN canonical_gossip END FROM witness_gossip ORDER BY checkpoint_sequence, checkpoint_hash, witness_id",
    )?;
    let rows = statement.query_map([], |row| row.get::<_, Option<Vec<u8>>>(0))?;
    let mut observations = Vec::new();
    for row in rows {
        let bytes = row?.ok_or(KeyringError::StateInvariant(
            "witness gossip exceeds byte limit",
        ))?;
        observations.push(crate::from_bounded_json(&bytes)?);
    }
    Ok(observations)
}

fn validate_retained_gossip(
    connection: &Connection,
    policy: &KeyLogPolicy,
    now: u64,
) -> Result<()> {
    let mut sequences = BTreeMap::new();
    let mut tree_sizes = BTreeMap::new();
    for gossip in load_gossip(connection)? {
        gossip.checkpoint.verify_operator(&policy.operator_key)?;
        policy.validate_checkpoint_time(gossip.checkpoint.body.issued_at, now)?;
        let witness_key = policy
            .witness_keys
            .get(&gossip.witness_signature.witness_id)
            .ok_or(KeyringError::InvalidSignature)?;
        gossip
            .witness_signature
            .verify(&gossip.checkpoint, witness_key)?;
        let hash = gossip.checkpoint.checkpoint_hash()?;
        if sequences
            .insert(gossip.checkpoint.body.checkpoint_sequence, hash)
            .is_some_and(|existing| existing != hash)
            || tree_sizes
                .insert(gossip.checkpoint.body.tree_size, hash)
                .is_some_and(|existing| existing != hash)
        {
            return Err(KeyringError::EquivocationDetected);
        }
    }
    Ok(())
}

fn bounded_checkpoint_query(
    connection: &Connection,
    sql: &str,
    value: i64,
) -> Result<Option<SignedKeyLogCheckpoint>> {
    let bytes = connection
        .query_row(sql, [value], |row| row.get::<_, Option<Vec<u8>>>(0))
        .optional()?
        .flatten();
    bytes
        .map(|bytes| SignedKeyLogCheckpoint::from_canonical_bytes(&bytes))
        .transpose()
}

fn decision_for_sequence(
    connection: &Connection,
    sequence: u64,
) -> Result<Option<(SignedKeyLogCheckpoint, WitnessSignature)>> {
    let Some(checkpoint) = checkpoint_for_sequence(connection, sequence)? else {
        return Ok(None);
    };
    let bytes = connection
        .query_row(
            "SELECT CASE WHEN length(canonical_signature) <= 1048576 THEN canonical_signature END FROM witness_decisions WHERE checkpoint_sequence = ?1",
            [to_i64(sequence)?],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()?
        .flatten();
    bytes
        .map(|bytes| {
            let signature = crate::from_bounded_json(&bytes)?;
            Ok((checkpoint, signature))
        })
        .transpose()
}

fn load_pin(connection: &Connection) -> Result<Option<crate::KeyLogPin>> {
    connection
        .query_row(
            "SELECT checkpoint_sequence, tree_size, checkpoint_hash, root_hash, signing_epoch FROM witness_pin WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?
        .map(|(sequence, size, checkpoint_hash, root_hash, epoch)| {
            Ok(crate::KeyLogPin {
                checkpoint_sequence: from_i64(sequence)?,
                tree_size: from_i64(size)?,
                checkpoint_hash: Hash::from_hex(&checkpoint_hash)?,
                root_hash: Hash::from_hex(&root_hash)?,
                signing_epoch: from_i64(epoch)?,
            })
        })
        .transpose()
}

fn load_conflicts(connection: &Connection) -> Result<Vec<CheckpointEquivocationEvidence>> {
    let mut statement = connection.prepare(
        "SELECT CASE WHEN length(canonical_evidence) <= 1048576 THEN canonical_evidence END FROM witness_conflicts ORDER BY conflict_hash",
    )?;
    let rows = statement.query_map([], |row| row.get::<_, Option<Vec<u8>>>(0))?;
    let mut conflicts = Vec::new();
    for row in rows {
        let bytes = row?.ok_or(KeyringError::StateInvariant(
            "witness conflict exceeds byte limit",
        ))?;
        conflicts.push(crate::from_bounded_json(&bytes)?);
    }
    Ok(conflicts)
}

fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| KeyringError::NumericRange)
}

fn from_i64(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| KeyringError::NumericRange)
}

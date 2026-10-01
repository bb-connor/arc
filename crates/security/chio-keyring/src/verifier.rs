use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use chio_core_types::{canonical_json_bytes, Hash};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};

use crate::{
    verify_retained_history, verify_sync_update, ArtifactTimeAnchorKind, ArtifactTimeEvidence,
    CheckpointConflictKind, CheckpointEquivocationEvidence, CheckpointGossip, KeyId, KeyLogPin,
    KeyLogPolicy, KeyLogState, KeyLogSyncResponse, KeyRecord, KeyringArtifactSignature,
    KeyringError, Result, SignedArtifactTimeAnchor, SignedKeyActivationCommit,
    SignedKeyLogCheckpoint, SignedKeyLogEvent, TrustedClock, CHECKPOINT_EQUIVOCATION_SCHEMA,
};

const VERIFIER_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS keyring_policy_binding (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    witness_roster_binding TEXT NOT NULL,
    recovery_policy_binding TEXT NOT NULL,
    artifact_time_policy_binding TEXT NOT NULL,
    auditor_policy_binding TEXT NOT NULL,
    configuration_binding TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS verifier_events (
    sequence INTEGER PRIMARY KEY,
    canonical_envelope BLOB NOT NULL CHECK (length(canonical_envelope) <= 1048576)
);
CREATE TABLE IF NOT EXISTS verifier_checkpoints (
    checkpoint_sequence INTEGER PRIMARY KEY,
    tree_size INTEGER NOT NULL UNIQUE,
    checkpoint_hash TEXT NOT NULL UNIQUE,
    root_hash TEXT NOT NULL,
    canonical_checkpoint BLOB NOT NULL CHECK (length(canonical_checkpoint) <= 1048576)
);
CREATE TABLE IF NOT EXISTS verifier_activation_commits (
    signing_epoch INTEGER PRIMARY KEY,
    canonical_commit BLOB NOT NULL CHECK (length(canonical_commit) <= 1048576)
);
CREATE TABLE IF NOT EXISTS verifier_pin (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    checkpoint_sequence INTEGER NOT NULL,
    tree_size INTEGER NOT NULL,
    checkpoint_hash TEXT NOT NULL,
    root_hash TEXT NOT NULL,
    signing_epoch INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS verifier_conflicts (
    conflict_hash TEXT PRIMARY KEY,
    canonical_evidence BLOB NOT NULL CHECK (length(canonical_evidence) <= 1048576)
);
CREATE TABLE IF NOT EXISTS verifier_gossip (
    checkpoint_hash TEXT NOT NULL,
    witness_id TEXT NOT NULL,
    checkpoint_sequence INTEGER NOT NULL CHECK (checkpoint_sequence >= 0),
    tree_size INTEGER NOT NULL CHECK (tree_size > 0),
    canonical_gossip BLOB NOT NULL CHECK (length(canonical_gossip) <= 1048576),
    PRIMARY KEY (checkpoint_hash, witness_id)
);
"#;

pub struct SqlitePinnedKeyLogVerifier {
    connection: Mutex<Connection>,
    policy: KeyLogPolicy,
    clock: Arc<dyn TrustedClock>,
    storage_file: crate::DurableSqliteFile,
}

impl SqlitePinnedKeyLogVerifier {
    #[must_use]
    pub fn storage_identity(&self) -> Hash {
        self.storage_file.identity()
    }

    pub fn provision(
        path: impl AsRef<Path>,
        policy: KeyLogPolicy,
        clock: Arc<dyn TrustedClock>,
    ) -> Result<Self> {
        let path = path.as_ref();
        crate::provision_durable_sqlite_path(path)?;
        match Self::open(path, policy, clock) {
            Ok(verifier) => Ok(verifier),
            Err(error) => {
                let _ = std::fs::remove_file(path);
                Err(error)
            }
        }
    }

    pub fn open(
        path: impl AsRef<Path>,
        policy: KeyLogPolicy,
        clock: Arc<dyn TrustedClock>,
    ) -> Result<Self> {
        let path = path.as_ref();
        crate::require_existing_durable_sqlite_path(path)?;
        let storage_file = crate::open_durable_sqlite_file(path, false, true)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        storage_file.validate_live_connection(&connection)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;",
        )?;
        connection.execute_batch(VERIFIER_SCHEMA)?;
        let durable_state_exists = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM verifier_events UNION ALL SELECT 1 FROM verifier_checkpoints UNION ALL SELECT 1 FROM verifier_activation_commits UNION ALL SELECT 1 FROM verifier_pin UNION ALL SELECT 1 FROM verifier_conflicts UNION ALL SELECT 1 FROM verifier_gossip LIMIT 1)",
            [],
            |row| row.get::<_, i64>(0),
        )? != 0;
        crate::persist_or_validate_policy_binding(&connection, &policy, durable_state_exists)?;
        let verifier = Self {
            connection: Mutex::new(connection),
            policy,
            clock,
            storage_file,
        };
        verifier.validate_startup()?;
        Ok(verifier)
    }

    pub fn apply_sync(&self, response: &KeyLogSyncResponse) -> Result<KeyLogPin> {
        let now = self.clock.now()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        response.validate_bounds()?;
        for checkpoint in &response.checkpoints {
            checkpoint.verify_operator(&self.policy.operator_key)?;
            self.policy
                .validate_checkpoint_time(checkpoint.body.issued_at, now)?;
        }
        if let Some(conflict) = find_response_conflict(&transaction, response, now)? {
            persist_conflict(&transaction, &conflict)?;
            transaction.commit()?;
            return Err(KeyringError::EquivocationDetected);
        }
        let events = load_events(&transaction)?;
        let checkpoints = load_checkpoints(&transaction)?;
        let commits = load_commits(&transaction)?;
        let verified = verify_sync_update(
            &events,
            &checkpoints,
            &commits,
            response,
            &self.policy,
            now,
            true,
        )?;
        persist_verified(&transaction, &verified)?;
        transaction.commit()?;
        Ok(verified.pin)
    }

    pub fn import_gossip(&self, gossip: &CheckpointGossip) -> Result<()> {
        gossip
            .checkpoint
            .verify_operator(&self.policy.operator_key)?;
        let key = self
            .policy
            .witness_keys
            .get(&gossip.witness_signature.witness_id)
            .ok_or(KeyringError::InvalidSignature)?;
        gossip.witness_signature.verify(&gossip.checkpoint, key)?;
        let now = self.clock.now()?;
        self.policy
            .validate_checkpoint_time(gossip.checkpoint.body.issued_at, now)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(conflict) = find_checkpoint_conflict(&transaction, &gossip.checkpoint, now)? {
            persist_conflict(&transaction, &conflict)?;
            transaction.commit()?;
            return Err(KeyringError::EquivocationDetected);
        }
        persist_gossip(&transaction, gossip)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn gossip_observations(&self) -> Result<Vec<CheckpointGossip>> {
        load_gossip(&*self.connection()?)
    }

    pub fn verify_key_for_artifact(
        &self,
        key_id: &KeyId,
        artifact_hash: &Hash,
        time_evidence: &ArtifactTimeEvidence,
    ) -> Result<KeyRecord> {
        let connection = self.connection()?;
        let state = rebuild_state(&connection, &self.policy, self.clock.now()?)?;
        Ok(state
            .verification_key_for_artifact(key_id, artifact_hash, time_evidence)?
            .clone())
    }

    /// Verify the complete router evidence for exact artifact bytes against a
    /// single retained verifier snapshot. This binds the artifact signature,
    /// router fence, trusted-time signature, referenced checkpoint, signing
    /// epoch, and historical key-validity interval in one operation.
    pub fn verify_artifact_signing_evidence(
        &self,
        artifact: &[u8],
        signature_evidence: &KeyringArtifactSignature,
        signed_time_anchor: &SignedArtifactTimeAnchor,
    ) -> Result<KeyRecord> {
        let now = self.clock.now()?;
        let connection = self.connection()?;
        let events = load_events(&connection)?;
        let checkpoints = load_checkpoints(&connection)?;
        let activation_commits = load_commits(&connection)?;
        let verified = verify_retained_history(
            &events,
            &checkpoints,
            &activation_commits,
            &self.policy,
            now,
            true,
        )?;
        let artifact_hash = crate::router::artifact_hash(artifact)?;
        if signature_evidence.artifact_hash != artifact_hash
            || signed_time_anchor.body.artifact_hash != artifact_hash
        {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
        verify_verifier_artifact_anchor_context(&checkpoints, signed_time_anchor)?;
        let time_verifier = self.policy.artifact_time_verifier(
            Arc::clone(&self.clock),
            self.policy.max_checkpoint_future_skew,
        )?;
        let time_evidence = time_verifier.verify(signed_time_anchor)?;
        if time_evidence.artifact_hash() != artifact_hash {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
        let epoch_key = verifier_key_for_epoch(
            &events,
            &activation_commits,
            signature_evidence.signing_epoch,
        )?;
        if epoch_key.body.key_id != signature_evidence.key_id {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
        signature_evidence.verify_artifact_bytes(&epoch_key.body.public_key, artifact)?;
        let record = verified.state.verification_key_for_artifact(
            &signature_evidence.key_id,
            &artifact_hash,
            &time_evidence,
        )?;
        if record.public_key != epoch_key.body.public_key {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
        Ok(record.clone())
    }

    pub fn pin(&self) -> Result<Option<KeyLogPin>> {
        load_pin(&*self.connection()?)
    }

    pub fn witnessed_state(&self) -> Result<Option<KeyLogState>> {
        let connection = self.connection()?;
        if load_events(&connection)?.is_empty() {
            return Ok(None);
        }
        rebuild_state(&connection, &self.policy, self.clock.now()?).map(Some)
    }

    pub fn conflicts(&self) -> Result<Vec<CheckpointEquivocationEvidence>> {
        load_conflicts(&*self.connection()?)
    }

    fn validate_startup(&self) -> Result<()> {
        let connection = self.connection()?;
        let events = load_events(&connection)?;
        let checkpoints = load_checkpoints(&connection)?;
        let commits = load_commits(&connection)?;
        let pin = load_pin(&connection)?;
        validate_retained_gossip(&connection, &self.policy, self.clock.now()?)?;
        if events.is_empty() {
            if !checkpoints.is_empty() || !commits.is_empty() || pin.is_some() {
                return Err(KeyringError::StateInvariant(
                    "empty verifier has retained verification state",
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
            true,
        )?;
        if pin.as_ref() != Some(&verified.pin) {
            return Err(KeyringError::StateInvariant(
                "verifier pin does not match retained history",
            ));
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

pub struct KeyLogAuditMonitor {
    verifier: SqlitePinnedKeyLogVerifier,
}

impl KeyLogAuditMonitor {
    #[must_use]
    pub fn new(verifier: SqlitePinnedKeyLogVerifier) -> Self {
        Self { verifier }
    }

    pub fn poll(&self, response: &KeyLogSyncResponse) -> Result<KeyLogPin> {
        self.verifier.apply_sync(response)
    }

    pub fn import_gossip(&self, gossip: &CheckpointGossip) -> Result<()> {
        self.verifier.import_gossip(gossip)
    }

    pub fn pin(&self) -> Result<Option<KeyLogPin>> {
        self.verifier.pin()
    }

    pub fn conflicts(&self) -> Result<Vec<CheckpointEquivocationEvidence>> {
        self.verifier.conflicts()
    }

    pub fn gossip_observations(&self) -> Result<Vec<CheckpointGossip>> {
        self.verifier.gossip_observations()
    }
}

fn rebuild_state(connection: &Connection, policy: &KeyLogPolicy, now: u64) -> Result<KeyLogState> {
    let checkpoints = load_checkpoints(connection)?;
    let events = load_events(connection)?;
    let commits = load_commits(connection)?;
    Ok(verify_retained_history(&events, &checkpoints, &commits, policy, now, true)?.state)
}

fn verify_verifier_artifact_anchor_context(
    checkpoints: &[SignedKeyLogCheckpoint],
    anchor: &SignedArtifactTimeAnchor,
) -> Result<()> {
    let (checkpoint_sequence, checkpoint_hash) = match &anchor.body.anchor {
        ArtifactTimeAnchorKind::KeyLogCheckpoint {
            checkpoint_sequence,
            checkpoint_hash,
        } => (checkpoint_sequence, checkpoint_hash),
        ArtifactTimeAnchorKind::External { .. } => return Ok(()),
        ArtifactTimeAnchorKind::ReceiptCheckpoint { .. } => {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
    };
    let checkpoint = checkpoints
        .iter()
        .find(|checkpoint| checkpoint.body.checkpoint_sequence == *checkpoint_sequence)
        .ok_or(KeyringError::InvalidArtifactTimeEvidence)?;
    if checkpoint.checkpoint_hash()? != *checkpoint_hash
        || checkpoint.body.issued_at > anchor.body.anchored_at
    {
        return Err(KeyringError::InvalidArtifactTimeEvidence);
    }
    Ok(())
}

fn verifier_key_for_epoch<'a>(
    events: &'a [SignedKeyLogEvent],
    activation_commits: &[SignedKeyActivationCommit],
    signing_epoch: u64,
) -> Result<&'a SignedKeyLogEvent> {
    if signing_epoch == 0 {
        return events
            .first()
            .ok_or(KeyringError::InvalidArtifactTimeEvidence);
    }
    let index = usize::try_from(
        signing_epoch
            .checked_sub(1)
            .ok_or(KeyringError::NumericRange)?,
    )
    .map_err(|_| KeyringError::NumericRange)?;
    let commit = activation_commits
        .get(index)
        .ok_or(KeyringError::InvalidArtifactTimeEvidence)?;
    events
        .iter()
        .find(|event| event.body.event_id == commit.body.event_id)
        .ok_or(KeyringError::InvalidArtifactTimeEvidence)
}

fn persist_verified(connection: &Connection, verified: &crate::sync::VerifiedKeyLog) -> Result<()> {
    for event in &verified.events {
        connection.execute(
            "INSERT OR IGNORE INTO verifier_events (sequence, canonical_envelope) VALUES (?1, ?2)",
            params![
                to_i64(event.body.sequence)?,
                event.canonical_envelope_bytes()?
            ],
        )?;
    }
    for checkpoint in &verified.checkpoints {
        connection.execute(
            "INSERT OR IGNORE INTO verifier_checkpoints (checkpoint_sequence, tree_size, checkpoint_hash, root_hash, canonical_checkpoint) VALUES (?1, ?2, ?3, ?4, ?5)",
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
            "INSERT OR IGNORE INTO verifier_activation_commits (signing_epoch, canonical_commit) VALUES (?1, ?2)",
            params![to_i64(commit.body.signing_epoch)?, commit.canonical_bytes()?],
        )?;
    }
    connection.execute(
        "INSERT INTO verifier_pin (singleton, checkpoint_sequence, tree_size, checkpoint_hash, root_hash, signing_epoch) VALUES (1, ?1, ?2, ?3, ?4, ?5) ON CONFLICT(singleton) DO UPDATE SET checkpoint_sequence = excluded.checkpoint_sequence, tree_size = excluded.tree_size, checkpoint_hash = excluded.checkpoint_hash, root_hash = excluded.root_hash, signing_epoch = excluded.signing_epoch",
        params![
            to_i64(verified.pin.checkpoint_sequence)?,
            to_i64(verified.pin.tree_size)?,
            verified.pin.checkpoint_hash.to_string(),
            verified.pin.root_hash.to_string(),
            to_i64(verified.pin.signing_epoch)?,
        ],
    )?;
    Ok(())
}

fn find_response_conflict(
    connection: &Connection,
    response: &KeyLogSyncResponse,
    detected_at: u64,
) -> Result<Option<CheckpointEquivocationEvidence>> {
    let mut sequences = BTreeMap::new();
    let mut tree_sizes = BTreeMap::new();
    for checkpoint in &response.checkpoints {
        if let Some(conflict) = find_checkpoint_conflict(connection, checkpoint, detected_at)? {
            return Ok(Some(conflict));
        }
        if let Some(first) = sequences.insert(checkpoint.body.checkpoint_sequence, checkpoint) {
            if first.checkpoint_hash()? != checkpoint.checkpoint_hash()? {
                return Ok(Some(evidence(
                    first.clone(),
                    checkpoint.clone(),
                    CheckpointConflictKind::CheckpointSequence,
                    detected_at,
                )));
            }
        }
        if let Some(first) = tree_sizes.insert(checkpoint.body.tree_size, checkpoint) {
            if first.checkpoint_hash()? != checkpoint.checkpoint_hash()? {
                return Ok(Some(evidence(
                    first.clone(),
                    checkpoint.clone(),
                    CheckpointConflictKind::TreeSize,
                    detected_at,
                )));
            }
        }
    }
    Ok(None)
}

fn find_checkpoint_conflict(
    connection: &Connection,
    candidate: &SignedKeyLogCheckpoint,
    detected_at: u64,
) -> Result<Option<CheckpointEquivocationEvidence>> {
    if let Some(first) = checkpoint_query(
        connection,
        "SELECT CASE WHEN length(canonical_checkpoint) <= 1048576 THEN canonical_checkpoint END FROM verifier_checkpoints WHERE checkpoint_sequence = ?1",
        to_i64(candidate.body.checkpoint_sequence)?,
    )? {
        if first.checkpoint_hash()? != candidate.checkpoint_hash()? {
            return Ok(Some(evidence(
                first,
                candidate.clone(),
                CheckpointConflictKind::CheckpointSequence,
                detected_at,
            )));
        }
    }
    if let Some(first) = gossip_checkpoint_query(
        connection,
        "SELECT CASE WHEN length(canonical_gossip) <= 1048576 THEN canonical_gossip END FROM verifier_gossip WHERE checkpoint_sequence = ?1 ORDER BY checkpoint_hash, witness_id LIMIT 1",
        to_i64(candidate.body.checkpoint_sequence)?,
    )? {
        if first.checkpoint_hash()? != candidate.checkpoint_hash()? {
            return Ok(Some(evidence(
                first,
                candidate.clone(),
                CheckpointConflictKind::CheckpointSequence,
                detected_at,
            )));
        }
    }
    if let Some(first) = checkpoint_query(
        connection,
        "SELECT CASE WHEN length(canonical_checkpoint) <= 1048576 THEN canonical_checkpoint END FROM verifier_checkpoints WHERE tree_size = ?1",
        to_i64(candidate.body.tree_size)?,
    )? {
        if first.checkpoint_hash()? != candidate.checkpoint_hash()? {
            return Ok(Some(evidence(
                first,
                candidate.clone(),
                CheckpointConflictKind::TreeSize,
                detected_at,
            )));
        }
    }
    if let Some(first) = gossip_checkpoint_query(
        connection,
        "SELECT CASE WHEN length(canonical_gossip) <= 1048576 THEN canonical_gossip END FROM verifier_gossip WHERE tree_size = ?1 ORDER BY checkpoint_hash, witness_id LIMIT 1",
        to_i64(candidate.body.tree_size)?,
    )? {
        if first.checkpoint_hash()? != candidate.checkpoint_hash()? {
            return Ok(Some(evidence(
                first,
                candidate.clone(),
                CheckpointConflictKind::TreeSize,
                detected_at,
            )));
        }
    }
    Ok(None)
}

fn evidence(
    first: SignedKeyLogCheckpoint,
    conflicting: SignedKeyLogCheckpoint,
    kind: CheckpointConflictKind,
    detected_at: u64,
) -> CheckpointEquivocationEvidence {
    CheckpointEquivocationEvidence {
        schema: CHECKPOINT_EQUIVOCATION_SCHEMA.to_string(),
        kind,
        first,
        conflicting,
        detected_at,
    }
}

fn persist_conflict(
    connection: &Connection,
    evidence: &CheckpointEquivocationEvidence,
) -> Result<()> {
    connection.execute(
        "INSERT OR IGNORE INTO verifier_conflicts (conflict_hash, canonical_evidence) VALUES (?1, ?2)",
        params![
            evidence.evidence_hash()?.to_string(),
            canonical_json_bytes(evidence)?,
        ],
    )?;
    Ok(())
}

fn checkpoint_query(
    connection: &Connection,
    sql: &str,
    value: i64,
) -> Result<Option<SignedKeyLogCheckpoint>> {
    connection
        .query_row(sql, [value], |row| row.get::<_, Option<Vec<u8>>>(0))
        .optional()?
        .flatten()
        .map(|bytes| SignedKeyLogCheckpoint::from_canonical_bytes(&bytes))
        .transpose()
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
        "INSERT OR IGNORE INTO verifier_gossip (checkpoint_hash, witness_id, checkpoint_sequence, tree_size, canonical_gossip) VALUES (?1, ?2, ?3, ?4, ?5)",
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
    load_bounded_rows(
        connection,
        "SELECT CASE WHEN length(canonical_gossip) <= 1048576 THEN canonical_gossip END FROM verifier_gossip ORDER BY checkpoint_sequence, checkpoint_hash, witness_id",
        crate::from_bounded_json,
    )
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

fn load_events(connection: &Connection) -> Result<Vec<SignedKeyLogEvent>> {
    load_bounded_rows(
        connection,
        "SELECT CASE WHEN length(canonical_envelope) <= 1048576 THEN canonical_envelope END FROM verifier_events ORDER BY sequence",
        SignedKeyLogEvent::from_canonical_envelope_bytes,
    )
}

fn load_checkpoints(connection: &Connection) -> Result<Vec<SignedKeyLogCheckpoint>> {
    load_bounded_rows(
        connection,
        "SELECT CASE WHEN length(canonical_checkpoint) <= 1048576 THEN canonical_checkpoint END FROM verifier_checkpoints ORDER BY checkpoint_sequence",
        SignedKeyLogCheckpoint::from_canonical_bytes,
    )
}

fn load_commits(connection: &Connection) -> Result<Vec<SignedKeyActivationCommit>> {
    load_bounded_rows(
        connection,
        "SELECT CASE WHEN length(canonical_commit) <= 1048576 THEN canonical_commit END FROM verifier_activation_commits ORDER BY signing_epoch",
        SignedKeyActivationCommit::from_canonical_bytes,
    )
}

fn load_bounded_rows<T>(
    connection: &Connection,
    sql: &str,
    parse: fn(&[u8]) -> Result<T>,
) -> Result<Vec<T>> {
    let mut statement = connection.prepare(sql)?;
    let rows = statement.query_map([], |row| row.get::<_, Option<Vec<u8>>>(0))?;
    let mut values = Vec::new();
    for row in rows {
        let bytes = row?.ok_or(KeyringError::StateInvariant(
            "verifier record exceeds byte limit",
        ))?;
        values.push(parse(&bytes)?);
    }
    Ok(values)
}

fn load_pin(connection: &Connection) -> Result<Option<KeyLogPin>> {
    connection
        .query_row(
            "SELECT checkpoint_sequence, tree_size, checkpoint_hash, root_hash, signing_epoch FROM verifier_pin WHERE singleton = 1",
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
            Ok(KeyLogPin {
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
    load_bounded_rows(
        connection,
        "SELECT CASE WHEN length(canonical_evidence) <= 1048576 THEN canonical_evidence END FROM verifier_conflicts ORDER BY conflict_hash",
        crate::from_bounded_json,
    )
}

fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| KeyringError::NumericRange)
}

fn from_i64(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| KeyringError::NumericRange)
}

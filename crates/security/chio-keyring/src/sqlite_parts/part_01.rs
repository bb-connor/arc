use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use chio_core_types::{
    canonical_json_bytes, Hash, MerkleTree, Signature, SigningAlgorithm, SigningBackend,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};

use crate::{
    AnchorId, ArtifactTimeAnchorBody, ArtifactTimeAnchorKind, CheckpointStage, EventId,
    KeyActivationCommitBody, KeyEnterpriseReceiptStage, KeyId, KeyLogCheckpointBody, KeyLogHead,
    KeyLogPin, KeyLogPolicy, KeyLogState, KeyLogSyncResponse, KeyringArtifactSignature,
    KeyringError, Result, SignedArtifactTimeAnchor, SignedKeyActivationCommit,
    SignedKeyEnterpriseReceipt, SignedKeyLogCheckpoint, SignedKeyLogEvent, SigningTopology,
    StoredCheckpoint, SystemTrustedClock, TrustedClock, WitnessId, WitnessSignature,
    WitnessedActivationSet, ARTIFACT_TIME_ANCHOR_SCHEMA, KEY_ACTIVATION_COMMIT_SCHEMA,
    KEY_LOG_CHECKPOINT_SCHEMA,
};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS keyring_policy_binding (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    witness_roster_binding TEXT NOT NULL,
    recovery_policy_binding TEXT NOT NULL,
    artifact_time_policy_binding TEXT NOT NULL,
    auditor_policy_binding TEXT NOT NULL,
    configuration_binding TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS key_events (
    sequence INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    canonical_envelope BLOB NOT NULL CHECK (length(canonical_envelope) <= 1048576),
    envelope_hash TEXT NOT NULL,
    leaf_hash TEXT NOT NULL,
    operation TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS key_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    active_key_id TEXT NOT NULL,
    pending_key_id TEXT,
    pending_event_id TEXT,
    signing_epoch INTEGER NOT NULL CHECK (signing_epoch >= 0),
    last_sequence INTEGER NOT NULL CHECK (last_sequence >= 0),
    last_event_hash TEXT NOT NULL,
    tree_size INTEGER NOT NULL CHECK (tree_size > 0),
    root_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS key_checkpoints (
    checkpoint_sequence INTEGER PRIMARY KEY,
    checkpoint_hash TEXT NOT NULL UNIQUE,
    tree_size INTEGER NOT NULL CHECK (tree_size > 0),
    root_hash TEXT NOT NULL,
    canonical_body BLOB NOT NULL CHECK (length(canonical_body) <= 1048576),
    operator_key_id TEXT NOT NULL,
    operator_algorithm TEXT NOT NULL,
    operator_signature TEXT NOT NULL,
    stage TEXT NOT NULL CHECK (stage IN ('pending', 'witnessed', 'activated'))
);
CREATE TABLE IF NOT EXISTS key_checkpoint_witnesses (
    checkpoint_hash TEXT NOT NULL,
    witness_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    signature TEXT NOT NULL,
    PRIMARY KEY (checkpoint_hash, witness_id),
    FOREIGN KEY (checkpoint_hash) REFERENCES key_checkpoints(checkpoint_hash) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS key_activations (
    event_id TEXT PRIMARY KEY,
    signing_epoch INTEGER NOT NULL UNIQUE CHECK (signing_epoch > 0),
    canonical_activation BLOB NOT NULL CHECK (length(canonical_activation) <= 1048576)
);
CREATE TABLE IF NOT EXISTS key_enterprise_receipts (
    receipt_id TEXT PRIMARY KEY,
    transaction_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_sequence INTEGER NOT NULL CHECK (event_sequence >= 0),
    stage TEXT NOT NULL CHECK (stage IN ('pending', 'active')),
    canonical_envelope BLOB NOT NULL CHECK (length(canonical_envelope) <= 1048576),
    UNIQUE (transaction_id, stage),
    FOREIGN KEY (event_id) REFERENCES key_events(event_id)
);
CREATE TRIGGER IF NOT EXISTS key_enterprise_receipts_no_update
BEFORE UPDATE ON key_enterprise_receipts
BEGIN
    SELECT RAISE(ABORT, 'key enterprise receipts are append-only');
END;
CREATE TRIGGER IF NOT EXISTS key_enterprise_receipts_no_delete
BEFORE DELETE ON key_enterprise_receipts
BEGIN
    SELECT RAISE(ABORT, 'key enterprise receipts are append-only');
END;
CREATE TABLE IF NOT EXISTS key_artifact_signatures (
    artifact_hash TEXT PRIMARY KEY,
    key_id TEXT NOT NULL,
    signing_epoch INTEGER NOT NULL CHECK (signing_epoch >= 0),
    canonical_signature BLOB NOT NULL CHECK (length(canonical_signature) <= 1048576)
);
CREATE TABLE IF NOT EXISTS key_artifact_time_anchors (
    artifact_hash TEXT PRIMARY KEY,
    canonical_anchor BLOB NOT NULL CHECK (length(canonical_anchor) <= 1048576),
    FOREIGN KEY (artifact_hash) REFERENCES key_artifact_signatures(artifact_hash) ON DELETE CASCADE
);
CREATE TRIGGER IF NOT EXISTS key_artifact_signatures_no_update
BEFORE UPDATE ON key_artifact_signatures
BEGIN
    SELECT RAISE(ABORT, 'key artifact signatures are append-only');
END;
CREATE TRIGGER IF NOT EXISTS key_artifact_signatures_no_delete
BEFORE DELETE ON key_artifact_signatures
BEGIN
    SELECT RAISE(ABORT, 'key artifact signatures are append-only');
END;
CREATE TRIGGER IF NOT EXISTS key_artifact_time_anchors_no_update
BEFORE UPDATE ON key_artifact_time_anchors
BEGIN
    SELECT RAISE(ABORT, 'key artifact time anchors are append-only');
END;
CREATE TRIGGER IF NOT EXISTS key_artifact_time_anchors_no_delete
BEFORE DELETE ON key_artifact_time_anchors
BEGIN
    SELECT RAISE(ABORT, 'key artifact time anchors are append-only');
END;
"#;

fn durable_state_exists(connection: &Connection) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM key_events UNION ALL SELECT 1 FROM key_state UNION ALL SELECT 1 FROM key_checkpoints UNION ALL SELECT 1 FROM key_activations UNION ALL SELECT 1 FROM key_enterprise_receipts UNION ALL SELECT 1 FROM key_artifact_signatures UNION ALL SELECT 1 FROM key_artifact_time_anchors LIMIT 1)",
        [],
        |row| row.get::<_, i64>(0),
    )? != 0)
}

fn selector_lock_path(database_path: &Path) -> PathBuf {
    let mut value = database_path.as_os_str().to_os_string();
    value.push(".chio-selector.lock");
    PathBuf::from(value)
}

fn acquire_selector_writer_lock(database_path: &Path) -> Result<File> {
    let lock_path = selector_lock_path(database_path);
    let mut create_options = OpenOptions::new();
    create_options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        create_options.mode(0o600);
    }
    let file = match create_options.open(&lock_path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            validate_selector_lock_path(&lock_path)?;
            OpenOptions::new().read(true).write(true).open(&lock_path)?
        }
        Err(error) => return Err(KeyringError::Io(error)),
    };
    validate_open_selector_lock(&lock_path, &file)?;
    file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => KeyringError::StateInvariant(
            "another local key selector writer already owns the durable log",
        ),
        TryLockError::Error(error) => KeyringError::Io(error),
    })?;
    Ok(file)
}

fn validate_selector_lock_path(lock_path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(lock_path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(KeyringError::StateInvariant(
            "key selector lock must be a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
            return Err(KeyringError::StateInvariant(
                "key selector lock must be private and singly linked",
            ));
        }
    }
    Ok(())
}

fn validate_open_selector_lock(lock_path: &Path, file: &File) -> Result<()> {
    validate_selector_lock_path(lock_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let path_metadata = std::fs::symlink_metadata(lock_path)?;
        let file_metadata = file.metadata()?;
        if path_metadata.dev() != file_metadata.dev() || path_metadata.ino() != file_metadata.ino()
        {
            return Err(KeyringError::StateInvariant(
                "key selector lock changed while it was opened",
            ));
        }
    }
    Ok(())
}

pub struct SqliteKeyLogStore {
    connection: Mutex<Connection>,
    policy: KeyLogPolicy,
    clock: Arc<dyn TrustedClock>,
    storage_file: crate::DurableSqliteFile,
    _selector_lock: Option<File>,
}

impl SqliteKeyLogStore {
    pub fn configuration_binding(&self) -> Result<Hash> {
        self.policy.configuration_binding()
    }

    pub fn witness_threshold(&self) -> Result<usize> {
        self.policy.witness_threshold()
    }

    pub fn policy_clone(&self) -> KeyLogPolicy {
        self.policy.clone()
    }

    #[must_use]
    pub fn storage_identity(&self) -> Hash {
        self.storage_file.identity()
    }

    pub fn open(path: impl AsRef<Path>, policy: KeyLogPolicy) -> Result<Self> {
        Self::open_with_clock(
            path,
            policy,
            SigningTopology::LocalSingleWriter,
            Arc::new(SystemTrustedClock),
        )
    }

    pub fn open_existing(path: impl AsRef<Path>, policy: KeyLogPolicy) -> Result<Self> {
        let path = path.as_ref();
        crate::require_existing_durable_sqlite_path(path)?;
        Self::open(path, policy)
    }

    /// Opens a strictly read-only view without acquiring the selector-writer
    /// fence. Observers can verify durable history but cannot mutate the
    /// authoritative key selector.
    pub fn open_observer(path: impl AsRef<Path>, policy: KeyLogPolicy) -> Result<Self> {
        let path = path.as_ref();
        crate::require_existing_durable_sqlite_path(path)?;
        let storage_file = crate::open_durable_sqlite_file(path, false, false)?;
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        storage_file.validate_path_binding(path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA query_only = ON;")?;
        let durable_state_exists = durable_state_exists(&connection)?;
        crate::persist_or_validate_policy_binding(&connection, &policy, durable_state_exists)?;
        let store = Self {
            connection: Mutex::new(connection),
            policy,
            clock: Arc::new(SystemTrustedClock),
            storage_file,
            _selector_lock: None,
        };
        store.validate_startup()?;
        Ok(store)
    }

    pub fn open_with_topology(
        path: impl AsRef<Path>,
        policy: KeyLogPolicy,
        topology: SigningTopology,
    ) -> Result<Self> {
        Self::open_with_clock(path, policy, topology, Arc::new(SystemTrustedClock))
    }

    pub fn open_with_clock(
        path: impl AsRef<Path>,
        policy: KeyLogPolicy,
        topology: SigningTopology,
        clock: Arc<dyn TrustedClock>,
    ) -> Result<Self> {
        let path = path.as_ref();
        if topology != SigningTopology::LocalSingleWriter {
            return Err(KeyringError::StateInvariant(
                "local SQLite selector supports one signing writer",
            ));
        }
        let storage_file = crate::open_durable_sqlite_file(path, true, true)?;
        let selector_lock = acquire_selector_writer_lock(path)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        storage_file.validate_path_binding(path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;",
        )?;
        connection.execute_batch(SCHEMA)?;
        let durable_state_exists = durable_state_exists(&connection)?;
        crate::persist_or_validate_policy_binding(&connection, &policy, durable_state_exists)?;
        let store = Self {
            connection: Mutex::new(connection),
            policy,
            clock,
            storage_file,
            _selector_lock: Some(selector_lock),
        };
        store.validate_startup()?;
        Ok(store)
    }

    pub fn append_event(
        &self,
        event: &SignedKeyLogEvent,
        operator: &dyn SigningBackend,
    ) -> Result<SignedKeyLogCheckpoint> {
        if operator.public_key() != self.policy.operator_key
            || operator.algorithm() != self.policy.operator_key.algorithm()
        {
            return Err(KeyringError::InvalidCheckpoint(
                "operator backend does not match configured key",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut events = load_events_from(&transaction)?;
        if let Ok(sequence) = usize::try_from(event.body.sequence) {
            if let Some(existing) = events.get(sequence) {
                if existing != event {
                    return Err(KeyringError::SequenceMismatch {
                        expected: u64::try_from(events.len())
                            .map_err(|_| KeyringError::NumericRange)?,
                        actual: event.body.sequence,
                    });
                }
                let checkpoint = load_checkpoints_from(&transaction)?
                    .get(sequence)
                    .map(|stored| stored.checkpoint.clone())
                    .ok_or(KeyringError::StateInvariant(
                        "persisted event is missing its checkpoint",
                    ))?;
                let checkpoints = load_checkpoints_from(&transaction)?
                    .into_iter()
                    .map(|stored| stored.checkpoint)
                    .collect::<Vec<_>>();
                let activation_commits = load_activation_commits_from(&transaction)?;
                let history = WitnessedActivationSet::verify_complete(
                    &events,
                    &checkpoints,
                    &activation_commits,
                    &self.policy,
                )?;
                KeyLogState::replay(events.iter(), &history, &self.policy)?;
                let receipt = enterprise_receipt_for_event_stage(
                    &transaction,
                    &event.body.event_id,
                    KeyEnterpriseReceiptStage::Pending,
                )?
                .ok_or(KeyringError::StateInvariant(
                    "persisted event is missing its pending enterprise receipt",
                ))?;
                receipt.verify_against(event, &checkpoint, &self.policy, None)?;
                transaction.rollback()?;
                return Ok(checkpoint);
            }
        }
        events.push(event.clone());
        let leaves = canonical_event_leaves(&events)?;
        let tree = MerkleTree::from_leaves(&leaves)?;
        let root_hash = tree.root();
        let tree_size = u64::try_from(events.len()).map_err(|_| KeyringError::NumericRange)?;
        let previous_checkpoints = load_checkpoints_from(&transaction)?;
        let checkpoint_sequence =
            u64::try_from(previous_checkpoints.len()).map_err(|_| KeyringError::NumericRange)?;
        let previous_checkpoint_hash = previous_checkpoints
            .last()
            .map(|stored| stored.checkpoint.checkpoint_hash())
            .transpose()?;
        let last_checkpoint_time = previous_checkpoints
            .last()
            .map(|stored| stored.checkpoint.body.issued_at);
        let checkpoint_issued_at = self.clock.now()?;
        self.policy
            .validate_checkpoint_time(checkpoint_issued_at, checkpoint_issued_at)?;
        if checkpoint_issued_at < event.body.issued_at
            || last_checkpoint_time.is_some_and(|last| checkpoint_issued_at < last)
        {
            return Err(KeyringError::InvalidTimeOrdering);
        }
        let checkpoint = SignedKeyLogCheckpoint::sign(
            KeyLogCheckpointBody {
                schema: KEY_LOG_CHECKPOINT_SCHEMA.to_string(),
                log_id: self.policy.log_id.clone(),
                checkpoint_sequence,
                tree_size,
                root_hash,
                previous_checkpoint_hash,
                issued_at: checkpoint_issued_at,
            },
            operator,
        )?;
        checkpoint.validate(crate::KeyLogCheckpointExpectation {
            log_id: &self.policy.log_id,
            sequence: checkpoint_sequence,
            tree_size,
            root: &root_hash,
            previous_checkpoint_hash: previous_checkpoint_hash.as_ref(),
            last_issued_at: last_checkpoint_time,
        })?;
        checkpoint.verify_operator(&self.policy.operator_key)?;

        let mut checkpoints = previous_checkpoints
            .into_iter()
            .map(|stored| stored.checkpoint)
            .collect::<Vec<_>>();
        checkpoints.push(checkpoint.clone());
        let activation_commits = load_activation_commits_from(&transaction)?;
        let history = WitnessedActivationSet::verify_complete(
            &events,
            &checkpoints,
            &activation_commits,
            &self.policy,
        )?;
        let state = KeyLogState::replay(events.iter(), &history, &self.policy)?;
        let source_receipt_ids =
            latest_enterprise_receipt_lineage(&transaction, event.body.sequence)?;
        let receipt = SignedKeyEnterpriseReceipt::pending(
            event,
            &checkpoint,
            &self.policy,
            source_receipt_ids,
            operator,
        )?;

        insert_event(&transaction, event)?;
        insert_checkpoint(&transaction, &checkpoint, CheckpointStage::Pending)?;
        insert_enterprise_receipt(&transaction, &receipt)?;
        persist_state(&transaction, &state, &events, root_hash)?;
        transaction.commit()?;
        Ok(checkpoint)
    }

    pub fn store_witness_signature(
        &self,
        checkpoint_hash: &Hash,
        witness: &WitnessSignature,
    ) -> Result<StoredCheckpoint> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut stored = checkpoint_by_hash(&transaction, checkpoint_hash)?
            .ok_or(KeyringError::InvalidCheckpoint("checkpoint is unknown"))?;
        stored
            .checkpoint
            .verify_operator(&self.policy.operator_key)?;
        let witness_key = self
            .policy
            .witness_keys
            .get(&witness.witness_id)
            .ok_or(KeyringError::InvalidSignature)?;
        witness.verify(&stored.checkpoint, witness_key)?;

        let existing = transaction
            .query_row(
                "SELECT algorithm, signature FROM key_checkpoint_witnesses WHERE checkpoint_hash = ?1 AND witness_id = ?2",
                params![checkpoint_hash.to_string(), witness.witness_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        if let Some((algorithm, signature)) = existing {
            if algorithm != algorithm_name(witness.algorithm)
                || signature != witness.signature.to_hex()
            {
                return Err(KeyringError::InvalidSignature);
            }
        } else {
            transaction.execute(
                "INSERT INTO key_checkpoint_witnesses (checkpoint_hash, witness_id, algorithm, signature) VALUES (?1, ?2, ?3, ?4)",
                params![
                    checkpoint_hash.to_string(),
                    witness.witness_id.as_str(),
                    algorithm_name(witness.algorithm),
                    witness.signature.to_hex(),
                ],
            )?;
        }

        stored = checkpoint_by_hash(&transaction, checkpoint_hash)?
            .ok_or(KeyringError::InvalidCheckpoint("checkpoint disappeared"))?;
        stored
            .checkpoint
            .verify_witness_signatures(&self.policy.witness_keys)?;
        let threshold = self.policy.witness_threshold()?;
        if stored.checkpoint.witness_signatures.len() >= threshold {
            stored
                .checkpoint
                .verify_witnesses(&self.policy.witness_keys)?;
            if stored.stage == CheckpointStage::Pending {
                stored.stage = CheckpointStage::Witnessed;
                transaction.execute(
                    "UPDATE key_checkpoints SET stage = 'witnessed' WHERE checkpoint_hash = ?1",
                    [checkpoint_hash.to_string()],
                )?;
            }
        }
        transaction.commit()?;
        Ok(stored)
    }

    pub fn activate_rotation(
        &self,
        event_id: &EventId,
        checkpoint_hash: &Hash,
        operator: &dyn SigningBackend,
    ) -> Result<KeyLogState> {
        if operator.public_key() != self.policy.operator_key
            || operator.algorithm() != self.policy.operator_key.algorithm()
        {
            return Err(KeyringError::InvalidCheckpoint(
                "operator backend does not match configured key",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let events = load_events_from(&transaction)?;
        let checkpoints = load_checkpoints_from(&transaction)?;
        let checkpoint_envelopes = checkpoints
            .iter()
            .map(|stored| stored.checkpoint.clone())
            .collect::<Vec<_>>();
        let now = self.clock.now()?;
        for checkpoint in &checkpoint_envelopes {
            self.policy
                .validate_checkpoint_time(checkpoint.body.issued_at, now)?;
        }
        let mut activation_commits = load_activation_commits_from(&transaction)?;
        if let Some(existing) = activation_commits
            .iter()
            .find(|commit| &commit.body.event_id == event_id)
        {
            if existing.body.checkpoint_hash != *checkpoint_hash {
                return Err(KeyringError::InvalidWitnessActivation);
            }
            let history = WitnessedActivationSet::verify_complete(
                &events,
                &checkpoint_envelopes,
                &activation_commits,
                &self.policy,
            )?;
            let state = KeyLogState::replay(events.iter(), &history, &self.policy)?;
            let event = events
                .iter()
                .find(|event| &event.body.event_id == event_id)
                .ok_or(KeyringError::StateInvariant(
                    "activated event is absent from the durable log",
                ))?;
            let checkpoint = checkpoint_envelopes
                .iter()
                .find(|checkpoint| checkpoint.checkpoint_hash().ok() == Some(*checkpoint_hash))
                .ok_or(KeyringError::StateInvariant(
                    "activated checkpoint is absent from the durable log",
                ))?;
            let receipt = enterprise_receipt_for_event_stage(
                &transaction,
                event_id,
                KeyEnterpriseReceiptStage::Active,
            )?
            .ok_or(KeyringError::StateInvariant(
                "activated event is missing its enterprise receipt",
            ))?;
            receipt.verify_against(event, checkpoint, &self.policy, Some(existing))?;
            transaction.rollback()?;
            return Ok(state);
        }
        let stored = checkpoints
            .iter()
            .find(|stored| {
                stored.checkpoint.checkpoint_hash().ok().as_ref() == Some(checkpoint_hash)
            })
            .cloned()
            .ok_or(KeyringError::InvalidCheckpoint("checkpoint is unknown"))?;
        if stored.stage != CheckpointStage::Witnessed {
            return Err(KeyringError::InvalidWitnessActivation);
        }
        stored
            .checkpoint
            .verify_operator(&self.policy.operator_key)?;
        stored
            .checkpoint
            .verify_witnesses(&self.policy.witness_keys)?;
        let event = events
            .iter()
            .find(|event| &event.body.event_id == event_id)
            .ok_or(KeyringError::InvalidWitnessActivation)?;
        let event_tree_size = event
            .body
            .sequence
            .checked_add(1)
            .ok_or(KeyringError::NumericRange)?;
        if stored.checkpoint.body.tree_size != event_tree_size
            || stored.checkpoint.body.checkpoint_sequence != event.body.sequence
        {
            return Err(KeyringError::InvalidWitnessActivation);
        }
        let mut committed_at = self.clock.now()?;
        if let Some(latest_anchor) = latest_verified_artifact_anchor_time_for_epoch(
            &transaction,
            u64::try_from(activation_commits.len()).map_err(|_| KeyringError::NumericRange)?,
            &self.policy,
            &self.clock,
        )? {
            committed_at = committed_at.max(
                latest_anchor
                    .checked_add(1)
                    .ok_or(KeyringError::NumericRange)?,
            );
        }
        self.policy
            .validate_checkpoint_time(stored.checkpoint.body.issued_at, committed_at)?;
        if activation_commits
            .last()
            .is_some_and(|previous| committed_at < previous.body.committed_at)
        {
            return Err(KeyringError::InvalidTimeOrdering);
        }
        let signing_epoch = u64::try_from(activation_commits.len())
            .map_err(|_| KeyringError::NumericRange)?
            .checked_add(1)
            .ok_or(KeyringError::NumericRange)?;
        let activation = SignedKeyActivationCommit::sign(
            KeyActivationCommitBody {
                schema: KEY_ACTIVATION_COMMIT_SCHEMA.to_string(),
                log_id: self.policy.log_id.clone(),
                event_id: event_id.clone(),
                checkpoint_hash: *checkpoint_hash,
                checkpoint_body_hash: stored.checkpoint.checkpoint_body_hash()?,
                checkpoint_sequence: stored.checkpoint.body.checkpoint_sequence,
                tree_size: stored.checkpoint.body.tree_size,
                root_hash: stored.checkpoint.body.root_hash,
                event_leaf_hash: event.merkle_leaf_hash()?,
                witness_set_hash: stored.checkpoint.witness_set_hash()?,
                witness_signatures: stored.checkpoint.witness_signatures.clone(),
                committed_at,
                signing_epoch,
            },
            operator,
        )?;
        activation_commits.push(activation.clone());
        let history = WitnessedActivationSet::verify_complete(
            &events,
            &checkpoint_envelopes,
            &activation_commits,
            &self.policy,
        )?;
        let state = KeyLogState::replay(events.iter(), &history, &self.policy)?;
        let pending_receipt = enterprise_receipt_for_event_stage(
            &transaction,
            event_id,
            KeyEnterpriseReceiptStage::Pending,
        )?
        .ok_or(KeyringError::StateInvariant(
            "activation is missing its pending enterprise receipt",
        ))?;
        let receipt = SignedKeyEnterpriseReceipt::active(
            event,
            &stored.checkpoint,
            &activation,
            &self.policy,
            vec![pending_receipt.body.receipt_id],
            operator,
        )?;
        let canonical_activation = activation.canonical_bytes()?;
        transaction.execute(
            "INSERT INTO key_activations (event_id, signing_epoch, canonical_activation) VALUES (?1, ?2, ?3)",
            params![event_id.as_str(), to_i64(signing_epoch)?, canonical_activation],
        )?;
        insert_enterprise_receipt(&transaction, &receipt)?;
        transaction.execute(
            "UPDATE key_checkpoints SET stage = 'activated' WHERE checkpoint_hash = ?1",
            [checkpoint_hash.to_string()],
        )?;
        let root_hash = merkle_root(&events)?;
        persist_state(&transaction, &state, &events, root_hash)?;
        transaction.commit()?;
        Ok(state)
    }

    pub fn load_events(&self) -> Result<Vec<SignedKeyLogEvent>> {
        load_events_from(&*self.connection()?)
    }

    pub fn load_checkpoints(&self) -> Result<Vec<StoredCheckpoint>> {
        load_checkpoints_from(&*self.connection()?)
    }

    pub fn verified_checkpoint_stage(&self, checkpoint_hash: &Hash) -> Result<CheckpointStage> {
        let stored = checkpoint_by_hash(&*self.connection()?, checkpoint_hash)?
            .ok_or(KeyringError::InvalidCheckpoint("checkpoint is unknown"))?;
        stored
            .checkpoint
            .verify_operator(&self.policy.operator_key)?;
        stored
            .checkpoint
            .verify_witness_signatures(&self.policy.witness_keys)?;
        if matches!(
            stored.stage,
            CheckpointStage::Witnessed | CheckpointStage::Activated
        ) {
            stored
                .checkpoint
                .verify_witnesses(&self.policy.witness_keys)?;
        } else if stored.checkpoint.witness_signatures.len() >= self.policy.witness_threshold()? {
            return Err(KeyringError::StateInvariant(
                "pending checkpoint already has a durable witness quorum",
            ));
        }
        Ok(stored.stage)
    }

    pub fn load_enterprise_receipts(&self) -> Result<Vec<SignedKeyEnterpriseReceipt>> {
        let connection = self.connection()?;
        let receipts = load_enterprise_receipts_from(&connection)?;
        validate_enterprise_receipts(
            &self.policy,
            &load_events_from(&connection)?,
            &load_checkpoints_from(&connection)?,
            &load_activation_commits_from(&connection)?,
            &receipts,
        )?;
        Ok(receipts)
    }

    pub fn load_enterprise_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<SignedKeyEnterpriseReceipt>> {
        let connection = self.connection()?;
        let receipt = enterprise_receipt_by_id(&connection, receipt_id)?;
        if let Some(receipt) = &receipt {
            receipt.verify_operator(&self.policy.operator_key)?;
        }
        Ok(receipt)
    }

    pub fn head_pin(&self) -> Result<Option<KeyLogPin>> {
        let connection = self.connection()?;
        let checkpoints = load_checkpoints_from(&connection)?;
        let Some(stored) = checkpoints.last() else {
            return Ok(None);
        };
        let signing_epoch = u64::try_from(load_activation_commits_from(&connection)?.len())
            .map_err(|_| KeyringError::NumericRange)?;
        Ok(Some(KeyLogPin {
            checkpoint_sequence: stored.checkpoint.body.checkpoint_sequence,
            tree_size: stored.checkpoint.body.tree_size,
            checkpoint_hash: stored.checkpoint.checkpoint_hash()?,
            root_hash: stored.checkpoint.body.root_hash,
            signing_epoch,
        }))
    }

    /// Returns the newest quorum-accepted checkpoint, excluding a pending
    /// operator tail that has not yet crossed the witness threshold.
    pub fn latest_accepted_pin(&self) -> Result<Option<KeyLogPin>> {
        let connection = self.connection()?;
        let checkpoints = load_checkpoints_from(&connection)?;
        let Some(stored) = checkpoints
            .iter()
            .rev()
            .find(|stored| stored.stage != CheckpointStage::Pending)
        else {
            return Ok(None);
        };
        let activation_commits = load_activation_commits_from(&connection)?;
        let signing_epoch = u64::try_from(
            activation_commits
                .iter()
                .filter(|commit| {
                    commit.body.checkpoint_sequence <= stored.checkpoint.body.checkpoint_sequence
                })
                .count(),
        )
        .map_err(|_| KeyringError::NumericRange)?;
        Ok(Some(KeyLogPin {
            checkpoint_sequence: stored.checkpoint.body.checkpoint_sequence,
            tree_size: stored.checkpoint.body.tree_size,
            checkpoint_hash: stored.checkpoint.checkpoint_hash()?,
            root_hash: stored.checkpoint.body.root_hash,
            signing_epoch,
        }))
    }

    pub fn head_stage(&self) -> Result<Option<CheckpointStage>> {
        Ok(load_checkpoints_from(&*self.connection()?)?
            .last()
            .map(|stored| stored.stage))
    }

    pub fn synchronization_response(&self, base: Option<&KeyLogPin>) -> Result<KeyLogSyncResponse> {
        let connection = self.connection()?;
        let events = load_events_from(&connection)?;
        let checkpoints = load_checkpoints_from(&connection)?
            .into_iter()
            .map(|stored| stored.checkpoint)
            .collect::<Vec<_>>();
        let activation_commits = load_activation_commits_from(&connection)?;
        if events.is_empty() || events.len() != checkpoints.len() {
            return Err(KeyringError::StateInvariant(
                "key log cannot produce a synchronization response",
            ));
        }
        let now = self.clock.now()?;
        for checkpoint in &checkpoints {
            self.policy
                .validate_checkpoint_time(checkpoint.body.issued_at, now)?;
        }
        let history = WitnessedActivationSet::verify_complete(
            &events,
            &checkpoints,
            &activation_commits,
            &self.policy,
        )?;
        KeyLogState::replay(events.iter(), &history, &self.policy)?;

        let (checkpoint_start, event_start, commit_start, base_checkpoint_hash) =
            if let Some(pin) = base {
                let checkpoint_index = usize::try_from(pin.checkpoint_sequence)
                    .map_err(|_| KeyringError::NumericRange)?;
                let checkpoint =
                    checkpoints
                        .get(checkpoint_index)
                        .ok_or(KeyringError::InvalidCheckpoint(
                            "synchronization pin is unknown",
                        ))?;
                let expected_signing_epoch = u64::try_from(
                    activation_commits
                        .iter()
                        .filter(|commit| commit.body.checkpoint_sequence <= pin.checkpoint_sequence)
                        .count(),
                )
                .map_err(|_| KeyringError::NumericRange)?;
                if checkpoint.checkpoint_hash()? != pin.checkpoint_hash
                    || checkpoint.body.tree_size != pin.tree_size
                    || checkpoint.body.root_hash != pin.root_hash
                    || pin.signing_epoch > expected_signing_epoch
                {
                    return Err(KeyringError::InvalidCheckpoint(
                        "synchronization pin does not match durable history",
                    ));
                }
                (
                    checkpoint_index
                        .checked_add(1)
                        .ok_or(KeyringError::NumericRange)?,
                    usize::try_from(pin.tree_size).map_err(|_| KeyringError::NumericRange)?,
                    usize::try_from(pin.signing_epoch).map_err(|_| KeyringError::NumericRange)?,
                    Some(pin.checkpoint_hash),
                )
            } else {
                (0, 0, 0, None)
            };

        let maximum_page_end = crate::sync::synchronization_page_end(event_start, events.len())?;
        if maximum_page_end <= event_start {
            let maximum_commit_end = commit_start
                .checked_add(crate::sync::MAX_SYNC_ITEMS)
                .map_or(activation_commits.len(), |end| {
                    end.min(activation_commits.len())
                });
            let mut commit_end = maximum_commit_end;
            loop {
                if commit_end == commit_start && commit_start < activation_commits.len() {
                    return Err(KeyringError::Canonical(
                        "one key-log activation commit exceeds the 1048576-byte page limit"
                            .to_string(),
                    ));
                }
                let response = KeyLogSyncResponse {
                    base_checkpoint_hash,
                    checkpoints: Vec::new(),
                    event_envelopes: Vec::new(),
                    activation_commits: activation_commits[commit_start..commit_end].to_vec(),
                    consistency_proof: None,
                };
                if canonical_json_bytes(&response)?.len() <= crate::MAX_CANONICAL_RECORD_BYTES {
                    response.validate_bounds()?;
                    return Ok(response);
                }
                commit_end = commit_start + (commit_end - commit_start) / 2;
            }
        }
        let mut lower = event_start
            .checked_add(1)
            .ok_or(KeyringError::NumericRange)?;
        let mut upper = maximum_page_end;
        let mut response = None;
        while lower <= upper {
            let candidate_end = lower + (upper - lower) / 2;
            let candidate = build_sync_response_page(
                &events,
                &checkpoints,
                &activation_commits,
                SyncPageWindow {
                    checkpoint_start,
                    event_start,
                    commit_start,
                    base_checkpoint_hash,
                    page_end: candidate_end,
                },
            )?;
            if canonical_json_bytes(&candidate)?.len() <= crate::MAX_CANONICAL_RECORD_BYTES {
                response = Some(candidate);
                lower = candidate_end
                    .checked_add(1)
                    .ok_or(KeyringError::NumericRange)?;
            } else {
                upper = candidate_end.saturating_sub(1);
            }
        }
        let response = response.ok_or_else(|| {
            KeyringError::Canonical(
                "one key-log synchronization record exceeds the 1048576-byte page limit"
                    .to_string(),
            )
        })?;
        response.validate_bounds()?;
        Ok(response)
    }

    pub fn load_state(&self) -> Result<Option<KeyLogState>> {
        let connection = self.connection()?;
        let events = load_events_from(&connection)?;
        if events.is_empty() {
            return Ok(None);
        }
        let checkpoints = load_checkpoints_from(&connection)?;
        let checkpoint_envelopes = checkpoints
            .into_iter()
            .map(|stored| stored.checkpoint)
            .collect::<Vec<_>>();
        let activation_commits = load_activation_commits_from(&connection)?;
        let history = WitnessedActivationSet::verify_complete(
            &events,
            &checkpoint_envelopes,
            &activation_commits,
            &self.policy,
        )?;
        Ok(Some(KeyLogState::replay(
            events.iter(),
            &history,
            &self.policy,
        )?))
    }

    pub fn head(&self) -> Result<Option<KeyLogHead>> {
        load_head_from(&*self.connection()?)
    }

    pub fn load_artifact_signatures(&self) -> Result<Vec<KeyringArtifactSignature>> {
        let connection = self.connection()?;
        let events = load_events_from(&connection)?;
        let checkpoints = load_checkpoints_from(&connection)?
            .into_iter()
            .map(|stored| stored.checkpoint)
            .collect::<Vec<_>>();
        let activation_commits = load_activation_commits_from(&connection)?;
        let history = WitnessedActivationSet::verify_complete(
            &events,
            &checkpoints,
            &activation_commits,
            &self.policy,
        )?;
        KeyLogState::replay(events.iter(), &history, &self.policy)?;
        let signatures = load_artifact_signatures_from(&connection)?;
        verify_artifact_signatures(&events, &activation_commits, &signatures)?;
        Ok(signatures)
    }

    pub fn validate_artifact_time_signer(
        &self,
        anchor_id: &AnchorId,
        public_key: &chio_core_types::PublicKey,
    ) -> Result<()> {
        if self.policy.artifact_time_key(anchor_id) != Some(public_key) {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
        Ok(())
    }

    pub fn build_local_artifact_time_anchor(
        &self,
        artifact_hash: Hash,
        anchor_id: &AnchorId,
        signer: &dyn SigningBackend,
    ) -> Result<SignedArtifactTimeAnchor> {
        self.validate_artifact_time_signer(anchor_id, &signer.public_key())?;
        let connection = self.connection()?;
        let stored = load_checkpoints_from(&connection)?
            .into_iter()
            .rfind(|stored| stored.stage != CheckpointStage::Pending)
            .ok_or(KeyringError::StateInvariant(
                "artifact signing requires a witnessed key-log checkpoint",
            ))?;
        stored
            .checkpoint
            .verify_operator(&self.policy.operator_key)?;
        stored
            .checkpoint
            .verify_witnesses(&self.policy.witness_keys)?;
        let anchored_at = self.clock.now()?;
        if anchored_at < stored.checkpoint.body.issued_at {
            return Err(KeyringError::InvalidTimeOrdering);
        }
        let checkpoint_hash = stored.checkpoint.checkpoint_hash()?;
        let anchor = SignedArtifactTimeAnchor::sign(
            ArtifactTimeAnchorBody {
                schema: ARTIFACT_TIME_ANCHOR_SCHEMA.to_string(),
                anchor_id: anchor_id.clone(),
                artifact_hash,
                anchored_at,
                anchor: ArtifactTimeAnchorKind::KeyLogCheckpoint {
                    checkpoint_sequence: stored.checkpoint.body.checkpoint_sequence,
                    checkpoint_hash,
                },
            },
            signer,
        )?;
        let verifier = self.policy.artifact_time_verifier(
            Arc::clone(&self.clock),
            self.policy.max_checkpoint_future_skew,
        )?;
        verifier.verify(&anchor)?;
        verify_artifact_anchor_context(&connection, &anchor)?;
        Ok(anchor)
    }

    pub fn verify_artifact_with_trusted_time(
        &self,
        artifact: &[u8],
        expected_issuer: &chio_core_types::PublicKey,
        expected_signature: &Signature,
    ) -> Result<chio_core_types::PublicKey> {
        let connection = self.connection()?;
        let events = load_events_from(&connection)?;
        let checkpoints = load_checkpoints_from(&connection)?
            .into_iter()
            .map(|stored| stored.checkpoint)
            .collect::<Vec<_>>();
        let activation_commits = load_activation_commits_from(&connection)?;
        let history = WitnessedActivationSet::verify_complete(
            &events,
            &checkpoints,
            &activation_commits,
            &self.policy,
        )?;
        let state = KeyLogState::replay(events.iter(), &history, &self.policy)?;
        let artifact_hash = crate::router::artifact_hash(artifact)?;
        let canonical = connection
            .query_row(
                "SELECT CASE WHEN length(canonical_signature) <= 1048576 THEN canonical_signature END FROM key_artifact_signatures WHERE artifact_hash = ?1",
                [artifact_hash.to_string()],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .flatten()
            .ok_or(KeyringError::InvalidArtifactTimeEvidence)?;
        let evidence = KeyringArtifactSignature::from_canonical_bytes(&canonical)?;
        let epoch_key = key_for_epoch(&events, &activation_commits, evidence.signing_epoch)?;
        if evidence.artifact_signature != *expected_signature
            || epoch_key.body.public_key != *expected_issuer
            || epoch_key.body.key_id != evidence.key_id
        {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
        evidence.verify_artifact_bytes(expected_issuer, artifact)?;
        let signed_anchor = load_artifact_time_anchor(&connection, &artifact_hash)?
            .ok_or(KeyringError::InvalidArtifactTimeEvidence)?;
        verify_artifact_anchor_context(&connection, &signed_anchor)?;
        let verifier = self.policy.artifact_time_verifier(
            Arc::clone(&self.clock),
            self.policy.max_checkpoint_future_skew,
        )?;
        let time_evidence = verifier.verify(&signed_anchor)?;
        let record = state.verification_key_for_artifact(
            &evidence.key_id,
            &artifact_hash,
            &time_evidence,
        )?;
        if record.public_key != *expected_issuer {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
        Ok(record.public_key.clone())
    }

    pub fn persist_artifact_time_anchor(
        &self,
        anchor: &SignedArtifactTimeAnchor,
    ) -> Result<SignedArtifactTimeAnchor> {
        let verifier = self.policy.artifact_time_verifier(
            Arc::clone(&self.clock),
            self.policy.max_checkpoint_future_skew,
        )?;
        let evidence = verifier.verify(anchor)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_artifact_anchor_context(&transaction, anchor)?;
        let artifact_exists = transaction
            .query_row(
                "SELECT 1 FROM key_artifact_signatures WHERE artifact_hash = ?1",
                [evidence.artifact_hash().to_string()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !artifact_exists {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
        let canonical = canonical_json_bytes(anchor)?;
        if let Some(existing) = load_artifact_time_anchor(&transaction, &evidence.artifact_hash())?
        {
            if canonical_json_bytes(&existing)? != canonical {
                return Err(KeyringError::InvalidArtifactTimeEvidence);
            }
            transaction.rollback()?;
            return Ok(existing);
        }
        transaction.execute(
            "INSERT INTO key_artifact_time_anchors (artifact_hash, canonical_anchor) VALUES (?1, ?2)",
            params![evidence.artifact_hash().to_string(), canonical],
        )?;
        transaction.commit()?;
        Ok(anchor.clone())
    }

    pub(crate) fn persist_artifact_signature_with_time_anchor(
        &self,
        signature: &KeyringArtifactSignature,
        anchor: &SignedArtifactTimeAnchor,
    ) -> Result<KeyringArtifactSignature> {
        let verifier = self.policy.artifact_time_verifier(
            Arc::clone(&self.clock),
            self.policy.max_checkpoint_future_skew,
        )?;
        let time_evidence = verifier.verify(anchor)?;
        if time_evidence.artifact_hash() != signature.artifact_hash {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_artifact_anchor_context(&transaction, anchor)?;
        let events = load_events_from(&transaction)?;
        let checkpoints = load_checkpoints_from(&transaction)?;
        let checkpoint_envelopes = checkpoints
            .into_iter()
            .map(|stored| stored.checkpoint)
            .collect::<Vec<_>>();
        let activation_commits = load_activation_commits_from(&transaction)?;
        let history = WitnessedActivationSet::verify_complete(
            &events,
            &checkpoint_envelopes,
            &activation_commits,
            &self.policy,
        )?;
        let state = KeyLogState::replay(events.iter(), &history, &self.policy)?;
        let active = state.active_signing_key()?;
        if signature.key_id != active.key_id || signature.signing_epoch != state.signing_epoch() {
            return Err(KeyringError::StateInvariant("stale signing epoch"));
        }
        signature.verify(&active.public_key)?;

        let canonical_signature = signature.canonical_bytes()?;
        let persisted_signature = transaction
            .query_row(
                "SELECT CASE WHEN length(canonical_signature) <= 1048576 THEN canonical_signature END FROM key_artifact_signatures WHERE artifact_hash = ?1",
                [signature.artifact_hash.to_string()],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .flatten();
        let persisted = match persisted_signature {
            Some(bytes) => {
                let existing = KeyringArtifactSignature::from_canonical_bytes(&bytes)?;
                if existing != *signature {
                    return Err(KeyringError::StateInvariant(
                        "artifact signature conflicts with durable anchor",
                    ));
                }
                existing.verify(&active.public_key)?;
                existing
            }
            None => {
                transaction.execute(
                    "INSERT INTO key_artifact_signatures (artifact_hash, key_id, signing_epoch, canonical_signature) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        signature.artifact_hash.to_string(),
                        signature.key_id.to_string(),
                        to_i64(signature.signing_epoch)?,
                        canonical_signature,
                    ],
                )?;
                signature.clone()
            }
        };

        let canonical_anchor = canonical_json_bytes(anchor)?;
        match load_artifact_time_anchor(&transaction, &signature.artifact_hash)? {
            Some(existing) if canonical_json_bytes(&existing)? == canonical_anchor => {}
            Some(_) => return Err(KeyringError::InvalidArtifactTimeEvidence),
            None => {
                transaction.execute(
                    "INSERT INTO key_artifact_time_anchors (artifact_hash, canonical_anchor) VALUES (?1, ?2)",
                    params![signature.artifact_hash.to_string(), canonical_anchor],
                )?;
            }
        }
        transaction.commit()?;
        Ok(persisted)
    }

    pub(crate) fn persist_artifact_signature(
        &self,
        evidence: &KeyringArtifactSignature,
    ) -> Result<KeyringArtifactSignature> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let events = load_events_from(&transaction)?;
        let checkpoints = load_checkpoints_from(&transaction)?;
        let checkpoint_envelopes = checkpoints
            .into_iter()
            .map(|stored| stored.checkpoint)
            .collect::<Vec<_>>();
        let activation_commits = load_activation_commits_from(&transaction)?;
        let history = WitnessedActivationSet::verify_complete(
            &events,
            &checkpoint_envelopes,
            &activation_commits,
            &self.policy,
        )?;
        let state = KeyLogState::replay(events.iter(), &history, &self.policy)?;
        let active = state.active_signing_key()?;
        if evidence.key_id != active.key_id || evidence.signing_epoch != state.signing_epoch() {
            return Err(KeyringError::StateInvariant("stale signing epoch"));
        }
        evidence.verify(&active.public_key)?;

        let existing = transaction
            .query_row(
                "SELECT CASE WHEN length(canonical_signature) <= 1048576 THEN canonical_signature END FROM key_artifact_signatures WHERE artifact_hash = ?1",
                [evidence.artifact_hash.to_string()],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .flatten();
        if let Some(canonical) = existing {
            let existing = KeyringArtifactSignature::from_canonical_bytes(&canonical)?;
            if existing.artifact_hash != evidence.artifact_hash
                || existing.key_id != evidence.key_id
                || existing.signing_epoch != evidence.signing_epoch
            {
                return Err(KeyringError::StateInvariant(
                    "artifact signature conflicts with durable anchor",
                ));
            }
            existing.verify(&active.public_key)?;
            transaction.rollback()?;
            return Ok(existing);
        }

        transaction.execute(
            "INSERT INTO key_artifact_signatures (artifact_hash, key_id, signing_epoch, canonical_signature) VALUES (?1, ?2, ?3, ?4)",
            params![
                evidence.artifact_hash.to_string(),
                evidence.key_id.to_string(),
                to_i64(evidence.signing_epoch)?,
                evidence.canonical_bytes()?,
            ],
        )?;
        transaction.commit()?;
        Ok(evidence.clone())
    }

    pub(crate) fn artifact_signature(
        &self,
        artifact_hash: &Hash,
    ) -> Result<Option<KeyringArtifactSignature>> {
        let connection = self.connection()?;
        let canonical = connection
            .query_row(
                "SELECT CASE WHEN length(canonical_signature) <= 1048576 THEN canonical_signature END FROM key_artifact_signatures WHERE artifact_hash = ?1",
                [artifact_hash.to_string()],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .flatten();
        canonical
            .map(|bytes| KeyringArtifactSignature::from_canonical_bytes(&bytes))
            .transpose()
    }

    pub(crate) fn artifact_time_anchor(
        &self,
        artifact_hash: &Hash,
    ) -> Result<Option<SignedArtifactTimeAnchor>> {
        let connection = self.connection()?;
        let anchor = load_artifact_time_anchor(&connection, artifact_hash)?;
        if let Some(anchor) = &anchor {
            let verifier = self.policy.artifact_time_verifier(
                Arc::clone(&self.clock),
                self.policy.max_checkpoint_future_skew,
            )?;
            let evidence = verifier.verify(anchor)?;
            if evidence.artifact_hash() != *artifact_hash {
                return Err(KeyringError::InvalidArtifactTimeEvidence);
            }
            verify_artifact_anchor_context(&connection, anchor)?;
        }
        Ok(anchor)
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| KeyringError::Synchronization)?;
        self.storage_file.validate()?;
        Ok(connection)
    }

    fn validate_startup(&self) -> Result<()> {
        let connection = self.connection()?;
        let events = load_events_from(&connection)?;
        let checkpoints = load_checkpoints_from(&connection)?;
        let enterprise_receipts = load_enterprise_receipts_from(&connection)?;
        let persisted_head = load_head_from(&connection)?;
        if events.is_empty() {
            if persisted_head.is_some()
                || !checkpoints.is_empty()
                || !load_activation_commits_from(&connection)?.is_empty()
                || !enterprise_receipts.is_empty()
                || !load_artifact_signatures_from(&connection)?.is_empty()
                || artifact_time_anchor_count(&connection)? != 0
            {
                return Err(KeyringError::StateInvariant(
                    "empty event log has persisted state or checkpoints",
                ));
            }
            return Ok(());
        }
        if checkpoints.len() != events.len() {
            return Err(KeyringError::StateInvariant(
                "event and checkpoint counts differ",
            ));
        }
        let checkpoint_envelopes = checkpoints
            .iter()
            .map(|stored| stored.checkpoint.clone())
            .collect::<Vec<_>>();
        let now = self.clock.now()?;
        for checkpoint in &checkpoint_envelopes {
            self.policy
                .validate_checkpoint_time(checkpoint.body.issued_at, now)?;
        }
        let activation_commits = load_activation_commits_from(&connection)?;
        validate_enterprise_receipts(
            &self.policy,
            &events,
            &checkpoints,
            &activation_commits,
            &enterprise_receipts,
        )?;
        let history = WitnessedActivationSet::verify_complete(
            &events,
            &checkpoint_envelopes,
            &activation_commits,
            &self.policy,
        )?;
        let state = KeyLogState::replay(events.iter(), &history, &self.policy)?;
        let expected_root = merkle_root(&events)?;
        let expected_head = derive_head(&state, &events, expected_root)?;
        if persisted_head.as_ref() != Some(&expected_head) {
            return Err(KeyringError::StateInvariant(
                "persisted key state does not match replay",
            ));
        }

        let activation_checkpoint_hashes = activation_commits
            .iter()
            .map(|activation| activation.body.checkpoint_hash.to_string())
            .collect::<std::collections::BTreeSet<_>>();
        for stored in &checkpoints {
            let verified = stored
                .checkpoint
                .verify_witness_signatures(&self.policy.witness_keys)?;
            let has_quorum = verified.len() >= self.policy.witness_threshold()?;
            if (stored.stage == CheckpointStage::Pending) == has_quorum {
                return Err(KeyringError::StateInvariant(
                    "checkpoint stage does not match witness quorum",
                ));
            }
            let checkpoint_hash = stored.checkpoint.checkpoint_hash()?.to_string();
            if (stored.stage == CheckpointStage::Activated)
                != activation_checkpoint_hashes.contains(&checkpoint_hash)
            {
                return Err(KeyringError::StateInvariant(
                    "checkpoint activation stage does not match activation journal",
                ));
            }
        }
        let artifact_signatures = load_artifact_signatures_from(&connection)?;
        verify_artifact_signatures(&events, &activation_commits, &artifact_signatures)?;
        verify_artifact_time_anchors(&connection, &self.policy, Arc::clone(&self.clock))?;
        Ok(())
    }
}

struct SyncPageWindow {
    checkpoint_start: usize,
    event_start: usize,
    commit_start: usize,
    base_checkpoint_hash: Option<Hash>,
    page_end: usize,
}

fn build_sync_response_page(
    events: &[SignedKeyLogEvent],
    checkpoints: &[SignedKeyLogCheckpoint],
    activation_commits: &[SignedKeyActivationCommit],
    window: SyncPageWindow,
) -> Result<KeyLogSyncResponse> {
    let SyncPageWindow {
        checkpoint_start,
        event_start,
        commit_start,
        base_checkpoint_hash,
        page_end,
    } = window;
    let checkpoint_end = checkpoint_start
        .checked_add(page_end.saturating_sub(event_start))
        .ok_or(KeyringError::NumericRange)?;
    let candidate_checkpoint_sequence = checkpoints
        .get(checkpoint_end.saturating_sub(1))
        .ok_or(KeyringError::InvalidCheckpoint(
            "synchronization candidate is absent",
        ))?
        .body
        .checkpoint_sequence;
    let commit_end = activation_commits
        .partition_point(|commit| commit.body.checkpoint_sequence <= candidate_checkpoint_sequence);
    let consistency_proof = if event_start > 0 && event_start < page_end {
        let leaves = canonical_event_leaves(&events[..page_end])?;
        Some(MerkleTree::from_leaves(&leaves)?.consistency_proof(event_start)?)
    } else {
        None
    };
    Ok(KeyLogSyncResponse {
        base_checkpoint_hash,
        checkpoints: checkpoints[checkpoint_start..checkpoint_end].to_vec(),
        event_envelopes: events[event_start..page_end].to_vec(),
        activation_commits: activation_commits[commit_start..commit_end].to_vec(),
        consistency_proof,
    })
}

fn insert_event(connection: &Connection, event: &SignedKeyLogEvent) -> Result<()> {
    connection.execute(
        "INSERT INTO key_events (sequence, event_id, canonical_envelope, envelope_hash, leaf_hash, operation) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            to_i64(event.body.sequence)?,
            event.body.event_id.as_str(),
            event.canonical_envelope_bytes()?,
            event.envelope_hash()?.to_string(),
            event.merkle_leaf_hash()?.to_string(),
            event.body.operation.name(),
        ],
    )?;
    Ok(())
}

fn insert_checkpoint(
    connection: &Connection,
    checkpoint: &SignedKeyLogCheckpoint,
    stage: CheckpointStage,
) -> Result<()> {
    connection.execute(
        "INSERT INTO key_checkpoints (checkpoint_sequence, checkpoint_hash, tree_size, root_hash, canonical_body, operator_key_id, operator_algorithm, operator_signature, stage) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            to_i64(checkpoint.body.checkpoint_sequence)?,
            checkpoint.checkpoint_hash()?.to_string(),
            to_i64(checkpoint.body.tree_size)?,
            checkpoint.body.root_hash.to_string(),
            checkpoint.canonical_body_bytes()?,
            checkpoint.operator_key_id.to_string(),
            algorithm_name(checkpoint.operator_algorithm),
            checkpoint.operator_signature.to_hex(),
            stage.as_str(),
        ],
    )?;
    Ok(())
}

fn insert_enterprise_receipt(
    connection: &Connection,
    receipt: &SignedKeyEnterpriseReceipt,
) -> Result<()> {
    receipt.body.validate()?;
    connection.execute(
        "INSERT INTO key_enterprise_receipts (receipt_id, transaction_id, event_id, event_sequence, stage, canonical_envelope) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            receipt.body.receipt_id,
            receipt.body.transaction_id,
            receipt.body.event_id.as_str(),
            to_i64(receipt.body.event_sequence)?,
            receipt.body.stage.as_str(),
            receipt.canonical_bytes()?,
        ],
    )?;
    Ok(())
}

fn latest_enterprise_receipt_lineage(
    connection: &Connection,
    event_sequence: u64,
) -> Result<Vec<String>> {
    if event_sequence == 0 {
        return Ok(Vec::new());
    }
    let previous_sequence = event_sequence
        .checked_sub(1)
        .ok_or(KeyringError::NumericRange)?;
    let receipt_id = connection
        .query_row(
            "SELECT receipt_id FROM key_enterprise_receipts WHERE event_sequence = ?1 ORDER BY CASE stage WHEN 'active' THEN 1 ELSE 0 END DESC LIMIT 1",
            [to_i64(previous_sequence)?],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(KeyringError::StateInvariant(
            "new key event is missing its source receipt lineage",
        ))?;
    Ok(vec![receipt_id])
}

fn enterprise_receipt_for_event_stage(
    connection: &Connection,
    event_id: &EventId,
    stage: KeyEnterpriseReceiptStage,
) -> Result<Option<SignedKeyEnterpriseReceipt>> {
    let record = connection
        .query_row(
            "SELECT receipt_id, transaction_id, event_id, event_sequence, stage, CASE WHEN length(canonical_envelope) <= 1048576 THEN canonical_envelope END FROM key_enterprise_receipts WHERE event_id = ?1 AND stage = ?2",
            params![event_id.as_str(), stage.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                ))
            },
        )
        .optional()?;
    record.map(parse_enterprise_receipt_record).transpose()
}

fn enterprise_receipt_by_id(
    connection: &Connection,
    receipt_id: &str,
) -> Result<Option<SignedKeyEnterpriseReceipt>> {
    let record = connection
        .query_row(
            "SELECT receipt_id, transaction_id, event_id, event_sequence, stage, CASE WHEN length(canonical_envelope) <= 1048576 THEN canonical_envelope END FROM key_enterprise_receipts WHERE receipt_id = ?1",
            [receipt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                ))
            },
        )
        .optional()?;
    record.map(parse_enterprise_receipt_record).transpose()
}

fn load_enterprise_receipts_from(
    connection: &Connection,
) -> Result<Vec<SignedKeyEnterpriseReceipt>> {
    let mut statement = connection.prepare(
        "SELECT receipt_id, transaction_id, event_id, event_sequence, stage, CASE WHEN length(canonical_envelope) <= 1048576 THEN canonical_envelope END FROM key_enterprise_receipts ORDER BY event_sequence, CASE stage WHEN 'pending' THEN 0 ELSE 1 END",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Option<Vec<u8>>>(5)?,
        ))
    })?;
    let mut records = Vec::new();
    for row in rows {
        records.push(row?);
    }
    drop(statement);
    records
        .into_iter()
        .map(parse_enterprise_receipt_record)
        .collect()
}

fn parse_enterprise_receipt_record(
    (receipt_id, transaction_id, event_id, event_sequence, stage, canonical): (
        String,
        String,
        String,
        i64,
        String,
        Option<Vec<u8>>,
    ),
) -> Result<SignedKeyEnterpriseReceipt> {
    let canonical = canonical.ok_or(KeyringError::StateInvariant(
        "stored key enterprise receipt exceeds canonical byte limit",
    ))?;
    let receipt = SignedKeyEnterpriseReceipt::from_canonical_bytes(&canonical)?;
    if receipt.body.receipt_id != receipt_id
        || receipt.body.transaction_id != transaction_id
        || receipt.body.event_id.as_str() != event_id
        || to_i64(receipt.body.event_sequence)? != event_sequence
        || receipt.body.stage.as_str() != stage
    {
        return Err(KeyringError::StateInvariant(
            "stored key enterprise receipt metadata is inconsistent",
        ));
    }
    Ok(receipt)
}

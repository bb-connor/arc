fn validate_enterprise_receipts(
    policy: &KeyLogPolicy,
    events: &[SignedKeyLogEvent],
    checkpoints: &[StoredCheckpoint],
    activation_commits: &[SignedKeyActivationCommit],
    receipts: &[SignedKeyEnterpriseReceipt],
) -> Result<()> {
    let expected_count = events
        .len()
        .checked_add(activation_commits.len())
        .ok_or(KeyringError::NumericRange)?;
    if checkpoints.len() != events.len() || receipts.len() != expected_count {
        return Err(KeyringError::StateInvariant(
            "key enterprise receipt journal does not cover durable history",
        ));
    }
    for receipt in receipts {
        receipt.verify_operator(&policy.operator_key)?;
    }
    let mut previous_receipt_id: Option<String> = None;
    for (event, stored) in events.iter().zip(checkpoints) {
        let pending = receipts
            .iter()
            .find(|receipt| {
                receipt.body.event_id == event.body.event_id
                    && receipt.body.stage == KeyEnterpriseReceiptStage::Pending
            })
            .ok_or(KeyringError::StateInvariant(
                "key event is missing its pending enterprise receipt",
            ))?;
        let expected_pending_lineage = previous_receipt_id.iter().cloned().collect::<Vec<_>>();
        if pending.body.source_receipt_ids != expected_pending_lineage {
            return Err(KeyringError::StateInvariant(
                "pending key receipt source lineage is inconsistent",
            ));
        }
        pending.verify_against(event, &stored.checkpoint, policy, None)?;
        let activation = activation_commits
            .iter()
            .find(|activation| activation.body.event_id == event.body.event_id);
        if let Some(activation) = activation {
            let active = receipts
                .iter()
                .find(|receipt| {
                    receipt.body.event_id == event.body.event_id
                        && receipt.body.stage == KeyEnterpriseReceiptStage::Active
                })
                .ok_or(KeyringError::StateInvariant(
                    "activated key event is missing its enterprise receipt",
                ))?;
            if active.body.source_receipt_ids != [pending.body.receipt_id.clone()] {
                return Err(KeyringError::StateInvariant(
                    "active key receipt source lineage is inconsistent",
                ));
            }
            active.verify_against(event, &stored.checkpoint, policy, Some(activation))?;
            previous_receipt_id = Some(active.body.receipt_id.clone());
        } else {
            previous_receipt_id = Some(pending.body.receipt_id.clone());
        }
    }
    Ok(())
}

fn persist_state(
    connection: &Connection,
    state: &KeyLogState,
    events: &[SignedKeyLogEvent],
    root_hash: Hash,
) -> Result<()> {
    let last = events.last().ok_or(KeyringError::StateInvariant(
        "cannot persist state for an empty event log",
    ))?;
    connection.execute(
        r#"
        INSERT INTO key_state (
            singleton, active_key_id, pending_key_id, pending_event_id, signing_epoch,
            last_sequence, last_event_hash, tree_size, root_hash
        ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        ON CONFLICT(singleton) DO UPDATE SET
            active_key_id = excluded.active_key_id,
            pending_key_id = excluded.pending_key_id,
            pending_event_id = excluded.pending_event_id,
            signing_epoch = excluded.signing_epoch,
            last_sequence = excluded.last_sequence,
            last_event_hash = excluded.last_event_hash,
            tree_size = excluded.tree_size,
            root_hash = excluded.root_hash
        "#,
        params![
            state.active_signing_key()?.key_id.to_string(),
            state
                .pending_rotation_key()
                .map(|record| record.key_id.to_string()),
            state.pending_event_id().map(EventId::as_str),
            to_i64(state.signing_epoch())?,
            to_i64(last.body.sequence)?,
            last.envelope_hash()?.to_string(),
            to_i64(u64::try_from(events.len()).map_err(|_| KeyringError::NumericRange)?)?,
            root_hash.to_string(),
        ],
    )?;
    Ok(())
}

fn load_events_from(connection: &Connection) -> Result<Vec<SignedKeyLogEvent>> {
    let mut statement = connection.prepare(
        "SELECT sequence, event_id, CASE WHEN length(canonical_envelope) <= 1048576 THEN canonical_envelope END, envelope_hash, leaf_hash, operation FROM key_events ORDER BY sequence",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<Vec<u8>>>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
        ))
    })?;
    let mut records = Vec::new();
    for row in rows {
        records.push(row?);
    }
    drop(statement);

    let mut events = Vec::with_capacity(records.len());
    for (sequence, event_id, canonical, envelope_hash, leaf_hash, operation) in records {
        let canonical = canonical.ok_or(KeyringError::StateInvariant(
            "stored event exceeds canonical byte limit",
        ))?;
        let event = SignedKeyLogEvent::from_canonical_envelope_bytes(&canonical)?;
        if canonical_json_bytes(&event)? != canonical
            || to_i64(event.body.sequence)? != sequence
            || event.body.event_id.as_str() != event_id
            || event.envelope_hash()?.to_string() != envelope_hash
            || event.merkle_leaf_hash()?.to_string() != leaf_hash
            || event.body.operation.name() != operation
        {
            return Err(KeyringError::StateInvariant(
                "stored event metadata or canonical bytes are inconsistent",
            ));
        }
        events.push(event);
    }
    Ok(events)
}

fn load_activation_commits_from(connection: &Connection) -> Result<Vec<SignedKeyActivationCommit>> {
    let mut statement = connection
        .prepare("SELECT event_id, signing_epoch, CASE WHEN length(canonical_activation) <= 1048576 THEN canonical_activation END FROM key_activations ORDER BY signing_epoch")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Option<Vec<u8>>>(2)?,
        ))
    })?;
    let mut records = Vec::new();
    for row in rows {
        records.push(row?);
    }
    drop(statement);
    let mut activations = Vec::with_capacity(records.len());
    for (event_id, signing_epoch, canonical) in records {
        let canonical = canonical.ok_or(KeyringError::StateInvariant(
            "stored activation exceeds canonical byte limit",
        ))?;
        let activation = SignedKeyActivationCommit::from_canonical_bytes(&canonical)?;
        if activation.body.event_id.as_str() != event_id
            || to_i64(activation.body.signing_epoch)? != signing_epoch
            || activation.canonical_bytes()? != canonical
        {
            return Err(KeyringError::StateInvariant(
                "stored activation is inconsistent",
            ));
        }
        activations.push(activation);
    }
    activations.sort_by_key(|activation| activation.body.signing_epoch);
    Ok(activations)
}

fn load_artifact_signatures_from(connection: &Connection) -> Result<Vec<KeyringArtifactSignature>> {
    let mut statement = connection.prepare(
        "SELECT artifact_hash, key_id, signing_epoch, CASE WHEN length(canonical_signature) <= 1048576 THEN canonical_signature END FROM key_artifact_signatures ORDER BY artifact_hash",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, Option<Vec<u8>>>(3)?,
        ))
    })?;
    let mut records = Vec::new();
    for row in rows {
        records.push(row?);
    }
    drop(statement);

    let mut signatures = Vec::with_capacity(records.len());
    for (artifact_hash, key_id, signing_epoch, canonical) in records {
        let canonical = canonical.ok_or(KeyringError::StateInvariant(
            "stored artifact signature exceeds canonical byte limit",
        ))?;
        let evidence = KeyringArtifactSignature::from_canonical_bytes(&canonical)?;
        if evidence.artifact_hash.to_string() != artifact_hash
            || evidence.key_id.to_string() != key_id
            || to_i64(evidence.signing_epoch)? != signing_epoch
            || evidence.canonical_bytes()? != canonical
        {
            return Err(KeyringError::StateInvariant(
                "stored artifact signature is inconsistent",
            ));
        }
        signatures.push(evidence);
    }
    Ok(signatures)
}

fn load_artifact_time_anchor(
    connection: &Connection,
    artifact_hash: &Hash,
) -> Result<Option<SignedArtifactTimeAnchor>> {
    let canonical = connection
        .query_row(
            "SELECT CASE WHEN length(canonical_anchor) <= 1048576 THEN canonical_anchor END FROM key_artifact_time_anchors WHERE artifact_hash = ?1",
            [artifact_hash.to_string()],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()?
        .flatten();
    canonical
        .map(|bytes| SignedArtifactTimeAnchor::from_canonical_bytes(&bytes))
        .transpose()
}

fn latest_verified_artifact_anchor_time_for_epoch(
    connection: &Connection,
    signing_epoch: u64,
    policy: &KeyLogPolicy,
    clock: &Arc<dyn TrustedClock>,
) -> Result<Option<u64>> {
    let mut statement = connection.prepare(
        "SELECT a.artifact_hash, CASE WHEN length(a.canonical_anchor) <= 1048576 THEN a.canonical_anchor END \
         FROM key_artifact_time_anchors a \
         JOIN key_artifact_signatures s ON s.artifact_hash = a.artifact_hash \
         WHERE s.signing_epoch = ?1",
    )?;
    let rows = statement.query_map([to_i64(signing_epoch)?], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<Vec<u8>>>(1)?))
    })?;
    let mut records = Vec::new();
    for row in rows {
        records.push(row?);
    }
    drop(statement);
    if records.is_empty() {
        return Ok(None);
    }
    let verifier =
        policy.artifact_time_verifier(Arc::clone(clock), policy.max_checkpoint_future_skew)?;
    let mut latest = None;
    for (artifact_hash, bytes) in records {
        let artifact_hash = Hash::from_hex(&artifact_hash)?;
        let bytes = bytes.ok_or(KeyringError::InvalidArtifactTimeEvidence)?;
        let anchor = SignedArtifactTimeAnchor::from_canonical_bytes(&bytes)?;
        verify_artifact_anchor_context(connection, &anchor)?;
        let evidence = verifier.verify(&anchor)?;
        if evidence.artifact_hash() != artifact_hash {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
        latest = Some(latest.map_or(evidence.anchored_at(), |current: u64| {
            current.max(evidence.anchored_at())
        }));
    }
    Ok(latest)
}

fn verify_artifact_anchor_context(
    connection: &Connection,
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
    let stored = load_checkpoints_from(connection)?
        .into_iter()
        .find(|stored| stored.checkpoint.body.checkpoint_sequence == *checkpoint_sequence)
        .ok_or(KeyringError::InvalidArtifactTimeEvidence)?;
    if stored.checkpoint.checkpoint_hash()? != *checkpoint_hash
        || stored.checkpoint.body.issued_at > anchor.body.anchored_at
    {
        return Err(KeyringError::InvalidArtifactTimeEvidence);
    }
    Ok(())
}

fn verify_artifact_time_anchors(
    connection: &Connection,
    policy: &KeyLogPolicy,
    clock: Arc<dyn TrustedClock>,
) -> Result<()> {
    let mut statement = connection
        .prepare("SELECT artifact_hash FROM key_artifact_time_anchors ORDER BY artifact_hash")?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    let mut hashes = Vec::new();
    for row in rows {
        hashes.push(Hash::from_hex(&row?)?);
    }
    drop(statement);
    if hashes.is_empty() {
        return Ok(());
    }
    let verifier = policy.artifact_time_verifier(clock, policy.max_checkpoint_future_skew)?;
    for hash in hashes {
        let anchor = load_artifact_time_anchor(connection, &hash)?.ok_or(
            KeyringError::StateInvariant("artifact-time anchor disappeared during replay"),
        )?;
        let evidence = verifier.verify(&anchor)?;
        verify_artifact_anchor_context(connection, &anchor)?;
        if evidence.artifact_hash() != hash {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
    }
    Ok(())
}

fn artifact_time_anchor_count(connection: &Connection) -> Result<usize> {
    let count = connection.query_row(
        "SELECT COUNT(*) FROM key_artifact_time_anchors",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    usize::try_from(count).map_err(|_| KeyringError::NumericRange)
}

fn key_for_epoch<'a>(
    events: &'a [SignedKeyLogEvent],
    activation_commits: &[SignedKeyActivationCommit],
    signing_epoch: u64,
) -> Result<&'a SignedKeyLogEvent> {
    if signing_epoch == 0 {
        return events.first().ok_or(KeyringError::StateInvariant(
            "signing epoch zero has no genesis event",
        ));
    }
    let index = usize::try_from(
        signing_epoch
            .checked_sub(1)
            .ok_or(KeyringError::NumericRange)?,
    )
    .map_err(|_| KeyringError::NumericRange)?;
    let commit = activation_commits
        .get(index)
        .ok_or(KeyringError::StateInvariant(
            "artifact signature epoch has no activation commit",
        ))?;
    events
        .iter()
        .find(|event| event.body.event_id == commit.body.event_id)
        .ok_or(KeyringError::StateInvariant(
            "activation commit event is absent",
        ))
}

fn verify_artifact_signatures(
    events: &[SignedKeyLogEvent],
    activation_commits: &[SignedKeyActivationCommit],
    signatures: &[KeyringArtifactSignature],
) -> Result<()> {
    for evidence in signatures {
        let key = key_for_epoch(events, activation_commits, evidence.signing_epoch)?;
        if evidence.key_id != key.body.key_id {
            return Err(KeyringError::StateInvariant(
                "artifact signature key does not match signing epoch",
            ));
        }
        evidence.verify(&key.body.public_key)?;
    }
    Ok(())
}

struct StoredCheckpointRow {
    sequence: i64,
    checkpoint_hash: String,
    tree_size: i64,
    root_hash: String,
    canonical_body: Option<Vec<u8>>,
    operator_key_id: String,
    operator_algorithm: String,
    operator_signature: String,
    stage: String,
}

fn load_checkpoints_from(connection: &Connection) -> Result<Vec<StoredCheckpoint>> {
    let mut statement = connection.prepare(
        "SELECT checkpoint_sequence, checkpoint_hash, tree_size, root_hash, CASE WHEN length(canonical_body) <= 1048576 THEN canonical_body END, operator_key_id, operator_algorithm, operator_signature, stage FROM key_checkpoints ORDER BY checkpoint_sequence",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(StoredCheckpointRow {
            sequence: row.get(0)?,
            checkpoint_hash: row.get(1)?,
            tree_size: row.get(2)?,
            root_hash: row.get(3)?,
            canonical_body: row.get(4)?,
            operator_key_id: row.get(5)?,
            operator_algorithm: row.get(6)?,
            operator_signature: row.get(7)?,
            stage: row.get(8)?,
        })
    })?;
    let mut records = Vec::new();
    for row in rows {
        records.push(row?);
    }
    drop(statement);

    let mut checkpoints = Vec::with_capacity(records.len());
    for row in records {
        let StoredCheckpointRow {
            sequence,
            checkpoint_hash,
            tree_size,
            root_hash,
            canonical_body,
            operator_key_id,
            operator_algorithm,
            operator_signature,
            stage,
        } = row;
        let canonical_body = canonical_body.ok_or(KeyringError::StateInvariant(
            "stored checkpoint exceeds canonical byte limit",
        ))?;
        let body = KeyLogCheckpointBody::from_canonical_bytes(&canonical_body)?;
        let checkpoint_hash_value = Hash::from_hex(&checkpoint_hash)?;
        let mut checkpoint = SignedKeyLogCheckpoint {
            body,
            operator_key_id: KeyId::from_hash(Hash::from_hex(&operator_key_id)?),
            operator_algorithm: parse_algorithm(&operator_algorithm)?,
            operator_signature: Signature::from_hex(&operator_signature)?,
            witness_signatures: load_witnesses_from(connection, &checkpoint_hash_value)?,
        };
        checkpoint
            .witness_signatures
            .sort_by(|left, right| left.witness_id.cmp(&right.witness_id));
        if canonical_json_bytes(&checkpoint.body)? != canonical_body
            || to_i64(checkpoint.body.checkpoint_sequence)? != sequence
            || to_i64(checkpoint.body.tree_size)? != tree_size
            || checkpoint.body.root_hash.to_string() != root_hash
            || checkpoint.checkpoint_hash()? != checkpoint_hash_value
        {
            return Err(KeyringError::StateInvariant(
                "stored checkpoint metadata or canonical bytes are inconsistent",
            ));
        }
        checkpoints.push(StoredCheckpoint {
            checkpoint,
            stage: CheckpointStage::parse(&stage).ok_or(KeyringError::InvalidCheckpoint(
                "checkpoint stage is invalid",
            ))?,
        });
    }
    Ok(checkpoints)
}

fn load_witnesses_from(
    connection: &Connection,
    checkpoint_hash: &Hash,
) -> Result<Vec<WitnessSignature>> {
    let mut statement = connection.prepare(
        "SELECT witness_id, algorithm, signature FROM key_checkpoint_witnesses WHERE checkpoint_hash = ?1 ORDER BY witness_id LIMIT ?2",
    )?;
    let query_limit = crate::MAX_WITNESS_SIGNATURES
        .checked_add(1)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(KeyringError::NumericRange)?;
    let rows = statement.query_map(params![checkpoint_hash.to_string(), query_limit], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut witnesses = Vec::new();
    for row in rows {
        let (witness_id, algorithm, signature) = row?;
        witnesses.push(WitnessSignature {
            witness_id: WitnessId::new(witness_id)?,
            algorithm: parse_algorithm(&algorithm)?,
            signature: Signature::from_hex(&signature)?,
        });
    }
    if witnesses.len() > crate::MAX_WITNESS_SIGNATURES {
        return Err(KeyringError::InvalidWitnessActivation);
    }
    Ok(witnesses)
}

fn checkpoint_by_hash(
    connection: &Connection,
    checkpoint_hash: &Hash,
) -> Result<Option<StoredCheckpoint>> {
    Ok(load_checkpoints_from(connection)?
        .into_iter()
        .find(|stored| stored.checkpoint.checkpoint_hash().ok().as_ref() == Some(checkpoint_hash)))
}

fn load_head_from(connection: &Connection) -> Result<Option<KeyLogHead>> {
    let row = connection
        .query_row(
            "SELECT active_key_id, pending_key_id, pending_event_id, signing_epoch, last_sequence, last_event_hash, tree_size, root_hash FROM key_state WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(
            active_key_id,
            pending_key_id,
            pending_event_id,
            signing_epoch,
            last_sequence,
            last_event_hash,
            tree_size,
            root_hash,
        )| {
            Ok(KeyLogHead {
                active_key_id: KeyId::from_hash(Hash::from_hex(&active_key_id)?),
                pending_key_id: pending_key_id
                    .map(|value| Hash::from_hex(&value).map(KeyId::from_hash))
                    .transpose()?,
                pending_event_id: pending_event_id.map(EventId::new).transpose()?,
                signing_epoch: from_i64(signing_epoch)?,
                last_sequence: from_i64(last_sequence)?,
                last_event_hash: Hash::from_hex(&last_event_hash)?,
                tree_size: from_i64(tree_size)?,
                root_hash: Hash::from_hex(&root_hash)?,
            })
        },
    )
    .transpose()
}

fn derive_head(
    state: &KeyLogState,
    events: &[SignedKeyLogEvent],
    root_hash: Hash,
) -> Result<KeyLogHead> {
    let last = events.last().ok_or(KeyringError::StateInvariant(
        "cannot derive head for an empty event log",
    ))?;
    Ok(KeyLogHead {
        active_key_id: state.active_signing_key()?.key_id,
        pending_key_id: state.pending_rotation_key().map(|record| record.key_id),
        pending_event_id: state.pending_event_id().cloned(),
        signing_epoch: state.signing_epoch(),
        last_sequence: last.body.sequence,
        last_event_hash: last.envelope_hash()?,
        tree_size: u64::try_from(events.len()).map_err(|_| KeyringError::NumericRange)?,
        root_hash,
    })
}

fn canonical_event_leaves(events: &[SignedKeyLogEvent]) -> Result<Vec<Vec<u8>>> {
    events
        .iter()
        .map(SignedKeyLogEvent::canonical_envelope_bytes)
        .collect()
}

fn merkle_root(events: &[SignedKeyLogEvent]) -> Result<Hash> {
    let leaves = canonical_event_leaves(events)?;
    Ok(MerkleTree::from_leaves(&leaves)?.root())
}

fn algorithm_name(algorithm: SigningAlgorithm) -> &'static str {
    match algorithm {
        SigningAlgorithm::Ed25519 => "ed25519",
        SigningAlgorithm::P256 => "p256",
        SigningAlgorithm::P384 => "p384",
        SigningAlgorithm::Hybrid => "hybrid",
    }
}

fn parse_algorithm(value: &str) -> Result<SigningAlgorithm> {
    match value {
        "ed25519" => Ok(SigningAlgorithm::Ed25519),
        "p256" => Ok(SigningAlgorithm::P256),
        "p384" => Ok(SigningAlgorithm::P384),
        "hybrid" => Ok(SigningAlgorithm::Hybrid),
        _ => Err(KeyringError::AlgorithmMismatch),
    }
}

fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| KeyringError::NumericRange)
}

fn from_i64(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| KeyringError::NumericRange)
}

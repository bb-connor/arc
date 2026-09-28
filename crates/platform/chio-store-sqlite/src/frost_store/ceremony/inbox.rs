//! Fenced, durable acceptance. A conflicting authenticated second message commits
//! failure before returning its domain error; rolling that transaction back would
//! let the same ceremony resume after equivocation.
use super::*;

struct Accepted {
    envelope: SealedFrostRound2Package,
    envelope_digest: String,
    share: EncryptedBlob,
    accepted_at: u64,
    record_digest: String,
}

impl SqliteFrostStore {
    pub fn accept_round2_package(
        &self,
        config: &FrostCeremonyConfig,
        custody: &FrostCustodyKey,
        envelope: &SealedFrostRound2Package,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(), FrostStoreError> {
        validate_trusted_time(trusted_now_unix_ms)?;
        let ceremony_id = config.ceremony_id()?;
        let config_digest =
            sha256_hex(&canonical_json_bytes(config).map_err(|e| invalid(e.to_string()))?);
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence)?;
        let stored = load_ceremony_tx(&transaction, &ceremony_id)?
            .ok_or(FrostStoreError::Conflict("ceremony has not started"))?;
        verify_exact_config(&stored, &config_digest, custody, trusted_now_unix_ms)?;
        if !matches!(
            stored.state,
            FrostCeremonyState::Round2Ready | FrostCeremonyState::Completed
        ) {
            return Err(FrostStoreError::Conflict("round two is not ready"));
        }
        verify_inbox_time(&transaction, &ceremony_id, trusted_now_unix_ms)?;
        let (_, sealing) = decrypt_secrets(&stored, custody)?;
        let opened = envelope.open(config, &sealing)?;
        let envelope_digest = envelope.envelope_digest()?;
        if let Some(previous) = load(&transaction, &stored, envelope.sender_participant_id())? {
            if previous.envelope_digest == envelope_digest {
                // Check encrypted custody as well as the public digest on a retry.
                check_share(&previous, &stored, custody, &opened)?;
                transaction.commit().map_err(super::super::sqlite_error)?;
                return Ok(());
            }
            fail_ceremony(
                &transaction,
                self,
                &stored,
                custody,
                fence,
                trusted_now_unix_ms,
            )?;
            self.commit_write(transaction)?;
            self.sync_after_write(&connection)?;
            return Err(FrostStoreError::CeremonyFailed);
        }
        if stored.state != FrostCeremonyState::Round2Ready {
            return Err(FrostStoreError::Round2NotAccepted);
        }
        let accepted_at = trusted_now_unix_ms;
        let share = encrypt_material(
            opened.secret_bytes(),
            custody,
            &acceptance_aad(&stored, &envelope_digest, accepted_at)?,
        )?;
        let mut accepted = Accepted {
            envelope: envelope.clone(),
            envelope_digest,
            share,
            accepted_at,
            record_digest: String::new(),
        };
        accepted.record_digest = acceptance_digest(&stored, &accepted)?;
        let encoded = canonical_json_bytes(envelope).map_err(|e| invalid(e.to_string()))?;
        transaction.execute(
            "INSERT INTO frost_round2_acceptances (ceremony_id, key_epoch, round, sender_participant_id, recipient_participant_id, envelope_json, envelope_digest, share_nonce, share_ciphertext, accepted_at_unix_ms, record_digest) VALUES (?1, ?2, 2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![ceremony_id, sqlite_u64(config.key_epoch, "key epoch")?, envelope.sender_participant_id(), config.local_participant_id,
                encoded, accepted.envelope_digest, accepted.share.nonce.as_slice(), accepted.share.ciphertext,
                sqlite_u64(accepted_at, "acceptance time")?, accepted.record_digest])
            .map_err(super::super::sqlite_error)?;
        append_projection_commit(
            &transaction,
            self,
            &inbox_projection(&ceremony_id, envelope.sender_participant_id()),
            ProjectionMutation {
                sequence: 1,
                projection_type: "ceremony_inbox",
                mutation_kind: "frost.ceremony.accept",
                record_digest: &accepted.record_digest,
            },
            fence,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)
    }
}

pub(super) fn verify_inbox_time(
    connection: &Connection,
    id: &str,
    now: u64,
) -> Result<(), FrostStoreError> {
    let latest: Option<i64> = connection
        .query_row(
            "SELECT MAX(accepted_at_unix_ms) FROM frost_round2_acceptances WHERE ceremony_id = ?1",
            [id],
            |row| row.get(0),
        )
        .map_err(super::super::sqlite_error)?;
    if latest
        .map(|v| read_u64(v, "acceptance time"))
        .transpose()?
        .is_some_and(|v| v > now)
    {
        return Err(FrostStoreError::Conflict(
            "trusted time regressed behind the inbox",
        ));
    }
    Ok(())
}

pub(super) fn load_accepted(
    connection: &Connection,
    config: &FrostCeremonyConfig,
    stored: &StoredCeremonyRow,
    custody: &FrostCustodyKey,
    sealing: &FrostSealingKey,
    transcript: &[SealedFrostRound2Package],
) -> Result<Vec<FrostRound2Package>, FrostStoreError> {
    let mut opened = Vec::new();
    for envelope in transcript
        .iter()
        .filter(|p| p.recipient_participant_id() == config.local_participant_id)
    {
        let accepted = load(connection, stored, envelope.sender_participant_id())?
            .ok_or(FrostStoreError::Round2NotAccepted)?;
        if accepted.envelope != *envelope {
            return Err(FrostStoreError::Conflict(
                "transcript differs from accepted round-two input",
            ));
        }
        let package = accepted.envelope.open(config, sealing)?;
        check_share(&accepted, stored, custody, &package)?;
        opened.push(package);
    }
    Ok(opened)
}

fn check_share(
    accepted: &Accepted,
    stored: &StoredCeremonyRow,
    custody: &FrostCustodyKey,
    opened: &FrostRound2Package,
) -> Result<(), FrostStoreError> {
    let bytes = Zeroizing::new(
        decrypt_blob_with_aad(
            custody.key(),
            &accepted.share,
            &acceptance_aad(stored, &accepted.envelope_digest, accepted.accepted_at)?,
        )
        .map_err(|_| FrostStoreError::Custody("accepted share authentication failed"))?,
    );
    if bytes.as_slice() != opened.secret_bytes() {
        return Err(FrostStoreError::Custody(
            "accepted share differs from envelope",
        ));
    }
    Ok(())
}

fn load(
    connection: &Connection,
    stored: &StoredCeremonyRow,
    sender: &str,
) -> Result<Option<Accepted>, FrostStoreError> {
    let row = connection.query_row(
        "SELECT envelope_json, envelope_digest, share_nonce, share_ciphertext, accepted_at_unix_ms, record_digest FROM frost_round2_acceptances WHERE ceremony_id = ?1 AND key_epoch = ?2 AND round = 2 AND sender_participant_id = ?3 AND recipient_participant_id = ?4",
        params![stored.ceremony_id, sqlite_u64(stored.key_epoch, "key epoch")?, sender, stored.local_participant_id],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?, row.get::<_, Vec<u8>>(3)?, row.get::<_, i64>(4)?, row.get::<_, String>(5)?)))
        .optional().map_err(super::super::sqlite_error)?;
    let Some((json, envelope_digest, nonce, ciphertext, at, record_digest)) = row else {
        return Ok(None);
    };
    let envelope = SealedFrostRound2Package::from_wire(&json)?;
    let config = decode_config(&stored.config_json)?;
    envelope.verify(&config)?;
    if envelope.sender_participant_id() != sender
        || envelope.recipient_participant_id() != stored.local_participant_id
        || envelope.envelope_digest()? != envelope_digest
    {
        return Err(invalid("accepted envelope binding mismatch"));
    }
    let accepted = Accepted {
        envelope,
        envelope_digest,
        share: EncryptedBlob {
            nonce: nonce
                .try_into()
                .map_err(|_| invalid("invalid accepted share nonce"))?,
            ciphertext,
        },
        accepted_at: read_u64(at, "acceptance time")?,
        record_digest,
    };
    let committed: Option<String> = connection.query_row(
        "SELECT record_digest FROM frost_projection_commits WHERE projection_key = ?1 AND projection_sequence = 1 AND projection_type = 'ceremony_inbox'",
        [inbox_projection(&stored.ceremony_id, sender)], |row| row.get(0)).optional().map_err(super::super::sqlite_error)?;
    if acceptance_digest(stored, &accepted)? != accepted.record_digest
        || committed.as_deref() != Some(&accepted.record_digest)
    {
        return Err(invalid(
            "round-two acceptance differs from projection commit",
        ));
    }
    Ok(Some(accepted))
}

fn fail_ceremony(
    transaction: &Transaction<'_>,
    store: &SqliteFrostStore,
    stored: &StoredCeremonyRow,
    custody: &FrostCustodyKey,
    fence: &StoreMutationFence,
    now: u64,
) -> Result<(), FrostStoreError> {
    let version = stored
        .state_version
        .checked_add(1)
        .ok_or_else(|| invalid("ceremony version overflow"))?;
    let (secret, sealing) = decrypt_secrets(stored, custody)?;
    let binding = CustodyBinding {
        ceremony_id: &stored.ceremony_id,
        config_digest: &stored.config_digest,
        state: FrostCeremonyState::Failed,
        state_version: version,
        custody_generation: custody.generation(),
        fence,
        updated_at_unix_ms: now,
    };
    let encrypted = encrypt_secret(
        &secret,
        &sealing,
        custody,
        &custody_aad("secret", &binding)?,
    )?;
    let mut write = row_as_write(stored);
    write.state = FrostCeremonyState::Failed;
    write.state_version = version;
    write.secret = &encrypted;
    write.output = None;
    write.public_key_package = None;
    write.group_public_key = None;
    write.verification_shares_json = None;
    write.completed_at_unix_ms = None;
    write.updated_at_unix_ms = now;
    write.source_fence = fence;
    let digest = record_digest(&write)?;
    update_ceremony(transaction, &write, &digest, stored.state_version)?;
    append_projection_commit(
        transaction,
        store,
        &projection_key(&stored.ceremony_id),
        ProjectionMutation {
            sequence: version,
            projection_type: "ceremony",
            mutation_kind: "frost.ceremony.fail",
            record_digest: &digest,
        },
        fence,
    )
}

fn inbox_projection(ceremony: &str, sender: &str) -> String {
    format!("ceremony_inbox/{ceremony}/{}", hex::encode(sender))
}

fn acceptance_aad(
    stored: &StoredCeremonyRow,
    envelope: &str,
    at: u64,
) -> Result<Vec<u8>, FrostStoreError> {
    canonical_json_bytes(&(
        "chio.frost.accepted-share.v1",
        &stored.ceremony_id,
        &stored.config_digest,
        &stored.local_participant_id,
        &stored.custody_generation,
        envelope,
        at,
    ))
    .map_err(|e| invalid(e.to_string()))
}

fn acceptance_digest(
    stored: &StoredCeremonyRow,
    accepted: &Accepted,
) -> Result<String, FrostStoreError> {
    prefixed_digest(
        b"chio.frost.round2-acceptance.digest.v1\0",
        &(
            &stored.ceremony_id,
            stored.key_epoch,
            2_u8,
            &stored.local_participant_id,
            accepted.envelope.sender_participant_id(),
            &accepted.envelope_digest,
            hex::encode(accepted.share.nonce),
            sha256_hex(&accepted.share.ciphertext),
            accepted.accepted_at,
        ),
    )
}

pub(super) fn verify_invariants(connection: &Connection) -> Result<(), FrostStoreError> {
    let rows = {
        let mut stmt = connection
            .prepare("SELECT ceremony_id, sender_participant_id FROM frost_round2_acceptances")
            .map_err(super::super::sqlite_error)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(super::super::sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(super::super::sqlite_error)?;
        rows
    };
    let mut keys = std::collections::BTreeSet::new();
    for (id, sender) in rows {
        let stored = load_ceremony_connection(connection, &id)?
            .ok_or_else(|| invalid("orphan round-two acceptance"))?;
        load(connection, &stored, &sender)?
            .ok_or_else(|| invalid("acceptance primary key differs from ceremony"))?;
        keys.insert(inbox_projection(&id, &sender));
    }
    let mut stmt = connection.prepare("SELECT projection_key FROM frost_projection_commits WHERE projection_type = 'ceremony_inbox'")
        .map_err(super::super::sqlite_error)?;
    let commits = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(super::super::sqlite_error)?;
    for commit in commits {
        if !keys.remove(&commit.map_err(super::super::sqlite_error)?) {
            return Err(invalid("committed round-two acceptance is missing"));
        }
    }
    if !keys.is_empty() {
        return Err(invalid("round-two acceptance is uncommitted"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;

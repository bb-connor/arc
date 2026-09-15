//! Bounded canonical records and a bijection with named admission commits.
//! Verification never recursively loads an operation or re-enters its anchor.

use super::*;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ownership {
    schema: String,
    operation_id: AdmissionOperationId,
    intent: RuntimeParticipantClaimIntentV1,
    ledger_digest: AdmissionDigest,
    recorded_at_unix_ms: u64,
}

pub(super) struct Claim {
    ownership: Ownership,
    operation: AdmissionOperationV1,
    released: bool,
}

impl Claim {
    pub(super) fn new(
        operation: &AdmissionOperationV1,
        intent: RuntimeParticipantClaimIntentV1,
        ledger_digest: AdmissionDigest,
        now: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        validate_trusted_time(now, "runtime_claim_time")?;
        Ok(Self {
            ownership: Ownership {
                schema: "chio.runtime-participant-claim.v1".into(),
                operation_id: operation.binding().operation_id().clone(),
                intent,
                ledger_digest,
                recorded_at_unix_ms: now,
            },
            operation: operation.clone(),
            released: false,
        })
    }

    pub(super) fn intent(&self) -> &RuntimeParticipantClaimIntentV1 {
        &self.ownership.intent
    }
    pub(super) fn released(&self) -> bool {
        self.released
    }
    pub(super) fn digest(&self) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
        hash(
            "chio.runtime-participant-claim-commit.v1",
            &(&self.ownership, &self.operation.to_persisted()),
        )
    }
    pub(super) fn reference(
        &self,
    ) -> Result<RuntimeParticipantClaimReferenceV1, AdmissionOperationStoreError> {
        Ok(RuntimeParticipantClaimReferenceV1::new(
            self.ownership.operation_id.clone(),
            self.intent().episode_id().clone(),
            self.digest()?,
        ))
    }
    pub(super) fn insert(
        &self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        let intent = self.intent();
        connection.execute(
            "INSERT INTO runtime_replay_claim_episodes (operation_id, episode_id, runtime_authority_id, ledger_digest, claim_digest, claim_json, operation_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![self.ownership.operation_id.as_str(), intent.episode_id().as_str(), intent.runtime_authority_id().as_str(),
                self.ownership.ledger_digest.as_str(), self.digest()?.as_str(), canonical(&self.ownership)?, encode_operation(&self.operation)?],
        ).map_err(sqlite_error)?;
        for resource in intent.resources() {
            connection.execute(
                "INSERT INTO runtime_replay_claim_resources (operation_id, episode_id, runtime_authority_id, participant_kind, resource_id, artifact_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![self.ownership.operation_id.as_str(), intent.episode_id().as_str(), intent.runtime_authority_id().as_str(), resource.kind().as_str(), resource.resource_id().as_str(), resource.artifact_digest().as_str()],
            ).map_err(sqlite_error)?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseBody {
    schema: String,
    reference: RuntimeParticipantClaimReferenceV1,
    recorded_at_unix_ms: u64,
}

pub(super) struct Release {
    body: ReleaseBody,
    operation: AdmissionOperationV1,
}

impl Release {
    pub(super) fn new(
        operation: &AdmissionOperationV1,
        reference: RuntimeParticipantClaimReferenceV1,
        now: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        validate_trusted_time(now, "runtime_release_time")?;
        Ok(Self {
            body: ReleaseBody {
                schema: "chio.runtime-participant-release.v1".into(),
                reference,
                recorded_at_unix_ms: now,
            },
            operation: operation.clone(),
        })
    }
    pub(super) fn digest(&self) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
        hash(
            "chio.runtime-participant-release-commit.v1",
            &(&self.body, self.operation.to_persisted()),
        )
    }
    pub(super) fn insert(
        &self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        connection.execute(
            "INSERT INTO runtime_replay_claim_releases (operation_id, episode_id, release_digest, release_json, operation_json) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![self.body.reference.operation_id().as_str(), self.body.reference.episode_id().as_str(), self.digest()?.as_str(), canonical(&self.body)?, encode_operation(&self.operation)?],
        ).map_err(sqlite_error)?;
        Ok(())
    }
}

pub(in crate::admission_operation_store) fn verify_operation(
    connection: &Connection,
    operation: &AdmissionOperationV1,
) -> Result<(), AdmissionOperationStoreError> {
    let episodes = load(connection, operation)?;
    if episodes.is_empty() != operation.runtime_participant_ledger_digest().is_none() {
        return Err(invariant(
            "runtime participant ledger attachment and history disagree",
        ));
    }
    let live: Vec<_> = episodes
        .iter()
        .filter(|episode| !episode.released)
        .collect();
    if live.len() > 1 {
        return Err(invariant(
            "runtime operation owns multiple live claim episodes",
        ));
    }
    if let Some(episode) = live.first() {
        if episode.intent().phase() == RuntimeParticipantPhase::NoncePreflight
            && (operation.execution_nonce_issuance_digest().is_some()
                || operation.dispatch_commit().is_some())
        {
            return Err(invariant(
                "runtime preflight claim must be released before issuance or dispatch",
            ));
        }
        if operation.state().is_terminal() && operation.dispatch_commit().is_none() {
            return Err(invariant(
                "runtime claim must be released before pre-dispatch termination",
            ));
        }
    }
    if !episodes.is_empty()
        && operation.dispatch_commit().is_some()
        && !live
            .first()
            .is_some_and(|episode| episode.intent().phase() == RuntimeParticipantPhase::Dispatch)
    {
        return Err(invariant(
            "dispatch commitment requires retained runtime participant ownership",
        ));
    }
    let (claims, releases): (i64, i64) = connection.query_row(
        "SELECT COALESCE(SUM(mutation_kind = 'runtime_participant_claim'), 0), COALESCE(SUM(mutation_kind = 'runtime_participant_release'), 0)
         FROM admission_operation_commits WHERE operation_id = ?1", [operation.binding().operation_id().as_str()], |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(sqlite_error)?;
    if claims != episodes.len() as i64
        || releases != episodes.iter().filter(|episode| episode.released).count() as i64
    {
        return Err(invariant(
            "runtime claim journal and physical records have different counts",
        ));
    }
    Ok(())
}

pub(super) fn load(
    connection: &Connection,
    operation: &AdmissionOperationV1,
) -> Result<Vec<Claim>, AdmissionOperationStoreError> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM runtime_replay_claim_episodes WHERE operation_id = ?1",
            [operation.binding().operation_id().as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !(0..=MAX_RUNTIME_PARTICIPANT_EPISODES as i64).contains(&count) {
        return Err(invariant("runtime claim episode count exceeds its bound"));
    }
    let mut statement = connection.prepare(
        "SELECT CASE WHEN typeof(claim_json) = 'blob' AND length(claim_json) BETWEEN 1 AND 16384 THEN claim_json END,
                CASE WHEN typeof(operation_json) = 'blob' AND length(operation_json) BETWEEN 1 AND 262144 THEN operation_json END
         FROM runtime_replay_claim_episodes WHERE operation_id = ?1 ORDER BY episode_id",
    ).map_err(sqlite_error)?;
    let mut rows = statement
        .query([operation.binding().operation_id().as_str()])
        .map_err(sqlite_error)?;
    let mut claims = Vec::with_capacity(count as usize);
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let bytes = bounded_bytes(row, 0)?;
        let snapshot = bounded_bytes(row, 1)?;
        let ownership: Ownership = decode(&bytes)?;
        let historical = decode_operation(&snapshot, operation)?;
        let mut claim = Claim {
            ownership,
            operation: historical,
            released: false,
        };
        if claim.ownership.schema != "chio.runtime-participant-claim.v1"
            || &claim.ownership.operation_id != operation.binding().operation_id()
            || Some(&claim.ownership.ledger_digest) != operation.runtime_participant_ledger_digest()
            || claim.operation.runtime_participant_ledger_digest()
                != operation.runtime_participant_ledger_digest()
            || ledger_digest(operation, claim.intent())? != claim.ownership.ledger_digest
        {
            return Err(invariant(
                "runtime claim lost its exact operation ledger binding",
            ));
        }
        require_intent(connection, &claim.operation, claim.intent())?;
        let digest = claim.digest()?;
        let exact: bool = connection.query_row(
            "SELECT COUNT(*) = 1 FROM runtime_replay_claim_episodes WHERE operation_id = ?1 AND episode_id = ?2 AND runtime_authority_id = ?3 AND ledger_digest = ?4 AND claim_digest = ?5 AND claim_json = ?6 AND operation_json = ?7",
            params![claim.ownership.operation_id.as_str(), claim.intent().episode_id().as_str(), claim.intent().runtime_authority_id().as_str(), claim.ownership.ledger_digest.as_str(), digest.as_str(), bytes, snapshot], |row| row.get(0),
        ).map_err(sqlite_error)?;
        if !exact {
            return Err(invariant(
                "runtime claim physical projection differs from canonical ownership",
            ));
        }
        let sequence = verify_commit(
            connection,
            &claim.operation,
            CLAIM_MUTATION,
            &digest,
            claim.ownership.recorded_at_unix_ms,
        )?;
        verify_resources(connection, &claim)?;
        claim.released = verify_release(connection, operation, &claim, sequence)?;
        claims.push(claim);
    }
    Ok(claims)
}

fn verify_resources(
    connection: &Connection,
    claim: &Claim,
) -> Result<(), AdmissionOperationStoreError> {
    let intent = claim.intent();
    let count: i64 = connection.query_row("SELECT COUNT(*) FROM runtime_replay_claim_resources WHERE operation_id = ?1 AND episode_id = ?2",
        params![claim.ownership.operation_id.as_str(), intent.episode_id().as_str()], |row| row.get(0)).map_err(sqlite_error)?;
    if count != intent.resources().len() as i64 {
        return Err(invariant(
            "runtime claim resource projection count mismatch",
        ));
    }
    for resource in intent.resources() {
        let exact: bool = connection.query_row(
            "SELECT COUNT(*) = 1 FROM runtime_replay_claim_resources WHERE operation_id = ?1 AND episode_id = ?2 AND runtime_authority_id = ?3 AND participant_kind = ?4 AND resource_id = ?5 AND artifact_digest = ?6",
            params![claim.ownership.operation_id.as_str(), intent.episode_id().as_str(), intent.runtime_authority_id().as_str(), resource.kind().as_str(), resource.resource_id().as_str(), resource.artifact_digest().as_str()], |row| row.get(0),
        ).map_err(sqlite_error)?;
        if !exact {
            return Err(invariant("runtime claim resource projection mismatch"));
        }
    }
    Ok(())
}

fn verify_release(
    connection: &Connection,
    current: &AdmissionOperationV1,
    claim: &Claim,
    claim_sequence: i64,
) -> Result<bool, AdmissionOperationStoreError> {
    let row = connection.query_row(
        "SELECT CASE WHEN typeof(release_json) = 'blob' AND length(release_json) BETWEEN 1 AND 16384 THEN release_json END,
                CASE WHEN typeof(operation_json) = 'blob' AND length(operation_json) BETWEEN 1 AND 262144 THEN operation_json END
         FROM runtime_replay_claim_releases WHERE operation_id = ?1 AND episode_id = ?2",
        params![claim.ownership.operation_id.as_str(), claim.intent().episode_id().as_str()], |row| Ok((bounded_bytes(row, 0), bounded_bytes(row, 1))),
    ).optional().map_err(sqlite_error)?;
    let Some((bytes, snapshot)) = row else {
        return Ok(false);
    };
    let (bytes, snapshot) = (bytes?, snapshot?);
    let body: ReleaseBody = decode(&bytes)?;
    let operation = decode_operation(&snapshot, current)?;
    if body.schema != "chio.runtime-participant-release.v1"
        || body.reference != claim.reference()?
        || operation.version() < claim.operation.version()
        || operation.dispatch_commit().is_some()
        || operation.state().is_terminal()
        || operation.runtime_participant_ledger_digest()
            != current.runtime_participant_ledger_digest()
    {
        return Err(invariant(
            "runtime release is not exact pre-dispatch ownership history",
        ));
    }
    let release = Release { body, operation };
    let digest = release.digest()?;
    let exact: bool = connection.query_row(
        "SELECT COUNT(*) = 1 FROM runtime_replay_claim_releases WHERE operation_id = ?1 AND episode_id = ?2 AND release_digest = ?3",
        params![claim.ownership.operation_id.as_str(), claim.intent().episode_id().as_str(), digest.as_str()], |row| row.get(0),
    ).map_err(sqlite_error)?;
    let release_sequence = verify_commit(
        connection,
        &release.operation,
        RELEASE_MUTATION,
        &digest,
        release.body.recorded_at_unix_ms,
    )?;
    if !exact || release_sequence <= claim_sequence {
        return Err(invariant(
            "runtime release lost its exact ordered participant commit",
        ));
    }
    Ok(true)
}

fn verify_commit(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    kind: &str,
    digest: &AdmissionDigest,
    now: u64,
) -> Result<i64, AdmissionOperationStoreError> {
    validate_trusted_time(now, "runtime_participant_time")?;
    let (count, sequence): (i64, Option<i64>) = connection.query_row(
        "SELECT COUNT(*), MIN(commit_sequence) FROM admission_operation_commits WHERE operation_id = ?1 AND operation_version = ?2 AND mutation_kind = ?3 AND participant_digest = ?4 AND operation_digest = ?5 AND recorded_at_unix_ms = ?6 AND recovery_claim_digest IS NOT NULL",
        params![operation.binding().operation_id().as_str(), sqlite_i64(operation.version(), "runtime_operation_version")?, kind, digest.as_str(), sha256_hex(&encode_operation(operation)?), sqlite_i64(now, "runtime_participant_time")?],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(sqlite_error)?;
    if count != 1 {
        return Err(invariant(
            "runtime participant lost its exact named admission commit",
        ));
    }
    sequence.ok_or_else(|| invariant("runtime participant commit sequence is absent"))
}

fn bounded_bytes(row: &Row<'_>, index: usize) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    row.get::<_, Option<Vec<u8>>>(index)
        .map_err(sqlite_error)?
        .ok_or_else(|| invariant("runtime participant record exceeds its storage bound"))
}

fn canonical(value: &impl Serialize) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    canonical_json_bytes(value).map_err(|error| invariant(error.to_string()))
}

fn decode<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, AdmissionOperationStoreError> {
    let value: T = serde_json::from_slice(bytes).map_err(|error| invariant(error.to_string()))?;
    if canonical(&value)? != bytes {
        return Err(invariant("runtime participant record is not canonical"));
    }
    Ok(value)
}

fn decode_operation(
    bytes: &[u8],
    current: &AdmissionOperationV1,
) -> Result<AdmissionOperationV1, AdmissionOperationStoreError> {
    let operation =
        AdmissionOperationV1::from_persisted(decode::<PersistedAdmissionOperationV1>(bytes)?)?;
    if operation.binding() != current.binding() || operation.version() > current.version() {
        return Err(invariant(
            "runtime participant operation snapshot binding or version mismatch",
        ));
    }
    Ok(operation)
}

pub(in crate::admission_operation_store) fn verify_all(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let orphan: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM runtime_replay_claim_episodes AS claim WHERE NOT EXISTS(SELECT 1 FROM admission_operations AS operation WHERE operation.operation_id = claim.operation_id))
         OR EXISTS(SELECT 1 FROM runtime_replay_claim_resources AS resource WHERE NOT EXISTS(SELECT 1 FROM runtime_replay_claim_episodes AS claim WHERE claim.operation_id = resource.operation_id AND claim.episode_id = resource.episode_id))
         OR EXISTS(SELECT 1 FROM runtime_replay_claim_releases AS release WHERE NOT EXISTS(SELECT 1 FROM runtime_replay_claim_episodes AS claim WHERE claim.operation_id = release.operation_id AND claim.episode_id = release.episode_id))
         OR EXISTS(SELECT 1 FROM runtime_replay_claim_resources AS resource WHERE NOT EXISTS(SELECT 1 FROM runtime_replay_claim_releases AS release WHERE release.operation_id = resource.operation_id AND release.episode_id = resource.episode_id) GROUP BY runtime_authority_id, participant_kind, resource_id HAVING COUNT(*) > 1)",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if orphan {
        return Err(invariant(
            "runtime participant records contain orphans or conflicting live owners",
        ));
    }
    let mut statement = connection.prepare("SELECT CASE WHEN typeof(operation_json) = 'blob' AND length(operation_json) BETWEEN 1 AND 262144 THEN operation_json END FROM admission_operations").map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let operation = AdmissionOperationV1::from_persisted(decode::<
            PersistedAdmissionOperationV1,
        >(&bounded_bytes(row, 0)?)?)?;
        verify_operation(connection, &operation)?;
    }
    Ok(())
}

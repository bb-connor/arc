//! Bounded canonical records and a bijection with named admission commits.
//! Verification never recursively loads an operation or re-enters its anchor.

use super::*;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ownership {
    schema: String,
    operation_id: AdmissionOperationId,
    intent: DpopReplayClaimIntentV1,
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
        intent: DpopReplayClaimIntentV1,
        ledger_digest: AdmissionDigest,
        now: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        validate_trusted_time(now, "dpop_claim_time")?;
        Ok(Self {
            ownership: Ownership {
                schema: "chio.dpop-claim.v1".into(),
                operation_id: operation.binding().operation_id().clone(),
                intent,
                ledger_digest,
                recorded_at_unix_ms: now,
            },
            operation: operation.clone(),
            released: false,
        })
    }

    pub(super) fn intent(&self) -> &DpopReplayClaimIntentV1 {
        &self.ownership.intent
    }
    pub(super) fn released(&self) -> bool {
        self.released
    }
    pub(super) fn digest(&self) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
        hash(
            "chio.dpop-claim-commit.v1",
            &(&self.ownership, &self.operation.to_persisted()),
        )
    }
    pub(super) fn reference(
        &self,
    ) -> Result<DpopReplayClaimReferenceV1, AdmissionOperationStoreError> {
        Ok(DpopReplayClaimReferenceV1::new(
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
            "INSERT INTO dpop_replay_claim_episodes (operation_id, episode_id, dpop_authority_id, ledger_digest, claim_digest, claim_json, operation_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![self.ownership.operation_id.as_str(), intent.episode_id().as_str(), intent.credential().authority().dpop_authority_id().as_str(),
                self.ownership.ledger_digest.as_str(), self.digest()?.as_str(), canonical(&self.ownership)?, encode_operation(&self.operation)?],
        ).map_err(sqlite_error)?;
        let credential = intent.credential();
        connection.execute(
            "INSERT INTO dpop_replay_claim_resources
             (operation_id, episode_id, dpop_authority_id, capability_id, nonce, proof_digest, valid_through)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![self.ownership.operation_id.as_str(), intent.episode_id().as_str(),
                credential.authority().dpop_authority_id().as_str(), credential.capability_id(), credential.nonce(),
                credential.proof_digest().as_str(), sqlite_i64(credential.valid_through_unix_secs()?, "dpop_horizon")?],
        ).map_err(sqlite_error)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseBody {
    schema: String,
    reference: DpopReplayClaimReferenceV1,
    recorded_at_unix_ms: u64,
}

pub(super) struct Release {
    body: ReleaseBody,
    operation: AdmissionOperationV1,
}

impl Release {
    pub(super) fn new(
        operation: &AdmissionOperationV1,
        reference: DpopReplayClaimReferenceV1,
        now: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        validate_trusted_time(now, "dpop_release_time")?;
        Ok(Self {
            body: ReleaseBody {
                schema: "chio.dpop-claim-release.v1".into(),
                reference,
                recorded_at_unix_ms: now,
            },
            operation: operation.clone(),
        })
    }
    pub(super) fn digest(&self) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
        hash(
            "chio.dpop-claim-release-commit.v1",
            &(&self.body, self.operation.to_persisted()),
        )
    }
    pub(super) fn insert(
        &self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        connection.execute(
            "INSERT INTO dpop_replay_claim_releases (operation_id, episode_id, release_digest, release_json, operation_json) VALUES (?1, ?2, ?3, ?4, ?5)",
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
    if episodes.is_empty() != operation.dpop_replay_ledger_digest().is_none() {
        return Err(invariant(
            "dpop participant ledger attachment and history disagree",
        ));
    }
    let live: Vec<_> = episodes
        .iter()
        .filter(|episode| !episode.released)
        .collect();
    if live.len() > 1 {
        return Err(invariant(
            "dpop operation owns multiple live claim episodes",
        ));
    }
    if let Some(episode) = live.first() {
        if episode.intent().phase() == DpopReplayClaimPhase::NoncePreflight
            && (operation.execution_nonce_issuance_digest().is_some()
                || operation.dispatch_commit().is_some())
        {
            return Err(invariant(
                "dpop preflight claim must be released before issuance or dispatch",
            ));
        }
        if operation.state().is_terminal() && operation.dispatch_commit().is_none() {
            return Err(invariant(
                "dpop claim must be released before pre-dispatch termination",
            ));
        }
    }
    if !episodes.is_empty()
        && operation.dispatch_commit().is_some()
        && !live
            .first()
            .is_some_and(|episode| episode.intent().phase() == DpopReplayClaimPhase::Dispatch)
    {
        return Err(invariant(
            "dispatch commitment requires retained dpop participant ownership",
        ));
    }
    let (claims, releases): (i64, i64) = connection.query_row(
        "SELECT COALESCE(SUM(mutation_kind = 'dpop_replay_claim'), 0), COALESCE(SUM(mutation_kind = 'dpop_replay_release'), 0)
         FROM admission_operation_commits WHERE operation_id = ?1", [operation.binding().operation_id().as_str()], |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(sqlite_error)?;
    if claims != episodes.len() as i64
        || releases != episodes.iter().filter(|episode| episode.released).count() as i64
    {
        return Err(invariant(
            "dpop claim journal and physical records have different counts",
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
            "SELECT COUNT(*) FROM dpop_replay_claim_episodes WHERE operation_id = ?1",
            [operation.binding().operation_id().as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !(0..=MAX_DPOP_CLAIM_EPISODES as i64).contains(&count) {
        return Err(invariant("dpop claim episode count exceeds its bound"));
    }
    let mut statement = connection.prepare(
        "SELECT CASE WHEN typeof(claim_json) = 'blob' AND length(claim_json) BETWEEN 1 AND 65536 THEN claim_json END,
                CASE WHEN typeof(operation_json) = 'blob' AND length(operation_json) BETWEEN 1 AND 262144 THEN operation_json END
         FROM dpop_replay_claim_episodes WHERE operation_id = ?1 ORDER BY episode_id",
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
        if claim.ownership.schema != "chio.dpop-claim.v1"
            || &claim.ownership.operation_id != operation.binding().operation_id()
            || Some(&claim.ownership.ledger_digest) != operation.dpop_replay_ledger_digest()
            || claim.operation.dpop_replay_ledger_digest() != operation.dpop_replay_ledger_digest()
            || ledger_digest(operation, claim.intent())? != claim.ownership.ledger_digest
        {
            return Err(invariant(
                "dpop claim lost its exact operation ledger binding",
            ));
        }
        let source = require_intent(connection, &claim.operation, claim.intent())?;
        let digest = claim.digest()?;
        let exact: bool = connection.query_row(
            "SELECT COUNT(*) = 1 FROM dpop_replay_claim_episodes WHERE operation_id = ?1 AND episode_id = ?2 AND dpop_authority_id = ?3 AND ledger_digest = ?4 AND claim_digest = ?5 AND claim_json = ?6 AND operation_json = ?7",
            params![claim.ownership.operation_id.as_str(), claim.intent().episode_id().as_str(), claim.intent().credential().authority().dpop_authority_id().as_str(), claim.ownership.ledger_digest.as_str(), digest.as_str(), bytes, snapshot], |row| row.get(0),
        ).map_err(sqlite_error)?;
        if !exact {
            return Err(invariant(
                "dpop claim physical projection differs from canonical ownership",
            ));
        }
        let sequence = verify_commit(
            connection,
            &claim.operation,
            CLAIM_MUTATION,
            &digest,
            claim.ownership.recorded_at_unix_ms,
        )?;
        let (authority_time, observed): (i64, i64) = connection.query_row(
            "SELECT MAX(recorded_at_unix_ms, observed_at_unix_ms), observed_at_unix_ms FROM admission_operation_commits WHERE commit_sequence = ?1",
            [sequence], |row| Ok((row.get(0)?, row.get(1)?))).map_err(sqlite_error)?;
        claim
            .intent()
            .credential()
            .validate_at(stored_u64(authority_time, "dpop_claim_clock")?)?;
        // The same read verified this immutable source with the claim intent.
        // No write or external callback separates that verification and its
        // historical clock check, so a second full catalog read adds no evidence.
        dpop_replay::verify_source_clock_floor(
            &source,
            stored_u64(observed, "dpop_claim_observation")?,
        )?;
        verify_resources(connection, &claim)?;
        claim.released = verify_release(connection, operation, &claim, sequence)?;
        claims.push(claim);
    }
    Ok(claims)
}

/// Persisted dispatch authority is evaluated at its anchored commit observation,
/// not at recovery time. This also catches expiry between the pre-write check
/// and commit append without leaving a partial dispatch or budget capture.
pub(in crate::admission_operation_store) fn verify_stored_operation(
    connection: &Connection,
    operation: &AdmissionOperationV1,
) -> Result<(), AdmissionOperationStoreError> {
    verify_operation(connection, operation)?;
    let Some(dispatch) = operation.dispatch_commit() else {
        return Ok(());
    };
    if operation.dpop_replay_ledger_digest().is_none() {
        return Ok(());
    }
    let episodes = load(connection, operation)?;
    let claim = episodes
        .iter()
        .find(|claim| !claim.released())
        .ok_or_else(|| invariant("persisted dpop dispatch has no retained owner"))?;
    let (count, sequence, observed, recorded): (i64, Option<i64>, Option<i64>, Option<i64>) = connection.query_row(
        "SELECT COUNT(*), MIN(commit_sequence), MIN(observed_at_unix_ms), MIN(recorded_at_unix_ms)
         FROM admission_operation_commits WHERE operation_id = ?1 AND operation_version = ?2
           AND mutation_kind = 'compare_and_swap' AND recovery_claim_digest IS NOT NULL",
        params![operation.binding().operation_id().as_str(), sqlite_i64(dispatch.committed_version, "dpop_dispatch_version")?],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))).map_err(sqlite_error)?;
    let claim_sequence = verify_commit(
        connection,
        &claim.operation,
        CLAIM_MUTATION,
        &claim.digest()?,
        claim.ownership.recorded_at_unix_ms,
    )?;
    if count != 1 || sequence.is_none_or(|sequence| sequence <= claim_sequence) {
        return Err(invariant("dpop dispatch lost its exact ordered commitment"));
    }
    let observed = stored_u64(
        observed.ok_or_else(|| invariant("dpop dispatch observation absent"))?,
        "dpop_dispatch_observation",
    )?;
    let recorded = stored_u64(
        recorded.ok_or_else(|| invariant("dpop dispatch time absent"))?,
        "dpop_dispatch_time",
    )?;
    let source =
        dpop_replay::require_active_authority(connection, claim.intent().credential().authority())?;
    dpop_replay::verify_source_clock_floor(&source, observed)?;
    claim
        .intent()
        .credential()
        .validate_at(observed.max(recorded))?;
    Ok(())
}

fn verify_resources(
    connection: &Connection,
    claim: &Claim,
) -> Result<(), AdmissionOperationStoreError> {
    let intent = claim.intent();
    let credential = intent.credential();
    let exact: bool = connection
        .query_row(
            "SELECT COUNT(*) = 1 AND COALESCE(MIN(dpop_authority_id = ?3 AND capability_id = ?4
            AND nonce = ?5 AND proof_digest = ?6 AND valid_through = ?7), 0)
         FROM dpop_replay_claim_resources WHERE operation_id = ?1 AND episode_id = ?2",
            params![
                claim.ownership.operation_id.as_str(),
                intent.episode_id().as_str(),
                credential.authority().dpop_authority_id().as_str(),
                credential.capability_id(),
                credential.nonce(),
                credential.proof_digest().as_str(),
                sqlite_i64(credential.valid_through_unix_secs()?, "dpop_horizon")?
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !exact {
        return Err(invariant(
            "DPoP resource projection differs from canonical claim",
        ));
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
        "SELECT CASE WHEN typeof(release_json) = 'blob' AND length(release_json) BETWEEN 1 AND 65536 THEN release_json END,
                CASE WHEN typeof(operation_json) = 'blob' AND length(operation_json) BETWEEN 1 AND 262144 THEN operation_json END
         FROM dpop_replay_claim_releases WHERE operation_id = ?1 AND episode_id = ?2",
        params![claim.ownership.operation_id.as_str(), claim.intent().episode_id().as_str()], |row| Ok((bounded_bytes(row, 0), bounded_bytes(row, 1))),
    ).optional().map_err(sqlite_error)?;
    let Some((bytes, snapshot)) = row else {
        return Ok(false);
    };
    let (bytes, snapshot) = (bytes?, snapshot?);
    let body: ReleaseBody = decode(&bytes)?;
    let operation = decode_operation(&snapshot, current)?;
    if body.schema != "chio.dpop-claim-release.v1"
        || body.reference != claim.reference()?
        || operation.version() < claim.operation.version()
        || operation.dispatch_commit().is_some()
        || operation.state().is_terminal()
        || operation.dpop_replay_ledger_digest() != current.dpop_replay_ledger_digest()
    {
        return Err(invariant(
            "dpop release is not exact pre-dispatch ownership history",
        ));
    }
    let release = Release { body, operation };
    let digest = release.digest()?;
    let exact: bool = connection.query_row(
        "SELECT COUNT(*) = 1 FROM dpop_replay_claim_releases WHERE operation_id = ?1 AND episode_id = ?2 AND release_digest = ?3",
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
            "dpop release lost its exact ordered participant commit",
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
    validate_trusted_time(now, "dpop_replay_claim_time")?;
    let (count, sequence): (i64, Option<i64>) = connection.query_row(
        "SELECT COUNT(*), MIN(commit_sequence) FROM admission_operation_commits WHERE operation_id = ?1 AND operation_version = ?2 AND mutation_kind = ?3 AND participant_digest = ?4 AND operation_digest = ?5 AND recorded_at_unix_ms = ?6 AND recovery_claim_digest IS NOT NULL",
        params![operation.binding().operation_id().as_str(), sqlite_i64(operation.version(), "dpop_operation_version")?, kind, digest.as_str(), sha256_hex(&encode_operation(operation)?), sqlite_i64(now, "dpop_replay_claim_time")?],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(sqlite_error)?;
    if count != 1 {
        return Err(invariant(
            "dpop participant lost its exact named admission commit",
        ));
    }
    sequence.ok_or_else(|| invariant("dpop participant commit sequence is absent"))
}

fn bounded_bytes(row: &Row<'_>, index: usize) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    row.get::<_, Option<Vec<u8>>>(index)
        .map_err(sqlite_error)?
        .ok_or_else(|| invariant("dpop participant record exceeds its storage bound"))
}

fn canonical(value: &impl Serialize) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    canonical_json_bytes(value).map_err(|error| invariant(error.to_string()))
}

fn decode<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, AdmissionOperationStoreError> {
    let value: T = serde_json::from_slice(bytes).map_err(|error| invariant(error.to_string()))?;
    if canonical(&value)? != bytes {
        return Err(invariant("dpop participant record is not canonical"));
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
            "dpop participant operation snapshot binding or version mismatch",
        ));
    }
    Ok(operation)
}

pub(in crate::admission_operation_store) fn verify_all(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let orphan: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM dpop_replay_claim_episodes AS claim WHERE NOT EXISTS(SELECT 1 FROM admission_operations AS operation WHERE operation.operation_id = claim.operation_id))
         OR EXISTS(SELECT 1 FROM dpop_replay_claim_resources AS resource WHERE NOT EXISTS(SELECT 1 FROM dpop_replay_claim_episodes AS claim WHERE claim.operation_id = resource.operation_id AND claim.episode_id = resource.episode_id))
         OR EXISTS(SELECT 1 FROM dpop_replay_claim_releases AS release WHERE NOT EXISTS(SELECT 1 FROM dpop_replay_claim_episodes AS claim WHERE claim.operation_id = release.operation_id AND claim.episode_id = release.episode_id))
         OR EXISTS(SELECT 1 FROM dpop_replay_claim_resources AS resource WHERE NOT EXISTS(SELECT 1 FROM dpop_replay_claim_releases AS release WHERE release.operation_id = resource.operation_id AND release.episode_id = resource.episode_id) GROUP BY dpop_authority_id, capability_id, nonce HAVING COUNT(*) > 1)",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if orphan {
        return Err(invariant(
            "dpop participant records contain orphans or conflicting live owners",
        ));
    }
    let mut statement = connection.prepare("SELECT CASE WHEN typeof(operation_json) = 'blob' AND length(operation_json) BETWEEN 1 AND 262144 THEN operation_json END FROM admission_operations").map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let operation = AdmissionOperationV1::from_persisted(decode::<
            PersistedAdmissionOperationV1,
        >(&bounded_bytes(row, 0)?)?)?;
        verify_stored_operation(connection, &operation)?;
    }
    Ok(())
}

//! Bounded canonical records and a bijection with named admission commits.
//! Verification never recursively loads an operation or re-enters its anchor.

use super::*;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ownership {
    schema: String,
    operation_id: AdmissionOperationId,
    intent: GovernedApprovalClaimIntentV1,
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
        intent: GovernedApprovalClaimIntentV1,
        ledger_digest: AdmissionDigest,
        now: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        validate_trusted_time(now, "approval_claim_time")?;
        Ok(Self {
            ownership: Ownership {
                schema: "chio.governed-approval-claim.v1".into(),
                operation_id: operation.binding().operation_id().clone(),
                intent,
                ledger_digest,
                recorded_at_unix_ms: now,
            },
            operation: operation.clone(),
            released: false,
        })
    }

    pub(super) fn intent(&self) -> &GovernedApprovalClaimIntentV1 {
        &self.ownership.intent
    }
    pub(super) fn released(&self) -> bool {
        self.released
    }
    pub(super) fn digest(&self) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
        hash(
            "chio.governed-approval-claim-commit.v1",
            &(&self.ownership, &self.operation.to_persisted()),
        )
    }
    pub(super) fn reference(
        &self,
    ) -> Result<GovernedApprovalClaimReferenceV1, AdmissionOperationStoreError> {
        Ok(GovernedApprovalClaimReferenceV1::new(
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
            "INSERT INTO governed_approval_replay_claim_episodes (operation_id, episode_id, approval_authority_id, ledger_digest, claim_digest, claim_json, operation_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![self.ownership.operation_id.as_str(), intent.episode_id().as_str(), intent.approval_authority_id().as_str(),
                self.ownership.ledger_digest.as_str(), self.digest()?.as_str(), canonical(&self.ownership)?, encode_operation(&self.operation)?],
        ).map_err(sqlite_error)?;
        let credential = intent.credential();
        connection.execute(
            "INSERT INTO governed_approval_replay_claim_resources
             (operation_id, episode_id, approval_authority_id, subject_id, request_id, intent_hash, token_digest, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![self.ownership.operation_id.as_str(), intent.episode_id().as_str(), intent.approval_authority_id().as_str(),
                credential.subject_id.as_str(), credential.request_id.as_str(), credential.intent_hash.as_str(),
                credential.token_digest.as_str(), sqlite_i64(credential.expires_at_unix_secs, "approval_expiry")?],
        ).map_err(sqlite_error)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseBody {
    schema: String,
    reference: GovernedApprovalClaimReferenceV1,
    recorded_at_unix_ms: u64,
}

pub(super) struct Release {
    body: ReleaseBody,
    operation: AdmissionOperationV1,
}

impl Release {
    pub(super) fn new(
        operation: &AdmissionOperationV1,
        reference: GovernedApprovalClaimReferenceV1,
        now: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        validate_trusted_time(now, "approval_release_time")?;
        Ok(Self {
            body: ReleaseBody {
                schema: "chio.governed-approval-claim-release.v1".into(),
                reference,
                recorded_at_unix_ms: now,
            },
            operation: operation.clone(),
        })
    }
    pub(super) fn digest(&self) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
        hash(
            "chio.governed-approval-claim-release-commit.v1",
            &(&self.body, self.operation.to_persisted()),
        )
    }
    pub(super) fn insert(
        &self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        connection.execute(
            "INSERT INTO governed_approval_replay_claim_releases (operation_id, episode_id, release_digest, release_json, operation_json) VALUES (?1, ?2, ?3, ?4, ?5)",
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
    if episodes.is_empty() != operation.governed_approval_ledger_digest().is_none() {
        return Err(invariant(
            "approval participant ledger attachment and history disagree",
        ));
    }
    let live: Vec<_> = episodes
        .iter()
        .filter(|episode| !episode.released)
        .collect();
    if live.len() > 1 {
        return Err(invariant(
            "approval operation owns multiple live claim episodes",
        ));
    }
    if let Some(episode) = live.first() {
        if episode.intent().phase() == GovernedApprovalClaimPhase::NoncePreflight
            && (operation.execution_nonce_issuance_digest().is_some()
                || operation.dispatch_commit().is_some())
        {
            return Err(invariant(
                "approval preflight claim must be released before issuance or dispatch",
            ));
        }
        if operation.state().is_terminal() && operation.dispatch_commit().is_none() {
            return Err(invariant(
                "approval claim must be released before pre-dispatch termination",
            ));
        }
    }
    if !episodes.is_empty()
        && operation.dispatch_commit().is_some()
        && !live
            .first()
            .is_some_and(|episode| episode.intent().phase() == GovernedApprovalClaimPhase::Dispatch)
    {
        return Err(invariant(
            "dispatch commitment requires retained approval participant ownership",
        ));
    }
    let (claims, releases): (i64, i64) = connection.query_row(
        "SELECT COALESCE(SUM(mutation_kind = 'governed_approval_claim'), 0), COALESCE(SUM(mutation_kind = 'governed_approval_release'), 0)
         FROM admission_operation_commits WHERE operation_id = ?1", [operation.binding().operation_id().as_str()], |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(sqlite_error)?;
    if claims != episodes.len() as i64
        || releases != episodes.iter().filter(|episode| episode.released).count() as i64
    {
        return Err(invariant(
            "approval claim journal and physical records have different counts",
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
            "SELECT COUNT(*) FROM governed_approval_replay_claim_episodes WHERE operation_id = ?1",
            [operation.binding().operation_id().as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !(0..=MAX_GOVERNED_APPROVAL_CLAIM_EPISODES as i64).contains(&count) {
        return Err(invariant("approval claim episode count exceeds its bound"));
    }
    let mut statement = connection.prepare(
        "SELECT CASE WHEN typeof(claim_json) = 'blob' AND length(claim_json) BETWEEN 1 AND 16384 THEN claim_json END,
                CASE WHEN typeof(operation_json) = 'blob' AND length(operation_json) BETWEEN 1 AND 262144 THEN operation_json END
         FROM governed_approval_replay_claim_episodes WHERE operation_id = ?1 ORDER BY episode_id",
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
        if claim.ownership.schema != "chio.governed-approval-claim.v1"
            || &claim.ownership.operation_id != operation.binding().operation_id()
            || Some(&claim.ownership.ledger_digest) != operation.governed_approval_ledger_digest()
            || claim.operation.governed_approval_ledger_digest()
                != operation.governed_approval_ledger_digest()
            || ledger_digest(operation, claim.intent())? != claim.ownership.ledger_digest
        {
            return Err(invariant(
                "approval claim lost its exact operation ledger binding",
            ));
        }
        require_intent(connection, &claim.operation, claim.intent())?;
        let digest = claim.digest()?;
        let exact: bool = connection.query_row(
            "SELECT COUNT(*) = 1 FROM governed_approval_replay_claim_episodes WHERE operation_id = ?1 AND episode_id = ?2 AND approval_authority_id = ?3 AND ledger_digest = ?4 AND claim_digest = ?5 AND claim_json = ?6 AND operation_json = ?7",
            params![claim.ownership.operation_id.as_str(), claim.intent().episode_id().as_str(), claim.intent().approval_authority_id().as_str(), claim.ownership.ledger_digest.as_str(), digest.as_str(), bytes, snapshot], |row| row.get(0),
        ).map_err(sqlite_error)?;
        if !exact {
            return Err(invariant(
                "approval claim physical projection differs from canonical ownership",
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
            .validate_at(stored_u64(authority_time, "approval_claim_clock")?)?;
        let source = governed_approval_replay::require_active_source(
            connection,
            claim.intent().approval_authority_id(),
            claim.intent().expectation_id(),
        )?;
        governed_approval_replay::verify_source_clock_floor(
            &source,
            stored_u64(observed, "approval_claim_observation")?,
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
    if operation.governed_approval_ledger_digest().is_none() {
        return Ok(());
    }
    let episodes = load(connection, operation)?;
    let claim = episodes
        .iter()
        .find(|claim| !claim.released())
        .ok_or_else(|| invariant("persisted approval dispatch has no retained owner"))?;
    let (count, sequence, observed, recorded): (i64, Option<i64>, Option<i64>, Option<i64>) = connection.query_row(
        "SELECT COUNT(*), MIN(commit_sequence), MIN(observed_at_unix_ms), MIN(recorded_at_unix_ms)
         FROM admission_operation_commits WHERE operation_id = ?1 AND operation_version = ?2
           AND mutation_kind = 'compare_and_swap' AND recovery_claim_digest IS NOT NULL",
        params![operation.binding().operation_id().as_str(), sqlite_i64(dispatch.committed_version, "approval_dispatch_version")?],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))).map_err(sqlite_error)?;
    let claim_sequence = verify_commit(
        connection,
        &claim.operation,
        CLAIM_MUTATION,
        &claim.digest()?,
        claim.ownership.recorded_at_unix_ms,
    )?;
    if count != 1 || sequence.is_none_or(|sequence| sequence <= claim_sequence) {
        return Err(invariant(
            "approval dispatch lost its exact ordered commitment",
        ));
    }
    let observed = stored_u64(
        observed.ok_or_else(|| invariant("approval dispatch observation absent"))?,
        "approval_dispatch_observation",
    )?;
    let recorded = stored_u64(
        recorded.ok_or_else(|| invariant("approval dispatch time absent"))?,
        "approval_dispatch_time",
    )?;
    let source = governed_approval_replay::require_active_source(
        connection,
        claim.intent().approval_authority_id(),
        claim.intent().expectation_id(),
    )?;
    governed_approval_replay::verify_source_clock_floor(&source, observed)?;
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
            "SELECT COUNT(*) = 1 AND COALESCE(MIN(approval_authority_id = ?3 AND subject_id = ?4
            AND request_id = ?5 AND intent_hash = ?6 AND token_digest = ?7 AND expires_at = ?8), 0)
         FROM governed_approval_replay_claim_resources WHERE operation_id = ?1 AND episode_id = ?2",
            params![
                claim.ownership.operation_id.as_str(),
                intent.episode_id().as_str(),
                intent.approval_authority_id().as_str(),
                credential.subject_id.as_str(),
                credential.request_id.as_str(),
                credential.intent_hash.as_str(),
                credential.token_digest.as_str(),
                sqlite_i64(credential.expires_at_unix_secs, "approval_expiry")?
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !exact {
        return Err(invariant(
            "approval credential projection differs from canonical claim",
        ));
    }
    let legacy_conflict: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM governed_approval_replay_legacy_tombstones
         WHERE approval_authority_id = ?1 AND request_id = ?2 AND intent_hash = ?3
           AND (subject_id = ?4 OR subject_id = ?5))",
        params![intent.approval_authority_id().as_str(), credential.request_id.as_str(), credential.intent_hash.as_str(),
            credential.subject_id.as_str(), chio_kernel::admission_operation::governed_approval_replay::LEGACY_UNSCOPED_GOVERNED_APPROVAL_SUBJECT],
        |row| row.get(0)).map_err(sqlite_error)?;
    if legacy_conflict {
        return Err(invariant(
            "approval claim conflicts with permanent imported replay history",
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
        "SELECT CASE WHEN typeof(release_json) = 'blob' AND length(release_json) BETWEEN 1 AND 16384 THEN release_json END,
                CASE WHEN typeof(operation_json) = 'blob' AND length(operation_json) BETWEEN 1 AND 262144 THEN operation_json END
         FROM governed_approval_replay_claim_releases WHERE operation_id = ?1 AND episode_id = ?2",
        params![claim.ownership.operation_id.as_str(), claim.intent().episode_id().as_str()], |row| Ok((bounded_bytes(row, 0), bounded_bytes(row, 1))),
    ).optional().map_err(sqlite_error)?;
    let Some((bytes, snapshot)) = row else {
        return Ok(false);
    };
    let (bytes, snapshot) = (bytes?, snapshot?);
    let body: ReleaseBody = decode(&bytes)?;
    let operation = decode_operation(&snapshot, current)?;
    if body.schema != "chio.governed-approval-claim-release.v1"
        || body.reference != claim.reference()?
        || operation.version() < claim.operation.version()
        || operation.dispatch_commit().is_some()
        || operation.state().is_terminal()
        || operation.governed_approval_ledger_digest() != current.governed_approval_ledger_digest()
    {
        return Err(invariant(
            "approval release is not exact pre-dispatch ownership history",
        ));
    }
    let release = Release { body, operation };
    let digest = release.digest()?;
    let exact: bool = connection.query_row(
        "SELECT COUNT(*) = 1 FROM governed_approval_replay_claim_releases WHERE operation_id = ?1 AND episode_id = ?2 AND release_digest = ?3",
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
            "approval release lost its exact ordered participant commit",
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
    validate_trusted_time(now, "governed_approval_claim_time")?;
    let (count, sequence): (i64, Option<i64>) = connection.query_row(
        "SELECT COUNT(*), MIN(commit_sequence) FROM admission_operation_commits WHERE operation_id = ?1 AND operation_version = ?2 AND mutation_kind = ?3 AND participant_digest = ?4 AND operation_digest = ?5 AND recorded_at_unix_ms = ?6 AND recovery_claim_digest IS NOT NULL",
        params![operation.binding().operation_id().as_str(), sqlite_i64(operation.version(), "approval_operation_version")?, kind, digest.as_str(), sha256_hex(&encode_operation(operation)?), sqlite_i64(now, "governed_approval_claim_time")?],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(sqlite_error)?;
    if count != 1 {
        return Err(invariant(
            "approval participant lost its exact named admission commit",
        ));
    }
    sequence.ok_or_else(|| invariant("approval participant commit sequence is absent"))
}

fn bounded_bytes(row: &Row<'_>, index: usize) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    row.get::<_, Option<Vec<u8>>>(index)
        .map_err(sqlite_error)?
        .ok_or_else(|| invariant("approval participant record exceeds its storage bound"))
}

fn canonical(value: &impl Serialize) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    canonical_json_bytes(value).map_err(|error| invariant(error.to_string()))
}

fn decode<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, AdmissionOperationStoreError> {
    let value: T = serde_json::from_slice(bytes).map_err(|error| invariant(error.to_string()))?;
    if canonical(&value)? != bytes {
        return Err(invariant("approval participant record is not canonical"));
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
            "approval participant operation snapshot binding or version mismatch",
        ));
    }
    Ok(operation)
}

pub(in crate::admission_operation_store) fn verify_all(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let orphan: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM governed_approval_replay_claim_episodes AS claim WHERE NOT EXISTS(SELECT 1 FROM admission_operations AS operation WHERE operation.operation_id = claim.operation_id))
         OR EXISTS(SELECT 1 FROM governed_approval_replay_claim_resources AS resource WHERE NOT EXISTS(SELECT 1 FROM governed_approval_replay_claim_episodes AS claim WHERE claim.operation_id = resource.operation_id AND claim.episode_id = resource.episode_id))
         OR EXISTS(SELECT 1 FROM governed_approval_replay_claim_releases AS release WHERE NOT EXISTS(SELECT 1 FROM governed_approval_replay_claim_episodes AS claim WHERE claim.operation_id = release.operation_id AND claim.episode_id = release.episode_id))
         OR EXISTS(SELECT 1 FROM governed_approval_replay_claim_resources AS resource WHERE NOT EXISTS(SELECT 1 FROM governed_approval_replay_claim_releases AS release WHERE release.operation_id = resource.operation_id AND release.episode_id = resource.episode_id) GROUP BY approval_authority_id, subject_id, request_id, intent_hash HAVING COUNT(*) > 1)",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if orphan {
        return Err(invariant(
            "approval participant records contain orphans or conflicting live owners",
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

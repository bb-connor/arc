//! Tenant counters retain their original census and authenticate every current head.
use super::*;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
enum ReferenceCapacitySchema {
    #[serde(rename = "chio.knowledge.reference-capacity.v1")]
    V1,
}

#[derive(Serialize)]
enum CapacityIdentity {
    KnowledgeReferenceOwner,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapacityBaseline {
    cutoff: ReferenceCutoff,
    cohort_digest: CanonicalPayloadDigest,
    census_digest: CanonicalPayloadDigest,
    artifact_count: u64,
    active_owners: u64,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReferenceCapacity {
    schema: ReferenceCapacitySchema,
    account: ReferenceAccount,
    baseline: CapacityBaseline,
    pub(super) admitted: u64,
    pub(super) retired: u64,
    pub(super) batches: u64,
}

impl ReferenceCapacity {
    pub(super) fn from_baseline(proof: &VerifiedKnowledgeReferenceAccountBaseline<'_, '_>) -> Self {
        Self {
            schema: ReferenceCapacitySchema::V1,
            account: ReferenceAccount::from_scope(proof.scope()),
            baseline: CapacityBaseline {
                cutoff: proof.global_cutoff().clone(),
                cohort_digest: proof.cohort_digest(),
                census_digest: proof.census_digest(),
                artifact_count: proof.artifact_count(),
                active_owners: proof.active_reference_owners(),
            },
            admitted: 0,
            retired: 0,
            batches: 0,
        }
    }

    pub(super) fn active(&self) -> Result<u64, AdmissionOperationStoreError> {
        self.baseline
            .active_owners
            .checked_add(self.admitted)
            .and_then(|total| total.checked_sub(self.retired))
            .ok_or_else(|| invariant("reference capacity counter is inconsistent"))
    }

    fn original(&self) -> Self {
        let mut original = self.clone();
        original.admitted = 0;
        original.retired = 0;
        original.batches = 0;
        original
    }

    pub(super) fn cutoff(&self) -> &ReferenceCutoff {
        &self.baseline.cutoff
    }

    pub(super) fn cohort_digest(&self) -> &CanonicalPayloadDigest {
        &self.baseline.cohort_digest
    }

    fn validate(&self, version: u64) -> Result<(), AdmissionOperationStoreError> {
        for number in [
            version,
            self.baseline.artifact_count,
            self.baseline.active_owners,
            self.admitted,
            self.retired,
            self.batches,
            self.active()?,
        ] {
            SafeInteger::new(number)
                .map_err(|_| invariant("reference capacity integer exhausted"))?;
        }
        if self.batches.checked_add(1) != Some(version)
            || (self.batches == 0 && (self.admitted != 0 || self.retired != 0))
            || self
                .admitted
                .checked_add(self.retired)
                .is_none_or(|arcs| arcs < self.batches)
        {
            return Err(invariant("reference capacity revision changed its batches"));
        }
        Ok(())
    }

    pub(super) fn matches_ready(&self, ready: &ReadyReferenceAccount) -> bool {
        self.baseline.cutoff == *ready.cutoff()
            && self.baseline.cohort_digest == *ready.cohort_digest()
            && self.baseline.census_digest == *ready.census_digest()
            && self.baseline.artifact_count == ready.artifact_count()
            && self.baseline.active_owners == ready.active_owner_count()
    }

    pub(super) fn matches_ready_record(&self, ready: &ReferenceReadyRecord) -> bool {
        self.account == ready.account
            && self.baseline.cutoff == ready.cutoff
            && self.baseline.cohort_digest == ready.cohort_digest
            && self.baseline.census_digest == ready.census_digest
            && self.baseline.artifact_count == ready.artifact_count.get()
            && self.baseline.active_owners == ready.active_owner_count.get()
            && self.admitted == 0
            && self.retired == 0
            && self.batches == 0
    }
}

pub(super) fn identity(
    scope: &RecoveryScopeV1,
) -> Result<(String, String), AdmissionOperationStoreError> {
    identity_account(&ReferenceAccount::from_scope(scope))
}

fn identity_account(
    account: &ReferenceAccount,
) -> Result<(String, String), AdmissionOperationStoreError> {
    let hash = sha256_hex(&encode(&(
        chio_core_types::recovery::RecoveryDigestDomain::ParticipantOwner.name(),
        CapacityIdentity::KnowledgeReferenceOwner,
        &account.authority_domain,
        &account.tenant_id,
    ))?);
    Ok((format!("knowledge-reference-capacity:{hash}"), hash))
}

pub(super) fn load_capacity(
    tx: &Connection,
    scope: &RecoveryScopeV1,
) -> Result<(ReferenceCapacity, ProtectedSourceReference), AdmissionOperationStoreError> {
    load_capacity_account(tx, &ReferenceAccount::from_scope(scope))
}

pub(super) fn load_capacity_account(
    tx: &Connection,
    account_identity: &ReferenceAccount,
) -> Result<(ReferenceCapacity, ProtectedSourceReference), AdmissionOperationStoreError> {
    let (key, account_scope) = identity_account(account_identity)?;
    let row =
        raw_checked(tx, &key)?.ok_or_else(|| invariant("reference capacity is not initialized"))?;
    let source = source_reference(tx, &key)?;
    ordinary_header(tx, &key)?;
    if row.kind != "command"
        || row.scope != account_scope
        || row.payload.len() > ACCOUNT_RECORD_BYTES
    {
        return Err(invariant("reference capacity changed its protected header"));
    }
    let account: ReferenceCapacity = decode(&row.payload)?;
    if account.account != *account_identity {
        return Err(invariant("reference capacity changed its tenant"));
    }
    account.validate(row.version)?;
    account.baseline.cutoff.verify(tx)?;
    if !matches_historical_command_payload(
        tx,
        &key,
        &account_scope,
        1,
        &encode(&account.original())?,
    )? {
        return Err(invariant("reference capacity changed its original census"));
    }
    Ok((account, source))
}

pub(super) fn require_ready_capacity(
    tx: &Connection,
    scope: &RecoveryScopeV1,
) -> Result<
    (
        ReferenceCapacity,
        ProtectedSourceReference,
        ProtectedSourceReference,
    ),
    AdmissionOperationStoreError,
> {
    let (account, source) = load_capacity(tx, scope)?;
    let ready = ready_reference_account(tx, scope)?;
    ready.verify_current(tx)?;
    if !account.matches_ready(&ready) {
        return Err(invariant(
            "reference capacity and readiness disagree on their census",
        ));
    }
    let ready_source = source_reference(tx, ready.source().record_key())?;
    Ok((account, source, ready_source))
}

pub(super) fn save_capacity(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    scope: &RecoveryScopeV1,
    value: &ReferenceCapacity,
    expected: Option<&ProtectedSourceReference>,
) -> Result<(ProtectedSourceReference, u64), AdmissionOperationStoreError> {
    let (key, account_scope) = identity(scope)?;
    if value.account != ReferenceAccount::from_scope(scope) {
        return Err(invariant("reference counter writer changed its tenant"));
    }
    let version = expected
        .map_or(0, ProtectedSourceReference::version)
        .checked_add(1)
        .ok_or_else(|| invariant("reference capacity revision exhausted"))?;
    value.validate(version)?;
    match expected {
        Some(source) => {
            if source.record_key() != key
                || source.scope_key() != account_scope
                || source.kind() != "command"
            {
                return Err(invariant("reference counter writer changed its exact head"));
            }
            verify_source_reference(tx, source)?;
        }
        None if raw_checked(tx, &key)?.is_some() => {
            return Err(invariant("reference capacity census was already installed"));
        }
        None => {}
    }
    let bytes = encode(value)?;
    if bytes.len() > ACCOUNT_RECORD_BYTES {
        return Err(invariant("reference capacity exceeds its closed envelope"));
    }
    persist_record(tx, owner, &key, &account_scope, "command", &bytes, None)?;
    let current = source_reference(tx, &key)?;
    if current.version() != version {
        return Err(invariant("reference counter writer changed its revision"));
    }
    Ok((
        current,
        u64::try_from(bytes.len())
            .map_err(|_| invariant("reference capacity byte count overflow"))?,
    ))
}

#[cfg(test)]
#[path = "reference_capacity_tests.rs"]
mod tests;

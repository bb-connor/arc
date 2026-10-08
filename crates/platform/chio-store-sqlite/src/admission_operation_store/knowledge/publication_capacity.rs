//! Live publication slots are distinct from retained physical finishing debt.
use super::reference_source::ReferenceCutoff;
use super::references::{ReferenceAccount, SourceAnchor};
use super::*;

mod cold;
pub(super) mod collection;

const MAX_LIVE_PUBLICATIONS: u64 = 512;
const ACCOUNT_BYTES: usize = 4096;
const LEASE_BYTES: usize = 16384;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
enum CapacitySchema {
    #[serde(rename = "chio.knowledge.publication-capacity.v1")]
    V1,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapacityBaseline {
    cutoff: ReferenceCutoff,
    census: CanonicalPayloadDigest,
    live: u64,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapacityRecord {
    schema: CapacitySchema,
    account: ReferenceAccount,
    baseline: CapacityBaseline,
    admitted: u64,
    collected: u64,
    changes: u64,
}

impl CapacityRecord {
    fn live(&self) -> Result<u64, AdmissionOperationStoreError> {
        self.baseline
            .live
            .checked_add(self.admitted)
            .and_then(|value| value.checked_sub(self.collected))
            .ok_or_else(|| refused("publication live counter changed its original owners"))
    }

    fn original(&self) -> Self {
        let mut original = self.clone();
        original.admitted = 0;
        original.collected = 0;
        original.changes = 0;
        original
    }

    fn validate(&self, version: u64) -> Result<(), AdmissionOperationStoreError> {
        for value in [
            self.baseline.live,
            self.admitted,
            self.collected,
            self.changes,
            self.live()?,
            version,
        ] {
            SafeInteger::new(value).map_err(refused)?;
        }
        if self.changes.checked_add(1) != Some(version)
            || self.admitted.checked_add(self.collected) != Some(self.changes)
            || self.live()? > MAX_LIVE_PUBLICATIONS
        {
            return Err(refused("publication live counter changed its closed bound"));
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
enum ReadySchema {
    #[serde(rename = "chio.knowledge.publication-ready.v1")]
    V1,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyRecord {
    schema: ReadySchema,
    account: ReferenceAccount,
    baseline: CapacityBaseline,
    capacity: SourceAnchor,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationIdentity {
    reference: ArtifactVersionRefV1,
    principal: Option<chio_security_types::PrincipalId>,
    publication: CommandId,
    object: ArtifactObjectId,
    input: CanonicalPayloadDigest,
    installation_generation: SafeInteger,
}

impl PublicationIdentity {
    fn from_record(record: &NativeArtifactRecordV1) -> Result<Self, AdmissionOperationStoreError> {
        Ok(Self {
            reference: artifact_version_reference(&record.metadata).map_err(refused)?,
            principal: record.publication_principal.clone(),
            publication: record.input.publication.clone(),
            object: record.object.clone(),
            input: CanonicalPayloadDigest::from_bytes(
                knowledge_digest(
                    RecoveryDigestDomain::KnowledgeReferenceOwner,
                    &("publication_original_input", &record.input),
                )
                .map_err(refused)?,
            ),
            installation_generation: record.installation_generation,
        })
    }

    fn matches_native_allocation(
        &self,
        record: &NativeArtifactRecordV1,
    ) -> Result<bool, AdmissionOperationStoreError> {
        let current = Self::from_record(record)?;
        // The original reference remains immutable. The owning metadata commit
        // may change its provenance through a verified label or certificate.
        Ok(self.reference.scope == current.reference.scope
            && self.reference.artifact == current.reference.artifact
            && self.reference.version == current.reference.version
            && self.principal == current.principal
            && self.publication == current.publication
            && self.object == current.object
            && self.input == current.input
            && self.installation_generation == current.installation_generation)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
enum LeaseSchema {
    #[serde(rename = "chio.knowledge.publication-lease.v1")]
    V1,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "origin", rename_all = "snake_case", deny_unknown_fields)]
enum LeaseOrigin {
    Cold { baseline: CapacityBaseline },
    NativeIntake,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseRecord {
    schema: LeaseSchema,
    account: ReferenceAccount,
    identity: PublicationIdentity,
    original: SourceAnchor,
    origin: LeaseOrigin,
    original_collection: Option<SourceAnchor>,
    collection: Option<SourceAnchor>,
    changes: u64,
}

impl LeaseRecord {
    fn original(&self) -> Self {
        let mut original = self.clone();
        original.collection = original.original_collection.clone();
        original.changes = 0;
        original
    }

    fn validate(&self, version: u64) -> Result<(), AdmissionOperationStoreError> {
        let expected_changes =
            u64::from(self.original_collection.is_none() && self.collection.is_some());
        if self.changes != expected_changes
            || self.changes.checked_add(1) != Some(version)
            || (self.original_collection.is_some() && self.original_collection != self.collection)
        {
            return Err(refused(
                "publication lease changed its original disposition",
            ));
        }
        self.original.validate_ordinary()?;
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
enum ObjectSchema {
    #[serde(rename = "chio.knowledge.publication-object.v1")]
    V1,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectRecord {
    schema: ObjectSchema,
    identity: PublicationIdentity,
    publication: String,
    original: SourceAnchor,
}

fn account(scope: &RecoveryScopeV1) -> ReferenceAccount {
    ReferenceAccount::from_scope(scope)
}

fn capacity_key(account: &ReferenceAccount) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "knowledge-publication-capacity:{}",
        account.scope_key()?
    ))
}

fn ready_key(account: &ReferenceAccount) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "knowledge-publication-ready:{}",
        account.scope_key()?
    ))
}

fn lease_key(
    account: &ReferenceAccount,
    publication: &str,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "knowledge-publication-lease:{}:{}",
        account.scope_key()?,
        sha256_hex(publication.as_bytes()),
    ))
}

fn object_key(
    scope: &RecoveryScopeV1,
    object: &ArtifactObjectId,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "knowledge-publication-object:{}:{}",
        account(scope).scope_key()?,
        hex::encode(
            knowledge_digest(
                RecoveryDigestDomain::KnowledgeObjectCustody,
                &(scope, object)
            )
            .map_err(refused)?
        ),
    ))
}

fn checked_row<T: Serialize + serde::de::DeserializeOwned>(
    tx: &Connection,
    key: &str,
    scope: &str,
    maximum: usize,
) -> Result<(T, protected::ProtectedSourceReference), AdmissionOperationStoreError> {
    let row = protected::raw_checked(tx, key)?
        .ok_or_else(|| refused("publication allocation source disappeared"))?;
    let source = protected::source_reference(tx, key)?;
    let ordinary: bool = tx.query_row(
        "SELECT native_namespace IS NULL AND native_request IS NULL FROM admission_operation_recovery_records WHERE record_key=?1",
        [key], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if !ordinary || row.kind != "command" || row.scope != scope || row.payload.len() > maximum {
        return Err(refused("publication allocation changed its exact header"));
    }
    Ok((protected::decode(&row.payload)?, source))
}

fn persist<T: Serialize>(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    account: &ReferenceAccount,
    key: &str,
    value: &T,
    maximum: usize,
) -> Result<protected::ProtectedSourceReference, AdmissionOperationStoreError> {
    let bytes = protected::encode(value)?;
    if bytes.len() > maximum {
        return Err(refused(
            "publication allocation exceeds its closed envelope",
        ));
    }
    // This remains ordinary Knowledge intake. Logical live slots supply no
    // physical reserve class, debt reduction, or terminal financing allowance.
    protected::save(
        tx,
        owner,
        key,
        &account.scope_key()?,
        "command",
        &bytes,
        None,
    )?;
    protected::source_reference(tx, key)
}

fn current_capacity(
    tx: &Connection,
    scope: &RecoveryScopeV1,
) -> Result<(CapacityRecord, protected::ProtectedSourceReference), AdmissionOperationStoreError> {
    let identity = account(scope);
    let capacity_key = capacity_key(&identity)?;
    let (record, source) =
        checked_row::<CapacityRecord>(tx, &capacity_key, &identity.scope_key()?, ACCOUNT_BYTES)?;
    record.validate(source.version())?;
    record.baseline.cutoff.verify(tx)?;
    if record.account != identity
        || !protected::matches_historical_command_payload(
            tx,
            &capacity_key,
            source.scope_key(),
            1,
            &protected::encode(&record.original())?,
        )?
    {
        return Err(refused("publication capacity changed its original census"));
    }
    let key = ready_key(&identity)?;
    let (ready, ready_source) =
        checked_row::<ReadyRecord>(tx, &key, &identity.scope_key()?, ACCOUNT_BYTES)?;
    ready.capacity.verify_historical_identity(tx)?;
    if ready_source.version() != 1
        || ready.capacity.version() != 1
        || ready.capacity.global_commit_sequence() <= record.baseline.cutoff.sequence()
        || ready_source.global_commit_sequence() <= ready.capacity.global_commit_sequence()
        || ready.account != identity
        || ready.baseline != record.baseline
        || ready.capacity.record_key() != capacity_key
        || !ready.capacity.not_after(&SourceAnchor::capture(&source))
        || ready_source.global_commit_sequence() <= record.baseline.cutoff.sequence()
        || !protected::matches_historical_command_payload(
            tx,
            &key,
            ready_source.scope_key(),
            1,
            &protected::encode(&ready)?,
        )?
    {
        return Err(refused(
            "publication readiness changed its authenticated activation",
        ));
    }
    Ok((record, source))
}

pub(super) fn require_intake_capacity(
    tx: &Connection,
    scope: &RecoveryScopeV1,
) -> Result<(), AdmissionOperationStoreError> {
    if current_capacity(tx, scope)?.0.live()? >= MAX_LIVE_PUBLICATIONS {
        return Err(refused("artifact live quota"));
    }
    Ok(())
}

fn current_lease(
    tx: &Connection,
    record: &NativeArtifactRecordV1,
) -> Result<(LeaseRecord, protected::ProtectedSourceReference), AdmissionOperationStoreError> {
    record.metadata.validate().map_err(refused)?;
    let identity = account(&record.metadata.scope);
    let publication = record_publication_key(record)?;
    let source = protected::source_reference(tx, &publication)?;
    let (lease, lease_source) = checked_row::<LeaseRecord>(
        tx,
        &lease_key(&identity, &publication)?,
        &identity.scope_key()?,
        LEASE_BYTES,
    )?;
    lease.validate(lease_source.version())?;
    lease.original.verify_historical_identity(tx)?;
    if lease.account != identity
        || !lease.identity.matches_native_allocation(record)?
        || lease.original.record_key() != publication
        || !lease.original.not_after(&SourceAnchor::capture(&source))
        || !protected::matches_historical_command_payload(
            tx,
            lease_source.record_key(),
            lease_source.scope_key(),
            1,
            &protected::encode(&lease.original())?,
        )?
    {
        return Err(refused(
            "publication lease changed its original native owner",
        ));
    }
    let (capacity, _) = current_capacity(tx, &record.metadata.scope)?;
    match &lease.origin {
        LeaseOrigin::Cold { baseline }
            if *baseline == capacity.baseline
                && lease.original.global_commit_sequence() <= baseline.cutoff.sequence() => {}
        LeaseOrigin::NativeIntake
            if lease.original.version() == 1
                && lease.original.global_commit_sequence()
                    > capacity.baseline.cutoff.sequence() => {}
        _ => return Err(refused("publication lease changed its baseline origin")),
    }
    if let Some(collected) = &lease.collection {
        collection::verify_retained_collection(tx, record, collected)?;
    }
    Ok((lease, lease_source))
}

/// Each genuine owning phase writer authenticates its original allocation.
/// A transition to Retired preserves the live slot until actual collection.
pub(super) fn validate_existing_allocation(
    tx: &Connection,
    record: &NativeArtifactRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    let (lease, _) = current_lease(tx, record)?;
    if lease.collection.is_some() {
        return Err(refused(
            "collected publication cannot resume its native writer",
        ));
    }
    Ok(())
}

pub(super) fn admit_publication<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    owner: &SqliteServingOwner,
    intake: super::publication_source::VerifiedKnowledgePublicationIntake<'tx, 'conn>,
) -> Result<(), AdmissionOperationStoreError> {
    intake.verify(tx)?;
    require_intake_capacity(tx, intake.scope())?;
    let (mut capacity, previous) = current_capacity(tx, intake.scope())?;
    let publication = intake.source_key();
    let key = lease_key(&capacity.account, publication)?;
    let object = object_key(intake.scope(), &intake.record().object)?;
    if protected::raw_checked(tx, &key)?.is_some() || protected::raw_checked(tx, &object)?.is_some()
    {
        return Err(refused(
            "publication intake cannot reuse a retained allocation",
        ));
    }
    save(tx, owner, intake.scope(), publication, intake.record())?;
    super::reference_custody::retain_publication_references(tx, owner, intake.record())?;
    let original = SourceAnchor::capture(&protected::source_reference(tx, publication)?);
    let identity = PublicationIdentity::from_record(intake.record())?;
    let lease = LeaseRecord {
        schema: LeaseSchema::V1,
        account: capacity.account.clone(),
        identity: identity.clone(),
        original: original.clone(),
        origin: LeaseOrigin::NativeIntake,
        original_collection: None,
        collection: None,
        changes: 0,
    };
    persist(tx, owner, &capacity.account, &key, &lease, LEASE_BYTES)?;
    persist(
        tx,
        owner,
        &capacity.account,
        &object,
        &ObjectRecord {
            schema: ObjectSchema::V1,
            identity,
            publication: publication.to_owned(),
            original,
        },
        LEASE_BYTES,
    )?;
    protected::verify_source_reference(tx, &previous)?;
    capacity.admitted = capacity
        .admitted
        .checked_add(1)
        .ok_or_else(|| refused("publication admissions exhausted"))?;
    capacity.changes = capacity
        .changes
        .checked_add(1)
        .ok_or_else(|| refused("publication counter exhausted"))?;
    capacity.validate(
        previous
            .version()
            .checked_add(1)
            .ok_or_else(|| refused("publication counter revision exhausted"))?,
    )?;
    persist(
        tx,
        owner,
        &capacity.account,
        &capacity_key(&capacity.account)?,
        &capacity,
        ACCOUNT_BYTES,
    )?;
    Ok(())
}

pub(super) fn validate_retained_allocation(
    tx: &Connection,
    record: &NativeArtifactRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    current_lease(tx, record).map(|_| ())
}

pub(super) use cold::activate_installation_publications;
pub(in crate::admission_operation_store) use cold::verify_catalog;

#[cfg(feature = "admission-test-support")]
impl SqliteAdmissionOperationStore {
    /// Data-only native account observation. It supplies no collection grant.
    pub fn inspect_live_publication_count(
        &self,
        actor: &AuthenticatedRecoveryActor,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<u64, AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeAdmin {
            return Err(refused("publication capacity inspection authority"));
        }
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(fence))?;
        let now = schema::authority_validation_time(&tx, now)?;
        let deployment = protected::deployment_tx(&tx, actor.scope())?;
        super::super::recovery::verify_actor(&tx, actor, &deployment, now)?;
        let profile = installation(&tx, actor.scope())?;
        validate_installation(&tx, &deployment, &profile)?;
        traversal::ensure_audience(
            &tx,
            actor,
            &source(&tx, &profile.native_authority, &profile.producer_context)?,
        )?;
        let count = current_capacity(&tx, actor.scope())?.0.live()?;
        let later = schema::authority_validation_time(&tx, now)?;
        super::super::recovery::verify_actor(&tx, actor, &deployment, later)?;
        tx.rollback().map_err(sqlite_error)?;
        Ok(count)
    }
}

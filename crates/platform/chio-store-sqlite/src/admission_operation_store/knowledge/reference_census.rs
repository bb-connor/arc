//! Complete cold custody is authenticated before any durable baseline write.
use super::reference_source::ReferenceCutoff;
use super::references::{ProductEvidenceOwner, ReferenceOwner, SourceAnchor};
use super::*;
use std::ops::Deref;
use std::rc::Rc;

impl SqliteAdmissionOperationStore {
    /// Inspect the actual cold source preflight without writing a baseline,
    /// marker or reference owner. The proof stays inside its originating writer.
    #[cfg(feature = "admission-test-support")]
    pub fn inspect_confined_input_cold_reference_count(
        &self,
        scope: &RecoveryScopeV1,
        request: &RequestId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<usize, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(fence))?;
        schema::authority_validation_time(&tx, now)?;
        let profile = installation(&tx, scope)?;
        let count = {
            let baseline = VerifiedKnowledgeReferenceAccountBaseline::for_installation(
                &tx,
                &self.serving_owner,
                &profile,
            )?;
            let mut count = 0_usize;
            baseline.visit_artifacts(|reference| {
                let cohort = baseline.artifact_cohort(&reference)?;
                cohort.visit_active_owners(|owner, _| {
                    if let ReferenceOwner::ConfinedInputs {
                        scope: source_scope,
                        request: source_request,
                        ..
                    } = owner
                    {
                        if source_scope == scope && source_request == request {
                            count = count
                                .checked_add(1)
                                .ok_or_else(|| refused("confined cold owner count overflow"))?;
                        }
                    }
                    Ok(())
                })
            })?;
            count
        };
        tx.rollback().map_err(sqlite_error)?;
        Ok(count)
    }
}

/// The spill table is local to the originating SQLite connection and writer.
/// It bounds resident Rust memory without truncating authenticated history.
/// It is never consulted by hot reads, never signed, and never grants custody.
struct ColdReferenceCensus<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    scope: RecoveryScopeV1,
    cutoff: ReferenceCutoff,
    artifacts: String,
    owners: String,
    sources: String,
    checkpoint_meanings: String,
    cohort: CanonicalPayloadDigest,
    census: CanonicalPayloadDigest,
    active: u64,
    artifact_count: u64,
}

pub(in crate::admission_operation_store) struct VerifiedKnowledgeReferenceAccountBaseline<
    'tx,
    'conn,
> {
    census: Rc<ColdReferenceCensus<'tx, 'conn>>,
}

pub(in crate::admission_operation_store) struct VerifiedKnowledgeReferenceColdCohort<'tx, 'conn> {
    census: Rc<ColdReferenceCensus<'tx, 'conn>>,
    reference: ArtifactVersionRefV1,
    active: u64,
    digest: CanonicalPayloadDigest,
}

impl<'tx, 'conn> VerifiedKnowledgeReferenceAccountBaseline<'tx, 'conn> {
    /// Explicit host activation requires the real fenced current installation.
    /// Neither a missing ready record nor a decoded tenant claim reaches this.
    pub(super) fn for_installation(
        tx: &'tx Transaction<'conn>,
        serving_owner: &SqliteServingOwner,
        profile: &NativeKnowledgeInstallationV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let recovery = protected::deployment_tx(tx, &profile.scope)?;
        validate_installation(tx, &recovery, profile)?;
        if protected::encode(&installation(tx, &profile.scope)?)? != protected::encode(profile)? {
            return Err(refused("reference cold installation changed"));
        }
        let cutoff = ReferenceCutoff::capture(tx, serving_owner)?;
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let artifacts = format!("knowledge_reference_artifacts_{nonce}");
        let owners = format!("knowledge_reference_owners_{nonce}");
        let sources = format!("knowledge_reference_sources_{nonce}");
        let checkpoint_meanings = format!("knowledge_reference_checkpoint_meanings_{nonce}");
        let initial = digest(&(
            "cold-reference-census",
            &profile.scope.authority_domain,
            &profile.scope.tenant_id,
            &cutoff,
        ))?;
        let mut census = ColdReferenceCensus {
            transaction: tx,
            scope: profile.scope.clone(),
            cutoff,
            artifacts,
            owners,
            sources,
            checkpoint_meanings,
            cohort: initial,
            census: initial,
            active: 0,
            artifact_count: 0,
        };
        // Install the cleanup guard before the first temporary table exists.
        // A failure midway through this batch cannot orphan a partial census.
        tx.execute_batch(&format!(
            "CREATE TEMP TABLE {}(identity TEXT PRIMARY KEY,reference BLOB NOT NULL) WITHOUT ROWID;
             CREATE TEMP TABLE {}(reference_identity TEXT NOT NULL,owner_identity TEXT NOT NULL,
             owner BLOB NOT NULL,original BLOB NOT NULL,meaning BLOB NOT NULL,
             PRIMARY KEY(reference_identity,owner_identity)) WITHOUT ROWID;
             CREATE TEMP TABLE {}(record_key TEXT PRIMARY KEY,original BLOB NOT NULL) WITHOUT ROWID;
             CREATE TEMP TABLE {}(owner BLOB PRIMARY KEY,envelope BLOB NOT NULL) WITHOUT ROWID;",
            census.artifacts, census.owners, census.sources, census.checkpoint_meanings,
        ))
        .map_err(sqlite_error)?;
        census.populate()?;
        census.seal()?;
        census.verify(tx)?;
        Ok(Self {
            census: Rc::new(census),
        })
    }

    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.census.transaction
    }
    pub(in crate::admission_operation_store) fn scope(&self) -> &RecoveryScopeV1 {
        &self.census.scope
    }
    pub(in crate::admission_operation_store) fn global_cutoff(&self) -> &ReferenceCutoff {
        &self.census.cutoff
    }
    pub(in crate::admission_operation_store) fn cohort_digest(&self) -> CanonicalPayloadDigest {
        self.census.cohort
    }
    pub(in crate::admission_operation_store) fn census_digest(&self) -> CanonicalPayloadDigest {
        self.census.census
    }
    pub(in crate::admission_operation_store) fn active_reference_owners(&self) -> u64 {
        self.census.active
    }
    pub(in crate::admission_operation_store) fn artifact_count(&self) -> u64 {
        self.census.artifact_count
    }
    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.census.verify(tx)
    }

    pub(in crate::admission_operation_store) fn visit_artifacts(
        &self,
        mut visit: impl FnMut(ArtifactVersionRefV1) -> Result<(), AdmissionOperationStoreError>,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.verify(self.transaction())?;
        let mut statement = self
            .transaction()
            .prepare(&format!(
                "SELECT reference FROM {} ORDER BY identity",
                self.census.artifacts
            ))
            .map_err(sqlite_error)?;
        let mut rows = statement.query([]).map_err(sqlite_error)?;
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            let body: Vec<u8> = row.get(0).map_err(sqlite_error)?;
            visit(protected::decode(&body)?)?;
        }
        Ok(())
    }

    pub(in crate::admission_operation_store) fn artifact_cohort(
        &self,
        reference: &ArtifactVersionRefV1,
    ) -> Result<VerifiedKnowledgeReferenceColdCohort<'tx, 'conn>, AdmissionOperationStoreError>
    {
        self.census.verify_writer(self.transaction())?;
        let identity = reference_identity(reference)?;
        let body: Option<Vec<u8>> = self
            .transaction()
            .query_row(
                &format!(
                    "SELECT reference FROM {} WHERE identity=?1",
                    self.census.artifacts
                ),
                [hex::encode(identity.as_bytes())],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if body.as_deref() != Some(protected::encode(reference)?.as_slice()) {
            return Err(refused(
                "reference cold artifact is outside its complete census",
            ));
        }
        let (active, digest) = self.census.reference_summary(reference)?;
        Ok(VerifiedKnowledgeReferenceColdCohort {
            census: Rc::clone(&self.census),
            reference: reference.clone(),
            active,
            digest,
        })
    }
}

impl<'tx, 'conn> VerifiedKnowledgeReferenceColdCohort<'tx, 'conn> {
    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.census.transaction
    }
    pub(in crate::admission_operation_store) fn reference(&self) -> &ArtifactVersionRefV1 {
        &self.reference
    }
    pub(in crate::admission_operation_store) fn baseline_active_count(&self) -> u64 {
        self.active
    }
    pub(in crate::admission_operation_store) fn cutoff(&self) -> &ReferenceCutoff {
        &self.census.cutoff
    }
    pub(in crate::admission_operation_store) fn cohort_digest(&self) -> CanonicalPayloadDigest {
        self.census.cohort
    }
    pub(in crate::admission_operation_store) fn census_digest(&self) -> CanonicalPayloadDigest {
        self.digest
    }
    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.census.verify_writer(tx)?;
        self.census.verify_artifact_sources(&self.reference)?;
        self.census
            .visit_reference_owners(&self.reference, |_, original, _| {
                let current =
                    SourceAnchor::capture(&protected::source_reference(tx, original.record_key())?);
                if current != *original {
                    return Err(refused("reference cold owner advanced after preflight"));
                }
                Ok(())
            })?;
        if self.census.reference_summary(&self.reference)? != (self.active, self.digest) {
            return Err(refused("reference cold cohort changed its complete census"));
        }
        Ok(())
    }
    pub(in crate::admission_operation_store) fn visit_active_owners(
        &self,
        mut visit: impl FnMut(
            &ReferenceOwner,
            &SourceAnchor,
        ) -> Result<(), AdmissionOperationStoreError>,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.verify(self.transaction())?;
        self.census
            .visit_reference_owners(&self.reference, |owner, original, _| visit(owner, original))
    }
}

impl<'tx, 'conn> ColdReferenceCensus<'tx, 'conn> {
    fn populate(&mut self) -> Result<(), AdmissionOperationStoreError> {
        let tx = self.transaction;
        // Every irreversible Product terminal, including an orphan retained
        // event or global key, must resolve its complete original and archive.
        super::super::product::evidence_reclamation::verify_product_reclamation_inventory(tx)?;
        // UNION includes vanished current rows. Exact source loading below must
        // refuse them; absence cannot become a zero baseline or reclaimed pin.
        let mut statement = tx.prepare(
            "SELECT record_key FROM admission_operation_recovery_records
             WHERE record_key GLOB 'knowledge-publication:*' OR record_key GLOB 'knowledge-checkpoint:*'
                OR record_key GLOB 'knowledge-pin:*' OR record_key GLOB 'knowledge-release:*' OR record_key GLOB 'knowledge-restore:*'
                OR record_key GLOB 'product-report:*' OR record_key GLOB 'product-proposal:*'
                OR record_key GLOB 'confined-boundary:*'
             UNION SELECT record_key FROM admission_operation_recovery_events
             WHERE record_key GLOB 'knowledge-publication:*' OR record_key GLOB 'knowledge-checkpoint:*'
                OR record_key GLOB 'knowledge-pin:*' OR record_key GLOB 'knowledge-release:*' OR record_key GLOB 'knowledge-restore:*'
                OR record_key GLOB 'product-report:*' OR record_key GLOB 'product-proposal:*'
                OR record_key GLOB 'confined-boundary:*'
             UNION SELECT projection_key FROM authority_global_commits WHERE projection_kind='recovery' AND
                (projection_key GLOB 'knowledge-publication:*' OR projection_key GLOB 'knowledge-checkpoint:*'
                 OR projection_key GLOB 'knowledge-pin:*' OR projection_key GLOB 'knowledge-release:*' OR projection_key GLOB 'knowledge-restore:*'
                 OR projection_key GLOB 'product-report:*' OR projection_key GLOB 'product-proposal:*'
                 OR projection_key GLOB 'confined-boundary:*') ORDER BY 1"
        ).map_err(sqlite_error)?;
        let mut rows = statement.query([]).map_err(sqlite_error)?;
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            let key: String = row.get(0).map_err(sqlite_error)?;
            let source = protected::source_reference(tx, &key)?;
            let raw = protected::raw_checked(tx, &key)?
                .ok_or_else(|| refused("reference cold source disappeared"))?;
            if raw.kind != "command" || source.global_commit_sequence() > self.cutoff.sequence() {
                return Err(refused("reference cold source changed kind or cutoff"));
            }
            if key.starts_with("confined-boundary:") {
                let inputs = confinement::input_reference_source(tx, &key)?
                    .ok_or_else(|| refused("reference cold confined boundary disappeared"))?;
                let boundary = inputs.boundary();
                if !self.in_account(&boundary.scope) {
                    continue;
                }
                self.add_source(inputs.source())?;
                for pin in inputs.pins() {
                    self.add_source(pin)?;
                }
                let owner = ReferenceOwner::ConfinedInputs {
                    scope: boundary.scope.clone(),
                    request: boundary.request.clone(),
                    boundary: boundary.boundary.clone(),
                };
                let original = SourceAnchor::capture(inputs.source());
                let meaning = digest(&(&owner, boundary))?;
                for reference in inputs.references() {
                    // A permanent original reservation never proves that its
                    // inputs became collectible. Lost physical availability
                    // cannot be promoted into a clean cold baseline.
                    artifact(tx, reference)?;
                    self.add_owner(&owner, reference, &original, meaning)?;
                }
            } else if key.starts_with("knowledge-publication:") {
                let record: NativeArtifactRecordV1 = protected::decode(&raw.payload)?;
                record.metadata.validate().map_err(refused)?;
                if record_publication_key(&record)? != key
                    || raw.scope != scope_key(&record.metadata.scope)?
                    || record.input.dependencies != record.metadata.dependencies
                {
                    return Err(refused(
                        "reference cold publication changed immutable identity",
                    ));
                }
                if !self.in_account(&record.metadata.scope) {
                    continue;
                }
                self.add_source(&source)?;
                let reference = artifact_version_reference(&record.metadata).map_err(refused)?;
                if let Some(pointer) = load::<String>(tx, &version_key(&reference)?)? {
                    if pointer != key {
                        return Err(refused("reference cold publication pointer changed"));
                    }
                    self.add_source(&protected::source_reference(tx, &version_key(&reference)?)?)?;
                    self.add_artifact(&reference)?;
                } else if matches!(
                    record.state,
                    ArtifactPublicationStateV1::MetadataCommitted
                        | ArtifactPublicationStateV1::Available
                ) {
                    return Err(refused(
                        "reference cold publication lost its committed pointer",
                    ));
                }
                if record.state != ArtifactPublicationStateV1::Retired {
                    let owner = ReferenceOwner::Publication {
                        scope: record.metadata.scope.clone(),
                        artifact: record.metadata.artifact.clone(),
                        version: record.metadata.version.clone(),
                    };
                    let meaning = digest(&(&owner, &record.input.dependencies))?;
                    for reference in record.input.dependencies.as_slice() {
                        if reference.scope != record.metadata.scope {
                            return Err(refused("reference cold dependency crossed process"));
                        }
                        self.add_owner(
                            &owner,
                            reference,
                            &SourceAnchor::capture(&source),
                            meaning,
                        )?;
                    }
                }
            } else if key.starts_with("product-report:") || key.starts_with("product-proposal:") {
                let product = if key.starts_with("product-report:") {
                    let report: super::super::product::StoredDecisionReportV1 =
                        protected::decode(&raw.payload)?;
                    ProductEvidenceOwner::Report {
                        scope: report.report.scope,
                        id: report.id,
                        digest: report.digest,
                    }
                } else {
                    let proposal: super::super::product::StoredPolicyMaintenanceProposalV1 =
                        protected::decode(&raw.payload)?;
                    ProductEvidenceOwner::Proposal {
                        scope: proposal.proposal.scope,
                        id: proposal.proposal.proposal_id,
                        digest: proposal.digest,
                    }
                };
                let (current, references) =
                    super::super::product::product_evidence_source(tx, &product)?;
                if SourceAnchor::capture(&current) != SourceAnchor::capture(&source) {
                    return Err(refused(
                        "reference cold product changed its complete source",
                    ));
                }
                let reclamation = if matches!(&product, ProductEvidenceOwner::Proposal { .. }) {
                    super::super::product::evidence_reclamation::product_reclamation_source(
                        tx, &product,
                    )?
                } else {
                    None
                };
                let owner = ReferenceOwner::from(product);
                if !self.in_account(owner.scope()) {
                    continue;
                }
                // Queue archival retains evidence. Only the complete separate
                // irreversible native terminal can exclude Proposal owners.
                // Even an empty immutable source guards the census cutoff.
                self.add_source(&current)?;
                if let Some(reclamation) = reclamation {
                    if reclamation.references() != references.as_slice()
                        || SourceAnchor::capture(reclamation.original())
                            != SourceAnchor::capture(&current)
                        || owner != ReferenceOwner::from(reclamation.owner().clone())
                    {
                        return Err(refused("reference cold Product reclamation changed source"));
                    }
                    self.add_source(reclamation.archive())?;
                    self.add_source(reclamation.terminal())?;
                    for reference in references {
                        self.add_artifact(&reference)?;
                        references::require_retired_reference_owner(
                            tx,
                            &reference,
                            &owner,
                            &SourceAnchor::capture(&current),
                            &SourceAnchor::capture(reclamation.terminal()),
                        )?;
                    }
                } else {
                    let original = SourceAnchor::capture(&current);
                    let meaning = digest(&(&owner, &references))?;
                    for reference in references {
                        self.add_owner(&owner, &reference, &original, meaning)?;
                    }
                }
            } else if key.starts_with("knowledge-pin:") {
                if key.starts_with(&format!("knowledge-pin:{}:confined:", raw.scope)) {
                    let reference: Option<ArtifactVersionRefV1> = protected::decode(&raw.payload)?;
                    let reference = reference.ok_or_else(|| {
                        refused("reference cold confined pin lost original input")
                    })?;
                    if raw.scope != scope_key(&reference.scope)? {
                        return Err(refused("reference cold confined pin changed input scope"));
                    }
                    if self.in_account(&reference.scope) {
                        // Boundary keys sort before pin keys. The complete
                        // original adapter must have enumerated this exact pin.
                        self.require_enumerated_source(&source)?;
                    }
                    continue;
                }
                if let Some(pin) = pins::modern_reference_source(tx, &key)? {
                    if !self.in_account(pin.scope()) {
                        continue;
                    }
                    self.add_source(&source)?;
                    if pin.active() {
                        let owner = pin_owner(&pin);
                        self.add_owner(
                            &owner,
                            pin.reference(),
                            &SourceAnchor::capture(&source),
                            digest(&owner)?,
                        )?;
                    }
                } else {
                    let reference = pins::reference(tx, &key)?;
                    let Some(reference) = reference else {
                        // The shared source reader authenticated every retained
                        // null, including the actual first source. It cannot
                        // conceal an older Some reference or intermediate value.
                        // Its exact head still participates in preflight, so a
                        // later mutation cannot race the finalized zero census.
                        self.add_source(&source)?;
                        continue;
                    };
                    if raw.scope != scope_key(&reference.scope)?
                        || !key.starts_with(&format!("knowledge-pin:{}:", raw.scope))
                    {
                        return Err(refused("reference cold legacy pin changed scope"));
                    }
                    if !self.in_account(&reference.scope) {
                        continue;
                    }
                    self.add_source(&source)?;
                    let original = SourceAnchor::capture(&source);
                    let owner = ReferenceOwner::LegacyPinSource {
                        scope: reference.scope.clone(),
                        original: original.clone(),
                    };
                    self.add_owner(&owner, &reference, &original, digest(&owner)?)?;
                }
            } else if key.starts_with("knowledge-checkpoint:") {
                let checkpoint = checkpoints::checkpoint_reference_source(tx, &key)?
                    .ok_or_else(|| refused("reference cold checkpoint disappeared"))?;
                if !self.in_account(checkpoint.scope()) {
                    continue;
                }
                self.add_source(checkpoint.source())?;
                if let Some(terminal) = checkpoint.terminal() {
                    self.add_source(terminal)?;
                }
                let owner = ReferenceOwner::CheckpointRevision {
                    scope: checkpoint.scope().clone(),
                    checkpoint: checkpoint.checkpoint().clone(),
                    revision: SafeInteger::new(checkpoint.revision()).map_err(refused)?,
                };
                self.add_checkpoint_meaning(&owner, &checkpoint.canonical_envelope()?)?;
                if checkpoint.active() {
                    for reference in checkpoint.references() {
                        self.add_owner(
                            &owner,
                            reference,
                            &SourceAnchor::capture(checkpoint.source()),
                            *checkpoint.envelope(),
                        )?;
                    }
                }
            } else if key.starts_with("knowledge-restore:") {
                let restore = checkpoints::restore_reference_source(tx, &key)?
                    .ok_or_else(|| refused("reference cold restore disappeared"))?;
                if !self.in_account(restore.scope()) {
                    continue;
                }
                self.add_source(restore.source())?;
                if restore.active() {
                    let owner = ReferenceOwner::CheckpointRestore {
                        scope: restore.scope().clone(),
                        release: restore.release().clone(),
                    };
                    for reference in restore.references() {
                        self.add_owner(
                            &owner,
                            reference,
                            &SourceAnchor::capture(restore.source()),
                            *restore.envelope(),
                        )?;
                    }
                }
            } else {
                // The owning release loader verifies exact original handle,
                // request key, actor principal and native join custody. This
                // adapter must be installed with the census, not approximated
                // by decoding a caller-supplied delivery state or artifact.
                let release = release::artifact_reference_source(tx, &key)?
                    .ok_or_else(|| refused("reference cold release disappeared"))?;
                if !self.in_account(release.scope()) {
                    continue;
                }
                self.add_source(release.source())?;
                for supporting in release.supporting_sources() {
                    self.add_source(supporting)?;
                }
                if release.active() {
                    let owner = ReferenceOwner::ArtifactRelease {
                        scope: release.scope().clone(),
                        release: release.release().clone(),
                    };
                    for reference in release.references() {
                        self.add_owner(
                            &owner,
                            reference,
                            &SourceAnchor::capture(release.source()),
                            release.envelope(),
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    fn in_account(&self, scope: &RecoveryScopeV1) -> bool {
        scope.authority_domain == self.scope.authority_domain
            && scope.tenant_id == self.scope.tenant_id
    }

    /// Authenticate one complete immutable envelope per logical checkpoint,
    /// independently of which artifacts its physical aliases happen to name.
    /// Otherwise disjoint conflicting aliases would never collide in the arc
    /// spill table. Historical and modern aliases remain source-guarded above.
    fn add_checkpoint_meaning(
        &self,
        owner: &ReferenceOwner,
        envelope: &[u8],
    ) -> Result<(), AdmissionOperationStoreError> {
        if !matches!(owner, ReferenceOwner::CheckpointRevision { .. })
            || !self.in_account(owner.scope())
        {
            return Err(refused("reference cold checkpoint owner changed purpose"));
        }
        let owner = protected::encode(owner)?;
        let existing: Option<Vec<u8>> = self
            .transaction
            .query_row(
                &format!(
                    "SELECT envelope FROM {} WHERE owner=?1",
                    self.checkpoint_meanings
                ),
                [&owner],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if existing.as_deref().is_some_and(|prior| prior != envelope) {
            return Err(refused(
                "reference cold checkpoint aliases changed complete envelope",
            ));
        }
        self.transaction
            .execute(
                &format!(
                    "INSERT OR IGNORE INTO {}(owner,envelope) VALUES(?1,?2)",
                    self.checkpoint_meanings
                ),
                rusqlite::params![owner, envelope],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    fn require_enumerated_source(
        &self,
        source: &protected::ProtectedSourceReference,
    ) -> Result<(), AdmissionOperationStoreError> {
        let expected = protected::encode(&SourceAnchor::capture(source))?;
        let retained: Option<Vec<u8>> = self
            .transaction
            .query_row(
                &format!("SELECT original FROM {} WHERE record_key=?1", self.sources),
                [source.record_key()],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if retained.as_deref() != Some(expected.as_slice()) {
            return Err(refused(
                "reference cold confined pin has no original boundary",
            ));
        }
        Ok(())
    }

    fn add_source(
        &self,
        source: &protected::ProtectedSourceReference,
    ) -> Result<(), AdmissionOperationStoreError> {
        if source.global_commit_sequence() > self.cutoff.sequence() {
            return Err(refused("reference cold source passed cutoff"));
        }
        let anchor = SourceAnchor::capture(source);
        let body = protected::encode(&anchor)?;
        let old: Option<Vec<u8>> = self
            .transaction
            .query_row(
                &format!("SELECT original FROM {} WHERE record_key=?1", self.sources),
                [source.record_key()],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if old.as_ref().is_some_and(|old| old != &body) {
            return Err(refused("reference cold source changed while enumerating"));
        }
        self.transaction
            .execute(
                &format!(
                    "INSERT OR IGNORE INTO {}(record_key,original) VALUES(?1,?2)",
                    self.sources
                ),
                rusqlite::params![source.record_key(), body],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    fn add_artifact(
        &self,
        reference: &ArtifactVersionRefV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !self.in_account(&reference.scope) {
            return Err(refused("reference cold artifact crossed tenant"));
        }
        let key = version_key(reference)?;
        let publication: String = load(self.transaction, &key)?
            .ok_or_else(|| refused("reference cold artifact pointer absent"))?;
        let record: NativeArtifactRecordV1 = load(self.transaction, &publication)?
            .ok_or_else(|| refused("reference cold artifact source absent"))?;
        record.metadata.validate().map_err(refused)?;
        if record_publication_key(&record)? != publication
            || artifact_version_reference(&record.metadata).map_err(refused)? != *reference
        {
            return Err(refused("reference cold artifact provenance changed"));
        }
        self.add_source(&protected::source_reference(self.transaction, &key)?)?;
        self.add_source(&protected::source_reference(
            self.transaction,
            &publication,
        )?)?;
        let identity = hex::encode(reference_identity(reference)?.as_bytes());
        let body = protected::encode(reference)?;
        let old: Option<Vec<u8>> = self
            .transaction
            .query_row(
                &format!("SELECT reference FROM {} WHERE identity=?1", self.artifacts),
                [&identity],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if old.as_ref().is_some_and(|old| old != &body) {
            return Err(refused("reference cold artifact identity collision"));
        }
        self.transaction
            .execute(
                &format!(
                    "INSERT OR IGNORE INTO {}(identity,reference) VALUES(?1,?2)",
                    self.artifacts
                ),
                rusqlite::params![identity, body],
            )
            .map_err(sqlite_error)?;
        Ok(())
    }

    fn add_owner(
        &self,
        owner: &ReferenceOwner,
        reference: &ArtifactVersionRefV1,
        original: &SourceAnchor,
        meaning: CanonicalPayloadDigest,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !self.in_account(owner.scope())
            || !self.in_account(&reference.scope)
            || original.scope_key() != scope_key(owner.scope())?
        {
            return Err(refused("reference cold logical owner crossed tenant"));
        }
        original.verify_historical_identity(self.transaction)?;
        self.add_artifact(reference)?;
        let reference_id = reference_identity(reference)?;
        let owner_id = owner.identity(reference_id)?;
        let identity = hex::encode(reference_id.as_bytes());
        let owner_identity = hex::encode(owner_id.as_bytes());
        let owner_body = protected::encode(owner)?;
        let meaning_body = protected::encode(&meaning)?;
        let existing: Option<(Vec<u8>,Vec<u8>,Vec<u8>)> = self.transaction.query_row(
            &format!("SELECT owner,original,meaning FROM {} WHERE reference_identity=?1 AND owner_identity=?2", self.owners),
            rusqlite::params![identity, owner_identity], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).optional().map_err(sqlite_error)?;
        if let Some((old_owner, old_source, old_meaning)) = existing {
            if old_owner != owner_body || old_meaning != meaning_body {
                return Err(refused("reference cold logical identity changed envelope"));
            }
            let prior: SourceAnchor = protected::decode(&old_source)?;
            prior.verify_historical_identity(self.transaction)?;
            if prior != *original && !matches!(owner, ReferenceOwner::CheckpointRevision { .. }) {
                return Err(refused("reference cold logical owner rebound source"));
            }
            // The checkpoint loader authenticated equal complete envelopes;
            // duplicate physical aliases retain one first logical source.
            return Ok(());
        }
        self.transaction.execute(&format!("INSERT INTO {}(reference_identity,owner_identity,owner,original,meaning) VALUES(?1,?2,?3,?4,?5)", self.owners), rusqlite::params![identity, owner_identity, owner_body, protected::encode(original)?, meaning_body]).map_err(sqlite_error)?;
        Ok(())
    }

    fn seal(&mut self) -> Result<(), AdmissionOperationStoreError> {
        let mut cohort = digest(&(
            "cold-reference-cohort",
            &self.scope.authority_domain,
            &self.scope.tenant_id,
            &self.cutoff,
        ))?;
        let mut statement = self
            .transaction
            .prepare(&format!(
                "SELECT record_key,original FROM {} ORDER BY record_key",
                self.sources
            ))
            .map_err(sqlite_error)?;
        let mut rows = statement.query([]).map_err(sqlite_error)?;
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            let key: String = row.get(0).map_err(sqlite_error)?;
            let body: Vec<u8> = row.get(1).map_err(sqlite_error)?;
            let anchor: SourceAnchor = protected::decode(&body)?;
            cohort = digest(&(cohort, key, anchor))?;
        }
        let mut census = digest(&(
            "cold-reference-arcs",
            &self.scope.authority_domain,
            &self.scope.tenant_id,
            &self.cutoff,
        ))?;
        let mut statement = self
            .transaction
            .prepare(&format!(
                "SELECT reference FROM {} ORDER BY identity",
                self.artifacts
            ))
            .map_err(sqlite_error)?;
        let mut rows = statement.query([]).map_err(sqlite_error)?;
        let mut active = 0_u64;
        let mut artifacts = 0_u64;
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            let body: Vec<u8> = row.get(0).map_err(sqlite_error)?;
            let reference: ArtifactVersionRefV1 = protected::decode(&body)?;
            let (count, own_census) = self.reference_summary(&reference)?;
            active = active
                .checked_add(count)
                .ok_or_else(|| refused("reference cold tenant census overflow"))?;
            artifacts = artifacts
                .checked_add(1)
                .ok_or_else(|| refused("reference cold artifact count overflow"))?;
            census = digest(&(census, reference, count, own_census))?;
        }
        self.cohort = cohort;
        self.census = census;
        self.active = active;
        self.artifact_count = artifacts;
        Ok(())
    }

    fn reference_summary(
        &self,
        reference: &ArtifactVersionRefV1,
    ) -> Result<(u64, CanonicalPayloadDigest), AdmissionOperationStoreError> {
        let mut count = 0_u64;
        let mut current = digest(&("cold-reference-artifact", reference, &self.cutoff))?;
        self.visit_reference_owners(reference, |owner, original, meaning| {
            count = count
                .checked_add(1)
                .ok_or_else(|| refused("reference cold owner count overflow"))?;
            current = digest(&(current, owner, original, meaning))?;
            Ok(())
        })?;
        Ok((count, current))
    }

    fn visit_reference_owners(
        &self,
        reference: &ArtifactVersionRefV1,
        mut visit: impl FnMut(
            &ReferenceOwner,
            &SourceAnchor,
            CanonicalPayloadDigest,
        ) -> Result<(), AdmissionOperationStoreError>,
    ) -> Result<(), AdmissionOperationStoreError> {
        let identity = hex::encode(reference_identity(reference)?.as_bytes());
        let mut statement = self.transaction.prepare(&format!("SELECT owner,original,meaning FROM {} WHERE reference_identity=?1 ORDER BY owner_identity", self.owners)).map_err(sqlite_error)?;
        let mut rows = statement.query([identity]).map_err(sqlite_error)?;
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            let owner: ReferenceOwner =
                protected::decode(&row.get::<_, Vec<u8>>(0).map_err(sqlite_error)?)?;
            let original: SourceAnchor =
                protected::decode(&row.get::<_, Vec<u8>>(1).map_err(sqlite_error)?)?;
            let meaning: CanonicalPayloadDigest =
                protected::decode(&row.get::<_, Vec<u8>>(2).map_err(sqlite_error)?)?;
            visit(&owner, &original, meaning)?;
        }
        Ok(())
    }

    fn verify(&self, tx: &Transaction<'conn>) -> Result<(), AdmissionOperationStoreError> {
        self.verify_writer(tx)?;
        let mut statement = tx
            .prepare(&format!(
                "SELECT record_key,original FROM {} ORDER BY record_key",
                self.sources
            ))
            .map_err(sqlite_error)?;
        let mut rows = statement.query([]).map_err(sqlite_error)?;
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            let key: String = row.get(0).map_err(sqlite_error)?;
            let original: SourceAnchor =
                protected::decode(&row.get::<_, Vec<u8>>(1).map_err(sqlite_error)?)?;
            let current = SourceAnchor::capture(&protected::source_reference(tx, &key)?);
            if current != original {
                return Err(refused("reference cold source advanced after preflight"));
            }
        }
        Ok(())
    }

    fn verify_writer(&self, tx: &Transaction<'conn>) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction), Deref::deref(tx)) {
            return Err(refused("reference cold census changed its physical writer"));
        }
        self.cutoff.verify(tx)
    }

    fn verify_artifact_sources(
        &self,
        reference: &ArtifactVersionRefV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        let pointer_key = version_key(reference)?;
        let publication: String = load(self.transaction, &pointer_key)?
            .ok_or_else(|| refused("reference cold artifact pointer disappeared"))?;
        for key in [&pointer_key, &publication] {
            let body: Vec<u8> = self
                .transaction
                .query_row(
                    &format!("SELECT original FROM {} WHERE record_key=?1", self.sources),
                    [key],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            let original: SourceAnchor = protected::decode(&body)?;
            if original
                != SourceAnchor::capture(&protected::source_reference(self.transaction, key)?)
            {
                return Err(refused("reference cold artifact advanced after preflight"));
            }
        }
        Ok(())
    }
}

impl Drop for ColdReferenceCensus<'_, '_> {
    fn drop(&mut self) {
        // Cleanup cannot grant authority or roll back already verified custody.
        let _ = self.transaction.execute_batch(&format!("DROP TABLE IF EXISTS temp.{}; DROP TABLE IF EXISTS temp.{}; DROP TABLE IF EXISTS temp.{}; DROP TABLE IF EXISTS temp.{};", self.artifacts, self.owners, self.sources, self.checkpoint_meanings));
    }
}

fn reference_identity(
    reference: &ArtifactVersionRefV1,
) -> Result<CanonicalPayloadDigest, AdmissionOperationStoreError> {
    Ok(CanonicalPayloadDigest::from_bytes(
        knowledge_digest(RecoveryDigestDomain::KnowledgeReferenceIdentity, reference)
            .map_err(refused)?,
    ))
}
fn digest(body: &impl Serialize) -> Result<CanonicalPayloadDigest, AdmissionOperationStoreError> {
    Ok(CanonicalPayloadDigest::from_bytes(
        knowledge_digest(RecoveryDigestDomain::KnowledgeReferenceOwner, body).map_err(refused)?,
    ))
}
fn pin_owner(pin: &pins::ModernPinSource) -> ReferenceOwner {
    let scope = pin.scope().clone();
    match pin.owner() {
        pins::PinOwner::Operator {
            principal,
            evidence,
        } => ReferenceOwner::OperatorPin {
            scope,
            principal: principal.clone(),
            evidence: evidence.clone(),
        },
        pins::PinOwner::NativeOperation { operation } => ReferenceOwner::NativeOperation {
            scope,
            operation: operation.clone(),
        },
        pins::PinOwner::PendingApproval { workflow } => ReferenceOwner::PendingApproval {
            scope,
            workflow: workflow.clone(),
        },
    }
}

impl std::fmt::Debug for VerifiedKnowledgeReferenceAccountBaseline<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedKnowledgeReferenceAccountBaseline([redacted])")
    }
}
impl std::fmt::Debug for VerifiedKnowledgeReferenceColdCohort<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedKnowledgeReferenceColdCohort([redacted])")
    }
}

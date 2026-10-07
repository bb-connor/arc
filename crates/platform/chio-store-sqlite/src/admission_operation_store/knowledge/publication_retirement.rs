//! Native publication retirement reserves finishing work before physical deletion.
use super::*;
use std::ops::Deref;

pub(in crate::admission_operation_store) struct VerifiedKnowledgePublicationRetireIntake<'tx, 'conn>
{
    authority: RetirementAuthority<'tx, 'conn>,
}

pub(in crate::admission_operation_store) struct VerifiedKnowledgePublicationCollectionIntake<
    'tx,
    'conn,
> {
    authority: RetirementAuthority<'tx, 'conn>,
    sweep: protected::ProtectedSourceReference,
    closure: references::CollectedPublicationReferenceClosure<'tx, 'conn>,
}

/// The original intake allocation, not this DATA witness, pays for completion.
pub(in crate::admission_operation_store) struct VerifiedKnowledgePublicationRetirement<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    record: NativeArtifactRecordV1,
    reference: ArtifactVersionRefV1,
    source: protected::ProtectedSourceReference,
    collected: protected::ProtectedSourceReference,
    closure: references::CollectedPublicationReferenceClosure<'tx, 'conn>,
}

struct RetirementAuthority<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    actor: &'tx AuthenticatedRecoveryActor,
    profile: &'tx NativeKnowledgeInstallationV1,
    now: u64,
    record: NativeArtifactRecordV1,
    reference: ArtifactVersionRefV1,
    source: protected::ProtectedSourceReference,
}

impl<'tx, 'conn> VerifiedKnowledgePublicationRetireIntake<'tx, 'conn> {
    /// Fresh reversible admission occurs before the retirement row, collection
    /// barrier or broker deletion. The closed allocator reserves all terminal
    /// source, dependency-owner release and acknowledgment writes together.
    pub(super) fn new(
        tx: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        now: u64,
        reference: &ArtifactVersionRefV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let authority = RetirementAuthority::new(tx, actor, profile, now, reference)?;
        if authority.record.state != ArtifactPublicationStateV1::Available {
            return Err(refused("retirement intake is not an available publication"));
        }
        let proof = Self { authority };
        proof.verify(tx)?;
        Ok(proof)
    }
    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.authority.verify(tx)?;
        if self.authority.record.state != ArtifactPublicationStateV1::Available {
            return Err(refused("retirement intake changed native phase"));
        }
        Ok(())
    }
    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.authority.transaction
    }
    pub(in crate::admission_operation_store) fn scope(&self) -> &RecoveryScopeV1 {
        &self.authority.record.metadata.scope
    }
    pub(in crate::admission_operation_store) fn source(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.authority.source
    }
    pub(in crate::admission_operation_store) fn reference(&self) -> &ArtifactVersionRefV1 {
        &self.authority.reference
    }
    pub(in crate::admission_operation_store) fn record(&self) -> &NativeArtifactRecordV1 {
        &self.authority.record
    }
    pub(in crate::admission_operation_store) fn dependency_references(
        &self,
    ) -> &[ArtifactVersionRefV1] {
        self.authority.record.input.dependencies.as_slice()
    }
    pub(in crate::admission_operation_store) fn seal(
        &self,
    ) -> Result<&ArtifactBlobSealV1, AdmissionOperationStoreError> {
        self.authority
            .record
            .seal
            .as_ref()
            .ok_or_else(|| refused("retirement intake lost exact object"))
    }
}

impl<'tx, 'conn> VerifiedKnowledgePublicationCollectionIntake<'tx, 'conn> {
    /// A replay of previously retired custody can obtain its first bounded
    /// collection allowance here, before the broker is allowed to delete.
    pub(super) fn new(
        tx: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        now: u64,
        reference: &ArtifactVersionRefV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let authority = RetirementAuthority::new(tx, actor, profile, now, reference)?;
        if authority.record.state != ArtifactPublicationStateV1::Retired {
            return Err(refused(
                "collection intake precedes irreversible retirement",
            ));
        }
        let sweep = lifecycle::publication_sweeping_source(tx, &authority.record)?
            .ok_or_else(|| refused("collection intake lacks exact protected deletion barrier"))?;
        let closure = references::collected_publication_closure(tx, &authority.record)?;
        let proof = Self {
            authority,
            sweep,
            closure,
        };
        proof.verify(tx)?;
        Ok(proof)
    }
    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.authority.verify(tx)?;
        self.closure.verify_current(tx)?;
        protected::verify_source_reference(tx, &self.sweep)?;
        let actual = lifecycle::publication_sweeping_source(tx, &self.authority.record)?
            .ok_or_else(|| refused("collection intake lost its actual barrier"))?;
        if !same_source(&actual, &self.sweep) {
            return Err(refused("collection intake changed exact sweep"));
        }
        Ok(())
    }
    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.authority.transaction
    }
    pub(in crate::admission_operation_store) fn scope(&self) -> &RecoveryScopeV1 {
        &self.authority.record.metadata.scope
    }
    pub(in crate::admission_operation_store) fn source(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.authority.source
    }
    pub(in crate::admission_operation_store) fn sweeping_source(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.sweep
    }
    pub(in crate::admission_operation_store) fn reference(&self) -> &ArtifactVersionRefV1 {
        &self.authority.reference
    }
    pub(in crate::admission_operation_store) fn record(&self) -> &NativeArtifactRecordV1 {
        &self.authority.record
    }
    pub(in crate::admission_operation_store) fn dependency_references(
        &self,
    ) -> &[ArtifactVersionRefV1] {
        self.authority.record.input.dependencies.as_slice()
    }
    pub(in crate::admission_operation_store) fn seal(
        &self,
    ) -> Result<&ArtifactBlobSealV1, AdmissionOperationStoreError> {
        self.authority
            .record
            .seal
            .as_ref()
            .ok_or_else(|| refused("collection intake lost exact object"))
    }
}

impl<'tx, 'conn> RetirementAuthority<'tx, 'conn> {
    fn new(
        tx: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        now: u64,
        reference: &ArtifactVersionRefV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let key: String = load(tx, &version_key(reference)?)?
            .ok_or_else(|| refused("retirement intake version absent"))?;
        let record: NativeArtifactRecordV1 =
            load(tx, &key)?.ok_or_else(|| refused("retirement intake publication absent"))?;
        let proof = Self {
            transaction: tx,
            actor,
            profile,
            now,
            source: protected::source_reference(tx, &key)?,
            record,
            reference: reference.clone(),
        };
        proof.verify(tx)?;
        Ok(proof)
    }
    fn verify(&self, tx: &Transaction<'conn>) -> Result<(), AdmissionOperationStoreError> {
        same_transaction(self.transaction, tx)?;
        let deployment = protected::deployment_tx(tx, self.actor.scope())?;
        super::super::recovery::verify_actor(tx, self.actor, &deployment, self.now)?;
        let current = installation(tx, self.actor.scope())?;
        validate_installation(tx, &deployment, &current)?;
        protected::verify_source_reference(tx, &self.source)?;
        self.record.metadata.validate().map_err(refused)?;
        let seal = self
            .record
            .seal
            .as_ref()
            .ok_or_else(|| refused("retirement intake lacks exact object custody"))?;
        if self.actor.permission() != RecoveryPermission::KnowledgeAdmin
            || self.reference.scope != *self.actor.scope()
            || protected::encode(&current)? != protected::encode(self.profile)?
            || self.record.metadata.retention != ArtifactRetentionV1::Ephemeral
            || matches!(
                self.record.metadata.producer,
                ArtifactProducerV1::NativeOperation { .. }
            )
            || !matches!(
                self.record.state,
                ArtifactPublicationStateV1::Available | ArtifactPublicationStateV1::Retired
            )
            || self.record.input.dependencies != self.record.metadata.dependencies
            || self.record.input.dependencies.as_slice().len() > 16
            || record_publication_key(&self.record)? != self.source.record_key()
            || artifact_version_reference(&self.record.metadata).map_err(refused)? != self.reference
            || self.source.scope_key() != scope_key(self.actor.scope())?
            || self.source.kind() != "command"
            || seal.object != self.record.object
            || seal.content != self.record.input.content
            || seal.bytes != self.record.input.size_bytes
            || seal.process != self.actor.scope().process_id
        {
            return Err(refused(
                "retirement intake lost fresh native storage authority",
            ));
        }
        let latest: NativeArtifactRecordV1 = load(tx, self.source.record_key())?
            .ok_or_else(|| refused("retirement intake source disappeared"))?;
        let pointer: String = load(tx, &version_key(&self.reference)?)?
            .ok_or_else(|| refused("retirement intake pointer disappeared"))?;
        if protected::encode(&latest)? != protected::encode(&self.record)?
            || pointer != self.source.record_key()
        {
            return Err(refused("retirement intake source changed exact object"));
        }
        traversal::ensure_audience(tx, self.actor, &self.record.metadata.label)?;
        traversal::ensure_audience(
            tx,
            self.actor,
            &source(tx, &current.native_authority, &current.producer_context)?,
        )?;
        if references::active_reference_owner_count(tx, &self.reference)? != 0 {
            return Err(refused(
                "retirement intake retains native or uncertain custody",
            ));
        }
        Ok(())
    }
}

impl<'tx, 'conn> VerifiedKnowledgePublicationRetirement<'tx, 'conn> {
    /// Minted only after the host's exact collection acknowledgment was retained.
    /// The allocator independently verifies the pre-delete accepted allocation.
    pub(super) fn new(
        tx: &'tx Transaction<'conn>,
        record: &NativeArtifactRecordV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let reference = artifact_version_reference(&record.metadata).map_err(refused)?;
        let collected = lifecycle::publication_collection_source(tx, record)?.ok_or_else(|| {
            refused("publication retirement lacks actual collection acknowledgment")
        })?;
        let closure = references::collected_publication_closure(tx, record)?;
        let proof = Self {
            transaction: tx,
            record: record.clone(),
            reference,
            source: protected::source_reference(tx, &record_publication_key(record)?)?,
            collected,
            closure,
        };
        proof.verify(tx)?;
        Ok(proof)
    }
    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.transaction
    }
    pub(in crate::admission_operation_store) fn scope(&self) -> &RecoveryScopeV1 {
        &self.record.metadata.scope
    }
    pub(in crate::admission_operation_store) fn reference(&self) -> &ArtifactVersionRefV1 {
        &self.reference
    }
    pub(in crate::admission_operation_store) fn source(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.source
    }
    pub(in crate::admission_operation_store) fn collected_source(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.collected
    }
    pub(in crate::admission_operation_store) fn record(&self) -> &NativeArtifactRecordV1 {
        &self.record
    }
    pub(in crate::admission_operation_store) fn dependency_references(
        &self,
    ) -> &[ArtifactVersionRefV1] {
        self.record.input.dependencies.as_slice()
    }
    pub(in crate::admission_operation_store) fn reference_closure(
        &self,
    ) -> &references::CollectedPublicationReferenceClosure<'tx, 'conn> {
        &self.closure
    }
    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        same_transaction(self.transaction, tx)?;
        protected::verify_source_reference(tx, &self.source)?;
        protected::verify_source_reference(tx, &self.collected)?;
        self.closure.verify_current(tx)?;
        let collected =
            lifecycle::publication_collection_source(tx, &self.record)?.ok_or_else(|| {
                refused("publication retirement lost its actual collection acknowledgment")
            })?;
        if self.record.state != ArtifactPublicationStateV1::Retired
            || self.source.record_key() != record_publication_key(&self.record)?
            || artifact_version_reference(&self.record.metadata).map_err(refused)? != self.reference
            || !same_source(&collected, &self.collected)
        {
            return Err(refused(
                "publication retirement changed immutable collection custody",
            ));
        }
        Ok(())
    }
}

fn same_transaction(
    left: &Transaction<'_>,
    right: &Transaction<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    if !std::ptr::eq::<Connection>(Deref::deref(left), Deref::deref(right)) {
        return Err(refused("publication retirement changed physical writer"));
    }
    Ok(())
}
fn same_source(
    left: &protected::ProtectedSourceReference,
    right: &protected::ProtectedSourceReference,
) -> bool {
    left.record_key() == right.record_key()
        && left.scope_key() == right.scope_key()
        && left.kind() == right.kind()
        && left.version() == right.version()
        && left.digest() == right.digest()
        && left.event_sequence() == right.event_sequence()
        && left.global_commit_sequence() == right.global_commit_sequence()
}

impl std::fmt::Debug for VerifiedKnowledgePublicationRetireIntake<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedKnowledgePublicationRetireIntake([redacted])")
    }
}
impl std::fmt::Debug for VerifiedKnowledgePublicationCollectionIntake<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedKnowledgePublicationCollectionIntake([redacted])")
    }
}
impl std::fmt::Debug for VerifiedKnowledgePublicationRetirement<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedKnowledgePublicationRetirement([redacted])")
    }
}

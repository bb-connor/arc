//! Affine publication custody is verified inside the exact accepting writer.
use super::*;
use std::ops::Deref;

/// A source identity includes its process and original principal; the allocator
/// account is separately derived from only its serving domain and tenant.
#[derive(Serialize)]
pub(in crate::admission_operation_store) struct KnowledgePublicationIdentity<'a> {
    scope: &'a RecoveryScopeV1,
    principal: &'a chio_security_types::PrincipalId,
    publication: &'a CommandId,
    artifact: &'a ArtifactId,
    version: &'a ArtifactRevisionId,
}

/// Fresh data is bound to the actual writer, original actor and exact current
/// installation. No deserialized payload can construct this intake witness.
pub(in crate::admission_operation_store) struct VerifiedKnowledgePublicationIntake<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    actor: &'tx AuthenticatedRecoveryActor,
    profile: &'tx NativeKnowledgeInstallationV1,
    now: u64,
    record: NativeArtifactRecordV1,
    source_key: String,
    canonical_payload: Vec<u8>,
}

impl<'tx, 'conn> VerifiedKnowledgePublicationIntake<'tx, 'conn> {
    /// Called only after reserve_artifact has resolved native producer custody,
    /// copied/imported provenance, dependencies and finite adopting audience.
    pub(super) fn new(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        now: u64,
        record: NativeArtifactRecordV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let source_key = record_publication_key(&record)?;
        let canonical_payload = protected::encode(&record)?;
        let witness = Self {
            transaction,
            actor,
            profile,
            now,
            record,
            source_key,
            canonical_payload,
        };
        witness.verify(transaction)?;
        Ok(witness)
    }

    pub(in crate::admission_operation_store) fn verify(
        &self,
        transaction: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction), Deref::deref(transaction)) {
            return Err(refused("publication intake changed its physical writer"));
        }
        let deployment = protected::deployment_tx(transaction, self.actor.scope())?;
        super::super::recovery::verify_actor(transaction, self.actor, &deployment, self.now)?;
        let current = installation(transaction, self.actor.scope())?;
        validate_installation(transaction, &deployment, &current)?;
        if protected::encode(&current)? != protected::encode(self.profile)?
            || !matches!(
                self.actor.permission(),
                RecoveryPermission::KnowledgeWrite | RecoveryPermission::KnowledgeAdopt
            )
            || self.record.state != ArtifactPublicationStateV1::Reserved
            || self.record.seal.is_some()
            || self.record.certificate.is_some()
            || self.record.metadata.scope != *self.actor.scope()
            || self.record.publication_principal.as_ref() != Some(self.actor.principal())
            || self.record.installation_generation != current.generation
            || self.record.metadata.content != self.record.input.content
            || self.record.metadata.size_bytes != self.record.input.size_bytes
            || self.record.metadata.media_type != self.record.input.media_type
            || self.record.metadata.schema != self.record.input.schema
            || self.record.metadata.producer != self.record.input.producer
            || self.record.metadata.dependencies != self.record.input.dependencies
            || self.record.metadata.retention != self.record.input.retention
            || self.record.metadata.policy != current.policy
            || self.record.metadata.contract != current.contract
            || self.record.metadata.lineage.as_str()
                != current.producer_context.as_v1().lineage_root_id().as_str()
            || self.record.metadata.isolation_epoch.as_str()
                != current
                    .producer_context
                    .as_v1()
                    .isolation_epoch_id()
                    .as_str()
            || self.record.input.size_bytes.get() > MAX_ARTIFACT_BYTES as u64
            || self.source_key != record_publication_key(&self.record)?
            || protected::raw_checked(transaction, &self.source_key)?.is_some()
            || self.canonical_payload != protected::encode(&self.record)?
            || self.canonical_payload.len() > 262_144
        {
            return Err(refused("publication intake lost its native binding"));
        }
        self.record.metadata.validate().map_err(refused)?;
        publication::ensure_publication_audience(transaction, self.actor, &self.record)?;
        verify_producer_custody(transaction, self.actor, &current, &self.record)?;
        for dependency in self.record.input.dependencies.as_slice() {
            let dependency = artifact(transaction, dependency)?;
            if dependency.metadata.scope != *self.actor.scope() {
                return Err(refused("publication dependency changed its account"));
            }
        }
        Ok(())
    }

    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.transaction
    }
    pub(in crate::admission_operation_store) fn scope(&self) -> &RecoveryScopeV1 {
        &self.record.metadata.scope
    }
    pub(in crate::admission_operation_store) fn source_key(&self) -> &str {
        &self.source_key
    }
    pub(in crate::admission_operation_store) fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }
    pub(in crate::admission_operation_store) fn record(&self) -> &NativeArtifactRecordV1 {
        &self.record
    }
    pub(in crate::admission_operation_store) fn publication_identity(
        &self,
    ) -> KnowledgePublicationIdentity<'_> {
        KnowledgePublicationIdentity {
            scope: &self.record.metadata.scope,
            principal: self.actor.principal(),
            publication: &self.record.input.publication,
            artifact: &self.record.metadata.artifact,
            version: &self.record.metadata.version,
        }
    }
    pub(in crate::admission_operation_store) fn dependency_references(
        &self,
    ) -> &[ArtifactVersionRefV1] {
        self.record.input.dependencies.as_slice()
    }
}

/// Rechecking the original native source avoids turning a decoded producer tag
/// into reservation authority. Imports retain their exact signed source floor.
fn verify_producer_custody(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
    record: &NativeArtifactRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    let input = &record.input;
    let mut floor = source(tx, &profile.native_authority, &profile.producer_context)?;
    match &input.producer {
        ArtifactProducerV1::NativeOperation { operation } => {
            let id = AdmissionOperationId::from_persisted(operation.as_str()).map_err(refused)?;
            let original = load_operation_for_participant_tx(tx, &id)?
                .ok_or_else(|| refused("publication native producer absent"))?;
            if original.state() != AdmissionOperationState::Completed
                || original.native_dispatch_ledger_digest().is_none()
            {
                return Err(refused("publication native producer incomplete"));
            }
            let retained = super::super::retained_request::load_retained_request_tx(tx, &original)?
                .ok_or_else(|| refused("publication native request absent"))?;
            retained.validate_native_security_authority(&profile.native_authority)?;
            retained.validate_native_security_context(&profile.producer_context)?;
            let outcome =
                crate::tool_outcome_store::load_outcome_connection(tx, operation.as_str())
                    .map_err(refused)?
                    .ok_or_else(|| refused("publication native outcome absent"))?;
            let blob = crate::tool_outcome_store::load_resolved_blob_connection(tx, &outcome)
                .map_err(refused)?
                .ok_or_else(|| refused("publication native bytes absent"))?;
            if knowledge_content_digest(blob.bytes()) != input.content
                || u64::try_from(blob.bytes().len()).map_err(refused)? != input.size_bytes.get()
            {
                return Err(refused("publication native bytes changed"));
            }
        }
        ArtifactProducerV1::Adoption { .. } => {
            if actor.permission() != RecoveryPermission::KnowledgeAdopt
                || !input.dependencies.as_slice().is_empty()
            {
                return Err(refused("publication adoption source"));
            }
            floor = InformationLabel::Top;
        }
        ArtifactProducerV1::Checkpoint { .. } | ArtifactProducerV1::Derivation { .. } => {
            if actor.permission() != RecoveryPermission::KnowledgeWrite {
                return Err(refused("publication writer source"));
            }
        }
        ArtifactProducerV1::Import { .. } => {
            if actor.permission() != RecoveryPermission::KnowledgeWrite {
                return Err(refused("publication import source"));
            }
            let imported = transfer::import_source(tx, profile, input)?;
            floor = floor.join_restrictions(&imported.label).map_err(refused)?;
            if (imported.influence.unknown && !record.metadata.influence.unknown)
                || !imported
                    .evidence
                    .as_slice()
                    .iter()
                    .all(|evidence| record.metadata.evidence.as_slice().contains(evidence))
            {
                return Err(refused("publication import omitted provenance"));
            }
        }
    }
    let dependencies = traversal::dependencies(tx, actor.scope(), input.dependencies.as_slice())?;
    let floor = traversal::join_metadata(floor, &dependencies)?;
    if !floor.flows_to(&record.metadata.label) {
        return Err(refused("publication intake weakened its actual source"));
    }
    Ok(())
}

/// A current source snapshot has no independent authority. Its owning native
/// writer must have validated the exact lawful transition before construction.
pub(in crate::admission_operation_store) struct VerifiedKnowledgePublicationProgress<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    previous: protected::ProtectedSourceReference,
    record: NativeArtifactRecordV1,
    canonical_payload: Vec<u8>,
}

impl<'tx, 'conn> VerifiedKnowledgePublicationProgress<'tx, 'conn> {
    pub(super) fn new(
        transaction: &'tx Transaction<'conn>,
        previous: protected::ProtectedSourceReference,
        record: NativeArtifactRecordV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let canonical_payload = protected::encode(&record)?;
        let witness = Self {
            transaction,
            previous,
            record,
            canonical_payload,
        };
        witness.verify(transaction)?;
        Ok(witness)
    }

    pub(in crate::admission_operation_store) fn verify(
        &self,
        transaction: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction), Deref::deref(transaction)) {
            return Err(refused("publication progress changed its physical writer"));
        }
        protected::verify_source_reference(transaction, &self.previous)?;
        let before: NativeArtifactRecordV1 = load(transaction, self.previous.record_key())?
            .ok_or_else(|| refused("publication progress source absent"))?;
        if self.previous.kind() != "command"
            || self.previous.record_key() != record_publication_key(&before)?
            || self.previous.scope_key() != scope_key(&before.metadata.scope)?
            || self.record.input != before.input
            || self.record.object != before.object
            || self.record.metadata.scope != before.metadata.scope
            || self.record.metadata.artifact != before.metadata.artifact
            || self.record.metadata.version != before.metadata.version
            || self.record.publication_principal != before.publication_principal
            || self.record.installation_generation != before.installation_generation
            || self.record.location != before.location
            || self.canonical_payload != protected::encode(&self.record)?
            || self.canonical_payload.len() > 262_144
        {
            return Err(refused("publication progress changed its immutable parent"));
        }
        validate_publication_transition(&before, &self.record)?;
        self.record.metadata.validate().map_err(refused)?;
        Ok(())
    }

    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.transaction
    }
    pub(in crate::admission_operation_store) fn scope(&self) -> &RecoveryScopeV1 {
        &self.record.metadata.scope
    }
    pub(in crate::admission_operation_store) fn previous(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.previous
    }
    pub(in crate::admission_operation_store) fn record(&self) -> &NativeArtifactRecordV1 {
        &self.record
    }
    pub(in crate::admission_operation_store) fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }
}

fn validate_publication_transition(
    before: &NativeArtifactRecordV1,
    after: &NativeArtifactRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    use ArtifactPublicationStateV1::*;
    let same_metadata = protected::encode(&before.metadata)? == protected::encode(&after.metadata)?;
    let same_certificate = before.certificate == after.certificate;
    let same_seal = before.seal == after.seal;
    let lawful = match (before.state, after.state) {
        (Reserved, Staged) => {
            same_metadata && same_certificate && before.seal.is_none() && after.seal.is_some()
        }
        (Staged, MetadataCommitted) => {
            // The owning commit writer independently validates the exact typed
            // certificate, source/dependency labels and current profile. This
            // source check additionally prevents changing immutable metadata.
            same_seal
                && before.metadata.domain_version == after.metadata.domain_version
                && before.metadata.content == after.metadata.content
                && before.metadata.size_bytes == after.metadata.size_bytes
                && before.metadata.media_type == after.metadata.media_type
                && before.metadata.schema == after.metadata.schema
                && before.metadata.producer == after.metadata.producer
                && before.metadata.dependencies == after.metadata.dependencies
                && before.metadata.influence == after.metadata.influence
                && before.metadata.lineage == after.metadata.lineage
                && before.metadata.isolation_epoch == after.metadata.isolation_epoch
                && before.metadata.policy == after.metadata.policy
                && before.metadata.contract == after.metadata.contract
                && before.metadata.creation_sequence == after.metadata.creation_sequence
                && before.metadata.retention == after.metadata.retention
        }
        (MetadataCommitted, Available) => same_metadata && same_certificate && same_seal,
        (Reserved | Staged | MetadataCommitted | Available | Quarantined, Quarantined) => {
            same_metadata && same_certificate && same_seal
        }
        (Reserved | Staged | MetadataCommitted | Available | Quarantined, Retired) => {
            same_metadata && same_certificate && same_seal
        }
        _ if before.state == after.state => protected::encode(before)? == protected::encode(after)?,
        _ => false,
    };
    if !lawful {
        return Err(refused(
            "publication progress is not a lawful bounded transition",
        ));
    }
    Ok(())
}

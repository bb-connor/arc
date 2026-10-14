//! Fresh native authority binds one exact checkpoint-head mutation.
use super::*;
use std::ops::Deref;

const MAX_CHECKPOINT_HEAD_BYTES: usize = 4096;

/// This affine proof has no wire constructor, independent writer or credits.
/// It is minted only by the owning checkpoint path after its fresh source
/// validation and immutable successor/latest writes in this transaction.
pub(in crate::admission_operation_store) struct VerifiedCheckpointHeadWrite<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    actor: &'tx AuthenticatedRecoveryActor,
    profile: &'tx NativeKnowledgeInstallationV1,
    now: u64,
    allocation: super::watermark::RevisionAllocation<'tx, 'conn>,
    checkpoint: &'tx LabeledCheckpointV1,
    source_key: String,
    canonical_payload: Vec<u8>,
    current_envelope_source: protected::ProtectedSourceReference,
    revision_source: protected::ProtectedSourceReference,
    source_set: Vec<protected::ProtectedSourceReference>,
}

impl<'tx, 'conn> VerifiedCheckpointHeadWrite<'tx, 'conn> {
    pub(super) fn new(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        now: u64,
        allocation: super::watermark::RevisionAllocation<'tx, 'conn>,
        checkpoint: &'tx LabeledCheckpointV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let source_key = super::watermark::key(&checkpoint.scope, &checkpoint.checkpoint)?;
        let canonical_payload = protected::encode(&super::watermark::completed_head(checkpoint)?)?;
        if canonical_payload.len() > MAX_CHECKPOINT_HEAD_BYTES {
            return Err(refused("checkpoint head exceeds its closed bound"));
        }
        let current_envelope_source = protected::source_reference(
            transaction,
            &head::checkpoint_key(&checkpoint.scope, &checkpoint.checkpoint)?,
        )?;
        let revision_source = protected::source_reference(
            transaction,
            &head::checkpoint_revision_key(
                &checkpoint.scope,
                &checkpoint.checkpoint,
                checkpoint.revision.get(),
            )?,
        )?;
        let records = checkpoint_sources(transaction, checkpoint)?;
        let mut source_set = Vec::with_capacity(records.len() * 2);
        for record in records {
            let reference = artifact_version_reference(&record.metadata).map_err(refused)?;
            for key in [version_key(&reference)?, record_publication_key(&record)?] {
                source_set.push(protected::source_reference(transaction, &key)?);
            }
        }
        let proof = Self {
            transaction,
            actor,
            profile,
            now,
            allocation,
            checkpoint,
            source_key,
            canonical_payload,
            current_envelope_source,
            revision_source,
            source_set,
        };
        proof.verify(transaction)?;
        Ok(proof)
    }

    pub(in crate::admission_operation_store) fn verify(
        &self,
        transaction: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction), Deref::deref(transaction)) {
            return Err(refused("checkpoint head changed its physical writer"));
        }
        let now = schema::authority_validation_time(transaction, self.now)?;
        let deployment = protected::deployment_tx(transaction, self.actor.scope())?;
        super::super::super::recovery::verify_actor(transaction, self.actor, &deployment, now)?;
        let current = installation(transaction, self.actor.scope())?;
        validate_installation(transaction, &deployment, &current)?;
        if self.actor.permission() != RecoveryPermission::KnowledgeWrite
            || self.checkpoint.scope != *self.actor.scope()
            || protected::encode(&current)? != protected::encode(self.profile)?
            || self.checkpoint.runtime.as_str()
                != current.producer_context.as_v1().session_id().as_str()
            || self.checkpoint.lineage.as_str()
                != current.producer_context.as_v1().lineage_root_id().as_str()
            || self.checkpoint.isolation_epoch.as_str()
                != current
                    .producer_context
                    .as_v1()
                    .isolation_epoch_id()
                    .as_str()
            || self.checkpoint.policy != current.policy
            || self.source_key
                != super::watermark::key(&self.checkpoint.scope, &self.checkpoint.checkpoint)?
            || self.canonical_payload
                != protected::encode(&super::watermark::completed_head(self.checkpoint)?)?
            || self.canonical_payload.len() > MAX_CHECKPOINT_HEAD_BYTES
            || protected::encode(self.checkpoint)?.len() > MAX_CHECKPOINT_ENVELOPE_BYTES
        {
            return Err(refused("checkpoint head lost its current native binding"));
        }
        self.allocation.verify(transaction, self.checkpoint)?;
        for context in self.checkpoint.model_contexts.as_slice() {
            if !current.recipients.as_slice().iter().any(|selection| {
                selection.recipient.sink
                    == (ArtifactSinkV1::Model {
                        context: context.clone(),
                    })
            }) {
                return Err(refused("checkpoint model selection changed"));
            }
        }
        let records = checkpoint_sources(transaction, self.checkpoint)?;
        if self.source_set.len() != records.len() * 2 {
            return Err(refused("checkpoint source inventory changed"));
        }
        for expected in &self.source_set {
            protected::verify_source_reference(transaction, expected)?;
        }
        let label = traversal::join_metadata(
            source(
                transaction,
                &current.native_authority,
                &current.producer_context,
            )?,
            &records,
        )?;
        let influence = traversal::influence(
            transaction,
            &current.native_authority,
            &current.producer_context,
            &records,
            false,
        )?;
        if label != self.checkpoint.label || influence != self.checkpoint.influence {
            return Err(refused("checkpoint native source changed"));
        }
        traversal::ensure_audience(transaction, self.actor, &self.checkpoint.label)?;
        for expected in [&self.current_envelope_source, &self.revision_source] {
            protected::verify_source_reference(transaction, expected)?;
            let retained = super::reference_source::checkpoint_reference_source(
                transaction,
                expected.record_key(),
            )?
            .ok_or_else(|| refused("checkpoint successor source absent"))?;
            if retained.canonical_envelope()? != protected::encode(self.checkpoint)?
                || !retained.active()
            {
                return Err(refused("checkpoint successor source changed"));
            }
        }
        Ok(())
    }

    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.transaction
    }
    pub(in crate::admission_operation_store) fn scope(&self) -> &RecoveryScopeV1 {
        &self.checkpoint.scope
    }
    pub(in crate::admission_operation_store) fn key(&self) -> &str {
        &self.source_key
    }
    pub(in crate::admission_operation_store) fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }
    pub(in crate::admission_operation_store) fn expected_head(
        &self,
    ) -> Option<&protected::ProtectedSourceReference> {
        self.allocation.expected_head()
    }
    pub(in crate::admission_operation_store) fn current_envelope_source(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.current_envelope_source
    }
    pub(in crate::admission_operation_store) fn revision_source(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.revision_source
    }
}

fn checkpoint_sources(
    transaction: &Transaction<'_>,
    checkpoint: &LabeledCheckpointV1,
) -> Result<Vec<NativeArtifactRecordV1>, AdmissionOperationStoreError> {
    let mut dependencies = checkpoint.artifacts.as_slice().to_vec();
    for context in checkpoint.model_contexts.as_slice() {
        dependencies.extend_from_slice(context.side_files.as_slice());
    }
    traversal::dependencies(transaction, &checkpoint.scope, &dependencies)
}

//! Authenticated checkpoint material for the private reference-custody index.
use super::*;

pub(super) struct CheckpointMaterial {
    checkpoint: LabeledCheckpointV1,
    envelope: CanonicalPayloadDigest,
    references: Vec<ArtifactVersionRefV1>,
}

impl CheckpointMaterial {
    pub(super) fn new(
        checkpoint: LabeledCheckpointV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        checkpoint.validate().map_err(refused)?;
        let mut references = Vec::new();
        for reference in checkpoint.artifacts.as_slice().iter().chain(
            checkpoint
                .model_contexts
                .as_slice()
                .iter()
                .flat_map(|model| model.side_files.as_slice()),
        ) {
            if reference.scope != checkpoint.scope {
                return Err(refused("checkpoint reference source scope"));
            }
            if !references.contains(reference) {
                if references.len() == MAX_ARTIFACT_TRAVERSAL {
                    return Err(refused("checkpoint reference source overflow"));
                }
                references.push(reference.clone());
            }
        }
        let envelope = CanonicalPayloadDigest::from_bytes(
            *chio_core::sha256(&protected::encode(&checkpoint)?).as_bytes(),
        );
        Ok(Self {
            checkpoint,
            envelope,
            references,
        })
    }

    pub(super) fn scope(&self) -> &RecoveryScopeV1 {
        &self.checkpoint.scope
    }
    pub(super) fn checkpoint(&self) -> &CheckpointId {
        &self.checkpoint.checkpoint
    }
    pub(super) fn revision(&self) -> u64 {
        self.checkpoint.revision.get()
    }
    pub(super) fn envelope(&self) -> &CanonicalPayloadDigest {
        &self.envelope
    }
    pub(super) fn references(&self) -> &[ArtifactVersionRefV1] {
        &self.references
    }
}

/// Data only. Construction and retirement status come from exact protected rows.
pub(in crate::admission_operation_store::knowledge) struct CheckpointReferenceSource {
    material: CheckpointMaterial,
    source: protected::ProtectedSourceReference,
    terminal: Option<protected::ProtectedSourceReference>,
}

impl CheckpointReferenceSource {
    pub(in crate::admission_operation_store::knowledge) fn scope(&self) -> &RecoveryScopeV1 {
        self.material.scope()
    }
    pub(in crate::admission_operation_store::knowledge) fn checkpoint(&self) -> &CheckpointId {
        self.material.checkpoint()
    }
    pub(in crate::admission_operation_store::knowledge) fn revision(&self) -> u64 {
        self.material.revision()
    }
    pub(in crate::admission_operation_store::knowledge) fn envelope(
        &self,
    ) -> &CanonicalPayloadDigest {
        self.material.envelope()
    }
    /// Exact authenticated bytes for historical source-alias verification.
    pub(in crate::admission_operation_store::knowledge) fn canonical_envelope(
        &self,
    ) -> Result<Vec<u8>, AdmissionOperationStoreError> {
        protected::encode(&self.material.checkpoint)
    }
    pub(in crate::admission_operation_store::knowledge) fn references(
        &self,
    ) -> &[ArtifactVersionRefV1] {
        self.material.references()
    }
    pub(in crate::admission_operation_store::knowledge) fn active(&self) -> bool {
        self.terminal.is_none()
    }
    pub(in crate::admission_operation_store::knowledge) fn source(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.source
    }
    pub(in crate::admission_operation_store::knowledge) fn terminal(
        &self,
    ) -> Option<&protected::ProtectedSourceReference> {
        self.terminal.as_ref()
    }
}

pub(in crate::admission_operation_store::knowledge) fn checkpoint_reference_source(
    connection: &Connection,
    key: &str,
) -> Result<Option<CheckpointReferenceSource>, AdmissionOperationStoreError> {
    if !key.starts_with("knowledge-checkpoint:") {
        return Ok(None);
    }
    let Some(row) = protected::raw_checked(connection, key)? else {
        return Ok(None);
    };
    let checkpoint: LabeledCheckpointV1 = protected::decode(&row.payload)?;
    if row.kind != "command" || row.scope != scope_key(&checkpoint.scope)? {
        return Err(refused("checkpoint reference source ownership"));
    }
    head::validate_record_key(&checkpoint, key)?;
    let source = protected::source_reference(connection, key)?;
    let terminal = retirement::retirement_source(connection, &checkpoint)?;
    Ok(Some(CheckpointReferenceSource {
        material: CheckpointMaterial::new(checkpoint)?,
        source,
        terminal,
    }))
}

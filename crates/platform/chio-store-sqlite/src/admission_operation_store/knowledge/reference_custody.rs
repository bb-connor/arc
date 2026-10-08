//! Native retained sources mint affine reference custody inside a fenced writer.
use super::references::{ProductEvidenceOwner, ReferenceOwner, SourceAnchor};
use super::*;
use std::ops::Deref;

pub(in crate::admission_operation_store) struct VerifiedKnowledgeReferenceRetain<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    source: protected::ProtectedSourceReference,
    owner: ReferenceOwner,
    references: Vec<ArtifactVersionRefV1>,
    evidence: RetainedSourceEvidence,
}

enum RetainedSourceEvidence {
    Publication,
    ModernPin,
    ConfinedInputs { envelope: CanonicalPayloadDigest },
    Product { owner: ProductEvidenceOwner },
    Checkpoint { envelope: CanonicalPayloadDigest },
    Restore { envelope: CanonicalPayloadDigest },
    ArtifactRelease { envelope: CanonicalPayloadDigest },
}

impl<'tx, 'conn> VerifiedKnowledgeReferenceRetain<'tx, 'conn> {
    /// The product source owner has already saved its immutable body in this
    /// writer. Declared source data cannot substitute for that protected body.
    pub(super) fn product(
        tx: &'tx Transaction<'conn>,
        owner: ProductEvidenceOwner,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let (source, references) = super::super::product::product_evidence_source(tx, &owner)?;
        if references.is_empty() {
            return Err(refused("empty product source has no reference intake"));
        }
        let witness = Self {
            transaction: tx,
            source,
            owner: ReferenceOwner::from(owner.clone()),
            references,
            evidence: RetainedSourceEvidence::Product { owner },
        };
        witness.verify(tx)?;
        Ok(witness)
    }

    /// Original reservation custody remains held across every child state.
    /// The source adapter authenticates the first boundary and every pin tuple.
    pub(super) fn confined_inputs(
        tx: &'tx Transaction<'conn>,
        key: &str,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let inputs: confinement::ConfinedInputReferenceSource =
            confinement::input_reference_source(tx, key)?
                .ok_or_else(|| refused("confined inputs have no original boundary source"))?;
        let boundary = inputs.boundary();
        let witness = Self {
            transaction: tx,
            source: protected::source_reference(tx, key)?,
            owner: ReferenceOwner::ConfinedInputs {
                scope: boundary.scope.clone(),
                request: boundary.request.clone(),
                boundary: boundary.boundary.clone(),
            },
            references: inputs.references().to_vec(),
            evidence: RetainedSourceEvidence::ConfinedInputs {
                envelope: confined_input_envelope_digest(boundary)?,
            },
        };
        witness.verify(tx)?;
        Ok(witness)
    }

    pub(super) fn artifact_release(
        tx: &'tx Transaction<'conn>,
        key: &str,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        let Some(release) = release::artifact_reference_source(tx, key)? else {
            return Ok(None);
        };
        if !release.active() {
            return Ok(None);
        }
        let witness = Self {
            transaction: tx,
            owner: ReferenceOwner::ArtifactRelease {
                scope: release.scope().clone(),
                release: release.release().clone(),
            },
            references: release.references().to_vec(),
            source: protected::source_reference(tx, key)?,
            evidence: RetainedSourceEvidence::ArtifactRelease {
                envelope: release.envelope(),
            },
        };
        witness.verify(tx)?;
        Ok(Some(witness))
    }
    pub(super) fn publication_dependencies(
        tx: &'tx Transaction<'conn>,
        record: &NativeArtifactRecordV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let source = protected::source_reference(tx, &record_publication_key(record)?)?;
        let witness = Self {
            transaction: tx,
            source,
            owner: ReferenceOwner::Publication {
                scope: record.metadata.scope.clone(),
                artifact: record.metadata.artifact.clone(),
                version: record.metadata.version.clone(),
            },
            references: record.input.dependencies.as_slice().to_vec(),
            evidence: RetainedSourceEvidence::Publication,
        };
        witness.verify(tx)?;
        Ok(witness)
    }

    pub(super) fn modern_pin(
        tx: &'tx Transaction<'conn>,
        key: &str,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        let Some(pin) = pins::modern_reference_source(tx, key)? else {
            return Ok(None);
        };
        if !pin.active() {
            return Ok(None);
        }
        let witness = Self {
            transaction: tx,
            owner: pin_owner(&pin),
            references: vec![pin.reference().clone()],
            source: protected::source_reference(tx, key)?,
            evidence: RetainedSourceEvidence::ModernPin,
        };
        witness.verify(tx)?;
        Ok(Some(witness))
    }

    pub(super) fn checkpoint(
        tx: &'tx Transaction<'conn>,
        key: &str,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        let Some(checkpoint) = checkpoints::checkpoint_reference_source(tx, key)? else {
            return Ok(None);
        };
        if !checkpoint.active() {
            return Ok(None);
        }
        let witness = Self {
            transaction: tx,
            source: protected::source_reference(tx, key)?,
            owner: ReferenceOwner::CheckpointRevision {
                scope: checkpoint.scope().clone(),
                checkpoint: checkpoint.checkpoint().clone(),
                revision: SafeInteger::new(checkpoint.revision()).map_err(refused)?,
            },
            references: checkpoint.references().to_vec(),
            evidence: RetainedSourceEvidence::Checkpoint {
                envelope: *checkpoint.envelope(),
            },
        };
        witness.verify(tx)?;
        Ok(Some(witness))
    }

    pub(super) fn restore(
        tx: &'tx Transaction<'conn>,
        key: &str,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        let Some(restore) = checkpoints::restore_reference_source(tx, key)? else {
            return Ok(None);
        };
        if !restore.active() {
            return Ok(None);
        }
        let witness = Self {
            transaction: tx,
            source: protected::source_reference(tx, key)?,
            owner: ReferenceOwner::CheckpointRestore {
                scope: restore.scope().clone(),
                release: restore.release().clone(),
            },
            references: restore.references().to_vec(),
            evidence: RetainedSourceEvidence::Restore {
                envelope: *restore.envelope(),
            },
        };
        witness.verify(tx)?;
        Ok(Some(witness))
    }

    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction), Deref::deref(tx)) {
            return Err(refused("reference custody changed its physical writer"));
        }
        protected::verify_source_reference(tx, &self.source)?;
        if self.source.kind() != "command"
            || self.source.scope_key() != scope_key(self.owner.scope())?
            || self.references.len() > MAX_ARTIFACT_TRAVERSAL
        {
            return Err(refused("reference custody changed its source account"));
        }
        match &self.evidence {
            RetainedSourceEvidence::Product { owner } => {
                if self.owner != ReferenceOwner::from(owner.clone()) || self.references.is_empty() {
                    return Err(refused("product reference changed its immutable owner"));
                }
                let (current, references) =
                    super::super::product::product_evidence_source(tx, owner)?;
                if current.record_key() != self.source.record_key()
                    || current.version() != self.source.version()
                    || current.digest() != self.source.digest()
                    || current.event_sequence() != self.source.event_sequence()
                    || current.global_commit_sequence() != self.source.global_commit_sequence()
                    || references != self.references
                {
                    return Err(refused("product reference changed its protected source"));
                }
            }
            RetainedSourceEvidence::ArtifactRelease { envelope } => {
                let release = release::artifact_reference_source(tx, self.source.record_key())?
                    .ok_or_else(|| refused("release reference source disappeared"))?;
                if !release.active()
                    || *envelope != release.envelope()
                    || self.references.as_slice() != release.references()
                    || self.owner
                        != (ReferenceOwner::ArtifactRelease {
                            scope: release.scope().clone(),
                            release: release.release().clone(),
                        })
                {
                    return Err(refused("release reference changed original custody"));
                }
            }
            RetainedSourceEvidence::Publication => {
                let record: NativeArtifactRecordV1 = load(tx, self.source.record_key())?
                    .ok_or_else(|| refused("reference publication disappeared"))?;
                let expected_owner = ReferenceOwner::Publication {
                    scope: record.metadata.scope.clone(),
                    artifact: record.metadata.artifact.clone(),
                    version: record.metadata.version.clone(),
                };
                if record.state == ArtifactPublicationStateV1::Retired
                    || record_publication_key(&record)? != self.source.record_key()
                    || record.input.dependencies != record.metadata.dependencies
                    || self.references.as_slice() != record.input.dependencies.as_slice()
                    || self.owner != expected_owner
                    || self
                        .references
                        .iter()
                        .any(|reference| reference.scope != record.metadata.scope)
                {
                    return Err(refused(
                        "reference publication changed its direct dependencies",
                    ));
                }
            }
            RetainedSourceEvidence::ConfinedInputs { envelope } => {
                let inputs = confinement::input_reference_source(tx, self.source.record_key())?
                    .ok_or_else(|| refused("confined original boundary source disappeared"))?;
                let boundary = inputs.boundary();
                if *envelope != confined_input_envelope_digest(boundary)?
                    || SourceAnchor::capture(inputs.source()) != SourceAnchor::capture(&self.source)
                    || self.references.as_slice() != inputs.references()
                    || self.owner
                        != (ReferenceOwner::ConfinedInputs {
                            scope: boundary.scope.clone(),
                            request: boundary.request.clone(),
                            boundary: boundary.boundary.clone(),
                        })
                {
                    return Err(refused(
                        "confined references changed original input custody",
                    ));
                }
            }
            RetainedSourceEvidence::ModernPin => {
                let pin = pins::modern_reference_source(tx, self.source.record_key())?
                    .ok_or_else(|| refused("reference pin disappeared"))?;
                if !pin.active()
                    || self.owner != pin_owner(&pin)
                    || self.references.as_slice() != [pin.reference().clone()]
                {
                    return Err(refused("reference pin changed its exact purpose"));
                }
            }
            RetainedSourceEvidence::Checkpoint { envelope } => {
                let checkpoint =
                    checkpoints::checkpoint_reference_source(tx, self.source.record_key())?
                        .ok_or_else(|| refused("reference checkpoint disappeared"))?;
                if !checkpoint.active()
                    || envelope != checkpoint.envelope()
                    || self.references.as_slice() != checkpoint.references()
                    || self.owner
                        != (ReferenceOwner::CheckpointRevision {
                            scope: checkpoint.scope().clone(),
                            checkpoint: checkpoint.checkpoint().clone(),
                            revision: SafeInteger::new(checkpoint.revision()).map_err(refused)?,
                        })
                {
                    return Err(refused(
                        "reference checkpoint changed its immutable envelope",
                    ));
                }
            }
            RetainedSourceEvidence::Restore { envelope } => {
                let restore = checkpoints::restore_reference_source(tx, self.source.record_key())?
                    .ok_or_else(|| refused("reference restore disappeared"))?;
                if !restore.active()
                    || envelope != restore.envelope()
                    || self.references.as_slice() != restore.references()
                    || self.owner
                        != (ReferenceOwner::CheckpointRestore {
                            scope: restore.scope().clone(),
                            release: restore.release().clone(),
                        })
                {
                    return Err(refused("reference restore changed its original custody"));
                }
            }
        }
        for (index, reference) in self.references.iter().enumerate() {
            if reference.scope.authority_domain != self.owner.scope().authority_domain
                || reference.scope.tenant_id != self.owner.scope().tenant_id
                || self.references[..index].contains(reference)
            {
                return Err(refused(
                    "reference custody crossed tenant or repeated a version",
                ));
            }
            if matches!(&self.evidence, RetainedSourceEvidence::Product { .. }) {
                super::product_evidence::verify_product_reference_available(tx, reference)?;
            } else {
                artifact(tx, reference)?;
            }
        }
        Ok(())
    }

    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.transaction
    }
    pub(in crate::admission_operation_store) fn owner(&self) -> &ReferenceOwner {
        &self.owner
    }
    pub(in crate::admission_operation_store) fn references(&self) -> &[ArtifactVersionRefV1] {
        &self.references
    }
    pub(in crate::admission_operation_store) fn source(
        &self,
    ) -> &protected::ProtectedSourceReference {
        &self.source
    }

    pub(in crate::admission_operation_store) fn verify_original_anchor(
        &self,
        tx: &Transaction<'conn>,
        original: &SourceAnchor,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.verify(tx)?;
        original.verify_historical_identity(tx)?;
        if original.not_after(&SourceAnchor::capture(&self.source)) {
            return Ok(());
        }
        // Physical checkpoint aliases can preserve one exact logical owner.
        // Equality of the authenticated historical envelope proves migration;
        // a new source key by itself never rebinds an owner.
        if matches!(self.evidence, RetainedSourceEvidence::Checkpoint { .. }) {
            let checkpoint =
                checkpoints::checkpoint_reference_source(tx, self.source.record_key())?
                    .ok_or_else(|| refused("checkpoint migration source disappeared"))?;
            if original.matches_historical_command_payload(tx, &checkpoint.canonical_envelope()?)? {
                return Ok(());
            }
        }
        Err(refused("reference owner changed its original source"))
    }
}

fn confined_input_envelope_digest(
    boundary: &chio_security_types::confinement::IsolationBoundaryV1,
) -> Result<CanonicalPayloadDigest, AdmissionOperationStoreError> {
    boundary.validate().map_err(refused)?;
    // Use the same canonical record bound and domain framing as the owning
    // source. This digest describes an envelope and grants no custody by itself.
    let _canonical_envelope = protected::encode(boundary)?;
    Ok(CanonicalPayloadDigest::from_bytes(
        knowledge_digest(RecoveryDigestDomain::KnowledgeReferenceOwner, boundary)
            .map_err(refused)?,
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

impl std::fmt::Debug for VerifiedKnowledgeReferenceRetain<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedKnowledgeReferenceRetain([redacted])")
    }
}

pub(super) fn retain_publication_references(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    record: &NativeArtifactRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    let proof = VerifiedKnowledgeReferenceRetain::publication_dependencies(tx, record)?;
    protected::persist_knowledge_reference_retain(tx, owner, proof)?;
    Ok(())
}

pub(super) fn retain_pin_references(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    key: &str,
) -> Result<(), AdmissionOperationStoreError> {
    let proof = VerifiedKnowledgeReferenceRetain::modern_pin(tx, key)?
        .ok_or_else(|| refused("active pin has no genuine reference source"))?;
    protected::persist_knowledge_reference_retain(tx, owner, proof)?;
    Ok(())
}

pub(super) fn retain_confined_input_references(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    key: &str,
) -> Result<(), AdmissionOperationStoreError> {
    let proof = VerifiedKnowledgeReferenceRetain::confined_inputs(tx, key)?;
    protected::persist_knowledge_reference_retain(tx, owner, proof)?;
    Ok(())
}

pub(super) fn retain_checkpoint_references(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    key: &str,
) -> Result<(), AdmissionOperationStoreError> {
    let proof = VerifiedKnowledgeReferenceRetain::checkpoint(tx, key)?
        .ok_or_else(|| refused("active checkpoint has no genuine reference source"))?;
    protected::persist_knowledge_reference_retain(tx, owner, proof)?;
    Ok(())
}

pub(super) fn retain_release_references(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    key: &str,
) -> Result<(), AdmissionOperationStoreError> {
    let proof = VerifiedKnowledgeReferenceRetain::artifact_release(tx, key)?
        .ok_or_else(|| refused("active release has no genuine reference source"))?;
    protected::persist_knowledge_reference_retain(tx, owner, proof)?;
    Ok(())
}

pub(super) fn retain_restore_references(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    key: &str,
) -> Result<(), AdmissionOperationStoreError> {
    let proof = VerifiedKnowledgeReferenceRetain::restore(tx, key)?
        .ok_or_else(|| refused("active restore has no genuine reference source"))?;
    protected::persist_knowledge_reference_retain(tx, owner, proof)?;
    Ok(())
}

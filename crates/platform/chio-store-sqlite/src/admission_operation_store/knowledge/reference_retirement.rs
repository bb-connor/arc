//! Retirement is minted from a closed native terminal source, never from absence.
use super::references::{ReferenceOwner, SourceAnchor};
use super::*;
use std::ops::Deref;

pub(in crate::admission_operation_store) struct VerifiedKnowledgeReferenceRetirement<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    owner: ReferenceOwner,
    references: Vec<ArtifactVersionRefV1>,
    original: protected::ProtectedSourceReference,
    terminal: protected::ProtectedSourceReference,
    evidence: TerminalEvidence,
}

enum TerminalEvidence {
    Publication,
    OperatorPin,
    Checkpoint { envelope: CanonicalPayloadDigest },
    Restore { envelope: CanonicalPayloadDigest },
    ArtifactRelease { envelope: CanonicalPayloadDigest },
}

impl<'tx, 'conn> VerifiedKnowledgeReferenceRetirement<'tx, 'conn> {
    pub(super) fn artifact_release(
        tx: &'tx Transaction<'conn>,
        key: &str,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        let Some(release) = release::artifact_reference_source(tx, key)? else {
            return Ok(None);
        };
        let Some(terminal) = release.terminal() else {
            return Ok(None);
        };
        let proof = Self {
            transaction: tx,
            owner: ReferenceOwner::ArtifactRelease {
                scope: release.scope().clone(),
                release: release.release().clone(),
            },
            references: release.references().to_vec(),
            original: protected::source_reference(tx, key)?,
            terminal: protected::source_reference(tx, terminal.record_key())?,
            evidence: TerminalEvidence::ArtifactRelease {
                envelope: release.envelope(),
            },
        };
        proof.verify(tx)?;
        Ok(Some(proof))
    }
    /// This only releases dependencies of an irreversibly retired publication.
    /// The publication's live allocation requires a separate actual Collected
    /// acknowledgment and complete reference closure before refund.
    pub(super) fn publication_dependencies(
        tx: &'tx Transaction<'conn>,
        record: &NativeArtifactRecordV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let key = record_publication_key(record)?;
        let witness = Self {
            transaction: tx,
            owner: ReferenceOwner::Publication {
                scope: record.metadata.scope.clone(),
                artifact: record.metadata.artifact.clone(),
                version: record.metadata.version.clone(),
            },
            references: record.input.dependencies.as_slice().to_vec(),
            original: protected::source_reference(tx, &key)?,
            terminal: protected::source_reference(tx, &key)?,
            evidence: TerminalEvidence::Publication,
        };
        witness.verify(tx)?;
        Ok(witness)
    }

    pub(super) fn operator_pin(
        tx: &'tx Transaction<'conn>,
        key: &str,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        let Some(pin) = pins::modern_reference_source(tx, key)? else {
            return Ok(None);
        };
        if pin.active() {
            return Ok(None);
        }
        let pins::PinOwner::Operator {
            principal,
            evidence,
        } = pin.owner()
        else {
            return Err(refused("operator retirement cannot consume native custody"));
        };
        let witness = Self {
            transaction: tx,
            owner: ReferenceOwner::OperatorPin {
                scope: pin.scope().clone(),
                principal: principal.clone(),
                evidence: evidence.clone(),
            },
            references: vec![pin.reference().clone()],
            original: protected::source_reference(tx, key)?,
            terminal: protected::source_reference(tx, key)?,
            evidence: TerminalEvidence::OperatorPin,
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
        let Some(terminal) = checkpoint.terminal() else {
            return Ok(None);
        };
        let witness = Self {
            transaction: tx,
            owner: ReferenceOwner::CheckpointRevision {
                scope: checkpoint.scope().clone(),
                checkpoint: checkpoint.checkpoint().clone(),
                revision: SafeInteger::new(checkpoint.revision()).map_err(refused)?,
            },
            references: checkpoint.references().to_vec(),
            original: protected::source_reference(tx, key)?,
            terminal: protected::source_reference(tx, terminal.record_key())?,
            evidence: TerminalEvidence::Checkpoint {
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
        let Some(terminal) = restore.terminal() else {
            return Ok(None);
        };
        let witness = Self {
            transaction: tx,
            owner: ReferenceOwner::CheckpointRestore {
                scope: restore.scope().clone(),
                release: restore.release().clone(),
            },
            references: restore.references().to_vec(),
            original: protected::source_reference(tx, key)?,
            terminal: protected::source_reference(tx, terminal.record_key())?,
            evidence: TerminalEvidence::Restore {
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
            return Err(refused("reference retirement changed its physical writer"));
        }
        protected::verify_source_reference(tx, &self.original)?;
        protected::verify_source_reference(tx, &self.terminal)?;
        let scope = scope_key(self.owner.scope())?;
        if self.original.kind() != "command"
            || self.terminal.kind() != "command"
            || self.original.scope_key() != scope
            || self.terminal.scope_key() != scope
            || self.references.len() > MAX_ARTIFACT_TRAVERSAL
        {
            return Err(refused("reference retirement changed its account"));
        }
        match &self.evidence {
            TerminalEvidence::ArtifactRelease { envelope } => {
                let release = release::artifact_reference_source(tx, self.original.record_key())?
                    .ok_or_else(|| refused("release retirement source disappeared"))?;
                let terminal = release
                    .terminal()
                    .ok_or_else(|| refused("uncertain release custody cannot retire"))?;
                if release.active()
                    || *envelope != release.envelope()
                    || self.references.as_slice() != release.references()
                    || !same_source(terminal, &self.terminal)
                    || self.owner
                        != (ReferenceOwner::ArtifactRelease {
                            scope: release.scope().clone(),
                            release: release.release().clone(),
                        })
                {
                    return Err(refused(
                        "release retirement changed actual delivery custody",
                    ));
                }
            }
            TerminalEvidence::Publication => {
                let record: NativeArtifactRecordV1 = load(tx, self.original.record_key())?
                    .ok_or_else(|| refused("retired publication source disappeared"))?;
                record.metadata.validate().map_err(refused)?;
                if record.state != ArtifactPublicationStateV1::Retired
                    || record_publication_key(&record)? != self.original.record_key()
                    || self.terminal.record_key() != self.original.record_key()
                    || self.references.as_slice() != record.input.dependencies.as_slice()
                    || record.input.dependencies != record.metadata.dependencies
                    || self.owner
                        != (ReferenceOwner::Publication {
                            scope: record.metadata.scope.clone(),
                            artifact: record.metadata.artifact.clone(),
                            version: record.metadata.version.clone(),
                        })
                {
                    return Err(refused("publication dependency retirement changed custody"));
                }
            }
            TerminalEvidence::OperatorPin => {
                let pin = pins::modern_reference_source(tx, self.original.record_key())?
                    .ok_or_else(|| refused("operator retirement source disappeared"))?;
                let pins::PinOwner::Operator {
                    principal,
                    evidence,
                } = pin.owner()
                else {
                    return Err(refused("operator retirement selected a different purpose"));
                };
                if pin.active()
                    || self.references.as_slice() != [pin.reference().clone()]
                    || self.terminal.record_key() != self.original.record_key()
                    || self.owner
                        != (ReferenceOwner::OperatorPin {
                            scope: pin.scope().clone(),
                            principal: principal.clone(),
                            evidence: evidence.clone(),
                        })
                {
                    return Err(refused(
                        "operator retirement changed its exact spent identity",
                    ));
                }
            }
            TerminalEvidence::Checkpoint { envelope } => {
                let checkpoint =
                    checkpoints::checkpoint_reference_source(tx, self.original.record_key())?
                        .ok_or_else(|| refused("checkpoint retirement source disappeared"))?;
                let terminal = checkpoint
                    .terminal()
                    .ok_or_else(|| refused("checkpoint revision is not irreversibly retired"))?;
                if checkpoint.active()
                    || envelope != checkpoint.envelope()
                    || self.references.as_slice() != checkpoint.references()
                    || !same_source(terminal, &self.terminal)
                    || self.owner
                        != (ReferenceOwner::CheckpointRevision {
                            scope: checkpoint.scope().clone(),
                            checkpoint: checkpoint.checkpoint().clone(),
                            revision: SafeInteger::new(checkpoint.revision()).map_err(refused)?,
                        })
                {
                    return Err(refused(
                        "checkpoint retirement changed its retained envelope",
                    ));
                }
            }
            TerminalEvidence::Restore { envelope } => {
                let restore =
                    checkpoints::restore_reference_source(tx, self.original.record_key())?
                        .ok_or_else(|| refused("restore retirement source disappeared"))?;
                let terminal = restore
                    .terminal()
                    .ok_or_else(|| refused("uncertain restore custody cannot be retired"))?;
                if restore.active()
                    || envelope != restore.envelope()
                    || self.references.as_slice() != restore.references()
                    || !same_source(terminal, &self.terminal)
                    || self.owner
                        != (ReferenceOwner::CheckpointRestore {
                            scope: restore.scope().clone(),
                            release: restore.release().clone(),
                        })
                {
                    return Err(refused(
                        "restore retirement changed its actual delivery custody",
                    ));
                }
            }
        }
        for (index, reference) in self.references.iter().enumerate() {
            if reference.scope.authority_domain != self.owner.scope().authority_domain
                || reference.scope.tenant_id != self.owner.scope().tenant_id
                || self.references[..index].contains(reference)
            {
                return Err(refused(
                    "reference retirement crossed tenant or repeated a version",
                ));
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
        &self.terminal
    }

    pub(in crate::admission_operation_store) fn verify_original_anchor(
        &self,
        tx: &Transaction<'conn>,
        original: &SourceAnchor,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.verify(tx)?;
        original.verify_historical_identity(tx)?;
        if original.not_after(&SourceAnchor::capture(&self.original)) {
            return Ok(());
        }
        if matches!(self.evidence, TerminalEvidence::Checkpoint { .. }) {
            let checkpoint =
                checkpoints::checkpoint_reference_source(tx, self.original.record_key())?
                    .ok_or_else(|| refused("checkpoint retirement alias disappeared"))?;
            if original.matches_historical_command_payload(tx, &checkpoint.canonical_envelope()?)? {
                return Ok(());
            }
        }
        Err(refused("reference retirement rebound the original owner"))
    }
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

impl std::fmt::Debug for VerifiedKnowledgeReferenceRetirement<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedKnowledgeReferenceRetirement([redacted])")
    }
}

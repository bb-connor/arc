//! Authenticated lifecycle progress may finish under exhausted ordinary intake.
//!
//! One concrete affine type borrows the actual writer transaction, the
//! authenticated actor and the validated installation. Its constructors derive
//! a closed set of one or two exact records from current typed owning records
//! and bind every authority and source head they read. Only the settlement sink
//! consumes it, after rechecking the same writer and rederiving every write.
//! Each write is owed 1:1 by an already admitted owner; it frees no history and
//! finances no native work.
use super::*;
use std::ops::Deref;

#[cfg(feature = "admission-test-support")]
mod test_support;
#[cfg(feature = "admission-test-support")]
pub use test_support::KnowledgeClosureInterference;

const MAX_CLOSURE_WRITES: usize = 2;

pub(in crate::admission_operation_store) struct PreparedKnowledgeClosure<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    actor: &'tx AuthenticatedRecoveryActor,
    profile: &'tx NativeKnowledgeInstallationV1,
    now: u64,
    deployment: protected::ProtectedSourceReference,
    installation: protected::ProtectedSourceReference,
    target: ClosureTarget,
    derivation: Derivation,
}

/// One exact record derived by an owning module from its current typed source.
pub(in crate::admission_operation_store) struct DerivedWrite {
    pub(super) key: String,
    pub(super) scope_key: String,
    pub(super) expected: Option<protected::ProtectedSourceReference>,
    pub(super) payload: Vec<u8>,
}

/// The exact writes plus every other selected source head their derivation
/// read. Each witness must still be the identical head at the sink, so an
/// advanced source refuses even when its projected content is unchanged.
pub(super) struct Derivation {
    writes: Vec<DerivedWrite>,
    witnesses: Vec<protected::ProtectedSourceReference>,
    checkpoint: Option<checkpoints::CheckpointReferenceSource>,
}

impl Derivation {
    pub(super) fn bound(
        writes: Vec<DerivedWrite>,
        witnesses: Vec<protected::ProtectedSourceReference>,
    ) -> Self {
        Self {
            writes,
            witnesses,
            checkpoint: None,
        }
    }
}

/// Selection inputs only. Every key, scope and payload is derived from them.
enum ClosureTarget {
    OperatorPin {
        reference: ArtifactVersionRefV1,
        evidence: EvidenceRef,
    },
    CheckpointRevision {
        checkpoint: CheckpointId,
        revision: u64,
    },
    PublicationRetirement {
        reference: ArtifactVersionRefV1,
    },
    PublicationAbort {
        input: ArtifactPublicationInputV1,
    },
    OrphanSeal {
        input: ArtifactPublicationInputV1,
        seal: ArtifactBlobSealV1,
    },
    CollectionSweep {
        publication: String,
    },
    CollectionAcknowledgment {
        seal: ArtifactBlobSealV1,
    },
    PublicationSlotRefund {
        publication: String,
    },
}

impl<'tx, 'conn> PreparedKnowledgeClosure<'tx, 'conn> {
    /// The actor's own exact Active operator pin becomes its one terminal
    /// record. An already retired pin has no pending closure.
    pub(super) fn operator_pin_retirement(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        reference: &ArtifactVersionRefV1,
        evidence: &EvidenceRef,
        now: u64,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        Self::prepare(
            transaction,
            actor,
            profile,
            now,
            ClosureTarget::OperatorPin {
                reference: reference.clone(),
                evidence: evidence.clone(),
            },
        )
    }

    /// A retained revision without a retirement receives its one retirement
    /// record. An already retired revision has no pending closure.
    pub(super) fn checkpoint_revision_retirement(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        checkpoint: &CheckpointId,
        revision: u64,
        now: u64,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        Self::prepare(
            transaction,
            actor,
            profile,
            now,
            ClosureTarget::CheckpointRevision {
                checkpoint: checkpoint.clone(),
                revision,
            },
        )
    }

    /// An available retained Ephemeral publication without live owners becomes
    /// Retired. An already retired publication has no pending closure.
    pub(super) fn publication_retirement(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        reference: &ArtifactVersionRefV1,
        now: u64,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        Self::prepare(
            transaction,
            actor,
            profile,
            now,
            ClosureTarget::PublicationRetirement {
                reference: reference.clone(),
            },
        )
    }

    /// The actor's own unreachable staging publication becomes Retired.
    pub(super) fn publication_abort(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        input: &ArtifactPublicationInputV1,
        now: u64,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        Self::prepare(
            transaction,
            actor,
            profile,
            now,
            ClosureTarget::PublicationAbort {
                input: input.clone(),
            },
        )
    }

    /// An aborted publication records the exact orphaned object generation as
    /// its own second version. An already recorded seal has no pending write.
    pub(super) fn orphan_seal(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        input: &ArtifactPublicationInputV1,
        seal: &ArtifactBlobSealV1,
        now: u64,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        Self::prepare(
            transaction,
            actor,
            profile,
            now,
            ClosureTarget::OrphanSeal {
                input: input.clone(),
                seal: seal.clone(),
            },
        )
    }

    /// A retired, sealed and unshared publication owns one Sweeping barrier.
    pub(super) fn collection_sweep(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        publication: &str,
        now: u64,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        Self::prepare(
            transaction,
            actor,
            profile,
            now,
            ClosureTarget::CollectionSweep {
                publication: publication.to_owned(),
            },
        )
    }

    /// The host's actual physical collection outcome moves its exact sweep to
    /// Collected. An already collected sweep has no pending write.
    pub(super) fn collection_acknowledgment(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        seal: &ArtifactBlobSealV1,
        now: u64,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        Self::prepare(
            transaction,
            actor,
            profile,
            now,
            ClosureTarget::CollectionAcknowledgment { seal: seal.clone() },
        )
    }

    /// The exact lease and tenant capacity account return one live slot only
    /// after an actual collection acknowledgment and complete reference
    /// closure. An already returned slot has no pending write.
    pub(super) fn publication_slot_refund(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        publication: &str,
        now: u64,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        Self::prepare(
            transaction,
            actor,
            profile,
            now,
            ClosureTarget::PublicationSlotRefund {
                publication: publication.to_owned(),
            },
        )
    }

    fn prepare(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        now: u64,
        target: ClosureTarget,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        let Some(derivation) = derive(transaction, actor, profile, now, &target)? else {
            return Ok(None);
        };
        let scope_key = scope_key(actor.scope())?;
        let closure = Self {
            transaction,
            actor,
            profile,
            now,
            deployment: protected::source_reference(
                transaction,
                &format!("deployment:{scope_key}"),
            )?,
            installation: protected::source_reference(transaction, &profile_key(actor.scope())?)?,
            target,
            derivation,
        };
        closure.verify(transaction)?;
        Ok(Some(closure))
    }

    /// Recheck the same writer, current authority and every bound source, and
    /// rederive every exact write from the current typed owning records.
    pub(in crate::admission_operation_store) fn verify(
        &self,
        transaction: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction), Deref::deref(transaction)) {
            return Err(invariant("knowledge closure changed its physical writer"));
        }
        let now = schema::authority_validation_time(transaction, self.now)?;
        let deployment = protected::deployment_tx(transaction, self.actor.scope())?;
        super::super::recovery::verify_actor(transaction, self.actor, &deployment, now)?;
        let current = installation(transaction, self.actor.scope())?;
        validate_installation(transaction, &deployment, &current)?;
        if self.actor.permission() != RecoveryPermission::KnowledgeAdmin
            || protected::encode(&current)? != protected::encode(self.profile)?
        {
            return Err(invariant("knowledge closure lost its current installation"));
        }
        let scope = scope_key(self.actor.scope())?;
        if self.deployment.record_key() != format!("deployment:{scope}")
            || self.installation.record_key() != profile_key(self.actor.scope())?
        {
            return Err(invariant("knowledge closure changed its authority sources"));
        }
        protected::verify_source_reference(transaction, &self.deployment)?;
        protected::verify_source_reference(transaction, &self.installation)?;
        let derived = derive(
            transaction,
            self.actor,
            self.profile,
            self.now,
            &self.target,
        )?
        .ok_or_else(|| invariant("knowledge closure has no pending source"))?;
        let bound = |expected: &protected::ProtectedSourceReference,
                     current: &protected::ProtectedSourceReference|
         -> Result<(), AdmissionOperationStoreError> {
            protected::verify_source_reference(transaction, expected)?;
            if expected.record_key() != current.record_key()
                || expected.version() != current.version()
            {
                return Err(invariant("knowledge closure changed its bound source"));
            }
            Ok(())
        };
        let stored = &self.derivation;
        if stored.witnesses.len() != derived.witnesses.len()
            || stored.writes.len() != derived.writes.len()
            || stored.checkpoint.is_some() != derived.checkpoint.is_some()
        {
            return Err(invariant("knowledge closure changed its bound source"));
        }
        for (expected, current) in stored.witnesses.iter().zip(&derived.witnesses) {
            bound(expected, current)?;
        }
        if let (Some(expected), Some(current)) = (&stored.checkpoint, &derived.checkpoint) {
            bound(expected.source(), current.source())?;
        }
        for (expected, current) in stored.writes.iter().zip(&derived.writes) {
            match (&expected.expected, &current.expected) {
                (Some(expected), Some(current)) => bound(expected, current)?,
                (None, None) => {}
                _ => return Err(invariant("knowledge closure changed its bound source")),
            }
            if expected.key != current.key
                || expected.scope_key != current.scope_key
                || expected.payload != current.payload
            {
                return Err(invariant("knowledge closure changed its derived terminal"));
            }
        }
        let mut keys = std::collections::BTreeSet::new();
        if stored.writes.is_empty()
            || stored.writes.len() > MAX_CLOSURE_WRITES
            || !stored.writes.iter().all(|write| keys.insert(&write.key))
        {
            return Err(invariant("knowledge closure exceeds its closed write set"));
        }
        Ok(())
    }

    /// Persist the writes through the settlement sink, then retire exactly the
    /// reference custody a terminal head closes through the existing
    /// authenticated reference retirement and refund transaction.
    pub(super) fn settle(
        self,
        transaction: &'tx Transaction<'conn>,
        owner: &SqliteServingOwner,
    ) -> Result<(), AdmissionOperationStoreError> {
        let custody = match &self.target {
            ClosureTarget::OperatorPin { .. } => Custody::OperatorPin(self.write_key(0)?),
            ClosureTarget::CheckpointRevision { .. } => Custody::Checkpoint(
                self.derivation
                    .checkpoint
                    .as_ref()
                    .ok_or_else(|| invariant("knowledge closure lost its checkpoint source"))?
                    .source()
                    .record_key()
                    .to_owned(),
            ),
            ClosureTarget::PublicationRetirement { .. }
            | ClosureTarget::PublicationAbort { .. } => Custody::Publication(self.write_key(0)?),
            ClosureTarget::OrphanSeal { .. }
            | ClosureTarget::CollectionSweep { .. }
            | ClosureTarget::CollectionAcknowledgment { .. }
            | ClosureTarget::PublicationSlotRefund { .. } => Custody::None,
        };
        let (written, _) = protected::persist_knowledge_closure(transaction, owner, self)?;
        let terminal = written
            .first()
            .ok_or_else(|| invariant("knowledge closure wrote no terminal"))?;
        let proof = match custody {
            Custody::None => return Ok(()),
            Custody::OperatorPin(key) => {
                reference_retirement::VerifiedKnowledgeReferenceRetirement::operator_pin(
                    transaction,
                    &key,
                )?
            }
            Custody::Checkpoint(key) => {
                reference_retirement::VerifiedKnowledgeReferenceRetirement::checkpoint(
                    transaction,
                    &key,
                )?
            }
            Custody::Publication(key) => {
                let record: NativeArtifactRecordV1 = load(transaction, &key)?
                    .ok_or_else(|| invariant("knowledge closure publication disappeared"))?;
                Some(
                    reference_retirement::VerifiedKnowledgeReferenceRetirement::publication_dependencies(
                        transaction,
                        &record,
                    )?,
                )
            }
        }
        .ok_or_else(|| invariant("knowledge closure terminal has no reference retirement"))?;
        require_terminal_head(proof.source(), terminal)?;
        protected::persist_knowledge_reference_retirement(transaction, owner, proof)?;
        Ok(())
    }

    fn write_key(&self, index: usize) -> Result<String, AdmissionOperationStoreError> {
        self.derivation
            .writes
            .get(index)
            .map(|write| write.key.clone())
            .ok_or_else(|| invariant("knowledge closure lost its derived terminal"))
    }

    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.transaction
    }
    pub(in crate::admission_operation_store) fn scope(&self) -> &RecoveryScopeV1 {
        self.actor.scope()
    }
    pub(in crate::admission_operation_store) fn writes(&self) -> &[DerivedWrite] {
        &self.derivation.writes
    }
}

impl DerivedWrite {
    pub(in crate::admission_operation_store) fn key(&self) -> &str {
        &self.key
    }
    pub(in crate::admission_operation_store) fn scope_key(&self) -> &str {
        &self.scope_key
    }
    pub(in crate::admission_operation_store) fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// The current pending head a write replaces, or none for a new record.
    pub(in crate::admission_operation_store) fn expected(
        &self,
    ) -> Option<&protected::ProtectedSourceReference> {
        self.expected.as_ref()
    }
}

enum Custody {
    None,
    OperatorPin(String),
    Checkpoint(String),
    Publication(String),
}

/// A reference refund must name the exact terminal head the sink just wrote.
pub(super) fn require_terminal_head(
    retired: &protected::ProtectedSourceReference,
    terminal: &protected::ProtectedSourceReference,
) -> Result<(), AdmissionOperationStoreError> {
    if retired.record_key() != terminal.record_key()
        || retired.version() != terminal.version()
        || retired.event_sequence() != terminal.event_sequence()
        || retired.global_commit_sequence() != terminal.global_commit_sequence()
    {
        return Err(invariant(
            "knowledge closure refund changed its terminal head",
        ));
    }
    Ok(())
}

impl std::fmt::Debug for PreparedKnowledgeClosure<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedKnowledgeClosure([redacted])")
    }
}

/// The single derivation shared by preparation and verification. None means
/// the target is already in its terminal or requested state.
fn derive(
    transaction: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
    now: u64,
    target: &ClosureTarget,
) -> Result<Option<Derivation>, AdmissionOperationStoreError> {
    let own_scope = || scope_key(actor.scope());
    Ok(match target {
        ClosureTarget::OperatorPin {
            reference,
            evidence,
        } => {
            let publication = operator_pin_publication(transaction, actor, profile, reference)?;
            pins::pending_operator_retirement(
                transaction,
                actor,
                profile,
                reference,
                evidence,
                now,
            )?
            .map(|pending| -> Result<_, AdmissionOperationStoreError> {
                let [index, record] = publication;
                Ok(Derivation {
                    writes: vec![DerivedWrite {
                        key: pending.key,
                        scope_key: own_scope()?,
                        expected: Some(pending.head),
                        payload: pending.successor,
                    }],
                    witnesses: vec![index, record],
                    checkpoint: None,
                })
            })
            .transpose()?
        }
        ClosureTarget::CheckpointRevision {
            checkpoint,
            revision,
        } => checkpoints::pending_revision_retirement(
            transaction,
            actor,
            checkpoint,
            *revision,
            now,
        )?
        .map(|pending| -> Result<_, AdmissionOperationStoreError> {
            Ok(Derivation {
                writes: vec![DerivedWrite {
                    key: pending.key,
                    scope_key: own_scope()?,
                    expected: None,
                    payload: pending.record,
                }],
                witnesses: Vec::new(),
                checkpoint: Some(pending.source),
            })
        })
        .transpose()?,
        ClosureTarget::PublicationRetirement { reference } => {
            lifecycle::pending_publication_retirement(transaction, actor, reference)?
        }
        ClosureTarget::PublicationAbort { input } => {
            lifecycle::pending_publication_abort(transaction, actor, input)?
        }
        ClosureTarget::OrphanSeal { input, seal } => {
            lifecycle::pending_orphan_seal(transaction, actor, profile, input, seal)?
        }
        ClosureTarget::CollectionSweep { publication } => {
            lifecycle::pending_sweep(transaction, actor, profile, publication)?
        }
        ClosureTarget::CollectionAcknowledgment { seal } => {
            lifecycle::pending_collection_acknowledgment(transaction, actor, profile, seal)?
        }
        ClosureTarget::PublicationSlotRefund { publication } => {
            publication_capacity::collection::pending_slot_refund(transaction, actor, publication)?
        }
    })
}

/// The pinned version must name its exact retained publication, visible to
/// this actor. The immutable publication stays available for authority and
/// audience checks after collection, without restoring execution or reads.
fn operator_pin_publication(
    transaction: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
    reference: &ArtifactVersionRefV1,
) -> Result<[protected::ProtectedSourceReference; 2], AdmissionOperationStoreError> {
    let index = version_key(reference)?;
    let key: String = load(transaction, &index)?
        .ok_or_else(|| refused("operator pin retirement version absent"))?;
    let record: NativeArtifactRecordV1 = load(transaction, &key)?
        .ok_or_else(|| refused("operator pin retirement artifact absent"))?;
    if record_publication_key(&record)? != key
        || artifact_version_reference(&record.metadata).map_err(refused)? != *reference
    {
        return Err(refused("operator pin retirement artifact changed"));
    }
    traversal::ensure_audience(transaction, actor, &record.metadata.label)?;
    traversal::ensure_audience(
        transaction,
        actor,
        &source(
            transaction,
            &profile.native_authority,
            &profile.producer_context,
        )?,
    )?;
    Ok([
        protected::source_reference(transaction, &index)?,
        protected::source_reference(transaction, &key)?,
    ])
}

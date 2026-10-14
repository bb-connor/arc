//! Authenticated Knowledge intake under exhaustible ordinary admission.
//!
//! One affine type borrows the actual writer transaction, the authenticated
//! actor and the validated installation. Its constructor derives the closed
//! write set of one intake family from current typed sources and binds every
//! authority and source head it read. Only the intake sink consumes it, after
//! rechecking the same writer and rederiving every write.
use super::closure::DerivedWrite;
use super::release::{handle_key, HandleRecord};
use super::*;
use std::ops::Deref;

/// Selection inputs only. Every key, scope and payload is derived from them.
/// Whole records are boxed so every family selection stays small.
enum KnowledgeIntakeFamily {
    /// A new handle row and the appended index of its version.
    HandleIssue {
        reference: ArtifactVersionRefV1,
        recipient: ArtifactRecipientId,
    },
    /// The signed manifest cited by an Import reservation already charged in
    /// this transaction.
    ImportManifest {
        publication: CommandId,
        manifest: Box<SignedArtifactArchiveManifestV1>,
    },
    /// The origin map of one Available Import publication.
    ImportMap { reference: ArtifactVersionRefV1 },
    /// The pin row of an owner the calling pin writer authenticated.
    PinRetain {
        owner: super::pins::PinOwner,
        reference: ArtifactVersionRefV1,
    },
    /// One new immutable checkpoint revision.
    CheckpointRevision {
        checkpoint: Box<LabeledCheckpointV1>,
    },
    /// The current checkpoint envelope advanced to its retained revision.
    CheckpointCurrent {
        checkpoint: Box<LabeledCheckpointV1>,
    },
    /// The original admission row of one new release.
    ReleaseAdmission {
        request: RequestId,
        record: Box<super::release::ReleaseRecord>,
    },
    /// One lawful nonterminal transition of a reserved publication.
    PublicationProgress { record: Box<NativeArtifactRecordV1> },
    /// The storage location of one Available publication.
    PublicationMove {
        reference: ArtifactVersionRefV1,
        location: ProtectedText<128>,
    },
}

impl KnowledgeIntakeFamily {
    /// The closed write count of each family. Publication progress writes its
    /// record, preceded on metadata commitment by the version pointer and the
    /// spent certificate; every other family has one exact count.
    fn closed(&self, writes: usize) -> bool {
        match self {
            Self::HandleIssue { .. } => writes == 2,
            Self::PublicationProgress { .. } => {
                (1..=super::publication::intake::MAX_PROGRESS_WRITES).contains(&writes)
            }
            Self::ImportManifest { .. }
            | Self::ImportMap { .. }
            | Self::PinRetain { .. }
            | Self::CheckpointRevision { .. }
            | Self::CheckpointCurrent { .. }
            | Self::ReleaseAdmission { .. }
            | Self::PublicationMove { .. } => writes == 1,
        }
    }
}

pub(in crate::admission_operation_store) struct AuthenticatedKnowledgeIntakeSource<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    actor: &'tx AuthenticatedRecoveryActor,
    profile: &'tx NativeKnowledgeInstallationV1,
    now: u64,
    family: KnowledgeIntakeFamily,
    writes: Vec<DerivedWrite>,
    witnesses: Vec<protected::ProtectedSourceReference>,
}

type Pending = (Vec<DerivedWrite>, Vec<protected::ProtectedSourceReference>);

/// The pending writes and bound source heads of one intake, none for an exact
/// replay, and the handle a handle issue returns either way.
struct Derived {
    handle: Option<ArtifactHandleV1>,
    pending: Option<Pending>,
}

impl<'tx, 'conn> AuthenticatedKnowledgeIntakeSource<'tx, 'conn> {
    /// An exact admitted identity derives no write. A new identity derives its
    /// handle row and the appended index of its version, bound to the current
    /// deployment, installation, handle baseline, version, publication and the
    /// publication's live slot in its (authority, tenant) account.
    pub(super) fn handle_issue(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        now: u64,
        reference: &ArtifactVersionRefV1,
        recipient: &ArtifactRecipientId,
    ) -> Result<(ArtifactHandleV1, Option<Self>), AdmissionOperationStoreError> {
        let family = KnowledgeIntakeFamily::HandleIssue {
            reference: reference.clone(),
            recipient: recipient.clone(),
        };
        let (derived, source) = Self::prepare(transaction, actor, profile, now, family)?;
        let handle = derived.ok_or_else(|| invariant("handle issue derived no handle"))?;
        Ok((handle, source))
    }

    /// The signed manifest an Import reservation cites, persisted only after
    /// that reservation is admitted and charged to its live slot in this same
    /// transaction. Root, signature, scope, complete ordered DAG and native
    /// provenance are authenticated before any write; the retained exact
    /// manifest is a replay with no write, and any other retained bytes refuse.
    pub(super) fn import_manifest(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        now: u64,
        publication: &CommandId,
        manifest: &SignedArtifactArchiveManifestV1,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        let family = KnowledgeIntakeFamily::ImportManifest {
            publication: publication.clone(),
            manifest: Box::new(manifest.clone()),
        };
        Ok(Self::prepare(transaction, actor, profile, now, family)?.1)
    }

    /// The origin map of one Available Import publication, derived only from
    /// its stored producer and its actual reference. The exact retained map is
    /// a replay with no write; a map to any other version refuses.
    pub(super) fn import_map(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        now: u64,
        reference: &ArtifactVersionRefV1,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        let family = KnowledgeIntakeFamily::ImportMap {
            reference: reference.clone(),
        };
        Ok(Self::prepare(transaction, actor, profile, now, family)?.1)
    }

    /// The pin of an owner the calling pin writer has authenticated in this
    /// transaction, charged by that writer to its tenant reference account.
    /// The exact retained pin is a replay with no write.
    pub(super) fn pin_retain(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        now: u64,
        owner: &super::pins::PinOwner,
        reference: &ArtifactVersionRefV1,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        let family = KnowledgeIntakeFamily::PinRetain {
            owner: owner.clone(),
            reference: reference.clone(),
        };
        Ok(Self::prepare(transaction, actor, profile, now, family)?.1)
    }

    /// One new immutable revision. A retired revision or the exact retained
    /// revision derives no write; any other retained envelope refuses.
    pub(super) fn checkpoint_revision(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        now: u64,
        checkpoint: &LabeledCheckpointV1,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        let family = KnowledgeIntakeFamily::CheckpointRevision {
            checkpoint: Box::new(checkpoint.clone()),
        };
        Ok(Self::prepare(transaction, actor, profile, now, family)?.1)
    }

    /// The current envelope advanced to a newer retained revision, bound to the
    /// exact current head.
    pub(super) fn checkpoint_current(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        now: u64,
        checkpoint: &LabeledCheckpointV1,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        let family = KnowledgeIntakeFamily::CheckpointCurrent {
            checkpoint: Box::new(checkpoint.clone()),
        };
        Ok(Self::prepare(transaction, actor, profile, now, family)?.1)
    }

    /// The original admission of one new release by the actor's own indexed
    /// handle. Callers return a retained release before this point.
    pub(super) fn release_admission(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        now: u64,
        request: &RequestId,
        record: &super::release::ReleaseRecord,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let family = KnowledgeIntakeFamily::ReleaseAdmission {
            request: request.clone(),
            record: Box::new(record.clone()),
        };
        Self::prepare(transaction, actor, profile, now, family)?
            .1
            .ok_or_else(|| invariant("release admission derived no write"))
    }

    /// One lawful transition of a reserved publication, derived from its
    /// stored parent, the transition rules and its live slot.
    pub(super) fn publication_progress(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        now: u64,
        record: &NativeArtifactRecordV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let family = KnowledgeIntakeFamily::PublicationProgress {
            record: Box::new(record.clone()),
        };
        Self::prepare(transaction, actor, profile, now, family)?
            .1
            .ok_or_else(|| invariant("publication progress derived no write"))
    }

    /// The new storage location of one Available publication in its live
    /// slot. The exact current location is a replay with no write.
    pub(super) fn publication_move(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        now: u64,
        reference: &ArtifactVersionRefV1,
        location: &ProtectedText<128>,
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        let family = KnowledgeIntakeFamily::PublicationMove {
            reference: reference.clone(),
            location: location.clone(),
        };
        Ok(Self::prepare(transaction, actor, profile, now, family)?.1)
    }

    fn prepare(
        transaction: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &'tx NativeKnowledgeInstallationV1,
        now: u64,
        family: KnowledgeIntakeFamily,
    ) -> Result<(Option<ArtifactHandleV1>, Option<Self>), AdmissionOperationStoreError> {
        let derived = derive(transaction, actor, profile, &family)?;
        let Some((writes, witnesses)) = derived.pending else {
            return Ok((derived.handle, None));
        };
        let source = Self {
            transaction,
            actor,
            profile,
            now,
            family,
            writes,
            witnesses,
        };
        source.verify(transaction)?;
        Ok((derived.handle, Some(source)))
    }

    /// Recheck the same writer, current authority and every bound source, and
    /// rederive every exact write from the current typed owning records.
    pub(in crate::admission_operation_store) fn verify(
        &self,
        transaction: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction), Deref::deref(transaction)) {
            return Err(invariant("knowledge intake changed its physical writer"));
        }
        let now = schema::authority_validation_time(transaction, self.now)?;
        let deployment = protected::deployment_tx(transaction, self.actor.scope())?;
        super::super::recovery::verify_actor(transaction, self.actor, &deployment, now)?;
        let current = installation(transaction, self.actor.scope())?;
        validate_installation(transaction, &deployment, &current)?;
        if protected::encode(&current)? != protected::encode(self.profile)? {
            return Err(invariant("knowledge intake lost its current installation"));
        }
        let (writes, witnesses) = derive(transaction, self.actor, self.profile, &self.family)?
            .pending
            .ok_or_else(|| invariant("knowledge intake has no pending source"))?;
        let bound = |expected: &protected::ProtectedSourceReference,
                     current: &protected::ProtectedSourceReference|
         -> Result<(), AdmissionOperationStoreError> {
            protected::verify_source_reference(transaction, expected)?;
            if expected.record_key() != current.record_key()
                || expected.version() != current.version()
            {
                return Err(invariant("knowledge intake changed its bound source"));
            }
            Ok(())
        };
        if self.witnesses.len() != witnesses.len() || self.writes.len() != writes.len() {
            return Err(invariant("knowledge intake changed its bound source"));
        }
        for (expected, current) in self.witnesses.iter().zip(&witnesses) {
            bound(expected, current)?;
        }
        for (expected, current) in self.writes.iter().zip(&writes) {
            match (&expected.expected, &current.expected) {
                (Some(expected), Some(current)) => bound(expected, current)?,
                (None, None) => {}
                _ => return Err(invariant("knowledge intake changed its bound source")),
            }
            if expected.key != current.key
                || expected.scope_key != current.scope_key
                || expected.payload != current.payload
            {
                return Err(invariant("knowledge intake changed its derived write"));
            }
        }
        let mut keys = std::collections::BTreeSet::new();
        if !self.family.closed(self.writes.len())
            || !self.writes.iter().all(|write| keys.insert(&write.key))
        {
            return Err(invariant("knowledge intake exceeds its closed write set"));
        }
        Ok(())
    }

    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.transaction
    }
    pub(in crate::admission_operation_store) fn scope(&self) -> &RecoveryScopeV1 {
        self.actor.scope()
    }
    pub(in crate::admission_operation_store) fn writes(&self) -> &[DerivedWrite] {
        &self.writes
    }
}

/// The current deployment and installation heads every intake binds.
fn authority_heads(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
) -> Result<Vec<protected::ProtectedSourceReference>, AdmissionOperationStoreError> {
    Ok(vec![
        protected::source_reference(tx, &format!("deployment:{}", scope_key(actor.scope())?))?,
        protected::source_reference(tx, &profile_key(actor.scope())?)?,
    ])
}

fn derive(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
    family: &KnowledgeIntakeFamily,
) -> Result<Derived, AdmissionOperationStoreError> {
    match family {
        KnowledgeIntakeFamily::HandleIssue {
            reference,
            recipient,
        } => handle_issue(tx, actor, profile, reference, recipient),
        KnowledgeIntakeFamily::ImportManifest {
            publication,
            manifest,
        } => Ok(Derived {
            handle: None,
            pending: import_manifest(tx, actor, profile, publication, manifest)?,
        }),
        KnowledgeIntakeFamily::ImportMap { reference } => Ok(Derived {
            handle: None,
            pending: import_map(tx, actor, reference)?,
        }),
        KnowledgeIntakeFamily::PinRetain { owner, reference } => Ok(Derived {
            handle: None,
            pending: pin_retain(tx, actor, owner, reference)?,
        }),
        KnowledgeIntakeFamily::CheckpointRevision { checkpoint } => Ok(Derived {
            handle: None,
            pending: super::checkpoints::derive_revision(tx, checkpoint)?
                .map(|write| -> Result<Pending, AdmissionOperationStoreError> {
                    Ok((vec![write], authority_heads(tx, actor)?))
                })
                .transpose()?,
        }),
        KnowledgeIntakeFamily::CheckpointCurrent { checkpoint } => Ok(Derived {
            handle: None,
            pending: super::checkpoints::derive_current(tx, checkpoint)?
                .map(
                    |(write, revision)| -> Result<Pending, AdmissionOperationStoreError> {
                        let mut witnesses = authority_heads(tx, actor)?;
                        witnesses.push(revision);
                        Ok((vec![write], witnesses))
                    },
                )
                .transpose()?,
        }),
        KnowledgeIntakeFamily::ReleaseAdmission { request, record } => {
            let (write, sources) = super::release::derive_admission(tx, actor, request, record)?;
            let mut witnesses = authority_heads(tx, actor)?;
            witnesses.extend(sources);
            Ok(Derived {
                handle: None,
                pending: Some((vec![write], witnesses)),
            })
        }
        KnowledgeIntakeFamily::PublicationProgress { record } => {
            let (writes, sources) = super::publication::intake::progress(tx, actor, record)?;
            let mut witnesses = authority_heads(tx, actor)?;
            witnesses.extend(sources);
            Ok(Derived {
                handle: None,
                pending: Some((writes, witnesses)),
            })
        }
        KnowledgeIntakeFamily::PublicationMove {
            reference,
            location,
        } => Ok(Derived {
            handle: None,
            pending: publication_move(tx, actor, reference, location)?,
        }),
    }
}

fn pin_retain(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    owner: &super::pins::PinOwner,
    reference: &ArtifactVersionRefV1,
) -> Result<Option<Pending>, AdmissionOperationStoreError> {
    let Some(write) = super::pins::derive_retain(tx, actor.scope(), owner, reference)? else {
        return Ok(None);
    };
    let version = artifact(tx, reference)?;
    let mut witnesses = authority_heads(tx, actor)?;
    witnesses.extend([
        protected::source_reference(tx, &version_key(reference)?)?,
        protected::source_reference(tx, &record_publication_key(&version)?)?,
    ]);
    Ok(Some((vec![write], witnesses)))
}

fn handle_issue(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
    reference: &ArtifactVersionRefV1,
    recipient: &ArtifactRecipientId,
) -> Result<Derived, AdmissionOperationStoreError> {
    let (record, version) =
        super::release::derive_handle(tx, actor, profile, reference, recipient)?;
    let key = handle_key(actor.scope(), &record.handle.handle)?;
    let index = super::handle_index::current(tx, reference)?;
    if let Some(existing) = load::<HandleRecord>(tx, &key)? {
        if existing != record || !index.admits(tx, &existing)? {
            return Err(refused("handle identity changed"));
        }
        return Ok(Derived {
            handle: Some(record.handle),
            pending: None,
        });
    }
    super::publication_capacity::validate_existing_allocation(tx, &version)?;
    let scope = scope_key(actor.scope())?;
    let mut witnesses = authority_heads(tx, actor)?;
    witnesses.extend([
        protected::source_reference(
            tx,
            &super::handle_index::baseline_key(actor.scope().authority_domain.as_str()),
        )?,
        protected::source_reference(tx, &version_key(reference)?)?,
        protected::source_reference(tx, &record_publication_key(&version)?)?,
        super::publication_capacity::retained_allocation_source(tx, &version)?,
    ]);
    let index_payload = index.appended(&record.handle.handle)?;
    let writes = vec![
        DerivedWrite {
            key,
            scope_key: scope.clone(),
            expected: None,
            payload: protected::encode(&record)?,
        },
        DerivedWrite {
            key: super::handle_index::index_key(reference)?,
            scope_key: scope,
            expected: index.into_source(),
            payload: index_payload,
        },
    ];
    Ok(Derived {
        handle: Some(record.handle),
        pending: Some((writes, witnesses)),
    })
}

fn import_manifest(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
    publication: &CommandId,
    manifest: &SignedArtifactArchiveManifestV1,
) -> Result<Option<Pending>, AdmissionOperationStoreError> {
    if actor.permission() != RecoveryPermission::KnowledgeWrite {
        return Err(refused("import manifest authority"));
    }
    let key = publication_key(actor.scope(), actor.principal(), publication)?;
    let record: NativeArtifactRecordV1 =
        load(tx, &key)?.ok_or_else(|| refused("import reservation absent"))?;
    let ArtifactProducerV1::Import {
        manifest: cited, ..
    } = &record.input.producer
    else {
        return Err(refused("import reservation producer"));
    };
    if record_publication_key(&record)? != key
        || record.metadata.scope != *actor.scope()
        || record.publication_principal != *actor.principal()
        || record.metadata.producer != record.input.producer
    {
        return Err(refused("import reservation identity"));
    }
    // The citing publication's live slot is already charged in this account.
    super::publication_capacity::validate_existing_allocation(tx, &record)?;
    if super::transfer::authenticate_import_manifest(tx, profile, manifest)? != *cited {
        return Err(refused("import manifest citation"));
    }
    let manifest_key = super::transfer::manifest_key(actor.scope(), *cited)?;
    match load::<SignedArtifactArchiveManifestV1>(tx, &manifest_key)? {
        Some(retained) if retained == *manifest => return Ok(None),
        Some(_) => return Err(refused("import manifest identity")),
        None => {}
    }
    let mut witnesses = authority_heads(tx, actor)?;
    witnesses.extend([
        protected::source_reference(tx, &key)?,
        super::publication_capacity::retained_allocation_source(tx, &record)?,
    ]);
    Ok(Some((
        vec![DerivedWrite {
            key: manifest_key,
            scope_key: scope_key(actor.scope())?,
            expected: None,
            payload: protected::encode(manifest)?,
        }],
        witnesses,
    )))
}

fn import_map(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    reference: &ArtifactVersionRefV1,
) -> Result<Option<Pending>, AdmissionOperationStoreError> {
    if actor.permission() != RecoveryPermission::KnowledgeWrite || reference.scope != *actor.scope()
    {
        return Err(refused("import map authority"));
    }
    let record = artifact(tx, reference)?;
    let ArtifactProducerV1::Import { manifest, origin } = &record.metadata.producer else {
        return Err(refused("import map producer"));
    };
    if record.publication_principal != *actor.principal() {
        return Err(refused("import map publication"));
    }
    let key = super::transfer::map_key(&record.metadata.scope, *manifest, origin)?;
    match load::<ArtifactVersionRefV1>(tx, &key)? {
        Some(mapped) if mapped == *reference => return Ok(None),
        Some(_) => return Err(refused("import map identity")),
        None => {}
    }
    super::publication_capacity::validate_existing_allocation(tx, &record)?;
    let mut witnesses = authority_heads(tx, actor)?;
    witnesses.extend([
        protected::source_reference(
            tx,
            &super::transfer::manifest_key(&record.metadata.scope, *manifest)?,
        )?,
        protected::source_reference(tx, &version_key(reference)?)?,
        protected::source_reference(tx, &record_publication_key(&record)?)?,
        super::publication_capacity::retained_allocation_source(tx, &record)?,
    ]);
    Ok(Some((
        vec![DerivedWrite {
            key,
            scope_key: scope_key(actor.scope())?,
            expected: None,
            payload: protected::encode(reference)?,
        }],
        witnesses,
    )))
}

fn publication_move(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    reference: &ArtifactVersionRefV1,
    location: &ProtectedText<128>,
) -> Result<Option<Pending>, AdmissionOperationStoreError> {
    if actor.permission() != RecoveryPermission::KnowledgeWrite || reference.scope != *actor.scope()
    {
        return Err(refused("move authority"));
    }
    let mut record = artifact(tx, reference)?;
    if record.location == *location {
        return Ok(None);
    }
    super::publication_capacity::validate_existing_allocation(tx, &record)?;
    let key = record_publication_key(&record)?;
    let current = protected::source_reference(tx, &key)?;
    record.location = location.clone();
    let mut witnesses = authority_heads(tx, actor)?;
    witnesses.extend([
        protected::source_reference(tx, &version_key(reference)?)?,
        super::publication_capacity::retained_allocation_source(tx, &record)?,
    ]);
    Ok(Some((
        vec![DerivedWrite {
            scope_key: scope_key(actor.scope())?,
            payload: protected::encode(&record)?,
            key,
            expected: Some(current),
        }],
        witnesses,
    )))
}

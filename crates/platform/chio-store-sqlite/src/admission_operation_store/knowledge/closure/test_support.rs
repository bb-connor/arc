//! One real prepared closure meets one closed interference, then rolls back.
use super::*;

/// The interference applied between real preparation and the real sink.
pub enum KnowledgeClosureInterference {
    /// Offer the closure through a separate owner-validated deferred writer.
    OtherWriter,
    /// Settle the same pending target through a second real closure first.
    SourceAdvanced,
    /// Install this successor profile through the production profile body first.
    ProfileAdvanced(Box<NativeKnowledgeInstallationV1>),
}

impl SqliteAdmissionOperationStore {
    /// Authenticate and prepare the actual operator pin closure, apply one
    /// interference and offer it to the actual sink. Every outcome rolls back;
    /// an accepted closure is reported as an invariant failure.
    pub fn attempt_operator_pin_closure_for_test(
        &self,
        actor: &AuthenticatedRecoveryActor,
        reference: &ArtifactVersionRefV1,
        evidence: &EvidenceRef,
        interference: KnowledgeClosureInterference,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeAdmin
            || reference.scope != *actor.scope()
        {
            return Err(refused("operator pin retirement authority"));
        }
        mutate_retained_admin(self, actor, fence, now, |tx, profile, now| {
            let prepare = || {
                PreparedKnowledgeClosure::operator_pin_retirement(
                    &tx, actor, profile, reference, evidence, now,
                )?
                .ok_or_else(|| invariant("knowledge closure interference has no pending pin"))
            };
            interfere(self, &tx, prepare()?, interference, prepare)?;
            Err(invariant("knowledge closure interference was accepted"))
        })
    }

    /// The checkpoint revision counterpart of the operator pin interference.
    pub fn attempt_checkpoint_closure_for_test(
        &self,
        actor: &AuthenticatedRecoveryActor,
        checkpoint: &CheckpointId,
        revision: u64,
        interference: KnowledgeClosureInterference,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeAdmin || revision == 0 {
            return Err(refused("checkpoint retirement authority"));
        }
        mutate_retained_admin(self, actor, fence, now, |tx, profile, now| {
            let prepare = || {
                PreparedKnowledgeClosure::checkpoint_revision_retirement(
                    &tx, actor, profile, checkpoint, revision, now,
                )?
                .ok_or_else(|| invariant("knowledge closure interference has no pending revision"))
            };
            interfere(self, &tx, prepare()?, interference, prepare)?;
            Err(invariant("knowledge closure interference was accepted"))
        })
    }
}

impl SqliteAdmissionOperationStore {
    /// The publication retirement counterpart of the operator pin interference.
    pub fn attempt_publication_retirement_closure_for_test(
        &self,
        actor: &AuthenticatedRecoveryActor,
        reference: &ArtifactVersionRefV1,
        interference: KnowledgeClosureInterference,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeAdmin
            || reference.scope != *actor.scope()
        {
            return Err(refused("retention authority"));
        }
        mutate_retained_admin(self, actor, fence, now, |tx, profile, now| {
            let prepare = || {
                PreparedKnowledgeClosure::publication_retirement(
                    &tx, actor, profile, reference, now,
                )?
                .ok_or_else(|| {
                    invariant("knowledge closure interference has no pending publication")
                })
            };
            interfere(self, &tx, prepare()?, interference, prepare)?;
            Err(invariant("knowledge closure interference was accepted"))
        })
    }
}

/// Returns Ok only when the sink accepted the interfered closure.
fn interfere<'tx, 'conn>(
    store: &SqliteAdmissionOperationStore,
    transaction: &'tx Transaction<'conn>,
    closure: PreparedKnowledgeClosure<'tx, 'conn>,
    interference: KnowledgeClosureInterference,
    again: impl FnOnce() -> Result<PreparedKnowledgeClosure<'tx, 'conn>, AdmissionOperationStoreError>,
) -> Result<(), AdmissionOperationStoreError> {
    match interference {
        KnowledgeClosureInterference::OtherWriter => {
            let path = transaction
                .path()
                .ok_or_else(|| invariant("knowledge closure requires a persistent authority"))?;
            let mut connection = Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(sqlite_error)?;
            connection
                .busy_timeout(std::time::Duration::ZERO)
                .map_err(sqlite_error)?;
            let other = store.begin_read(&mut connection)?;
            protected::persist_knowledge_closure(&other, &store.serving_owner, closure)?;
        }
        KnowledgeClosureInterference::SourceAdvanced => {
            protected::persist_knowledge_closure(transaction, &store.serving_owner, again()?)?;
            protected::persist_knowledge_closure(transaction, &store.serving_owner, closure)?;
        }
        KnowledgeClosureInterference::ProfileAdvanced(profile) => {
            validate_knowledge_profile(&store.serving_owner, &profile)?;
            install_knowledge_profile(transaction, &store.serving_owner, &profile)?;
            protected::persist_knowledge_closure(transaction, &store.serving_owner, closure)?;
        }
    }
    Ok(())
}

//! Read-only observer of the authenticated pin reader.
use super::*;

impl SqliteAdmissionOperationStore {
    /// Observe the actual production pin reader in a fresh fenced authority
    /// snapshot. This returns data and exports no source or retirement proof.
    pub fn inspect_retained_artifact_pin_source(
        &self,
        actor: &AuthenticatedRecoveryActor,
        key: &str,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<ArtifactVersionRefV1>, AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeAdmin {
            return Err(refused("pin source inspection authority"));
        }
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(fence))?;
        let now = schema::authority_validation_time(&tx, now)?;
        let deployment = protected::deployment_tx(&tx, actor.scope())?;
        super::super::super::recovery::verify_actor(&tx, actor, &deployment, now)?;
        let profile = installation(&tx, actor.scope())?;
        validate_installation(&tx, &deployment, &profile)?;
        traversal::ensure_audience(
            &tx,
            actor,
            &source(&tx, &profile.native_authority, &profile.producer_context)?,
        )?;
        let row = protected::raw_checked(&tx, key)?
            .ok_or_else(|| refused("pin source inspection absent"))?;
        if !key.starts_with("knowledge-pin:") || row.scope != scope_key(actor.scope())? {
            return Err(refused("pin source inspection scope"));
        }
        let reference = super::reference(&tx, key)?;
        if let Some(reference) = &reference {
            if reference.scope != *actor.scope() {
                return Err(refused("pin source inspection changed reference scope"));
            }
            let record = artifact(&tx, reference)?;
            traversal::ensure_audience(&tx, actor, &record.metadata.label)?;
        }
        let later = schema::authority_validation_time(&tx, now)?;
        super::super::super::recovery::verify_actor(&tx, actor, &deployment, later)?;
        tx.rollback().map_err(sqlite_error)?;
        Ok(reference)
    }
}

//! Real retained source fixtures and a read-only observer of the owning reader.
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

    /// Append a deliberately selected legacy source fixture through the real
    /// protected writer, retaining its record, event and global custody. The
    /// fixture namespace cannot overwrite a genuine confinement or typed pin.
    pub fn append_legacy_artifact_pin_fixture(
        &self,
        actor: &AuthenticatedRecoveryActor,
        key: &str,
        reference: Option<&ArtifactVersionRefV1>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<u64, AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeAdmin
            || !key.starts_with(&format!(
                "knowledge-pin:{}:legacy-custody-reader-",
                scope_key(actor.scope())?
            ))
            || reference.is_some_and(|reference| reference.scope != *actor.scope())
        {
            return Err(refused("legacy pin fixture scope"));
        }
        mutate_retained_admin(self, actor, fence, now, |tx, profile, _| {
            traversal::ensure_audience(
                &tx,
                actor,
                &source(&tx, &profile.native_authority, &profile.producer_context)?,
            )?;
            if let Some(row) = protected::raw_checked(&tx, key)? {
                let previous: Option<ArtifactVersionRefV1> = protected::decode(&row.payload)?;
                protected::source_reference(&tx, key)?;
                if row.kind != "command"
                    || row.scope != scope_key(actor.scope())?
                    || previous.is_some_and(|reference| reference.scope != *actor.scope())
                {
                    return Err(refused("legacy pin fixture original scope"));
                }
            }
            if let Some(reference) = reference {
                let record = artifact(&tx, reference)?;
                traversal::ensure_audience(&tx, actor, &record.metadata.label)?;
            }
            save(
                &tx,
                &self.serving_owner,
                actor.scope(),
                key,
                &reference.cloned(),
            )?;
            let version = protected::source_reference(&tx, key)?.version();
            Ok((tx, version))
        })
    }
}

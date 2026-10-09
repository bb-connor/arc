//! Modeled predecessor sources, never an older executable or synthetic custody.
use super::*;

impl SqliteAdmissionOperationStore {
    /// Retain bounded original legacy checkpoints before first installation.
    /// The caller supplies genuine broker seals and verifies their bytes. This
    /// fixture authenticates the original writer/context and derives all keys,
    /// labels and metadata. It cannot write an index, loan or activation marker.
    pub fn retain_cold_legacy_checkpoint_fixture(
        &self,
        actor: &AuthenticatedRecoveryActor,
        profile: &NativeKnowledgeInstallationV1,
        originals: &[(CheckpointId, ArtifactBlobSealV1)],
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Vec<LabeledCheckpointV1>, AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeWrite
            || actor.scope() != &profile.scope
            || originals.is_empty()
            || originals.len() > 8
        {
            return Err(refused("cold checkpoint fixture scope"));
        }
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(fence))?;
        let now = schema::authority_validation_time(&tx, now)?;
        let deployment = protected::deployment_tx(&tx, actor.scope())?;
        super::super::super::recovery::verify_actor(&tx, actor, &deployment, now)?;
        security_participant_state::verify_recovery_initialization(&tx, &profile.native_authority)?;
        if profile.native_authority != deployment.native_authority
            || profile.policy != deployment.policy_digest
            || profile.contract.as_bytes() != deployment.contract_digest.as_bytes()
            || protected::encode(&profile.producer_context)?
                != protected::encode(&deployment.security_context)?
        {
            return Err(refused("cold checkpoint fixture original context"));
        }
        let occupied: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records
             WHERE scope_key=?1 AND record_key GLOB 'knowledge-*')",
                [scope_key(actor.scope())?],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        let account = super::super::references::ReferenceAccount::from_scope(actor.scope());
        if occupied || protected::raw_checked(&tx, &account.ready_key()?)?.is_some() {
            return Err(refused(
                "cold checkpoint fixture requires an unactivated empty scope",
            ));
        }
        let label = source(&tx, &profile.native_authority, &profile.producer_context)?;
        traversal::ensure_audience(&tx, actor, &label)?;
        let influence = traversal::influence(
            &tx,
            &profile.native_authority,
            &profile.producer_context,
            &[],
            false,
        )?;
        let context = profile.producer_context.as_v1();
        let mut checkpoints = Vec::with_capacity(originals.len());
        for (id, seal) in originals {
            if seal.runtime.as_str() != context.session_id().as_str()
                || seal.process != profile.scope.process_id
                || !super::super::lifecycle::logical_object(seal)
            {
                return Err(refused("cold checkpoint fixture sealed object"));
            }
            let input = ArtifactPublicationInputV1 {
                publication: CommandId::new(id.as_str()).map_err(refused)?,
                producer: ArtifactProducerV1::Checkpoint {
                    checkpoint: id.clone(),
                },
                content: seal.content,
                size_bytes: seal.bytes,
                media_type: ProtectedText::new("application/octet-stream").map_err(refused)?,
                schema: knowledge_content_digest(b"chio.knowledge.opaque-bytes.v1"),
                dependencies: BoundedList::new(vec![]).map_err(refused)?,
                retention: ArtifactRetentionV1::Ephemeral,
            };
            let sequence: i64 = tx
                .query_row(
                    "SELECT COALESCE(max(sequence),0)+1 FROM admission_operation_recovery_events",
                    [],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            let metadata = ArtifactVersionV1 {
                domain_version: VersionV1,
                scope: profile.scope.clone(),
                artifact: ArtifactId::new(seal.object.as_str()).map_err(refused)?,
                version: ArtifactRevisionId::new("original").map_err(refused)?,
                content: input.content,
                size_bytes: input.size_bytes,
                media_type: input.media_type.clone(),
                schema: input.schema,
                producer: input.producer.clone(),
                dependencies: input.dependencies.clone(),
                label: label.clone(),
                influence: influence.clone(),
                lineage: IsolationLineageId::new(context.lineage_root_id().as_str())
                    .map_err(refused)?,
                isolation_epoch: ProtectedText::new(context.isolation_epoch_id().as_str())
                    .map_err(refused)?,
                evidence: BoundedList::new(vec![]).map_err(refused)?,
                policy: profile.policy,
                contract: profile.contract,
                creation_sequence: SafeInteger::new(u64::try_from(sequence).map_err(refused)?)
                    .map_err(refused)?,
                retention: input.retention,
            };
            metadata.validate().map_err(refused)?;
            let reference = artifact_version_reference(&metadata).map_err(refused)?;
            let record = NativeArtifactRecordV1 {
                input,
                metadata: metadata.clone(),
                object: seal.object.clone(),
                seal: Some(seal.clone()),
                state: ArtifactPublicationStateV1::Available,
                installation_generation: profile.generation,
                certificate: None,
                location: ProtectedText::new("private-process-blob").map_err(refused)?,
                publication_principal: None,
            };
            let native_sequence: i64 = tx
                .query_row(
                    "SELECT COALESCE(max(commit_sequence),0) FROM authority_global_commits",
                    [],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            let checkpoint = LabeledCheckpointV1 {
                domain_version: VersionV1,
                checkpoint: id.clone(),
                revision: SafeInteger::new(1).map_err(refused)?,
                scope: profile.scope.clone(),
                runtime: ProtectedText::new(context.session_id().as_str()).map_err(refused)?,
                artifacts: NonEmptyBoundedList::new(vec![reference.clone()]).map_err(refused)?,
                model_contexts: BoundedList::new(vec![]).map_err(refused)?,
                label: label.clone(),
                influence: influence.clone(),
                lineage: metadata.lineage,
                isolation_epoch: metadata.isolation_epoch,
                native_evidence_sequence: SafeInteger::new(
                    u64::try_from(native_sequence).map_err(refused)?,
                )
                .map_err(refused)?,
                policy: profile.policy,
            };
            checkpoint.validate().map_err(refused)?;
            let publication = record_publication_key(&record)?;
            let version = version_key(&reference)?;
            let key = head::legacy_checkpoint_key(actor.scope(), id, 0)?;
            for key in [&publication, &version, &key] {
                if protected::raw_checked(&tx, key)?.is_some() {
                    return Err(refused("cold checkpoint fixture duplicate original"));
                }
            }
            save(
                &tx,
                &self.serving_owner,
                actor.scope(),
                &publication,
                &record,
            )?;
            save(
                &tx,
                &self.serving_owner,
                actor.scope(),
                &version,
                &publication,
            )?;
            save(&tx, &self.serving_owner, actor.scope(), &key, &checkpoint)?;
            checkpoints.push(checkpoint);
        }
        let later = schema::authority_validation_time(&tx, now)?;
        super::super::super::recovery::verify_actor(&tx, actor, &deployment, later)?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)?;
        Ok(checkpoints)
    }
}

impl SqliteAdmissionOperationStore {
    /// Fail only the real checkpoint owner retirement write on this connection.
    /// A TEMP trigger changes no durable schema, authority or protected source.
    pub fn inject_checkpoint_retirement_owner_failure_for_test(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.connection()?.execute_batch(
            "CREATE TEMP TRIGGER fail_checkpoint_owner_retirement BEFORE UPDATE ON main.admission_operation_recovery_records
             WHEN NEW.record_key GLOB 'knowledge-reference-owner:*'
               AND json_extract(NEW.payload,'$.owner.owner')='checkpoint_revision'
               AND json_extract(NEW.payload,'$.state')='retired'
             BEGIN SELECT RAISE(ABORT,'injected checkpoint owner retirement failure'); END;",
        ).map_err(sqlite_error)
    }

    pub fn clear_checkpoint_retirement_owner_failure_for_test(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.connection()?
            .execute_batch("DROP TRIGGER temp.fail_checkpoint_owner_retirement")
            .map_err(sqlite_error)
    }
}

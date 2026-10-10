use super::*;

pub(super) fn private_release_observation(
    fixture: &KnowledgeFixture,
    release: &ReleaseId,
) -> TestResult<ArtifactReleaseIntentV1> {
    let connection = rusqlite::Connection::open(fixture.f.path.join("admission.db"))?;
    let (count, encoded): (i64, Option<String>) = connection.query_row(
        "SELECT count(*),json_extract(payload,'$.release')
         FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-join:*' AND json_extract(payload,'$.release.release')=?1",
        [release.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(
        count, 1,
        "private observation must identify exactly one retained join"
    );
    Ok(serde_json::from_str(
        &encoded.ok_or("private release observation absent")?,
    )?)
}

#[test]
fn artifacts_clearance_reduction_refuses_publication_metadata_and_checkpoint() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let input = f.input("audience-changing", b"pending")?;
    f.runtime.reserve(&f.f.control, &input)?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let reservation = store.reserve_artifact(
        &f.actor(RecoveryPermission::KnowledgeWrite)?,
        &input,
        &fence,
        now_ms()?,
    )?;
    let seal = f
        .broker
        .stage(&reservation.object, &f.profile.scope.process_id, b"pending")?;
    store.stage_artifact(
        &f.actor(RecoveryPermission::KnowledgeWrite)?,
        &input,
        &seal,
        &fence,
        now_ms()?,
    )?;
    let secret = publish_label(&f, "audience-secret", b"secret", restricted_label())?;
    let handle = f.runtime.handle(
        &f.f.control,
        &secret,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    f.runtime.release_into(
        &f.f.control,
        &RequestId::new("audience-observe")?,
        f.runtime.prepare_read(&f.f.control, &handle)?,
        &f.sink(),
    )?;
    let mut deployment = f.f.kernel.recovery_deployment(&f.profile.scope)?;
    let original = deployment.clone();
    let mut actors = deployment.actors.as_slice().to_vec();
    actors[0].preview_clearance = InformationLabel::bottom();
    deployment.actors = NonEmptyBoundedList::new(actors)?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    store.configure_recovery_deployment(&deployment)?;
    let writer = f.actor(RecoveryPermission::KnowledgeWrite)?;
    assert!(store
        .commit_artifact_metadata(&writer, &input, None, &fence, now_ms()?)
        .is_err());
    let collector = f.actor(RecoveryPermission::KnowledgeAdmin)?;
    // The reservation remains public, but collection cannot expose a private
    // retained version or its physical content seal to a reduced audience.
    assert!(store
        .retire_artifact(&collector, &secret, &fence, now_ms()?)
        .is_err());
    assert!(f
        .runtime
        .checkpoint(
            &f.f.control,
            &CheckpointId::new("audience-checkpoint")?,
            0,
            std::slice::from_ref(&secret),
            &[]
        )
        .is_err());
    let state:String=rusqlite::Connection::open(f.f.path.join("admission.db"))?.query_row("SELECT json_extract(payload,'$.state') FROM admission_operation_recovery_records WHERE json_extract(payload,'$.input.publication')=?1",[input.publication.as_str()],|row|row.get(0))?;
    assert_eq!(state, "staged");
    store.configure_recovery_deployment(&original)?;
    let committed = store.commit_artifact_metadata(
        &f.actor(RecoveryPermission::KnowledgeWrite)?,
        &input,
        None,
        &fence,
        now_ms()?,
    )?;
    assert_eq!(committed.metadata.label, restricted_label());
    Ok(())
}

#[test]
fn artifacts_summary_and_dependency_overflow_refuse_missing_paths() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let public = publish_label(&f, "summary-public", b"public", InformationLabel::bottom())?;
    let restricted = publish_label(&f, "summary-secret", b"secret", restricted_label())?;
    let mut input = f.input("summary", b"summary")?;
    input.producer = ArtifactProducerV1::Derivation {
        operation: OperationId::new("summarize")?,
    };
    input.dependencies = BoundedList::new(vec![public.clone(), restricted])?;
    let summary = f.runtime.publish(&f.f.control, &input, b"summary", None)?;
    let actor = f.actor(RecoveryPermission::KnowledgeRead)?;
    let store = f.f.authority.admission_operation_store();
    let inventory = store.artifact_transfer_inventory(
        &actor,
        &summary,
        &f.f.authority.mutation_fence(),
        now_ms()?,
    )?;
    for reference in &inventory {
        assert!(f.metadata(reference)?.influence.externally_influenced);
    }
    assert!(restricted_label().flows_to(&f.metadata(inventory.last().ok_or("summary")?)?.label));
    let mut missing = public.clone();
    missing.version = ArtifactRevisionId::new("missing-version")?;
    input.publication = CommandId::new("missing-dependency")?;
    input.dependencies = BoundedList::new(vec![missing])?;
    assert!(f.runtime.reserve(&f.f.control, &input).is_err());
    assert!(BoundedList::<ArtifactVersionRefV1, 16>::new(vec![public; 17]).is_err());
    let mut last = None;
    for index in 0..=MAX_ARTIFACT_TRAVERSAL {
        let key = format!("bounded-chain-{index}");
        let mut input = f.input(&key, b"chain")?;
        input.dependencies = BoundedList::new(last.iter().cloned().collect())?;
        last = Some(f.runtime.publish(&f.f.control, &input, b"chain", None)?);
    }
    let mut overflow = f.input("chain-overflow", b"chain")?;
    overflow.dependencies = BoundedList::new(last.into_iter().collect())?;
    assert!(f.runtime.reserve(&f.f.control, &overflow).is_err());
    Ok(())
}
#[test]
fn artifacts_delayed_collection_cannot_delete_a_new_storage_generation() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let old = f.publish("gc-old", b"equal-again")?;
    let actor = f.actor(RecoveryPermission::KnowledgeAdmin)?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let seal = store
        .retire_artifact(&actor, &old, &fence, now_ms()?)?
        .ok_or("sweep")?;
    let delayed = store
        .retire_artifact(&actor, &old, &fence, now_ms()?)?
        .ok_or("second collector")?;
    f.broker.collect_private(&seal)?;
    store.finish_artifact_collection(&actor, &seal, &fence, now_ms()?)?;
    let new = f.publish("gc-new", b"equal-again")?;
    f.broker.collect_private(&delayed)?;
    assert!(store
        .retire_artifact(&actor, &old, &fence, now_ms()?)?
        .is_none());
    let handle = f
        .runtime
        .handle(&f.f.control, &new, &ArtifactRecipientId::new("agent-root")?)?;
    assert!(f.runtime.prepare_read(&f.f.control, &handle).is_ok());
    let replacement = store
        .retire_artifact(&actor, &new, &fence, now_ms()?)?
        .ok_or("replacement sweep")?;
    assert_ne!(replacement.generation, seal.generation);
    assert!(store
        .finish_artifact_collection(&actor, &seal, &fence, now_ms()?)
        .is_err());
    f.broker.collect_private(&replacement)?;
    store.finish_artifact_collection(&actor, &replacement, &fence, now_ms()?)?;
    Ok(())
}
#[test]
fn artifacts_unreachable_staging_is_collected_without_identity_reuse() -> TestResult {
    for stage in [
        KnowledgeCutpoint::Reserved,
        KnowledgeCutpoint::BlobStaged,
        KnowledgeCutpoint::StageRetained,
        KnowledgeCutpoint::MetadataCommitted,
    ] {
        let f = KnowledgeFixture::new()?;
        let input = f.input("orphan", b"orphan")?;
        let faulty = f
            .runtime
            .clone()
            .with_test_cutpoint(Arc::new(move |actual| {
                if actual == stage {
                    Err(KernelError::Internal("lost acknowledgement".into()))
                } else {
                    Ok(())
                }
            }));
        assert!(faulty
            .publish(&f.f.control, &input, b"orphan", None)
            .is_err());
        f.runtime.abort_publication(&f.f.control, &input)?;
        f.runtime.abort_publication(&f.f.control, &input)?;
        assert!(f
            .runtime
            .publish(&f.f.control, &input, b"orphan", None)
            .is_err());
        let count: i64 = rusqlite::Connection::open(f.f.path.join("process.db"))?.query_row(
            "SELECT count(*) FROM process_artifact_objects WHERE data IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(count, 0);
    }
    Ok(())
}
#[test]
fn memory_model_context_and_side_files_remain_bound_on_restore() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let root = publish_label(
        &f,
        "model-public",
        b"transcript",
        InformationLabel::bottom(),
    )?;
    let secret = publish_label(&f, "model-side", b"side-file-canary", restricted_label())?;
    let context = ModelContextV1 {
        context: ModelContextId::new("model-context")?,
        provider: ProviderId::new("provider")?,
        account: ProviderAccountId::new("account")?,
        conversation: ProtectedText::new("conversation")?,
        cache: ProtectedText::new("cache")?,
        side_files: BoundedList::new(vec![secret])?,
        contract: f.profile.contract,
    };
    let mut profile = f.profile.clone();
    let mut entry = profile.recipients.as_slice()[0].clone();
    entry.recipient.recipient = ArtifactRecipientId::new("model")?;
    entry.recipient.sink = ArtifactSinkV1::Model {
        context: context.clone(),
    };
    profile.recipients = NonEmptyBoundedList::new(vec![
        profile.recipients.as_slice()[0].clone(),
        entry.clone(),
    ])?;
    profile.generation = SafeInteger::new(2)?;
    let store = f.f.authority.admission_operation_store();
    store.configure_knowledge(&profile)?;
    let checkpoint = f.runtime.checkpoint(
        &f.f.control,
        &CheckpointId::new("model-memory")?,
        0,
        std::slice::from_ref(&root),
        std::slice::from_ref(&context),
    )?;
    assert!(restricted_label().flows_to(&checkpoint.label));
    let sink = RecordingSink {
        recipient: entry.recipient,
        delivered: Mutex::new(vec![]),
        path: f.f.path.join("admission.db"),
    };
    let intent = f.runtime.restore_into(
        &f.f.control,
        &checkpoint.checkpoint,
        1,
        &RequestId::new("model-restore")?,
        &sink,
    )?;
    assert!(
        private_release_observation(&f, &intent.release)?
            .influence
            .externally_influenced
    );
    assert!(sink
        .delivered
        .lock()
        .map_err(|_| "sink")?
        .first()
        .ok_or("restore")?
        .windows(b"side-file-canary".len())
        .any(|bytes| bytes == b"side-file-canary"));
    for (index, field) in [
        "provider",
        "account",
        "conversation",
        "cache",
        "side_files",
        "contract",
    ]
    .into_iter()
    .enumerate()
    {
        let mut changed = context.clone();
        match field {
            "provider" => changed.provider = ProviderId::new("other-provider")?,
            "account" => changed.account = ProviderAccountId::new("other-account")?,
            "conversation" => changed.conversation = ProtectedText::new("other-conversation")?,
            "cache" => changed.cache = ProtectedText::new("other-cache")?,
            "side_files" => changed.side_files = BoundedList::new(vec![])?,
            _ => changed.contract = ContractDigest::from_bytes([19; 32]),
        }
        let mut recipients = profile.recipients.as_slice().to_vec();
        recipients[1].recipient.sink = ArtifactSinkV1::Model { context: changed };
        profile.recipients = NonEmptyBoundedList::new(recipients)?;
        profile.generation = SafeInteger::new(index as u64 + 3)?;
        store.configure_knowledge(&profile)?;
        assert!(f
            .runtime
            .restore_into(
                &f.f.control,
                &checkpoint.checkpoint,
                1,
                &RequestId::new(&format!("stale-model-{index}"))?,
                &sink
            )
            .is_err());
    }
    assert_eq!(sink.delivered.lock().map_err(|_| "sink")?.len(), 1);
    Ok(())
}
#[test]
fn artifacts_restart_folds_native_knowledge_and_reuses_release_identity() -> TestResult {
    let mut f = KnowledgeFixture::new()?;
    let reference = f.publish("restart", b"restart-canary")?;
    let handle = f.runtime.handle(
        &f.f.control,
        &reference,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    let request = RequestId::new("restart-release")?;
    let first = f.runtime.release_into(
        &f.f.control,
        &request,
        f.runtime.prepare_read(&f.f.control, &handle)?,
        &f.sink(),
    )?;
    let original_control = f.f.control.clone();
    let path = f.f.path.clone();
    let directory = f.f._directory.take();
    drop(f);
    let f = KnowledgeFixture::from(RecoveryFixture::open(path, directory, false)?)?;
    let again = f.runtime.release_into(
        &f.f.control,
        &request,
        f.runtime.prepare_read(&f.f.control, &handle)?,
        &f.sink(),
    );
    // The original release is bound to its original signed read capability.
    // A freshly issued capability cannot reinterpret an older request identity.
    assert!(again.is_err());
    let replay = f.runtime.release_into(
        &original_control,
        &request,
        f.runtime.prepare_read(&original_control, &handle)?,
        &f.sink(),
    )?;
    assert_eq!(replay.release, first.release);
    let second = f.runtime.release_into(
        &f.f.control,
        &RequestId::new("new-read-after-restart")?,
        f.runtime.prepare_read(&f.f.control, &handle)?,
        &f.sink(),
    )?;
    assert!(
        private_release_observation(&f, &second.release)?.observation_generation
            > private_release_observation(&f, &first.release)?.observation_generation
    );
    let influence = f
        .f
        .authority
        .admission_operation_store()
        .observe_knowledge_influence(&f.profile.scope, &f.f.authority.mutation_fence(), now_ms()?)?
        .ok_or("influence")?;
    assert!(influence.externally_influenced);
    Ok(())
}
#[cfg(unix)]
#[test]
fn artifacts_journal_symlink_hard_link_and_rename_refuse_before_bytes() -> TestResult {
    use std::os::unix::fs::symlink;
    for change in ["symlink", "hard-link", "rename"] {
        let f = KnowledgeFixture::new()?;
        let root = f.publish("filesystem", b"filesystem-canary")?;
        let handle = f.runtime.handle(
            &f.f.control,
            &root,
            &ArtifactRecipientId::new("agent-root")?,
        )?;
        let prepared = f.runtime.prepare_read(&f.f.control, &handle)?;
        let path = f.f.path.join("process.db");
        match change {
            "hard-link" => std::fs::hard_link(&path, f.f.path.join("alias.db"))?,
            "symlink" => {
                let replacement = f.f.path.join("original.db");
                std::fs::rename(&path, &replacement)?;
                symlink(&replacement, &path)?;
            }
            _ => {
                std::fs::rename(&path, f.f.path.join("original.db"))?;
                std::fs::write(&path, b"replacement")?;
            }
        }
        let sink = f.sink();
        assert!(f
            .runtime
            .release_into(
                &f.f.control,
                &RequestId::new("unsafe-path")?,
                prepared,
                &sink
            )
            .is_err());
        assert!(sink.delivered.lock().map_err(|_| "sink")?.is_empty());
        assert!(chio_process::ProcessRuntime::open(&path, f.f.kernel.clone()).is_err());
    }
    Ok(())
}

#[test]
fn memory_open_legacy_reader_is_revoked_by_durable_activation() -> TestResult {
    let base = RecoveryFixture::new(false)?;
    let original = base.process.process("root")?;
    base.process
        .checkpoint("root", 0, serde_json::json!({"legacy":"private-canary"}))?;
    let registry = chio_process::ProcessRegistry::open(base.path.join("process.db"), &base.kernel)?;
    let raw = base.process.put_blob("root", b"legacy-reader")?;
    let reader = chio_process::ProcessStateReader::open(base.path.join("process.db"))?;
    assert_eq!(reader.blob("root", &raw.sha256)?, b"legacy-reader");
    let f = KnowledgeFixture::from(base)?;
    assert!(reader.blob("root", &raw.sha256).is_err());
    assert!(reader.checkpoint("root").is_err());
    let registered =
        f.f.process
            .create_root("root", &original.capability, original.limits)?;
    assert_eq!(registered.checkpoint.value, serde_json::Value::Null);
    assert_eq!(
        registry.process("root")?.checkpoint.value,
        serde_json::Value::Null
    );
    let connection = rusqlite::Connection::open(f.f.path.join("process.db"))?;
    assert!(connection
        .execute("UPDATE process_runtime SET version=1 WHERE singleton=1", [])
        .is_err());
    // A simulated restore of an old journal cannot clear the native authority's
    // marker, even if the local refusal trigger is absent in that old image.
    connection.execute_batch("DROP TRIGGER process_knowledge_no_downgrade; UPDATE process_runtime SET version=1 WHERE singleton=1;")?;
    assert!(f.f.process.read_blob("root", &raw.sha256).is_err());
    assert_eq!(
        registry.process("root")?.checkpoint.value,
        serde_json::Value::Null
    );
    let process = f.f.process.process("root")?;
    assert_eq!(process.checkpoint.value, serde_json::Value::Null);
    assert!(reader.blob("root", &raw.sha256).is_err());
    Ok(())
}
#[test]
fn artifacts_immutable_object_refuses_mutation_and_lost_bytes_quarantine_release() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let root = f.publish("corrupt", b"original")?;
    let handle = f.runtime.handle(
        &f.f.control,
        &root,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    let prepared = f.runtime.prepare_read(&f.f.control, &handle)?;
    let connection = rusqlite::Connection::open(f.f.path.join("process.db"))?;
    assert!(connection
        .execute(
            "UPDATE process_artifact_objects SET data=?1 WHERE sha256=?2",
            rusqlite::params![b"modified".as_slice(), chio_core::sha256_hex(b"original")],
        )
        .is_err());
    let (record, _) =
        f.f.authority
            .admission_operation_store()
            .prepare_artifact_read(
                &f.actor(RecoveryPermission::KnowledgeRead)?,
                &handle,
                &f.f.authority.mutation_fence(),
                now_ms()?,
            )?;
    f.broker
        .collect_private(record.seal.as_ref().ok_or("immutable object seal")?)?;
    let sink = f.sink();
    assert!(f
        .runtime
        .release_into(
            &f.f.control,
            &RequestId::new("changed-buffer")?,
            prepared,
            &sink
        )
        .is_err());
    assert!(f.runtime.prepare_read(&f.f.control, &handle).is_err());
    assert!(sink.delivered.lock().map_err(|_| "sink")?.is_empty());
    let state:String=rusqlite::Connection::open(f.f.path.join("admission.db"))?.query_row("SELECT json_extract(payload,'$.state') FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-publication:*'",[],|row|row.get(0))?;
    assert_eq!(state, "quarantined");
    Ok(())
}
#[tokio::test]
async fn artifacts_pending_approval_has_a_native_version_pin() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let root = f.publish("approval-version", b"review-required")?;
    let seed = f.f.denied_seed_named("pending-pin").await?;
    let created =
        f.f.execute(
            "pending-create",
            RecoveryCommandBodyV1::CreateWorkflow {
                creation_key: CreationKey::new("pending-pin")?,
                template: RecoveryTemplateV1::SupportTicketPublicIssue,
                request_seed: text(&seed)?,
            },
        )
        .await?;
    let id = created.status.workflow_id;
    let record = f.f.record(&id)?;
    let digest = recovery_digest(
        RecoveryDigestDomain::ActionIntent,
        record.action.as_ref().ok_or("pending action")?,
    )?;
    let offer = format!(
        "offer:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    f.f.execute(
        "pending-select",
        RecoveryCommandBodyV1::SelectOffer {
            workflow_id: id.clone(),
            expected_revision: record.revision,
            offer_id: OfferId::new(&offer)?,
        },
    )
    .await?;
    f.f.runtime.approval_intent(&f.f.control, &id)?;
    let actor = f.actor(RecoveryPermission::KnowledgeAdmin)?;
    let operator_evidence =
        f.publish("approval-operator-evidence", b"separate-operator-evidence")?;
    f.f.authority.admission_operation_store().pin_artifact(
        &actor,
        &operator_evidence,
        &EvidenceRef::new(&format!("approval:{}", id.as_str()))?,
        &f.f.authority.mutation_fence(),
        now_ms()?,
    )?;
    let pending = f.f.record(&id)?;
    assert!(pending.review.is_some());
    assert!(pending.approval.is_none());
    assert!(
        f.f.authority
            .admission_operation_store()
            .pin_pending_artifact_approval(
                &actor,
                &root,
                &id,
                &f.f.authority.mutation_fence(),
                now_ms()?,
            )
            .is_ok(),
        "operator display identity must not occupy pending approval pin custody"
    );
    assert!(f.runtime.collect(&f.f.control, &root).is_err());
    assert_eq!(external_count(&f.f.path)?, 0);
    Ok(())
}

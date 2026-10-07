//! durable knowledge acceptance through the production blob broker, writer and native flow rows.
use super::*;
use crate::knowledge::*;
use chio_core_types::recovery::*;
use chio_kernel::knowledge::*;
use chio_security_types::knowledge::*;
use chio_store_sqlite::admission_operation_store::*;
use std::sync::Mutex;

struct KnowledgeFixture {
    f: RecoveryFixture,
    runtime: NativeKnowledgeRuntime,
    profile: NativeKnowledgeInstallationV1,
    broker: Arc<chio_process::ProcessArtifactBroker>,
    certificate: Keypair,
}
mod audience;
mod checkpoints;
mod confinement;
mod custody;
mod distinct_labels;
mod host;
mod influence;
mod live_capacity;
mod pins;
mod product;
mod qualification;
mod release_audience;
mod request_owners;
mod retained_owner;
mod retention;
mod setup;
impl KnowledgeFixture {
    fn new() -> TestResult<Self> {
        Self::from(RecoveryFixture::new(false)?)
    }
    fn from(mut f: RecoveryFixture) -> TestResult<Self> {
        let mut deployment = f.kernel.recovery_deployment(f.runtime.scope())?;
        let mut permissions = deployment.actors.as_slice()[0]
            .permissions
            .as_slice()
            .to_vec();
        for permission in [
            RecoveryPermission::KnowledgeRead,
            RecoveryPermission::KnowledgeWrite,
            RecoveryPermission::KnowledgeAdopt,
            RecoveryPermission::KnowledgeAdmin,
        ] {
            if !permissions.contains(&permission) {
                permissions.push(permission);
            }
        }
        permissions.sort();
        let mut actors = deployment.actors.as_slice().to_vec();
        actors[0].permissions = BoundedList::new(permissions.clone())?;
        let preview_clearance = actors[0].preview_clearance.clone();
        deployment.actors = NonEmptyBoundedList::new(actors)?;
        deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
        let store = Arc::new(f.authority.admission_operation_store());
        store.configure_recovery_deployment(&deployment)?;
        f.control = f.kernel.issue_capability(
            &f.approval_key.public_key(),
            ChioScope {
                grants: permissions
                    .iter()
                    .map(|permission| ToolGrant {
                        server_id: "chio.recovery".into(),
                        tool_name: permission.wire_name().into(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    })
                    .collect(),
                ..Default::default()
            },
            1200,
        )?;
        let context = f
            .process
            .recovery_security_context(deployment.scope.process_id.as_str())?;
        let recipient = ArtifactRecipientV1 {
            recipient: ArtifactRecipientId::new("agent-root")?,
            scope: deployment.scope.clone(),
            runtime: ProtectedText::new(f.process.runtime_id())?,
            principal: context.as_v1().principal_id().clone(),
            lineage: IsolationLineageId::new(context.as_v1().lineage_root_id().as_str())?,
            isolation_epoch: ProtectedText::new(context.as_v1().isolation_epoch_id().as_str())?,
            context_generation: SafeInteger::new(context.as_v1().context_generation())?,
            clearance: preview_clearance,
            sink: ArtifactSinkV1::Agent,
        };
        let certificate = Keypair::from_seed(&[217; 32]);
        let profile = NativeKnowledgeInstallationV1 {
            scope: deployment.scope.clone(),
            native_authority: deployment.native_authority.clone(),
            producer_context: context.clone(),
            recipients: NonEmptyBoundedList::new(vec![NativeKnowledgeRecipientV1 {
                recipient,
                context,
            }])?,
            certificate_root: certificate.public_key(),
            classifier_implementation: knowledge_content_digest(b"authoritative-classifier-v1"),
            classifier_configuration: knowledge_content_digest(b"exact-content-review"),
            archive_root: certificate.public_key(),
            generation: SafeInteger::new(1)?,
            policy: deployment.policy_digest,
            contract: ContractDigest::from_bytes(*deployment.contract_digest.as_bytes()),
        };
        let broker = Arc::new(f.process.enable_durable_knowledge()?);
        let runtime = NativeKnowledgeRuntime::new(
            f.kernel.clone(),
            store,
            broker.clone(),
            profile.clone(),
            f.authority.mutation_fence(),
        )?;
        Ok(Self {
            f,
            runtime,
            profile,
            broker,
            certificate,
        })
    }
    fn input(&self, key: &str, bytes: &[u8]) -> TestResult<ArtifactPublicationInputV1> {
        Ok(ArtifactPublicationInputV1 {
            publication: CommandId::new(key)?,
            producer: ArtifactProducerV1::Checkpoint {
                checkpoint: CheckpointId::new(key)?,
            },
            content: knowledge_content_digest(bytes),
            size_bytes: SafeInteger::new(bytes.len() as u64)?,
            media_type: ProtectedText::new("application/octet-stream")?,
            schema: knowledge_content_digest(b"chio.knowledge.opaque-bytes.v1"),
            dependencies: BoundedList::new(vec![])?,
            retention: ArtifactRetentionV1::Ephemeral,
        })
    }
    fn publish(&self, key: &str, bytes: &[u8]) -> TestResult<ArtifactVersionRefV1> {
        Ok(self
            .runtime
            .publish(&self.f.control, &self.input(key, bytes)?, bytes, None)?)
    }
    fn sink(&self) -> RecordingSink {
        RecordingSink {
            recipient: self.profile.recipients.as_slice()[0].recipient.clone(),
            delivered: Mutex::new(Vec::new()),
            path: self.f.path.join("admission.db"),
        }
    }
    fn actor(&self, permission: RecoveryPermission) -> TestResult<AuthenticatedRecoveryActor> {
        Ok(self.f.kernel.authenticate_recovery_actor(
            &self.profile.scope,
            &self.f.control,
            permission,
        )?)
    }
    fn metadata(&self, reference: &ArtifactVersionRefV1) -> TestResult<ArtifactVersionV1> {
        let handle = self.runtime.handle(
            &self.f.control,
            reference,
            &ArtifactRecipientId::new("agent-root")?,
        )?;
        let (record, _) = self
            .f
            .authority
            .admission_operation_store()
            .prepare_artifact_read(
                &self.actor(RecoveryPermission::KnowledgeRead)?,
                &handle,
                &self.f.authority.mutation_fence(),
                now_ms()?,
            )?;
        Ok(record.metadata)
    }
}
struct RecordingSink {
    recipient: ArtifactRecipientV1,
    delivered: Mutex<Vec<Vec<u8>>>,
    path: std::path::PathBuf,
}
impl ArtifactReleaseSink for RecordingSink {
    fn recipient(&self) -> &ArtifactRecipientV1 {
        &self.recipient
    }
    fn deliver(&self, intent: &ArtifactReleaseIntentV1, bytes: &[u8]) -> Result<(), KernelError> {
        let connection = rusqlite::Connection::open(&self.path)
            .map_err(|_| KernelError::Internal("sink".into()))?;
        let count:i64=connection.query_row("SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-join:*' AND json_extract(payload,'$.release.release')=?1",[intent.release.as_str()],|row|row.get(0)).map_err(|_|KernelError::Internal("sink".into()))?;
        if count != 1 {
            return Err(KernelError::Internal(
                "bytes preceded knowledge commit".into(),
            ));
        }
        self.delivered
            .lock()
            .map_err(|_| KernelError::Internal("sink".into()))?
            .push(bytes.to_vec());
        Ok(())
    }
}
#[test]
fn artifacts_native_publication_and_taint_commit_before_first_byte() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("first", b"private-artifact-canary")?;
    let handle = f.runtime.handle(
        &f.f.control,
        &reference,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    let sink = f.sink();
    let request = RequestId::new("read-first")?;
    let prepared = f.runtime.prepare_read(&f.f.control, &handle)?;
    let first = f
        .runtime
        .release_into(&f.f.control, &request, prepared, &sink)?;
    let again = f.runtime.release_into(
        &f.f.control,
        &request,
        f.runtime.prepare_read(&f.f.control, &handle)?,
        &sink,
    )?;
    assert_eq!(first.release, again.release);
    assert_eq!(
        sink.delivered.lock().map_err(|_| "sink")?.as_slice(),
        &[
            b"private-artifact-canary".to_vec(),
            b"private-artifact-canary".to_vec()
        ]
    );
    let observed =
        f.f.authority
            .admission_operation_store()
            .observe_security_participant_flow(
                &f.profile.native_authority,
                &recovery_flow_key(&f.profile.producer_context),
                &f.f.authority.mutation_fence(),
                now_ms()?,
            )?;
    assert_eq!(
        observed.snapshot().ok_or("flow")?.context_generation,
        acceptance::private_release_observation(&f, &first.release)?
            .observation_generation
            .get()
    );
    assert!(f
        .f
        .process
        .read_blob("root", &chio_core::sha256_hex(b"private-artifact-canary"))
        .is_err());
    assert!(f.f.process.put_blob("root", b"raw").is_err());
    assert!(f.f.process.storage("root").is_err());
    assert!(f
        .f
        .process
        .checkpoint("root", 0, serde_json::json!({"secret":"raw"}))
        .is_err());
    assert!(chio_process::ProcessStateReader::open(f.f.path.join("process.db")).is_err());
    Ok(())
}
fn certificate(
    f: &KnowledgeFixture,
    reservation: &ArtifactPublicationViewV1,
    label: InformationLabel,
) -> TestResult<SignedArtifactCertificateV1> {
    let metadata = &reservation.metadata;
    let time = now_ms()?;
    Ok(SignedArtifactCertificateV1::sign(
        ArtifactCertificateV1 {
            domain_version: VersionV1,
            evidence: match &metadata.producer {
                ArtifactProducerV1::Adoption { evidence } => evidence.clone(),
                _ => EvidenceRef::new("projection-proof")?,
            },
            scope: metadata.scope.clone(),
            kind: ArtifactCertificateKindV1::Classification,
            artifact: metadata.artifact.clone(),
            version: metadata.version.clone(),
            producer: metadata.producer.clone(),
            content: metadata.content,
            size_bytes: metadata.size_bytes,
            schema: metadata.schema,
            dependencies: metadata.dependencies.clone(),
            implementation: knowledge_content_digest(b"authoritative-classifier-v1"),
            configuration: knowledge_content_digest(b"exact-content-review"),
            output_label: label,
            influence: metadata.influence.clone(),
            issued_at_unix_ms: SafeInteger::new(time)?,
            valid_until_unix_ms: SafeInteger::new(time + 60_000)?,
        },
        &f.certificate,
    )?)
}
fn publish_label(
    f: &KnowledgeFixture,
    key: &str,
    bytes: &[u8],
    label: InformationLabel,
) -> TestResult<ArtifactVersionRefV1> {
    let mut input = f.input(key, bytes)?;
    input.producer = ArtifactProducerV1::Adoption {
        evidence: EvidenceRef::new(key)?,
    };
    let reservation = f.runtime.reserve(&f.f.control, &input)?;
    let proof = certificate(f, &reservation, label)?;
    Ok(f.runtime
        .publish(&f.f.control, &input, bytes, Some(&proof))?)
}
#[test]
fn artifacts_publication_commit_cutpoints_reconcile_original_identity() -> TestResult {
    use crate::knowledge::KnowledgeCutpoint::*;
    for cutpoint in [
        Reserved,
        BlobStaged,
        StageRetained,
        MetadataCommitted,
        AvailabilityCommitted,
    ] {
        let f = KnowledgeFixture::new()?;
        let input = f.input("cutpoint", b"cutpoint-secret")?;
        let once = Arc::new(AtomicUsize::new(0));
        let seen = once.clone();
        let faulty = f.runtime.clone().with_test_cutpoint(Arc::new(move |stage| {
            if stage == cutpoint && seen.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(KernelError::Internal("lost acknowledgement".into()));
            }
            Ok(())
        }));
        assert!(faulty
            .publish(&f.f.control, &input, b"cutpoint-secret", None)
            .is_err());
        let reserved = f.runtime.reserve(&f.f.control, &input)?;
        let resumed = f
            .runtime
            .publish(&f.f.control, &input, b"cutpoint-secret", None)?;
        assert_eq!(reserved.metadata.artifact, resumed.artifact);
        assert_eq!(reserved.metadata.version, resumed.version);
        assert_eq!(
            f.runtime
                .publish(&f.f.control, &input, b"cutpoint-secret", None)?,
            resumed
        );
        let mut changed = input.clone();
        changed.content = knowledge_content_digest(b"different");
        changed.size_bytes = SafeInteger::new(9)?;
        assert!(f.runtime.reserve(&f.f.control, &changed).is_err());
        let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
        let count:i64=connection.query_row("SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-publication:*'",[],|row|row.get(0))?;
        assert_eq!(count, 1);
    }
    Ok(())
}
#[test]
fn artifacts_equal_bytes_different_provenance_and_cross_tenant_oracle() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let public = publish_label(&f, "public-root", b"equal", InformationLabel::bottom())?;
    let secret = publish_label(&f, "secret-root", b"equal", restricted_label())?;
    assert_ne!(public.artifact, secret.artifact);
    assert_ne!(public.provenance, secret.provenance);
    let connection = rusqlite::Connection::open(f.f.path.join("process.db"))?;
    let count: i64 = connection.query_row(
        "SELECT count(*) FROM process_artifact_objects WHERE data IS NOT NULL",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        count, 2,
        "independent provenance consumes independent custody"
    );
    assert_eq!(
        f.broker
            .storage_usage(&f.profile.scope.process_id)?
            .tree_bytes,
        10
    );
    let mut foreign = public.clone();
    foreign.scope.tenant_id = RecoveryTenantId::new("foreign-tenant")?;
    let recipient = ArtifactRecipientId::new("agent-root")?;
    let errors = [
        f.runtime.handle(&f.f.control, &foreign, &recipient).err(),
        f.runtime
            .handle(
                &f.f.control,
                &ArtifactVersionRefV1 {
                    artifact: ArtifactId::new("missing")?,
                    ..public.clone()
                },
                &recipient,
            )
            .err(),
    ];
    let messages = errors
        .into_iter()
        .map(|error| {
            error
                .ok_or("refusal missing")
                .map(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(messages[0], messages[1]);
    assert!(!messages[0].contains("equal"));
    // Even trusted profile setup must not reuse one physical process namespace
    // for another tenant and silently share its private dedup/deletion domain.
    let mut alias = f.profile.clone();
    alias.scope.tenant_id = RecoveryTenantId::new("foreign-tenant")?;
    let context = alias.producer_context.as_v1();
    alias.producer_context =
        chio_kernel::SecurityInvocationContext::V1(chio_kernel::SecurityInvocationContextV1::new(
            chio_security_types::ports::TenantId::new("foreign-tenant")?,
            context.session_id().clone(),
            context.principal_id().clone(),
            context.isolation_epoch_id().clone(),
            context.lineage_root_id().clone(),
            context.context_generation(),
        ));
    let mut aliases = alias.recipients.as_slice().to_vec();
    aliases[0].context = alias.producer_context.clone();
    aliases[0].recipient.scope = alias.scope.clone();
    alias.recipients = NonEmptyBoundedList::new(aliases)?;
    assert!(f
        .f
        .authority
        .admission_operation_store()
        .configure_knowledge(&alias)
        .is_err());
    let mut profile = f.profile.clone();
    let mut recipients = profile.recipients.as_slice().to_vec();
    recipients[0].recipient.clearance = InformationLabel::bottom();
    profile.recipients = NonEmptyBoundedList::new(recipients)?;
    profile.generation = SafeInteger::new(2)?;
    f.f.authority
        .admission_operation_store()
        .configure_knowledge(&profile)?;
    assert!(f.runtime.handle(&f.f.control, &public, &recipient).is_ok());
    assert!(f.runtime.handle(&f.f.control, &secret, &recipient).is_err());
    Ok(())
}
#[test]
fn artifacts_release_readback_uncertainty_and_live_revocation() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let root = f.publish("release", b"readback-canary")?;
    let recipient = ArtifactRecipientId::new("agent-root")?;
    let handle = f.runtime.handle(&f.f.control, &root, &recipient)?;
    let sink = f.sink();
    let request = RequestId::new("original-release")?;
    let once = Arc::new(AtomicUsize::new(0));
    let seen = once.clone();
    let faulty = f.runtime.clone().with_test_cutpoint(Arc::new(move |stage| {
        if stage == crate::knowledge::KnowledgeCutpoint::ReleaseCommitted
            && seen.fetch_add(1, Ordering::SeqCst) == 0
        {
            return Err(KernelError::Internal("lost ack".into()));
        }
        Ok(())
    }));
    assert!(faulty
        .release_into(
            &f.f.control,
            &request,
            f.runtime.prepare_read(&f.f.control, &handle)?,
            &sink
        )
        .is_err());
    assert!(sink.delivered.lock().map_err(|_| "sink")?.is_empty());
    assert!(f.runtime.collect(&f.f.control, &root).is_err());
    let released = f.runtime.release_into(
        &f.f.control,
        &request,
        f.runtime.prepare_read(&f.f.control, &handle)?,
        &sink,
    )?;
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let count:i64=connection.query_row("SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-join:*'",[],|row|row.get(0))?;
    assert_eq!(count, 1);
    let prepared = f.runtime.prepare_read(&f.f.control, &handle)?;
    f.f.kernel.revoke_capability(&f.f.control.id)?;
    assert!(f
        .runtime
        .release_into(&f.f.control, &request, prepared, &sink)
        .is_err());
    assert_eq!(sink.delivered.lock().map_err(|_| "sink")?.len(), 1);
    assert_eq!(
        acceptance::private_release_observation(&f, &released.release)?.artifact,
        root
    );
    Ok(())
}
#[test]
fn memory_old_checkpoint_cannot_reset_context_and_cas_pins() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let public = publish_label(&f, "old-public", b"old", InformationLabel::bottom())?;
    let checkpoint = f.runtime.checkpoint(
        &f.f.control,
        &CheckpointId::new("memory")?,
        0,
        std::slice::from_ref(&public),
        &[],
    )?;
    let restricted = publish_label(&f, "new-secret", b"new", restricted_label())?;
    let handle = f.runtime.handle(
        &f.f.control,
        &restricted,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    let sink = f.sink();
    f.runtime.release_into(
        &f.f.control,
        &RequestId::new("learn-new")?,
        f.runtime.prepare_read(&f.f.control, &handle)?,
        &sink,
    )?;
    let before =
        f.f.authority
            .admission_operation_store()
            .observe_security_participant_flow(
                &f.profile.native_authority,
                &recovery_flow_key(&f.profile.producer_context),
                &f.f.authority.mutation_fence(),
                now_ms()?,
            )?;
    f.runtime.restore_into(
        &f.f.control,
        &checkpoint.checkpoint,
        1,
        &RequestId::new("restore-old")?,
        &sink,
    )?;
    let after =
        f.f.authority
            .admission_operation_store()
            .observe_security_participant_flow(
                &f.profile.native_authority,
                &recovery_flow_key(&f.profile.producer_context),
                &f.f.authority.mutation_fence(),
                now_ms()?,
            )?;
    assert!(before
        .snapshot()
        .ok_or("before")?
        .principal_label
        .flows_to(&after.snapshot().ok_or("after")?.principal_label));
    assert_eq!(
        after.snapshot().ok_or("after")?.principal_label,
        restricted_label()
    );
    assert!(f
        .runtime
        .checkpoint(
            &f.f.control,
            &checkpoint.checkpoint,
            0,
            std::slice::from_ref(&restricted),
            &[]
        )
        .is_err());
    let next = f.runtime.checkpoint(
        &f.f.control,
        &checkpoint.checkpoint,
        1,
        std::slice::from_ref(&restricted),
        &[],
    )?;
    assert_eq!(next.revision.get(), 2);
    assert!(f.runtime.collect(&f.f.control, &public).is_err());
    assert!(f
        .runtime
        .restore_into(
            &f.f.control,
            &checkpoint.checkpoint,
            2,
            &RequestId::new("restore-old")?,
            &sink
        )
        .is_err());
    Ok(())
}
#[test]
fn artifacts_missing_blob_quarantines_and_never_substitutes_same_digest() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let input = f.input("missing", b"exact")?;
    let root = f.runtime.publish(&f.f.control, &input, b"exact", None)?;
    let handle = f.runtime.handle(
        &f.f.control,
        &root,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
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
        .collect_private(record.seal.as_ref().ok_or("exact object seal")?)?;
    assert!(f.runtime.prepare_read(&f.f.control, &handle).is_err());
    assert!(f
        .runtime
        .publish(&f.f.control, &input, b"exact", None)
        .is_err());
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let state:String=connection.query_row("SELECT json_extract(payload,'$.state') FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-publication:*'",[],|row|row.get(0))?;
    assert_eq!(state, "quarantined");
    assert!(connection.execute("DELETE FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-publication:*'",[]).is_err());
    Ok(())
}
#[test]
fn artifacts_collection_barrier_dedup_and_identity_tombstones() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let first = f.publish("gc-first", b"same")?;
    let second = f.publish("gc-second", b"same")?;
    f.runtime.collect(&f.f.control, &first)?;
    let handle = f.runtime.handle(
        &f.f.control,
        &second,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    assert!(f.runtime.prepare_read(&f.f.control, &handle).is_ok());
    let faulty = f.runtime.clone().with_test_cutpoint(Arc::new(|stage| {
        if stage == crate::knowledge::KnowledgeCutpoint::CollectionRetired {
            Err(KernelError::Internal("lost retire ack".into()))
        } else {
            Ok(())
        }
    }));
    assert!(faulty.collect(&f.f.control, &second).is_err());
    assert!(f
        .runtime
        .publish(
            &f.f.control,
            &f.input("new-during-sweep", b"same")?,
            b"same",
            None
        )
        .is_err());
    f.runtime.collect(&f.f.control, &second)?;
    let count: i64 = rusqlite::Connection::open(f.f.path.join("process.db"))?.query_row(
        "SELECT count(*) FROM process_artifact_objects WHERE data IS NOT NULL",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    assert!(f.publish("gc-second", b"same").is_err());
    assert!(f.publish("independent-new-version", b"same").is_ok());
    Ok(())
}
#[test]
fn artifacts_copy_restore_archive_and_aliases_preserve_every_origin() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let source = publish_label(&f, "copy-source", b"archive-canary", restricted_label())?;
    let handle = f.runtime.handle(
        &f.f.control,
        &source,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    let copy = f
        .runtime
        .copy(&f.f.control, &handle, &CommandId::new("copy")?)?;
    assert_ne!(source.artifact, copy.artifact);
    let actor = f.actor(RecoveryPermission::KnowledgeWrite)?;
    let store = f.f.authority.admission_operation_store();
    let copy_inventory = store.artifact_transfer_inventory(
        &actor,
        &copy,
        &f.f.authority.mutation_fence(),
        now_ms()?,
    )?;
    for reference in &copy_inventory {
        assert!(restricted_label().flows_to(&f.metadata(reference)?.label));
    }
    store.move_artifact(
        &actor,
        &copy,
        &ProtectedText::new("logical-destination")?,
        &f.f.authority.mutation_fence(),
        now_ms()?,
    )?;
    let mut profile = f.profile.clone();
    let mut entry = profile.recipients.as_slice()[0].clone();
    entry.recipient.recipient = ArtifactRecipientId::new("archive")?;
    entry.recipient.sink = ArtifactSinkV1::Archive;
    profile.recipients = NonEmptyBoundedList::new(vec![
        profile.recipients.as_slice()[0].clone(),
        entry.clone(),
    ])?;
    profile.generation = SafeInteger::new(2)?;
    store.configure_knowledge(&profile)?;
    let sink = RecordingSink {
        recipient: entry.recipient,
        delivered: Mutex::new(vec![]),
        path: f.f.path.join("admission.db"),
    };
    let signer = chio_core_types::crypto::Ed25519Backend::new(f.certificate.clone());
    let exported = f.runtime.export_into(
        &f.f.control,
        &handle,
        &RequestId::new("export")?,
        &signer,
        &sink,
    )?;
    let archive_inventory = store.artifact_transfer_inventory(
        &actor,
        &acceptance::private_release_observation(&f, &exported.release)?.artifact,
        &f.f.authority.mutation_fence(),
        now_ms()?,
    )?;
    for reference in &archive_inventory {
        assert!(restricted_label().flows_to(&f.metadata(reference)?.label));
    }
    let bytes = sink
        .delivered
        .lock()
        .map_err(|_| "sink")?
        .first()
        .ok_or("archive")?
        .clone();
    let imported = f.runtime.import_archive(&f.f.control, &bytes)?;
    assert_ne!(source.artifact, imported.artifact);
    let inventory = store.artifact_transfer_inventory(
        &actor,
        &imported,
        &f.f.authority.mutation_fence(),
        now_ms()?,
    )?;
    for reference in &inventory {
        assert!(restricted_label().flows_to(&f.metadata(reference)?.label));
    }
    assert!(matches!(
        f.metadata(&inventory[0])?.producer,
        ArtifactProducerV1::Import { .. }
    ));
    let mut corrupted = bytes.clone();
    let last = corrupted.last_mut().ok_or("bytes")?;
    *last ^= 1;
    assert!(f.runtime.import_archive(&f.f.control, &corrupted).is_err());
    assert!(f
        .runtime
        .import_archive(&f.f.control, &bytes[..bytes.len() - 1])
        .is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(f.runtime.import_archive(&f.f.control, &trailing).is_err());
    let mut deployment = f.f.kernel.recovery_deployment(&f.profile.scope)?;
    let mut actors = deployment.actors.as_slice().to_vec();
    actors[0].preview_clearance = InformationLabel::bottom();
    deployment.actors = NonEmptyBoundedList::new(actors)?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    store.configure_recovery_deployment(&deployment)?;
    assert!(f.runtime.import_archive(&f.f.control, &bytes).is_err());
    Ok(())
}
#[test]
fn memory_legacy_state_activation_and_exact_adoption() -> TestResult {
    let base = RecoveryFixture::new(false)?;
    let bytes = b"legacy-canary";
    let blob = base.process.put_blob("root", bytes)?;
    base.process
        .checkpoint("root", 0, serde_json::json!({"legacy":blob.sha256}))?;
    let f = KnowledgeFixture::from(base)?;
    assert_eq!(
        f.f.process.process("root")?.checkpoint.value,
        serde_json::Value::Null
    );
    assert!(f.f.process.read_blob("root", &blob.sha256).is_err());
    let mut input = f.input("adopt", bytes)?;
    input.producer = ArtifactProducerV1::Adoption {
        evidence: EvidenceRef::new("adopt")?,
    };
    let reservation = f.runtime.reserve(&f.f.control, &input)?;
    let proof = certificate(&f, &reservation, restricted_label())?;
    let mut changed = proof.body().clone();
    changed.content = knowledge_content_digest(b"wrong");
    let wrong = SignedArtifactCertificateV1::sign(changed, &f.certificate)?;
    assert!(f
        .runtime
        .adopt_legacy(&f.f.control, &input, &wrong)
        .is_err());
    let adopted = f.runtime.adopt_legacy(&f.f.control, &input, &proof)?;
    let actor = f.actor(RecoveryPermission::KnowledgeRead)?;
    let before =
        f.f.authority
            .admission_operation_store()
            .observe_security_participant_flow(
                &f.profile.native_authority,
                &recovery_flow_key(&f.profile.producer_context),
                &f.f.authority.mutation_fence(),
                now_ms()?,
            )?;
    assert_eq!(
        before.snapshot().ok_or("source")?.principal_label,
        InformationLabel::bottom()
    );
    let handle = f.runtime.handle(
        &f.f.control,
        &adopted,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    let (record, _) =
        f.f.authority
            .admission_operation_store()
            .prepare_artifact_read(&actor, &handle, &f.f.authority.mutation_fence(), now_ms()?)?;
    assert!(record.metadata.influence.unknown);
    assert_eq!(record.metadata.label, restricted_label());
    let seal = record.seal.ok_or("seal")?;
    assert_eq!(f.broker.read_private(&seal)?, bytes);
    f.runtime.collect(&f.f.control, &adopted)?;
    let count: i64 = rusqlite::Connection::open(f.f.path.join("process.db"))?.query_row(
        "SELECT count(*) FROM process_state_blobs WHERE legacy_quarantined=1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1);
    Ok(())
}

#[path = "knowledge/acceptance.rs"]
mod acceptance;
#[path = "knowledge/native.rs"]
mod native;

use super::*;
use chio_security_types::semantic::*;

#[tokio::test]
async fn artifacts_projection_recomputes_native_producer_and_refuses_one_shot_authority(
) -> TestResult {
    let f = KnowledgeFixture::from(semantic::native_fixture("project")?)?;
    let (runtime, request, p) = semantic::prepare(
        &f.f,
        "project-artifact",
        SemanticOutputDispositionV1::ReturnValue,
    )?;
    let input_bytes = chio_core::canonical_json_bytes(&p.payload)?;
    let source = publish_label(&f, "projection-input", &input_bytes, restricted_label())?;
    let response = runtime
        .execute_step(&f.f.process, "root", "project-artifact", &request)
        .await?;
    let output = match response.output.ok_or("output")? {
        chio_kernel::ToolCallOutput::Value(value) => chio_core::canonical_json_bytes(&value)?,
        _ => return Err("projection output".into()),
    };
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let operation: String = connection.query_row(
        "SELECT operation_id FROM admission_operations WHERE request_id=?1",
        [&request.request_id],
        |row| row.get(0),
    )?;
    let mut input = f.input("projected-version", &output)?;
    input.producer = ArtifactProducerV1::NativeOperation {
        operation: OperationId::new(&operation)?,
    };
    input.dependencies = BoundedList::new(vec![source])?;
    let reservation = f.runtime.reserve(&f.f.control, &input)?;
    let mut body = certificate(&f, &reservation, InformationLabel::bottom())?
        .body()
        .clone();
    body.kind = ArtifactCertificateKindV1::Projection;
    body.implementation = p.package.body().operations.as_slice()[0].implementation;
    body.configuration =
        semantic_content_digest(&p.package.body().operations.as_slice()[0].projection_fields)?;
    let mut wrong = body.clone();
    wrong.configuration = CanonicalPayloadDigest::from_bytes([9; 32]);
    assert!(f
        .runtime
        .publish(
            &f.f.control,
            &input,
            &output,
            Some(&SignedArtifactCertificateV1::sign(wrong, &f.certificate)?)
        )
        .is_err());
    let certificate = SignedArtifactCertificateV1::sign(body, &f.certificate)?;
    let reference = f
        .runtime
        .publish(&f.f.control, &input, &output, Some(&certificate))?;
    let actor = f.actor(RecoveryPermission::KnowledgeRead)?;
    let store = f.f.authority.admission_operation_store();
    let inventory = store.artifact_transfer_inventory(
        &actor,
        &reference,
        &f.f.authority.mutation_fence(),
        now_ms()?,
    )?;
    let metadata = f.metadata(inventory.last().ok_or("projected")?)?;
    assert_eq!(metadata.label, InformationLabel::bottom());
    assert!(metadata.influence.externally_influenced);
    // A self-described derivation cannot acquire native projection authority,
    // even with a valid signature by the selected persistent certificate root.
    let mut fake = f.input("self-described-projection", &output)?;
    fake.producer = ArtifactProducerV1::Derivation {
        operation: OperationId::new(&operation)?,
    };
    fake.dependencies = input.dependencies.clone();
    let reservation = f.runtime.reserve(&f.f.control, &fake)?;
    let mut body = certificate.body().clone();
    body.artifact = reservation.metadata.artifact;
    body.version = reservation.metadata.version;
    body.producer = fake.producer.clone();
    body.influence = reservation.metadata.influence;
    assert!(f
        .runtime
        .publish(
            &f.f.control,
            &fake,
            &output,
            Some(&SignedArtifactCertificateV1::sign(body, &f.certificate)?)
        )
        .is_err());
    Ok(())
}
#[tokio::test]
async fn artifacts_withheld_native_output_cannot_gain_projection_authority() -> TestResult {
    let f = KnowledgeFixture::from(semantic::native_fixture("project")?)?;
    let (runtime, request, p) = semantic::prepare(
        &f.f,
        "withheld-projection",
        SemanticOutputDispositionV1::Withhold,
    )?;
    let source = publish_label(
        &f,
        "withheld-input",
        &chio_core::canonical_json_bytes(&p.payload)?,
        restricted_label(),
    )?;
    runtime
        .execute_step(&f.f.process, "root", "withheld-projection", &request)
        .await?;
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let operation: String = connection.query_row(
        "SELECT operation_id FROM admission_operations WHERE request_id=?1",
        [&request.request_id],
        |row| row.get(0),
    )?;
    let output = chio_semantic_contracts::project_semantic_fields(
        &p.payload,
        p.package.body().operations.as_slice()[0]
            .projection_fields
            .as_slice(),
        &mut chio_semantic_contracts::VerificationBudget::new(4096)?,
    )?;
    let bytes = chio_core::canonical_json_bytes(&output)?;
    let mut input = f.input("withheld-artifact", &bytes)?;
    input.producer = ArtifactProducerV1::NativeOperation {
        operation: OperationId::new(&operation)?,
    };
    input.dependencies = BoundedList::new(vec![source])?;
    assert!(f.runtime.reserve(&f.f.control, &input).is_err());
    Ok(())
}
#[tokio::test]
async fn artifacts_observed_model_influence_invalidates_old_scoped_endorsement() -> TestResult {
    let f = KnowledgeFixture::from(semantic::native_fixture("write")?)?;
    let (runtime, request, p) = semantic::prepare(
        &f.f,
        "old-endorsement",
        SemanticOutputDispositionV1::ReturnValue,
    )?;
    let root = publish_label(
        &f,
        "model-influence",
        b"untrusted-public-input",
        InformationLabel::bottom(),
    )?;
    let handle = f.runtime.handle(
        &f.f.control,
        &root,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    f.runtime.release_into(
        &f.f.control,
        &RequestId::new("observe-influence")?,
        f.runtime.prepare_read(&f.f.control, &handle)?,
        &f.sink(),
    )?;
    let mut framed = runtime.frame_action(&request, p.invocation.action.clone(), &p.payload)?;
    assert_ne!(framed.influence, p.invocation.action.influence);
    assert!(framed.externally_influenced);
    // Refreshing confidentiality alone cannot reuse an endorsement for the old
    // influence commitment. The original exact action is independently spent.
    framed.influence = p.invocation.action.influence;
    let mut invocation = p.invocation;
    invocation.action = framed;
    let mut request = request;
    request.arguments = serde_json::to_value(invocation)?;
    let response = runtime
        .execute_step(&f.f.process, "root", "old-endorsement", &request)
        .await;
    assert!(response.is_err() || response.is_ok_and(|response| response.verdict == Verdict::Deny));
    assert_eq!(f.f.effects.load(Ordering::SeqCst), 0);
    Ok(())
}
#[tokio::test]
async fn artifacts_gc_keeps_unknown_native_operation_and_receipt_pins() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let root = f.publish("unknown-custody", b"unknown-input")?;
    let workflow = f.f.ready().await?;
    f.f.behavior.store(1, Ordering::SeqCst);
    let record = f.f.record(&workflow)?;
    f.f.runtime
        .execute_command(
            &f.f.control,
            &f.f.command(
                "unknown-resume",
                RecoveryCommandBodyV1::ResumeWorkflow {
                    workflow_id: workflow.clone(),
                    expected_revision: record.revision,
                },
            )?,
        )
        .await?;
    let record = f.f.record(&workflow)?;
    let operation = record.native_link.ok_or("native link")?;
    assert!(matches!(record.effect, EffectObservationV1::Unknown { .. }));
    let actor = f.actor(RecoveryPermission::KnowledgeAdmin)?;
    let store = f.f.authority.admission_operation_store();
    let operator_evidence = f.publish("operator-evidence", b"independent-evidence")?;
    store.pin_artifact(
        &actor,
        &operator_evidence,
        &EvidenceRef::new(&format!("operation:{}", operation.as_str()))?,
        &f.f.authority.mutation_fence(),
        now_ms()?,
    )?;
    assert!(
        store
            .pin_native_artifact_operation(
                &actor,
                &root,
                &operation,
                &f.f.authority.mutation_fence(),
                now_ms()?,
            )
            .is_ok(),
        "operator display identity must not occupy native operation pin custody"
    );
    assert!(f.runtime.collect(&f.f.control, &root).is_err());
    assert_eq!(external_count(&f.f.path)?, 1);
    let other = f.publish("evidence-pin", b"receipt")?;
    store.pin_artifact(
        &actor,
        &other,
        &EvidenceRef::new("receipt-evidence")?,
        &f.f.authority.mutation_fence(),
        now_ms()?,
    )?;
    assert!(f.runtime.collect(&f.f.control, &other).is_err());
    assert!(store
        .pin_artifact(
            &actor,
            &root,
            &EvidenceRef::new("receipt-evidence")?,
            &f.f.authority.mutation_fence(),
            now_ms()?
        )
        .is_err());
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn artifacts_join_and_native_capture_race_proves_both_commit_orders() -> TestResult {
    // These waits coordinate an observed writer cutpoint. Scheduling under the
    // qualification host's concurrent load must not masquerade as a race error.
    let coordination_deadline = std::time::Duration::from_secs(180);
    for capture_first in [false, true] {
        let directory = tempfile::tempdir()?;
        std::fs::write(directory.path().join("semantic-kind"), "read")?;
        let (ready, waiting) = std::sync::mpsc::sync_channel(1);
        let (resume, continuation) = std::sync::mpsc::sync_channel(1);
        let continuation = Mutex::new(continuation);
        let used = AtomicUsize::new(0);
        let observer = Arc::new(move |committed: bool| {
            if committed == capture_first && used.fetch_add(1, Ordering::SeqCst) == 0 {
                ready
                    .send(())
                    .map_err(|_| KernelError::Internal("race ready".into()))?;
                continuation
                    .lock()
                    .map_err(|_| KernelError::Internal("race lock".into()))?
                    .recv_timeout(coordination_deadline)
                    .map_err(|error| {
                        KernelError::Internal(format!(
                            "native capture continuation failed (capture_first={capture_first}): {error}"
                        ))
                    })?;
            }
            Ok(())
        });
        let base = RecoveryFixture::open_with_native_observer(
            directory.path().to_path_buf(),
            Some(directory),
            false,
            Some(observer),
        )?;
        let f = KnowledgeFixture::from(base)?;
        let (runtime, request, _) = semantic::prepare(
            &f.f,
            "racing-read",
            SemanticOutputDispositionV1::ReturnValue,
        )?;
        let root = publish_label(&f, "race-artifact", b"race-observation", restricted_label())?;
        let handle = f.runtime.handle(
            &f.f.control,
            &root,
            &ArtifactRecipientId::new("agent-root")?,
        )?;
        let process = f.f.process.clone();
        let task = tokio::spawn(async move {
            runtime
                .execute_step(&process, "root", "racing-read", &request)
                .await
        });
        let coordinated = tokio::task::spawn_blocking(move || {
            waiting.recv_timeout(coordination_deadline).map_err(|error| {
                format!("native capture cutpoint was not reached (capture_first={capture_first}): {error}")
            })
        })
        .await
        .map_err(|error| {
            format!(
                "native capture coordination task failed (capture_first={capture_first}): {error}"
            )
        })
        .and_then(|result| result);
        if let Err(error) = coordinated {
            // Closing the continuation releases the blocked observer before
            // this fixture and its private database directory are dropped.
            drop(resume);
            let _ = task.await;
            return Err(error.into());
        }
        let release = (|| -> TestResult<ArtifactDeliveryOutcomeV1> {
            Ok(f.runtime.release_into(
                &f.f.control,
                &RequestId::new("racing-knowledge")?,
                f.runtime.prepare_read(&f.f.control, &handle)?,
                &f.sink(),
            )?)
        })();
        let resumed = resume.send(());
        drop(resume);
        let response = task.await?;
        resumed?;
        let outcome = release?;
        let intent = super::acceptance::private_release_observation(&f, &outcome.release)?;
        if capture_first {
            // A captured operation keeps its original effect ownership. Later
            // knowledge can still close the connector's fresh dispatch check.
            if response
                .as_ref()
                .is_ok_and(|response| response.verdict == Verdict::Allow)
            {
                assert_eq!(f.f.effects.load(Ordering::SeqCst), 1);
            } else {
                assert_eq!(f.f.effects.load(Ordering::SeqCst), 0);
            }
        } else {
            assert!(
                response.is_err()
                    || response
                        .as_ref()
                        .is_ok_and(|response| response.verdict == Verdict::Deny)
            );
            assert_eq!(f.f.effects.load(Ordering::SeqCst), 0);
        }
        let snapshot =
            f.f.authority
                .admission_operation_store()
                .observe_security_participant_flow(
                    &f.profile.native_authority,
                    &recovery_flow_key(&f.profile.producer_context),
                    &f.f.authority.mutation_fence(),
                    now_ms()?,
                )?;
        assert!(
            snapshot
                .snapshot()
                .ok_or("native source")?
                .context_generation
                >= intent.observation_generation.get()
        );
        let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
        let captured:i64=connection.query_row("SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'semantic-capture:*'",[],|row|row.get(0))?;
        assert_eq!(captured, i64::from(capture_first));
    }
    Ok(())
}

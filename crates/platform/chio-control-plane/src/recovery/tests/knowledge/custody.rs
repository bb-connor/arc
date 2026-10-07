//! Replays and release outcomes exercise the public native knowledge boundary.
use super::*;

fn retained_count(f: &KnowledgeFixture, prefix: &str) -> TestResult<i64> {
    Ok(
        rusqlite::Connection::open(f.f.path.join("admission.db"))?.query_row(
            "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB ?1",
            [format!("{prefix}*")],
            |row| row.get(0),
        )?,
    )
}

#[test]
fn artifacts_handle_replay_reuses_scoped_custody_without_new_events() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("handle-replay", b"same-reference")?;
    let recipient = ArtifactRecipientId::new("agent-root")?;
    let first = f.runtime.handle(&f.f.control, &reference, &recipient)?;
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let events: i64 = connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_events",
        [],
        |row| row.get(0),
    )?;
    for _ in 0..64 {
        assert_eq!(
            f.runtime.handle(&f.f.control, &reference, &recipient)?,
            first
        );
    }
    assert_eq!(retained_count(&f, "knowledge-handle:")?, 1);
    let after: i64 = connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_events",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        after, events,
        "read retries must not consume durable work slots"
    );
    Ok(())
}

#[test]
fn memory_restore_replay_records_delivery_and_reuses_read_custody() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("restore-outcome", b"restore-content")?;
    let checkpoint = f.runtime.checkpoint(
        &f.f.control,
        &CheckpointId::new("restore-outcome")?,
        0,
        &[reference],
        &[],
    )?;
    let request = RequestId::new("restore-outcome")?;
    let sink = f.sink();
    let first = f
        .runtime
        .restore_into(&f.f.control, &checkpoint.checkpoint, 1, &request, &sink)?;
    for _ in 0..4 {
        assert_eq!(
            f.runtime
                .restore_into(&f.f.control, &checkpoint.checkpoint, 1, &request, &sink,)?
                .release,
            first.release,
        );
    }
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let state: String = connection.query_row(
        "SELECT json_extract(payload,'$.intent.state') FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-restore:*'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(state, "delivered");
    assert_eq!(retained_count(&f, "knowledge-handle:")?, 1);
    assert_eq!(retained_count(&f, "knowledge-join:")?, 1);
    Ok(())
}

#[test]
fn artifacts_prepared_read_refuses_current_contract_change_before_delivery() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("current-contract", b"private-current-contract")?;
    let handle = f.runtime.handle(
        &f.f.control,
        &reference,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    let prepared = f.runtime.prepare_read(&f.f.control, &handle)?;
    let mut profile = f.profile.clone();
    profile.generation = SafeInteger::new(2)?;
    profile.contract = ContractDigest::from_bytes([221; 32]);
    f.f.authority
        .admission_operation_store()
        .configure_knowledge(&profile)?;
    let sink = f.sink();
    assert!(f
        .runtime
        .release_into(
            &f.f.control,
            &RequestId::new("stale-contract-release")?,
            prepared,
            &sink,
        )
        .is_err());
    assert!(sink.delivered.lock().map_err(|_| "sink")?.is_empty());
    assert_eq!(retained_count(&f, "knowledge-join:")?, 0);
    Ok(())
}

#[test]
fn artifacts_delivery_acknowledgement_requires_original_capability() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("ack-authority", b"original-release")?;
    let handle = f.runtime.handle(
        &f.f.control,
        &reference,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    let store = f.f.authority.admission_operation_store();
    let actor = f.actor(RecoveryPermission::KnowledgeRead)?;
    let (record, _) =
        store.prepare_artifact_read(&actor, &handle, &f.f.authority.mutation_fence(), now_ms()?)?;
    let request = RequestId::new("ack-original")?;
    let intent = store.admit_artifact_release(
        &actor,
        &handle,
        &request,
        record.seal.as_ref().ok_or("seal")?,
        &f.f.authority.mutation_fence(),
        now_ms()?,
    )?;
    let other = f.f.kernel.issue_capability(
        &f.f.approval_key.public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "chio.recovery".into(),
                tool_name: RecoveryPermission::KnowledgeRead.wire_name().into(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..Default::default()
        },
        1200,
    )?;
    let other_actor = f.f.kernel.authenticate_recovery_actor(
        &f.profile.scope,
        &other,
        RecoveryPermission::KnowledgeRead,
    )?;
    assert!(store
        .acknowledge_artifact_delivery(
            &other_actor,
            &request,
            &intent,
            true,
            &f.f.authority.mutation_fence(),
            now_ms()?,
        )
        .is_err());
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let state: String = connection.query_row(
        "SELECT json_extract(payload,'$.intent.state') FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-release:*'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(state, "admitted");
    store.acknowledge_artifact_delivery(
        &actor,
        &request,
        &intent,
        true,
        &f.f.authority.mutation_fence(),
        now_ms()?,
    )?;
    Ok(())
}

#[test]
fn artifacts_available_publication_readback_survives_profile_generation_change() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let input = f.input("generation-readback", b"immutable-publication")?;
    let reference = f
        .runtime
        .publish(&f.f.control, &input, b"immutable-publication", None)?;
    let mut profile = f.profile.clone();
    profile.generation = SafeInteger::new(2)?;
    f.f.authority
        .admission_operation_store()
        .configure_knowledge(&profile)?;
    assert_eq!(
        f.runtime
            .publish(&f.f.control, &input, b"immutable-publication", None)?,
        reference,
    );
    assert_eq!(retained_count(&f, "knowledge-publication:")?, 1);
    Ok(())
}

#[test]
fn artifacts_lifecycle_ports_refuse_versions_above_actor_audience() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = publish_label(
        &f,
        "lifecycle-audience",
        b"restricted-reference",
        restricted_label(),
    )?;
    let mut deployment = f.f.kernel.recovery_deployment(&f.profile.scope)?;
    let mut actors = deployment.actors.as_slice().to_vec();
    actors[0].preview_clearance = InformationLabel::bottom();
    deployment.actors = NonEmptyBoundedList::new(actors)?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    let store = f.f.authority.admission_operation_store();
    store.configure_recovery_deployment(&deployment)?;
    let writer = f.actor(RecoveryPermission::KnowledgeWrite)?;
    let admin = f.actor(RecoveryPermission::KnowledgeAdmin)?;
    assert!(store
        .move_artifact(
            &writer,
            &reference,
            &ProtectedText::new("hidden-move")?,
            &f.f.authority.mutation_fence(),
            now_ms()?,
        )
        .is_err());
    assert!(store
        .pin_artifact(
            &admin,
            &reference,
            &EvidenceRef::new("hidden-pin")?,
            &f.f.authority.mutation_fence(),
            now_ms()?,
        )
        .is_err());
    assert_eq!(retained_count(&f, "knowledge-pin:")?, 0);
    Ok(())
}

#[test]
fn artifacts_public_reservation_omits_private_blob_custody() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let input = f.input("public-view", b"caller-supplied-bytes")?;
    let reference = f
        .runtime
        .publish(&f.f.control, &input, b"caller-supplied-bytes", None)?;
    let readback = serde_json::to_value(f.runtime.reserve(&f.f.control, &input)?)?;
    let object = readback.as_object().ok_or("publication view")?;
    assert!(!object.contains_key("object"));
    assert!(!object.contains_key("seal"));
    assert!(!object.contains_key("installation_generation"));
    assert_eq!(
        readback["metadata"]["content"],
        serde_json::to_value(input.content)?
    );
    let inventory =
        f.f.authority
            .admission_operation_store()
            .artifact_transfer_inventory(
                &f.actor(RecoveryPermission::KnowledgeRead)?,
                &reference,
                &f.f.authority.mutation_fence(),
                now_ms()?,
            )?;
    for entry in inventory {
        let encoded = serde_json::to_value(entry)?;
        let object = encoded.as_object().ok_or("public transfer view")?;
        for private in ["object", "seal", "installation_generation", "content"] {
            assert!(!object.contains_key(private));
        }
    }
    Ok(())
}

#[test]
fn artifacts_logical_object_quota_is_independent_of_equal_hidden_content() -> TestResult {
    let f = KnowledgeFixture::new()?;
    f.f.process.create_root(
        "quota-root",
        &f.f.control,
        ProcessLimits {
            max_processes: 1,
            max_depth: 0,
            max_calls: 1,
            state: chio_process::ProcessStateLimits {
                max_bytes: 8,
                max_blobs: 1,
            },
        },
    )?;
    let process = ProcessId::new("quota-root")?;
    let first = ArtifactObjectId::new("first-opaque-object")?;
    let seal = f.broker.stage(&first, &process, b"12345678")?;
    assert_eq!(f.broker.stage(&first, &process, b"12345678")?, seal);
    for (id, bytes) in [("same-guess", b"12345678"), ("other-guess", b"abcdefgh")] {
        assert!(
            f.broker
                .stage(&ArtifactObjectId::new(id)?, &process, bytes)
                .is_err(),
            "a new object must consume its own quota even when its bytes already exist"
        );
    }
    assert_eq!(f.broker.read_private(&seal)?, b"12345678");
    Ok(())
}

#[test]
fn artifacts_journal_activation_refuses_raw_routes_before_profile_registration() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let blob = f.process.put_blob("root", b"pre-activation-secret")?;
    assert_eq!(
        f.process.read_blob("root", &blob.sha256)?,
        b"pre-activation-secret"
    );
    let _broker = f.process.enable_durable_knowledge()?;
    assert!(!f
        .kernel
        .durable_knowledge_enforced(f.process.runtime_id())?);
    assert!(
        f.process.read_blob("root", &blob.sha256).is_err(),
        "journal activation must close raw read before profile registration"
    );
    assert!(f.process.put_blob("root", b"raw-after-activation").is_err());
    assert!(f.process.storage("root").is_err());
    assert!(f
        .process
        .checkpoint("root", 0, serde_json::json!({"raw":"after-activation"}))
        .is_err());
    assert!(chio_process::ProcessStateReader::open(f.path.join("process.db")).is_err());
    Ok(())
}

#[test]
fn memory_adoption_uses_finite_clearance_and_checks_certified_output() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let mut deployment = f.f.kernel.recovery_deployment(&f.profile.scope)?;
    let mut actors = deployment.actors.as_slice().to_vec();
    actors[0].preview_clearance = restricted_label();
    deployment.actors = NonEmptyBoundedList::new(actors)?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    f.f.authority
        .admission_operation_store()
        .configure_recovery_deployment(&deployment)?;
    f.runtime
        .reserve(
            &f.f.control,
            &f.input("finite-ordinary-control", b"ordinary")?,
        )
        .map_err(|error| format!("finite adoption: ordinary reservation control: {error}"))?;
    let mut input = f.input("finite-adoption", b"exact-certified-content")?;
    input.producer = ArtifactProducerV1::Adoption {
        evidence: EvidenceRef::new("finite-adoption")?,
    };
    let reservation = f.runtime.reserve(&f.f.control, &input).map_err(|error| {
        format!("finite adoption: reserve after finite actor installation: {error}")
    })?;
    let proof = certificate(&f, &reservation, restricted_label())?;
    let reference = f.runtime.publish(
        &f.f.control,
        &input,
        b"exact-certified-content",
        Some(&proof),
    )?;
    let handle = f.runtime.handle(
        &f.f.control,
        &reference,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    assert!(f.runtime.prepare_read(&f.f.control, &handle).is_ok());

    let mut denied = f.input("over-clearance-adoption", b"over-clearance-content")?;
    denied.producer = ArtifactProducerV1::Adoption {
        evidence: EvidenceRef::new("over-clearance-adoption")?,
    };
    let reservation = f.runtime.reserve(&f.f.control, &denied)?;
    let proof = certificate(&f, &reservation, InformationLabel::Top)?;
    assert!(f
        .runtime
        .publish(
            &f.f.control,
            &denied,
            b"over-clearance-content",
            Some(&proof)
        )
        .is_err());
    assert_eq!(retained_count(&f, "knowledge-version:")?, 1);
    Ok(())
}

#[test]
fn artifacts_strengthened_producer_quarantines_incomplete_publication() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let input = f.input(
        "strengthened-publication",
        b"preparation-under-public-source",
    )?;
    let faulty = f.runtime.clone().with_test_cutpoint(Arc::new(|stage| {
        if stage == crate::knowledge::KnowledgeCutpoint::MetadataCommitted {
            Err(KernelError::Internal(
                "metadata acknowledgement lost".into(),
            ))
        } else {
            Ok(())
        }
    }));
    assert!(faulty
        .publish(
            &f.f.control,
            &input,
            b"preparation-under-public-source",
            None
        )
        .is_err());
    let restricted = publish_label(
        &f,
        "strengthening-source",
        b"restricted-observation",
        restricted_label(),
    )?;
    let handle = f.runtime.handle(
        &f.f.control,
        &restricted,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    f.runtime.release_into(
        &f.f.control,
        &RequestId::new("strengthen-producer")?,
        f.runtime.prepare_read(&f.f.control, &handle)?,
        &f.sink(),
    )?;
    assert!(f
        .runtime
        .publish(
            &f.f.control,
            &input,
            b"preparation-under-public-source",
            None
        )
        .is_err());
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let state: String = connection.query_row(
        "SELECT json_extract(payload,'$.state') FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-publication:*'
          AND json_extract(payload,'$.input.publication')='strengthened-publication'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(state, "quarantined");
    Ok(())
}

#[test]
fn artifacts_delivery_acknowledgement_loss_retains_uncertain_custody() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let reference = f.publish("ack-loss", b"delivered-without-host-ack")?;
    let handle = f.runtime.handle(
        &f.f.control,
        &reference,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    let faulty = f.runtime.clone().with_test_cutpoint(Arc::new(|stage| {
        if stage == crate::knowledge::KnowledgeCutpoint::DeliveryCompleted {
            Err(KernelError::Internal(
                "delivery acknowledgement lost".into(),
            ))
        } else {
            Ok(())
        }
    }));
    let sink = f.sink();
    assert!(faulty
        .release_into(
            &f.f.control,
            &RequestId::new("lost-delivery-ack")?,
            f.runtime.prepare_read(&f.f.control, &handle)?,
            &sink
        )
        .is_err());
    assert_eq!(sink.delivered.lock().map_err(|_| "sink")?.len(), 1);
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let state: String = connection.query_row(
        "SELECT json_extract(payload,'$.intent.state') FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-release:*'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(state, "uncertain");
    assert!(f.runtime.collect(&f.f.control, &reference).is_err());
    Ok(())
}

#[test]
fn artifacts_publication_request_id_is_partitioned_by_authenticated_actor() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let first = f.publish("actor-local-id", b"first-actor-content")?;
    let second_key = Keypair::from_seed(&[219; 32]);
    let mut deployment = f.f.kernel.recovery_deployment(&f.profile.scope)?;
    let mut actors = deployment.actors.as_slice().to_vec();
    let mut second = actors[0].clone();
    second.subject = second_key.public_key();
    second.principal = PrincipalId::new("second-knowledge-actor")?;
    actors.push(second);
    deployment.actors = NonEmptyBoundedList::new(actors)?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    f.f.authority
        .admission_operation_store()
        .configure_recovery_deployment(&deployment)
        .map_err(|error| format!("actor partition: install independent actor: {error}"))?;
    let second =
        f.f.kernel
            .issue_capability(&second_key.public_key(), f.f.control.scope.clone(), 1200)?;
    f.runtime
        .publish(
            &second,
            &f.input("second-actor-ordinary-control", b"independent-control")?,
            b"independent-control",
            None,
        )
        .map_err(|error| format!("actor partition: independent fresh-ID control: {error}"))?;
    let second_input = f.input("actor-local-id", b"second-actor-content")?;
    let second_reference = f
        .runtime
        .publish(&second, &second_input, b"second-actor-content", None)
        .map_err(|error| {
            format!("actor partition: publish existing display ID as second actor: {error}")
        })?;
    assert_ne!(first.artifact, second_reference.artifact);
    let recipient = ArtifactRecipientId::new("agent-root")?;
    let first_handle = f.runtime.handle(&f.f.control, &first, &recipient)?;
    let second_handle = f.runtime.handle(&second, &second_reference, &recipient)?;
    let first_sink = f.sink();
    let second_sink = f.sink();
    let request = RequestId::new("actor-local-release")?;
    f.runtime.release_into(
        &f.f.control,
        &request,
        f.runtime.prepare_read(&f.f.control, &first_handle)?,
        &first_sink,
    )?;
    f.runtime.release_into(
        &second,
        &request,
        f.runtime.prepare_read(&second, &second_handle)?,
        &second_sink,
    )?;
    assert_eq!(
        first_sink.delivered.lock().map_err(|_| "sink")?.as_slice(),
        &[b"first-actor-content".to_vec()]
    );
    assert_eq!(
        second_sink.delivered.lock().map_err(|_| "sink")?.as_slice(),
        &[b"second-actor-content".to_vec()]
    );
    Ok(())
}

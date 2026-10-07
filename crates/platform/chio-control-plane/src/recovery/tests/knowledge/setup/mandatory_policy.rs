//! Trusted native setup policy closes new work before the first selection.
use super::*;

#[tokio::test]
async fn setup_required_policy_refuses_a_bare_runtime_before_any_selection_exists() -> TestResult {
    let f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let mut value = serde_json::to_value(f.f.kernel.recovery_deployment(f.f.runtime.scope())?)?;
    value
        .as_object_mut()
        .ok_or("native deployment object")?
        .insert(
            "setup_policy".into(),
            serde_json::json!({
                "operator_root": Keypair::from_seed(&[211; 32]).public_key(),
            }),
        );
    let mut deployment: RecoveryDeploymentV1 = chio_core_types::recovery::decode_contract(
        &chio_core_types::canonical_json_bytes(&value)?,
    )?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    f.f.authority
        .admission_operation_store()
        .configure_recovery_deployment(&deployment)?;
    let original = Box::pin(f.f.denied_seed_named("mandatory-first-setup-original")).await?;
    require_eligible_original(&f, &original)?;
    let command = f.f.command(
        "mandatory-first-setup-create",
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new("mandatory-first-setup")?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: text(&original)?,
        },
    )?;
    let bare = crate::recovery::RecoveryRuntime::new(
        f.f.kernel.clone(),
        f.f.process.clone(),
        f.f.runtime.flow.clone(),
        f.f.runtime.scope().clone(),
        f.f.runtime.signer.clone(),
    )?;
    let calls = f.f.process.process("root")?.tree_calls;
    assert_eq!(
        bare.execute_command(&f.f.control, &command).await.err(),
        Some(crate::recovery::RecoveryRuntimeError::UncoveredMediation),
        "deployment-selected protection must apply before the first self-test selection"
    );
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let selections: i64 = connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key LIKE 'protected-setup:%' OR record_key LIKE 'protected-setup:v2:%'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(selections, 0);
    let workflows: i64 = connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records WHERE kind='workflow'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(workflows, 0);
    Ok(())
}

#[tokio::test]
async fn setup_selected_operator_root_refuses_a_different_trusted_host_key_before_pinning(
) -> TestResult {
    let f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let workflow = Box::pin(f.f.ready()).await?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let mut deployment = f.f.kernel.recovery_deployment(f.f.runtime.scope())?;
    deployment.setup_policy = Some(chio_kernel::recovery::NativeSetupPolicyV1 {
        operator_root: Keypair::from_seed(&[212; 32]).public_key(),
    });
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    store.configure_recovery_deployment(&deployment)?;
    let actor = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &f.f.control,
        RecoveryPermission::Inspect,
    )?;
    f.runtime
        .validate_setup_binding(f.f.runtime.scope(), &deployment.native_authority)?;
    assert!(actor.permission() == RecoveryPermission::Inspect);
    let record = f.f.record(&workflow)?;
    assert!(!record.captured && record.native_link.is_none());
    let calls = f.f.process.process("root")?.tree_calls;
    let records = || -> TestResult<Vec<(String, u64, Vec<u8>)>> {
        let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
        let mut statement = connection.prepare(
            "SELECT record_key,version,payload FROM admission_operation_recovery_records ORDER BY record_key",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        rows.map(|row| {
            let (key, version, payload) = row?;
            Ok((key, u64::try_from(version)?, payload))
        })
        .collect()
    };
    let before = records()?;
    let result = store.configure_protected_setup(
        f.f.runtime.scope(),
        &workflow,
        &f.f.kernel.receipt_signing_public_key(),
        &Keypair::from_seed(&[211; 32]).public_key(),
        &fence,
        now_ms()?,
    );
    assert!(result.is_err(), "a trusted semantic operator cannot substitute for the distinct deployment-selected setup root");
    assert_eq!(records()?, before);
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    Ok(())
}

#[tokio::test]
async fn setup_required_policy_accepts_the_exact_pinned_operator_and_live_mediator() -> TestResult {
    let f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let mut deployment = f.f.kernel.recovery_deployment(f.f.runtime.scope())?;
    deployment.setup_policy = Some(chio_kernel::recovery::NativeSetupPolicyV1 {
        operator_root: Keypair::from_seed(&[211; 32]).public_key(),
    });
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    store.configure_recovery_deployment(&deployment)?;
    let original = Box::pin(f.f.denied_seed_named("pinned-operator-self-test")).await?;
    require_eligible_original(&f, &original)?;
    let command = f.f.command(
        "pinned-operator-self-test-create",
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new("pinned-operator-self-test")?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: text(&original)?,
        },
    )?;
    let calls = f.f.process.process("root")?.tree_calls;
    let ordinary_calls = || -> TestResult<Vec<(String, String, String, i64)>> {
        let connection = rusqlite::Connection::open(f.f.path.join("process.db"))?;
        let mut statement = connection.prepare(
            "SELECT process_id,operation_key,request_hash,attempts FROM process_calls ORDER BY process_id,operation_key",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    };
    let native_operations = || -> TestResult<Vec<(String, String, String, Vec<u8>)>> {
        let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
        let mut statement = connection.prepare(
            "SELECT operation_id,request_namespace_digest,request_id,operation_json FROM admission_operations ORDER BY operation_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    };
    let before_calls = ordinary_calls()?;
    let before_operations = native_operations()?;
    let service = RecoverySetupService::for_creation(
        RecoverySetupHost {
            runtime: f.f.runtime.clone(),
            store: Arc::new(store.clone()),
            fence: fence.clone(),
            knowledge: Some(Arc::new(f.runtime.clone())),
            operator: Keypair::from_seed(&[211; 32]),
        },
        &f.f.control,
        &command,
    )
    .await?;
    let actor = f.actor(RecoveryPermission::Inspect)?;
    assert!(actor.permission() == RecoveryPermission::Inspect);
    let prepared =
        f.f.authority
            .admission_operation_store()
            .configure_protected_setup(
                f.f.runtime.scope(),
                service.workflow(),
                &f.f.kernel.receipt_signing_public_key(),
                &Keypair::from_seed(&[211; 32]).public_key(),
                &fence,
                now_ms()?,
            )?;
    assert_eq!(&prepared.probe.benign_workflow, service.workflow());
    assert!(prepared.signed_probe.is_none() && prepared.report.is_none());
    let retained = f.f.record(service.workflow())?;
    assert!(!retained.captured && retained.native_link.is_none());
    let reservation: chio_process::RecoveryCallReservation =
        chio_core_types::recovery::decode_contract(
            retained
                .process_reservation
                .as_ref()
                .ok_or("the exact setup recovery reservation")?
                .as_str()
                .as_bytes(),
        )?;
    assert_eq!(
        reservation.process_id(),
        f.f.runtime.scope().process_id.as_str()
    );
    assert_eq!(reservation.continuation_id(), &retained.continuation_id);
    assert_eq!(
        reservation.operation_key(),
        crate::recovery::materialize::operation_key(&retained.continuation_id)
    );
    let data: chio_kernel::recovery::RecoveryProcessReservationV1 =
        serde_json::from_slice(&chio_core_types::canonical_json_bytes(&reservation)?)?;
    chio_kernel::recovery::RecoveryProcessReservationPort::verify_reservation(&f.f.process, &data)?;
    assert_eq!(ordinary_calls()?, before_calls);
    assert_eq!(native_operations()?, before_operations);
    assert_eq!(retained_workflow_count(&f)?, 1);
    assert_eq!(external_count(&f.f.path)?, 0);
    let reserved_calls = calls
        .checked_add(1)
        .ok_or("logical call counter exhausted")?;
    assert_eq!(f.f.process.process("root")?.tree_calls, reserved_calls);
    let replayed = RecoverySetupService::for_creation(
        RecoverySetupHost {
            runtime: f.f.runtime.clone(),
            store: Arc::new(store),
            fence,
            knowledge: Some(Arc::new(f.runtime.clone())),
            operator: Keypair::from_seed(&[211; 32]),
        },
        &f.f.control,
        &command,
    )
    .await?;
    assert_eq!(replayed.workflow(), service.workflow());
    assert_eq!(
        f.f.record(service.workflow())?.process_reservation,
        retained.process_reservation
    );
    assert_eq!(retained_workflow_count(&f)?, 1);
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, reserved_calls);
    assert_eq!(ordinary_calls()?, before_calls);
    assert_eq!(native_operations()?, before_operations);
    Ok(())
}

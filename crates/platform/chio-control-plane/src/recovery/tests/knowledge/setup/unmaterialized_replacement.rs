//! An interrupted setup creation keeps its original identity across replacement.
use super::*;

type NativeOperationRow = (String, String, String, Vec<u8>);

fn native_operations(f: &KnowledgeFixture) -> TestResult<Vec<NativeOperationRow>> {
    let connection = rusqlite::Connection::open_with_flags(
        f.f.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let mut statement = connection.prepare(
        "SELECT operation_id,request_namespace_digest,request_id,operation_json \
         FROM admission_operations ORDER BY operation_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn require_unmaterialized(record: &RecoveryWorkflowRecordV1) -> TestResult {
    assert!(record.origin.is_some());
    assert_eq!(record.revision.get(), 1);
    assert_eq!(record.control, WorkflowControlV1::Active);
    assert!(record.action.is_none() && record.process_reservation.is_none());
    assert!(!record.selected);
    assert!(record.review.is_none() && record.approval.is_none());
    assert!(record.issuance.is_none() && record.signed_grant.is_none());
    assert!(record.envelope.is_none() && record.admission.is_none());
    assert!(!record.admission_closed && !record.captured);
    assert!(record.native_link.is_none() && record.historical_hold.is_none());
    assert_eq!(record.effect, EffectObservationV1::NeverAdmitted);
    assert!(record.original_flow.is_none());
    Ok(())
}

#[tokio::test]
async fn interrupted_unmaterialized_setup_can_replace_its_writer_without_reusing_the_old_identity(
) -> TestResult {
    eprintln!("setup replacement phase=original native fixture");
    let mut f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let original = Box::pin(f.f.denied_seed_named("interrupted-setup-original")).await?;
    require_eligible_original(&f, &original)?;
    let creation = f.f.command(
        "interrupted-setup-create",
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new("interrupted-setup-original")?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: text(&original)?,
        },
    )?;
    let calls_before_pin = f.f.process.process("root")?.tree_calls;
    let operations_before_pin = native_operations(&f)?;
    let (workflow, previous, probe) = {
        let store = f.f.authority.admission_operation_store();
        let fence = f.f.authority.mutation_fence();
        let selected = f.f.kernel.recovery_deployment(f.f.runtime.scope())?;
        f.runtime
            .validate_setup_binding(f.f.runtime.scope(), &selected.native_authority)?;
        let creator = f.f.kernel.authenticate_recovery_actor(
            f.f.runtime.scope(),
            &f.f.control,
            RecoveryPermission::Create,
        )?;
        eprintln!("setup replacement phase=durable pin before materialization");
        // This is the real durable boundary before for_creation executes the
        // command and materializes its Action and process reservation.
        let workflow = store.pin_setup_creation(
            &creator,
            &creation,
            NativeSetupCreationHost {
                receipt_key: &f.f.kernel.receipt_signing_public_key(),
                operator: &Keypair::from_seed(&[211; 32]).public_key(),
                process: &f.f.process,
            },
            &fence,
            now_ms()?,
        )?;
        let record = f.f.record(&workflow)?;
        require_unmaterialized(&record)?;
        assert_eq!(record.creation_seed, text(&original)?);
        let preparation = store.configure_protected_setup(
            f.f.runtime.scope(),
            &workflow,
            &f.f.kernel.receipt_signing_public_key(),
            &Keypair::from_seed(&[211; 32]).public_key(),
            &fence,
            now_ms()?,
        )?;
        assert_eq!(preparation.probe.benign_workflow, workflow);
        assert!(preparation.signed_probe.is_none() && preparation.report.is_none());
        (workflow, record, preparation.probe)
    };
    assert_eq!(native_operations(&f)?, operations_before_pin);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls_before_pin);
    assert_eq!(external_count(&f.f.path)?, 0);
    let path = f.f.path.clone();
    let directory = f.f._directory.take();
    drop(f);

    eprintln!("setup replacement phase=same-path new serving writer");
    let reopened = KnowledgeFixture::from(RecoveryFixture::open(path, directory, false)?)?;
    let store = reopened.f.authority.admission_operation_store();
    let fence = reopened.f.authority.mutation_fence();
    let inspector = reopened.f.kernel.authenticate_recovery_actor(
        reopened.f.runtime.scope(),
        &reopened.f.control,
        RecoveryPermission::Inspect,
    )?;
    let preserved = reopened.f.record(&workflow)?;
    require_unmaterialized(&preserved)?;
    assert_eq!(
        chio_core_types::canonical_json_bytes(&preserved)?,
        chio_core_types::canonical_json_bytes(&previous)?
    );
    let preparation = store.configure_protected_setup(
        reopened.f.runtime.scope(),
        &workflow,
        &reopened.f.kernel.receipt_signing_public_key(),
        &Keypair::from_seed(&[211; 32]).public_key(),
        &fence,
        now_ms()?,
    )?;
    assert_eq!(preparation.probe, probe);
    let before_refusal = journal_availability::retained_setup_records(&reopened)?;
    let calls_before_refusal = reopened.f.process.process("root")?.tree_calls;
    eprintln!("setup replacement phase=authenticated changed-writer refusal");
    assert!(matches!(
        store.setup_preparation(&inspector, &fence, now_ms()?),
        Err(NativeSetupPreparationError::WriterChanged)
    ));
    assert_eq!(
        journal_availability::retained_setup_records(&reopened)?,
        before_refusal
    );
    assert_eq!(
        reopened.f.process.process("root")?.tree_calls,
        calls_before_refusal
    );
    assert_eq!(external_count(&reopened.f.path)?, 0);

    eprintln!("setup replacement phase=fresh current original and mediator");
    let replacement_seed =
        Box::pin(reopened.f.denied_seed_named("new-writer-setup-original")).await?;
    require_eligible_original(&reopened, &replacement_seed)?;
    let deployment = reopened
        .f
        .kernel
        .recovery_deployment(reopened.f.runtime.scope())?;
    reopened
        .runtime
        .validate_setup_binding(reopened.f.runtime.scope(), &deployment.native_authority)?;
    let creator = reopened.f.kernel.authenticate_recovery_actor(
        reopened.f.runtime.scope(),
        &reopened.f.control,
        RecoveryPermission::Create,
    )?;
    let replacement = reopened.f.command(
        "new-writer-setup-create",
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new("new-writer-setup-original")?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: text(&replacement_seed)?,
        },
    )?;
    let calls_before_replacement = reopened.f.process.process("root")?.tree_calls;
    let operations_before_replacement = native_operations(&reopened)?;
    eprintln!("setup replacement phase=replacement pin");
    let replaced = store.pin_setup_creation(
        &creator,
        &replacement,
        NativeSetupCreationHost {
            receipt_key: &reopened.f.kernel.receipt_signing_public_key(),
            operator: &Keypair::from_seed(&[211; 32]).public_key(),
            process: &reopened.f.process,
        },
        &fence,
        now_ms()?,
    ).map_err(|error| format!("unmaterialized selection replacement after genuine changed-writer, original and mediator controls: {error}"))?;
    assert_ne!(replaced, workflow);
    let closed = reopened.f.record(&workflow)?;
    let mut expected = previous.clone();
    expected.control = WorkflowControlV1::Cancelled;
    expected.admission_closed = true;
    expected.revision = SafeInteger::new(
        previous
            .revision
            .get()
            .checked_add(1)
            .ok_or("setup closure revision overflow")?,
    )?;
    assert_eq!(
        chio_core_types::canonical_json_bytes(&closed)?,
        chio_core_types::canonical_json_bytes(&expected)?
    );
    require_unmaterialized(&reopened.f.record(&replaced)?)?;
    assert_eq!(
        reopened.f.process.process("root")?.tree_calls,
        calls_before_replacement
    );
    assert_eq!(native_operations(&reopened)?, operations_before_replacement);
    assert_eq!(external_count(&reopened.f.path)?, 0);

    eprintln!("setup replacement phase=healthy replacement materialization");
    let service = RecoverySetupService::for_creation(
        RecoverySetupHost {
            runtime: reopened.f.runtime.clone(),
            store: Arc::new(store.clone()),
            fence: fence.clone(),
            knowledge: Some(Arc::new(reopened.runtime.clone())),
            operator: Keypair::from_seed(&[211; 32]),
        },
        &reopened.f.control,
        &replacement,
    )
    .await?;
    assert_eq!(service.workflow(), &replaced);
    let actual = reopened.f.record(&replaced)?;
    assert!(actual.action.is_some() && actual.process_reservation.is_some());
    assert!(!actual.captured && actual.native_link.is_none());
    assert_eq!(
        reopened.f.process.process("root")?.tree_calls,
        calls_before_replacement + 1
    );
    assert_eq!(native_operations(&reopened)?, operations_before_replacement);
    assert_eq!(external_count(&reopened.f.path)?, 0);

    let late = reopened
        .f
        .command("closed-setup-fresh-create-alias", creation.command.clone())?;
    let before_late = journal_availability::retained_setup_records(&reopened)?;
    let calls_before_late = reopened.f.process.process("root")?.tree_calls;
    eprintln!("setup replacement phase=closed original cannot materialize");
    assert!(reopened
        .f
        .runtime
        .execute_command(&reopened.f.control, &late)
        .await
        .is_err());
    assert_eq!(
        journal_availability::retained_setup_records(&reopened)?,
        before_late
    );
    assert_eq!(
        chio_core_types::canonical_json_bytes(&reopened.f.record(&workflow)?)?,
        chio_core_types::canonical_json_bytes(&expected)?
    );
    assert_eq!(
        reopened.f.process.process("root")?.tree_calls,
        calls_before_late
    );
    assert_eq!(native_operations(&reopened)?, operations_before_replacement);
    assert_eq!(external_count(&reopened.f.path)?, 0);
    Ok(())
}

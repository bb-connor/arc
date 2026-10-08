//! Selected Input custody follows the genuine tenant counter across independent keys.
use super::*;
use chio_kernel::tool_outcome::ToolOutcomeStore;
use chio_kernel::{SecurityInvocationContext, ToolCallResponse};

fn assert_signed_deny(
    f: &RecoveryFixture,
    request: &ToolCallRequest,
    response: &ToolCallResponse,
) -> TestResult {
    assert_eq!(response.request_id, request.request_id);
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert!(response.receipt.verify_signature()?);
    assert_eq!(
        response.receipt.kernel_key,
        f.kernel.receipt_signing_public_key()
    );
    assert_eq!(response.receipt.capability_id, request.capability.id);
    assert_eq!(response.receipt.tool_server, request.server_id);
    assert_eq!(response.receipt.tool_name, request.tool_name);
    assert_eq!(response.receipt.action.parameters, request.arguments);
    Ok(())
}

fn owned_input_generation(
    f: &RecoveryFixture,
    request: &ToolCallRequest,
    context: &SecurityInvocationContext,
) -> TestResult<u64> {
    let store = f.authority.admission_operation_store();
    let fence = f.authority.mutation_fence();
    let deployment = f.kernel.recovery_deployment(f.runtime.scope())?;
    let (operation, original) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("real native Input original absent")?;
    original.validate_binding(operation.binding())?;
    original.validate_request_material(request)?;
    original.validate_native_security_authority(&deployment.native_authority)?;
    original.validate_native_security_context(context)?;
    let (loaded, input) = store
        .load_native_security_input_join(operation.binding().operation_id(), &fence, now_ms()?)?
        .ok_or("real native Input operation absent")?;
    let input = input.ok_or(
        "same-operation native Input journal absent after the unrelated tenant counter advanced",
    )?;
    input.validate()?;
    assert_eq!(loaded, operation);
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    assert!(operation.native_dispatch_ledger_digest().is_none());
    assert_eq!(
        input.input.operation_id(),
        operation.binding().operation_id()
    );
    assert_eq!(input.input.key(), &recovery_flow_key(context));
    assert_eq!(input.join.binding, deployment.native_authority);
    let connection = rusqlite::Connection::open_with_flags(
        f.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    connection.execute_batch("PRAGMA query_only=ON; BEGIN;")?;
    let (bytes, digest, sequence): (Vec<u8>, String, i64) = connection.query_row(
        "SELECT canonical_record,mutation_digest,sequence
         FROM main.security_participant_state_mutations WHERE operation_id=?1",
        [operation.binding().operation_id().as_str()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let body: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(chio_core::canonical_json_bytes(&body)?, bytes);
    assert_eq!(body["input"], serde_json::to_value(&input.input)?);
    assert_eq!(body["result"], serde_json::to_value(&input.join.snapshot)?);
    let mut commitment = b"chio.native-security-mutation.commit.v1\0".to_vec();
    commitment.extend_from_slice(&bytes);
    assert_eq!(chio_core::sha256_hex(&commitment), digest);
    assert_eq!(input.join.mutation_digest.as_str(), digest);
    let global: i64 = connection.query_row(
        "SELECT commit_sequence FROM main.authority_global_commits
         WHERE projection_kind='security_participant_state' AND projection_key=?1
           AND projection_sequence=?2 AND projection_reference_digest=?3",
        rusqlite::params![
            deployment.native_authority.security_authority_id().as_str(),
            sequence,
            digest
        ],
        |row| row.get(0),
    )?;
    assert!(global > 0);
    assert!(store
        .load_security_participant_output(operation.binding().operation_id(), &fence, now_ms()?)?
        .is_none());
    assert!(f
        .authority
        .tool_outcome_store()
        .load_raw_invocation_by_operation(operation.binding().operation_id())?
        .is_none());
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    assert_eq!(external_count(&f.path)?, 0);
    Ok(input.join.snapshot.context_generation)
}

async fn install_changed_selected_answer(
    f: &RecoveryFixture,
    request: &mut ToolCallRequest,
    profile: &mut SemanticFixture,
) -> TestResult {
    let neutral = SignedSemanticAnnotationV1::sign(
        SemanticAnnotationV1 {
            domain_version: VersionV1,
            scope: profile.plan.scope.clone(),
            input: profile.invocation.action.inputs.as_slice()[0].clone(),
            restrictions: InformationLabel::bottom(),
            externally_influenced: false,
            facts: BoundedList::new(vec![])?,
            confidence_basis_points: SafeInteger::new(10_000)?,
            issued_at_unix_ms: profile.invocation.action.issued_at_unix_ms,
            valid_until_unix_ms: profile.invocation.action.valid_until_unix_ms,
        },
        &profile.annotator,
    )?;
    let store = f.authority.admission_operation_store();
    store.install_semantic_annotation(&neutral)?;
    profile.invocation.action.influence = chio_semantic_contracts::semantic_annotated_influence(
        profile.invocation.action.influence,
        std::slice::from_ref(&neutral),
    )?;
    profile.invocation.annotations = BoundedList::new(vec![neutral.clone()])?;
    request.arguments = serde_json::to_value(&profile.invocation)?;
    assert!(!profile.invocation.action.externally_influenced);
    assert!(request.model_metadata.is_none());
    let issued = now_ms()?.max(
        neutral
            .body()
            .issued_at_unix_ms
            .get()
            .checked_add(1)
            .ok_or("annotation clock overflow")?,
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while now_ms()? < issued {
        if std::time::Instant::now() >= deadline {
            return Err("annotation authority clock did not advance".into());
        }
        tokio::task::yield_now().await;
    }
    let mut current = neutral.body().clone();
    current.externally_influenced = true;
    current.issued_at_unix_ms = SafeInteger::new(issued)?;
    current.valid_until_unix_ms = SafeInteger::new(
        issued
            .checked_add(50_000)
            .ok_or("annotation deadline overflow")?,
    )?;
    let current = SignedSemanticAnnotationV1::sign(current, &profile.annotator)?;
    assert_ne!(
        chio_core::canonical_json_bytes(&current)?,
        chio_core::canonical_json_bytes(&neutral)?
    );
    store.install_semantic_annotation(&current)?;
    assert!(now_ms()? < profile.invocation.action.valid_until_unix_ms.get());
    Ok(())
}

#[tokio::test]
async fn native_refused_input_retains_the_tenant_generation_after_an_unrelated_owned_input(
) -> TestResult {
    let f = empty_import::native_fixture_from_empty_import("trusted-annotated-read").await?;
    let deployment = f.kernel.recovery_deployment(f.runtime.scope())?;
    let key = recovery_flow_key(&deployment.security_context);
    let store = f.authority.admission_operation_store();
    let fence = f.authority.mutation_fence();
    let observed = store.observe_security_participant_flow(
        &deployment.native_authority,
        &key,
        &fence,
        now_ms()?,
    )?;
    let before = observed
        .snapshot()
        .ok_or("original genuine Input source absent")?
        .clone();
    let other_principal = Keypair::from_seed(&[152; 32]);
    let other_capability = f.kernel.issue_capability(
        &other_principal.public_key(),
        f.seed.capability.scope.clone(),
        600,
    )?;
    let other = ProcessRuntime::open(f.path.join("unrelated-native-process.db"), f.kernel.clone())?
        .with_security_profile(ProcessSecurityProfile {
            tenant_id: "native-tenant".into(),
            isolation_epoch_id: "native-epoch".into(),
            generation: 1,
        })?;
    other.create_root(
        "unrelated-root",
        &other_capability,
        ProcessLimits {
            max_processes: 8,
            max_depth: 2,
            max_calls: 8,
            state: Default::default(),
        },
    )?;
    let other_context = other.recovery_security_context("unrelated-root")?;
    let other_key = recovery_flow_key(&other_context);
    assert_ne!(other_key.principal_id, key.principal_id);
    assert_ne!(other_key.lineage_id, key.lineage_id);
    assert_ne!(other_key.session_id, key.session_id);
    assert_eq!(other_key.tenant_id, key.tenant_id);
    let other_request = other.tool_request(
        "unrelated-root",
        "unrelated-native-input",
        &f.seed.server_id,
        &f.seed.tool_name,
        f.seed.arguments.clone(),
    )?;
    let other_response = Box::pin(other.invoke_known_only(
        "unrelated-root",
        "unrelated-native-input",
        &other_request,
    ))
    .await?;
    assert_signed_deny(&f, &other_request, &other_response)?;
    let other_generation = owned_input_generation(&f, &other_request, &other_context)?;
    assert!(other_generation > before.context_generation);
    let unchanged = store.observe_security_participant_flow(
        &deployment.native_authority,
        &key,
        &fence,
        now_ms()?,
    )?;
    assert_eq!(unchanged.snapshot(), Some(&before));
    let (runtime, mut request, mut profile) = prepare(
        &f,
        "refused-after-unrelated-input",
        SemanticOutputDispositionV1::Withhold,
    )?;
    install_changed_selected_answer(&f, &mut request, &mut profile).await?;
    eprintln!("native Input generation: unrelated genuine Input committed at {other_generation}; original context retained at {}", before.context_generation);
    let response = runtime
        .execute_step(
            &f.process,
            "root",
            "refused-after-unrelated-input",
            &request,
        )
        .await;
    let uncommitted_signed_deny = if let Ok(response) = &response {
        assert_signed_deny(&f, &request, response)?;
        let (operation, _) = store
            .load_unambiguous_retained_tool_request(
                &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
                &fence,
                now_ms()?,
            )?
            .ok_or("signed denial original absent")?;
        let (_, input) = store
            .load_native_security_input_join(operation.binding().operation_id(), &fence, now_ms()?)?
            .ok_or("signed denial native operation absent")?;
        input.is_none()
    } else {
        false
    };
    if response.is_err() || uncommitted_signed_deny {
        let (operation, original) = store
            .load_unambiguous_retained_tool_request(
                &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
                &fence,
                now_ms()?,
            )?
            .ok_or("failed selected Input original absent")?;
        original.validate_binding(operation.binding())?;
        original.validate_request_material(&request)?;
        original.validate_native_security_authority(&deployment.native_authority)?;
        original.validate_native_security_context(&deployment.security_context)?;
        let (_, input) = store
            .load_native_security_input_join(operation.binding().operation_id(), &fence, now_ms()?)?
            .ok_or("failed selected Input operation absent")?;
        assert!(
            input.is_none(),
            "failed join unexpectedly committed an Input journal"
        );
        assert!(operation.dispatch_commit().is_none());
        assert!(operation.native_dispatch_ledger_digest().is_none());
        assert!(store
            .load_security_participant_output(
                operation.binding().operation_id(),
                &fence,
                now_ms()?
            )?
            .is_none());
        assert!(f
            .authority
            .tool_outcome_store()
            .load_raw_invocation_by_operation(operation.binding().operation_id())?
            .is_none());
        let rolled_back = store.observe_security_participant_flow(
            &deployment.native_authority,
            &key,
            &fence,
            now_ms()?,
        )?;
        assert_eq!(rolled_back.snapshot(), Some(&before));
        assert_eq!(f.effects.load(Ordering::SeqCst), 0);
        assert_eq!(external_count(&f.path)?, 0);
        match &response {
            Err(error) => {
                eprintln!("native Input generation: no selected Input committed; original snapshot restored; actual public failure {error}");
            }
            Ok(_) => {
                assert_eq!(
                    operation.state(),
                    AdmissionOperationState::CompensatedBeforeDispatch
                );
                eprintln!("native Input generation: actual signed Deny without a committed selected Input; original snapshot restored");
            }
        }
    }
    if uncommitted_signed_deny {
        return Err("selected Input was rolled back before immutable commit; owning cause requires the real precommit source/result diagnostics and unchanged validator error".into());
    }
    // Attribution comes from the real pre-validator source/result diagnostics
    // in the narrow owning hook, not from the rolled-back journal's absence.
    let response = response?;
    assert_signed_deny(&f, &request, &response)?;
    let actual_generation = owned_input_generation(&f, &request, &deployment.security_context)?;
    assert_eq!(
        actual_generation,
        other_generation
            .checked_add(1)
            .ok_or("tenant generation overflow")?
    );
    let after = store.observe_security_participant_flow(
        &deployment.native_authority,
        &key,
        &fence,
        now_ms()?,
    )?;
    assert_eq!(
        after
            .snapshot()
            .ok_or("selected native source absent")?
            .context_generation,
        actual_generation
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    assert_eq!(external_count(&f.path)?, 0);
    Ok(())
}

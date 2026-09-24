// Real signed downgrade authority, monotone native state, no legacy use store.
use super::*;

mod matrix {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_declassification_matrix_tests.rs"
    ));
}

mod rejection {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_declassification_rejection_tests.rs"
    ));
}

mod faults {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_declassification_fault_tests.rs"
    ));
}

fn fixture() -> TestResult<Fixture> {
    Ok(profile(false, 300)?.0)
}

pub(in crate::security::adapters::tests::native_flow::support) fn profile(
    combined: bool,
    grant_ttl_secs: u64,
) -> TestResult<(Fixture, Keypair)> {
    let fixture = if combined {
        Fixture::combined_native_declassification_credentials()?
    } else {
        Fixture::new_with_declassification_profile()?
    };
    configure(fixture, grant_ttl_secs)
}

fn configure(mut fixture: Fixture, grant_ttl_secs: u64) -> TestResult<(Fixture, Keypair)> {
    // The original issued capability includes a second invocation, so replay
    // rejection cannot pass merely because the invocation quota was exhausted.
    let purpose = DeclassificationPurpose::new("approved-disclosure")?;
    let authority = Keypair::generate();
    let key = fixture.context.as_v1();
    let canonical =
        CanonicalBody::new(chio_core::canonical_json_bytes(&fixture.request.arguments)?)?;
    let now = now_ms()? / 1000;
    fixture.request.declassification_grant = Some(SignedDeclassificationGrant::sign(
        DeclassificationGrantBody::new(DeclassificationGrantClaims {
            grant_id: GrantId::new("native-disclosure")?,
            capability_id: RecordId::new(&fixture.request.capability.id)?,
            tenant_id: key.tenant_id().clone(),
            subject_id: key.principal_id().clone(),
            agent_id: RecordId::new(&fixture.request.agent_id)?,
            session_id: key.session_id().clone(),
            source_label_hash: information_label_hash(&restricted_label())?,
            target_label: InformationLabel::bottom(),
            destination_id: DestinationId::new(&fixture.request.server_id)?,
            tool_name: RecordId::new(&fixture.request.tool_name)?,
            purpose: purpose.clone(),
            request_hash: canonical_request_hash(&canonical)?,
            issued_at_unix_seconds: now,
            expires_at_unix_seconds: now
                .checked_add(grant_ttl_secs)
                .ok_or("grant expiry overflow")?,
            authority_key_id: RecordId::new("native-disclosure-authority")?,
        })?,
        &authority,
    )?);
    let resolver = resolver(&fixture, &authority)?;
    fixture
        .kernel
        .set_security_pre_dispatch_hook(Arc::new(resolver.with_captured_lifecycle()));
    Ok((fixture, authority))
}

fn resolver(fixture: &Fixture, authority: &Keypair) -> TestResult<NativeFlowResolver> {
    let purpose = DeclassificationPurpose::new("approved-disclosure")?;
    let config = FlowResolverConfig::new(
        restricted_label(),
        flow_config().category_labels,
        BTreeMap::from([(
            RecordId::new("native-disclosure-authority")?,
            authority.public_key(),
        )]),
        60_000,
    )?;
    Ok(NativeFlowResolver::new(
        fixture.binding.clone(),
        declassification_registry(&purpose),
        Arc::new(CountingEmptyClassifier::new()),
        Arc::new(Clock::default()),
        config,
    )?)
}

pub(in crate::security::adapters::tests::native_flow::support) fn assert_completed(
    fixture: &Fixture,
    combined: bool,
    nonce: bool,
) -> TestResult {
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("original completed declassification")?;
    assert_eq!(operation.state(), AdmissionOperationState::Completed);
    assert!(operation.native_dispatch_ledger_digest().is_some());
    assert_eq!(operation.execution_nonce_id().is_some(), nonce);
    assert_eq!(
        operation.runtime_participant_ledger_digest().is_some(),
        combined
    );
    assert_eq!(
        operation.governed_approval_ledger_digest().is_some(),
        combined
    );
    assert_eq!(operation.dpop_replay_ledger_digest().is_some(), combined);
    let (_, history) = store
        .load_native_security_egress(operation.binding().operation_id(), &fence, now_ms()?)?
        .ok_or("original egress operation")?;
    assert!(history
        .ok_or("egress")?
        .commitment
        .ok_or("commitment")?
        .declassification
        .is_some());
    let connection = rusqlite::Connection::open_with_flags(
        fixture._directory.path().join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let (state, evidence_count): (String, i64) = connection.query_row(
        "SELECT state, (SELECT COUNT(*) FROM security_participant_state_declassification_receipt_outbox WHERE security_authority_id = ?1 AND tenant_id = ?2 AND grant_id = ?3)
         FROM security_participant_state_declassification_uses WHERE security_authority_id = ?1 AND tenant_id = ?2 AND grant_id = ?3",
        rusqlite::params![fixture.binding.security_authority_id().as_str(), fixture.context.as_v1().tenant_id().as_str(), fixture.request.declassification_grant.as_ref().ok_or("grant")?.body().grant_id().as_str()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!((state.as_str(), evidence_count), ("released", 2));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn native_declassification_executes_once_without_lowering_inherited_state() -> TestResult {
    let mut fixture = fixture()?;
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert!(
        matches!(&response.output, Some(chio_kernel::ToolCallOutput::Value(value)) if value == &fixture.request.arguments)
    );
    assert!(response.receipt.verify_signature()?);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_completed(&fixture, false, false)?;
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("original declassified operation")?;
    assert_eq!(operation.state(), AdmissionOperationState::Completed);
    assert!(operation.native_dispatch_ledger_digest().is_some());
    let key = crate::security::adapters::flow_key(fixture.context.as_v1());
    let observed = store.observe_native_security_flow(&fixture.binding, &key, &fence, now_ms()?)?;
    let state = observed.snapshot().ok_or("native state")?;
    for label in [
        &state.principal_label,
        &state.lineage_label,
        &state.session_label,
    ] {
        assert_eq!(
            label,
            &restricted_label(),
            "declassification lowered inherited taint"
        );
    }
    let replay = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert_eq!(
        chio_core::canonical_json_bytes(&response.receipt)?,
        chio_core::canonical_json_bytes(&replay.receipt)?
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    fixture.context = SecurityInvocationContext::v1(
        fixture.context.as_v1().clone().with_flow_state_generation(
            observed
                .stored_context_generation()
                .ok_or("current generation")?,
        ),
    );
    fixture.request.request_id.push_str("-grant-reuse");
    let rejected = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert_eq!(rejected.verdict, Verdict::Deny, "{:?}", rejected.reason);
    assert!(rejected.output.is_none());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

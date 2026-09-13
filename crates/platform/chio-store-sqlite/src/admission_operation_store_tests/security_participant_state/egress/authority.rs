use super::*;

#[test]
fn changed_arguments_payload_context_and_selected_authority_deny_before_writes(
) -> AnchoredTestResult {
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let other = hydrate(&fixture, &imported(&fixture, "other")?)?;
    let pending = pending(&fixture, "egress-binding", None)?;
    let before = counts(&fixture)?;
    for variant in 0..7 {
        let mut request = pending.request.clone();
        let mut plan = pending.plan.clone();
        let mut context = pending.context.clone();
        let mut initialized = &pending.initialized;
        match variant {
            0 => request.arguments = serde_json::json!({"substituted": true}),
            1 => plan.request_hash = Digest32::new([9; 32]),
            2 => plan.key.session_id = chio_security_types::ports::SessionId::new("other-session")?,
            3 => {
                context = SecurityInvocationContext::v1(
                    context
                        .as_v1()
                        .clone()
                        .with_flow_state_generation(plan.expected_context_generation + 1),
                )
            }
            4 => initialized = &other,
            5 => plan.request_id = RequestId::new("other-request")?,
            6 => plan.expires_at_unix_ms = now_ms() - 1,
            _ => unreachable!(),
        }
        assert!(
            fixture
                .store
                .acquire_security_participant_egress(
                    &pending.operation,
                    &pending.lease,
                    initialized,
                    &context,
                    &request,
                    &plan,
                    now_ms(),
                )
                .is_err(),
            "variant {variant}"
        );
        assert_eq!(counts(&fixture)?, before, "variant {variant}");
        assert!(fixture.store.connection()?.is_autocommit());
    }
    pending.acquire(&fixture)?;
    native::verify_coverage(&*fixture.store.connection()?)?;
    Ok(())
}

#[test]
fn live_credential_substitution_cannot_reuse_acquisition_or_commitment() -> AnchoredTestResult {
    use chio_core::crypto::Keypair;
    use chio_kernel::dpop::{DpopProof, DpopProofBody, DPOP_SCHEMA};
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let mut pending = pending(&fixture, "egress-live-envelope", None)?;
    let acquired = pending.acquire(&fixture)?;
    let commitment = commitment(&acquired)?;
    let before = counts(&fixture)?;
    let original = pending.request.clone();
    let key = Keypair::generate();
    // Signed fixture material exercises full-envelope equality, not DPoP
    // verification. The native custody writer grants no credential authority.
    pending.request.dpop_proof = Some(DpopProof::sign(
        DpopProofBody {
            schema: DPOP_SCHEMA.into(),
            replay_authority: None,
            capability_id: original.capability.id.clone(),
            tool_server: original.server_id.clone(),
            tool_name: original.tool_name.clone(),
            action_hash: pending
                .operation
                .binding()
                .action_parameter_hash()
                .as_str()
                .into(),
            nonce: "private-transient-proof".into(),
            issued_at: now_ms() / 1000,
            agent_key: key.public_key(),
        },
        &key,
    )?);
    let (_, retained) = fixture
        .store
        .load_retained_tool_request(
            pending.operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("retained request absent")?;
    retained.validate_request_material(&pending.request)?;
    assert!(pending.acquire(&fixture).is_err());
    assert!(pending.commit(&fixture, &commitment).is_err());
    assert_eq!(counts(&fixture)?, before);
    pending.request = original;
    pending.commit(&fixture, &commitment)?;
    let mut changed = commitment.clone();
    changed.dispatch_commitment_id = RecordId::new("substituted-commitment")?;
    assert!(pending.commit(&fixture, &changed).is_err());
    assert_eq!(counts(&fixture)?.0, 2);
    Ok(())
}

#[test]
fn owner_rotation_requires_a_new_lease_and_preserves_historical_custody() -> AnchoredTestResult {
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let mut pending = pending(&fixture, "egress-owner-rotation", None)?;
    let acquired = pending.acquire(&fixture)?;
    let old_fence = fixture.fence.clone();
    let fixture = reopen(fixture)?;
    assert!(fixture.fence.owner_epoch > old_fence.owner_epoch);
    let before = counts(&fixture)?;
    assert!(fixture
        .store
        .load_security_participant_egress(
            pending.operation.binding().operation_id(),
            &old_fence,
            now_ms(),
        )
        .is_err());
    let history = fixture
        .store
        .load_security_participant_egress(
            pending.operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("pending history absent")?;
    assert_eq!(history.historical_fence(), &acquired);
    assert!(pending.acquire(&fixture).is_err());
    assert!(pending.commit(&fixture, &commitment(&acquired)?).is_err());
    assert_eq!(counts(&fixture)?, before);
    pending.operation = fixture
        .store
        .load_by_operation_id(pending.operation.binding().operation_id())?
        .ok_or("operation absent")?;
    pending.lease = renew(&fixture, &pending.operation, &pending.lease)?;
    let committed = pending.commit(&fixture, &commitment(&acquired)?)?;
    assert_eq!(counts(&fixture)?.0, 2);
    let history = fixture
        .store
        .load_security_participant_egress(
            pending.operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("committed history absent")?;
    assert_eq!(history.historical_commitment(), Some(&committed));
    Ok(())
}

#[test]
fn expired_fence_history_is_readable_but_cannot_be_committed() -> AnchoredTestResult {
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let pending = pending(&fixture, "egress-expiry", None)?;
    let acquired = pending.acquire(&fixture)?;
    let commitment = commitment(&acquired)?;
    let before = counts(&fixture)?;
    let expired = acquired.expires_at_unix_ms.div_ceil(1000) * 1000;
    assert!(expired < pending.lease.expires_at_unix_ms());
    let _clock =
        chio_kernel::scope_fixed_runtime_for_current_thread(expired / 1000, std::iter::empty());
    assert!(fixture
        .store
        .commit_security_participant_egress(
            &pending.operation,
            &pending.lease,
            &pending.initialized,
            &pending.context,
            &pending.request,
            &commitment,
            expired,
        )
        .is_err());
    let history = fixture
        .store
        .load_security_participant_egress(
            pending.operation.binding().operation_id(),
            &fixture.fence,
            expired,
        )?
        .ok_or("expired history absent")?;
    assert_eq!(history.historical_fence(), &acquired);
    assert!(history.historical_commitment().is_none());
    assert_eq!(counts(&fixture)?, before);
    Ok(())
}

#[test]
fn commit_requires_same_operation_acquisition_and_capture_phase() -> AnchoredTestResult {
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let pending = pending(&fixture, "egress-phase", None)?;
    let planned =
        crate::security_state::NativeEgressCommand::Acquire(pending.plan.clone()).fence()?;
    let before = counts(&fixture)?;
    assert!(pending.commit(&fixture, &commitment(&planned)?).is_err());
    assert_eq!(counts(&fixture)?, before);
    let acquired = pending.acquire(&fixture)?;
    // Acquisition cannot activate dispatch through a generic state command.
    let error = fixture
        .store
        .compare_and_swap(
            &command(
                &pending.operation,
                pending.lease.clone(),
                vec![],
                AdmissionOperationState::DispatchCommitted,
                None,
            ),
            now_ms(),
        )
        .err()
        .ok_or("native generic dispatch succeeded")?;
    assert!(error
        .to_string()
        .contains("native security dispatch custody is unsupported"));
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(pending.operation.binding().operation_id())?
            .as_ref(),
        Some(&pending.operation)
    );
    // A real pre-dispatch terminal is outside capture custody. Neither the old
    // operation nor its current terminal snapshot can commit the acquired fence.
    let updated = compensation::compensate(&fixture, &pending)?;
    assert!(renew(&fixture, &updated, &pending.lease).is_err());
    assert!(pending.commit(&fixture, &commitment(&acquired)?).is_err());
    assert!(fixture
        .store
        .commit_security_participant_egress(
            &updated,
            &pending.lease,
            &pending.initialized,
            &pending.context,
            &pending.request,
            &commitment(&acquired)?,
            now_ms(),
        )
        .is_err());
    assert_eq!(counts(&fixture)?.0, 1);
    Ok(())
}

#[test]
fn imported_pending_fence_cannot_be_adopted_even_when_the_command_matches() -> AnchoredTestResult {
    use chio_security_types::ports::FlowStateStore;
    let fixture = fixture();
    let path = fixture._temp.path().join("occupied-source.db");
    drop(crate::security_state::seeded_security_history(&path)?);
    seed_isolation_history(&path)?;
    let source_store = crate::SqliteSecurityStateStore::open(&path)?;
    let (_, join) = mutations::request("imported-egress-join")?;
    let snapshot = source_store.join(&join)?;
    let hash: [u8; 32] = hex::decode(sha256_hex(&canonical_json_bytes(
        &serde_json::json!({"private_argument": "must-not-appear-in-debug"}),
    )?))?
    .try_into()
    .map_err(|_| "action digest width")?;
    let plan = EgressFenceRequest {
        key: join.key,
        request_id: RequestId::new("egress-imported")?,
        request_hash: Digest32::new(hash),
        expected_context_generation: snapshot.context_generation,
        expires_at_unix_ms: now_ms() + 90_000,
    };
    let imported_fence = source_store.acquire_egress_fence(&plan)?;
    drop(source_store);
    let source = crate::security_state::SqliteSecurityParticipantSource::open(path)?;
    let authority = identifier("authority", "source");
    let expected = fixture.store.expect_security_participant_source(
        &identifier("source", "source"),
        &authority,
        &source,
        &fixture.fence,
        now_ms(),
    )?;
    let migrated = fixture.store.import_security_participant_source(
        &authority,
        expected.expectation_id(),
        &source,
        &fixture.fence,
        now_ms(),
    )?;
    hydrate(&fixture, &migrated)?;
    let mut pending = pending(
        &fixture,
        "egress-imported",
        Some(snapshot.context_generation),
    )?;
    assert_eq!(pending.plan.request_hash, plan.request_hash);
    // The required join advanced current flow generation. Present the exact
    // imported command to prove rejection occurs at the no-adoption boundary,
    // independently of the later fresh-generation check.
    pending.plan = plan;
    pending.context = SecurityInvocationContext::v1(
        pending
            .context
            .as_v1()
            .clone()
            .with_flow_state_generation(snapshot.context_generation),
    );
    let before = counts(&fixture)?;
    let error = pending
        .acquire(&fixture)
        .err()
        .ok_or("imported fence was adopted")?;
    assert!(error
        .to_string()
        .contains("belongs to imported or another operation's history"));
    assert!(pending
        .commit(&fixture, &commitment(&imported_fence)?)
        .is_err());
    assert_eq!(counts(&fixture)?, before);
    assert_eq!(before.0, 0);
    native::verify_coverage(&*fixture.store.connection()?)?;
    Ok(())
}

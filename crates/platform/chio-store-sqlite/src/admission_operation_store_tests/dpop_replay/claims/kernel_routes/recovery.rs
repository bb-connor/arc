use super::*;

#[test]
fn committed_dpop_survives_kernel_reopen_and_rejects_a_fresh_signature_for_the_spent_nonce(
) -> AnchoredTestResult {
    let route = Route::new()?;
    let mut request = route.request("committed-restart", &[2])?;
    let response = route.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    let (operation, history) = route.history(&request)?;
    let expires = history[0].intent.credential().valid_through_unix_secs()? + 1;
    let Route {
        fixture,
        domain,
        signer,
        agent,
        kernel: original_kernel,
        calls,
    } = route;
    drop(original_kernel);
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(expires, std::iter::empty());
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fixture = Fixture {
        store: authority.admission_operation_store(),
        fence: authority.mutation_fence(),
        authority,
        _temp,
        database,
        lock_root,
    };
    let mut kernel = kernel(&fixture, signer)?;
    kernel.set_operation_owned_dpop_authority(domain)?;
    kernel.register_tool_server(Box::new(Server(calls.clone())));
    assert_eq!(kernel.reconcile_durable_admission_startup()?, 0);
    assert_eq!(
        fixture.store.load_dpop_replay_claim_history(
            operation.binding().operation_id(),
            &fixture.fence,
            expires * 1000
        )?,
        Some((operation, history))
    );
    request.request_id = "spent-nonce-after-restart".into();
    let mut body = request.dpop_proof.take().ok_or("proof missing")?.body;
    body.issued_at = expires;
    request.dpop_proof = Some(DpopProof::sign(body, &agent)?);
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("historically spent")),
        "{:?}",
        response.reason
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn startup_releases_expired_pre_dispatch_dpop_without_recreating_the_source() -> AnchoredTestResult
{
    for phase in [
        DpopReplayClaimPhase::NoncePreflight,
        DpopReplayClaimPhase::Dispatch,
    ] {
        let fixture = fixture();
        let source = Source::new(&fixture, true)?;
        let domain = activate(&fixture, &source)?;
        let (operation, lease, credential) =
            setup(&fixture, &domain, "recover-dpop", "nonce", phase)?;
        let expires = credential.valid_through_unix_secs()? + 1;
        let intent = candidate(&operation, "owned", credential, phase)?;
        let (operation, reference) =
            fixture
                .store
                .claim_dpop_replay(&operation, &lease, &intent, now_ms())?;
        drop(source);
        let Fixture {
            _temp,
            database,
            lock_root,
            authority,
            store,
            ..
        } = fixture;
        drop(store);
        drop(authority);
        let _clock =
            chio_kernel::scope_fixed_runtime_for_current_thread(expires, std::iter::empty());
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fixture = Fixture {
            store: authority.admission_operation_store(),
            fence: authority.mutation_fence(),
            authority,
            _temp,
            database,
            lock_root,
        };
        let kernel = kernel(&fixture, Keypair::generate())?;
        // Startup cleans historical custody before any fresh serving profile
        // is selected. It cannot treat that history as a new proof or permit.
        assert_eq!(kernel.reconcile_durable_admission_startup()?, 1);
        assert_eq!(kernel.reconcile_recoverable_admissions()?, 0);
        let (operation, history) = fixture
            .store
            .load_dpop_replay_claim_history(
                operation.binding().operation_id(),
                &fixture.fence,
                expires * 1000,
            )?
            .ok_or("history absent")?;
        assert_eq!(
            operation.state(),
            AdmissionOperationState::CompensatedBeforeDispatch
        );
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].reference, reference);
        assert_eq!(history[0].intent, intent);
        assert_eq!(
            history[0].disposition,
            DpopReplayClaimDisposition::ReleasedBeforeDispatch
        );
    }
    Ok(())
}

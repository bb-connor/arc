use super::*;

fn source(
    fixture: &Fixture,
    count: usize,
    per_capability: usize,
    bytes: usize,
    legacy: bool,
) -> AnchoredTestResult<Source> {
    let raw = Arc::new(DpopNonceStore::new_with_identity_byte_capacity(
        count,
        per_capability,
        bytes,
        Duration::from_secs(3600),
    ));
    if legacy {
        assert!(raw.check_and_insert("legacy-nonce", "original-capability")?);
    }
    let snapshot = raw.preview_unsealed(&DpopReplaySourceBinding {
        dpop_authority_id: identifier("authority", AUTHORITY_ID),
        destination_authority_id: identifier("destination", &fixture.fence.store_uuid),
    })?;
    Ok(Source::attach(
        raw,
        identifier("instance", snapshot.instance_id()),
        &fixture.store,
    ))
}

#[test]
fn fresh_v2_domain_is_separate_from_preserved_full_legacy_inventory() -> AnchoredTestResult {
    let fixture = fixture();
    let source = source(&fixture, 1, 1, 16 * 1024 * 1024, true)?;
    let domain = activate(&fixture, &source)?;
    let (operation, lease, credential) = setup(
        &fixture,
        &domain,
        "v2-new-domain",
        "legacy-nonce",
        DpopReplayClaimPhase::Dispatch,
    )?;
    let expires = credential.valid_through_unix_secs()? + 1;
    let intent = candidate(
        &operation,
        "claim",
        credential,
        DpopReplayClaimPhase::Dispatch,
    )?;
    fixture
        .store
        .claim_dpop_replay(&operation, &lease, &intent, now_ms())?;
    assert_eq!(counts(&fixture), [1, 3, 1]);
    assert!(source
        .raw
        .check_and_insert("any", "original-capability")
        .is_err());
    let (other, lease, credential) = setup(
        &fixture,
        &domain,
        "capacity-contender",
        "different",
        DpopReplayClaimPhase::Dispatch,
    )?;
    let intent = candidate(&other, "claim", credential, DpopReplayClaimPhase::Dispatch)?;
    let error = fixture
        .store
        .claim_dpop_replay(&other, &lease, &intent, now_ms())
        .expect_err("live v2 capacity exhausted");
    assert!(error.to_string().contains("capacity exhausted"), "{error}");
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(expires, std::iter::empty());
    let (fresh, lease, credential) = setup(
        &fixture,
        &domain,
        "fresh-proof",
        "different",
        DpopReplayClaimPhase::Dispatch,
    )?;
    let intent = candidate(&fresh, "claim", credential, DpopReplayClaimPhase::Dispatch)?;
    fixture
        .store
        .claim_dpop_replay(&fresh, &lease, &intent, now_ms())?;
    assert_eq!(counts(&fixture), [1, 3, 1]);
    Ok(())
}

#[test]
fn per_capability_and_identity_byte_limits_deny_without_new_history() -> AnchoredTestResult {
    for bytes in [1, 16 * 1024 * 1024] {
        let fixture = fixture();
        let source = source(&fixture, 8, 1, bytes, false)?;
        let domain = activate(&fixture, &source)?;
        let (operation, lease, credential) = setup(
            &fixture,
            &domain,
            "capacity-first",
            "first",
            DpopReplayClaimPhase::Dispatch,
        )?;
        let intent = candidate(
            &operation,
            "claim",
            credential,
            DpopReplayClaimPhase::Dispatch,
        )?;
        if bytes > 1 {
            fixture
                .store
                .claim_dpop_replay(&operation, &lease, &intent, now_ms())?;
        }
        let (other, lease, credential) = setup(
            &fixture,
            &domain,
            "capacity-next",
            "next",
            DpopReplayClaimPhase::Dispatch,
        )?;
        let intent = candidate(&other, "claim", credential, DpopReplayClaimPhase::Dispatch)?;
        let before = global_count(&fixture);
        let error = fixture
            .store
            .claim_dpop_replay(&other, &lease, &intent, now_ms())
            .expect_err("bounded capacity");
        assert!(error.to_string().contains("capacity exhausted"), "{error}");
        assert_eq!(global_count(&fixture), before);
    }
    Ok(())
}

#[test]
fn maximum_utf8_and_control_nonces_fit_bounded_canonical_history_without_normalization(
) -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let domain = activate(&fixture, &source)?;
    for (index, nonce) in ["\0".repeat(4096), "é".repeat(2048)]
        .into_iter()
        .enumerate()
    {
        let (operation, lease, credential) = setup(
            &fixture,
            &domain,
            &format!("bounded-{index}"),
            &nonce,
            DpopReplayClaimPhase::Dispatch,
        )?;
        let intent = candidate(
            &operation,
            "claim",
            credential,
            DpopReplayClaimPhase::Dispatch,
        )?;
        let (operation, _) =
            fixture
                .store
                .claim_dpop_replay(&operation, &lease, &intent, now_ms())?;
        let (_, history) = fixture
            .store
            .load_dpop_replay_claim_history(
                operation.binding().operation_id(),
                &fixture.fence,
                now_ms(),
            )?
            .ok_or("history absent")?;
        assert_eq!(history[0].intent.credential().nonce(), nonce);
    }
    assert!(setup(
        &fixture,
        &domain,
        "oversized",
        &"x".repeat(4097),
        DpopReplayClaimPhase::Dispatch
    )
    .is_err());
    Ok(())
}

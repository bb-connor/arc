//! An independently valid initialization cannot replace original selection.
use super::*;
use chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1;

#[test]
fn first_join_cannot_substitute_another_valid_native_authority() -> TestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let other = hydrate(&fixture, &imported(&fixture, "other")?)?;
    let (context, request) = request("original-selection")?;
    let (operation, lease) = setup(&fixture, "original-selection", &context)?;
    let commits = global_count(&*fixture.store.connection()?)?;
    let error = fixture
        .store
        .join_security_participant_flow(&operation, &lease, &other, &context, &request, now_ms())
        .expect_err("first mutation must use original authority");
    assert!(
        error
            .to_string()
            .contains("native authority differs from original admission selection"),
        "{error}"
    );
    assert_eq!(count(&fixture)?, 0);
    assert_eq!(global_count(&*fixture.store.connection()?)?, commits);
    let joined = fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &request,
        now_ms(),
    )?;
    assert_eq!(joined.key, request.key);
    assert_eq!(count(&fixture)?, 1);
    native::verify_coverage(&*fixture.store.connection()?)?;
    Ok(())
}

#[test]
fn native_join_requires_original_store_source_digest_and_presence() -> TestResult {
    for variant in 0..3 {
        let fixture = fixture();
        let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
        let selected = match variant {
            0 => None,
            1 => Some(NativeSecurityAuthorityBindingV1::new(
                identifier("store", "different-destination"),
                initialized.security_authority_id().clone(),
                AdmissionDigest::try_new("initialization", initialized.initialization_digest())?,
            )),
            _ => Some(NativeSecurityAuthorityBindingV1::new(
                identifier("store", &fixture.fence.store_uuid),
                initialized.security_authority_id().clone(),
                AdmissionDigest::try_new("initialization", sha256_hex(b"replacement-source"))?,
            )),
        };
        let (context, request) = request("original-selection")?;
        let (operation, lease, _) =
            setup_selected_at(&fixture, "original-selection", &context, now_ms(), selected)?;
        let commits = global_count(&*fixture.store.connection()?)?;
        let error = fixture
            .store
            .join_security_participant_flow(
                &operation,
                &lease,
                &initialized,
                &context,
                &request,
                now_ms(),
            )
            .expect_err("missing or different original selection must deny");
        assert!(
            error
                .to_string()
                .contains("native authority differs from original admission selection"),
            "variant {variant}: {error}"
        );
        assert_eq!(count(&fixture)?, 0);
        assert_eq!(global_count(&*fixture.store.connection()?)?, commits);
        native::verify_coverage(&*fixture.store.connection()?)?;
    }
    Ok(())
}

#[test]
fn original_native_binding_remains_stable_across_serving_owner_rotation() -> TestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let selected = initialized.admission_binding()?;
    let (context, request) = request("original-selection")?;
    let (operation, lease) = setup(&fixture, "original-selection", &context)?;
    let joined = fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &request,
        now_ms(),
    )?;
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        fence,
    } = fixture;
    drop(store);
    drop(authority);
    let authority = crate::SqliteAuthorityStore::open_serving(database, lock_root)?;
    let next_fence = authority.mutation_fence();
    assert!(next_fence.owner_epoch > fence.owner_epoch);
    let store = authority.admission_operation_store();
    let recovered = store
        .load_security_participant_state(
            initialized.security_authority_id(),
            &next_fence,
            now_ms(),
        )?
        .ok_or("original initialization")?;
    assert_eq!(recovered, initialized);
    assert_eq!(recovered.admission_binding()?, selected);
    assert_eq!(
        store
            .load_security_participant_flow_join(
                operation.binding().operation_id(),
                &next_fence,
                now_ms()
            )?
            .ok_or("historical join")?
            .historical_snapshot(),
        &joined
    );
    Ok(())
}

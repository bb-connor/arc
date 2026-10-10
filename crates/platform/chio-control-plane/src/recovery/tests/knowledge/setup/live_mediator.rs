//! A live broker must belong to the current complete native installation.
use super::*;

#[test]
fn setup_live_mediator_refuses_a_replaced_native_profile_with_the_same_authority() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let scope = f.f.runtime.scope();
    let selected = f.f.kernel.recovery_deployment(scope)?;
    f.runtime
        .validate_setup_binding(scope, &selected.native_authority)?;
    let mut profile = f.profile.clone();
    profile.generation = SafeInteger::new(profile.generation.get() + 1)?;
    let current = NativeKnowledgeRuntime::new(
        f.f.kernel.clone(),
        Arc::new(f.f.authority.admission_operation_store()),
        f.broker.clone(),
        profile,
        f.f.authority.mutation_fence(),
    )?;
    current.validate_setup_binding(scope, &selected.native_authority)?;
    assert!(
        f.runtime
            .validate_setup_binding(scope, &selected.native_authority)
            .is_err(),
        "the live broker check must not accept a cached generation after native replacement"
    );
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, 0);
    Ok(())
}

#[test]
fn setup_live_mediator_accepts_the_exact_current_profile_without_changing_it() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let scope = f.f.runtime.scope();
    let selected = f.f.kernel.recovery_deployment(scope)?;
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let before: Vec<(String, Vec<u8>)> = connection
        .prepare("SELECT record_key,payload FROM admission_operation_recovery_records ORDER BY record_key")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()?;
    for _ in 0..3 {
        f.runtime
            .validate_setup_binding(scope, &selected.native_authority)?;
    }
    let after: Vec<(String, Vec<u8>)> = connection
        .prepare("SELECT record_key,payload FROM admission_operation_recovery_records ORDER BY record_key")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()?;
    assert_eq!(before, after);
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, 0);
    Ok(())
}

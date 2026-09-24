//! Fresh native reads remain separate from historical joins and write custody.
use super::*;
use chio_kernel::admission_operation::{
    NativeSecurityAuthorityBindingV1, NativeSecurityFlowObservationV1,
};
use chio_kernel::{SecurityInvocationContext, SecurityInvocationContextV1};
use chio_security_types::ports::{FlowStateKey, SessionId};
use chio_security_types::InformationLabel;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn footprint(fixture: &Fixture) -> TestResult<(u64, i64)> {
    let connection = fixture.store.connection()?;
    Ok((
        connection.total_changes(),
        connection.query_row("SELECT COUNT(*) FROM authority_global_commits", [], |row| {
            row.get(0)
        })?,
    ))
}

fn observe(
    fixture: &Fixture,
    initialized: &SecurityParticipantStateInitialization,
    key: &FlowStateKey,
) -> TestResult<NativeSecurityFlowObservationV1> {
    let store: &dyn AdmissionOperationStore = &fixture.store;
    Ok(store.observe_native_security_flow(
        &initialized.admission_binding()?,
        key,
        &fixture.fence,
        now_ms(),
    )?)
}

#[test]
fn fresh_observation_precedes_admission_without_creating_rows_or_commits() -> TestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let (_, request) = mutations::request("not-yet-admitted")?;
    let before = footprint(&fixture)?;
    let now = now_ms();
    let result = observe(&fixture, &initialized, &request.key)?;
    assert_eq!(result.binding(), &initialized.admission_binding()?);
    assert_eq!(result.key(), &request.key);
    assert!(result.snapshot().is_none());
    assert_eq!(result.stored_context_generation(), None);
    assert!(result.observed_at_unix_ms() >= now);
    assert_eq!(footprint(&fixture)?, before);
    Ok(())
}

#[test]
fn inherited_labels_do_not_forge_an_exact_context_generation() -> TestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let (context, mut request) = mutations::request("first-session")?;
    request.principal_join = InformationLabel::Top;
    let (operation, lease) = mutations::setup(&fixture, "first-session", &context)?;
    fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &request,
        now_ms(),
    )?;
    request.key.session_id = SessionId::new("unjoined-session")?;
    request.transition_id = chio_security_types::ports::RecordId::new("unjoined-session")?;
    let before = footprint(&fixture)?;
    let observation = observe(&fixture, &initialized, &request.key)?;
    assert_eq!(footprint(&fixture)?, before);
    let inherited = observation.snapshot().ok_or("inherited effective state")?;
    assert_eq!(inherited.session_label, InformationLabel::Top);
    assert_eq!(observation.stored_context_generation(), None);
    let key = observation.key();
    let context = SecurityInvocationContextV1::new(
        key.tenant_id.clone(),
        key.session_id.clone(),
        key.principal_id.clone(),
        key.isolation_epoch_id.clone(),
        key.lineage_id.clone(),
        1,
    );
    let wrong = SecurityInvocationContext::v1(
        context
            .clone()
            .with_flow_state_generation(inherited.context_generation),
    );
    let (operation, lease) = mutations::setup(&fixture, "unjoined-session", &wrong)?;
    assert!(fixture
        .store
        .join_security_participant_flow(
            &operation,
            &lease,
            &initialized,
            &wrong,
            &request,
            now_ms()
        )
        .is_err());
    let joined = fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &SecurityInvocationContext::v1(context),
        &request,
        now_ms(),
    )?;
    assert_eq!(joined.session_label, InformationLabel::Top);
    let current = observe(&fixture, &initialized, &request.key)?;
    assert_eq!(
        current.stored_context_generation(),
        Some(joined.context_generation)
    );
    assert_eq!(current.snapshot(), Some(&joined));
    Ok(())
}

#[test]
fn current_native_rows_are_not_replaced_by_historical_join_results() -> TestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let other = hydrate(&fixture, &imported(&fixture, "other")?)?;
    let (context, mut request) = mutations::request("first")?;
    let (first, lease) = mutations::setup(&fixture, "first", &context)?;
    let recorded = fixture.store.join_security_participant_flow(
        &first,
        &lease,
        &initialized,
        &context,
        &request,
        now_ms(),
    )?;
    let old = observe(&fixture, &initialized, &request.key)?;
    assert_eq!(old.snapshot(), Some(&recorded));
    let context =
        SecurityInvocationContext::v1(context.as_v1().clone().with_flow_state_generation(
            old.stored_context_generation().ok_or("stored generation")?,
        ));
    let (second, lease) = mutations::setup(&fixture, "second", &context)?;
    request.transition_id = chio_security_types::ports::RecordId::new("second")?;
    request.lineage_join = InformationLabel::Top;
    let changed = fixture.store.join_security_participant_flow(
        &second,
        &lease,
        &initialized,
        &context,
        &request,
        now_ms(),
    )?;
    let before = footprint(&fixture)?;
    let current = observe(&fixture, &initialized, &request.key)?;
    assert_eq!(current.snapshot(), Some(&changed));
    assert!(current.stored_context_generation() > old.stored_context_generation());
    assert_eq!(
        current.snapshot().ok_or("current state")?.lineage_label,
        InformationLabel::Top
    );
    assert!(observe(&fixture, &other, &request.key)?
        .snapshot()
        .is_none());
    assert_eq!(footprint(&fixture)?, before);
    let history = fixture
        .store
        .load_security_participant_flow_join(
            first.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("historical join")?;
    assert_eq!(history.historical_snapshot(), &recorded);
    assert_ne!(history.historical_snapshot(), &changed);
    Ok(())
}

#[test]
fn observation_rejects_wrong_initialization_fence_and_time_without_writes() -> TestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let (_, request) = mutations::request("unjoined")?;
    let selected = initialized.admission_binding()?;
    imported(&fixture, "imported-only")?;
    let before = footprint(&fixture)?;
    for changed in [
        NativeSecurityAuthorityBindingV1::new(
            selected.store_uuid().clone(),
            identifier("authority", "imported-only"),
            selected.initialization_digest().clone(),
        ),
        NativeSecurityAuthorityBindingV1::new(
            identifier("store", "other"),
            selected.security_authority_id().clone(),
            selected.initialization_digest().clone(),
        ),
        NativeSecurityAuthorityBindingV1::new(
            selected.store_uuid().clone(),
            identifier("authority", "missing"),
            selected.initialization_digest().clone(),
        ),
        NativeSecurityAuthorityBindingV1::new(
            selected.store_uuid().clone(),
            selected.security_authority_id().clone(),
            AdmissionDigest::try_new("initialization", sha256_hex(b"wrong"))?,
        ),
    ] {
        assert!(fixture
            .store
            .observe_native_security_flow(&changed, &request.key, &fixture.fence, now_ms())
            .is_err());
    }
    let mut wrong = fixture.fence.clone();
    wrong.owner_epoch += 1;
    assert!(fixture
        .store
        .observe_native_security_flow(&selected, &request.key, &wrong, now_ms())
        .is_err());
    for now in [0, 1, u64::MAX] {
        assert!(fixture
            .store
            .observe_native_security_flow(&selected, &request.key, &fixture.fence, now)
            .is_err());
    }
    assert!(observe(&fixture, &initialized, &request.key)?
        .snapshot()
        .is_none());
    assert_eq!(footprint(&fixture)?, before);
    Ok(())
}

#[test]
fn unanchored_current_row_changes_cannot_be_observed_as_valid_state() -> TestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let (context, request) = mutations::request("joined")?;
    let (operation, lease) = mutations::setup(&fixture, "joined", &context)?;
    fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &request,
        now_ms(),
    )?;
    observe(&fixture, &initialized, &request.key)?;
    {
        // Corrupt only this disposable fixture, restoring the exact catalog so
        // the read must reject unanchored row contents, not missing triggers.
        let connection = fixture.store.connection()?;
        let (index, table) = native::schema::TABLES
            .iter()
            .enumerate()
            .find(|(_, table)| table.source == "security_flow_contexts")
            .ok_or("context table")?;
        let mut restore = Vec::new();
        for suffix in ["inactive_update", "capture_update"] {
            let name = format!("security_participant_state_{index}_{suffix}");
            let sql: String = connection.query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
                [&name],
                |row| row.get(0),
            )?;
            connection.execute_batch(&format!("DROP TRIGGER {name}"))?;
            restore.push((name, sql));
        }
        assert_eq!(connection.execute(&format!("UPDATE {} SET generation = generation + 1 WHERE security_authority_id = ?1 AND tenant_id = ?2", table.native), params![initialized.security_authority_id().as_str(), request.key.tenant_id.as_str()])?, 1);
        for (name, sql) in restore {
            connection.execute_batch(&sql)?;
            let restored: String = connection.query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
                [&name],
                |row| row.get(0),
            )?;
            assert_eq!(restored, sql);
        }
    }
    let before = footprint(&fixture)?;
    assert!(observe(&fixture, &initialized, &request.key).is_err());
    assert_eq!(footprint(&fixture)?, before);
    Ok(())
}

#[test]
fn fresh_observation_requires_current_owner_but_preserves_original_initialization() -> TestResult {
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let (_, request) = mutations::request("unjoined")?;
    let original = initialized.admission_binding()?;
    observe(&fixture, &initialized, &request.key)?;
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
    let authority = SqliteAuthorityStore::open_serving(database, lock_root)?;
    let current = authority.mutation_fence();
    assert!(current.owner_epoch > fence.owner_epoch);
    let store = authority.admission_operation_store();
    assert!(store
        .observe_native_security_flow(&original, &request.key, &fence, now_ms())
        .is_err());
    let observation =
        store.observe_native_security_flow(&original, &request.key, &current, now_ms())?;
    assert_eq!(observation.binding(), &original);
    assert!(observation.snapshot().is_none());
    Ok(())
}

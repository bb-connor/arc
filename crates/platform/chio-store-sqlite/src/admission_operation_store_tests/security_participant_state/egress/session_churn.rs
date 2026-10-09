//! Distinct finished native sessions leave the current-row budget only when
//! their rows add nothing a later reader could observe, and never while live
//! custody or an unfinished operation can still read them.
use super::*;
use chio_kernel::SecurityInvocationContextV1;
use chio_security_types::ports::{
    FlowJoinRequest, FlowStateKey, FlowStateSnapshot, IsolationEpochId, LineageId, SessionId,
    TenantId,
};
use chio_security_types::{Compartment, InformationLabel, PrincipalId};

/// Head room above the steady state. Near the budget, every per-evaluation
/// tick sweeps; a finished session leaves one sweep after its committed fence.
const MARGIN: u64 = 40;
/// Three current rows each: far beyond the head room if none ever left.
const SESSIONS: usize = 32;

pub(super) fn taint(name: &str) -> AnchoredTestResult<InformationLabel> {
    Ok(InformationLabel::try_known(
        Default::default(),
        std::collections::BTreeSet::from([Compartment::new(name)?]),
    )?)
}

pub(super) fn key(
    principal: &str,
    lineage: &str,
    session: &str,
) -> AnchoredTestResult<FlowStateKey> {
    Ok(FlowStateKey {
        tenant_id: TenantId::new("native-tenant")?,
        principal_id: PrincipalId::new(principal)?,
        lineage_id: LineageId::new(lineage)?,
        session_id: SessionId::new(session)?,
        isolation_epoch_id: IsolationEpochId::new("native-epoch")?,
    })
}

/// A first join for `key`: the principal and lineage receive `principal`, the
/// session receives `session`.
pub(super) fn request(
    name: &str,
    key: &FlowStateKey,
    principal: &InformationLabel,
    session: &InformationLabel,
) -> AnchoredTestResult<(SecurityInvocationContext, FlowJoinRequest)> {
    let context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        key.tenant_id.clone(),
        key.session_id.clone(),
        key.principal_id.clone(),
        key.isolation_epoch_id.clone(),
        key.lineage_id.clone(),
        1,
    ));
    Ok((
        context,
        FlowJoinRequest {
            key: key.clone(),
            principal_join: principal.clone(),
            lineage_join: principal.clone(),
            session_join: session.clone(),
            transition_id: RecordId::new(format!("{name}-join"))?,
        },
    ))
}

fn initialization(fixture: &Fixture) -> AnchoredTestResult<SecurityParticipantStateInitialization> {
    Ok(fixture
        .store
        .load_security_participant_state(
            &identifier("authority", "source"),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("native initialization absent")?)
}

pub(super) fn rows(fixture: &Fixture) -> AnchoredTestResult<u64> {
    let connection = fixture.store.connection()?;
    let mut total = 0_u64;
    for table in native::schema::TABLES {
        let count: i64 = connection.query_row(
            &format!("SELECT COUNT(*) FROM {}", table.native),
            [],
            |row| row.get(0),
        )?;
        total += u64::try_from(count)?;
    }
    Ok(total)
}

/// Current (session label, membership, context) rows of one session.
pub(super) fn session_rows(
    fixture: &Fixture,
    key: &FlowStateKey,
) -> AnchoredTestResult<(i64, i64, i64)> {
    let connection = fixture.store.connection()?;
    let count = |table: &str| -> rusqlite::Result<i64> {
        connection.query_row(
            &format!(
                "SELECT COUNT(*) FROM {table} WHERE tenant_id = ?1 AND principal_id = ?2
                 AND session_id = ?3 AND isolation_epoch_id = ?4"
            ),
            [
                key.tenant_id.as_str(),
                key.principal_id.as_str(),
                key.session_id.as_str(),
                key.isolation_epoch_id.as_str(),
            ],
            |row| row.get(0),
        )
    };
    Ok((
        count("security_participant_state_session_flow_state")?,
        count("security_participant_state_session_memberships")?,
        count("security_participant_state_flow_contexts")?,
    ))
}

pub(super) fn observe(
    fixture: &Fixture,
    key: &FlowStateKey,
) -> AnchoredTestResult<(Option<FlowStateSnapshot>, Option<u64>)> {
    let binding = initialization(fixture)?.admission_binding()?;
    let observed =
        fixture
            .store
            .observe_security_participant_flow(&binding, key, &fixture.fence, now_ms())?;
    Ok((
        observed.snapshot().cloned(),
        observed.stored_context_generation(),
    ))
}

/// The trusted host's per-evaluation maintenance tick, as the kernel runs it.
fn tick(fixture: &Fixture) -> AnchoredTestResult {
    let binding = initialization(fixture)?.admission_binding()?;
    fixture
        .store
        .checkpoint_native_security_history_if_due(&binding, &fixture.fence, now_ms())?;
    Ok(())
}

/// Explicit operator maintenance.
pub(super) fn checkpoint(fixture: &Fixture) -> AnchoredTestResult {
    fixture.store.checkpoint_security_participant_history(
        &initialization(fixture)?,
        &fixture.fence,
        now_ms(),
    )?;
    Ok(())
}

/// One complete native session: join, acquire, commit, then a real terminal.
pub(super) fn finish(
    fixture: &Fixture,
    name: &str,
    key: &FlowStateKey,
    principal: &InformationLabel,
    session: &InformationLabel,
) -> AnchoredTestResult<FlowStateSnapshot> {
    tick(fixture)?;
    let (context, join) = request(name, key, principal, session)?;
    let pending = pending_with(fixture, name, None, context, join)?;
    let fence = pending.acquire(fixture)?;
    pending.commit(fixture, &commitment(&fence)?)?;
    compensation::compensate(fixture, &pending)?;
    observe(fixture, key)?
        .0
        .ok_or_else(|| "joined session has no snapshot".into())
}

pub(super) fn clock() -> chio_test_support::clock::ClockScope {
    chio_test_support::clock::scope_unix_secs(now_ms().div_ceil(1_000))
}

#[test]
fn distinct_finished_sessions_stay_within_current_row_budget() -> AnchoredTestResult {
    let _clock = clock();
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let label = taint("churn")?;
    let first = key("churn-principal", "churn-lineage", "churn-0")?;
    finish(&fixture, "churn-0", &first, &label, &label)?;
    let budget = rows(&fixture)? + MARGIN;
    native::with_test_current_rows(budget, || -> AnchoredTestResult {
        for index in 1..=SESSIONS {
            let name = format!("churn-{index}");
            let key = key("churn-principal", "churn-lineage", &name)?;
            finish(&fixture, &name, &key, &label, &label).map_err(|error| {
                format!("native session {index} under a {budget}-row budget: {error}")
            })?;
            assert!(rows(&fixture)? <= budget);
        }
        Ok(())
    })?;
    assert_eq!(session_rows(&fixture, &first)?, (0, 0, 0));
    let fixture = reopen(fixture)?;
    {
        let connection = fixture.store.connection()?;
        native::verify_all(&connection)?;
        native::verify_coverage(&connection)?;
    }
    checkpoint(&fixture)?;
    let fixture = reopen(fixture)?;
    let again = key("churn-principal", "churn-lineage", "churn-reopened")?;
    finish(&fixture, "churn-reopened", &again, &label, &label)?;
    Ok(())
}

#[test]
fn imported_sessions_stay_current_through_maintenance() -> AnchoredTestResult {
    let _clock = clock();
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let sessions = || -> AnchoredTestResult<i64> {
        Ok(fixture.store.connection()?.query_row(
            "SELECT COUNT(*) FROM security_participant_state_session_flow_state",
            [],
            |row| row.get(0),
        )?)
    };
    let imported = sessions()?;
    assert!(imported > 0);
    checkpoint(&fixture)?;
    checkpoint(&fixture)?;
    assert_eq!(sessions()?, imported);
    Ok(())
}

#[test]
fn reused_session_identifier_after_eviction_keeps_every_label() -> AnchoredTestResult {
    let _clock = clock();
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let secret = taint("reused-secret")?;
    let reused = key("reuse-principal", "reuse-lineage", "reuse-session")?;
    let joined = finish(&fixture, "reuse-first", &reused, &secret, &secret)?;
    assert!(secret.flows_to(&joined.session_label));
    checkpoint(&fixture)?;
    checkpoint(&fixture)?;
    assert_eq!(session_rows(&fixture, &reused)?, (0, 0, 0));
    let (evicted, generation) = observe(&fixture, &reused)?;
    let evicted = evicted.ok_or("evicted session snapshot")?;
    // Only the context generation token is gone; every effective label stays.
    assert_eq!(generation, None);
    assert_eq!(evicted.principal_label, joined.principal_label);
    assert_eq!(evicted.lineage_label, joined.lineage_label);
    assert_eq!(evicted.session_label, joined.session_label);
    // A new first join under the old identifier cannot start below its taint.
    let bottom = InformationLabel::bottom();
    let rejoined = finish(&fixture, "reuse-again", &reused, &bottom, &bottom)?;
    assert!(secret.flows_to(&rejoined.session_label));
    assert!(rejoined.context_generation > joined.context_generation);
    Ok(())
}

#[test]
fn session_only_taint_stays_current() -> AnchoredTestResult {
    let _clock = clock();
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let only = taint("session-only")?;
    let held = key("only-principal", "only-lineage", "only-session")?;
    let bottom = InformationLabel::bottom();
    finish(&fixture, "session-only", &held, &bottom, &only)?;
    checkpoint(&fixture)?;
    checkpoint(&fixture)?;
    assert_eq!(session_rows(&fixture, &held)?, (1, 1, 1));
    let (current, generation) = observe(&fixture, &held)?;
    assert!(generation.is_some());
    assert!(only.flows_to(&current.ok_or("session snapshot")?.session_label));
    Ok(())
}

#[test]
fn shared_lineage_taint_survives_its_first_principals_eviction() -> AnchoredTestResult {
    let _clock = clock();
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let shared = taint("shared-lineage")?;
    let owner = key("lineage-owner", "shared-lineage", "owner-session")?;
    finish(&fixture, "lineage-owner", &owner, &shared, &shared)?;
    checkpoint(&fixture)?;
    checkpoint(&fixture)?;
    assert_eq!(session_rows(&fixture, &owner)?, (0, 0, 0));
    let lineage: i64 = fixture.store.connection()?.query_row(
        "SELECT COUNT(*) FROM security_participant_state_lineage_flow_state WHERE lineage_id = 'shared-lineage'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(lineage, 1);
    let guest = key("lineage-guest", "shared-lineage", "guest-session")?;
    let bottom = InformationLabel::bottom();
    let joined = finish(&fixture, "lineage-guest", &guest, &bottom, &bottom)?;
    assert!(shared.flows_to(&joined.session_label));
    // The guest's session carries lineage taint its principal lacks.
    checkpoint(&fixture)?;
    checkpoint(&fixture)?;
    assert_eq!(session_rows(&fixture, &guest)?, (1, 1, 1));
    Ok(())
}

#[test]
fn joined_unfinished_operation_keeps_its_context_through_maintenance() -> AnchoredTestResult {
    let _clock = clock();
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let label = taint("held")?;
    let held = key("held-principal", "held-lineage", "held-session")?;
    let (context, join) = request("held", &held, &label, &label)?;
    let pending = pending_with(&fixture, "held", None, context, join)?;
    // Dominated labels and no fence: only the unfinished operation pins it.
    checkpoint(&fixture)?;
    checkpoint(&fixture)?;
    assert_eq!(session_rows(&fixture, &held)?, (1, 1, 1));
    let fence = pending.acquire(&fixture)?;
    pending.commit(&fixture, &commitment(&fence)?)?;
    Ok(())
}

#[test]
fn pending_fence_keeps_its_session_until_the_fence_is_dead() -> AnchoredTestResult {
    let _clock = clock();
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let label = taint("fenced")?;
    let fenced = key("fenced-principal", "fenced-lineage", "fenced-session")?;
    let (context, join) = request("fenced", &fenced, &label, &label)?;
    let mut pending = pending_with(&fixture, "fenced", None, context, join)?;
    pending.plan.expires_at_unix_ms = now_ms() + 5_000;
    let fence = pending.acquire(&fixture)?;
    // A real terminal leaves only the pending fence to name the session.
    compensation::compensate(&fixture, &pending)?;
    checkpoint(&fixture)?;
    checkpoint(&fixture)?;
    assert_eq!(session_rows(&fixture, &fenced)?, (1, 1, 1));
    assert!(identities(&fixture)?.contains(&fence.fence_id.as_str().to_owned()));
    let _expired = chio_test_support::clock::scope_unix_secs(fence.expires_at_unix_ms / 1_000 + 1);
    checkpoint(&fixture)?;
    assert!(!identities(&fixture)?.contains(&fence.fence_id.as_str().to_owned()));
    checkpoint(&fixture)?;
    assert_eq!(session_rows(&fixture, &fenced)?, (0, 0, 0));
    Ok(())
}

#[test]
fn unfinished_operations_past_their_bound_pin_every_session() -> AnchoredTestResult {
    let _clock = clock();
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let label = taint("bounded")?;
    let finished = key("bounded-principal", "bounded-lineage", "bounded-finished")?;
    finish(&fixture, "bounded-finished", &finished, &label, &label)?;
    for name in ["bounded-open-a", "bounded-open-b"] {
        let other = key("bounded-other", "bounded-lineage", name)?;
        let (context, join) = request(name, &other, &label, &label)?;
        pending_with(&fixture, name, None, context, join)?;
    }
    // Two unfinished operations exceed a bound of one: evidence is incomplete.
    native::with_test_pinning_operations(1, || -> AnchoredTestResult {
        checkpoint(&fixture)?;
        checkpoint(&fixture)?;
        assert_eq!(session_rows(&fixture, &finished)?, (1, 1, 1));
        Ok(())
    })?;
    checkpoint(&fixture)?;
    assert_eq!(session_rows(&fixture, &finished)?, (0, 0, 0));
    Ok(())
}

fn identities(fixture: &Fixture) -> AnchoredTestResult<Vec<String>> {
    let connection = fixture.store.connection()?;
    let mut statement =
        connection.prepare("SELECT fence_id FROM security_participant_state_egress_fences")?;
    let rows = statement
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[test]
fn missing_principal_label_under_an_existing_epoch_is_refused_by_the_native_reader(
) -> AnchoredTestResult {
    let _clock = clock();
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let label = taint("missing-principal")?;
    let first = key("missing-principal", "root-0", "missing-session")?;
    finish(&fixture, "missing-0", &first, &label, &label)?;
    // The kernel's pre-evaluation refresh observes with the selected binding;
    // it does not refold current rows.
    let binding = initialization(&fixture)?.admission_binding()?;
    let index = native::schema::TABLES
        .iter()
        .position(|table| table.native == "security_participant_state_principal_flow_state")
        .ok_or("principal table")?;
    {
        let connection = fixture.store.connection()?;
        connection.execute_batch(&format!(
            "DROP TRIGGER security_participant_state_{index}_inactive_delete;
             DROP TRIGGER security_participant_state_{index}_capture_delete;
             DELETE FROM security_participant_state_principal_flow_state
             WHERE principal_id = 'missing-principal';"
        ))?;
        connection.execute_batch(&native::schema::sql()?)?;
    }
    // The epoch and the session survive under root-0; the principal row does
    // not. Every native read transaction refolds current rows against anchored
    // history before any flow read, so the gap is refused there.
    for session in ["missing-session", "fresh-session"] {
        let next = key("missing-principal", "root-1", session)?;
        let refused = fixture
            .store
            .observe_security_participant_flow(&binding, &next, &fixture.fence, now_ms())
            .err()
            .ok_or("a missing principal label was observed as absent")?;
        assert!(
            refused
                .to_string()
                .contains("native current rows are missing anchored history"),
            "{refused}"
        );
    }
    Ok(())
}

#[test]
fn resurrected_evicted_session_row_is_refused_at_open() -> AnchoredTestResult {
    let _clock = clock();
    let fixture = fixture();
    let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let label = taint("resurrected")?;
    let evicted = key("resurrected-principal", "resurrected-lineage", "evicted")?;
    finish(&fixture, "resurrected", &evicted, &label, &label)?;
    checkpoint(&fixture)?;
    checkpoint(&fixture)?;
    assert_eq!(session_rows(&fixture, &evicted)?, (0, 0, 0));
    let index = native::schema::TABLES
        .iter()
        .position(|table| table.native == "security_participant_state_session_flow_state")
        .ok_or("session table")?;
    {
        let connection = fixture.store.connection()?;
        connection.execute_batch(&format!(
            "DROP TRIGGER security_participant_state_{index}_inactive_insert;
             DROP TRIGGER security_participant_state_{index}_capture_insert;
             INSERT INTO security_participant_state_session_flow_state
             SELECT security_authority_id, tenant_id, principal_id, 'evicted', isolation_epoch_id,
                    label_json, label_hash, generation
             FROM security_participant_state_principal_flow_state
             WHERE principal_id = 'resurrected-principal';"
        ))?;
        connection.execute_batch(&native::schema::sql()?)?;
    }
    let refused = fixture
        .store
        .load_security_participant_state(
            initialized.security_authority_id(),
            &fixture.fence,
            now_ms(),
        )
        .err()
        .ok_or("resurrected session row was accepted")?;
    assert!(
        refused
            .to_string()
            .contains("native current row differs from anchored history"),
        "{refused}"
    );
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
    let refused = crate::test_authority::open_serving(&database, &lock_root)
        .err()
        .ok_or("resurrected session row was accepted at open")?;
    assert!(
        refused
            .to_string()
            .contains("native current row differs from anchored history"),
        "{refused}"
    );
    Ok(())
}

//! Native live state is bounded per (authority, tenant). Retained identity and
//! sealed journal history grow under the physical band with no lifetime cap.
use super::*;
use chio_kernel::{SecurityInvocationContext, SecurityInvocationContextV1};
use chio_security_types::ports::{
    FlowJoinRequest, FlowStateKey, FlowStateSnapshot, IsolationEpochId, LineageId, RecordId,
    SessionId, TenantId,
};
use chio_security_types::{InformationLabel, PrincipalId};
use rusqlite::OptionalExtension;
use std::collections::{BTreeMap, BTreeSet};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// A flow key and the stable invocation context its admission operation binds.
struct Flow {
    key: FlowStateKey,
    context: SecurityInvocationContext,
}

fn flow(tenant: &str, principal: &str, lineage: &str, session: &str) -> TestResult<Flow> {
    let key = FlowStateKey {
        tenant_id: TenantId::new(tenant)?,
        principal_id: PrincipalId::new(principal)?,
        lineage_id: LineageId::new(lineage)?,
        session_id: SessionId::new(session)?,
        isolation_epoch_id: IsolationEpochId::new("native-epoch")?,
    };
    let context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        key.tenant_id.clone(),
        key.session_id.clone(),
        key.principal_id.clone(),
        key.isolation_epoch_id.clone(),
        key.lineage_id.clone(),
        1,
    ));
    Ok(Flow { key, context })
}

/// The invocation context at the key's current flow generation, when the key
/// already holds live custody.
fn current_context(
    fixture: &Fixture,
    authority: &str,
    flow: &Flow,
) -> TestResult<SecurityInvocationContext> {
    let generation: Option<i64> = fixture
        .store
        .connection()?
        .query_row(
            "SELECT generation FROM security_participant_state_flow_contexts
             WHERE security_authority_id = ?1 AND tenant_id = ?2 AND principal_id = ?3
               AND lineage_id = ?4 AND session_id = ?5 AND isolation_epoch_id = ?6",
            rusqlite::params![
                authority,
                flow.key.tenant_id.as_str(),
                flow.key.principal_id.as_str(),
                flow.key.lineage_id.as_str(),
                flow.key.session_id.as_str(),
                flow.key.isolation_epoch_id.as_str()
            ],
            |row| row.get(0),
        )
        .optional()?;
    Ok(match generation {
        None => flow.context.clone(),
        Some(generation) => SecurityInvocationContext::v1(
            flow.context
                .as_v1()
                .clone()
                .with_flow_state_generation(u64::try_from(generation)?),
        ),
    })
}

/// One real admission operation, prepared and leased, for one native join.
struct Prepared {
    operation: AdmissionOperationV1,
    lease: AdmissionRecoveryLease,
    context: SecurityInvocationContext,
    request: FlowJoinRequest,
}

fn prepare(
    fixture: &Fixture,
    initialized: &SecurityParticipantStateInitialization,
    flow: &Flow,
    transition: &str,
    label: &InformationLabel,
) -> TestResult<Prepared> {
    let (operation, lease, _) = super::mutations::setup_selected_at(
        fixture,
        transition,
        &flow.context,
        now_ms(),
        Some(initialized.admission_binding()?),
    )?;
    Ok(Prepared {
        operation,
        lease,
        context: current_context(fixture, initialized.security_authority_id().as_str(), flow)?,
        request: FlowJoinRequest {
            key: flow.key.clone(),
            principal_join: InformationLabel::bottom(),
            lineage_join: InformationLabel::bottom(),
            session_join: label.clone(),
            transition_id: RecordId::new(transition)?,
        },
    })
}

fn join(
    fixture: &Fixture,
    initialized: &SecurityParticipantStateInitialization,
    prepared: &Prepared,
) -> Result<FlowStateSnapshot, AdmissionOperationStoreError> {
    fixture.store.join_security_participant_flow(
        &prepared.operation,
        &prepared.lease,
        initialized,
        &prepared.context,
        &prepared.request,
        now_ms(),
    )
}

/// A label at the default owner and reader limits. Every owner is a member of
/// its own reader set, so the shared reader roster carries all 64 owners plus
/// 192 dedicated readers, staying at the 256 readers per owner limit. One
/// session row holding it is a few hundred KiB of live custody.
fn wide_label(seed: &str) -> TestResult<InformationLabel> {
    let owned = (0..64)
        .map(|owner| PrincipalId::new(format!("{seed}-owner-{owner:02}")))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut readers = (0..192)
        .map(|reader| PrincipalId::new(format!("{seed}-reader-{reader:04}")))
        .collect::<Result<BTreeSet<_>, _>>()?;
    readers.extend(owned.iter().cloned());
    let owners = owned
        .into_iter()
        .map(|owner| Ok((owner, readers.clone())))
        .collect::<TestResult<BTreeMap<_, _>>>()?;
    Ok(InformationLabel::try_known(owners, BTreeSet::new())?)
}

/// Every durable trace a refused native append could leave.
fn footprint(connection: &Connection) -> TestResult<[i64; 5]> {
    Ok(connection.query_row(
        "SELECT (SELECT COUNT(*) FROM security_participant_state_mutations),
                (SELECT COUNT(*) FROM security_participant_state_transitions),
                (SELECT COUNT(*) FROM security_participant_state_session_flow_state),
                (SELECT COUNT(*) FROM authority_global_commits),
                (SELECT COUNT(*) FROM admission_operation_recovery_records)",
        [],
        |row| {
            Ok([
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ])
        },
    )?)
}

fn seals(connection: &Connection) -> TestResult<i64> {
    Ok(connection.query_row(
        "SELECT COUNT(*) FROM admission_operation_recovery_records
         WHERE record_key GLOB 'native-journal-seal:*'",
        [],
        |row| row.get(0),
    )?)
}

fn native_rows(connection: &Connection, authority: &str) -> TestResult<i64> {
    let mut total = 0_i64;
    for table in native::schema::TABLES {
        total += connection.query_row(
            &format!(
                "SELECT COUNT(*) FROM {} WHERE security_authority_id = ?1",
                table.native
            ),
            [authority],
            |row| row.get::<_, i64>(0),
        )?;
    }
    Ok(total)
}

/// Run one catalog-restored tamper in a rolled-back transaction and return
/// the cold verification refusal.
fn cold_refusal(fixture: &Fixture, mutation: &str) -> TestResult<String> {
    let mut connection = fixture.store.connection()?;
    let tx = connection.transaction()?;
    let mut statement = tx.prepare(
        "SELECT name FROM sqlite_schema WHERE type = 'trigger'
         AND name GLOB 'security_participant_state*'",
    )?;
    let triggers = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    for trigger in triggers {
        tx.execute_batch(&format!("DROP TRIGGER {trigger}"))?;
    }
    tx.execute_batch(mutation)?;
    tx.execute_batch(&native::schema::sql()?)?;
    let refusal = native::verify_all(&tx)
        .err()
        .ok_or("cold verification accepted a tampered native inventory")?
        .to_string();
    tx.rollback()?;
    Ok(refusal)
}

#[test]
fn tenant_live_bound_refuses_only_new_keys_of_its_own_tenant() -> TestResult {
    let fixture = fixture();
    // The large authenticated capacity writes below would otherwise let real
    // elapsed time consume the fixture's 10-second claim lifetime while the
    // store acquires and checks authority. Run the whole selector on the
    // Kernel's thread-bound fixed clock, started at the trusted clock origin:
    // now_ms() and the authority's own time observation follow it, so no
    // claim expires and no lease is lengthened.
    let _clock = chio_kernel::scope_fixed_runtime_clock_for_current_thread(
        clock_origin_ms(&fixture)? / 1_000,
    );
    let source = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let other = hydrate(&fixture, &imported(&fixture, "other")?)?;
    imported(&fixture, "ghost")?;
    let label = wide_label("live")?;
    let original = flow(
        "native-tenant",
        "native-principal",
        "native-lineage",
        "session-0",
    )?;
    let first = prepare(&fixture, &source, &original, "live-0", &label)?;
    let first_result = join(&fixture, &source, &first)?;
    let mut session = 1_u32;
    let refusal = loop {
        assert!(
            session < 1024,
            "the tenant live bound never refused a new key"
        );
        let next = flow(
            "native-tenant",
            "native-principal",
            "native-lineage",
            &format!("session-{session}"),
        )?;
        let next = prepare(&fixture, &source, &next, &format!("live-{session}"), &label)?;
        let before = footprint(&*fixture.store.connection()?)?;
        match join(&fixture, &source, &next) {
            Ok(_) => session += 1,
            Err(error) => {
                assert_eq!(footprint(&*fixture.store.connection()?)?, before);
                break error.to_string();
            }
        }
    };
    assert!(
        refusal.contains("native tenant live state exhausted"),
        "{refusal}"
    );
    // The same journal crossed its live segment bound and continued sealed.
    assert!(seals(&*fixture.store.connection()?)? >= 1);

    // An existing key still joins: its transition is retained identity.
    let existing = prepare(&fixture, &source, &original, "live-existing", &label)?;
    join(&fixture, &source, &existing)?;
    // The first operation replays its original result and writes nothing.
    let operation = fixture
        .store
        .load_by_operation_id(first.operation.binding().operation_id())?
        .ok_or("first operation")?;
    // The fixed clock keeps the first operation's original lease live, and
    // production fencing correctly refuses a different claimant while it is.
    // Advance the same fixture clock beyond that lease before the replay's
    // reclaim; the rest of the selector stays at this later, still fixed
    // time, so every later decision remains monotone.
    let _past_first_lease = chio_kernel::scope_fixed_runtime_clock_for_current_thread(
        first.lease.expires_at_unix_ms().div_ceil(1_000),
    );
    let replay = Prepared {
        lease: claim(&fixture, &operation, "live-replay", now_ms()),
        operation,
        context: current_context(&fixture, "source", &original)?,
        request: first.request.clone(),
    };
    let before = footprint(&*fixture.store.connection()?)?;
    assert_eq!(join(&fixture, &source, &replay)?, first_result);
    assert_eq!(footprint(&*fixture.store.connection()?)?, before);

    // Another tenant of the same authority, and another authority, continue.
    let tenant = flow(
        "other-tenant",
        "native-principal",
        "native-lineage",
        "session-0",
    )?;
    join(
        &fixture,
        &source,
        &prepare(&fixture, &source, &tenant, "tenant-first", &label)?,
    )?;
    join(
        &fixture,
        &source,
        &prepare(&fixture, &source, &tenant, "tenant-again", &label)?,
    )?;
    join(
        &fixture,
        &other,
        &prepare(&fixture, &other, &original, "authority-first", &label)?,
    )?;
    native::verify_all(&*fixture.store.connection()?)?;
    native::verify_coverage(&*fixture.store.connection()?)?;

    // Cold verification refuses a live account above its bound and a row of
    // an authority that was never initialized.
    let above = cold_refusal(
        &fixture,
        "INSERT INTO security_participant_state_session_flow_state
         SELECT security_authority_id, tenant_id, principal_id, 'tampered-' || copy.ordinal,
                isolation_epoch_id, label_json, label_hash, generation
         FROM security_participant_state_session_flow_state,
              (SELECT 1 AS ordinal UNION ALL SELECT 2) AS copy
         WHERE security_authority_id = 'source' AND tenant_id = 'native-tenant'
           AND session_id = 'session-0'",
    )?;
    assert!(
        above.contains("native tenant live state exceeds its bound"),
        "{above}"
    );
    let orphan = cold_refusal(
        &fixture,
        "INSERT INTO security_participant_state_flow_sequences VALUES ('ghost', 'orphan', 1)",
    )?;
    assert!(orphan.contains("orphan native state"), "{orphan}");
    Ok(())
}

#[test]
fn native_rows_pass_the_old_cap_without_locking_out_tenants() -> TestResult {
    let fixture = fixture();
    let source = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let other = hydrate(&fixture, &imported(&fixture, "other")?)?;
    // Each join on a new identity opens new live rows plus one retained
    // transition, spread over tenants so no tenant reaches its own bound.
    let mut index = 0_u32;
    while !index.is_multiple_of(32)
        || native_rows(&*fixture.store.connection()?, "source")? <= 65_536
    {
        let next = flow(
            &format!("tenant-{}", index % 8),
            &format!("principal-{index}"),
            &format!("lineage-{index}"),
            &format!("session-{index}"),
        )?;
        join(
            &fixture,
            &source,
            &prepare(
                &fixture,
                &source,
                &next,
                &format!("row-{index}"),
                &InformationLabel::bottom(),
            )?,
        )?;
        index += 1;
    }
    let tenant = flow(
        "tenant-after-cap",
        "native-principal",
        "native-lineage",
        "native-session",
    )?;
    join(
        &fixture,
        &source,
        &prepare(
            &fixture,
            &source,
            &tenant,
            "after-cap",
            &InformationLabel::bottom(),
        )?,
    )?;
    join(
        &fixture,
        &other,
        &prepare(
            &fixture,
            &other,
            &tenant,
            "other-after-cap",
            &InformationLabel::bottom(),
        )?,
    )?;

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
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let store = authority.admission_operation_store();
    assert_eq!(
        store.load_security_participant_state(
            source.security_authority_id(),
            &authority.mutation_fence(),
            now_ms()
        )?,
        Some(source.clone())
    );
    let connection = store.connection()?;
    assert!(native_rows(&connection, "source")? > 65_536);
    native::verify_all(&connection)?;
    native::verify_coverage(&connection)?;
    Ok(())
}

fn tenant_transitions(connection: &Connection, authority: &str, tenant: &str) -> TestResult<i64> {
    Ok(connection.query_row(
        "SELECT COUNT(*) FROM security_participant_state_transitions
         WHERE security_authority_id = ?1 AND tenant_id = ?2",
        [authority, tenant],
        |row| row.get(0),
    )?)
}

/// Rows of every table other than retained transitions and the authority
/// singleton, for one (authority, tenant).
fn tenant_live_rows(connection: &Connection, authority: &str, tenant: &str) -> TestResult<i64> {
    let mut total = 0_i64;
    for table in native::schema::TABLES {
        if matches!(
            table.source,
            "security_transitions" | "security_declassification_lifecycle"
        ) {
            continue;
        }
        total += connection.query_row(
            &format!(
                "SELECT COUNT(*) FROM {} WHERE security_authority_id = ?1 AND tenant_id = ?2",
                table.native
            ),
            [authority, tenant],
            |row| row.get::<_, i64>(0),
        )?;
    }
    Ok(total)
}

/// Retained transitions of one existing flow key are identity, never live
/// custody: the key passes the old 65,536 native row cap through real
/// admission operations while its tenant's live rows stay constant, and its
/// replay, the same key, another tenant and a restart all continue.
#[test]
#[ignore = "scale acceptance; 65,537 real native admission operations on one flow key, run with --release -- --ignored"]
fn one_flow_key_retains_transitions_past_the_old_cap_without_live_growth() -> TestResult {
    let fixture = fixture();
    let source = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let bottom = InformationLabel::bottom();
    let key = flow(
        "native-tenant",
        "native-principal",
        "native-lineage",
        "native-session",
    )?;
    let first = prepare(&fixture, &source, &key, "same-key-0", &bottom)?;
    let first_result = join(&fixture, &source, &first)?;
    let live = tenant_live_rows(&*fixture.store.connection()?, "source", "native-tenant")?;
    for transition in 1..=65_536_u32 {
        let next = prepare(
            &fixture,
            &source,
            &key,
            &format!("same-key-{transition}"),
            &bottom,
        )?;
        join(&fixture, &source, &next)?;
    }
    {
        let connection = fixture.store.connection()?;
        assert!(tenant_transitions(&connection, "source", "native-tenant")? > 65_536);
        assert!(native_rows(&connection, "source")? > 65_536);
        assert_eq!(
            tenant_live_rows(&connection, "source", "native-tenant")?,
            live
        );
        assert!(seals(&connection)? >= 1);
    }

    // The same key keeps joining past the old cap.
    join(
        &fixture,
        &source,
        &prepare(&fixture, &source, &key, "same-key-after", &bottom)?,
    )?;
    // The first operation replays its original result and writes nothing.
    let operation = fixture
        .store
        .load_by_operation_id(first.operation.binding().operation_id())?
        .ok_or("first operation")?;
    let replay = Prepared {
        lease: claim(&fixture, &operation, "same-key-replay", now_ms()),
        operation,
        context: current_context(&fixture, "source", &key)?,
        request: first.request.clone(),
    };
    let before = footprint(&*fixture.store.connection()?)?;
    assert_eq!(join(&fixture, &source, &replay)?, first_result);
    assert_eq!(footprint(&*fixture.store.connection()?)?, before);
    // Another tenant of the same authority is unaffected.
    let tenant = flow(
        "other-tenant",
        "native-principal",
        "native-lineage",
        "native-session",
    )?;
    join(
        &fixture,
        &source,
        &prepare(&fixture, &source, &tenant, "same-key-tenant", &bottom)?,
    )?;

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
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let store = authority.admission_operation_store();
    assert_eq!(
        store.load_security_participant_state(
            source.security_authority_id(),
            &authority.mutation_fence(),
            now_ms()
        )?,
        Some(source.clone())
    );
    let connection = store.connection()?;
    assert_eq!(
        tenant_live_rows(&connection, "source", "native-tenant")?,
        live
    );
    native::verify_all(&connection)?;
    native::verify_coverage(&connection)?;
    Ok(())
}

#[test]
fn pre_effect_join_under_intake_pressure_leaves_no_history() -> TestResult {
    let fixture = fixture();
    let source = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let label = wide_label("pressure")?;
    // A pinned reader keeps every later frame in the WAL until intake refuses.
    let reader = Connection::open(&fixture.database)?;
    reader.execute_batch("BEGIN")?;
    let _: i64 = reader.query_row(
        "SELECT COUNT(*) FROM security_participant_state_mutations",
        [],
        |row| row.get(0),
    )?;
    let mut session = 0_u32;
    let refusal = loop {
        assert!(
            session < 512,
            "WAL pressure never refused a pre-effect join"
        );
        let next = flow(
            "native-tenant",
            "native-principal",
            "native-lineage",
            &format!("pressure-{session}"),
        )?;
        let next = prepare(
            &fixture,
            &source,
            &next,
            &format!("pressure-{session}"),
            &label,
        )?;
        let before = footprint(&*fixture.store.connection()?)?;
        match join(&fixture, &source, &next) {
            Ok(_) => session += 1,
            Err(error) => {
                assert_eq!(footprint(&*fixture.store.connection()?)?, before);
                break error.to_string();
            }
        }
    };
    assert!(
        refusal.contains("recovery disk headroom exhausted"),
        "{refusal}"
    );
    reader.execute_batch("ROLLBACK")?;
    Ok(())
}

#[test]
fn owed_append_at_a_segment_boundary_needs_its_priced_allowance() -> TestResult {
    let fixture = fixture();
    let source = hydrate(&fixture, &imported(&fixture, "source")?)?;
    let first = flow(
        "native-tenant",
        "native-principal",
        "native-lineage",
        "native-session",
    )?;
    join(
        &fixture,
        &source,
        &prepare(
            &fixture,
            &source,
            &first,
            "owed-live",
            &InformationLabel::bottom(),
        )?,
    )?;
    let mut connection = fixture.store.connection()?;
    let tx = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    let before = footprint(&tx)?;
    let owed =
        native::decide_unfitting_output_fixture(&tx, &fixture.store.serving_owner, &source, true);
    assert!(
        owed.is_err_and(|error| error.to_string().contains("no priced seal allowance")),
        "an owed append sealed without its allowance"
    );
    assert_eq!(footprint(&tx)?, before);
    assert!(native::decide_unfitting_output_fixture(
        &tx,
        &fixture.store.serving_owner,
        &source,
        false
    )?);
    let sealed = footprint(&tx)?;
    assert_eq!(
        sealed,
        [
            before[0],
            before[1],
            before[2],
            before[3] + 1,
            before[4] + 1
        ]
    );
    let seal: i64 = tx.query_row(
        "SELECT length(payload) FROM admission_operation_recovery_records
         WHERE record_key GLOB 'native-journal-seal:*'",
        [],
        |row| row.get(0),
    )?;
    let price = native::finishing_plan::describe_native_seal_allowance(
        &fixture.store.serving_owner,
        &source,
    )?;
    assert!(price.maximum_payload_bytes() >= u64::try_from(seal)?);
    drop(tx);
    Ok(())
}

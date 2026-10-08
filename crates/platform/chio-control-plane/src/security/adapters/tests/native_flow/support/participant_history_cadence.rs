// One participant, sequential native calls through the real kernel and authority.
use super::*;
use chio_kernel::tool_outcome::ToolOutcomeStore;
use std::collections::{BTreeMap, HashSet};
use std::sync::PoisonError;
use std::thread::ThreadId;

const CALLS: usize = 16;
/// Anchored participant events per completed call: nonce preflight, input join,
/// egress acquisition, egress commitment and output join.
const EVENTS_PER_CALL: [u64; 4] = [1, 2, 1, 1];
/// Declared checkpoint contract: when a call's flow resolution starts, the
/// verified suffix retains at most this many completed calls past its seal.
const CHECKPOINT_CADENCE_CALLS: u64 = 4;
const FAMILIES: [&str; 4] = [
    "security_participant_state",
    "security_participant_egress",
    "security_participant_output",
    "security_participant_nonce_preflight",
];

struct Walk {
    thread: ThreadId,
    events: u64,
}

#[derive(Default)]
struct Walks {
    walks: Mutex<Vec<Walk>>,
    gaps: AtomicUsize,
    image_walks: Mutex<Vec<(&'static str, u64)>>,
}

impl Walks {
    fn observe(&self, visited: u64) {
        let mut walks = self.walks.lock().unwrap_or_else(PoisonError::into_inner);
        if visited == 0 {
            walks.push(Walk {
                thread: std::thread::current().id(),
                events: 0,
            });
        } else if let Some(walk) = walks
            .last_mut()
            .filter(|walk| walk.events.checked_add(1) == Some(visited))
        {
            walk.events = visited;
        } else {
            self.gaps.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn observe_image(&self, kind: &'static str, visited: u64) {
        let mut walks = self
            .image_walks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if visited == 0 {
            walks.push((kind, 0));
        } else if let Some(walk) = walks
            .last_mut()
            .filter(|walk| walk.0 == kind && walk.1.checked_add(1) == Some(visited))
        {
            walk.1 = visited;
        } else {
            self.gaps.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn image_len(&self) -> usize {
        self.image_walks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    fn image_since(&self, start: usize) -> Vec<(&'static str, u64)> {
        self.image_walks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(start..)
            .unwrap_or_default()
            .to_vec()
    }

    fn len(&self) -> usize {
        self.walks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    fn since(&self, start: usize) -> (Vec<u64>, HashSet<ThreadId>) {
        let walks = self.walks.lock().unwrap_or_else(PoisonError::into_inner);
        let selected = walks.get(start..).unwrap_or_default();
        (
            selected.iter().map(|walk| walk.events).collect(),
            selected.iter().map(|walk| walk.thread).collect(),
        )
    }
}

struct Cost {
    walks: Vec<u64>,
    threads: usize,
    preflight_walks: usize,
    journal_before: u64,
    journal_after: u64,
    image_after: u64,
    sealed_after: [u64; 2],
    elapsed: std::time::Duration,
    image_walks: Vec<(&'static str, u64)>,
}

impl Cost {
    fn visits(&self) -> u64 {
        self.walks.iter().sum()
    }
}

fn journal(fixture: &Fixture) -> TestResult<[u64; 4]> {
    let connection = rusqlite::Connection::open_with_flags(
        fixture._directory.path().join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut counts = [0; 4];
    for (count, kind) in counts.iter_mut().zip(FAMILIES) {
        let stored: i64 = connection.query_row(
            "SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = ?1 AND projection_key = ?2",
            rusqlite::params![kind, fixture.binding.security_authority_id().as_str()],
            |row| row.get(0),
        )?;
        *count = u64::try_from(stored)?;
    }
    Ok(counts)
}

/// Current native rows of this participant, the image every verification reads.
fn image(fixture: &Fixture) -> TestResult<BTreeMap<String, u64>> {
    let connection = rusqlite::Connection::open_with_flags(
        fixture._directory.path().join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut statement = connection.prepare(
        "SELECT name FROM sqlite_schema WHERE type = 'table' AND name GLOB 'security_participant_state_*'
         AND name NOT IN ('security_participant_state_mutations', 'security_participant_state_initializations')",
    )?;
    let tables = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut rows = BTreeMap::new();
    for table in tables {
        let stored: i64 = connection.query_row(
            &format!("SELECT COUNT(*) FROM \"{table}\" WHERE security_authority_id = ?1"),
            [fixture.binding.security_authority_id().as_str()],
            |row| row.get(0),
        )?;
        rows.insert(table, u64::try_from(stored)?);
    }
    Ok(rows)
}

/// Retained checkpoint events and sealed image rows of this participant.
fn sealed(fixture: &Fixture) -> TestResult<[u64; 2]> {
    let connection = rusqlite::Connection::open_with_flags(
        fixture._directory.path().join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut counts = [0; 2];
    for (count, table) in counts.iter_mut().zip([
        "security_participant_checkpoint_events",
        "security_participant_checkpoint_rows",
    ]) {
        let stored: i64 = connection.query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE security_authority_id = ?1"),
            [fixture.binding.security_authority_id().as_str()],
            |row| row.get(0),
        )?;
        *count = u64::try_from(stored)?;
    }
    Ok(counts)
}

const HEADER: &str = "call journal_before journal_after image_rows seals sealed_rows walks visits max_walk threads elapsed_ms";

fn row(index: usize, cost: &Cost) -> String {
    format!(
        "{index:>4} {:>14} {:>13} {:>10} {:>5} {:>11} {:>5} {:>6} {:>8} {:>7} {:>10}",
        cost.journal_before,
        cost.journal_after,
        cost.image_after,
        cost.sealed_after[0],
        cost.sealed_after[1],
        cost.walks.len(),
        cost.visits(),
        cost.walks.iter().max().copied().unwrap_or_default(),
        cost.threads,
        cost.elapsed.as_millis(),
    )
}

/// Every call's preconditions and the declared suffix contract. Called as
/// each call completes, after its measurements are printed.
fn check(index: usize, cost: &Cost, second: Option<&Cost>) -> TestResult {
    let per_call = EVENTS_PER_CALL.iter().sum::<u64>();
    let measured = row(index, cost);
    // Both evaluations verify anchored history; a walk never exceeds it.
    assert!(cost.preflight_walks > 0, "{measured}");
    assert!(cost.walks.len() > cost.preflight_walks, "{measured}");
    assert!(cost.visits() > 0, "{measured}");
    assert!(
        cost.walks
            .iter()
            .all(|events| *events <= cost.journal_after),
        "{measured}"
    );
    assert_eq!(
        cost.journal_after.checked_sub(cost.journal_before),
        Some(per_call),
        "{measured}"
    );
    // One walk replays at most the declared cadence of completed calls, the
    // open call and, before any seal, the initialization event.
    let walk_bound = CHECKPOINT_CADENCE_CALLS
        .checked_add(1)
        .and_then(|calls| calls.checked_mul(per_call))
        .and_then(|events| events.checked_add(1))
        .ok_or("walk bound overflow")?;
    assert!(
        cost.walks.iter().all(|events| *events <= walk_bound),
        "call {index} walk exceeds the {walk_bound}-event suffix contract\n{HEADER}\n{measured}"
    );
    if let Some(second) = second {
        // Relative to call 2, which already replays initialization and call 1,
        // each walk may retain at most the declared cadence of completed calls.
        let slack = u64::try_from(cost.walks.len())?
            .checked_mul(CHECKPOINT_CADENCE_CALLS)
            .and_then(|walks| walks.checked_mul(per_call))
            .ok_or("slack overflow")?;
        assert!(
            cost.visits() <= second.visits().checked_add(slack).ok_or("bound overflow")?,
            "call {index} visited {} participant events in {} walks, call 2 visited {} in {}; \
             declared cadence allows {slack} more\n{HEADER}\n{}\n{measured}",
            cost.visits(),
            cost.walks.len(),
            second.visits(),
            second.walks.len(),
            row(2, second),
        );
    }
    Ok(())
}

/// Completed custody of one call: nonce preflight, input join, committed
/// egress, dispatch ledger, output join and security release.
fn custody(fixture: &Fixture, request_id: &str) -> TestResult {
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("completed native operation")?;
    let id = operation.binding().operation_id();
    assert_eq!(operation.state(), AdmissionOperationState::Completed);
    assert!(operation.execution_nonce_id().is_some());
    assert!(operation.execution_nonce_issuance_digest().is_some());
    assert!(operation.native_dispatch_ledger_digest().is_some());
    assert!(store
        .load_native_security_nonce_preflight_join(id, &fence, now_ms()?)?
        .ok_or("nonce preflight operation")?
        .1
        .is_some());
    store
        .load_native_security_input_join(id, &fence, now_ms()?)?
        .ok_or("input operation")?
        .1
        .ok_or("input join")?
        .validate()?;
    assert!(store
        .load_native_security_egress(id, &fence, now_ms()?)?
        .ok_or("egress operation")?
        .1
        .ok_or("egress custody")?
        .commitment
        .is_some());
    assert!(store
        .load_native_dispatch_ledger(id, &fence, now_ms()?)?
        .is_some());
    assert!(store
        .load_native_security_output_join(id, &fence, now_ms()?)?
        .ok_or("output operation")?
        .1
        .is_some());
    assert!(fixture
        .authority
        .tool_outcome_store()
        .lookup_security_release(id)?
        .is_some());
    Ok(())
}

fn call(fixture: &mut Fixture, walks: &Walks, index: usize) -> TestResult<Cost> {
    fixture.request.request_id = format!("participant-history-cadence-{index:02}");
    fixture.request.arguments = serde_json::json!({"call": index});
    fixture.request.execution_nonce = None;
    let before = journal(fixture)?;
    let start = walks.len();
    let image_start = walks.image_len();
    let started = std::time::Instant::now();
    // The trusted host refreshes mutable flow state before each evaluation.
    fixture.context = fixture
        .kernel
        .refresh_native_security_context(&fixture.context)?;
    let preflight = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    let preflight_walks = walks
        .len()
        .checked_sub(start)
        .ok_or("walk count regressed")?;
    assert_eq!(preflight.verdict, Verdict::Allow, "{:?}", preflight.reason);
    assert!(preflight.output.is_none());
    assert!(preflight.receipt.verify_signature()?);
    fixture.request.execution_nonce = Some(*preflight.execution_nonce.ok_or("issued nonce")?);
    fixture.context = fixture
        .kernel
        .refresh_native_security_context(&fixture.context)?;
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    let elapsed = started.elapsed();
    let (call_walks, threads) = walks.since(start);
    let image_walks = walks.image_since(image_start);
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert!(
        matches!(&response.output, Some(chio_kernel::ToolCallOutput::Value(value)) if value == &fixture.request.arguments)
    );
    assert!(response.receipt.verify_signature()?);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), index);

    // Readback after measurement: every lifecycle stage ran for this call.
    custody(fixture, &fixture.request.request_id)?;
    let usage = fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(
            fixture.request.capability.id.as_str(),
            0,
        ))?
        .ok_or("captured invocation quota")?;
    assert_eq!(
        (usage.reserved_invocations, usage.captured_invocations),
        (0, u32::try_from(index)?)
    );
    let after = journal(fixture)?;
    for ((before, after), (family, added)) in before
        .iter()
        .zip(after)
        .zip(FAMILIES.into_iter().zip(EVENTS_PER_CALL))
    {
        assert_eq!(
            after.checked_sub(*before),
            Some(added),
            "call {index} {family} events"
        );
    }
    Ok(Cost {
        threads: threads.len(),
        walks: call_walks,
        preflight_walks,
        journal_before: before.iter().sum(),
        journal_after: after.iter().sum(),
        image_after: image(fixture)?.values().sum(),
        sealed_after: sealed(fixture)?,
        elapsed,
        image_walks,
    })
}

/// Anchored participant events after the latest seal, by global commit order.
/// This is the exact set one ordinary history walk must visit.
fn suffix(fixture: &Fixture) -> TestResult<u64> {
    let connection = rusqlite::Connection::open_with_flags(
        fixture._directory.path().join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let stored: i64 = connection.query_row(
        "SELECT COUNT(*) FROM authority_global_commits WHERE projection_key = ?1
         AND projection_kind IN (?2, ?3, ?4, ?5)
         AND commit_sequence > COALESCE((SELECT MAX(commit_sequence) FROM authority_global_commits
             WHERE projection_key = ?1 AND projection_kind = 'security_participant_checkpoint'), 0)",
        rusqlite::params![
            fixture.binding.security_authority_id().as_str(),
            FAMILIES[0],
            FAMILIES[1],
            FAMILIES[2],
            FAMILIES[3]
        ],
        |row| row.get(0),
    )?;
    Ok(u64::try_from(stored)?)
}

/// Measurement coverage: a store read on another thread reports one complete
/// walk per verification over exactly the anchored suffix.
fn calibrate(fixture: &Fixture, walks: &Walks) -> TestResult {
    let expected = suffix(fixture)?;
    let start = walks.len();
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let authority = fixture.binding.security_authority_id().clone();
    let reader = std::thread::spawn(move || -> Result<ThreadId, String> {
        store
            .load_security_participant_state(
                &authority,
                &fence,
                now_ms().map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?
            .ok_or("participant initialization")?;
        Ok(std::thread::current().id())
    })
    .join()
    .map_err(|_| "participant reader panicked")??;
    let (calibration, threads) = walks.since(start);
    assert!(expected > 0);
    assert!(!calibration.is_empty());
    assert!(
        calibration.iter().all(|events| *events == expected),
        "walks {calibration:?}, anchored suffix {expected}"
    );
    assert_eq!(threads, HashSet::from([reader]));
    assert_ne!(reader, std::thread::current().id());
    Ok(())
}

#[test]
fn native_participant_history_verification_stays_bounded_across_sequential_calls() -> TestResult {
    let mut fixture = super::super::public_fixture()?;
    let standalone_calls = super::nonce::execution::configure(&mut fixture, true)?;
    let capability = fixture.kernel.issue_capability(
        &fixture.agent.public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: fixture.request.server_id.clone(),
                tool_name: fixture.request.tool_name.clone(),
                operations: vec![Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: Some(u32::try_from(CALLS)?),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        },
        600,
    )?;
    let trusted = fixture.context.as_v1().clone();
    fixture.context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        trusted.tenant_id().clone(),
        trusted.session_id().clone(),
        trusted.principal_id().clone(),
        trusted.isolation_epoch_id().clone(),
        LineageId::new(capability.id.clone())?,
        trusted.context_generation(),
    ));
    fixture.request.capability = capability;

    let walks = Arc::new(Walks::default());
    fixture
        .authority
        .admission_operation_store()
        .observe_native_history_visits_for_test({
            let walks = walks.clone();
            move |visited| walks.observe(visited)
        })?;

    fixture
        .authority
        .admission_operation_store()
        .observe_native_image_visits_for_test({
            let walks = walks.clone();
            move |kind, visited| walks.observe_image(kind, visited)
        })?;

    eprintln!("native participant history visits\n{HEADER}");
    let mut costs: Vec<Cost> = Vec::with_capacity(CALLS);
    for index in 1..=CALLS {
        let cost = call(&mut fixture, &walks, index)?;
        eprintln!("{}", row(index, &cost));
        for kind in ["snapshot", "current", "imported", "copy"] {
            let visits: Vec<_> = cost
                .image_walks
                .iter()
                .filter(|(tag, _)| *tag == kind)
                .map(|(_, visited)| *visited)
                .collect();
            eprintln!(
                "image call={index} kind={kind} traversals={} visits={} max_traversal={}",
                visits.len(),
                visits.iter().sum::<u64>(),
                visits.iter().max().copied().unwrap_or_default()
            );
        }
        if index == 1 {
            calibrate(&fixture, &walks)?;
        }
        check(index, &cost, costs.get(1).filter(|_| index > 2))?;
        costs.push(cost);
    }
    eprintln!("current image rows {:?}", image(&fixture)?);
    assert_eq!(walks.gaps.load(Ordering::SeqCst), 0);
    assert_eq!(standalone_calls.load(Ordering::SeqCst), 0);
    // Bounding verification must not prune earlier calls' custody.
    for index in 1..=CALLS {
        custody(&fixture, &format!("participant-history-cadence-{index:02}"))?;
    }
    let second = costs.get(1).ok_or("second call")?;
    let last = costs.get(CALLS - 1).ok_or("final call")?;
    check(CALLS, last, Some(second))?;
    Ok(())
}

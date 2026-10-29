//! Mutation event acknowledgement heads, watermarks and abandoned sequence ranges.

use super::*;

#[test]
fn max_mutation_event_seq_reports_head() -> Result<(), Box<dyn std::error::Error>> {
    let (_path_dir, path) = temp_sqlite_path("chio-budget-head");
    let store = SqliteBudgetStore::open(&path)?;
    assert_eq!(store.max_mutation_event_seq()?, 0);
    // A single authorize charge allocates event_seq 1.
    store.try_charge_cost("cap-a", 0, Some(5), 3, None, None)?;
    assert_eq!(store.max_mutation_event_seq()?, 1);
    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn budget_ack_heads_reports_contiguous_prefix_only() -> Result<(), Box<dyn std::error::Error>> {
    let (_path_dir, path) = temp_sqlite_path("chio-ack-heads");
    let store = SqliteBudgetStore::open(&path)?;

    // Import events {40, 42} for origin O (41 skipped) via the snapshot path,
    // which is how a peer's log arrives; floor defaults to 0.
    let event = |seq: u64| BudgetMutationRecord {
        event_id: format!("evt-{seq}"),
        hold_id: None,
        admission_binding: None,
        capability_id: format!("cap-o-{seq}"),
        grant_index: 0,
        kind: BudgetMutationKind::AuthorizeExposure,
        allowed: Some(true),
        authorization_outcome: None,
        invocation_state_before: BudgetInvocationState::Absent,
        invocation_state_after: BudgetInvocationState::Absent,
        monetary_state_before: BudgetMonetaryState::None,
        monetary_state_after: BudgetMonetaryState::None,
        recorded_at: seq as i64,
        event_seq: seq,
        usage_seq: Some(seq),
        exposure_units: 1,
        realized_spend_units: 0,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: 1,
        invocation_quota_usages: Vec::new(),
        invocation_quota_mutations: Vec::new(),
        cumulative_approval: None,
        cumulative_approval_mutation: None,
        cumulative_approval_set_digest: None,
        total_cost_exposed_after: 1,
        total_cost_realized_spend_after: 0,
        authority: Some(BudgetEventAuthority {
            authority_id: "http://origin-o".to_string(),
            lease_id: "http://origin-o#term-1".to_string(),
            lease_epoch: 1,
        }),
    };
    // Missing prefix (holds only {42,43}): with floor 0, no row is in the
    // island=0 group, so the origin is absent -> caller defaults to floor 0.
    store.import_snapshot_records(&[], &[event(42), event(43)])?;
    let heads = store.budget_ack_heads()?;
    assert!(
        heads.iter().all(|(origin, _)| origin != "http://origin-o"),
        "a missing prefix must not be laundered into an ack head"
    );

    // Now add the contiguous prefix 1..=41 for the same origin: the head is
    // the last contiguous seq before the 42/43 island, i.e. 43 becomes reachable.
    let contiguous: Vec<_> = (1..=41).map(event).collect();
    store.import_snapshot_records(&[], &contiguous)?;
    let heads = store.budget_ack_heads()?;
    let head = heads
        .iter()
        .find(|(origin, _)| origin == "http://origin-o")
        .map(|(_, seq)| *seq)
        .ok_or("origin O must now have a contiguous ack head")?;
    assert_eq!(head, 43, "1..=43 is now gap-free, so the head is 43");

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn budget_ack_heads_caps_partial_head_at_interior_gap() -> Result<(), Box<dyn std::error::Error>> {
    let (_path_dir, path) = temp_sqlite_path("chio-ack-heads-partial");
    let store = SqliteBudgetStore::open(&path)?;

    let event = |seq: u64| BudgetMutationRecord {
        event_id: format!("evt-{seq}"),
        hold_id: None,
        admission_binding: None,
        capability_id: format!("cap-p-{seq}"),
        grant_index: 0,
        kind: BudgetMutationKind::AuthorizeExposure,
        allowed: Some(true),
        authorization_outcome: None,
        invocation_state_before: BudgetInvocationState::Absent,
        invocation_state_after: BudgetInvocationState::Absent,
        monetary_state_before: BudgetMonetaryState::None,
        monetary_state_after: BudgetMonetaryState::None,
        recorded_at: seq as i64,
        event_seq: seq,
        usage_seq: Some(seq),
        exposure_units: 1,
        realized_spend_units: 0,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: 1,
        invocation_quota_usages: Vec::new(),
        invocation_quota_mutations: Vec::new(),
        cumulative_approval: None,
        cumulative_approval_mutation: None,
        cumulative_approval_set_digest: None,
        total_cost_exposed_after: 1,
        total_cost_realized_spend_after: 0,
        authority: Some(BudgetEventAuthority {
            authority_id: "http://origin-p".to_string(),
            lease_id: "http://origin-p#term-1".to_string(),
            lease_epoch: 1,
        }),
    };

    // Import {1,2,3,5,6} from floor 0: the run reaches down to the floor and is
    // gap-free through 3, then an interior gap at 4 splits off the {5,6} island.
    // The contiguous ack head must be the last gap-free seq (3), NOT the max
    // present seq (6): a mid-stream hole yields a PARTIAL head.
    store.import_snapshot_records(&[], &[event(1), event(2), event(3), event(5), event(6)])?;
    let heads = store.budget_ack_heads()?;
    let head = heads
        .iter()
        .find(|(origin, _)| origin == "http://origin-p")
        .map(|(_, seq)| *seq)
        .ok_or("origin P has a contiguous prefix from the floor, so it must report a head")?;
    assert_eq!(
        head, 3,
        "an interior gap at 4 caps the head at 3, not the max present seq 6"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn budget_ack_heads_stays_pinned_at_a_post_watermark_gap() -> Result<(), Box<dyn std::error::Error>>
{
    // Once the watermark W has advanced over a contiguous prefix and a REAL hole
    // sits at
    // W+1, the head is pinned at W. The status-path fast path probes only the
    // single W+1 slot and short-circuits the O(suffix) window scan, so it must
    // (a) keep returning W across repeated polls (never advance over the gap) and
    // (b) advance correctly the moment the gap is filled - the result must match
    // the genesis-anchored gaps-and-islands computation exactly.
    let (_path_dir, path) = temp_sqlite_path("chio-ack-heads-post-watermark-gap");
    let store = SqliteBudgetStore::open(&path)?;

    let origin = "http://origin-g";
    let event = |seq: u64| BudgetMutationRecord {
        event_id: format!("evt-{seq}"),
        hold_id: None,
        admission_binding: None,
        capability_id: format!("cap-g-{seq}"),
        grant_index: 0,
        kind: BudgetMutationKind::AuthorizeExposure,
        allowed: Some(true),
        authorization_outcome: None,
        invocation_state_before: BudgetInvocationState::Absent,
        invocation_state_after: BudgetInvocationState::Absent,
        monetary_state_before: BudgetMonetaryState::None,
        monetary_state_after: BudgetMonetaryState::None,
        recorded_at: seq as i64,
        event_seq: seq,
        usage_seq: Some(seq),
        exposure_units: 1,
        realized_spend_units: 0,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: 1,
        invocation_quota_usages: Vec::new(),
        invocation_quota_mutations: Vec::new(),
        cumulative_approval: None,
        cumulative_approval_mutation: None,
        cumulative_approval_set_digest: None,
        total_cost_exposed_after: 1,
        total_cost_realized_spend_after: 0,
        authority: Some(BudgetEventAuthority {
            authority_id: origin.to_string(),
            lease_id: format!("{origin}#term-1"),
            lease_epoch: 1,
        }),
    };
    let origin_head = |heads: &[(String, u64)]| -> Option<u64> {
        heads
            .iter()
            .find(|(id, _)| id == origin)
            .map(|(_, seq)| *seq)
    };

    // Contiguous {1,2,3}: the head reaches 3 and the durable watermark advances to 3.
    store.import_snapshot_records(&[], &[event(1), event(2), event(3)])?;
    assert_eq!(origin_head(&store.budget_ack_heads()?), Some(3));

    // A hole at 4 (== W+1) with a later island {5,6}: the head must stay pinned at
    // 3 no matter how many times it is polled, and must never jump over the gap.
    store.import_snapshot_records(&[], &[event(5), event(6)])?;
    for _ in 0..3 {
        assert_eq!(
            origin_head(&store.budget_ack_heads()?),
            Some(3),
            "a permanent hole at W+1 keeps the head pinned at W (fail-closed, no over-count)"
        );
    }

    // Filling the gap at 4 lets the head advance across the now-contiguous 4,5,6.
    store.import_snapshot_records(&[], &[event(4)])?;
    assert_eq!(
        origin_head(&store.budget_ack_heads()?),
        Some(6),
        "filling W+1 advances the head over the now-contiguous 4,5,6"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn list_abandoned_event_seqs_in_range_bounds_upper_and_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    // The budget delta endpoint must never serialize an unbounded abandoned window.
    // The bounded query enforces
    // BOTH an upper bound (<= page_max) and a row cap in SQL, so a rollback storm
    // cannot materialize millions of tombstones into one response and blow past
    // the peer-response byte cap.
    let (_path_dir, path) = temp_sqlite_path("chio-abandoned-in-range");
    let store = SqliteBudgetStore::open(&path)?;

    let seqs: Vec<u64> = (1..=1000).collect();
    store.record_abandoned_event_seqs(&seqs)?;

    // Upper bound: only (10, 20], ascending.
    let bounded = store.list_abandoned_event_seqs_in_range(10, 20, 100)?;
    assert_eq!(bounded, (11..=20).collect::<Vec<u64>>());

    // Row cap: a huge window returns at most `limit` rows, never the whole window.
    let capped = store.list_abandoned_event_seqs_in_range(0, 1000, 5)?;
    assert_eq!(capped, vec![1, 2, 3, 4, 5]);

    // Contrast: the unbounded method returns the whole window (the oversized-response
    // risk the bounded query removes).
    assert_eq!(store.list_abandoned_event_seqs_after(0)?.len(), 1000);

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn abandoned_seq_ranges_round_trip_and_advance_the_head() -> Result<(), Box<dyn std::error::Error>>
{
    // The cluster snapshot carries abandoned seqs RANGE-ENCODED so a rollback storm's
    // long contiguous run stays a handful of small pairs instead of an unbounded
    // integer list that could exceed MAX_PEER_RESPONSE_BYTES and stall recovery.
    // list_abandoned_event_seq_ranges
    // must COLLAPSE contiguous runs, and record_abandoned_event_seq_ranges must EXPAND
    // them back to the identical seq set so the filled-or-abandoned head advance is
    // preserved bit-for-bit.
    let head_for = |heads: &[(String, u64)], origin: &str| {
        heads.iter().find(|(o, _)| o == origin).map(|(_, seq)| *seq)
    };

    // Enumerated form -> range-encoded runs: {2,3,4},{7},{9,10} collapse to 3 pairs.
    let (_source_path_dir, source_path) = temp_sqlite_path("chio-abandoned-ranges-source");
    let source = SqliteBudgetStore::open(&source_path)?;
    source.record_abandoned_event_seqs(&[2, 3, 4, 7, 9, 10])?;
    assert_eq!(
        source.list_abandoned_event_seq_ranges()?,
        vec![(2, 4), (7, 7), (9, 10)],
        "contiguous abandoned seqs must collapse to inclusive runs"
    );

    // Range form -> enumerated set on a fresh follower (lossless expansion).
    let (_follower_path_dir, follower_path) = temp_sqlite_path("chio-abandoned-ranges-follower");
    let follower = SqliteBudgetStore::open(&follower_path)?;
    follower.record_abandoned_event_seq_ranges(&[(2, 4), (7, 7), (9, 10)])?;
    assert_eq!(
        follower.list_abandoned_event_seqs()?,
        vec![2, 3, 4, 7, 9, 10],
        "a follower expands the runs to the identical abandoned seq set"
    );

    // A single LARGE contiguous run collapses to ONE pair (the rollback-storm case):
    // recorded cheaply via the range insert (a recursive CTE, not per-seq round-trips).
    let (_storm_path_dir, storm_path) = temp_sqlite_path("chio-abandoned-ranges-storm");
    let storm = SqliteBudgetStore::open(&storm_path)?;
    storm.record_abandoned_event_seq_ranges(&[(2, 50_001)])?;
    let ranges = storm.list_abandoned_event_seq_ranges()?;
    assert_eq!(
        ranges,
        vec![(2, 50_001)],
        "a 50k-seq rollback storm stays a single (start, end) pair"
    );
    assert_eq!(storm.list_abandoned_event_seqs()?.len(), 50_000);

    // Head advance: present {1, 50002} with the whole (2, 50001) run abandoned makes
    // [1..=50002] contiguous, so the head advances across the run - exactly as if each
    // seq had been recorded individually.
    storm.import_snapshot_records(
        &[],
        &[
            ack_head_event(1, "e1", "http://o"),
            ack_head_event(50_002, "e-tail", "http://o"),
        ],
    )?;
    assert_eq!(
        head_for(&storm.budget_ack_heads()?, "http://o"),
        Some(50_002),
        "the abandoned RANGE fills every hole so the head advances past the whole run"
    );

    let _ = fs::remove_file(&source_path);
    let _ = fs::remove_file(&follower_path);
    let _ = fs::remove_file(&storm_path);
    Ok(())
}

#[test]
fn budget_ack_heads_recognizes_multi_authority_global_contiguity(
) -> Result<(), Box<dyn std::error::Error>> {
    // event_seq is a single store-wide sequence, so multiple authorities share
    // one global stream and an origin's events are a sparse subsequence of it.
    // budget_ack_heads must anchor on the GLOBAL contiguous head, not a per-origin
    // island.
    let (_path_dir, path) = temp_sqlite_path("chio-ack-heads-multi");
    let store = SqliteBudgetStore::open(&path)?;

    let event = |seq: u64, origin: &str| BudgetMutationRecord {
        event_id: format!("evt-{origin}-{seq}"),
        hold_id: None,
        admission_binding: None,
        capability_id: format!("cap-m-{seq}"),
        grant_index: 0,
        kind: BudgetMutationKind::AuthorizeExposure,
        allowed: Some(true),
        authorization_outcome: None,
        invocation_state_before: BudgetInvocationState::Absent,
        invocation_state_after: BudgetInvocationState::Absent,
        monetary_state_before: BudgetMonetaryState::None,
        monetary_state_after: BudgetMonetaryState::None,
        recorded_at: seq as i64,
        event_seq: seq,
        usage_seq: Some(seq),
        exposure_units: 1,
        realized_spend_units: 0,
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        invocation_count_after: 1,
        invocation_quota_usages: Vec::new(),
        invocation_quota_mutations: Vec::new(),
        cumulative_approval: None,
        cumulative_approval_mutation: None,
        cumulative_approval_set_digest: None,
        total_cost_exposed_after: 1,
        total_cost_realized_spend_after: 0,
        authority: Some(BudgetEventAuthority {
            authority_id: origin.to_string(),
            lease_id: format!("{origin}#term-{seq}"),
            lease_epoch: seq,
        }),
    };
    let head_for = |heads: &[(String, u64)], origin: &str| {
        heads.iter().find(|(o, _)| o == origin).map(|(_, seq)| *seq)
    };
    let a = "http://origin-a";
    let b = "http://origin-b";

    // Interleaved gap-free global prefix 1..=5: A owns {1,2,5}, B owns {3,4}.
    // Even though A's own seqs (1,2,5) are NOT consecutive integers, the GLOBAL
    // stream is gap-free, so both origins are acked at their true max within the
    // global head (5): A -> 5, B -> 4. A per-origin island query would wrongly
    // cap A at 2 (the 5 looks like a gap in A's own order).
    store.import_snapshot_records(
        &[],
        &[
            event(1, a),
            event(2, a),
            event(3, b),
            event(4, b),
            event(5, a),
        ],
    )?;
    let heads = store.budget_ack_heads()?;
    assert_eq!(
        head_for(&heads, a),
        Some(5),
        "origin A's sparse block must be acked to the global head, not its own island"
    );
    assert_eq!(
        head_for(&heads, b),
        Some(4),
        "the authority-change origin B (block starts at global 3) must be acked"
    );

    let _ = fs::remove_file(&path);

    // Global hole: A owns {1,2}, B owns {4,5} -> global seq 3 missing.
    // The global head is 2, so A -> 2 and B is ABSENT. A naive MAX-per-origin
    // ack head would over-report B = 5 past the hole (a double-spend risk).
    let (_path_dir, path) = temp_sqlite_path("chio-ack-heads-multi-hole");
    let store = SqliteBudgetStore::open(&path)?;
    store.import_snapshot_records(&[], &[event(1, a), event(2, a), event(4, b), event(5, b)])?;
    let heads = store.budget_ack_heads()?;
    assert_eq!(
        head_for(&heads, a),
        Some(2),
        "origin A is gap-free through the global head 2"
    );
    assert_eq!(
        head_for(&heads, b),
        None,
        "origin B (all events above the global hole at 3) must be absent, never acked past the hole"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}
#[test]
fn mutation_event_witness_returns_this_events_seq_not_authority_max(
) -> Result<(), Box<dyn std::error::Error>> {
    // The quorum-witness token must wait on THIS write's own event_seq (looked up
    // by event_id), not MAX(event_seq) for the authority, which a later
    // same-authority commit raises.
    let (_path_dir, path) = temp_sqlite_path("chio-event-seq-by-id");
    let store = SqliteBudgetStore::open(&path)?;
    // Two events under the SAME authority: e1 at seq 1, e2 at seq 2.
    store.import_snapshot_records(
        &[],
        &[
            ack_head_event(1, "e1", "http://a"),
            ack_head_event(2, "e2", "http://a"),
        ],
    )?;
    assert_eq!(
        store.mutation_event_witness_for_event_id("e1")?,
        Some((1, Some("http://a".to_owned()), Some(1)))
    );
    assert_eq!(
        store.mutation_event_witness_for_event_id("e2")?,
        Some((2, Some("http://a".to_owned()), Some(1)))
    );
    assert_eq!(store.mutation_event_witness_for_event_id("missing")?, None);
    // The authority MAX is 2 - the WRONG seq for e1's quorum wait; the by-id
    // lookup returns 1, so e1's wait targets its own event.
    assert_eq!(store.max_mutation_event_seq_for_authority("http://a")?, 2);

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn budget_ack_head_watermark_recomputes_after_delete_caps_below_hole(
) -> Result<(), Box<dyn std::error::Error>> {
    // budget_ack_heads maintains the contiguous head from a durable watermark for
    // O(new rows) cost, but a DELETE that punches a hole
    // below the watermark must reset it so the next call re-verifies and caps the
    // head below the hole (never a stale-high head that over-counts).
    let (_path_dir, path) = temp_sqlite_path("chio-ack-watermark-delete");
    let store = SqliteBudgetStore::open(&path)?;
    let head_for = |heads: &[(String, u64)], origin: &str| {
        heads.iter().find(|(o, _)| o == origin).map(|(_, seq)| *seq)
    };
    store.import_snapshot_records(
        &[],
        &[
            ack_head_event(1, "e1", "http://o"),
            ack_head_event(2, "e2", "http://o"),
            ack_head_event(3, "e3", "http://o"),
        ],
    )?;
    // Contiguous 1..3 -> head 3. Called twice to prove the watermark is stable
    // (the second call is a no-op advance, not a regression).
    assert_eq!(head_for(&store.budget_ack_heads()?, "http://o"), Some(3));
    assert_eq!(head_for(&store.budget_ack_heads()?, "http://o"), Some(3));
    assert_eq!(store.budget_snapshot_covered_head()?, 3);

    // Delete the middle event (seq 2): the watermark reset forces re-verification
    // and the head caps at 1, NOT the stale-high 3.
    store.delete_mutation_event("e2")?;
    assert_eq!(
        store.budget_snapshot_covered_head()?,
        1,
        "snapshot coverage must not trust an allocator high-water mark past a hole"
    );
    assert_eq!(
        head_for(&store.budget_ack_heads()?, "http://o"),
        Some(1),
        "a hole punched below the watermark must cap the head at 1, never stay at 3"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn budget_mutation_events_delete_trigger_resets_watermark_even_without_manual_call(
) -> Result<(), Box<dyn std::error::Error>> {
    // Defense-in-depth: every known DELETE FROM budget_mutation_events call site
    // pairs the delete with a manual reset_budget_ack_head_watermark call in the
    // same transaction. This test proves the invariant does NOT depend on that
    // discipline: a raw SQL delete that deliberately bypasses the manual reset
    // path (simulating a future call site that forgets it, or an out-of-band /
    // operator delete) must still zero the watermark, because the
    // budget_mutation_events_reset_ack_head_watermark AFTER DELETE trigger fires
    // structurally on the table itself.
    //
    // Without the trigger this test fails: head_seq would stay stale-high at 3
    // and budget_ack_heads would over-count origin "http://o" up to a seq (3)
    // whose row 2 no longer exists - a witness over-count / data-loss double-spend.
    let (_path_dir, path) = temp_sqlite_path("chio-ack-watermark-trigger-raw-delete");
    let store = SqliteBudgetStore::open(&path)?;
    let head_for = |heads: &[(String, u64)], origin: &str| {
        heads.iter().find(|(o, _)| o == origin).map(|(_, seq)| *seq)
    };

    store.import_snapshot_records(
        &[],
        &[
            ack_head_event(1, "e1", "http://o"),
            ack_head_event(2, "e2", "http://o"),
            ack_head_event(3, "e3", "http://o"),
        ],
    )?;
    // Advance the watermark to 3 via the normal incremental path.
    assert_eq!(head_for(&store.budget_ack_heads()?, "http://o"), Some(3));
    {
        let connection = store.connection()?;
        let watermark: i64 = connection.query_row(
            "SELECT head_seq FROM budget_ack_head_watermark WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(watermark, 3, "watermark must have advanced to 3");
    }

    // Delete row seq 2 directly via raw SQL, bypassing delete_mutation_event
    // (and therefore bypassing reset_budget_ack_head_watermark entirely) to
    // isolate the trigger as the sole thing that can reset the watermark here.
    {
        let connection = store.connection()?;
        let deleted = connection.execute(
            "DELETE FROM budget_mutation_events WHERE event_id = ?1",
            params!["e2"],
        )?;
        assert_eq!(deleted, 1, "raw delete must remove exactly one row");
    }

    // The trigger fired in the same transaction as the raw DELETE (SQLite AFTER
    // triggers run within the firing statement), so head_seq is already 0 with
    // no further application-level call.
    {
        let connection = store.connection()?;
        let watermark: i64 = connection.query_row(
            "SELECT head_seq FROM budget_ack_head_watermark WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            watermark, 0,
            "the AFTER DELETE trigger must reset head_seq to 0 on any delete, \
             even one that bypasses reset_budget_ack_head_watermark"
        );
    }

    // budget_ack_heads must therefore re-verify from genesis and cap at 1, not
    // report a stale-high (or worse, unreset) head past the punched hole at 2.
    assert_eq!(
        head_for(&store.budget_ack_heads()?, "http://o"),
        Some(1),
        "re-verification from a reset watermark must cap the head at 1, not stay at 3"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn ack_head_reset_trigger_is_idempotent_across_reopens_and_concurrent_opens(
) -> Result<(), Box<dyn std::error::Error>> {
    // open() must not DROP+CREATE the ack-reset trigger on every open. Repeated and
    // concurrent opens must not error (no "trigger
    // already exists" race) and must not churn the trigger, while it still exists
    // exactly once with the current per-origin-clearing body.
    let (_path_dir, path) = temp_sqlite_path("chio-trigger-idempotent");
    // First open creates the trigger.
    {
        let _ = SqliteBudgetStore::open(&path)?;
    }
    // Many concurrent opens: the steady-state path is a single sqlite_master read
    // with no DDL, so none of these may fail or churn the trigger.
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let path = path.clone();
            std::thread::spawn(move || SqliteBudgetStore::open(&path).map(|_| ()))
        })
        .collect();
    for handle in handles {
        handle
            .join()
            .expect("open thread panicked")
            .expect("a concurrent open must preserve the catalog");
    }

    let store = SqliteBudgetStore::open(&path)?;
    // The trigger exists exactly once and clears the per-origin heads (new body).
    {
        let connection = store.connection()?;
        let count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' \
             AND name = 'budget_mutation_events_reset_ack_head_watermark'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(count, 1, "the reset trigger must exist exactly once");
        let sql: String = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' \
             AND name = 'budget_mutation_events_reset_ack_head_watermark'",
            [],
            |row| row.get(0),
        )?;
        assert!(
            sql.contains("budget_origin_ack_heads"),
            "the trigger must be the current version that clears the per-origin heads"
        );
    }

    // Functional: after all the reopens the trigger still resets the watermark on
    // delete, so the ack head re-verifies and caps below a punched hole.
    let head_for = |heads: &[(String, u64)], origin: &str| {
        heads.iter().find(|(o, _)| o == origin).map(|(_, seq)| *seq)
    };
    store.import_snapshot_records(
        &[],
        &[
            ack_head_event(1, "t1", "http://o"),
            ack_head_event(2, "t2", "http://o"),
            ack_head_event(3, "t3", "http://o"),
        ],
    )?;
    assert_eq!(head_for(&store.budget_ack_heads()?, "http://o"), Some(3));
    store.delete_mutation_event("t2")?;
    assert_eq!(
        head_for(&store.budget_ack_heads()?, "http://o"),
        Some(1),
        "the reset trigger must still fire after repeated/concurrent reopens"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn abandoned_seqs_advance_the_head_but_genuine_gaps_still_cap(
) -> Result<(), Box<dyn std::error::Error>> {
    // An abandoned/tombstoned seq (a rolled-back-then-re-appended write's original
    // seq) is treated as FILLED so the global contiguous ack head advances past it
    // (no permanent stall). A GENUINELY missing seq (never recorded abandoned) still
    // caps the head (never over-counts a data-losing node).
    let (_path_dir, path) = temp_sqlite_path("chio-abandoned-fills-hole");
    let store = SqliteBudgetStore::open(&path)?;
    let head_for = |heads: &[(String, u64)], origin: &str| {
        heads.iter().find(|(o, _)| o == origin).map(|(_, seq)| *seq)
    };

    // Present {1, 3} with a hole at 2: without an abandoned record the head caps
    // at 1 (fail-closed).
    store.import_snapshot_records(
        &[],
        &[
            ack_head_event(1, "e1", "http://o"),
            ack_head_event(3, "e3", "http://o"),
        ],
    )?;
    assert_eq!(
        head_for(&store.budget_ack_heads()?, "http://o"),
        Some(1),
        "a genuine gap at 2 must cap the head at 1"
    );

    // Record 2 as abandoned: the head now advances to 3 (2 is a filled tombstone).
    store.record_abandoned_event_seqs(&[2])?;
    assert_eq!(
        head_for(&store.budget_ack_heads()?, "http://o"),
        Some(3),
        "an abandoned seq is filled, so the head advances past it"
    );

    // Add {5} (a NEW genuine hole at 4, not abandoned): the head still caps at 3.
    store.import_snapshot_records(&[], &[ack_head_event(5, "e5", "http://o")])?;
    assert_eq!(
        head_for(&store.budget_ack_heads()?, "http://o"),
        Some(3),
        "a genuine missing seq 4 (not abandoned) must still cap the head at 3"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn mutation_event_witness_returns_stored_origin_authority() -> Result<(), Box<dyn std::error::Error>>
{
    // The witness identity for an idempotent retry comes from the event's STORED
    // origin authority, not the current lease, so a retry
    // after leadership moved targets the origin peers advertise it under.
    let (_path_dir, path) = temp_sqlite_path("chio-stored-witness");
    let store = SqliteBudgetStore::open(&path)?;
    let old_leader = authority("http://old-leader", "http://old-leader#term-3", 3);
    store.try_charge_cost_with_ids_and_authority(
        "cap",
        0,
        Some(10),
        5,
        None,
        None,
        None,
        Some("evt-1"),
        Some(&old_leader),
    )?;

    let (seq, authority_id, lease_epoch) = store
        .mutation_event_witness_for_event_id("evt-1")?
        .ok_or("the written event must be found")?;
    assert!(seq > 0, "a real event carries a positive seq");
    assert_eq!(
        authority_id.as_deref(),
        Some("http://old-leader"),
        "the witness must carry the STORED origin, not the current leader"
    );
    assert_eq!(lease_epoch, Some(3), "and the stored lease epoch");

    // An absent event returns None so the caller falls back to the current lease.
    assert!(store
        .mutation_event_witness_for_event_id("evt-absent")?
        .is_none());

    let _ = fs::remove_file(&path);
    Ok(())
}

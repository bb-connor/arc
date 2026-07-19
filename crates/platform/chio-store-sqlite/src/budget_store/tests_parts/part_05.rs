#[test]
fn follower_replace_inserts_reappended_event_and_head_reaches_new_seq() {
    // Exercises the follower REPLACE path. An ALREADY-SYNCED follower holds the
    // ORIGINAL authorize E@1 (its pull cursor is already past 1). When it imports
    // the leader's re-appended E@new (same event_id, fresh higher seq), the REPLACE
    // path deletes E@1 and tombstones seq 1, then MUST re-insert E@new so the
    // follower actually holds the retried write and its budget_ack_heads head
    // ADVANCES to the new seq. Without the re-insert, E@new is ABSENT and the head
    // halts at the rollback marker (never witnessing the retried write -> quorum
    // waits time out). This asserts the ABSOLUTE new seq (not head == max, which
    // passes even with E@new missing because both degrade to the rollback marker
    // together).
    let leader_path = unique_db_path("chio-follower-replace-leader");
    let follower_path = unique_db_path("chio-follower-replace-follower");
    let leader = SqliteBudgetStore::open(&leader_path).unwrap();
    let follower = SqliteBudgetStore::open(&follower_path).unwrap();
    let hold_id = "hold-fr";
    let event_id = "evt-fr:authorize";
    let initial = authority("budget-primary", "lease-1", 1);
    let changed = authority("budget-primary", "lease-2", 2);

    // Leader authorizes E (seq 1), then rolls it back (rollback marker at seq 2).
    assert!(leader
        .try_charge_cost_with_ids_and_authority(
            "cap-fr",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&initial),
        )
        .unwrap());
    leader
        .reverse_charge_cost_with_ids_and_authority(
            "cap-fr",
            0,
            100,
            Some(hold_id),
            Some("evt-fr:authorize:rollback:1"),
            Some(&initial),
        )
        .unwrap();

    // Follower syncs the PRE-retry state (E@1 + the rollback marker), and confirms it
    // holds the ORIGINAL authorize at seq 1 with no abandoned slot yet.
    let pre_retry = leader.list_mutation_events_after_seq(100, 0).unwrap();
    import_events_with_quota_authority(&follower, &pre_retry).unwrap();
    assert_eq!(
        follower.mutation_event_seq_for_event_id(event_id).unwrap(),
        Some(1),
        "follower holds the ORIGINAL authorize at seq 1 pre-retry"
    );
    assert!(follower.list_abandoned_event_seqs().unwrap().is_empty());

    // Leader retries under the NEW lease: deletes E@1 (abandons 1), re-appends E@new.
    assert!(leader
        .try_charge_cost_with_ids_and_authority(
            "cap-fr",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .unwrap());
    let reappended = leader
        .list_mutation_events_after_seq(100, 0)
        .unwrap()
        .into_iter()
        .find(|record| record.event_id == event_id)
        .expect("the re-appended authorize event");
    let new_seq = reappended.event_seq;
    assert!(
        new_seq > 2,
        "re-appended strictly above the rollback marker"
    );

    // Follower imports the re-appended authorize. The REPLACE path deletes E@1,
    // tombstones seq 1, and re-inserts E@new.
    import_events_with_quota_authority(&follower, std::slice::from_ref(&reappended)).unwrap();

    // The re-appended event is PRESENT at its new seq (exactly one row: the
    // unique event_seq index would reject a duplicate).
    assert_eq!(
        follower.mutation_event_seq_for_event_id(event_id).unwrap(),
        Some(new_seq),
        "the follower re-inserts the re-appended event at its fresh seq"
    );
    // The follower's max advances to the re-appended seq (E@new is held, not lost).
    assert_eq!(
        follower.max_mutation_event_seq().unwrap(),
        new_seq,
        "the follower's max advances to the re-appended seq"
    );
    // The contiguous ack head ADVANCES to the ABSOLUTE new seq, so the
    // follower witnesses the retried write.
    let head = follower
        .budget_ack_heads()
        .unwrap()
        .into_iter()
        .find(|(origin, _)| origin == "budget-primary")
        .map(|(_, seq)| seq);
    assert_eq!(
        head,
        Some(new_seq),
        "the follower's ack head reaches the re-appended seq, not the rollback marker"
    );
    // The superseded OLD seq stays abandoned (a FILLED-but-not-live slot: it lets the
    // head cross the hole but contributes no origin ack, so no over-count).
    assert_eq!(
        follower.list_abandoned_event_seqs().unwrap(),
        vec![1],
        "the superseded old seq stays abandoned, never a live witness"
    );

    let _ = fs::remove_file(&leader_path);
    let _ = fs::remove_file(&follower_path);
}

#[test]
fn same_authority_rollback_retry_reinserts_reappended_event_and_head_advances() {
    // Exercises the SAME-AUTHORITY re-append. When the leader keeps its lease and
    // retries a rolled-back authorize, the re-appended event is byte-identical to
    // the original EXCEPT its fresh higher event_seq, so `same_imported_mutation`
    // (authority/content-only, ignores event_seq) reports it a duplicate. If the
    // importer short-circuited on that, it would never store the re-appended row, so
    // the follower's ack head would stall at the rollback marker (seq 2) and it could
    // not witness the retried write until a full snapshot rebuild. Gating the replace
    // path on `record.event_seq > existing.event_seq` makes a differing seq force the
    // replace + reinsert even when authority/content match; without it the follower
    // still holds E@1 and its head is 2.
    let leader_path = unique_db_path("chio-same-authority-retry-leader");
    let follower_path = unique_db_path("chio-same-authority-retry-follower");
    let leader = SqliteBudgetStore::open(&leader_path).unwrap();
    let follower = SqliteBudgetStore::open(&follower_path).unwrap();
    let hold_id = "hold-sa";
    let event_id = "evt-sa:authorize";
    // ONE authority reused across the original authorize AND the retry: the leader
    // never changed leases, so the re-appended event's authority is byte-identical.
    let leased = authority("budget-primary", "lease-1", 1);

    // Leader authorizes E (seq 1), then rolls it back (rollback marker at seq 2).
    assert!(leader
        .try_charge_cost_with_ids_and_authority(
            "cap-sa",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&leased),
        )
        .unwrap());
    leader
        .reverse_charge_cost_with_ids_and_authority(
            "cap-sa",
            0,
            100,
            Some(hold_id),
            Some("evt-sa:authorize:rollback:1"),
            Some(&leased),
        )
        .unwrap();

    // Follower syncs the PRE-retry state (E@1 + the rollback marker) and confirms it
    // holds the ORIGINAL authorize at seq 1 with no abandoned slot yet.
    let pre_retry = leader.list_mutation_events_after_seq(100, 0).unwrap();
    import_events_with_quota_authority(&follower, &pre_retry).unwrap();
    assert_eq!(
        follower.mutation_event_seq_for_event_id(event_id).unwrap(),
        Some(1),
        "follower holds the ORIGINAL authorize at seq 1 pre-retry"
    );
    assert!(follower.list_abandoned_event_seqs().unwrap().is_empty());

    // Leader retries under the SAME lease: the rollback decremented the usage
    // counters, so this is a GENUINE re-append (not the idempotent no-op) - it
    // deletes E@1 (abandons 1) and re-appends E@new at a fresh higher seq.
    assert!(leader
        .try_charge_cost_with_ids_and_authority(
            "cap-sa",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&leased),
        )
        .unwrap());
    let reappended = leader
        .list_mutation_events_after_seq(100, 0)
        .unwrap()
        .into_iter()
        .find(|record| record.event_id == event_id)
        .expect("the re-appended authorize event");
    let new_seq = reappended.event_seq;
    assert!(
        new_seq > 2,
        "re-appended strictly above the rollback marker (leader really re-appended, not idempotent)"
    );
    // Sanity: the re-appended event carries the SAME authority as the original, so
    // `same_imported_mutation` would call it a duplicate on authority/content alone.
    assert_eq!(
        reappended.authority.as_ref(),
        Some(&leased),
        "the retry kept the original lease (same-authority re-append)"
    );

    // Follower imports the same-authority re-append.
    import_events_with_quota_authority(&follower, std::slice::from_ref(&reappended)).unwrap();

    // The re-appended event is PRESENT at its new seq (exactly one row: the
    // unique event_seq index would reject a duplicate).
    assert_eq!(
        follower.mutation_event_seq_for_event_id(event_id).unwrap(),
        Some(new_seq),
        "the follower re-inserts the same-authority re-append at its fresh seq"
    );
    assert_eq!(
        follower.max_mutation_event_seq().unwrap(),
        new_seq,
        "the follower's max advances to the re-appended seq"
    );
    // The contiguous ack head ADVANCES to the ABSOLUTE new seq (not the
    // rollback marker), so the follower witnesses the retried write.
    let head = follower
        .budget_ack_heads()
        .unwrap()
        .into_iter()
        .find(|(origin, _)| origin == "budget-primary")
        .map(|(_, seq)| seq);
    assert_eq!(
        head,
        Some(new_seq),
        "the follower's ack head reaches the re-appended seq, not the rollback marker"
    );
    // The superseded OLD seq stays abandoned: a FILLED-but-not-live slot that lets
    // the head cross the hole but contributes NO origin ack, so no over-count.
    assert_eq!(
        follower.list_abandoned_event_seqs().unwrap(),
        vec![1],
        "the superseded old seq stays abandoned, never a live witness"
    );

    let _ = fs::remove_file(&leader_path);
    let _ = fs::remove_file(&follower_path);
}

#[test]
fn mutation_event_witness_returns_stored_origin_authority() -> Result<(), Box<dyn std::error::Error>>
{
    // The witness identity for an idempotent retry comes from the event's STORED
    // origin authority, not the current lease, so a retry
    // after leadership moved targets the origin peers advertise it under.
    let path = unique_db_path("chio-stored-witness");
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

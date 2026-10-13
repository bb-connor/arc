use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

// These units check immutable allocation algebra and protected record preimages.
// Actual owner/global-chain migration custody is exercised by the native case.
fn empty_fixture() -> Result<Connection, Box<dyn std::error::Error>> {
    let tx = Connection::open_in_memory()?;
    tx.execute_batch(
        "CREATE TABLE admission_operation_recovery_records (
            record_key TEXT PRIMARY KEY,scope_key TEXT NOT NULL,kind TEXT NOT NULL,
            version INTEGER NOT NULL,payload BLOB NOT NULL,
            native_namespace TEXT,native_request TEXT
        );
        CREATE TABLE admission_operation_recovery_events (
            sequence INTEGER PRIMARY KEY,record_key TEXT NOT NULL,
            record_version INTEGER NOT NULL,record_digest TEXT NOT NULL,
            UNIQUE(record_key,record_version)
        );
        CREATE TABLE authority_global_commits (
            projection_kind TEXT NOT NULL,projection_key TEXT NOT NULL
        )",
    )?;
    Ok(tx)
}

fn fixture() -> Result<(Connection, PlanningBudget), Box<dyn std::error::Error>> {
    let tx = empty_fixture()?;
    let first = PlanningBudget {
        schema: PlanningBudgetSchema::V1,
        authority_domain: AuthorityDomainId::new("planning-authority")?,
        tenant_id: None,
        legacy_cutoff_sequence: SafeInteger::new(40000)?,
        baseline_bytes: SafeInteger::new(4478)?,
        baseline_events: SafeInteger::new(30002)?,
        writes: SafeInteger::new(1)?,
    };
    retain(&tx, &first, 40002)?;
    let key = metadata_key(&first.authority_domain, None)?;
    tx.execute(
        "INSERT INTO authority_global_commits VALUES('recovery',?1)",
        [&key],
    )?;
    Ok((tx, first))
}

#[test]
fn planning_reservation_allows_pristine_pre_global_bootstrap() -> TestResult {
    let tx = empty_fixture()?;
    tx.execute_batch("DROP TABLE authority_global_commits")?;
    assert!(!any_metadata(&tx)?);
    verify_all(&tx)?;
    tx.execute_batch(
        "CREATE TABLE chio_serving_owner(singleton INTEGER PRIMARY KEY,owner_epoch INTEGER NOT NULL,lease_id TEXT);
        INSERT INTO chio_serving_owner VALUES(1,0,NULL)",
    )?;
    assert!(!any_metadata(&tx)?);
    verify_all(&tx)?;
    Ok(())
}

#[test]
fn planning_reservation_rejects_missing_global_chain_on_established_owner() -> TestResult {
    let tx = empty_fixture()?;
    tx.execute_batch(
        "DROP TABLE authority_global_commits;
        CREATE TABLE chio_serving_owner(singleton INTEGER PRIMARY KEY,owner_epoch INTEGER NOT NULL,lease_id TEXT);
        INSERT INTO chio_serving_owner VALUES(1,1,NULL)",
    )?;
    assert!(any_metadata(&tx).is_err());
    tx.execute(
        "UPDATE chio_serving_owner SET owner_epoch=0,lease_id='active-owner'",
        [],
    )?;
    assert!(any_metadata(&tx).is_err());
    Ok(())
}

#[test]
fn planning_reservation_rejects_absent_global_chain_with_retained_recovery() -> TestResult {
    let (tx, _) = fixture()?;
    tx.execute_batch("DROP TABLE authority_global_commits")?;
    assert!(any_metadata(&tx).is_err());
    assert!(verify_all(&tx).is_err());
    Ok(())
}

#[test]
fn planning_reservation_rejects_partial_global_chain_during_bootstrap() -> TestResult {
    let tx = empty_fixture()?;
    tx.execute_batch(
        "DROP TABLE authority_global_commits;
        CREATE TABLE authority_global_commit_meta(singleton INTEGER PRIMARY KEY,head_sequence INTEGER NOT NULL,head_chain_digest TEXT NOT NULL)",
    )?;
    assert!(any_metadata(&tx).is_err());
    Ok(())
}

fn retain(tx: &Connection, budget: &PlanningBudget, sequence: i64) -> TestResult {
    let key = metadata_key(&budget.authority_domain, budget.tenant_id.as_ref())?;
    let scope = metadata_scope(&budget.authority_domain, budget.tenant_id.as_ref())?;
    let payload = encode(budget)?;
    let version = budget.writes.get();
    tx.execute(
        "INSERT INTO admission_operation_recovery_records VALUES(?1,?2,'command',?3,?4,NULL,NULL)
            ON CONFLICT(record_key) DO UPDATE SET payload=excluded.payload,version=excluded.version",
        params![key,scope,i64::try_from(version)?,payload],
    )?;
    tx.execute(
        "INSERT INTO admission_operation_recovery_events VALUES(?1,?2,?3,?4)",
        params![
            sequence,
            key,
            i64::try_from(version)?,
            record_digest(&key, &scope, "command", version, &payload, None, None)?
        ],
    )?;
    Ok(())
}

fn usage(budget: &PlanningBudget) -> Usage {
    Usage {
        bytes: budget.baseline_bytes.get(),
        events: budget.baseline_events.get() + budget.writes.get(),
        before_cutoff: budget.baseline_events.get(),
    }
}

#[test]
fn planning_reservation_preserves_authenticated_legacy_baseline() -> TestResult {
    let (tx, mut current) = fixture()?;
    current.writes = SafeInteger::new(3)?;
    retain(&tx, &current, 40008)?;
    let retained = load(&tx, &current.authority_domain, None, &usage(&current))?
        .ok_or("allocation disappeared")?;
    assert_eq!(retained.baseline_events.get(), 30002);
    assert_eq!(retained.writes.get(), 3);
    Ok(())
}

#[test]
fn planning_reservation_rejects_self_consistent_baseline_and_cutoff_swaps() -> TestResult {
    for field in ["bytes", "events", "cutoff"] {
        let (tx, mut changed) = fixture()?;
        match field {
            "bytes" => changed.baseline_bytes = SafeInteger::new(4479)?,
            "events" => changed.baseline_events = SafeInteger::new(30003)?,
            _ => changed.legacy_cutoff_sequence = SafeInteger::new(40001)?,
        }
        changed.writes = SafeInteger::new(3)?;
        retain(&tx, &changed, 40008)?;
        assert!(load(&tx, &changed.authority_domain, None, &usage(&changed)).is_err());
    }
    Ok(())
}

#[test]
fn planning_reservation_rejects_lost_first_allocation_event() -> TestResult {
    let (tx, mut current) = fixture()?;
    current.writes = SafeInteger::new(3)?;
    retain(&tx, &current, 40008)?;
    tx.execute(
        "DELETE FROM admission_operation_recovery_events WHERE record_version=1",
        [],
    )?;
    assert!(load(&tx, &current.authority_domain, None, &usage(&current)).is_err());
    Ok(())
}

#[test]
fn planning_reservation_rejects_missing_projection_with_retained_global_reference() -> TestResult {
    let (tx, current) = fixture()?;
    tx.execute("DELETE FROM admission_operation_recovery_records", [])?;
    tx.execute("DELETE FROM admission_operation_recovery_events", [])?;
    assert!(load(&tx, &current.authority_domain, None, &usage(&current)).is_err());
    Ok(())
}

#[test]
fn planning_reservation_rejects_reordered_first_global_allocation() -> TestResult {
    let (tx, current) = fixture()?;
    tx.execute(
        "UPDATE admission_operation_recovery_events SET sequence=40003",
        [],
    )?;
    assert!(load(&tx, &current.authority_domain, None, &usage(&current)).is_err());
    Ok(())
}

#[test]
fn planning_reservation_refuses_lazy_tenant_post_cutoff_credit() -> TestResult {
    let (_, first) = fixture()?;
    let tenant = RecoveryTenantId::new("late-tenant")?;
    let post_cutoff = Usage {
        bytes: 100,
        events: 2,
        before_cutoff: 1,
    };
    assert!(new_budget(&first.authority_domain, Some(&tenant), 40000, &post_cutoff).is_err());
    Ok(())
}

#[test]
fn planning_reservation_allows_byte_shrink_below_fixed_baseline() -> TestResult {
    let (tx, mut current) = fixture()?;
    let mut smaller = usage(&current);
    smaller.bytes = 100;
    load(&tx, &current.authority_domain, None, &smaller)?.ok_or("allocation disappeared")?;
    next_budget(&mut current, &smaller, 100, 90)?;
    assert_eq!(current.baseline_bytes.get(), 4478);
    assert_eq!(current.writes.get(), 2);
    Ok(())
}

#[test]
fn planning_reservation_enforces_fixed_byte_allowance_on_verify_and_next_write() -> TestResult {
    let (tx, mut current) = fixture()?;
    let mut full = usage(&current);
    full.bytes = current.baseline_bytes.get() + GLOBAL_BYTES;
    load(&tx, &current.authority_domain, None, &full)?.ok_or("allocation disappeared")?;
    assert!(next_budget(&mut current, &full, 0, 1).is_err());
    full.bytes += 1;
    assert!(load(&tx, &current.authority_domain, None, &full).is_err());
    Ok(())
}

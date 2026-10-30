use super::*;
use chio_process::run_journal::{
    Completion, FileIdentity, ResourceUsage, WorkerState, MAX_ABANDONED_SOCKET_INTENTS,
    MAX_ACCOUNTED, MAX_WORKERS,
};
use rusqlite::params;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn initialize(path: &Path) -> Result<SqliteRunJournal, JournalError> {
    let mut store = SqliteRunJournal::open(path, "binding")?;
    store.recover(&[
        WorkerSeed {
            process: "first",
            max_attempts: 2,
        },
        WorkerSeed {
            process: "second",
            max_attempts: 2,
        },
    ])?;
    Ok(store)
}

#[test]
fn cancellation_is_durable_and_rejects_running_and_terminal_workers() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("run.db");
    let store = initialize(&path)?;
    store.transition("first", WorkerTransition::CancelPending)?;
    store.transition("second", WorkerTransition::Start { max_attempts: 2 })?;
    assert_eq!(
        store.transition("second", WorkerTransition::CancelPending),
        Err(JournalError::Cancellation)
    );
    store.transition(
        "second",
        WorkerTransition::Finish {
            completion: Completion::Terminal("process_cancelled"),
            max_attempts: 2,
            max_suspensions: 2,
            usage: ResourceUsage {
                peak_resident_bytes: 4096,
                cpu_ms: 7,
            },
        },
    )?;
    drop(store);
    let store = initialize(&path)?;
    let workers = store.snapshots()?;
    assert!(workers
        .iter()
        .all(|worker| worker.state == WorkerState::Failed
            && worker.outcome.as_deref() == Some("process_cancelled")));
    assert_eq!(
        (workers[0].attempts, workers[1].attempts, workers[1].cpu_ms),
        (0, 1, 7)
    );
    for worker in workers {
        assert_eq!(
            store.transition(&worker.process, WorkerTransition::Start { max_attempts: 2 }),
            Err(JournalError::Transition)
        );
    }
    Ok(())
}

#[test]
fn binding_and_dependency_failures_roll_back_the_whole_operation() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("run.db");
    let store = initialize(&path)?;
    store.transition("second", WorkerTransition::Start { max_attempts: 2 })?;
    let before = store.snapshots()?;
    assert_eq!(
        store.fail_dependents(&["first", "second"]),
        Err(JournalError::Transition)
    );
    assert_eq!(store.snapshots()?, before);
    assert!(matches!(
        SqliteRunJournal::open(&path, "changed"),
        Err(JournalError::Binding)
    ));
    assert_eq!(store.snapshots()?, before);
    drop(store);
    let store = initialize(&path)?;
    assert_eq!(
        store.snapshots()?[1].outcome.as_deref(),
        Some("host_interrupted")
    );
    assert_eq!(store.snapshots()?[1].state, WorkerState::Pending);
    Ok(())
}

#[test]
fn durable_container_intent_blocks_unreserve_until_removed() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("run.db");
    let store = initialize(&path)?;
    assert_eq!(
        store.reserve_container("first", 1, "owner", "docker"),
        Err(JournalError::ContainerIntent)
    );
    store.transition("first", WorkerTransition::Start { max_attempts: 2 })?;
    store.reserve_container("first", 1, "owner", "docker")?;
    assert_eq!(
        store.transition("first", WorkerTransition::Unreserve),
        Err(JournalError::Transition)
    );
    let writer = SqliteContainerJournal::open(&path)?;
    writer.created("owner", "container")?;
    assert_eq!(
        writer.create_rejected("owner"),
        Err(JournalError::ContainerIntent)
    );
    assert_eq!(
        writer.created("owner", "replacement"),
        Err(JournalError::ContainerIntent)
    );
    assert_eq!(store.containers()?[0].id.as_deref(), Some("container"));
    writer.removed("owner")?;
    let worker = store.transition("first", WorkerTransition::Unreserve)?;
    assert_eq!((worker.state, worker.attempts), (WorkerState::Pending, 0));
    Ok(())
}

#[test]
fn busy_and_corrupt_rows_fail_closed_and_accounting_saturates() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("run.db");
    let store = initialize(&path)?;
    let other = Connection::open(&path)?;
    store.db.busy_timeout(Duration::ZERO)?;
    let tx = rusqlite::Transaction::new_unchecked(&other, TransactionBehavior::Immediate)?;
    assert_eq!(
        store.transition("first", WorkerTransition::CancelPending),
        Err(JournalError::Busy)
    );
    tx.rollback()?;
    store.transition("first", WorkerTransition::Start { max_attempts: 2 })?;
    other.execute(
        "UPDATE run_workers SET cpu_ms=?1 WHERE process='first'",
        [i64::MAX],
    )?;
    let finished = store.transition(
        "first",
        WorkerTransition::Finish {
            completion: Completion::Completed("ok"),
            max_attempts: 2,
            max_suspensions: 2,
            usage: ResourceUsage {
                peak_resident_bytes: 0,
                cpu_ms: 1,
            },
        },
    )?;
    assert_eq!(finished.cpu_ms, MAX_ACCOUNTED);
    assert_eq!(store.snapshots()?[0].cpu_ms, MAX_ACCOUNTED);
    other.execute("UPDATE run_workers SET cpu_ms=-1 WHERE process='first'", [])?;
    assert_eq!(
        store.transition("first", WorkerTransition::Recover { max_attempts: 2 }),
        Err(JournalError::Integrity)
    );
    Ok(())
}

fn terminal(store: &SqliteRunJournal, process: &str, outcome: &str) -> Result<(), JournalError> {
    store.transition(process, WorkerTransition::Start { max_attempts: 2 })?;
    store.transition(
        process,
        WorkerTransition::Finish {
            completion: Completion::Terminal(outcome),
            max_attempts: 2,
            max_suspensions: 2,
            usage: ResourceUsage::default(),
        },
    )?;
    Ok(())
}

#[test]
fn settlement_requires_a_running_parent_and_records_failures_once() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = initialize(&dir.path().join("run.db"))?;
    let children = ["second".to_owned(), "late".to_owned()];
    assert_eq!(
        store.settle_children("first", &children, "request-1"),
        Err(JournalError::NotRunning)
    );
    store.transition("first", WorkerTransition::Start { max_attempts: 2 })?;
    terminal(&store, "second", "exit_1")?;
    let outcomes = store.settle_children("first", &children, "request-1")?;
    assert_eq!(
        (outcomes[1].state, outcomes[1].attempts),
        (WorkerState::Pending, 0)
    );
    assert!(store.settlements()?.is_empty());
    store.insert_worker("late")?;
    terminal(&store, "late", "exit_2")?;
    store.settle_children("first", &children, "request-2")?;
    store.settle_children("first", &children, "request-3")?;
    let recorded = store.settlements()?;
    assert_eq!(recorded.len(), 2);
    assert!(recorded
        .iter()
        .all(|settlement| settlement.parent == "first" && settlement.request_id == "request-2"));
    Ok(())
}

#[test]
fn a_journal_without_schema_holds_no_intents() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().canonicalize()?.join("run.db");
    std::fs::write(&path, b"")?;
    let journal = SqliteRunJournal::open_existing(&path, Access::Export)?;
    assert!(!journal.has_container_intents()?);
    assert!(!journal.has_socket_intents()?);
    for access in [Access::Read, Access::Write] {
        assert!(matches!(
            SqliteRunJournal::open_existing(&path, access),
            Err(JournalError::Schema)
        ));
    }
    Ok(())
}

#[test]
fn a_journal_without_the_v1_catalog_is_refused_at_every_open() -> TestResult {
    for (table, column) in [
        ("run_containers", "create_rejected"),
        ("run_workers", "cpu_ms"),
        ("run_workers", "outcome"),
    ] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().canonicalize()?.join("run.db");
        drop(initialize(&path)?);
        Connection::open(&path)?
            .execute_batch(&format!("ALTER TABLE {table} DROP COLUMN {column}"))?;
        assert!(matches!(
            SqliteRunJournal::open(&path, "binding"),
            Err(JournalError::Schema)
        ));
        for access in [Access::Read, Access::Write, Access::Export] {
            assert!(matches!(
                SqliteRunJournal::open_existing(&path, access),
                Err(JournalError::Schema)
            ));
        }
        assert!(matches!(
            SqliteContainerJournal::open(&path),
            Err(JournalError::Schema)
        ));
    }
    let dir = tempfile::tempdir()?;
    let foreign = dir.path().join("foreign.db");
    Connection::open(&foreign)?.execute_batch("CREATE TABLE run_binding(singleton INTEGER)")?;
    assert!(matches!(
        SqliteRunJournal::open(&foreign, "binding"),
        Err(JournalError::Schema)
    ));
    Ok(())
}

#[test]
fn socket_writes_match_the_live_intent_and_history_is_bounded() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = initialize(&dir.path().join("run.db"))?;
    let identity = FileIdentity {
        device: 1,
        inode: 2,
    };
    assert_eq!(
        store.socket_directory_created("absent", identity),
        Err(JournalError::SocketIntent)
    );
    assert_eq!(
        store.abandon_socket_intent(),
        Err(JournalError::SocketIntent)
    );
    for index in 0..=MAX_ABANDONED_SOCKET_INTENTS {
        let name = format!("intent-{index}");
        store.record_socket_intent(&name)?;
        store.socket_directory_created(&name, identity)?;
        assert_eq!(
            store.socket_bound("other", identity),
            Err(JournalError::SocketIntent)
        );
        if index == MAX_ABANDONED_SOCKET_INTENTS {
            assert_eq!(
                store.abandon_socket_intent(),
                Err(JournalError::SocketHistoryFull)
            );
        } else {
            store.abandon_socket_intent()?;
        }
    }
    assert_eq!(
        store.abandoned_socket_intents()?,
        MAX_ABANDONED_SOCKET_INTENTS
    );
    let live = store.socket_lease()?.ok_or("live intent")?;
    assert_eq!((live.directory, live.socket), (Some(identity), None));
    Ok(())
}

fn query_plan(store: &SqliteRunJournal, sql: &str) -> Result<String, rusqlite::Error> {
    let details = store
        .db
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?
        .query_map([1], |row| row.get::<_, String>(3))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(details.join("; "))
}

#[test]
fn hot_reads_search_an_index_and_list_reads_never_sort() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = initialize(&dir.path().join("run.db"))?;
    for sql in [workers::HAS_CONTAINER, sockets::LIST_ABANDONED] {
        let plan = query_plan(&store, sql)?;
        assert!(plan.contains("SEARCH"), "{sql}: {plan}");
        assert!(!plan.contains("TEMP B-TREE"), "{sql}: {plan}");
    }
    for sql in [workers::LIST, containers::LIST, settlements::LIST] {
        let plan = query_plan(&store, sql)?;
        assert!(!plan.contains("TEMP B-TREE"), "{sql}: {plan}");
    }
    Ok(())
}

#[test]
fn worker_and_container_capacity_is_enforced_inside_the_write() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("run.db");
    let mut store = SqliteRunJournal::open(&path, "binding")?;
    let names = (0..=MAX_WORKERS)
        .map(|index| format!("worker-{index:03}"))
        .collect::<Vec<_>>();
    let seeds = names
        .iter()
        .map(|process| WorkerSeed {
            process,
            max_attempts: 2,
        })
        .collect::<Vec<_>>();
    assert_eq!(store.recover(&seeds), Err(JournalError::WorkerCapacity));
    assert!(store.snapshots()?.is_empty());
    store.recover(&seeds[1..])?;
    assert_eq!(
        store.insert_worker(&names[0]),
        Err(JournalError::WorkerCapacity)
    );
    assert_eq!(store.snapshots()?.len(), names.len() - 1);
    store.transition(&names[1], WorkerTransition::Start { max_attempts: 2 })?;
    let other = Connection::open(&path)?;
    for (index, process) in names[2..].iter().enumerate() {
        other.execute(
            "INSERT INTO run_containers(owner,process,attempt,engine) VALUES(?1,?2,1,'docker')",
            [format!("owner-{index:03}"), process.clone()],
        )?;
    }
    store.reserve_container(&names[1], 1, "owner-last", "docker")?;
    store.transition(&names[2], WorkerTransition::Start { max_attempts: 2 })?;
    assert_eq!(
        store.reserve_container(&names[2], 1, "owner-next", "docker"),
        Err(JournalError::ContainerCapacity)
    );
    assert_eq!(store.containers()?.len(), names.len() - 1);
    Ok(())
}

#[test]
fn list_reads_beyond_their_bound_are_integrity_faults() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("run.db");
    let store = initialize(&path)?;
    let other = Connection::open(&path)?;
    for index in 0..MAX_WORKERS {
        let index = format!("{index:03}");
        other.execute(
            "INSERT INTO run_workers(process,state) VALUES(?1,'pending')",
            [format!("extra-{index}")],
        )?;
        other.execute(
            "INSERT INTO run_containers(owner,process,attempt,engine) VALUES(?1,?1,1,'docker')",
            [format!("extra-{index}")],
        )?;
        other.execute(
            "INSERT INTO run_child_settlements(parent,child,request_id) VALUES('first',?1,?1)",
            [format!("extra-{index}")],
        )?;
    }
    other.execute(
        "INSERT INTO run_containers(owner,process,attempt,engine) VALUES('first','first',1,'docker')",
        [],
    )?;
    other.execute(
        "INSERT INTO run_child_settlements(parent,child,request_id) VALUES('second','first','r')",
        [],
    )?;
    for slot in 2..=MAX_ABANDONED_SOCKET_INTENTS.saturating_add(2) {
        other.execute(
            "INSERT INTO run_socket_leases(singleton,name) VALUES(?1,?2)",
            params![slot, format!("abandoned-{slot}")],
        )?;
    }
    assert_eq!(store.snapshots(), Err(JournalError::Integrity));
    assert_eq!(store.containers(), Err(JournalError::Integrity));
    assert_eq!(store.settlements(), Err(JournalError::Integrity));
    assert!(matches!(
        store.retire_socket_intents(),
        Err(JournalError::Integrity)
    ));
    Ok(())
}

//! A count oracle must inspect committed state without borrowing the production
//! SQL work budget or being interrupted by cancellation after that commit.
use super::*;

const ORACLE_SQL: &str = "WITH RECURSIVE numbers(n) AS \
    (VALUES(1) UNION ALL SELECT n + 1 FROM numbers WHERE n < 1000) \
    SELECT SUM(n) FROM numbers";

type Observations = Arc<Mutex<Vec<Result<i64, String>>>>;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn published(hold_sql_steps: u64) -> TestResult<(Published, Observations)> {
    let observations = Observations::default();
    let recorded = Arc::clone(&observations);
    let observer = Arc::new(move |db: &SnapshotDb, _: &str, _: u64| {
        let value = db
            .connection()
            .map_err(|error| error.to_string())
            .and_then(|connection| {
                connection
                    .query_row(ORACLE_SQL, [], |row| row.get::<_, i64>(0))
                    .map_err(|error| error.to_string())
            });
        match recorded.lock() {
            Ok(mut recorded) => recorded.push(value),
            Err(error) => panic!("generation observation log poisoned: {error}"),
        }
    });
    let published = Published {
        lineage: "generation-observer-control".into(),
        owned: Mutex::new(Owned {
            db: SnapshotDb::open_memory(1024 * 1024)?,
            meta: Meta {
                generation: 1,
                through_entry_seq: 0,
                checkpoint_seq: 0,
                observed_at_ms: 1,
                observed_at: Instant::now(),
                recertified_at_ms: 1,
            },
            head: None,
            chain: CheckpointChainFrontier::default(),
            watermark: 0,
            lineage_rowid: 0,
        }),
        waiting: Arc::new(AtomicUsize::new(0)),
        changed: Arc::new(Condvar::new()),
        cancel: Arc::new(AtomicBool::new(false)),
        hold_sql_steps,
        commit_fault: Mutex::new(None),
        read_fault: Mutex::new(None),
        status_fault: Mutex::new(None),
        gate: (Mutex::new(TestGate::default()), Condvar::new()),
        max_staged_per_hold: AtomicU64::new(0),
        observer: Some(observer),
    };
    Ok((published, observations))
}

#[test]
fn post_commit_cancellation_does_not_interrupt_the_generation_oracle() -> TestResult {
    let (published, observations) = published(5_000_000)?;
    published.with_db_mut(|_| {
        // Cancellation arrives after successful mutation, before its
        // generation is observed. The committed state still needs a check.
        published.cancel.store(true, Ordering::SeqCst);
        Ok(())
    })?;
    assert_eq!(
        *observations.lock().map_err(|error| error.to_string())?,
        vec![Ok(500_500)]
    );
    Ok(())
}

#[test]
fn generation_oracle_does_not_spend_the_walker_sql_budget() -> TestResult {
    let (published, observations) = published(1_000)?;
    published.with_db_mut(|_| Ok(()))?;
    assert_eq!(
        *observations.lock().map_err(|error| error.to_string())?,
        vec![Ok(500_500)]
    );
    Ok(())
}

#[test]
fn observed_walker_work_still_refuses_exhaustion_and_cancellation() -> TestResult {
    for cancelled in [false, true] {
        let (published, observations) = published(1_000)?;
        let outcome = published.with_db_mut(|db| {
            published.cancel.store(cancelled, Ordering::SeqCst);
            db.connection()?
                .query_row(ORACLE_SQL, [], |row| row.get::<_, i64>(0))?;
            Ok(())
        });
        assert!(
            matches!(
                (&outcome, cancelled),
                (Err(WalkError::Cancelled), true) | (Err(WalkError::WalkerBudget), false)
            ),
            "cancelled={cancelled}: {outcome:?}"
        );
        assert!(observations
            .lock()
            .map_err(|error| error.to_string())?
            .is_empty());
        assert_eq!(
            published
                .owned
                .lock()
                .map_err(|error| error.to_string())?
                .meta
                .generation,
            1
        );
    }
    Ok(())
}

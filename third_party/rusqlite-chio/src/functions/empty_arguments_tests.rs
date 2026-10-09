//! Scalar, aggregate and window callback argument boundary regressions.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn null_zero_argument_array_is_empty() {
    // No SQLite context or value is fabricated. This tests only the private
    // pointer-array primitive under its explicitly permitted null/zero contract.
    let args = unsafe { callback_args(0, ptr::null_mut()) };
    assert!(args.is_empty());
    assert_eq!(args.len(), 0);
}

#[test]
fn nonempty_argument_array_preserves_slots_and_borrow() {
    // The primitive borrows pointer slots, without dereferencing their values.
    // Null slot values are initialized pointers, not fabricated SQLite values.
    let mut slots: [*mut sqlite3_value; 2] = [ptr::null_mut(); 2];
    let expected = slots.as_ptr();
    let args = unsafe { callback_args(2, slots.as_mut_ptr()) };
    assert_eq!(args.as_ptr(), expected);
    assert_eq!(args.len(), 2);
    assert_eq!(args, &slots);
}

#[test]
fn ordinary_zero_argument_scalar_runs_for_each_row() -> TestResult {
    let db = Connection::open_in_memory()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    db.create_scalar_function("zero_scalar", 0, FunctionFlags::SQLITE_UTF8, move |ctx| {
        assert!(ctx.is_empty());
        assert_eq!(ctx.len(), 0);
        counted.fetch_add(1, Ordering::SeqCst);
        Ok(37_i64)
    })?;
    let mut stmt = db.prepare("SELECT zero_scalar() FROM (SELECT 1 UNION ALL SELECT 2)")?;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let rows = stmt
        .query_map([], |row| row.get::<_, i64>(0))?
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(rows, vec![37, 37]);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[test]
fn variable_arity_scalar_preserves_empty_and_nonempty_arguments() -> TestResult {
    let db = Connection::open_in_memory()?;
    db.create_scalar_function("variable_scalar", -1, FunctionFlags::SQLITE_UTF8, |ctx| {
        if ctx.is_empty() {
            assert_eq!(ctx.len(), 0);
            Ok("empty".to_owned())
        } else {
            assert_eq!(ctx.len(), 2);
            Ok(format!("{}:{}", ctx.get::<String>(0)?, ctx.get::<i64>(1)?))
        }
    })?;
    assert_eq!(
        db.query_row("SELECT variable_scalar()", [], |row| row
            .get::<_, String>(0))?,
        "empty"
    );
    let nonempty: String = db.query_row("SELECT variable_scalar('retained', 41)", [], |row| {
        row.get(0)
    })?;
    assert_eq!(nonempty, "retained:41");
    // SqlFnArg results still use the very same nonempty argument array.
    db.create_scalar_function("return_argument", 1, FunctionFlags::SQLITE_UTF8, |ctx| {
        assert_eq!(ctx.len(), 1);
        Ok(ctx.get_arg(0))
    })?;
    assert_eq!(
        db.query_row("SELECT return_argument('unchanged')", [], |row| row
            .get::<_, String>(0))?,
        "unchanged"
    );
    Ok(())
}

type Phases = Arc<Mutex<Vec<&'static str>>>;

struct ZeroCount(Phases);

impl ZeroCount {
    fn record(&self, ctx: &Context<'_>, phase: &'static str) -> Result<()> {
        assert!(ctx.is_empty());
        assert_eq!(ctx.len(), 0);
        self.0.lock().map_err(|_| Error::InvalidQuery)?.push(phase);
        Ok(())
    }
}

impl Aggregate<i64, i64> for ZeroCount {
    fn init(&self, ctx: &mut Context<'_>) -> Result<i64> {
        self.record(ctx, "init")?;
        Ok(0)
    }

    fn step(&self, ctx: &mut Context<'_>, count: &mut i64) -> Result<()> {
        self.record(ctx, "step")?;
        *count += 1;
        Ok(())
    }

    fn finalize(&self, ctx: &mut Context<'_>, count: Option<i64>) -> Result<i64> {
        self.record(
            ctx,
            if count.is_some() {
                "final"
            } else {
                "empty final"
            },
        )?;
        Ok(count.unwrap_or(0))
    }
}

#[cfg(feature = "window")]
impl WindowAggregate<i64, i64> for ZeroCount {
    fn inverse(&self, ctx: &mut Context<'_>, count: &mut i64) -> Result<()> {
        self.record(ctx, "inverse")?;
        *count -= 1;
        Ok(())
    }

    fn value(&self, count: Option<&mut i64>) -> Result<i64> {
        self.0
            .lock()
            .map_err(|_| Error::InvalidQuery)?
            .push("value");
        Ok(count.map_or(0, |value| *value))
    }
}

#[test]
fn zero_argument_aggregate_counts_rows_and_finalizes_empty_input() -> TestResult {
    let db = Connection::open_in_memory()?;
    db.execute_batch("CREATE TABLE source(x); INSERT INTO source VALUES(1),(2),(3),(4)")?;
    let phases = Phases::default();
    db.create_aggregate_function(
        "zero_count",
        0,
        FunctionFlags::SQLITE_UTF8,
        ZeroCount(phases.clone()),
    )?;
    assert_eq!(
        db.query_row("SELECT zero_count() FROM source", [], |row| row
            .get::<_, i64>(0))?,
        4
    );
    assert_eq!(
        *phases.lock().map_err(|_| "poisoned")?,
        vec!["init", "step", "step", "step", "step", "final"]
    );
    phases.lock().map_err(|_| "poisoned")?.clear();
    assert_eq!(
        db.query_row("SELECT zero_count() FROM source WHERE 0", [], |row| row
            .get::<_, i64>(0))?,
        0
    );
    assert_eq!(*phases.lock().map_err(|_| "poisoned")?, vec!["empty final"]);
    Ok(())
}

#[cfg(feature = "window")]
#[test]
fn zero_argument_window_runs_step_inverse_value_and_final() -> TestResult {
    let db = Connection::open_in_memory()?;
    db.execute_batch("CREATE TABLE source(x); INSERT INTO source VALUES(1),(2),(3),(4)")?;
    let phases = Phases::default();
    db.create_window_function(
        "zero_window",
        0,
        FunctionFlags::SQLITE_UTF8,
        ZeroCount(phases.clone()),
    )?;
    let rows = db
        .prepare("SELECT zero_window() OVER (ORDER BY x ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM source ORDER BY x")?
        .query_map([], |row| row.get::<_, i64>(0))?
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(rows, vec![1, 2, 2, 2]);
    let recorded = phases.lock().map_err(|_| "poisoned")?;
    for (phase, count) in [
        ("init", 1),
        ("step", 4),
        ("inverse", 2),
        ("value", 4),
        ("final", 1),
    ] {
        assert_eq!(
            recorded.iter().filter(|&&p| p == phase).count(),
            count,
            "{recorded:?}"
        );
    }
    assert!(!recorded.contains(&"empty final"));
    Ok(())
}

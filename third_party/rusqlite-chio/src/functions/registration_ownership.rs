//! Registration ownership controls. All resources are inert in-memory counters.

#[cfg(feature = "window")]
use crate::functions::WindowAggregate;
use crate::functions::{Aggregate, Context, FunctionFlags};
use crate::util::Named;
use crate::{ffi, Connection, Error, Name, Result};
use std::ffi::CString;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Default)]
struct Counts {
    drops: AtomicUsize,
    calls: AtomicUsize,
    inverses: AtomicUsize,
}

struct Callback {
    counts: Arc<Counts>,
    bias: i64,
}

impl Callback {
    fn new(counts: &Arc<Counts>, bias: i64) -> Self {
        Self {
            counts: Arc::clone(counts),
            bias,
        }
    }

    fn scalar(&self, ctx: &Context<'_>) -> Result<i64> {
        self.counts.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ctx.get::<i64>(0)? + self.bias)
    }
}

impl Drop for Callback {
    fn drop(&mut self) {
        self.counts.drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl Aggregate<i64, i64> for Callback {
    fn init(&self, _: &mut Context<'_>) -> Result<i64> {
        self.counts.calls.fetch_add(1, Ordering::SeqCst);
        Ok(0)
    }

    fn step(&self, ctx: &mut Context<'_>, acc: &mut i64) -> Result<()> {
        self.counts.calls.fetch_add(1, Ordering::SeqCst);
        *acc += ctx.get::<i64>(0)?;
        Ok(())
    }

    fn finalize(&self, _: &mut Context<'_>, acc: Option<i64>) -> Result<i64> {
        self.counts.calls.fetch_add(1, Ordering::SeqCst);
        Ok(acc.unwrap_or_default() + self.bias)
    }
}

#[cfg(feature = "window")]
impl WindowAggregate<i64, i64> for Callback {
    fn value(&self, acc: Option<&mut i64>) -> Result<i64> {
        self.counts.calls.fetch_add(1, Ordering::SeqCst);
        Ok(acc.map(|value| *value).unwrap_or_default() + self.bias)
    }

    fn inverse(&self, ctx: &mut Context<'_>, acc: &mut i64) -> Result<()> {
        self.counts.inverses.fetch_add(1, Ordering::SeqCst);
        *acc -= ctx.get::<i64>(0)?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Scalar,
    Aggregate,
    #[cfg(feature = "window")]
    Window,
}

impl Kind {
    fn register<N: Name>(
        self,
        db: &Connection,
        name: N,
        arity: i32,
        callback: Callback,
    ) -> Result<()> {
        let flags = FunctionFlags::SQLITE_UTF8;
        match self {
            // Calling a method captures the entire Drop-bearing value, even
            // with disjoint closure capture enabled in Rust 2021.
            Self::Scalar => {
                db.create_scalar_function(name, arity, flags, move |ctx| callback.scalar(ctx))
            }
            Self::Aggregate => db.create_aggregate_function(name, arity, flags, callback),
            #[cfg(feature = "window")]
            Self::Window => db.create_window_function(name, arity, flags, callback),
        }
    }

    fn call(self, db: &Connection) -> Result<i64> {
        let sql = match self {
            Self::Scalar | Self::Aggregate => "SELECT owned_callback(7)",
            #[cfg(feature = "window")]
            Self::Window => "SELECT owned_callback(7) OVER ()",
        };
        db.query_row(sql, [], |row| row.get(0))
    }
}

fn assert_owned(counts: &Arc<Counts>, drops: usize, owners: usize) {
    assert_eq!(counts.drops.load(Ordering::SeqCst), drops);
    // This independently checks that a retained callback did not just update
    // the counter while leaking its captured Arc.
    assert_eq!(Arc::strong_count(counts), owners);
}

fn assert_uninvoked(counts: &Counts) {
    assert_eq!(counts.calls.load(Ordering::SeqCst), 0);
    assert_eq!(counts.inverses.load(Ordering::SeqCst), 0);
}

fn close(db: Connection) -> Result<()> {
    db.close().map_err(|(_, error)| error)
}

#[derive(Debug)]
struct ErrorName<'a>(&'a AtomicUsize);

impl Name for ErrorName<'_> {
    fn as_cstr(&self) -> Result<Named<'_>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(Error::InvalidParameterName("synthetic name error".into()))
    }
}

#[derive(Debug)]
struct PanicName<'a>(&'a AtomicUsize);

impl Name for PanicName<'_> {
    fn as_cstr(&self) -> Result<Named<'_>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("synthetic name panic");
    }
}

#[derive(Debug)]
struct OwnedName(CString);

impl Name for OwnedName {
    fn as_cstr(&self) -> Result<Named<'_>> {
        Ok(Named::C(self.0.as_c_str()))
    }
}

fn invalid_str_name(kind: Kind) -> Result<()> {
    for name in ["owned_callback\0suffix".to_owned(), "x".repeat(80) + "\0"] {
        let db = Connection::open_in_memory()?;
        let counts = Arc::new(Counts::default());
        let result = kind.register(&db, name.as_str(), 1, Callback::new(&counts, 0));
        assert!(matches!(result, Err(Error::NulError(_))));
        // This assertion fails on upstream: zero drops and two Arc owners.
        assert_owned(&counts, 1, 1);
        assert_uninvoked(&counts);
        assert!(kind.call(&db).is_err());
        db.remove_function("owned_callback", 1)?;
        close(db)?;
        assert_owned(&counts, 1, 1);
    }
    Ok(())
}

fn custom_name_error(kind: Kind) -> Result<()> {
    let db = Connection::open_in_memory()?;
    let counts = Arc::new(Counts::default());
    let conversions = AtomicUsize::new(0);
    let result = kind.register(&db, ErrorName(&conversions), 1, Callback::new(&counts, 0));
    assert!(
        matches!(result, Err(Error::InvalidParameterName(ref name)) if name == "synthetic name error")
    );
    assert_eq!(conversions.load(Ordering::SeqCst), 1);
    assert_owned(&counts, 1, 1);
    assert_uninvoked(&counts);
    close(db)?;
    assert_owned(&counts, 1, 1);
    Ok(())
}

fn custom_name_panic(kind: Kind) -> Result<()> {
    let db = Connection::open_in_memory()?;
    let counts = Arc::new(Counts::default());
    let conversions = AtomicUsize::new(0);
    let callback = Callback::new(&counts, 0);
    let result = catch_unwind(AssertUnwindSafe(|| {
        kind.register(&db, PanicName(&conversions), 1, callback)
    }));
    match result {
        Err(payload) => assert_eq!(
            payload.downcast_ref::<&str>(),
            Some(&"synthetic name panic")
        ),
        Ok(_) => panic!("name conversion must unwind"),
    }
    assert_eq!(conversions.load(Ordering::SeqCst), 1);
    assert_owned(&counts, 1, 1);
    assert_uninvoked(&counts);
    close(db)?;
    assert_owned(&counts, 1, 1);
    Ok(())
}

fn sqlite_rejects_arity(kind: Kind) -> Result<()> {
    for arity in [-2, i32::MAX] {
        let db = Connection::open_in_memory()?;
        let counts = Arc::new(Counts::default());
        let result = kind.register(&db, c"owned_callback", arity, Callback::new(&counts, 0));
        assert!(
            matches!(result, Err(Error::SqliteFailure(ref e, _)) if e.extended_code == ffi::SQLITE_MISUSE)
        );
        assert_owned(&counts, 1, 1);
        assert_uninvoked(&counts);
        assert!(kind.call(&db).is_err());
        db.remove_function(c"owned_callback", 1)?;
        close(db)?;
        assert_owned(&counts, 1, 1);
    }
    Ok(())
}

fn sqlite_rejects_long_name(kind: Kind) -> Result<()> {
    let db = Connection::open_in_memory()?;
    let counts = Arc::new(Counts::default());
    let name = "x".repeat(256);
    let result = kind.register(&db, name.as_str(), 1, Callback::new(&counts, 0));
    assert!(
        matches!(result, Err(Error::SqliteFailure(ref e, _)) if e.extended_code == ffi::SQLITE_MISUSE)
    );
    assert_owned(&counts, 1, 1);
    assert_uninvoked(&counts);
    close(db)?;
    assert_owned(&counts, 1, 1);
    Ok(())
}

fn names_outlive_registration_only(kind: Kind) -> Result<()> {
    let db = Connection::open_in_memory()?;
    for form in 0..3 {
        let counts = Arc::new(Counts::default());
        match form {
            0 => {
                let name = String::from("owned_callback");
                kind.register(&db, name.as_str(), 1, Callback::new(&counts, 10))?;
            }
            1 => {
                let name = CString::new("owned_callback")?;
                kind.register(&db, name.as_c_str(), 1, Callback::new(&counts, 10))?;
            }
            _ => kind.register(
                &db,
                OwnedName(CString::new("owned_callback")?),
                1,
                Callback::new(&counts, 10),
            )?,
        }
        // Each name's backing storage has been dropped before this SQL.
        assert_owned(&counts, 0, 2);
        assert_uninvoked(&counts);
        assert_eq!(kind.call(&db)?, 17);
        assert!(counts.calls.load(Ordering::SeqCst) > 0);
        assert_owned(&counts, 0, 2);
        db.remove_function(c"owned_callback", 1)?;
        assert_owned(&counts, 1, 1);
        assert!(kind.call(&db).is_err());
    }
    close(db)
}

fn replace_remove_close(kind: Kind) -> Result<()> {
    let db = Connection::open_in_memory()?;
    let first = Arc::new(Counts::default());
    let second = Arc::new(Counts::default());
    kind.register(&db, c"owned_callback", 1, Callback::new(&first, 10))?;
    assert_owned(&first, 0, 2);
    assert_eq!(kind.call(&db)?, 17);
    kind.register(&db, c"owned_callback", 1, Callback::new(&second, 20))?;
    assert_owned(&first, 1, 1);
    assert_owned(&second, 0, 2);
    assert_eq!(kind.call(&db)?, 27);
    db.remove_function(c"owned_callback", 1)?;
    assert_owned(&second, 1, 1);
    assert!(kind.call(&db).is_err());
    db.remove_function(c"owned_callback", 1)?;
    close(db)?;
    assert_owned(&first, 1, 1);
    assert_owned(&second, 1, 1);
    Ok(())
}

fn close_retained_callback(kind: Kind) -> Result<()> {
    let counts = Arc::new(Counts::default());
    let db = Connection::open_in_memory()?;
    kind.register(&db, c"owned_callback", 1, Callback::new(&counts, 10))?;
    assert_eq!(kind.call(&db)?, 17);
    assert_owned(&counts, 0, 2);
    close(db)?;
    assert_owned(&counts, 1, 1);
    Ok(())
}

fn drop_connection(kind: Kind) -> Result<()> {
    let counts = Arc::new(Counts::default());
    {
        let db = Connection::open_in_memory()?;
        kind.register(&db, c"owned_callback", 1, Callback::new(&counts, 0))?;
        assert_owned(&counts, 0, 2);
        assert_uninvoked(&counts);
    }
    assert_owned(&counts, 1, 1);
    assert_uninvoked(&counts);
    Ok(())
}

fn busy_replacement_preserves_original(kind: Kind) -> Result<()> {
    let db = Connection::open_in_memory()?;
    let first = Arc::new(Counts::default());
    let rejected = Arc::new(Counts::default());
    kind.register(&db, c"owned_callback", 1, Callback::new(&first, 10))?;
    {
        let mut stmt = db.prepare("SELECT 1 UNION ALL SELECT 2")?;
        let mut rows = stmt.query([])?;
        assert!(rows.next()?.is_some());
        let result = kind.register(&db, c"owned_callback", 1, Callback::new(&rejected, 20));
        assert!(
            matches!(result, Err(Error::SqliteFailure(ref e, _)) if e.extended_code == ffi::SQLITE_BUSY)
        );
        assert_owned(&rejected, 1, 1);
        assert_uninvoked(&rejected);
        assert_owned(&first, 0, 2);
    }
    assert_eq!(kind.call(&db)?, 17);
    close(db)?;
    assert_owned(&first, 1, 1);
    assert_owned(&rejected, 1, 1);
    Ok(())
}

macro_rules! ownership_controls {
    ($module:ident, $kind:expr) => {
        mod $module {
            use super::*;
            #[test]
            fn invalid_name_drops_capture() -> Result<()> {
                invalid_str_name($kind)
            }
            #[test]
            fn custom_error_drops_capture() -> Result<()> {
                custom_name_error($kind)
            }
            #[test]
            fn custom_panic_drops_capture() -> Result<()> {
                custom_name_panic($kind)
            }
            #[test]
            fn invalid_arity_destroys_once() -> Result<()> {
                sqlite_rejects_arity($kind)
            }
            #[test]
            fn long_name_destroys_once() -> Result<()> {
                sqlite_rejects_long_name($kind)
            }
            #[test]
            fn borrowed_names_need_no_static_lifetime() -> Result<()> {
                names_outlive_registration_only($kind)
            }
            #[test]
            fn replacement_removal_and_close_destroy_once() -> Result<()> {
                replace_remove_close($kind)
            }
            #[test]
            fn explicit_close_destroys_once() -> Result<()> {
                close_retained_callback($kind)
            }
            #[test]
            fn implicit_close_destroys_once() -> Result<()> {
                drop_connection($kind)
            }
            #[test]
            fn busy_replacement_destroys_only_rejected_callback() -> Result<()> {
                busy_replacement_preserves_original($kind)
            }
        }
    };
}

ownership_controls!(scalar, Kind::Scalar);
ownership_controls!(aggregate, Kind::Aggregate);
#[cfg(feature = "window")]
ownership_controls!(window, Kind::Window);

#[cfg(feature = "window")]
#[test]
fn moving_window_keeps_callback_until_close() -> Result<()> {
    let db = Connection::open_in_memory()?;
    let counts = Arc::new(Counts::default());
    Kind::Window.register(&db, c"owned_callback", 1, Callback::new(&counts, 10))?;
    {
        let mut stmt = db.prepare(
            "WITH input(x) AS (VALUES (1), (2), (3))
             SELECT owned_callback(x) OVER (
                 ORDER BY x ROWS BETWEEN 1 PRECEDING AND CURRENT ROW
             ) FROM input ORDER BY x",
        )?;
        let values: Result<Vec<i64>> = stmt.query_map([], |row| row.get(0))?.collect();
        assert_eq!(values?, vec![11, 13, 15]);
    }
    assert!(counts.inverses.load(Ordering::SeqCst) > 0);
    assert_owned(&counts, 0, 2);
    close(db)?;
    assert_owned(&counts, 1, 1);
    Ok(())
}

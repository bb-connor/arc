use std::panic::{self, Location, UnwindSafe};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::ctx;
use crate::plain;

struct NonDebugHandle;

#[cfg(unix)]
#[test]
fn unique_sqlite_path_uses_an_exact_private_parent_mode() {
    use std::os::unix::fs::PermissionsExt;

    use plain::TestResultOk;

    let path = crate::private_fs::unique_sqlite_path("private-mode");
    let parent = path.parent().test_expect("SQLite test path has a parent");
    let mode = std::fs::symlink_metadata(parent)
        .test_expect("inspect SQLite test parent")
        .permissions()
        .mode()
        & 0o777;

    assert_eq!(mode, 0o700);
}

#[test]
fn unique_sqlite_paths_do_not_reuse_a_same_prefix_name() {
    let first = crate::private_fs::unique_sqlite_path("same-prefix");
    let second = crate::private_fs::unique_sqlite_path("same-prefix");

    assert_ne!(first, second);
    assert_eq!(first.parent(), second.parent());
}

#[test]
#[should_panic(expected = "prefix must be one non-empty normal path component")]
fn unique_sqlite_path_rejects_a_separator_prefix() {
    let _ = crate::private_fs::unique_sqlite_path("nested/path");
}

#[test]
fn ctx_unwrap_err_accepts_non_debug_ok_payloads() {
    use ctx::TestUnwrapErr;

    let result: Result<NonDebugHandle, &str> = Err("denied");

    assert_eq!(result.test_unwrap_err("expected denial"), "denied");
}

#[test]
fn plain_unwraps_do_not_require_debug_value_payloads() {
    use plain::{TestResultErr, TestResultOk};

    let ok: Result<NonDebugHandle, &str> = Ok(NonDebugHandle);
    let _: NonDebugHandle = ok.test_unwrap();

    let some = Some(NonDebugHandle);
    let _: NonDebugHandle = some.test_unwrap();

    let err: Result<NonDebugHandle, &str> = Err("denied");
    assert_eq!(err.test_unwrap_err(), "denied");
}

#[test]
fn plain_panic_reports_test_call_site() {
    use plain::TestResultOk;

    let expected_line = line!() + 1;
    let panic = capture_panic(|| Option::<u8>::None.test_unwrap());

    assert_eq!(panic.location_line, Some(expected_line));
    assert!(
        panic
            .location_file
            .as_deref()
            .is_some_and(|file| file.ends_with("chio-test-support/src/lib.rs")),
        "unexpected panic location file: {:?}",
        panic.location_file
    );
    assert_eq!(panic.message, "expected Some(..), got None");
}

#[test]
fn ctx_panic_reports_test_call_site() {
    use ctx::TestUnwrap;

    let expected_line = line!() + 1;
    let panic = capture_panic(|| Result::<u8, &str>::Err("denied").test_unwrap("ctx"));

    assert_eq!(panic.location_line, Some(expected_line));
    assert!(
        panic
            .location_file
            .as_deref()
            .is_some_and(|file| file.ends_with("chio-test-support/src/lib.rs")),
        "unexpected panic location file: {:?}",
        panic.location_file
    );
    assert_eq!(panic.message, "ctx: denied");
}

#[test]
fn loopback_denied_helper_recognizes_permission_denied() {
    let error = std::io::Error::from(std::io::ErrorKind::PermissionDenied);

    assert!(crate::loopback::is_loopback_bind_denied(&error));
}

#[test]
fn loopback_denied_helper_rejects_address_conflicts() {
    let error = std::io::Error::from(std::io::ErrorKind::AddrInUse);

    assert!(!crate::loopback::is_loopback_bind_denied(&error));
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapturedPanic {
    message: String,
    location_file: Option<String>,
    location_line: Option<u32>,
}

fn capture_panic<F, R>(f: F) -> CapturedPanic
where
    F: FnOnce() -> R + UnwindSafe,
{
    static HOOK_LOCK: Mutex<()> = Mutex::new(());

    let _guard = lock(&HOOK_LOCK);
    let previous_hook = panic::take_hook();
    let captured = Arc::new(Mutex::new(None));
    let captured_for_hook = Arc::clone(&captured);

    panic::set_hook(Box::new(move |info| {
        let message = if let Some(message) = info.payload().downcast_ref::<&'static str>() {
            (*message).to_string()
        } else if let Some(message) = info.payload().downcast_ref::<String>() {
            message.clone()
        } else {
            "<non-string panic>".to_string()
        };
        let (location_file, location_line) = info.location().map_or((None, None), location_parts);
        *lock(&captured_for_hook) = Some(CapturedPanic {
            message,
            location_file,
            location_line,
        });
    }));

    let result = panic::catch_unwind(f);
    panic::set_hook(previous_hook);

    match result {
        Ok(_) => panic!("expected closure to panic"),
        Err(_) => match lock(&captured).clone() {
            Some(panic) => panic,
            None => panic!("panic hook did not capture panic"),
        },
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn location_parts(location: &Location<'_>) -> (Option<String>, Option<u32>) {
    (Some(location.file().to_string()), Some(location.line()))
}

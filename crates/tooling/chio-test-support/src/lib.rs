//! Shared test-only assertion helpers for the Chio workspace.
//!
//! The workspace enforces `clippy::unwrap_used = "deny"` and
//! `clippy::expect_used = "deny"` everywhere, including test code. To keep
//! tests readable without reaching for the banned `.unwrap()` / `.expect()`
//! inherent methods, this crate provides small extension traits that perform
//! the same fail-the-test-on-error behaviour through explicit `panic!` calls.
//!
//! Two families of helpers exist for two call conventions that are
//! intentionally kept distinct:
//!
//! - The default family (re-exported from [`prelude`]) takes no context
//!   argument: `value.test_unwrap()`. An optional `test_expect(context)` is
//!   available when a caller wants a human-readable label on the panic.
//! - The [`ctx`] family always takes a `&str` context: `value.test_unwrap(ctx)`
//!   and `result.test_unwrap_err(ctx)`.
//!
//! The two families deliberately collide on the `test_unwrap` method name, so a
//! single source file should import exactly one of them.
//!
//! The [`loopback`] module provides shared helpers for integration tests that
//! need to bind local listeners. Tests can probe whether the current sandbox
//! permits loopback sockets and return early only when the operating system
//! denies the bind itself.
//!
//! The [`private_fs`] module creates private temporary directories and unique
//! SQLite paths beneath a canonical process-scoped root.
//!
//! These helpers are intended for use from `#[cfg(test)]` code only. Add the
//! crate as a `[dev-dependencies]` entry and bring the traits into scope with
//! `use chio_test_support::prelude::*;` (or `use chio_test_support::ctx::*;`).

#![forbid(unsafe_code)]

/// Context-free unwrap helpers (the dominant workspace convention).
///
/// Methods here mirror `Result::unwrap` / `Option::unwrap` /
/// `Result::unwrap_err`, panicking (and thereby failing the test) on the
/// unexpected variant. Error and value payloads are rendered with their
/// [`std::fmt::Debug`] representation so failures are diagnosable.
pub mod plain {
    use std::fmt::Debug;

    /// Extract the `Ok`/`Some` value or fail the test.
    pub trait TestResultOk<T> {
        /// Return the contained value, panicking on the error/none variant.
        #[track_caller]
        fn test_unwrap(self) -> T;

        /// Return the contained value, panicking with `context` on the
        /// error/none variant.
        #[track_caller]
        fn test_expect(self, context: &str) -> T;
    }

    /// Extract the `Err` value or fail the test.
    pub trait TestResultErr<E> {
        /// Return the contained error, panicking on the `Ok` variant.
        #[track_caller]
        fn test_unwrap_err(self) -> E;

        /// Return the contained error, panicking with `context` on the `Ok`
        /// variant.
        #[track_caller]
        fn test_expect_err(self, context: &str) -> E;
    }

    impl<T, E: Debug> TestResultOk<T> for Result<T, E> {
        #[track_caller]
        fn test_unwrap(self) -> T {
            match self {
                Ok(value) => value,
                Err(error) => panic!("expected Ok(..), got Err({error:?})"),
            }
        }

        #[track_caller]
        fn test_expect(self, context: &str) -> T {
            match self {
                Ok(value) => value,
                Err(error) => panic!("{context}: expected Ok(..), got Err({error:?})"),
            }
        }
    }

    impl<T> TestResultOk<T> for Option<T> {
        #[track_caller]
        fn test_unwrap(self) -> T {
            match self {
                Some(value) => value,
                None => panic!("expected Some(..), got None"),
            }
        }

        #[track_caller]
        fn test_expect(self, context: &str) -> T {
            match self {
                Some(value) => value,
                None => panic!("{context}: expected Some(..), got None"),
            }
        }
    }

    // No `T: Debug` bound here on purpose: some call sites unwrap the error of a
    // `Result` whose `Ok` payload is a non-`Debug` handle (for example a store
    // connection), so the `Ok` value is not interpolated into the panic.
    impl<T, E> TestResultErr<E> for Result<T, E> {
        #[track_caller]
        fn test_unwrap_err(self) -> E {
            match self {
                Ok(_) => panic!("expected Err(..), got Ok(..)"),
                Err(error) => error,
            }
        }

        #[track_caller]
        fn test_expect_err(self, context: &str) -> E {
            match self {
                Ok(_) => panic!("{context}: expected Err(..), got Ok(..)"),
                Err(error) => error,
            }
        }
    }
}

/// Context-carrying unwrap helpers.
///
/// Every method takes a `&str` context label that is prefixed onto the panic
/// message. Used by call sites written as `value.test_unwrap("loading config")`.
pub mod ctx {
    use std::fmt::Display;

    /// Extract the `Ok`/`Some` value or fail the test with a context label.
    pub trait TestUnwrap<T> {
        /// Return the contained value, panicking with `context` on the
        /// error/none variant.
        #[track_caller]
        fn test_unwrap(self, context: &str) -> T;
    }

    /// Extract the `Err` value or fail the test with a context label.
    pub trait TestUnwrapErr<E> {
        /// Return the contained error, panicking with `context` on the `Ok`
        /// variant.
        #[track_caller]
        fn test_unwrap_err(self, context: &str) -> E;
    }

    impl<T, E: Display> TestUnwrap<T> for Result<T, E> {
        #[track_caller]
        fn test_unwrap(self, context: &str) -> T {
            match self {
                Ok(value) => value,
                Err(error) => panic!("{context}: {error}"),
            }
        }
    }

    impl<T> TestUnwrap<T> for Option<T> {
        #[track_caller]
        fn test_unwrap(self, context: &str) -> T {
            match self {
                Some(value) => value,
                None => panic!("{context}"),
            }
        }
    }

    impl<T, E> TestUnwrapErr<E> for Result<T, E> {
        #[track_caller]
        fn test_unwrap_err(self, context: &str) -> E {
            match self {
                Ok(_) => panic!("{context}: unexpected Ok(..)"),
                Err(error) => error,
            }
        }
    }
}

/// Private filesystem fixtures for tests that exercise authority-bearing files.
pub mod private_fs {
    use std::fs;
    use std::io;
    use std::path::{Component, Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;

    use tempfile::{Builder, TempDir};

    const SQLITE_ROOT_PREFIX: &str = "chio-sqlite-tests-";

    #[cfg(unix)]
    const SQLITE_ROOT_LEASE_FILE: &str = ".chio-sqlite-root.lease";

    static PRIVATE_SQLITE_ROOT: OnceLock<PrivateSqliteRoot> = OnceLock::new();
    static NEXT_SQLITE_PATH: AtomicU64 = AtomicU64::new(0);

    struct PrivateSqliteRoot {
        path: PathBuf,
        #[cfg(unix)]
        _lease: fs::File,
    }

    /// Return a unique SQLite path beneath this test process's canonical private root.
    #[must_use]
    #[track_caller]
    pub fn unique_sqlite_path(prefix: &str) -> PathBuf {
        if let Err(error) = validate_prefix(prefix) {
            panic!("invalid private test path prefix {prefix:?}: {error}");
        }
        let sequence =
            match NEXT_SQLITE_PATH.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            }) {
                Ok(sequence) => sequence,
                Err(_) => panic!("private SQLite test path sequence exhausted"),
            };
        private_sqlite_root().join(format!("{prefix}-{sequence}.sqlite3"))
    }

    /// Create a randomized temporary directory with private authority.
    pub fn private_tempdir(prefix: &str) -> io::Result<TempDir> {
        validate_prefix(prefix)?;
        let base = fs::canonicalize(std::env::temp_dir())?;
        private_tempdir_in(prefix, &base)
    }

    fn private_tempdir_in(prefix: &str, base: &Path) -> io::Result<TempDir> {
        validate_prefix(prefix)?;
        let mut builder = Builder::new();
        builder.prefix(prefix);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            builder.permissions(fs::Permissions::from_mode(0o700));
        }
        let directory = builder.tempdir_in(base)?;
        enforce_private_directory(directory.path())?;
        Ok(directory)
    }

    #[track_caller]
    fn private_sqlite_root() -> &'static Path {
        PRIVATE_SQLITE_ROOT
            .get_or_init(|| match initialize_private_sqlite_root() {
                Ok(root) => root,
                Err(error) => panic!("create private SQLite test root: {error}"),
            })
            .path
            .as_path()
    }

    #[cfg(unix)]
    fn initialize_private_sqlite_root() -> io::Result<PrivateSqliteRoot> {
        let base = fs::canonicalize(std::env::temp_dir())?;
        initialize_private_sqlite_root_in(&base)
    }

    #[cfg(unix)]
    fn initialize_private_sqlite_root_in(base: &Path) -> io::Result<PrivateSqliteRoot> {
        let setup_lock = acquire_sqlite_root_setup_lock(base)?;
        reap_stale_sqlite_roots(base)?;

        let directory = private_tempdir_in(SQLITE_ROOT_PREFIX, base)?;
        let canonical = fs::canonicalize(directory.path())?;
        let lease = create_private_lock_file(&canonical.join(SQLITE_ROOT_LEASE_FILE))?;
        rustix::fs::flock(&lease, rustix::fs::FlockOperation::LockExclusive)
            .map_err(io::Error::from)?;

        // The root must outlive every parallel test in this process. A later
        // process reclaims it only after this process's lease is released.
        let retained_path = directory.keep();
        drop(retained_path);
        drop(setup_lock);

        Ok(PrivateSqliteRoot {
            path: canonical,
            _lease: lease,
        })
    }

    #[cfg(not(unix))]
    fn initialize_private_sqlite_root() -> io::Result<PrivateSqliteRoot> {
        let directory = private_tempdir(SQLITE_ROOT_PREFIX)?;
        let canonical = fs::canonicalize(directory.path())?;
        let retained_path = directory.keep();
        drop(retained_path);
        Ok(PrivateSqliteRoot { path: canonical })
    }

    #[cfg(unix)]
    fn acquire_sqlite_root_setup_lock(base: &Path) -> io::Result<fs::File> {
        let path = sqlite_root_setup_lock_path(base);
        let lock = open_or_create_private_lock_file(&path)?;
        loop {
            match rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive) {
                Ok(()) => return Ok(lock),
                Err(error) if error == rustix::io::Errno::INTR => {}
                Err(error) => return Err(io::Error::from(error)),
            }
        }
    }

    #[cfg(unix)]
    fn sqlite_root_setup_lock_path(base: &Path) -> PathBuf {
        let effective_uid = rustix::process::geteuid().as_raw();
        base.join(format!(".chio-sqlite-root-setup-{effective_uid}.lock"))
    }

    #[cfg(unix)]
    fn reap_stale_sqlite_roots(base: &Path) -> io::Result<()> {
        let mut remove_entry = remove_sqlite_root_entry;
        reap_stale_sqlite_roots_with(base, &mut remove_entry)
    }

    #[cfg(unix)]
    fn reap_stale_sqlite_roots_with(
        base: &Path,
        remove_entry: &mut impl FnMut(&Path) -> io::Result<()>,
    ) -> io::Result<()> {
        for entry in fs::read_dir(base)? {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            let candidate = entry.path();
            if !is_sqlite_root_name(&candidate) || !is_private_sqlite_root(&candidate) {
                continue;
            }

            let lease_path = candidate.join(SQLITE_ROOT_LEASE_FILE);
            let lease = match open_existing_private_lock_file(&lease_path) {
                Ok(lease) => lease,
                // Initialization publishes no usable path before the lease is
                // created. While the per-UID setup lock is held, an empty,
                // exact-authority root with no lease can therefore only be an
                // initializer that died in that narrow window. `remove_dir`
                // deliberately refuses a non-empty root, so missing a lease
                // never broadens recursive deletion authority.
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    if is_private_sqlite_root(&candidate) {
                        let _ = fs::remove_dir(&candidate);
                    }
                    continue;
                }
                Err(_) => continue,
            };
            match rustix::fs::flock(&lease, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => {
                    if is_private_sqlite_root(&candidate)
                        && validate_private_lock_file(&lease_path, &lease).is_ok()
                    {
                        let _ = remove_sqlite_root_preserving_lease(
                            &candidate,
                            &lease_path,
                            &lease,
                            remove_entry,
                        );
                    }
                }
                Err(error)
                    if error == rustix::io::Errno::WOULDBLOCK
                        || error == rustix::io::Errno::AGAIN => {}
                Err(_) => {}
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    fn remove_sqlite_root_preserving_lease(
        candidate: &Path,
        lease_path: &Path,
        lease: &fs::File,
        remove_entry: &mut impl FnMut(&Path) -> io::Result<()>,
    ) -> io::Result<()> {
        // Remove every payload entry before the lease. If traversal fails after
        // making partial progress, the still-linked lease preserves both the
        // deletion authority and the next process's ability to retry.
        for entry in fs::read_dir(candidate)? {
            let entry = entry?;
            if entry.file_name() == std::ffi::OsStr::new(SQLITE_ROOT_LEASE_FILE) {
                continue;
            }
            remove_entry(&entry.path())?;
        }

        if !is_private_sqlite_root(candidate) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private SQLite test root changed during reap",
            ));
        }
        validate_private_lock_file(lease_path, lease)?;

        // The lease is the final directory entry. If the final rmdir loses a
        // race or otherwise fails, restore a fresh valid lease so the next pass
        // remains authorized to retry. A crash between these two operations
        // leaves an empty missing-lease directory, which the narrow remove_dir
        // recovery path above can safely finish.
        fs::remove_file(lease_path)?;
        match fs::remove_dir(candidate) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => {
                let _ = restore_reaper_lease(candidate, lease_path);
                Err(error)
            }
        }
    }

    #[cfg(unix)]
    fn remove_sqlite_root_entry(path: &Path) -> io::Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_dir() {
            fs::remove_dir_all(path)
        } else {
            fs::remove_file(path)
        }
    }

    #[cfg(unix)]
    fn restore_reaper_lease(candidate: &Path, lease_path: &Path) -> io::Result<()> {
        if !is_private_sqlite_root(candidate) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private SQLite test root changed before lease restoration",
            ));
        }
        match create_private_lock_file(lease_path) {
            Ok(lease) => {
                drop(lease);
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                drop(open_existing_private_lock_file(lease_path)?);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    #[cfg(unix)]
    fn is_sqlite_root_name(path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.starts_with(SQLITE_ROOT_PREFIX) && name.len() > SQLITE_ROOT_PREFIX.len()
            })
    }

    #[cfg(unix)]
    fn is_private_sqlite_root(path: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;

        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(_) => return false,
        };
        metadata.file_type().is_dir()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o7777 == 0o700
    }

    #[cfg(unix)]
    fn open_or_create_private_lock_file(path: &Path) -> io::Result<fs::File> {
        match create_private_lock_file(path) {
            Ok(file) => Ok(file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                open_existing_private_lock_file(path)
            }
            Err(error) => Err(error),
        }
    }

    #[cfg(unix)]
    fn create_private_lock_file(path: &Path) -> io::Result<fs::File> {
        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(io::Error::from)?;
        let file = fs::File::from(descriptor);
        validate_private_lock_file_identity(path, &file)?;
        rustix::fs::fchmod(&file, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR)
            .map_err(io::Error::from)?;
        validate_private_lock_file(path, &file)?;
        Ok(file)
    }

    #[cfg(unix)]
    fn open_existing_private_lock_file(path: &Path) -> io::Result<fs::File> {
        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(io::Error::from)?;
        let file = fs::File::from(descriptor);
        validate_private_lock_file(path, &file)?;
        Ok(file)
    }

    #[cfg(unix)]
    fn validate_private_lock_file_identity(path: &Path, file: &fs::File) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;

        let path_metadata = fs::symlink_metadata(path)?;
        let descriptor_metadata = file.metadata()?;
        if !path_metadata.file_type().is_file()
            || !descriptor_metadata.file_type().is_file()
            || path_metadata.dev() != descriptor_metadata.dev()
            || path_metadata.ino() != descriptor_metadata.ino()
            || descriptor_metadata.uid() != rustix::process::geteuid().as_raw()
            || descriptor_metadata.nlink() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private lock file identity is unsafe",
            ));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn validate_private_lock_file(path: &Path, file: &fs::File) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;

        validate_private_lock_file_identity(path, file)?;
        let mode = file.metadata()?.mode() & 0o7777;
        if mode != 0o600 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("private lock file has mode {mode:04o}, expected 0600"),
            ));
        }
        Ok(())
    }

    fn validate_prefix(prefix: &str) -> io::Result<()> {
        let mut components = Path::new(prefix).components();
        match (components.next(), components.next()) {
            (Some(Component::Normal(component)), None) if !component.is_empty() => Ok(()),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "prefix must be one non-empty normal path component",
            )),
        }
    }

    fn enforce_private_directory(path: &Path) -> io::Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_dir() {
            return Err(io::Error::other(
                "private test directory is not a real directory",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            let mode = fs::symlink_metadata(path)?.permissions().mode() & 0o777;
            if mode != 0o700 {
                return Err(io::Error::other(format!(
                    "private test directory has mode {mode:04o}, expected 0700"
                )));
            }
        }
        Ok(())
    }

    #[cfg(all(test, unix))]
    mod tests {
        use std::io::{self, Read};
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::process::{Command, Stdio};
        use std::time::Duration;

        use super::{
            acquire_sqlite_root_setup_lock, create_private_lock_file,
            open_existing_private_lock_file, private_tempdir, reap_stale_sqlite_roots,
            reap_stale_sqlite_roots_with, remove_sqlite_root_entry, sqlite_root_setup_lock_path,
            SQLITE_ROOT_LEASE_FILE, SQLITE_ROOT_PREFIX,
        };

        const REAPER_CHILD_BASE_ENV: &str = "CHIO_TEST_SUPPORT_REAPER_CHILD_BASE";
        const REAPER_CHILD_READY_ENV: &str = "CHIO_TEST_SUPPORT_REAPER_CHILD_READY";

        #[test]
        fn active_sqlite_root_is_preserved() -> io::Result<()> {
            let base = private_tempdir("chio-reaper-active-")?;
            let candidate = create_candidate(base.path(), "active")?;
            let lease = create_private_lock_file(&candidate.join(SQLITE_ROOT_LEASE_FILE))?;
            rustix::fs::flock(&lease, rustix::fs::FlockOperation::LockExclusive)
                .map_err(io::Error::from)?;

            reap_stale_sqlite_roots(base.path())?;

            assert!(candidate.is_dir());
            Ok(())
        }

        #[test]
        fn released_sqlite_root_is_reclaimed() -> io::Result<()> {
            let base = private_tempdir("chio-reaper-released-")?;
            let candidate = create_candidate(base.path(), "released")?;
            let lease = create_private_lock_file(&candidate.join(SQLITE_ROOT_LEASE_FILE))?;
            rustix::fs::flock(&lease, rustix::fs::FlockOperation::LockExclusive)
                .map_err(io::Error::from)?;
            drop(lease);

            reap_stale_sqlite_roots(base.path())?;

            assert!(!candidate.exists());
            Ok(())
        }

        #[test]
        fn empty_missing_lease_root_is_reclaimed_without_deleting_nonempty_root() -> io::Result<()>
        {
            let base = private_tempdir("chio-reaper-missing-lease-")?;
            let empty = create_candidate(base.path(), "empty")?;
            let nonempty = create_candidate(base.path(), "nonempty")?;
            let payload = nonempty.join("receipt.sqlite3");
            std::fs::write(&payload, b"retained")?;

            reap_stale_sqlite_roots(base.path())?;

            assert!(!empty.exists());
            assert!(nonempty.is_dir());
            assert_eq!(std::fs::read(payload)?, b"retained");
            Ok(())
        }

        #[test]
        fn partial_reap_failure_preserves_lease_for_retry() -> io::Result<()> {
            let base = private_tempdir("chio-reaper-retry-")?;
            let candidate = create_candidate(base.path(), "partial")?;
            let lease_path = candidate.join(SQLITE_ROOT_LEASE_FILE);
            drop(create_private_lock_file(&lease_path)?);
            std::fs::write(candidate.join("first.sqlite3"), b"first")?;
            std::fs::write(candidate.join("second.sqlite3"), b"second")?;

            let mut removals = 0_u8;
            reap_stale_sqlite_roots_with(base.path(), &mut |path| {
                removals = removals.saturating_add(1);
                if removals == 2 {
                    return Err(io::Error::other("injected partial reap failure"));
                }
                remove_sqlite_root_entry(path)
            })?;

            assert_eq!(removals, 2);
            assert!(candidate.is_dir());
            drop(open_existing_private_lock_file(&lease_path)?);

            reap_stale_sqlite_roots(base.path())?;
            assert!(!candidate.exists());
            Ok(())
        }

        #[test]
        fn subprocess_death_releases_root_for_reclamation() -> io::Result<()> {
            let base = private_tempdir("chio-reaper-subprocess-")?;
            let ready = base.path().join("child-ready");
            let executable = std::env::current_exe()?;
            let mut child = Command::new(executable)
                .arg("private_fs::tests::sqlite_root_lease_subprocess_child")
                .arg("--exact")
                .arg("--nocapture")
                .env(REAPER_CHILD_BASE_ENV, base.path())
                .env(REAPER_CHILD_READY_ENV, &ready)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()?;

            let active_check = (|| -> io::Result<std::path::PathBuf> {
                for _ in 0..500 {
                    if ready.is_file() {
                        let pid = std::fs::read_to_string(&ready)?;
                        let candidate = base
                            .path()
                            .join(format!("{SQLITE_ROOT_PREFIX}child-{}", pid.trim()));
                        reap_stale_sqlite_roots(base.path())?;
                        if !candidate.is_dir() {
                            return Err(io::Error::other(
                                "reaper removed a root whose subprocess still held the lease",
                            ));
                        }
                        return Ok(candidate);
                    }
                    if let Some(status) = child.try_wait()? {
                        return Err(io::Error::other(format!(
                            "lease subprocess exited before publishing readiness: {status}"
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "lease subprocess did not publish readiness",
                ))
            })();

            // Always terminate and join the helper, including when its active
            // lease check failed, so this regression cannot strand a process.
            let _ = child.kill();
            let _ = child.wait();
            let candidate = active_check?;

            reap_stale_sqlite_roots(base.path())?;
            assert!(!candidate.exists());
            Ok(())
        }

        #[test]
        fn sqlite_root_lease_subprocess_child() -> io::Result<()> {
            let Some(base) = std::env::var_os(REAPER_CHILD_BASE_ENV) else {
                return Ok(());
            };
            let ready = std::env::var_os(REAPER_CHILD_READY_ENV).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "missing child-ready path")
            })?;
            let base = std::path::PathBuf::from(base);
            let candidate = create_candidate(&base, &format!("child-{}", std::process::id()))?;
            let lease = create_private_lock_file(&candidate.join(SQLITE_ROOT_LEASE_FILE))?;
            rustix::fs::flock(&lease, rustix::fs::FlockOperation::LockExclusive)
                .map_err(io::Error::from)?;
            std::fs::write(candidate.join("receipt.sqlite3"), b"durable test payload")?;
            std::fs::write(ready, std::process::id().to_string())?;

            // The parent retains the write end of this pipe while checking that
            // the live lease is preserved, then kills this process. Process death
            // releases the flock without a cooperative unlock.
            let mut byte = [0_u8; 1];
            let _ = std::io::stdin().read(&mut byte)?;
            drop(lease);
            Ok(())
        }

        #[test]
        fn unsafe_roots_and_lease_files_are_preserved() -> io::Result<()> {
            let base = private_tempdir("chio-reaper-unsafe-")?;
            let unsafe_root = create_candidate(base.path(), "unsafe-root")?;
            let root_lease = create_private_lock_file(&unsafe_root.join(SQLITE_ROOT_LEASE_FILE))?;
            drop(root_lease);
            std::fs::set_permissions(&unsafe_root, std::fs::Permissions::from_mode(0o755))?;

            let unsafe_lease = create_candidate(base.path(), "unsafe-lease")?;
            let lease_path = unsafe_lease.join(SQLITE_ROOT_LEASE_FILE);
            let lease = create_private_lock_file(&lease_path)?;
            drop(lease);
            std::fs::set_permissions(&lease_path, std::fs::Permissions::from_mode(0o644))?;

            reap_stale_sqlite_roots(base.path())?;

            assert!(unsafe_root.is_dir());
            assert!(unsafe_lease.is_dir());
            Ok(())
        }

        #[test]
        fn symlink_roots_and_lease_files_are_preserved() -> io::Result<()> {
            let base = private_tempdir("chio-reaper-symlink-")?;
            let root_target = base.path().join("root-target");
            std::fs::create_dir(&root_target)?;
            let symlink_root = base
                .path()
                .join(format!("{SQLITE_ROOT_PREFIX}symlink-root"));
            symlink(&root_target, &symlink_root)?;

            let symlink_lease_root = create_candidate(base.path(), "symlink-lease")?;
            let lease_target = base.path().join("lease-target");
            std::fs::write(&lease_target, b"not a lease")?;
            symlink(
                &lease_target,
                symlink_lease_root.join(SQLITE_ROOT_LEASE_FILE),
            )?;

            reap_stale_sqlite_roots(base.path())?;

            assert!(std::fs::symlink_metadata(&symlink_root)?
                .file_type()
                .is_symlink());
            assert!(root_target.is_dir());
            assert!(symlink_lease_root.is_dir());
            assert!(lease_target.is_file());
            Ok(())
        }

        #[test]
        fn sqlite_root_setup_lock_serializes_initializers() -> io::Result<()> {
            let base = private_tempdir("chio-reaper-setup-")?;
            let canonical_base = std::fs::canonicalize(base.path())?;
            let setup_lock = acquire_sqlite_root_setup_lock(&canonical_base)?;
            let contender =
                open_existing_private_lock_file(&sqlite_root_setup_lock_path(&canonical_base))?;
            let contention = rustix::fs::flock(
                &contender,
                rustix::fs::FlockOperation::NonBlockingLockExclusive,
            );
            assert!(matches!(
                contention,
                Err(error)
                    if error == rustix::io::Errno::WOULDBLOCK
                        || error == rustix::io::Errno::AGAIN
            ));

            drop(setup_lock);
            rustix::fs::flock(
                &contender,
                rustix::fs::FlockOperation::NonBlockingLockExclusive,
            )
            .map_err(io::Error::from)?;
            Ok(())
        }

        fn create_candidate(
            base: &std::path::Path,
            suffix: &str,
        ) -> io::Result<std::path::PathBuf> {
            let path = base.join(format!("{SQLITE_ROOT_PREFIX}{suffix}"));
            std::fs::create_dir(&path)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
            Ok(path)
        }
    }
}

/// Glob-import target for the default (context-free) helper family.
///
/// `use chio_test_support::prelude::*;` brings [`plain::TestResultOk`] and
/// [`plain::TestResultErr`] into scope.
pub mod prelude {
    pub use crate::plain::{TestResultErr, TestResultOk};
}

/// Loopback listener helpers for integration tests that spawn local services.
///
/// CI runners should normally allow `127.0.0.1:0` binds. Locked-down local
/// sandboxes can deny the bind with `PermissionDenied`, in which case tests may
/// return early after calling [`skip_when_loopback_bind_denied`]. Other bind
/// errors still fail the test because they may indicate a real regression.
pub mod loopback {
    use std::io::{self, ErrorKind};
    use std::net::{SocketAddr, TcpListener};

    /// Return true when this process can bind an ephemeral IPv4 loopback port.
    pub fn loopback_bind_available() -> bool {
        TcpListener::bind(("127.0.0.1", 0)).is_ok()
    }

    /// Return true only when the local environment denies loopback binding.
    ///
    /// Unexpected probe failures panic instead of being treated as a skip so a
    /// broken test environment does not hide production bind regressions.
    #[track_caller]
    pub fn skip_when_loopback_bind_denied(test_name: &str) -> bool {
        match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(listener) => {
                drop(listener);
                false
            }
            Err(error) if is_loopback_bind_denied(&error) => {
                eprintln!("skipping {test_name}: loopback bind denied: {error}");
                true
            }
            Err(error) => panic!("probe loopback bind for {test_name}: {error}"),
        }
    }

    /// Reserve an ephemeral loopback address for a local test server.
    ///
    /// Callers should invoke [`skip_when_loopback_bind_denied`] at the start of
    /// a socket-backed test before reserving an address. If they do not, a
    /// sandbox permission failure is reported with a diagnostic that points at
    /// the missing probe.
    #[track_caller]
    pub fn reserve_listen_addr() -> SocketAddr {
        reserve_listen_addr_for("integration test")
    }

    /// Reserve an ephemeral loopback address with a diagnostic label.
    #[track_caller]
    pub fn reserve_listen_addr_for(label: &str) -> SocketAddr {
        match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => {
                let addr = match listener.local_addr() {
                    Ok(addr) => addr,
                    Err(error) => panic!("read listener addr for {label}: {error}"),
                };
                drop(listener);
                addr
            }
            Err(error) if is_loopback_bind_denied(&error) => panic!(
                "loopback bind denied while reserving address for {label}: {error}; \
                 call skip_when_loopback_bind_denied at test start"
            ),
            Err(error) => panic!("bind temp listener for {label}: {error}"),
        }
    }

    /// True for operating-system permission denials caused by locked-down test
    /// sandboxes. This intentionally excludes address conflicts and malformed
    /// addresses, which should still fail tests.
    pub fn is_loopback_bind_denied(error: &io::Error) -> bool {
        error.kind() == ErrorKind::PermissionDenied
    }
}

#[cfg(test)]
mod tests {
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
            let (location_file, location_line) =
                info.location().map_or((None, None), location_parts);
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
}

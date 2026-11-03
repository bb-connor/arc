//! Short worker endpoints with write-ahead ownership and restart cleanup.
//!
//! Durable host paths are unrestricted by Unix socket address length. The fixed
//! Linux /tmp parent is independent of TMPDIR and never exposes host state.

use std::ffi::CString;
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use chio_process::run_journal::FileIdentity;
use chio_store_sqlite::process_run_store::SqliteRunJournal;

use super::super::state::error;
use crate::CliError;

const SOCKET: &str = "process.sock";

pub(super) struct Endpoint {
    parent: File,
    directory: File,
    name: String,
    path: PathBuf,
}

fn identity(metadata: &Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn owned_private(metadata: &Metadata) -> bool {
    // SAFETY: geteuid is a read-only process query.
    metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0
}

fn open_at(parent: &File, name: &str, flags: i32) -> io::Result<File> {
    let name = CString::new(name)?;
    // SAFETY: name is NUL-terminated and parent remains open for this call.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a newly owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn entry(parent: &File, name: &str) -> io::Result<Option<Metadata>> {
    match open_at(parent, name, libc::O_PATH) {
        Ok(file) => file.metadata().map(Some),
        Err(failure) if failure.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(failure) => Err(failure),
    }
}

fn remove_at(parent: &File, name: &str, directory: bool) -> io::Result<()> {
    let name = CString::new(name)?;
    // SAFETY: name is NUL-terminated and parent remains open for this call.
    if unsafe {
        libc::unlinkat(
            parent.as_raw_fd(),
            name.as_ptr(),
            if directory { libc::AT_REMOVEDIR } else { 0 },
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    parent.sync_all()
}

fn parent() -> Result<File, CliError> {
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/tmp")?;
    let metadata = parent.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o1000 == 0 {
        return Err(error(
            "worker socket parent /tmp must be a root-owned sticky directory",
        ));
    }
    Ok(parent)
}

fn validate_name(name: &str) -> Result<(), CliError> {
    if !name.strip_prefix("chio-worker-").is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err(error("invalid recorded worker socket directory name"));
    }
    Ok(())
}

fn reconcile(store: &SqliteRunJournal, parent: &File) -> Result<(), CliError> {
    // Hold the journal's write lock across lookup and retirement. Only a
    // positively absent, validated pre-credential intent may be forgotten.
    let retirement = store.retire_socket_intents().map_err(error)?;
    for intent in retirement.intents() {
        validate_name(&intent.name)?;
        if entry(parent, &intent.name)?.is_none() {
            retirement.forget(intent).map_err(error)?;
        }
    }
    retirement.commit().map_err(error)?;
    let Some(record) = store.socket_lease().map_err(error)? else {
        return Ok(());
    };
    validate_name(&record.name)?;
    if let Some(metadata) = entry(parent, &record.name)? {
        if record.directory.is_none() {
            // The pre-bind intent never issued worker credentials. Preserve the
            // unknown object and history, then use a new random endpoint.
            return store.abandon_socket_intent().map_err(error);
        }
        if !metadata.is_dir()
            || !owned_private(&metadata)
            || Some(identity(&metadata)) != record.directory
        {
            return Err(error(format!("worker socket directory ownership is unresolved: /tmp/{}; preserve the directory and runner journal", record.name)));
        }
        let directory = open_at(parent, &record.name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        if Some(identity(&directory.metadata()?)) != record.directory {
            return Err(error("worker socket directory changed during cleanup"));
        }
        if let Some(metadata) = entry(&directory, SOCKET)? {
            if record.socket.is_none() {
                // A listener may have existed, but no worker credential was
                // delivered before the socket identity commit.
                return store.abandon_socket_intent().map_err(error);
            }
            if !metadata.file_type().is_socket()
                || !owned_private(&metadata)
                || metadata.nlink() != 1
                || Some(identity(&metadata)) != record.socket
            {
                return Err(error(format!("worker socket ownership is unresolved: /tmp/{}/{SOCKET}; preserve the endpoint and runner journal", record.name)));
            }
            remove_at(&directory, SOCKET, false)?;
        }
        // Only the known socket is unlinked. Unknown siblings keep the directory
        // and its durable lease intact, even when they belong to the operator.
        if entry(parent, &record.name)?.as_ref().map(identity) != record.directory {
            return Err(error("worker socket directory changed before removal"));
        }
        remove_at(parent, &record.name, true)?;
    }
    store.forget_socket_intent().map_err(error)
}

pub(super) fn cleanup_for_export(store: &SqliteRunJournal) -> Result<(), CliError> {
    if store.has_socket_intents().map_err(error)? {
        reconcile(store, &parent()?)?;
        if store.has_socket_intents().map_err(error)? {
            return Err(error("worker socket ownership is unresolved; preserve abandoned endpoint records on the original host before export"));
        }
    }
    Ok(())
}

impl Endpoint {
    pub fn prepare(store: &SqliteRunJournal) -> Result<Self, CliError> {
        let parent = parent()?;
        reconcile(store, &parent)?;
        let name = format!("chio-worker-{}", uuid::Uuid::new_v4().simple());
        // A crash at either filesystem creation boundary leaves a tracked lease.
        // Missing identity is never inferred from a name, owner or permissions.
        store.record_socket_intent(&name).map_err(error)?;
        let c_name = CString::new(name.as_bytes()).map_err(error)?;
        // SAFETY: the name is NUL-terminated and parent remains open.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), c_name.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        parent.sync_all()?;
        let directory = open_at(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        let metadata = directory.metadata()?;
        if !owned_private(&metadata) {
            return Err(error("new worker socket directory must be private"));
        }
        store
            .socket_directory_created(&name, identity(&metadata))
            .map_err(error)?;
        let path = Path::new("/tmp").join(&name).join(SOCKET);
        Ok(Self {
            parent,
            directory,
            name,
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn bound(&self, store: &SqliteRunJournal) -> Result<(), CliError> {
        let directory = self.directory.metadata()?;
        if entry(&self.parent, &self.name)?.as_ref().map(identity) != Some(identity(&directory)) {
            return Err(error("worker socket directory changed during bind"));
        }
        let metadata = entry(&self.directory, SOCKET)?
            .ok_or_else(|| error("worker socket is missing after bind"))?;
        if !metadata.file_type().is_socket() || !owned_private(&metadata) || metadata.nlink() != 1 {
            return Err(error(
                "new worker socket must be private and operator-owned",
            ));
        }
        self.directory.sync_all()?;
        store
            .socket_bound(&self.name, identity(&metadata))
            .map_err(error)
    }

    pub fn cleanup(&self, store: &SqliteRunJournal) -> Result<(), CliError> {
        reconcile(store, &self.parent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_store_sqlite::process_run_store::tamper::{tamper, JournalTamper};
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::os::unix::net::UnixListener;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The store under test and its path for tampering.
    fn journal(
    ) -> Result<(tempfile::TempDir, SqliteRunJournal, PathBuf), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("runner.db");
        let store = SqliteRunJournal::open(&path, "binding")?;
        Ok((directory, store, path))
    }

    /// Live and abandoned intents the journal retains.
    fn intents(store: &SqliteRunJournal) -> Result<u32, Box<dyn std::error::Error>> {
        Ok(store.abandoned_socket_intents()? + u32::from(store.socket_lease()?.is_some()))
    }

    fn bind(
        endpoint: &Endpoint,
        store: &SqliteRunJournal,
    ) -> Result<UnixListener, Box<dyn std::error::Error>> {
        let listener = UnixListener::bind(endpoint.path())?;
        std::fs::set_permissions(endpoint.path(), std::fs::Permissions::from_mode(0o600))?;
        endpoint.bound(store)?;
        Ok(listener)
    }

    #[test]
    fn short_endpoint_recovers_socket_and_cleans_completed_runs() -> TestResult {
        let (_journal, store, _) = journal()?;
        let first = Endpoint::prepare(&store)?;
        assert!(first.path().as_os_str().len() < 104);
        let listener = bind(&first, &store)?;
        std::os::unix::net::UnixStream::connect(first.path())?;
        drop(listener); // Host death leaves the filesystem socket behind.
        let second = Endpoint::prepare(&store)?;
        assert!(!first.path.parent().ok_or("parent")?.exists());
        assert_ne!(first.path(), second.path());
        let listener = bind(&second, &store)?;
        drop(listener);
        second.cleanup(&store)?;
        assert!(!second.path.parent().ok_or("parent")?.exists());
        assert!(store.socket_lease()?.is_none());
        Ok(())
    }

    #[test]
    fn socket_creation_gaps_preserve_objects_and_resume_with_a_new_endpoint() -> TestResult {
        for directory_gap in [true, false] {
            let (_journal, store, path) = journal()?;
            let first = Endpoint::prepare(&store)?;
            let listener = if directory_gap {
                None
            } else {
                Some(bind(&first, &store)?)
            };
            tamper(
                &path,
                if directory_gap {
                    JournalTamper::LiveDirectoryUncommitted
                } else {
                    JournalTamper::LiveSocketUncommitted
                },
            )?;
            let before = first.directory.metadata()?;
            let second = Endpoint::prepare(&store)?;
            assert_eq!(
                identity(&before),
                identity(&std::fs::metadata(first.path.parent().ok_or("parent")?)?)
            );
            assert_eq!(store.abandoned_socket_intents()?, 1);
            assert!(cleanup_for_export(&store).is_err());
            assert!(first.path.parent().ok_or("parent")?.exists());
            second.cleanup(&store)?;
            drop(listener);
            if first.path.exists() {
                std::fs::remove_file(first.path())?;
            }
            std::fs::remove_dir(first.path.parent().ok_or("parent")?)?;
        }
        Ok(())
    }

    #[test]
    fn recorded_socket_replacement_is_never_unlinked() -> TestResult {
        for symlink_replacement in [true, false] {
            let (_journal, store, _) = journal()?;
            let endpoint = Endpoint::prepare(&store)?;
            let listener = bind(&endpoint, &store)?;
            let original = endpoint.path.with_extension("original");
            std::fs::rename(endpoint.path(), &original)?;
            if symlink_replacement {
                symlink(&original, endpoint.path())?;
            } else {
                std::fs::write(endpoint.path(), b"must survive")?;
            }
            assert!(Endpoint::prepare(&store).is_err());
            assert!(endpoint.path.symlink_metadata().is_ok());
            assert!(store.socket_lease()?.is_some());
            std::fs::remove_file(endpoint.path())?;
            std::fs::rename(&original, endpoint.path())?;
            drop(listener);
            endpoint.cleanup(&store)?;
        }
        Ok(())
    }

    #[test]
    fn replaced_directory_and_unexpected_siblings_survive_cleanup() -> TestResult {
        let (_journal, store, _) = journal()?;
        let endpoint = Endpoint::prepare(&store)?;
        let directory = endpoint.path.parent().ok_or("parent")?;
        let moved = directory.with_extension("original");
        std::fs::rename(directory, &moved)?;
        std::fs::create_dir(directory)?;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
        assert!(endpoint.cleanup(&store).is_err());
        assert!(directory.exists());
        std::fs::remove_dir(directory)?;
        std::fs::rename(&moved, directory)?;
        let sibling = directory.join("unrelated");
        std::fs::write(&sibling, b"must survive")?;
        assert!(endpoint.cleanup(&store).is_err());
        assert_eq!(std::fs::read(&sibling)?, b"must survive");
        assert!(store.socket_lease()?.is_some());
        std::fs::remove_file(sibling)?;
        endpoint.cleanup(&store)?;
        Ok(())
    }

    #[test]
    fn replacement_socket_identity_blocks_export_until_original_is_restored() -> TestResult {
        let (_journal, store, _) = journal()?;
        let endpoint = Endpoint::prepare(&store)?;
        let listener = bind(&endpoint, &store)?;
        let original = endpoint.path.with_extension("original");
        std::fs::rename(endpoint.path(), &original)?;
        let replacement = UnixListener::bind(endpoint.path())?;
        std::fs::set_permissions(endpoint.path(), std::fs::Permissions::from_mode(0o600))?;
        let replacement_identity = identity(&std::fs::symlink_metadata(endpoint.path())?);
        assert!(cleanup_for_export(&store).is_err());
        assert_eq!(
            identity(&std::fs::symlink_metadata(endpoint.path())?),
            replacement_identity
        );
        drop(replacement);
        std::fs::remove_file(endpoint.path())?;
        std::fs::rename(&original, endpoint.path())?;
        drop(listener);
        cleanup_for_export(&store)?;
        assert!(!endpoint.path.parent().ok_or("parent")?.exists());
        assert!(store.socket_lease()?.is_none());
        Ok(())
    }

    #[test]
    fn broad_permissions_and_hardlinked_socket_preserve_the_lease() -> TestResult {
        let (_journal, store, _) = journal()?;
        let endpoint = Endpoint::prepare(&store)?;
        let listener = bind(&endpoint, &store)?;
        let directory = endpoint.path.parent().ok_or("parent")?;
        for (path, invalid, restored) in
            [(directory, 0o755, 0o700), (endpoint.path(), 0o644, 0o600)]
        {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(invalid))?;
            assert!(endpoint.cleanup(&store).is_err());
            assert!(endpoint.path.exists());
            assert!(store.socket_lease()?.is_some());
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(restored))?;
        }
        let alias = directory.join("alias");
        std::fs::hard_link(endpoint.path(), &alias)?;
        assert!(endpoint.cleanup(&store).is_err());
        assert!(endpoint.path.exists());
        std::fs::remove_file(alias)?;
        drop(listener);
        endpoint.cleanup(&store)?;
        Ok(())
    }

    #[test]
    fn absent_intents_clear_and_abandoned_history_is_bounded() -> TestResult {
        let (_journal, store, path) = journal()?;
        let endpoint = Endpoint::prepare(&store)?;
        std::fs::remove_dir(endpoint.path.parent().ok_or("parent")?)?;
        endpoint.cleanup(&store)?;
        assert!(store.socket_lease()?.is_none());
        for slot in 2..=9 {
            let name = format!("chio-worker-{slot:032x}");
            tamper(
                &path,
                JournalTamper::AbandonedSocketIntent { slot, name: &name },
            )?;
        }
        let _endpoint = Endpoint::prepare(&store)?;
        assert_eq!(intents(&store)?, 1);
        // Foreign objects, including symlinks, are never unlinked or retired.
        let foreign = tempfile::Builder::new()
            .prefix("chio-worker-")
            .tempdir_in("/tmp")?;
        let name = format!("chio-worker-{}", uuid::Uuid::new_v4().simple());
        let alias = Path::new("/tmp").join(&name);
        std::os::unix::fs::symlink(foreign.path(), &alias)?;
        tamper(
            &path,
            JournalTamper::AbandonedSocketIntent {
                slot: 2,
                name: &name,
            },
        )?;
        reconcile(&store, &parent()?)?;
        assert!(alias.symlink_metadata()?.file_type().is_symlink());
        assert_eq!(store.abandoned_socket_intents()?, 1);
        std::fs::remove_file(&alias)?;
        reconcile(&store, &parent()?)?;
        assert_eq!(intents(&store)?, 0);
        let endpoint = Endpoint::prepare(&store)?;
        let mut retained = Vec::new();
        for slot in 2..=9 {
            let name = format!("chio-worker-{}", uuid::Uuid::new_v4().simple());
            let alias = Path::new("/tmp").join(&name);
            symlink(endpoint.path.parent().ok_or("parent")?, &alias)?;
            tamper(
                &path,
                JournalTamper::AbandonedSocketIntent { slot, name: &name },
            )?;
            retained.push(alias);
        }
        tamper(&path, JournalTamper::LiveDirectoryUncommitted)?;
        assert!(Endpoint::prepare(&store).is_err());
        assert!(endpoint.path.parent().ok_or("parent")?.exists());
        assert_eq!(intents(&store)?, 9);
        for alias in retained {
            std::fs::remove_file(alias)?;
        }
        std::fs::remove_dir(endpoint.path.parent().ok_or("parent")?)?;
        Ok(())
    }

    #[test]
    fn abandoned_invalid_names_and_lookup_errors_retain_journal_rows() -> TestResult {
        let (_journal, store, path) = journal()?;
        let endpoint = Endpoint::prepare(&store)?;
        endpoint.cleanup(&store)?;
        tamper(
            &path,
            JournalTamper::AbandonedSocketIntent {
                slot: 2,
                name: "../foreign",
            },
        )?;
        assert!(reconcile(&store, &parent()?).is_err());
        assert_eq!(intents(&store)?, 1);
        let name = format!("chio-worker-{}", uuid::Uuid::new_v4().simple());
        tamper(&path, JournalTamper::SocketIntentRenamed(&name))?;
        assert!(reconcile(&store, &File::open("/dev/null")?).is_err());
        assert_eq!(intents(&store)?, 1);
        reconcile(&store, &parent()?)?;
        assert_eq!(intents(&store)?, 0);
        Ok(())
    }
}
